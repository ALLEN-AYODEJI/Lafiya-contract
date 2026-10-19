//! Rules engine: turns events (and wasm-hash observations) into alerts.

use crate::config::{Config, EventRule, RateRule};
use crate::{Alert, Event, Severity};
use std::collections::{BTreeMap, VecDeque};

/// Alert kinds with a fixed meaning, referenced by the incident runbooks.
pub const UNKNOWN_WASM_UPGRADE: &str = "unknown_wasm_upgrade";
pub const WASM_CHANGED_WITHOUT_EVENT: &str = "wasm_changed_without_event";
pub const MASS_ENROLLMENT: &str = "mass_enrollment";
pub const WATCHDOG_LAG: &str = "watchdog_lag";
pub const WATCHDOG_FAILING: &str = "watchdog_failing";
pub const LARGE_WITHDRAWAL: &str = "large_withdrawal";
pub const APPROVAL_BURST: &str = "approval_burst";
pub const CLAIM_BY_READDED_ATTESTER: &str = "claim_by_readded_attester";
pub const POOL_PAUSED: &str = "pool_paused";

/// Thresholds for the incentive-pool rules.
#[derive(Debug, Clone)]
pub struct PoolRules {
    /// Withdrawals of at least this amount (in stroops) are flagged.
    pub large_withdrawal_amount: i128,
    /// More than this many approvals within `approval_window_ledgers` is a burst.
    pub approval_max_count: usize,
    pub approval_window_ledgers: u32,
    /// How long a re-added attester stays "recent" for claim alerting.
    pub readd_window_ledgers: u32,
}

impl Default for PoolRules {
    fn default() -> PoolRules {
        PoolRules {
            large_withdrawal_amount: 1_000_000_000_000,
            approval_max_count: 5,
            approval_window_ledgers: 20,
            readd_window_ledgers: 100,
        }
    }
}

pub struct Engine {
    rules: Vec<EventRule>,
    rate: Option<RateRule>,
    known_wasm: Vec<String>,
    explorer_tx_url: Option<String>,
    rate_window: VecDeque<u32>,
    /// Wasm hash each contract is expected to run, from `upgraded` events or
    /// the first observation.
    expected_wasm: BTreeMap<String, String>,
    pool: PoolRules,
    /// Ledgers of recent pool approvals, for burst detection.
    approval_window: VecDeque<u32>,
    /// Attesters that were (re-)added, with the ledger of the add.
    readded_attesters: BTreeMap<String, u32>,
}

/// Default rules from the issue: privileged changes are critical, pause
/// toggles are high.
pub fn default_rules() -> Vec<EventRule> {
    let rule = |kind: &str, events: &[&str], severity| EventRule {
        kind: kind.into(),
        events: events.iter().map(|e| e.to_string()).collect(),
        severity,
    };
    vec![
        rule(
            "admin_transferred",
            &["admin_transferred"],
            Severity::Critical,
        ),
        rule("upgraded", &["upgraded"], Severity::Critical),
        rule(
            "attester_registry_repointed",
            &["attester_registry_repointed"],
            Severity::Critical,
        ),
        rule(
            "multisig_reconfigured",
            &["multisig_*", "signers_*", "threshold_*", "recovery_*"],
            Severity::Critical,
        ),
        rule("pause_toggled", &["paused", "unpaused"], Severity::High),
        rule("bulk_revocation", &["attestation_revoked"], Severity::Info),
    ]
}

fn matches(pattern: &str, name: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => pattern == name,
    }
}

impl Engine {
    pub fn new(cfg: &Config) -> Engine {
        Engine {
            rules: if cfg.rules.is_empty() {
                default_rules()
            } else {
                cfg.rules.clone()
            },
            rate: cfg.mass_enrollment.clone(),
            known_wasm: cfg
                .known_wasm_hashes
                .iter()
                .map(|h| h.to_ascii_lowercase())
                .collect(),
            explorer_tx_url: cfg.explorer_tx_url.clone(),
            rate_window: VecDeque::new(),
            expected_wasm: BTreeMap::new(),
            pool: PoolRules::default(),
            approval_window: VecDeque::new(),
            readded_attesters: BTreeMap::new(),
        }
    }

    /// Override the incentive-pool rule thresholds.
    pub fn with_pool_rules(mut self, pool: PoolRules) -> Engine {
        self.pool = pool;
        self
    }

    fn alert(&self, kind: &str, severity: Severity, summary: String, e: &Event) -> Alert {
        let mut details = Vec::new();
        if !e.topics.is_empty() {
            details.push(format!("topics: {}", e.topics.join(", ")));
        }
        if !e.data.is_empty() {
            details.push(format!("data: {}", e.data));
        }
        if let Some(tx) = &e.tx_hash {
            details.push(format!("tx: {tx}"));
        }
        Alert {
            kind: kind.into(),
            severity,
            summary,
            ledger: e.ledger,
            contract: e.contract.clone(),
            details,
            explorer_link: match (&self.explorer_tx_url, &e.tx_hash) {
                (Some(base), Some(tx)) => Some(format!("{base}{tx}")),
                _ => None,
            },
        }
    }

    /// Evaluate one event. Events must be fed in ledger order.
    pub fn evaluate(&mut self, e: &Event) -> Vec<Alert> {
        let mut alerts = Vec::new();

        for rule in &self.rules {
            if rule.events.iter().any(|p| matches(p, &e.name)) {
                alerts.push(self.alert(
                    &rule.kind,
                    rule.severity,
                    format!("{} on {}", e.name, e.contract),
                    e,
                ));
            }
        }

        if e.name == "upgraded" {
            // The new wasm hash is the first topic after the event name.
            let hash = e
                .topics
                .first()
                .cloned()
                .unwrap_or_default()
                .to_ascii_lowercase();
            if !self.known_wasm.contains(&hash) {
                alerts.push(self.alert(
                    UNKNOWN_WASM_UPGRADE,
                    Severity::Critical,
                    format!("upgrade to wasm {hash} which is NOT in any release manifest"),
                    e,
                ));
            }
            self.expected_wasm.insert(e.contract.clone(), hash);
        }

        alerts.extend(self.evaluate_pool(e));

        if let Some(rate) = &self.rate {
            if e.name == rate.event {
                self.rate_window.push_back(e.ledger);
                while let Some(&first) = self.rate_window.front() {
                    if e.ledger.saturating_sub(first) >= rate.window_ledgers {
                        self.rate_window.pop_front();
                    } else {
                        break;
                    }
                }
                if self.rate_window.len() == rate.max_count + 1 {
                    let summary = format!(
                        "{} {} events within {} ledgers (mass enrollment)",
                        self.rate_window.len(),
                        rate.event,
                        rate.window_ledgers
                    );
                    alerts.push(self.alert(MASS_ENROLLMENT, rate.severity, summary, e));
                }
            }
        }

        alerts
    }

    /// Incentive-pool rules: large withdrawals, approval bursts, claims by
    /// recently re-added attesters, and pool pauses.
    fn evaluate_pool(&mut self, e: &Event) -> Vec<Alert> {
        let mut alerts = Vec::new();

        match e.name.as_str() {
            "attester_added" | "attester_readded" => {
                // The first topic carries the attester address.
                if let Some(attester) = e.topics.first() {
                    self.readded_attesters
                        .insert(attester.to_ascii_lowercase(), e.ledger);
                }
            }
            "withdrawal" | "withdrawn" => {
                if let Some(amount) = parse_amount(&e.data) {
                    if amount >= self.pool.large_withdrawal_amount {
                        alerts.push(self.alert(
                            LARGE_WITHDRAWAL,
                            Severity::High,
                            format!(
                                "withdrawal of {amount} on {} exceeds threshold {}",
                                e.contract, self.pool.large_withdrawal_amount
                            ),
                            e,
                        ));
                    }
                }
            }
            "approval" | "approved" => {
                self.approval_window.push_back(e.ledger);
                while let Some(&first) = self.approval_window.front() {
                    if e.ledger.saturating_sub(first) >= self.pool.approval_window_ledgers {
                        self.approval_window.pop_front();
                    } else {
                        break;
                    }
                }
                if self.approval_window.len() == self.pool.approval_max_count + 1 {
                    let summary = format!(
                        "{} approvals within {} ledgers (approval burst)",
                        self.approval_window.len(),
                        self.pool.approval_window_ledgers
                    );
                    alerts.push(self.alert(APPROVAL_BURST, Severity::High, summary, e));
                }
            }
            "claim" | "claimed" => {
                if let Some(attester) = e.topics.first() {
                    let key = attester.to_ascii_lowercase();
                    if let Some(&added) = self.readded_attesters.get(&key) {
                        if e.ledger.saturating_sub(added) <= self.pool.readd_window_ledgers {
                            alerts.push(self.alert(
                                CLAIM_BY_READDED_ATTESTER,
                                Severity::High,
                                format!(
                                    "claim by attester {attester} re-added at ledger {added}"
                                ),
                                e,
                            ));
                        }
                    }
                }
            }
            "pool_paused" | "paused" => {
                if e.name == "pool_paused" || e.contract.to_ascii_lowercase().contains("pool") {
                    alerts.push(self.alert(
                        POOL_PAUSED,
                        Severity::High,
                        format!("incentive pool paused on {}", e.contract),
                        e,
                    ));
                }
            }
            _ => {}
        }

        alerts
    }

    /// Compare a contract's on-chain wasm hash (from `getLedgerEntries`)
    /// against the hash implied by the events seen so far.
    pub fn observe_wasm(&mut self, contract: &str, hash: &str, ledger: u32) -> Option<Alert> {
        let hash = hash.to_ascii_lowercase();
        match self.expected_wasm.get(contract) {
            None => {
                self.expected_wasm.insert(contract.into(), hash);
                None
            }
            Some(expected) if *expected == hash => None,
            Some(expected) => {
                let summary =
                    format!("wasm hash changed from {expected} to {hash} with no upgraded event");
                let alert = Alert {
                    kind: WASM_CHANGED_WITHOUT_EVENT.into(),
                    severity: Severity::Critical,
                    summary,
                    ledger,
                    contract: contract.into(),
                    details: Vec::new(),
                    explorer_link: None,
                };
                self.expected_wasm.insert(contract.into(), hash);
                Some(alert)
            }
        }
    }
}

/// Dead-man's-switch state: tracks lag and consecutive poll failures.
#[derive(Debug, Default)]
pub struct HealthMonitor {
    pub consecutive_failures: u32,
    alerted_failing: bool,
    alerted_lag: bool,
}

impl HealthMonitor {
    pub fn record_failure(&mut self, max: u32, error: &str) -> Option<Alert> {
        self.consecutive_failures += 1;
        if self.consecutive_failures >= max && !self.alerted_failing {
            self.alerted_failing = true;
            return Some(self_alert(
                WATCHDOG_FAILING,
                format!(
                    "watchdog failed {} polls in a row: {error}",
                    self.consecutive_failures
                ),
                0,
            ));
        }
        None
    }

    pub fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.alerted_failing = false;
    }

    pub fn check_lag(&mut self, processed: u32, latest: u32, max_lag: u32) -> Option<Alert> {
        let lag = latest.saturating_sub(processed);
        if lag > max_lag {
            if !self.alerted_lag {
                self.alerted_lag = true;
                return Some(self_alert(
                    WATCHDOG_LAG,
                    format!("watchdog is {lag} ledgers behind (limit {max_lag})"),
                    latest,
                ));
            }
        } else {
            self.alerted_lag = false;
        }
        None
    }
}

/// Parse an amount from event data, which may be a bare integer or a JSON
/// object with an `amount` field.
fn parse_amount(data: &str) -> Option<i128> {
    let data = data.trim();
    if let Ok(n) = data.parse::<i128>() {
        return Some(n);
    }
    let key = "\"amount\"";
    let idx = data.find(key)?;
    let rest = &data[idx + key.len()..];
    let rest = rest.trim_start().strip_prefix(':')?.trim_start();
    let end = rest
        .find(|c: char| !(c.is_ascii_digit() || c == '-'))
        .unwrap_or(rest.len());
    rest[..end].parse::<i128>().ok()
}

fn self_alert(kind: &str, summary: String, ledger: u32) -> Alert {
    Alert {
        kind: kind.into(),
        severity: Severity::Critical,
        summary,
        ledger,
        contract: "lafiya-watchdog".into(),
        details: Vec::new(),
        explorer_link: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Heartbeat;

    fn cfg() -> Config {
        Config {
            rpc_url: "http://localhost:8000/rpc".into(),
            contracts: vec!["CREG".into()],
            poll_interval_secs: 5,
            explorer_tx_url: Some("https://stellar.expert/explorer/testnet/tx/".into()),
            release_manifests: vec![],
            known_wasm_hashes: vec!["aa".repeat(32)],
            rules: vec![],
            mass_enrollment: Some(RateRule {
                event: "attester_added".into(),
                max_count: 3,
                window_ledgers: 10,
                severity: Severity::High,
            }),
            heartbeat: Heartbeat::default(),
            sinks: vec![],
        }
    }

    fn ev(name: &str, ledger: u32, topics: &[&str]) -> Event {
        Event {
            ledger,
            contract: "CREG".into(),
            name: name.into(),
            topics: topics.iter().map(|t| t.to_string()).collect(),
            data: String::new(),
            tx_hash: Some("ab".repeat(32)),
            closed_at: None,
        }
    }

    fn kinds(alerts: &[Alert]) -> Vec<(&str, Severity)> {
        alerts
            .iter()
            .map(|a| (a.kind.as_str(), a.severity))
            .collect()
    }

    #[test]
    fn admin_transfer_is_critical() {
        let a = Engine::new(&cfg()).evaluate(&ev("admin_transferred", 1, &["GOLD", "GNEW"]));
        assert_eq!(kinds(&a), vec![("admin_transferred", Severity::Critical)]);
        assert!(a[0]
            .explorer_link
            .as_ref()
            .unwrap()
            .ends_with(&"ab".repeat(32)));
    }

    #[test]
    fn registry_repoint_is_critical() {
        let a = Engine::new(&cfg()).evaluate(&ev("attester_registry_repointed", 1, &[]));
        assert_eq!(
            kinds(&a),
            vec![("attester_registry_repointed", Severity::Critical)]
        );
    }

    #[test]
    fn multisig_events_match_prefix_patterns() {
        let mut e = Engine::new(&cfg());
        for name in [
            "multisig_config_changed",
            "signers_updated",
            "recovery_started",
        ] {
            assert_eq!(
                kinds(&e.evaluate(&ev(name, 1, &[]))),
                vec![("multisig_reconfigured", Severity::Critical)]
            );
        }
    }

    #[test]
    fn pause_and_unpause_are_high() {
        let mut e = Engine::new(&cfg());
        assert_eq!(
            kinds(&e.evaluate(&ev("paused", 1, &[]))),
            vec![("pause_toggled", Severity::High)]
        );
        assert_eq!(
            kinds(&e.evaluate(&ev("unpaused", 2, &[]))),
            vec![("pause_toggled", Severity::High)]
        );
    }

    #[test]
    fn known_upgrade_only_raises_upgrade_alert() {
        let a = Engine::new(&cfg()).evaluate(&ev("upgraded", 1, &[&"aa".repeat(32)]));
        assert_eq!(kinds(&a), vec![("upgraded", Severity::Critical)]);
    }

    #[test]
    fn upgrade_to_unknown_wasm_is_flagged() {
        let a = Engine::new(&cfg()).evaluate(&ev("upgraded", 1, &[&"bb".repeat(32)]));
        assert!(kinds(&a).contains(&(UNKNOWN_WASM_UPGRADE, Severity::Critical)));
    }

    #[test]
    fn mass_enrollment_fires_once_per_burst() {
        let mut e = Engine::new(&cfg());
        let mut fired = 0;
        for ledger in 1..=6 {
            fired += e
                .evaluate(&ev("attester_added", ledger, &[]))
                .iter()
                .filter(|a| a.kind == MASS_ENROLLMENT)
                .count();
        }
        assert_eq!(fired, 1);
    }

    #[test]
    fn slow_enrollment_does_not_fire() {
        let mut e = Engine::new(&cfg());
        for i in 0..10 {
            assert!(e.evaluate(&ev("attester_added", i * 20, &[])).is_empty());
        }
    }

    #[test]
    fn wasm_change_without_event_is_critical() {
        let mut e = Engine::new(&cfg());
        assert!(e.observe_wasm("CREG", &"aa".repeat(32), 1).is_none());
        let a = e.observe_wasm("CREG", &"cc".repeat(32), 2).unwrap();
        assert_eq!(
            (a.kind.as_str(), a.severity),
            (WASM_CHANGED_WITHOUT_EVENT, Severity::Critical)
        );
    }

    #[test]
    fn wasm_change_after_upgrade_event_is_expected() {
        let mut e = Engine::new(&cfg());
        e.observe_wasm("CREG", &"aa".repeat(32), 1);
        e.evaluate(&ev("upgraded", 2, &[&"aa".repeat(32)]));
        e.evaluate(&ev("upgraded", 3, &[&"dd".repeat(32)]));
        assert!(e.observe_wasm("CREG", &"dd".repeat(32), 4).is_none());
    }

    #[test]
    fn heartbeat_alerts_on_lag_and_failures() {
        let mut h = HealthMonitor::default();
        assert!(h.check_lag(100, 150, 60).is_none());
        assert_eq!(h.check_lag(100, 200, 60).unwrap().kind, WATCHDOG_LAG);
        assert!(
            h.check_lag(100, 201, 60).is_none(),
            "no repeat while still lagging"
        );
        assert!(h.record_failure(2, "timeout").is_none());
        assert_eq!(
            h.record_failure(2, "timeout").unwrap().kind,
            WATCHDOG_FAILING
        );
        h.record_success();
        assert_eq!(h.consecutive_failures, 0);
    }

    #[test]
    fn routine_events_are_ignored() {
        assert!(Engine::new(&cfg())
            .evaluate(&ev("attestation_recorded", 1, &[]))
            .is_empty());
    }

    fn pool_engine() -> Engine {
        Engine::new(&cfg()).with_pool_rules(PoolRules {
            large_withdrawal_amount: 1_000,
            approval_max_count: 2,
            approval_window_ledgers: 10,
            readd_window_ledgers: 50,
        })
    }

    fn pool_ev(name: &str, ledger: u32, topics: &[&str], data: &str) -> Event {
        let mut e = ev(name, ledger, topics);
        e.contract = "CPOOL".into();
        e.data = data.into();
        e
    }

    #[test]
    fn large_withdrawal_is_flagged() {
        let mut e = pool_engine();
        let a = e.evaluate(&pool_ev("withdrawal", 1, &["GATT"], "1500"));
        assert_eq!(kinds(&a), vec![(LARGE_WITHDRAWAL, Severity::High)]);
        let a = e.evaluate(&pool_ev("withdrawal", 2, &["GATT"], "{\"amount\": 2000}"));
        assert_eq!(kinds(&a), vec![(LARGE_WITHDRAWAL, Severity::High)]);
    }

    #[test]
    fn small_withdrawal_is_ignored() {
        let mut e = pool_engine();
        assert!(e
            .evaluate(&pool_ev("withdrawal", 1, &["GATT"], "999"))
            .is_empty());
    }

    #[test]
    fn approval_burst_fires_once() {
        let mut e = pool_engine();
        let mut fired = 0;
        for ledger in 1..=5 {
            fired += e
                .evaluate(&pool_ev("approval", ledger, &["GATT"], ""))
                .iter()
                .filter(|a| a.kind == APPROVAL_BURST)
                .count();
        }
        assert_eq!(fired, 1);
    }

    #[test]
    fn slow_approvals_do_not_burst() {
        let mut e = pool_engine();
        for i in 0..5 {
            assert!(e
                .evaluate(&pool_ev("approval", i * 20, &["GATT"], ""))
                .is_empty());
        }
    }

    #[test]
    fn claim_by_recently_readded_attester_is_flagged() {
        let mut e = pool_engine();
        e.evaluate(&pool_ev("attester_readded", 10, &["GATT"], ""));
        let a = e.evaluate(&pool_ev("claim", 20, &["GATT"], ""));
        assert_eq!(
            kinds(&a),
            vec![(CLAIM_BY_READDED_ATTESTER, Severity::High)]
        );
    }

    #[test]
    fn claim_by_long_standing_attester_is_ignored() {
        let mut e = pool_engine();
        e.evaluate(&pool_ev("attester_added", 1, &["GATT"], ""));
        assert!(e.evaluate(&pool_ev("claim", 100, &["GATT"], "")).is_empty());
    }

    #[test]
    fn pool_pause_is_flagged() {
        let mut e = pool_engine();
        let a = e.evaluate(&pool_ev("pool_paused", 1, &[], ""));
        assert_eq!(kinds(&a), vec![(POOL_PAUSED, Severity::High)]);
    }
}
