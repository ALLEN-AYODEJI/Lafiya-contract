//! `watchdog.toml`: rules, sinks, and heartbeat settings.

use crate::Severity;
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub rpc_url: String,
    /// Contract IDs to watch.
    pub contracts: Vec<String>,
    #[serde(default = "default_poll")]
    pub poll_interval_secs: u64,
    /// Transaction explorer prefix; the tx hash is appended.
    #[serde(default)]
    pub explorer_tx_url: Option<String>,
    /// Release manifests whose `contracts[].wasm.sha256` are trusted upgrade targets.
    #[serde(default)]
    pub release_manifests: Vec<String>,
    /// Extra trusted wasm hashes (hex), in addition to the manifests.
    #[serde(default)]
    pub known_wasm_hashes: Vec<String>,
    #[serde(default)]
    pub rules: Vec<EventRule>,
    #[serde(default)]
    pub mass_enrollment: Option<RateRule>,
    /// Alert when attestation entries approach expiry (issue #544).
    #[serde(default)]
    pub expiry_warning: ExpiryWarning,
    /// Alert on patient-initiated dispute flags (issue #546).
    #[serde(default)]
    pub disputes: DisputeMonitoring,
    #[serde(default)]
    pub heartbeat: Heartbeat,
    #[serde(default)]
    pub sinks: Vec<SinkConfig>,
}

fn default_poll() -> u64 {
    5
}

/// Alert on every event whose name matches one of `events`. A trailing `*`
/// matches a prefix (e.g. `multisig_*`).
#[derive(Debug, Clone, Deserialize)]
pub struct EventRule {
    pub kind: String,
    pub events: Vec<String>,
    pub severity: Severity,
}

/// Alert when more than `max_count` `event`s land within `window_ledgers`.
#[derive(Debug, Clone, Deserialize)]
pub struct RateRule {
    #[serde(default = "default_rate_event")]
    pub event: String,
    pub max_count: usize,
    pub window_ledgers: u32,
    #[serde(default = "default_high")]
    pub severity: Severity,
}

fn default_rate_event() -> String {
    "attester_added".into()
}

/// Watchdog guidance for attestation TTLs: warn before entries archive so an
/// operator can call `extend_attestation_ttl` (or `restore`) in time.
#[derive(Debug, Clone, Deserialize)]
pub struct ExpiryWarning {
    /// Emit a warning when an entry's remaining TTL falls below this many
    /// ledgers.
    #[serde(default = "default_expiry_warn_ledgers")]
    pub warn_below_ledgers: u32,
    /// Emit a critical alert when remaining TTL falls below this many ledgers.
    #[serde(default = "default_expiry_critical_ledgers")]
    pub critical_below_ledgers: u32,
    /// How often to scan tracked attestation entries, in ledgers.
    #[serde(default = "default_expiry_scan")]
    pub scan_interval_ledgers: u32,
    /// Record hashes (hex) whose TTL should be monitored. Empty means monitor
    /// every entry the indexer reports.
    #[serde(default)]
    pub record_hashes: Vec<String>,
}

impl Default for ExpiryWarning {
    fn default() -> Self {
        ExpiryWarning {
            warn_below_ledgers: default_expiry_warn_ledgers(),
            critical_below_ledgers: default_expiry_critical_ledgers(),
            scan_interval_ledgers: default_expiry_scan(),
            record_hashes: Vec::new(),
        }
    }
}

fn default_expiry_warn_ledgers() -> u32 {
    100_000
}

fn default_expiry_critical_ledgers() -> u32 {
    20_000
}

fn default_expiry_scan() -> u32 {
    1_000
}

/// Watchdog guidance for patient-initiated dispute flags: surface disputes so
/// verifiers and responders act on them.
#[derive(Debug, Clone, Deserialize)]
pub struct DisputeMonitoring {
    /// Alert on every newly observed dispute flag.
    #[serde(default = "default_true")]
    pub alert_on_new: bool,
    /// Alert when a single signer raises more than this many disputes within
    /// `window_ledgers` (anti-abuse / spam signal).
    #[serde(default = "default_dispute_spam")]
    pub max_disputes_per_signer: usize,
    #[serde(default = "default_dispute_window")]
    pub window_ledgers: u32,
    #[serde(default = "default_high")]
    pub severity: Severity,
}

impl Default for DisputeMonitoring {
    fn default() -> Self {
        DisputeMonitoring {
            alert_on_new: true,
            max_disputes_per_signer: default_dispute_spam(),
            window_ledgers: default_dispute_window(),
            severity: Severity::High,
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_dispute_spam() -> usize {
    5
}

fn default_dispute_window() -> u32 {
    1_000
}

fn default_high() -> Severity {
    Severity::High
}

#[derive(Debug, Clone, Deserialize)]
pub struct Heartbeat {
    /// Alert when the watchdog falls this many ledgers behind the network.
    #[serde(default = "default_lag")]
    pub max_lag_ledgers: u32,
    /// Alert after this many consecutive failed polls.
    #[serde(default = "default_failures")]
    pub max_consecutive_failures: u32,
    /// Dead-man's switch: pinged (HTTP GET) after every healthy poll, so an
    /// external monitor (healthchecks.io, Cronitor, ...) pages when pings stop.
    #[serde(default)]
    pub ping_url: Option<String>,
}

impl Default for Heartbeat {
    fn default() -> Self {
        Heartbeat {
            max_lag_ledgers: default_lag(),
            max_consecutive_failures: default_failures(),
            ping_url: None,
        }
    }
}

fn default_lag() -> u32 {
    60
}

fn default_failures() -> u32 {
    5
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum SinkConfig {
    /// JSON webhook. `format` is `slack`, `discord`, `matrix`, or `generic`.
    Webhook {
        url: String,
        #[serde(default = "default_format")]
        format: String,
        #[serde(default)]
        min_severity: Option<Severity>,
    },
    /// PagerDuty Events API v2.
    Pagerduty {
        routing_key: String,
        #[serde(default)]
        min_severity: Option<Severity>,
    },
    /// Opsgenie Alerts API.
    Opsgenie {
        api_key: String,
        #[serde(default)]
        min_severity: Option<Severity>,
    },
    /// Pipe the alert text to a command's stdin, e.g. `sendmail -t` or
    /// `msmtp oncall@example.org` for email through SMTP.
    Command {
        program: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        min_severity: Option<Severity>,
    },
}

fn default_format() -> String {
    "generic".into()
}

impl SinkConfig {
    pub fn min_severity(&self) -> Severity {
        match self {
            SinkConfig::Webhook { min_severity, .. }
            | SinkConfig::Pagerduty { min_severity, .. }
            | SinkConfig::Opsgenie { min_severity, .. }
            | SinkConfig::Command { min_severity, .. } => min_severity.unwrap_or(Severity::Info),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Config> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
        let mut cfg: Config = toml::from_str(&text)?;
        let base = path.parent().unwrap_or(Path::new("."));
        for manifest in cfg.release_manifests.clone() {
            cfg.known_wasm_hashes
                .extend(manifest_hashes(&base.join(&manifest))?);
        }
        Ok(cfg)
    }
}

/// Wasm hashes (`contracts[].wasm.sha256`) recorded in a release manifest.
pub fn manifest_hashes(path: &Path) -> anyhow::Result<Vec<String>> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("reading manifest {}: {e}", path.display()))?;
    let json: serde_json::Value = serde_json::from_str(&text)?;
    Ok(json["contracts"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|c| c["wasm"]["sha256"].as_str())
        .map(str::to_ascii_lowercase)
        .collect())
}
