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
    #[serde(default)]
    pub heartbeat: Heartbeat,
    #[serde(default)]
    pub sinks: Vec<SinkConfig>,
    /// Persistent rule-window / dedup state (#532).
    #[serde(default)]
    pub state: StateConfig,
    /// Escalation policy by severity (#532).
    #[serde(default)]
    pub escalation: Escalation,
    /// Guarded auto-response proposals (#533).
    #[serde(default)]
    pub auto_response: AutoResponse,
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
    /// See `docs/runbooks/watchdog.md` for healthchecks.io / Cronitor setup.
    #[serde(default)]
    pub ping_url: Option<String>,
    /// Minimum seconds between heartbeat pings. Defaults to the poll interval
    /// when unset; a value of `0` pings after every healthy poll.
    #[serde(default)]
    pub ping_interval_secs: Option<u64>,
    /// Optional HTTP method for the ping (`GET` by default). Some monitors
    /// (e.g. Cronitor) accept `POST`.
    #[serde(default)]
    pub ping_method: Option<String>,
}

impl Default for Heartbeat {
    fn default() -> Self {
        Heartbeat {
            max_lag_ledgers: default_lag(),
            max_consecutive_failures: default_failures(),
            ping_url: None,
            ping_interval_secs: None,
            ping_method: None,
        }
    }
}

fn default_lag() -> u32 {
    60
}

fn default_failures() -> u32 {
    5
}

/// Where rule-window and last-alert fingerprints are persisted so a restart
/// neither re-alerts nor loses in-flight windows (#532).
#[derive(Debug, Clone, Deserialize)]
pub struct StateConfig {
    /// Path to the state file. `None` disables persistence (in-memory only).
    #[serde(default)]
    pub path: Option<String>,
    /// Flush the state file after every poll rather than only on shutdown.
    #[serde(default = "default_true")]
    pub flush_every_poll: bool,
}

impl Default for StateConfig {
    fn default() -> Self {
        StateConfig {
            path: None,
            flush_every_poll: true,
        }
    }
}

fn default_true() -> bool {
    true
}

/// Escalation policy: how long to wait for an ack before re-notifying and
/// which sinks to target per severity (#532).
#[derive(Debug, Clone, Deserialize)]
pub struct Escalation {
    /// Seconds to wait for an acknowledgement before escalating. `0` disables.
    #[serde(default = "default_ack_timeout")]
    pub ack_timeout_secs: u64,
    /// Seconds between re-notifications while unacknowledged. `0` disables.
    #[serde(default = "default_renotify")]
    pub renotify_interval_secs: u64,
    /// Per-severity escalation targets, keyed by `info`/`low`/`medium`/`high`/`critical`.
    #[serde(default)]
    pub targets: std::collections::BTreeMap<String, Vec<String>>,
}

impl Default for Escalation {
    fn default() -> Self {
        Escalation {
            ack_timeout_secs: default_ack_timeout(),
            renotify_interval_secs: default_renotify(),
            targets: Default::default(),
        }
    }
}

fn default_ack_timeout() -> u64 {
    900
}

fn default_renotify() -> u64 {
    1800
}

/// Guarded auto-response: build (never execute) pause proposals on critical
/// alerts, gated by rate limiting and alert authenticity checks (#533).
#[derive(Debug, Clone, Deserialize)]
pub struct AutoResponse {
    /// Master switch. Disabled by default; proposals are never executed.
    #[serde(default)]
    pub enabled: bool,
    /// Rule kinds (e.g. `event`, `mass_enrollment`) that may trigger a proposal.
    #[serde(default = "default_critical_kinds")]
    pub critical_kinds: Vec<String>,
    /// Maximum proposals generated per `rate_limit_window_secs`.
    #[serde(default = "default_rate_limit")]
    pub rate_limit: usize,
    /// Window for `rate_limit`, in seconds.
    #[serde(default = "default_rate_window")]
    pub rate_limit_window_secs: u64,
    /// HMAC key (hex) used to verify signed alerts before proposing a pause.
    #[serde(default)]
    pub alert_signing_key: Option<String>,
    /// Public key (hex) for asymmetric alert verification, if used instead of HMAC.
    #[serde(default)]
    pub alert_public_key: Option<String>,
    /// Path to the pause-policy matrix (see `docs/PAUSE-POLICY.md`).
    #[serde(default)]
    pub pause_policy_path: Option<String>,
}

impl Default for AutoResponse {
    fn default() -> Self {
        AutoResponse {
            enabled: false,
            critical_kinds: default_critical_kinds(),
            rate_limit: default_rate_limit(),
            rate_limit_window_secs: default_rate_window(),
            alert_signing_key: None,
            alert_public_key: None,
            pause_policy_path: None,
        }
    }
}

fn default_critical_kinds() -> Vec<String> {
    vec!["event".into(), "mass_enrollment".into()]
}

fn default_rate_limit() -> usize {
    3
}

fn default_rate_window() -> u64 {
    3600
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
