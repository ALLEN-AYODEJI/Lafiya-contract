//! Ledger-bounded submission for state-changing CLI commands (issue #407).
//!
//! Every write is built with a `maxLedger` bound (`latest + --ledger-window`)
//! so its outcome is always deterministic: it either lands before
//! `maxLedger`, or it provably never will and is rebuilt with a fresh
//! sequence number and bounds. The flow is:
//!
//! 1. `stellar contract invoke ... --build-only` + `stellar tx simulate`
//! 2. [`apply_ledger_bounds`] (`maxLedger` + auth `signature_expiration_ledger`)
//! 3. `stellar tx sign`
//! 4. [`FailoverClient::submit_with_bounds`] over Soroban JSON-RPC, which
//!    polls until the transaction is included, expired, or its sequence
//!    number is consumed (see ADR-0011).

use anyhow::{bail, Context};
use lafiya_config::NetworkConfig;
use lafiya_rpc_resilience::xdr::apply_ledger_bounds;
use lafiya_rpc_resilience::{
    max_ledger_for, FailoverClient, RecoveryLog, RecoveryResult, RetryPolicy, RpcError,
    RpcProvider, SubmitOutcome, TxState,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use std::time::Duration;
use stellar_xdr::{
    AccountId, LedgerEntryData, LedgerKey, LedgerKeyAccount, Limits, ReadXdr, TransactionEnvelope,
    WriteXdr,
};

/// How many times an expired transaction is rebuilt before giving up.
const MAX_REBUILDS: u32 = 2;

/// A persisted record of a submission intent, written *before* the envelope is
/// sent. It lets a later invocation (or an operator) reconcile an ambiguous
/// outcome without blindly resubmitting a non-idempotent call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmissionIntent {
    /// Hex transaction hash of the signed envelope.
    pub tx_hash: String,
    /// `maxLedger` bound: after this ledger the transaction can never land.
    pub max_ledger: u32,
    /// Source account sequence number consumed by this transaction.
    pub sequence: i64,
    /// Source account (G...) that owns `sequence`.
    pub source_account: String,
    /// Ledger at which the intent was recorded (for operator context).
    pub recorded_at_ledger: u32,
    /// Final state once reconciliation proves it, if known.
    #[serde(default)]
    pub final_state: Option<FinalState>,
}

/// A precise, proven final state for a submission intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FinalState {
    /// Included successfully in `ledger`.
    Succeeded { ledger: u32 },
    /// Included but failed on-chain with `reason`.
    Failed { reason: String },
    /// Provably never included: `latest_ledger` passed `max_ledger`.
    Expired { latest_ledger: u32 },
    /// The source sequence was consumed by another transaction.
    SequenceConsumed { consumed_by: Option<String> },
}

/// Directory holding submission intents, overridable for tests.
fn state_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("LAFIYA_STATE_DIR") {
        return PathBuf::from(dir);
    }
    let base = std::env::var("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|_| std::env::var("HOME").map(|h| PathBuf::from(h).join(".local/state")))
        .unwrap_or_else(|_| PathBuf::from("."));
    base.join("lafiya").join("submissions")
}

fn intent_path(dir: &Path, tx_hash: &str) -> PathBuf {
    dir.join(format!("{tx_hash}.json"))
}

/// Persist `intent` with an atomic write (temp file + fsync + rename) so a
/// crash never leaves a truncated record behind.
pub fn save_intent(dir: &Path, intent: &SubmissionIntent) -> anyhow::Result<()> {
    fs::create_dir_all(dir)
        .with_context(|| format!("creating state dir {}", dir.display()))?;
    let final_path = intent_path(dir, &intent.tx_hash);
    let tmp_path = dir.join(format!(".{}.tmp", intent.tx_hash));
    let bytes = serde_json::to_vec_pretty(intent)?;
    {
        let mut file = fs::File::create(&tmp_path)
            .with_context(|| format!("creating {}", tmp_path.display()))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    fs::rename(&tmp_path, &final_path)
        .with_context(|| format!("renaming into {}", final_path.display()))?;
    // Best-effort durability of the rename itself.
    if let Ok(dir_handle) = fs::File::open(dir) {
        let _ = dir_handle.sync_all();
    }
    Ok(())
}

/// Load a previously persisted intent, if any.
pub fn load_intent(dir: &Path, tx_hash: &str) -> anyhow::Result<Option<SubmissionIntent>> {
    let path = intent_path(dir, tx_hash);
    match fs::read(&path) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes).with_context(|| {
            format!("parsing submission intent {}", path.display())
        })?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// Reconcile a persisted intent by polling `getTransaction` until a final
/// state is proven. Never resubmits.
pub fn reconcile(
    rpc: &mut dyn RpcProvider,
    intent: &SubmissionIntent,
    policy: &RetryPolicy,
) -> Result<FinalState, RpcError> {
    let mut log = RecoveryLog::new();
    let bounds = lafiya_rpc_resilience::LedgerBounds {
        max_ledger: intent.max_ledger,
        sequence: intent.sequence,
        source_account: intent.source_account.clone(),
    };
    let result = rpc.reconcile_with_bounds(&intent.tx_hash, &bounds, policy, &mut log);
    Ok(match result {
        RecoveryResult::Accepted { ledger, .. } => FinalState::Succeeded { ledger },
        RecoveryResult::RejectedOnChain { reason } => FinalState::Failed { reason },
        RecoveryResult::Expired { latest_ledger, .. } => FinalState::Expired { latest_ledger },
        RecoveryResult::SequenceConsumed { consumed_by } => {
            FinalState::SequenceConsumed { consumed_by }
        }
        RecoveryResult::ExhaustedNeedsOperator { last_known } => {
            return Err(RpcError::Other(format!(
                "outcome of {} still ambiguous (last known: {last_known:?}); see docs/runbooks/rpc-outage-recovery.md",
                intent.tx_hash
            )))
        }
    })
}

/// `tx status <hash>`: read the persisted intent and report its state,
/// reconciling against the network when no final state is recorded yet.
pub fn status(cfg: &NetworkConfig, tx_hash: &str) -> anyhow::Result<()> {
    let dir = state_dir();
    let Some(mut intent) = load_intent(&dir, tx_hash)? else {
        bail!("no submission intent recorded for {tx_hash} in {}", dir.display());
    };
    if let Some(state) = &intent.final_state {
        println!("{tx_hash}: {state:?} (recorded)");
        return Ok(());
    }
    let mut rpc = SorobanRpc::new(&cfg.rpc_url);
    match reconcile(&mut rpc, &intent, &RetryPolicy::default()) {
        Ok(state) => {
            intent.final_state = Some(state.clone());
            save_intent(&dir, &intent)?;
            println!("{tx_hash}: {state:?}");
            Ok(())
        }
        Err(e) => bail!(
            "could not determine the outcome of {tx_hash}: {e}; the intent is still recorded at {}",
            intent_path(&dir, tx_hash).display()
        ),
    }
}

/// Build, bound, sign, and submit a `stellar contract invoke` argument list
/// (as produced by `invoke_args`), rebuilding it if it expires.
pub fn run_bounded(cfg: &NetworkConfig, invoke: Vec<String>, window: u32) -> anyhow::Result<()> {
    for attempt in 0..=MAX_REBUILDS {
        let mut rpc = SorobanRpc::new(&cfg.rpc_url);
        let latest = rpc
            .latest_ledger()
            .map_err(|e| anyhow::anyhow!("getLatestLedger failed: {e}"))?;
        let max_ledger = max_ledger_for(latest, window);

        let unsigned = stellar(&build_only_args(&invoke))?;
        let simulated = stellar(&tx_args(cfg, "simulate", &invoke, &unsigned))?;
        let (bounded, bounds) = apply_ledger_bounds(&simulated, max_ledger)?;
        let signed = stellar(&tx_args(cfg, "sign", &invoke, &bounded))?;
        let tx_hash = tx_hash(&signed, &cfg.network_passphrase)?;
        println!(
            "Submitting {tx_hash} (sequence {}, valid through ledger {max_ledger})",
            bounds.sequence
        );

        // Persist the intent *before* sending so an ambiguous outcome can be
        // reconciled later without double submission.
        let dir = state_dir();
        let mut intent = SubmissionIntent {
            tx_hash: tx_hash.clone(),
            max_ledger,
            sequence: bounds.sequence,
            source_account: bounds.source_account.clone(),
            recorded_at_ledger: latest,
            final_state: None,
        };
        save_intent(&dir, &intent)?;

        rpc.envelope = Some(signed);
        let mut client = FailoverClient::new(vec![Box::new(rpc)], RetryPolicy::default());
        let mut log = RecoveryLog::new();
        let result = client.submit_with_bounds(&tx_hash, &bounds, &mut log);
        for line in log.lines() {
            eprintln!("  {line}");
        }
        match result {
            RecoveryResult::Accepted { ledger, .. } => {
                intent.final_state = Some(FinalState::Succeeded { ledger });
                save_intent(&dir, &intent)?;
                println!("Transaction {tx_hash} succeeded in ledger {ledger}");
                return Ok(());
            }
            RecoveryResult::RejectedOnChain { reason } => {
                intent.final_state = Some(FinalState::Failed {
                    reason: reason.clone(),
                });
                save_intent(&dir, &intent)?;
                bail!("transaction {tx_hash} failed on-chain: {reason}")
            }
            RecoveryResult::Expired { latest_ledger, .. } if attempt < MAX_REBUILDS => {
                intent.final_state = Some(FinalState::Expired { latest_ledger });
                save_intent(&dir, &intent)?;
                eprintln!(
                    "Transaction {tx_hash} expired (ledger {latest_ledger} > {max_ledger}); it can never be included -- rebuilding"
                );
            }
            RecoveryResult::Expired { latest_ledger, .. } => {
                intent.final_state = Some(FinalState::Expired { latest_ledger });
                save_intent(&dir, &intent)?;
                bail!("transaction {tx_hash} expired at ledger {latest_ledger} after {MAX_REBUILDS} rebuilds; nothing was applied")
            }
            RecoveryResult::SequenceConsumed { consumed_by } => {
                intent.final_state = Some(FinalState::SequenceConsumed {
                    consumed_by: consumed_by.clone(),
                });
                save_intent(&dir, &intent)?;
                bail!(
                    "sequence {} of {} was consumed by {}; transaction {tx_hash} can never be included. Check whether that transaction already made this change before retrying.",
                    bounds.sequence,
                    bounds.source_account,
                    consumed_by.as_deref().unwrap_or("another transaction")
                )
            }
            RecoveryResult::ExhaustedNeedsOperator { last_known } => bail!(
                "could not determine the outcome of {tx_hash} (last known: {last_known:?}); the intent is recorded at {} -- run `tx status {tx_hash}` to reconcile; see docs/runbooks/rpc-outage-recovery.md",
                intent_path(&dir, &tx_hash).display()
            ),
        }
    }
    unreachable!("the final attempt always returns")
}

/// `stellar contract invoke ... --build-only -- fn args`
fn build_only_args(invoke: &[String]) -> Vec<String> {
    let mut args = invoke.to_vec();
    let at = args.iter().position(|a| a == "--").unwrap_or(args.len());
    args.insert(at, "--build-only".to_string());
    args
}

/// `stellar tx <sub> --rpc-url .. --network-passphrase .. [--source-account|--sign-with-key <source>] <xdr>`
fn tx_args(cfg: &NetworkConfig, sub: &str, invoke: &[String], xdr: &str) -> Vec<String> {
    let mut args = vec![
        "tx".to_string(),
        sub.to_string(),
        "--rpc-url".to_string(),
        cfg.rpc_url.clone(),
        "--network-passphrase".to_string(),
        cfg.network_passphrase.clone(),
    ];
    if let Some(source) = invoke
        .iter()
        .position(|a| a == "--source")
        .and_then(|i| invoke.get(i + 1))
    {
        let flag = if sub == "sign" {
            "--sign-with-key"
        } else {
            "--source-account"
        };
        args.push(flag.to_string());
        args.push(source.clone());
    }
    args.push(xdr.to_string());
    args
}

fn stellar(args: &[String]) -> anyhow::Result<String> {
    let output = Command::new("stellar")
        .args(args)
        .output()
        .context("failed to run stellar CLI (install with: cargo install --locked stellar-cli)")?;
    if !output.status.success() {
        bail!(
            "stellar {} failed: {}",
            args.iter().take(2).cloned().collect::<Vec<_>>().join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

/// Hex transaction hash of a signed envelope for `passphrase`.
pub fn tx_hash(envelope_b64: &str, passphrase: &str) -> anyhow::Result<String> {
    let envelope = TransactionEnvelope::from_xdr_base64(envelope_b64, Limits::none())?;
    let network_id: [u8; 32] = Sha256::digest(passphrase.as_bytes()).into();
    Ok(hex::encode(envelope.hash(network_id)?))
}

/// Minimal Soroban JSON-RPC provider for [`FailoverClient`].
struct SorobanRpc {
    url: String,
    agent: ureq::Agent,
    envelope: Option<String>,
}

impl SorobanRpc {
    fn new(url: &str) -> Self {
        SorobanRpc {
            url: url.to_string(),
            agent: ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(15))
                .build(),
            envelope: None,
        }
    }

    /// Call `method`. Errors are split the ADR-0011 way: a failure to
    /// connect is definite (nothing sent); anything after that is ambiguous.
    fn call(&self, method: &str, params: Value) -> Result<Value, (bool, RpcError)> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        match self.agent.post(&self.url).send_json(body) {
            Ok(resp) => {
                let value: Value = resp
                    .into_json()
                    .map_err(|e| (true, RpcError::Other(e.to_string())))?;
                if let Some(err) = value.get("error") {
                    return Err((false, RpcError::Other(err.to_string())));
                }
                Ok(value["result"].clone())
            }
            Err(ureq::Error::Status(429, _)) => {
                Err((false, RpcError::RateLimited { retry_after: None }))
            }
            Err(ureq::Error::Status(code, _)) => {
                Err((true, RpcError::Other(format!("HTTP {code}"))))
            }
            Err(ureq::Error::Transport(t)) if t.kind() == ureq::ErrorKind::ConnectionFailed => {
                Err((false, RpcError::ProviderUnavailable))
            }
            Err(ureq::Error::Transport(t)) if t.kind() == ureq::ErrorKind::Dns => {
                Err((false, RpcError::ProviderUnavailable))
            }
            Err(ureq::Error::Transport(_)) => Err((true, RpcError::Timeout)),
        }
    }
}

impl RpcProvider for SorobanRpc {
    fn name(&self) -> &str {
        &self.url
    }

    fn submit(&mut self, _tx_hash: &str) -> SubmitOutcome {
        let Some(envelope) = self.envelope.clone() else {
            return SubmitOutcome::Definite(RpcError::Other("no envelope to submit".into()));
        };
        match self.call("sendTransaction", json!({ "transaction": envelope })) {
            Ok(result) => match result["status"].as_str().unwrap_or_default() {
                "PENDING" | "DUPLICATE" => SubmitOutcome::Ack(TxState::Pending),
                "TRY_AGAIN_LATER" => {
                    SubmitOutcome::Definite(RpcError::RateLimited { retry_after: None })
                }
                _ => SubmitOutcome::Ack(TxState::Rejected {
                    reason: result["errorResultXdr"]
                        .as_str()
                        .unwrap_or("sendTransaction error")
                        .to_string(),
                }),
            },
            Err((true, err)) => SubmitOutcome::Ambiguous(err),
            Err((false, err)) => SubmitOutcome::Definite(err),
        }
    }

    fn get_transaction(&mut self, tx_hash: &str) -> Result<TxState, RpcError> {
        let result = self
            .call("getTransaction", json!({ "hash": tx_hash }))
            .map_err(|(_, e)| e)?;
        Ok(match result["status"].as_str().unwrap_or_default() {
            "SUCCESS" => TxState::Accepted {
                ledger: result["ledger"].as_u64().unwrap_or_default() as u32,
            },
            "FAILED" => TxState::Rejected {
                reason: result["resultXdr"].as_str().unwrap_or("failed").to_string(),
            },
            _ => TxState::Unknown,
        })
    }

    fn latest_ledger(&mut self) -> Result<u32, RpcError> {
        let result = self
            .call("getLatestLedger", json!({}))
            .map_err(|(_, e)| e)?;
        result["sequence"]
            .as_u64()
            .map(|s| s as u32)
            .ok_or_else(|| RpcError::Other("getLatestLedger: missing sequence".into()))
    }

    fn account_sequence(&mut self, account: &str) -> Result<i64, RpcError> {
        let key = LedgerKey::Account(LedgerKeyAccount {
            account_id: AccountId::from_str(account).map_err(|e| RpcError::Other(e.to_string()))?,
        })
        .to_xdr_base64(Limits::none())
        .map_err(|e| RpcError::Other(e.to_string()))?;
        let result = self
            .call("getLedgerEntries", json!({ "keys": [key] }))
            .map_err(|(_, e)| e)?;
        let xdr = result["entries"][0]["xdr"]
            .as_str()
            .ok_or_else(|| RpcError::Other("account not found".into()))?;
        match LedgerEntryData::from_xdr_base64(xdr, Limits::none()) {
            Ok(LedgerEntryData::Account(account)) => Ok(account.seq_num.0),
            Ok(_) => Err(RpcError::Other("unexpected ledger entry type".into())),
            Err(e) => Err(RpcError::Other(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intent_round_trips_through_atomic_write() {
        let dir = std::env::temp_dir().join(format!("lafiya-intent-{}", std::process::id()));
        let intent = SubmissionIntent {
            tx_hash: "abc123".into(),
            max_ledger: 42,
            sequence: 7,
            source_account: "GAAA".into(),
            recorded_at_ledger: 40,
            final_state: None,
        };
        save_intent(&dir, &intent).unwrap();
        let loaded = load_intent(&dir, "abc123").unwrap().unwrap();
        assert_eq!(loaded.tx_hash, "abc123");
        assert_eq!(loaded.max_ledger, 42);
        assert_eq!(loaded.sequence, 7);
        assert!(loaded.final_state.is_none());
        // No temp file is left behind.
        assert!(!dir.join(".abc123.tmp").exists());
        assert!(load_intent(&dir, "missing").unwrap().is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn build_only_goes_before_the_function_separator() {
        let invoke: Vec<String> = ["contract", "invoke", "--id", "C1", "--", "add_attester"]
            .map(String::from)
            .to_vec();
        assert_eq!(
            build_only_args(&invoke),
            [
                "contract",
                "invoke",
                "--id",
                "C1",
                "--build-only",
                "--",
                "add_attester"
            ]
            .map(String::from)
            .to_vec()
        );
    }
}
