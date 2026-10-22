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

/// Maximum number of ledger entries a single restore footprint may cover.
const MAX_RESTORE_ENTRIES: usize = 32;

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

/// Build, bound, sign, and submit an `extend_attestation_ttl` invocation.
///
/// This is permissionless: any account may pay rent to extend an attestation
/// (issue #544). The contract caps `extend_to` to its maximum horizon, so the
/// CLI only validates that the value is a plausible ledger sequence.
pub fn run_extend_ttl(
    cfg: &NetworkConfig,
    contract_id: &str,
    source: &str,
    record_hash: &str,
    extend_to: u32,
    window: u32,
) -> anyhow::Result<()> {
    if extend_to == 0 {
        bail!("extend_to must be a positive ledger sequence");
    }
    let invoke = invoke_args(
        contract_id,
        source,
        "extend_attestation_ttl",
        &[
            "--record_hash".to_string(),
            record_hash.to_string(),
            "--extend_to".to_string(),
            extend_to.to_string(),
        ],
    );
    run_bounded(cfg, invoke, window)
}

/// Build, bound, sign, and submit a patient-initiated `dispute` invocation.
///
/// The dispute overlay is keyed by record hash and signer; the patient signs
/// the commitment with the QR-spec scheme, so the signature is passed through
/// verbatim (issue #546).
pub fn run_dispute(
    cfg: &NetworkConfig,
    contract_id: &str,
    source: &str,
    record_hash: &str,
    patient: &str,
    signature: &str,
    window: u32,
) -> anyhow::Result<()> {
    if signature.is_empty() {
        bail!("dispute requires a patient signature over the commitment");
    }
    let invoke = invoke_args(
        contract_id,
        source,
        "dispute",
        &[
            "--record_hash".to_string(),
            record_hash.to_string(),
            "--patient".to_string(),
            patient.to_string(),
            "--signature".to_string(),
            signature.to_string(),
        ],
    );
    run_bounded(cfg, invoke, window)
}

/// Restore archived attestation entries, then extend their TTL.
///
/// Archived entries must be restored into the live footprint before they can
/// be extended. The restore transaction is submitted first (bounded like any
/// other write); only once it is accepted do we submit the TTL extension.
pub fn run_restore(
    cfg: &NetworkConfig,
    contract_id: &str,
    source: &str,
    record_hash: &str,
    extend_to: u32,
    window: u32,
) -> anyhow::Result<()> {
    if extend_to == 0 {
        bail!("extend_to must be a positive ledger sequence");
    }
    let restore = invoke_args(
        contract_id,
        source,
        "restore_attestation",
        &[
            "--record_hash".to_string(),
            record_hash.to_string(),
            "--max_entries".to_string(),
            MAX_RESTORE_ENTRIES.to_string(),
        ],
    );
    run_bounded(cfg, restore, window)
        .with_context(|| format!("restoring archived attestation {record_hash} failed"))?;
    println!("Attestation {record_hash} restored; extending TTL to ledger {extend_to}");
    run_extend_ttl(cfg, contract_id, source, record_hash, extend_to, window)
}

/// Assemble a `stellar contract invoke` argument list.
fn invoke_args(contract_id: &str, source: &str, function: &str, args: &[String]) -> Vec<String> {
    let mut invoke = vec![
        "contract".to_string(),
        "invoke".to_string(),
        "--id".to_string(),
        contract_id.to_string(),
        "--source".to_string(),
        source.to_string(),
        "--".to_string(),
        function.to_string(),
    ];
    invoke.extend(args.iter().cloned());
    invoke
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
    fn invoke_args_places_function_after_separator() {
        let args = invoke_args(
            "C1",
            "GSOURCE",
            "extend_attestation_ttl",
            &[
                "--record_hash".to_string(),
                "abc".to_string(),
                "--extend_to".to_string(),
                "42".to_string(),
            ],
        );
        assert_eq!(
            args,
            [
                "contract",
                "invoke",
                "--id",
                "C1",
                "--source",
                "GSOURCE",
                "--",
                "extend_attestation_ttl",
                "--record_hash",
                "abc",
                "--extend_to",
                "42",
            ]
            .map(String::from)
            .to_vec()
        );
    }

    #[test]
    fn dispute_requires_signature() {
        let cfg = NetworkConfig {
            rpc_url: "http://localhost".into(),
            network_passphrase: "Test SDF Network ; September 2015".into(),
            ..Default::default()
        };
        let err = run_dispute(&cfg, "C1", "GSOURCE", "abc", "GPATIENT", "", 10)
            .expect_err("empty signature must be rejected");
        assert!(err.to_string().contains("signature"));
    }

    #[test]
    fn extend_ttl_rejects_zero_horizon() {
        let cfg = NetworkConfig {
            rpc_url: "http://localhost".into(),
            network_passphrase: "Test SDF Network ; September 2015".into(),
            ..Default::default()
        };
        let err = run_extend_ttl(&cfg, "C1", "GSOURCE", "abc", 0, 10)
            .expect_err("zero extend_to must be rejected");
        assert!(err.to_string().contains("extend_to"));
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
