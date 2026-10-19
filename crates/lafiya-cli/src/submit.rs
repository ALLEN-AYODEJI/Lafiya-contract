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
use std::process::Command;
use std::str::FromStr;
use std::time::Duration;
use stellar_xdr::{
    AccountId, DecoratedSignature, LedgerEntryData, LedgerKey, LedgerKeyAccount, Limits, ReadXdr,
    Signature, TransactionEnvelope, WriteXdr,
};

/// How many times an expired transaction is rebuilt before giving up.
const MAX_REBUILDS: u32 = 2;

/// Version tag for the air-gapped transaction envelope (issue #534).
pub const ENVELOPE_VERSION: u32 = 1;

/// Version tag for the detached signature bundle (issue #534).
pub const BUNDLE_VERSION: u32 = 1;

/// A self-describing, transportable envelope carrying an unsigned
/// transaction between an online host and an offline signer.
///
/// The `checksum` covers every other field (see [`Envelope::checksum`]) so
/// that any tampering in transit -- including a swapped network passphrase,
/// contract id, or expiry -- is detected before the offline device signs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    /// Envelope format version; must equal [`ENVELOPE_VERSION`].
    pub version: u32,
    /// Network passphrase the transaction is bound to.
    pub network_passphrase: String,
    /// Contract id the invocation targets, if any.
    pub contract_id: Option<String>,
    /// Ledger after which the transaction can never be included.
    pub max_ledger: u32,
    /// Sequence number of the source account.
    pub sequence: i64,
    /// Source account (G...).
    pub source_account: String,
    /// Base64 unsigned transaction envelope XDR.
    pub xdr: String,
    /// Human-readable decode of the invocation, for offline review.
    pub human_readable: String,
    /// Hex SHA-256 over the canonical encoding of all fields above.
    pub checksum: String,
}

impl Envelope {
    /// Build an envelope, computing its checksum.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        network_passphrase: impl Into<String>,
        contract_id: Option<String>,
        max_ledger: u32,
        sequence: i64,
        source_account: impl Into<String>,
        xdr: impl Into<String>,
        human_readable: impl Into<String>,
    ) -> Self {
        let mut envelope = Envelope {
            version: ENVELOPE_VERSION,
            network_passphrase: network_passphrase.into(),
            contract_id,
            max_ledger,
            sequence,
            source_account: source_account.into(),
            xdr: xdr.into(),
            human_readable: human_readable.into(),
            checksum: String::new(),
        };
        envelope.checksum = envelope.checksum();
        envelope
    }

    /// Hex SHA-256 over the canonical encoding of every field except
    /// `checksum`. Field order and separators are fixed so the value is
    /// stable across hosts and serialization formats.
    pub fn checksum(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.version.to_le_bytes());
        hash_field(&mut hasher, &self.network_passphrase);
        hash_field(&mut hasher, self.contract_id.as_deref().unwrap_or(""));
        hasher.update(self.max_ledger.to_le_bytes());
        hasher.update(self.sequence.to_le_bytes());
        hash_field(&mut hasher, &self.source_account);
        hash_field(&mut hasher, &self.xdr);
        hash_field(&mut hasher, &self.human_readable);
        hex::encode(hasher.finalize())
    }

    /// Recompute the checksum and reject the envelope if it does not match.
    /// Call this on the offline device *before* signing.
    pub fn verify(&self) -> anyhow::Result<()> {
        if self.version != ENVELOPE_VERSION {
            bail!(
                "unsupported envelope version {} (expected {ENVELOPE_VERSION})",
                self.version
            );
        }
        let expected = self.checksum();
        if !constant_time_eq(expected.as_bytes(), self.checksum.as_bytes()) {
            bail!(
                "envelope checksum mismatch: expected {expected}, found {} -- the envelope was modified in transit",
                self.checksum
            );
        }
        Ok(())
    }

    /// Verify the checksum, then reject an envelope whose `max_ledger` has
    /// already passed. `latest_ledger` is supplied by the caller so the
    /// offline device can be told the current ledger out of band.
    pub fn verify_for_signing(&self, latest_ledger: u32) -> anyhow::Result<()> {
        self.verify()?;
        if latest_ledger > self.max_ledger {
            bail!(
                "envelope expired: max ledger {} is before current ledger {latest_ledger}",
                self.max_ledger
            );
        }
        Ok(())
    }

    /// Serialize to a single-line JSON string suitable for a file or QR
    /// transport.
    pub fn to_json(&self) -> anyhow::Result<String> {
        Ok(serde_json::to_string(self)?)
    }

    /// Parse an envelope from JSON and verify its checksum.
    pub fn from_json(json: &str) -> anyhow::Result<Self> {
        let envelope: Envelope =
            serde_json::from_str(json).context("failed to parse transaction envelope")?;
        envelope.verify()?;
        Ok(envelope)
    }
}

/// A detached signature bundle produced by `tx sign --offline`.
///
/// It carries the signed envelope XDR plus the checksum of the envelope it
/// was produced from, so `tx submit` can confirm it is assembling the
/// signature onto the exact envelope that was reviewed offline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureBundle {
    /// Bundle format version; must equal [`BUNDLE_VERSION`].
    pub version: u32,
    /// Checksum of the [`Envelope`] this bundle signs.
    pub envelope_checksum: String,
    /// Base64 signed transaction envelope XDR.
    pub signed_xdr: String,
    /// Hex transaction hash of the signed envelope.
    pub tx_hash: String,
    /// Hex-encoded decorated signatures, for inspection/audit.
    pub signatures: Vec<String>,
    /// Hex SHA-256 over the canonical encoding of all fields above.
    pub checksum: String,
}

impl SignatureBundle {
    /// Build a bundle from a signed envelope, computing its checksum.
    pub fn new(
        envelope_checksum: impl Into<String>,
        signed_xdr: impl Into<String>,
        tx_hash: impl Into<String>,
        signatures: Vec<String>,
    ) -> Self {
        let mut bundle = SignatureBundle {
            version: BUNDLE_VERSION,
            envelope_checksum: envelope_checksum.into(),
            signed_xdr: signed_xdr.into(),
            tx_hash: tx_hash.into(),
            signatures,
            checksum: String::new(),
        };
        bundle.checksum = bundle.checksum();
        bundle
    }

    /// Hex SHA-256 over the canonical encoding of every field except
    /// `checksum`.
    pub fn checksum(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.version.to_le_bytes());
        hash_field(&mut hasher, &self.envelope_checksum);
        hash_field(&mut hasher, &self.signed_xdr);
        hash_field(&mut hasher, &self.tx_hash);
        hasher.update((self.signatures.len() as u64).to_le_bytes());
        for sig in &self.signatures {
            hash_field(&mut hasher, sig);
        }
        hex::encode(hasher.finalize())
    }

    /// Recompute the checksum and reject the bundle if it does not match.
    pub fn verify(&self) -> anyhow::Result<()> {
        if self.version != BUNDLE_VERSION {
            bail!(
                "unsupported signature bundle version {} (expected {BUNDLE_VERSION})",
                self.version
            );
        }
        let expected = self.checksum();
        if !constant_time_eq(expected.as_bytes(), self.checksum.as_bytes()) {
            bail!(
                "signature bundle checksum mismatch: expected {expected}, found {}",
                self.checksum
            );
        }
        Ok(())
    }

    /// Serialize to a single-line JSON string.
    pub fn to_json(&self) -> anyhow::Result<String> {
        Ok(serde_json::to_string(self)?)
    }

    /// Parse a bundle from JSON and verify its checksum.
    pub fn from_json(json: &str) -> anyhow::Result<Self> {
        let bundle: SignatureBundle =
            serde_json::from_str(json).context("failed to parse signature bundle")?;
        bundle.verify()?;
        Ok(bundle)
    }

    /// Assemble the signed envelope for submission, confirming that the
    /// bundle signs `envelope` and that the resulting transaction hash
    /// matches the one recorded in the bundle.
    pub fn assemble(&self, envelope: &Envelope, passphrase: &str) -> anyhow::Result<String> {
        self.verify()?;
        envelope.verify()?;
        if self.envelope_checksum != envelope.checksum {
            bail!(
                "signature bundle signs envelope {}, but the supplied envelope is {}",
                self.envelope_checksum,
                envelope.checksum
            );
        }
        let actual = tx_hash(&self.signed_xdr, passphrase)?;
        if actual != self.tx_hash {
            bail!(
                "signed envelope hash {actual} does not match bundle hash {}",
                self.tx_hash
            );
        }
        Ok(self.signed_xdr.clone())
    }
}

/// Feed a length-prefixed field into `hasher` so concatenation is unambiguous.
fn hash_field(hasher: &mut Sha256, field: &str) {
    hasher.update((field.len() as u64).to_le_bytes());
    hasher.update(field.as_bytes());
}

/// Compare two byte slices without early exit.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Extract the hex-encoded decorated signatures from a signed envelope.
pub fn envelope_signatures(envelope_b64: &str) -> anyhow::Result<Vec<String>> {
    let envelope = TransactionEnvelope::from_xdr_base64(envelope_b64, Limits::none())?;
    let signatures: &[DecoratedSignature] = match &envelope {
        TransactionEnvelope::Tx(v1) => &v1.signatures,
        TransactionEnvelope::TxV0(v0) => &v0.signatures,
        TransactionEnvelope::TxFeeBump(fb) => &fb.signatures,
    };
    Ok(signatures
        .iter()
        .map(|sig| hex::encode(sig.signature.0.as_slice()))
        .collect())
}

/// Attach a detached signature (hex) to an unsigned envelope, producing a
/// signed envelope XDR. Used by `tx sign --offline` when assembling the
/// bundle from a raw signature.
pub fn attach_signature(
    envelope_b64: &str,
    hint: [u8; 4],
    signature_hex: &str,
) -> anyhow::Result<String> {
    let mut envelope = TransactionEnvelope::from_xdr_base64(envelope_b64, Limits::none())?;
    let bytes = hex::decode(signature_hex).context("signature is not valid hex")?;
    let decorated = DecoratedSignature {
        hint: stellar_xdr::SignatureHint(hint),
        signature: Signature(bytes.try_into().map_err(|_| {
            anyhow::anyhow!("signature must be exactly 64 bytes, got {}", signature_hex.len() / 2)
        })?),
    };
    match &mut envelope {
        TransactionEnvelope::Tx(v1) => v1.signatures.push(decorated),
        TransactionEnvelope::TxV0(v0) => v0.signatures.push(decorated),
        TransactionEnvelope::TxFeeBump(fb) => fb.signatures.push(decorated),
    }
    Ok(envelope.to_xdr_base64(Limits::none())?)
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

        rpc.envelope = Some(signed);
        let mut client = FailoverClient::new(vec![Box::new(rpc)], RetryPolicy::default());
        let mut log = RecoveryLog::new();
        let result = client.submit_with_bounds(&tx_hash, &bounds, &mut log);
        for line in log.lines() {
            eprintln!("  {line}");
        }
        match result {
            RecoveryResult::Accepted { ledger, .. } => {
                println!("Transaction {tx_hash} succeeded in ledger {ledger}");
                return Ok(());
            }
            RecoveryResult::RejectedOnChain { reason } => {
                bail!("transaction {tx_hash} failed on-chain: {reason}")
            }
            RecoveryResult::Expired { latest_ledger, .. } if attempt < MAX_REBUILDS => {
                eprintln!(
                    "Transaction {tx_hash} expired (ledger {latest_ledger} > {max_ledger}); it can never be included -- rebuilding"
                );
            }
            RecoveryResult::Expired { latest_ledger, .. } => {
                bail!("transaction {tx_hash} expired at ledger {latest_ledger} after {MAX_REBUILDS} rebuilds; nothing was applied")
            }
            RecoveryResult::SequenceConsumed { consumed_by } => bail!(
                "sequence {} of {} was consumed by {}; transaction {tx_hash} can never be included. Check whether that transaction already made this change before retrying.",
                bounds.sequence,
                bounds.source_account,
                consumed_by.as_deref().unwrap_or("another transaction")
            ),
            RecoveryResult::ExhaustedNeedsOperator { last_known } => bail!(
                "could not determine the outcome of {tx_hash} (last known: {last_known:?}); see docs/runbooks/rpc-outage-recovery.md"
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

    fn sample_envelope() -> Envelope {
        Envelope::new(
            "Test SDF Network ; September 2015",
            Some("CABC".to_string()),
            1000,
            42,
            "GABC",
            "AAAAAA==",
            "invoke add_attester(GBOB)",
        )
    }

    #[test]
    fn envelope_round_trips_through_json() {
        let envelope = sample_envelope();
        let json = envelope.to_json().unwrap();
        let parsed = Envelope::from_json(&json).unwrap();
        assert_eq!(parsed, envelope);
    }

    #[test]
    fn envelope_tampering_is_detected() {
        let mut envelope = sample_envelope();
        envelope.max_ledger += 1;
        assert!(envelope.verify().is_err());
    }

    #[test]
    fn envelope_network_swap_is_detected() {
        let mut envelope = sample_envelope();
        envelope.network_passphrase = "Public Global Stellar Network ; September 2015".to_string();
        assert!(envelope.verify().is_err());
    }

    #[test]
    fn envelope_expiry_is_enforced() {
        let envelope = sample_envelope();
        assert!(envelope.verify_for_signing(1000).is_ok());
        assert!(envelope.verify_for_signing(1001).is_err());
    }

    #[test]
    fn envelope_rejects_unknown_version() {
        let mut envelope = sample_envelope();
        envelope.version = ENVELOPE_VERSION + 1;
        envelope.checksum = envelope.checksum();
        assert!(envelope.verify().is_err());
    }

    #[test]
    fn bundle_round_trips_and_detects_tampering() {
        let bundle = SignatureBundle::new("abc", "AAAAAA==", "deadbeef", vec!["00".into()]);
        let json = bundle.to_json().unwrap();
        assert_eq!(SignatureBundle::from_json(&json).unwrap(), bundle);

        let mut tampered = bundle.clone();
        tampered.tx_hash = "cafebabe".to_string();
        assert!(tampered.verify().is_err());
    }

    #[test]
    fn assemble_rejects_bundle_for_a_different_envelope() {
        let envelope = sample_envelope();
        let bundle = SignatureBundle::new("not-the-checksum", "AAAAAA==", "deadbeef", vec![]);
        assert!(bundle.assemble(&envelope, "Test SDF Network ; September 2015").is_err());
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
