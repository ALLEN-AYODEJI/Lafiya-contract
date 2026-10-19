# Patient linkability through public record-hash activity

- **Status:** Analysis
- **Decision:** [ADR-0012](../adr/0012-per-attestation-blinded-commitments.md)
- **Proof of concept:** [`scripts/poc/linkability_poc.py`](../../scripts/poc/linkability_poc.py)

Lafiya keeps only hashes on-chain ([ADR-0001](../adr/0001-hash-only-on-chain-footprint.md))
and salts *record commitments* ([ADR-0008](../adr/0008-record-commitment-canonicalization.md)).
That hides record **contents**, but the **pattern** of on-chain activity around a
commitment still leaks information. This document quantifies each leak and evaluates
mitigations.

## Threat model

- **Observer:** anyone who can read the public ledger (block explorer, indexer, RPC).
- **Side knowledge:** the observer may have scanned a patient's card once (a clinic
  worker, a checkpoint, anyone shown the QR code), and knows which region or facility
  each *attester* address belongs to (attester addresses are public and often discoverable).
- **Goal:** link on-chain events to a person and learn their movements, visit timing,
  record history, or a *CHW*'s workload.

## Channels

Severity: **High** = one card scan is enough to track a person over time; **Medium** =
needs extra side knowledge or reveals aggregate data; **Low** = small marginal leak.

| # | Channel | What the observer learns | Side knowledge needed | Severity |
|---|---|---|---|---|
| 1 | **Watch a hash:** the card's `record_hash` repeats on every re-attestation and revocation (and on access-log entries, if built). | Every future and past visit to a verification point: when, and through which attester. | One card scan. | **High** |
| 2 | **Timestamps + attester region** on each attestation. | The patient's movements between regions and facilities over time. | Channel 1, plus a mapping of attester to region (often public). | **High** |
| 3 | **Supersession chains** (if built): a new record links to the one it replaces. | Links successive records of one patient, so rotating the record does not break tracking. | Any one record hash in the chain. | **Medium** (future) |
| 4 | **Attester activity stream:** all attestations by one CHW address. | How many patients a CHW verified and when; in conflict-affected areas this exposes CHW operations and patterns. | The CHW's address (public). | **Medium** |
| 5 | **Fee-payer / source account** of the submitting transaction. | Links attestations submitted from the same device or account even across attesters. | None. | **Low** |

The PoC reproduces channels 1 and 2 against a local sandbox event log: with 200 patients
and 6 visits each, a single scanned hash links all 6 of the victim's attestations and
reveals the regions visited.

## Mitigations

| Mitigation | Breaks | Cost / trade-off |
|---|---|---|
| **Per-attestation blinded commitments:** each attestation commits to `H(domain ‖ record ‖ fresh_nonce)`; the nonce is carried on the card and used during verification. | 1, 2 (no repeating hash to watch), 3 (if supersession links blinded values). | New card must be issued per attestation; revocation must target the specific blinded hash; the registry can no longer list a record's history by one key (history lives off-chain with the patient). |
| **Card-scoped rotating identifiers** in the QR code. | Linking across cards if the QR identifier is not the on-chain key. | Only helps if the on-chain key also rotates; alone it just moves the linkable value. Needs a resolver service, which becomes a tracking point. |
| **Batch anchoring** (Merkle roots of many attestations). | 2 partly (timing hidden inside the batch window); 4 partly. | Verification needs a Merkle proof on the card; revocation needs a separate structure; latency equals the batch window; significant contract changes. |
| **Relayed submission** through a shared relayer account. | 5 (source account). | Operates a relayer (availability, fees, trust); does **not** hide the attester address inside the attestation. |
| **Coarse timestamps** (rounded to the day). | 2 partly (fine-grained timing). | Weakens compromise windows ("attested after T") to day precision; ledger close time is still public at the transaction level, so it only helps together with batching. |

## Recommendation

Adopt **per-attestation blinded commitments** (ADR-0012) as the primary mitigation: it
removes the highest-severity channel (watch a hash) with a contained change to the commitment
format and no new infrastructure. The PoC shows the attack linking 1 event instead of 6.
Pair it with relayed submission later for channel 5, and track batch anchoring as a
research item for channels 2 and 4.

## Indexer query surface as a probing oracle

The public indexer API (`crates/lafiya-indexer/src/api.rs`) exposes
`/attesters`, `/attestations`, and `/records/{hash}/history`. The history endpoint is a
direct instance of channel 1: anyone holding a `record_hash` (from one card scan, or by
scraping hashes out of the ledger) can query it to enumerate every attestation tied to
that record, and can sweep candidate hashes to confirm which ones exist. Even without
the history endpoint, the ability to test "does this hash have activity?" is a
linkability oracle, so the query surface must be treated as part of the threat model,
not just the ledger.

### Guidance for operators

- **Do not expose the indexer directly.** Put it behind a reverse proxy that terminates
  TLS, enforces its own connection limits, and forwards a trustworthy client IP
  (`X-Forwarded-For` handling must be configured so the indexer sees the real peer, not
  a spoofable header). The indexer's own limits are a backstop, not the only control.
- **Keep the history endpoint private by default.** `/records/{hash}/history` should be
  reachable only by authenticated clients (API key) and, where possible, only from
  trusted networks. Public, unauthenticated history lookups are the highest-risk
  configuration and should require an explicit opt-in.
- **Never expose admin, metrics, or debug endpoints** (health detail, config dumps,
  raw DB access) on the public listener; bind them to a separate internal interface.
- **Defaults are safe:** rate limits and request budgets are enabled unless explicitly
  disabled in configuration. Disabling them should be a deliberate, logged action.

### Controls in the indexer

- **Token-bucket limits by IP and by API key**, with configurable tiers. Both buckets
  apply; a request is denied if either is exhausted. Limits must hold under load
  (target: no more than the configured rate sustained at 10x offered load).
- **Bounded page size** on list endpoints, with a hard maximum and a stable default, so
  a client cannot request an unbounded scan in one call.
- **Constant-shape responses** to reduce enumeration signal: a miss and a hit should be
  indistinguishable in status code, body shape, and (as far as practical) timing.
  History responses for unknown hashes return the same empty-page shape as a known hash
  with no visible entries, rather than a distinct 404.
- **Structured denial logging without cleartext hashes.** When a request is denied
  (rate limit, quota, auth failure), log a structured event with the client identity
  (hashed or truncated), the route, the reason, and a timestamp. Do **not** log the
  requested `record_hash` in cleartext; log a keyed hash or a truncated prefix so
  operators can correlate abuse without turning logs into a linkability dataset.

### Residual risk

Rate limits and constant-shape responses raise the cost of scraping but do not remove
the oracle: a patient with a known hash can still be tracked by a determined observer
who stays under the limits, and a slow sweep can still confirm hash existence. The
durable fix remains per-attestation blinded commitments (ADR-0012), which removes the
repeating hash the endpoint keys on. Until then, treat the indexer as a
sensitive service and restrict it accordingly.

## Follow-up engineering issues

1. Extend LRC-1 with a per-attestation nonce (`LRC-2`) and update `lafiya-commitment` and the CLI.
2. Carry the nonce in the card payload; update the verifier and the [verification model](../specs/verification-model.md) inputs.
3. Revocation by blinded hash, and an off-chain (patient-held) attestation history.
4. Relayed submission for attesters (channel 5).
5. Research spike: batch anchoring and CHW activity privacy (channels 2 and 4).
6. Harden the indexer query surface: API keys, per-IP/per-key token buckets, bounded page
   size, constant-shape responses, and redacted denial logging (see above).
