# Runbook: Security Watchdog (`lafiya-watchdog`)

The watchdog follows privileged contract events in real time and pages on-call.
Several controls (two-step admin transfer, upgrade review, recovery delays)
only work if someone notices the first step; this is that someone.

## Deployment

1. Build: `cargo build --release -p lafiya-watchdog`.
2. Copy [`crates/lafiya-watchdog/watchdog.example.toml`](../../crates/lafiya-watchdog/watchdog.example.toml)
   to `watchdog.toml` and set `rpc_url`, `contracts`, `release_manifests`, and
   `sinks`. Keep webhook URLs and API keys out of git (template the file from
   your secret store).
3. Run it as a supervised service (systemd `Restart=always`, a Kubernetes
   Deployment with one replica, ...):

   ```bash
   lafiya-watchdog --config /etc/lafiya/watchdog.toml run
   ```

4. Configure the **dead-man's switch**: set `heartbeat.ping_url` to a
   healthchecks.io / Cronitor check with a grace period of about 5 minutes and
   route that check to the same on-call rotation. The watchdog pings only after
   healthy polls, so a crashed host, a stuck process, or a lost network all page.
5. Use a different RPC provider from the one the admin tooling uses, so one
   provider outage cannot blind both.

## Recommended on-call routing

| Severity | Sink | Response |
| --- | --- | --- |
| critical | PagerDuty / Opsgenie (P1) **and** the security channel webhook | Page immediately, 24/7 |
| high | Security channel webhook, email via `command` sink | Acknowledge within business hours |
| info | Webhook to an ops channel | No action; audit trail |

Every privileged action should be announced in the security channel before it
is submitted. An alert with no matching announcement is an incident.

## Alert types

| Kind | Severity | Meaning | First response |
| --- | --- | --- | --- |
| `admin_transferred` | critical | Admin changed on a registry | Confirm with the signer set that this was planned; if not, treat the admin as compromised, pause via the remaining authority and start incident response |
| `attester_registry_repointed` | critical | Attestation registry now trusts a different attester registry | Verify the new address against the deployment record; an unknown target means attestations can be forged |
| `upgraded` | critical | Contract wasm upgraded | Match against the announced upgrade ([contract-upgrade.md](contract-upgrade.md)) |
| `unknown_wasm_upgrade` | critical | Upgrade target hash is in no release manifest | Assume compromise until the hash is traced to a reviewed build |
| `wasm_changed_without_event` | critical | On-chain wasm hash changed with no `upgraded` event | Treat as compromise or a watchdog blind spot; investigate immediately |
| `multisig_reconfigured` | critical | Multisig signer set, threshold, or recovery changed | Confirm with every signer out of band |
| `pause_toggled` | high | Registry paused or unpaused | Confirm with the admin; unplanned unpause during an incident is critical |
| `mass_enrollment` | high | More than N attesters added within M ledgers | Check the batch against the approved attester list |
| `bulk_revocation` | info | Attestation revoked | Watch for bursts |
| `attestation_expiring` | high | An attestation's live-until ledger is within the configured horizon (default 30 days) | Notify the attester and the patient; anyone may extend it (see below) |
| `attestation_archived` | high | An attestation entry has archived (rent lapsed) | Restore it with the CLI helper (see below) and extend its TTL |
| `attestation_disputed` | high | A patient flagged an attestation as disputed | Surface the dispute to verifiers; only the attester or admin can clear it (see below) |
| `dispute_spam` | high | More than N disputes from the same signer within M ledgers | Treat as abuse; review the signer and consider admin clearing |
| `watchdog_lag` | critical | Watchdog is behind the network by more than `max_lag_ledgers` | Check RPC health ([rpc-outage-recovery.md](rpc-outage-recovery.md)); nothing is being watched |
| `watchdog_failing` | critical | Polls failing repeatedly | Same as above |

## Attestation expiry and TTL extension

Soroban entries archive when their rent lapses. Attestations backing a patient's
card must not depend on the original attester remembering to extend them, so
`extend_attestation_ttl(record_hash, extend_to)` is **permissionless**: any
caller may extend an entry up to the contract's maximum horizon. It can never
shorten a TTL or alter attestation data.

Monitoring guidance:

- The watchdog emits `attestation_expiring` for every live attestation whose
  `live_until_ledger` falls inside `attestation_expiry_horizon_ledgers`
  (default: 30 days of ledgers). Route it to the attester's contact and the
  patient's channel so either can act.
- Indexers should expose `live_until_ledger` per record hash and alert on the
  same horizon; the watchdog is a backstop, not the only signal.
- Track the rent cost per attestation at scale (see
  [storage-cost.md](../storage-cost.md)) and budget the extension spend; a
  watchdog-driven extension job should be funded and rate-limited.

### Restoring archived entries

If an entry has already archived, restore it before extending:

```bash
# Inspect the record and its current TTL state
lafiya-cli attestation show --record-hash <hash>

# Restore the archived entry (pays rent) and extend it to the horizon
lafiya-cli attestation restore --record-hash <hash> --extend-to <ledger>
```

`restore` is idempotent: it is a no-op for entries that are still live. After a
restore, re-run `show` and confirm `live_until_ledger` is past the horizon, then
record the action in the security channel.

## Disputes

A patient can flag an attestation as disputed by signing the commitment with
the patient signature scheme from the QR spec. The dispute is an overlay keyed
by `(record_hash, signer)`; it never deletes or mutates the attestation.

- Verification returns a dedicated `Disputed` state. Verifiers **must** surface
  it and must not treat a disputed attestation as valid until it is cleared.
- Clearing requires the attester or an admin; the patient cannot clear it.
- Disputes are replay-safe via domain separation in the signed payload; see
  [verification-model.md](../specs/verification-model.md).
- Disputes add a linkability signal (a patient key tied to a record hash).
  Note this in the privacy review and avoid logging dispute payloads beyond
  what the alert needs.

First response to `attestation_disputed`: confirm the signer is the patient on
the record, notify the attester, and follow the responder guidance in the
verification model. For `dispute_spam`, escalate to the admin for review.

## Replay (forensics)

Evaluate the same rules over a historical range; alerts print as JSON lines and
are only sent with `--send`:

```bash
lafiya-watchdog --config watchdog.toml replay --from 1200000 --to 1210000
lafiya-watchdog --config watchdog.toml replay --events exported-events.jsonl
```

RPC retains events for a limited window (about 7 days on public providers);
older ranges need an archive RPC or an indexer export.

## Testing against a local quickstart

```bash
stellar container start local
# deploy the registries, then run admin transfer, upgrade, and repoint once each
LAFIYA_WATCHDOG_RPC=http://localhost:8000/rpc \
LAFIYA_WATCHDOG_CONTRACTS=C...,C... \
cargo test -p lafiya-watchdog -- --ignored live_quickstart_scenario
```

CI runs `every_critical_rule_reaches_the_webhook`, which feeds the same event
sequence through the rules and a real HTTP webhook sink into a mock server.
