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
| `pool_paused` | high | Incentive pool paused or unpaused | Confirm with the admin; an unplanned pause stalls all funding and payouts, an unplanned unpause during an incident is critical |
| `large_pool_withdrawal` | high | A single withdrawal from the incentive pool exceeded `pool.large_withdrawal_threshold` | Confirm the payout was approved; check the recipient against the work item and the attester record |
| `pool_approval_burst` | high | More than `pool.approval_burst_count` approvals within `pool.approval_burst_ledgers` ledgers | Check the batch against the approved work items; bursts can indicate a compromised attester or a scripted drain |
| `claim_by_readded_attester` | critical | A pool claim came from an attester that was removed and re-added within `pool.readd_window_ledgers` ledgers | Treat as an attempt to launder a revoked attester's standing; freeze the pool and review the re-add approval |
======>>>REPLACE
<<<<<<< SEARCH
CI runs `every_critical_rule_reaches_the_webhook`, which feeds the same event
sequence through the rules and a real HTTP webhook sink into a mock server.
=======
CI runs `every_critical_rule_reaches_the_webhook`, which feeds the same event
sequence through the rules and a real HTTP webhook sink into a mock server.

## Incentive-pool rules

The pool rules read the same event stream as the registry rules; the pool
contract address is configured under `contracts` alongside the registries.
Thresholds live in the `[pool]` section of `watchdog.toml`:

| Key | Default | Meaning |
| --- | --- | --- |
| `large_withdrawal_threshold` | `10000000000` (stroops) | Withdrawals at or above this amount raise `large_pool_withdrawal` |
| `approval_burst_count` | `10` | Number of approvals that constitutes a burst |
| `approval_burst_ledgers` | `100` | Window (in ledgers) over which approvals are counted |
| `readd_window_ledgers` | `1000` | How far back to look for a remove/re-add of the claiming attester |

Tune the thresholds to the pool's normal payout size before enabling the
rules; a threshold far below typical payouts will page on every cycle. The
`claim_by_readded_attester` rule keeps a bounded in-memory history of attester
removals, so after a watchdog restart it can only flag re-adds that happened
since startup; replay over an exported event range covers the gap.
| `watchdog_lag` | critical | Watchdog is behind the network by more than `max_lag_ledgers` | Check RPC health ([rpc-outage-recovery.md](rpc-outage-recovery.md)); nothing is being watched |
| `watchdog_failing` | critical | Polls failing repeatedly | Same as above |

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
