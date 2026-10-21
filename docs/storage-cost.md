# Storage Cost Benchmarks

This document tracks the resource-regression guard for the attester allowlist as it scales.

## Enforced checkpoints

`large_attester_allowlist_load` records the budget of `add_attester` after the
allowlist reaches each checkpoint and fails if either ceiling is exceeded.

| Operation | Attesters | Maximum CPU instructions | Maximum memory bytes |
|---|---:|---:|---:|
| `add_attester` | 10 | 2,000,000 | 1,000,000 |
| `add_attester` | 100 | 2,000,000 | 1,000,000 |
| `add_attester` | 1,000 | 2,000,000 | 1,000,000 |

## Methodology

The test initializes `attester-registry`, adds 1,000 distinct addresses, and
reads `Budget::cpu_instruction_cost` and `Budget::memory_bytes_cost` immediately
after additions 10, 100, and 1,000. Soroban resets metering before each
top-level invocation, so each checkpoint measures one `add_attester` call with
the allowlist at that size. This catches a size-dependent scan without conflating
the result with the cost of populating the preceding entries.

These are native-test regression measurements, not fee estimates. Native
registration omits Wasm execution, transaction-envelope processing, and some
ledger work, so the values must not be used to predict production fees.

Run the test and print its measured values with:

```sh
cargo test -p attester-registry large_attester_allowlist_load -- --nocapture
```

Last source verification: contract commit `82f7473`, with `soroban-sdk 27.0.0`
from the workspace lockfile. Update this reference and review the ceilings
whenever contract behavior or the pinned SDK cost model changes.

## Attestation rate limiting

`attestation-registry` can cap how many attestations each attester records
per window (`set_attestation_rate_limit(max_per_window, window_ledgers)`),
with per-attester overrides for high-volume clinical sites
(`set_attester_rate_limit` / `remove_attester_rate_limit`). This bounds the
blast radius of a compromised or fraudulent attester key: it limits how many
persistent attestation entries (and their rent) one key can create before it
is caught, and how many must be revoked afterwards.

### Storage

| Key | Storage | Lifetime |
|---|---|---|
| `RateLimit` | instance | Until changed by the admin |
| `RateLimitOverride(attester)` | persistent | Extended to 90 days on write |
| `RateWindow(attester)` → `{ window_start_ledger, count }` | temporary | TTL set to the remaining ledgers in the window |

The window counter uses **temporary** storage. It is cheaper than persistent
storage, it expires on its own when the window ends so nothing needs cleaning
up, and it is never restored from archival. If the entry expires before its
window ends, the next `attest` finds no window and starts a fresh one, so the
limiter **fails open**. That is acceptable for rate limiting. At worst an
attester gets one extra window's worth of attestations, and the allowlist and
revocation remain the real controls. Windows are capped at 30 days of
ledgers (`InvalidRateLimit` otherwise) so the entry's TTL always fits within
the network's maximum entry TTL.

### Budget

Measured with `env.cost_estimate().budget()` on the second `attest` by the
same attester (in-process `soroban-sdk` 27 test host):

| `attest` | CPU instructions | Memory bytes |
|---|---|---|
| Rate limiting disabled (default) | 268,515 | 107,366 |
| Rate limiting enabled | 362,594 | 139,568 |
| Added cost | +94,079 (~35%) | +32,202 |

The added cost is one instance read of `RateLimit`, one persistent read of the
override, one temporary read and write of `RateWindow`, and one TTL extension.
With rate limiting disabled, the only extra work is one read of `RateLimit`
from the already loaded instance storage.

### Default limits

Rate limiting is **off** until the admin configures it, so an upgrade does not
change existing behaviour. No pilot or load-campaign data exists yet. Until it
does, the recommended starting configuration is:

```text
set_attestation_rate_limit(max_per_window = 100, window_ledgers = 17_280)  # 100 per attester per ~24h
```

A CHW verifying records by hand in the field is unlikely to exceed a few dozen
attestations a day. 100 per day leaves headroom for busy clinic days, while
capping a compromised key at about 100 bad entries per day instead of
thousands per hour. Give clinical sites with known higher volume an override
rather than raising the global limit. Revisit these numbers once pilot data
is available.

### Watchdog integration

`RateLimitHit { attester, retry_after_ledger }` is published on the
attestation that **fills** an attester's window, so it appears at most once
per attester per window and cannot be used to spam. Attempts after that fail
with `RateLimited` (error `10`). Failed invocations publish no events, so the
watchdog alerts on the event and not on failures. Call
`get_rate_limit_retry_after(attester)` to get the ledger at which the
attester may attest again.

Recommended watchdog rules (for the event indexer described in
[`architecture/event-indexing.md`](architecture/event-indexing.md)):

- **Warn** on any `RateLimitHit`: an attester reached its daily cap.
- **Page** when the same attester hits the limit in two consecutive windows,
  or when three or more distinct attesters hit it within one window. Both
  suggest key compromise or scripted incentive farming. Consider
  `suspend_attester` on `attester-registry` and review that attester's
  recent `AttestationRecorded` events.
- **Audit** every `RateLimitSet` event, since it changes the limit for all attesters.

## Incentive pool

### Persistent TTL policy

All `incentive-pool` persistent entries use the same policy as instance
storage and `attester-registry`: extend to 90 days (1,555,200 ledgers)
whenever fewer than 30 days (518,400 ledgers) remain.

| Key | Written by | Extended by (who pays) |
|---|---|---|
| `WorkItem(id)` | approve / execute | approver on approval; claimant on claim; anyone via `bump_work_item(id)` |
| `WorkItemProgramme(id)` | approve / execute | approver; `bump_work_item(id)` |
| `WorkItemClaimed(id)` | claim | claimant; `bump_work_item(id)` |
| `AttesterTotalClaimed(attester)` | claim | claimant on every claim |
| `Proposal(id)` | propose / endorse | proposer and each endorser; removed on execute |
| `ApproverWindow(approver)` | approve / propose / endorse | the approver |
| `ProgrammeBalance(p)`, `DonorContributed(d)`, `DonorProgramme(d, p)` | `fund_for`, `refund_programme`, claim | the writer |

`bump_work_item(id)` is permissionless so a long-lived approval (e.g. an
attester who claims months later) can be kept live by the attester,
programme operator, or a keeper.

### Archival safety argument

Soroban never deletes an expired **persistent** entry; it is archived. Any
later read or write of an archived key fails the invocation until the entry
is restored (explicitly via `RestoreFootprint`, or automatically on protocol
23+), and restoration brings back the *original* value. Consequently:

- An archived `WorkItem(id)` makes `claim` fail rather than see "not
  approved", and `approve_work_item` cannot re-approve it because the
  `has()` check also touches the archived key. No double approval.
- An archived `WorkItemClaimed(id)` cannot be read as `false`; replay is
  impossible.
- An archived `AttesterTotalClaimed(attester)` cannot be recreated at `0`,
  because `claim` reads it before writing; no code path resets a cap.
- An archived `ProgrammeBalance` likewise cannot be re-created at zero and
  re-funded inconsistently; reconciliation via `get_funding_totals` uses
  instance-stored aggregates.

TTL extension is therefore a liveness measure (avoids restore fees and
failed claims), not a safety requirement. Temporary storage is deliberately
not used for any of these keys, because expired temporary entries *are*
deleted and could be recreated.

### Storage cost per approval

| Mode | New persistent entries | Notes |
|---|---:|---|
| Single approver, unallocated | 1 (`WorkItem`) + 1 updated `ApproverWindow` | `ApproverWindow` is created once per approver and reused |
| Single approver, programme | 2 (`WorkItem`, `WorkItemProgramme`) + `ApproverWindow` | |
| Quorum M-of-N | `WorkItem` (+ `WorkItemProgramme`) + transient `Proposal` | `Proposal` holds ≤ N addresses and is removed on execute |
| Claim | 1 (`WorkItemClaimed`) + updated `AttesterTotalClaimed` | |

Budget baseline: add `approve_work_item`, `execute_work_item` (M = 3) and
`claim` to the native budget checkpoints above with the same 2,000,000 CPU /
1,000,000 memory-byte ceilings; none of them scale with pool history.

### Per-approver rate limits

`set_rate_limit(window_seconds, max_count, max_value)`; default 86,400 s,
100 approvals, value bounded only by `MaxPerClaim × max_count`. Each
approver has **one** fixed-window counter (`ApproverWindow`) that resets
when `window_start + window_seconds` passes, so storage is O(approvers),
never O(approvals). A fixed window allows at most 2× the limit across a
window boundary; this is accepted in exchange for constant storage.

Every single-approver approval, quorum proposal, and endorsement is charged
to the signing approver. `ApproverRateLimitHit` is published on the
approval that **fills** the window (count or value); later attempts fail
with `ApproverRateLimited` (error `24`) and publish nothing.

**Enforcement order with epoch budgets:** per-approver rate limit is checked
first (bounds a single compromised key), then the pool-wide epoch budget
(bounds aggregate spend). A rejected approval therefore never consumes
epoch budget, and an exhausted epoch never hides a key that is approving
abnormally — the rate-limit event still fires.

### Watchdog rules (proposal)

Implemented in `crates/lafiya-watchdog/src/rules.rs` default rules:

- `approver_reconfigured` (**critical**): `approver_set_changed`, `rate_limit_set`.
- `approver_rate_limit_hit` (**high**): any `approver_rate_limit_hit`.
  Page when the same approver hits it in consecutive windows or when two
  or more approvers hit it in one window; consider `pause`.
- `work_item_endorsement` (**info**): `work_item_proposed`,
  `work_item_endorsed`; operators can alert when endorsements for one work
  item arrive within seconds of each other from the same source.
