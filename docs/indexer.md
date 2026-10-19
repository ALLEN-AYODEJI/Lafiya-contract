# Event Indexer: Deployment Guide

`crates/lafiya-indexer` is the reference indexer for the Lafiya contracts. It
keeps a durable, queryable copy of contract history that contract storage
does not hold and Soroban RPC only retains for a short window (about 7 days
by default). The design rationale is in
[`architecture/event-indexing.md`](architecture/event-indexing.md); event
schemas are in [`events.md`](events.md).

## What it does

| Component | Behaviour |
|---|---|
| **Ingestion** | Polls `getEvents` for the two registry contract IDs. Each page is applied in one Postgres transaction together with the new cursor, so a crash either keeps or discards the whole page, and events already stored are never applied twice. |
| **Retention guard** | Before every page, compares the resume ledger with the RPC's `oldestLedger` (`getHealth`). If history has been pruned past the checkpoint, the process **exits non-zero** with a `retention gap` error naming the missing ledger range. It never skips ahead. |
| **Backfill** | `lafiya-indexer backfill` loads archived events for ranges RPC no longer serves (see below). |
| **Storage** | `raw_events` (append-only audit copy with ledger and tx hash; UPDATE/DELETE are rejected by a trigger), `attesters`, `attestations`, `revocations`, `admin_events`, `checkpoints`. Migrations run automatically on start (sqlx). |
| **Reconciler** | Every `LAFIYA_RECONCILE_INTERVAL_SECS`, samples attesters and records and compares derived state with `get_attester_status` / `get_attestation` (via `simulateTransaction`). Mismatches are logged and counted in metrics. It also fills in region and license hash after `AttesterInfoUpdated`, which carries no data. |
| **API** | Read-only HTTP/JSON, keyset-paginated. Spec: `crates/lafiya-indexer/openapi.yaml`, also served at `/openapi.yaml`. |

### Attester lifecycle

The attester registry stores allowlist membership and suspension
independently, and the indexer mirrors that:

| Event | `allowlisted` | `suspended` | Region / license |
|---|---|---|---|
| `attester_added` | true | unchanged | cleared |
| `attester_suspended` | unchanged | true | unchanged |
| `attester_reinstated` | unchanged | false | unchanged |
| `attester_removed` | false | false | unchanged |
| `attester_info_updated` | unchanged | unchanged | re-read from chain |

`status` is `removed` when not allowlisted, else `suspended` when suspended,
else `active`. Re-adding a suspended attester therefore leaves it
`suspended`, matching the contract.

### Attestations

Each `attestation_recorded` is one row. The record's current attestation is
the latest one not revoked; `attestation_revoked` marks all earlier rows
revoked, because `revoke_attestation` deletes the record's whole on-chain
history.

## API

| Endpoint | Query parameters |
|---|---|
| `GET /attesters` | `region`, `status` (`active` / `suspended` / `removed`), `limit`, `cursor` |
| `GET /attestations` | `attester`, `record_hash`, `limit`, `cursor` |
| `GET /records/{hash}/history` | `limit`, `cursor` |
| `GET /health` | Returns 200 with checkpoint and lag, 503 if Postgres is unreachable. |
| `GET /metrics` | Prometheus text format. |
| `GET /openapi.yaml` | OpenAPI 3 spec. |

List responses are `{ "items": [...], "next_cursor": "..." | null }`; pass
`next_cursor` as `cursor` to get the next page. `limit` defaults to 50 (max 500).

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `DATABASE_URL` | required | Postgres connection string. |
| `LAFIYA_RPC_URL` | required | Soroban RPC endpoint. |
| `LAFIYA_ATTESTER_REGISTRY` | required | `C...` contract ID. |
| `LAFIYA_ATTESTATION_REGISTRY` | required | `C...` contract ID. |
| `LAFIYA_START_LEDGER` | none | First ledger to ingest on an empty database: the ledger the contracts were deployed in. Ignored once a checkpoint exists. |
| `LAFIYA_LISTEN` | `0.0.0.0:8080` | API listen address. |
| `LAFIYA_POLL_INTERVAL_SECS` | `5` | Delay between polls once caught up. |
| `LAFIYA_PAGE_LIMIT` | `200` | `getEvents` page size. |
| `LAFIYA_RECONCILE_INTERVAL_SECS` | `300` | Reconciliation period. |
| `LAFIYA_RECONCILE_SAMPLE` | `50` | Attesters and records sampled per cycle. |
| `LAFIYA_RECONCILE_MAX_LAG` | `2` | Skip the sample while ingestion lags more ledgers than this, so in-flight changes are not reported as mismatches. |
| `LAFIYA_RETENTION_OPERATIONAL_DAYS` | `30` | Prune derived/operational rows (delivery attempts, dead letters, request logs) older than this. `0` disables pruning. |
| `LAFIYA_RETENTION_PRUNE_INTERVAL_SECS` | `3600` | How often the pruning job runs. |
| `LAFIYA_WEBHOOK_SECRET` | none | HMAC-SHA256 key for webhook signatures. Required to enable webhook delivery. |
| `LAFIYA_WEBHOOK_MAX_ATTEMPTS` | `8` | Delivery attempts before a webhook is moved to the dead-letter table. |
| `RUST_LOG` | `info` | Log filter. |

## Running

The published image is built from `crates/lafiya-indexer/Dockerfile` on a
distroless runtime, runs as a non-root user (UID 65532), and expects a
read-only root filesystem. It writes nothing to disk: all state lives in
Postgres, so the only writable mounts needed are a `tmpfs` at `/tmp`.

```sh
docker build -f crates/lafiya-indexer/Dockerfile -t lafiya-indexer .

docker run -d --name lafiya-indexer -p 8080:8080 \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --user 65532:65532 \
  -e DATABASE_URL=postgres://indexer:...@db:5432/lafiya \
  -e LAFIYA_RPC_URL=https://soroban-testnet.stellar.org \
  -e LAFIYA_ATTESTER_REGISTRY=C... \
  -e LAFIYA_ATTESTATION_REGISTRY=C... \
  -e LAFIYA_START_LEDGER=<deployment ledger> \
  lafiya-indexer
```

### Docker Compose

```yaml
services:
  indexer:
    image: ghcr.io/<org>/lafiya-indexer:<version>
    read_only: true
    user: "65532:65532"
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=16m
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    environment:
      DATABASE_URL: postgres://indexer:...@db:5432/lafiya
      LAFIYA_RPC_URL: https://soroban-testnet.stellar.org
      LAFIYA_ATTESTER_REGISTRY: C...
      LAFIYA_ATTESTATION_REGISTRY: C...
    ports: ["8080:8080"]
```

### Kubernetes / Helm

```yaml
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    runAsGroup: 65532
    fsGroup: 65532
    seccompProfile: { type: RuntimeDefault }
  containers:
    - name: indexer
      image: ghcr.io/<org>/lafiya-indexer:<version>
      securityContext:
        readOnlyRootFilesystem: true
        allowPrivilegeEscalation: false
        capabilities: { drop: ["ALL"] }
      volumeMounts:
        - { name: tmp, mountPath: /tmp }
  volumes:
    - name: tmp
      emptyDir: { medium: Memory, sizeLimit: 16Mi }
```

The image contains no shell, so `kubectl exec` debugging is not available;
use logs and `/metrics` instead.

### Verifying the published image

Every release image is signed with cosign keyless (Sigstore Fulcio/Rekor),
and ships a CycloneDX SBOM and SLSA provenance attestations. Verification
is exercised in CI against the published image on each release.

```sh
IMAGE=ghcr.io/<org>/lafiya-indexer@sha256:<digest>

# Signature, pinned to this repository's workflow identity
cosign verify "$IMAGE" \
  --certificate-identity-regexp '^https://github.com/<org>/<repo>/\.github/workflows/.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# CycloneDX SBOM
cosign download attestation "$IMAGE" \
  --predicate-type https://cyclonedx.org/bom | jq -r '.payload' | base64 -d | jq .

# SLSA provenance
cosign download attestation "$IMAGE" \
  --predicate-type https://slsa.dev/provenance/v1 | jq -r '.payload' | base64 -d | jq .

# Vulnerability scan gate (exceptions require justification in
# .github/trivy-exceptions.yaml)
trivy image --exit-code 1 --severity HIGH,CRITICAL "$IMAGE"
```

Always deploy by digest, not tag. Image size and CVE counts are reported on
each release.

Run one replica. Two replicas would not corrupt state, because pages and
checkpoints are transactional and idempotent, but they duplicate RPC load.
Use a restart policy (`--restart on-failure` or a Kubernetes Deployment), but
**alert on a retention-gap exit rather than letting it crash-loop silently**:
restarts cannot fix it, only a backfill can.

### Operations checklist

- Keep downtime well under the RPC retention window. The indexer resumes
  from its checkpoint after any restart shorter than that.
- Use a Postgres backup policy that matches your audit needs. `raw_events`
  is the authoritative audit copy.
- Point `/health` at your liveness probe.

### Metrics and alerts

Metric names are stable; see [`observability.md`](observability.md) for the
full SLI/SLO definitions, recording rules and alert runbooks.

| Metric | SLI / SLO | Suggested alert |
|---|---|---|
| `lafiya_indexer_lag_ledgers` | Ingestion lag ≤ 60 ledgers for 99% of the time | > 60 for 5 minutes (about 5 minutes behind). |
| `lafiya_indexer_lag_seconds` | Ingestion lag ≤ 300s for 99% of the time | > 300 for 5 minutes. |
| `lafiya_indexer_checkpoint_age_seconds` | Checkpoint age ≤ 600s for 99% of the time | > 600 for 5 minutes. |
| `lafiya_indexer_api_errors_total` / `lafiya_indexer_api_requests_total` | API error ratio < 1% over 5 minutes | `rate(...errors[5m]) / rate(...requests[5m]) > 0.01`. |
| `lafiya_indexer_api_request_duration_seconds` | p99 latency < 500ms | p99 > 500ms for 10 minutes. |
| `rate(lafiya_indexer_events_total[1m])` | Events per second, for dashboards. | — |
| `lafiya_indexer_ingest_errors_total` | Increasing steadily (RPC or database problems; retried with backoff). | — |
| `lafiya_indexer_reconcile_mismatches_total{kind}` | Any sustained increase: derived state disagrees with chain. | Any increase over 15 minutes. |
| `lafiya_indexer_webhook_dead_letters_total` | Any increase: a subscriber is not receiving events. | Any increase. |
| `lafiya_indexer_checkpoint_ledger` | Not advancing. | — |
| process exit with `retention gap` | Page immediately: backfill needed. | — |

Labels never carry record hashes or addresses; see the data inventory in
[`compliance/`](compliance/) for the classification of every stored column
and log field.

## Push delivery (SSE and webhooks)

Integrators can subscribe instead of polling. Both transports are
**at-least-once**: consumers must deduplicate on the event `id` (the RPC
event id), which is stable across retries and replays.

### Server-sent events

`GET /events/stream` streams events as they are ingested. Filters:
`contract` (contract ID), `event_type`, `attester`. Resume with the standard
`Last-Event-ID` header (or `?last_event_id=`); the server maps it to the
ledger/event index and replays everything after it, so a reconnect never
skips or duplicates beyond the at-least-once guarantee.

### Webhooks

Register a subscription with `POST /subscriptions` (URL, filters, optional
secret override). Each delivery is signed:

```
X-Lafiya-Signature: sha256=<hex HMAC-SHA256 of the raw body using LAFIYA_WEBHOOK_SECRET>
X-Lafiya-Event-Id: <event id>
```

Verify the signature over the raw request body before parsing. Failed
deliveries are retried with exponential backoff up to
`LAFIYA_WEBHOOK_MAX_ATTEMPTS`, then moved to the `webhook_dead_letters`
table; inspect and replay them with `lafiya-indexer webhooks dead-letters`
and `lafiya-indexer webhooks replay <id>`. Replays are idempotent because
consumers key on the event id. Delivery semantics are covered by a
fault-injection test in CI.

## Retention and pruning

The index stores only public chain data plus operational tables (delivery
attempts, dead letters, request logs). The data inventory in
[`compliance/`](compliance/) classifies every column and log field; a test
fails if a new column lacks a classification. The pruning job deletes
operational rows older than `LAFIYA_RETENTION_OPERATIONAL_DAYS`; it is
idempotent and takes short row-level locks so ingestion is not blocked.
`raw_events` is never pruned.

## Backfill from archived history

**Chosen source:** the
[Stellar Hubble](https://developers.stellar.org/docs/data/analytics/hubble)
public BigQuery dataset. It is derived from full ledger history (via Galexie
and stellar-etl) and exposes contract events with their XDR topics and data.
Any archive works if it can be exported in the format below: a Galexie data
lake processed with `stellar-etl`, or a captive-core history source.

The `backfill` command reads **newline-delimited JSON** where each line is a
`getEvents` event object:

```json
{"id":"0000000429496733696-0000000000","ledger":100,"ledgerClosedAt":"2026-01-01T00:00:00Z","contractId":"C...","txHash":"...","topic":["<base64 ScVal>", "..."],"value":"<base64 ScVal>","inSuccessfulContractCall":true}
```

`id` must be the RPC event id (`<19-digit TOID>-<10-digit event index>`),
which sorts in chain order. When exporting from Hubble, filter on the two
contract IDs and on successful contract events, then map the table's ledger,
transaction and operation columns into this shape. Check the column names
against the current Hubble schema.

Procedure:

1. Export all events for the two contracts from the deployment ledger up to
   a ledger `N` that RPC still retains (`oldestLedger` from `getHealth`).
2. On an empty database (or one whose checkpoint is before the export's
   first ledger), run:

   ```sh
   lafiya-indexer backfill --file events.ndjson --through-ledger N
   ```

   `--through-ledger` declares the export complete through ledger `N`, so
   live ingestion resumes at `N + 1`. Without it, ingestion resumes right
   after the last exported event.
3. Start `lafiya-indexer run`. If `N + 1` has already been pruned by RPC, it
   exits with a retention-gap error: export a later `N` and repeat.

The backfill refuses to run behind an existing checkpoint, because derived
state must be built in chain order. To rebuild from scratch, drop the
database and backfill again.

## Tests

```sh
# Unit tests (no database needed)
cargo test -p lafiya-indexer

# Database tests: restart/resume, retention-gap, backfill, API
DATABASE_URL=postgres://postgres:pg@localhost:5432/postgres cargo test -p lafiya-indexer

# End to end against a local quickstart (deploys contracts, drives a scenario,
# indexes it, and asserts the API equals contract state)
docker run -d -p 8000:8000 stellar/quickstart:testing --local --enable rpc
DATABASE_URL=postgres://postgres:pg@localhost:5432/postgres crates/lafiya-indexer/tests/e2e.sh
```

Database tests create an isolated schema per test and are skipped when
`DATABASE_URL` is unset.
