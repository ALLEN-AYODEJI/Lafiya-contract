# Observability: logs, traces, and the operation audit trail

## Structured logs

`lafiya-cli` logs through `tracing` to **stderr**, so command output on stdout
(`config env`, `auth decode --format json`) stays pipeable.

| Flag / env | Effect |
| --- | --- |
| `--log-format text` (default) | Human-readable lines |
| `--log-format json` | One JSON object per event, with the current span and span list |
| `-v` / `-vv` | `debug` / `trace` |
| `LAFIYA_LOG=<filter>` | Full `EnvFilter` syntax, overrides `-v` |

Mutating commands run inside an `operation` span (`command`, `network`,
`contract`, `function`) and log each stellar CLI call with latency and outcome.
`lafiya-rpc-resilience` emits an event per RPC call (`rpc submit`,
`rpc get_transaction`) with provider, latency, and classified outcome.

### Redaction

Every byte a log layer writes passes through `logging::redact`, which replaces
Stellar secret seeds (`S...`, 56 chars) and mnemonic phrases (12+ lowercase
words) with `[REDACTED]`. The stellar CLI's own stderr is passed through the
same filter. Tests: `cargo test -p lafiya-cli logging`.

## Operation audit log

Every mutating command (`attester add`, `attester remove`) appends a record to
`~/.lafiya/audit.jsonl` (override with `LAFIYA_AUDIT_LOG`), whether it succeeded
or failed:

```json
{"seq":0,"timestamp":1790000000,"command":"attester add","network":"testnet","contract":"C...","function":"add_attester","arg_hashes":["<sha256>"],"signer":"admin","tx_hash":"<hash or null>","outcome":"success","prev_hash":"000...","hash":"<sha256>"}
```

- Arguments are stored only as SHA-256 hashes; strings are redacted.
- Each record's `hash` covers all its fields plus `prev_hash`, so editing,
  reordering, or deleting a record breaks the chain.

```bash
lafiya-cli audit show     # print records
lafiya-cli audit verify   # check the hash chain; non-zero exit when broken
```

The chain detects tampering after the fact, not a user rewriting the whole
file; ship the file to append-only storage if that matters.

## OpenTelemetry (OTLP) export

Build with the `otel` feature and set the standard OTLP endpoint variable.
Spans are exported over OTLP/HTTP (protobuf) as service `lafiya-cli`.

Local demo with the OpenTelemetry Collector printing spans to its console:

```bash
cat > otel-collector.yaml <<'YAML'
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318
exporters:
  debug:
    verbosity: detailed
service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [debug]
YAML
docker run --rm -p 4318:4318 -v "$PWD/otel-collector.yaml:/etc/otelcol/config.yaml" \
  otel/opentelemetry-collector:latest

# In another shell:
cargo build -p lafiya-cli --features otel
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318 \
  ./target/debug/lafiya-cli --network testnet auth decode "$(cat entry.xdr)"
```

The collector prints an `auth.decode` span with `service.name: lafiya-cli`.
Point the endpoint at Jaeger, Tempo, or Honeycomb in the same way. Without
`OTEL_EXPORTER_OTLP_ENDPOINT` the exporter stays off even when compiled in.

## Indexer health and leadership

The indexer exposes a health endpoint that reports whether the replica is the
active ingester or a read-only follower, plus ingestion lag. It is safe to
scrape from a load balancer and from monitoring.

```json
{"status":"ok","role":"leader","fencing_token":42,"lag_ledgers":0,"lag_seconds":0}
{"status":"ok","role":"follower","leader_observed":true,"lag_ledgers":3,"lag_seconds":12}
```

| Field | Meaning |
| --- | --- |
| `role` | `leader` (holds the single-writer lock) or `follower` |
| `fencing_token` | Monotonic token on checkpoint writes; stale writers are rejected |
| `leader_observed` | Follower has seen a leader heartbeat recently |
| `lag_ledgers` / `lag_seconds` | Distance between the last ingested ledger and chain tip |

`status` is `ok` while a leader exists and lag is within budget, `degraded`
when a follower has not observed a leader or lag exceeds the budget, and
`error` when the replica cannot reach Postgres or the RPC provider.

### Metrics

| Metric | Type | Labels | Use |
| --- | --- | --- | --- |
| `indexer_role` | gauge | `role` | 1 for the current role, 0 otherwise |
| `indexer_leader_changes_total` | counter | — | Failover events |
| `indexer_ingest_lag_ledgers` | gauge | — | Ingestion lag in ledgers |
| `indexer_ingest_lag_seconds` | gauge | — | Ingestion lag in wall-clock seconds |
| `indexer_checkpoint_fenced_total` | counter | — | Stale checkpoint writes rejected by fencing |
| `indexer_api_requests_total` | counter | `route`, `tier`, `outcome` | `outcome` is `allowed` or `denied` |
| `indexer_api_denials_total` | counter | `route`, `tier`, `reason` | `reason` is `rate_limited`, `quota_exhausted`, or `unauthenticated` |
| `indexer_api_page_size` | histogram | `route` | Bounded page sizes actually served |

Denial logs are structured and never contain query hashes in cleartext; the
record-hash route logs only a keyed digest. See
`docs/security/linkability.md` for the scraping threat model.

### Alerting

- **Failover**: page when `indexer_leader_changes_total` increases more than
  twice in 15 minutes, or when no replica reports `indexer_role{role="leader"} == 1`
  for 2 minutes.
- **Lag**: warn when `indexer_ingest_lag_ledgers` exceeds the configured budget
  for 5 minutes; page when `indexer_ingest_lag_seconds` exceeds 10 minutes.
- **Fencing**: alert on any sustained increase in
  `indexer_checkpoint_fenced_total`, which indicates two writers racing.
- **Quota enforcement**: alert when the ratio of
  `indexer_api_denials_total{reason="rate_limited"}` to
  `indexer_api_requests_total` exceeds 10% for 10 minutes, or when
  `reason="quota_exhausted"` denials appear for a tier that should not be
  exhausting its budget. A sudden drop in `allowed` requests with stable
  traffic suggests limits are misconfigured.
