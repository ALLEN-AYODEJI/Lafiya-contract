-- Ingestion checkpoint. `cursor` is the last RPC `getEvents` cursor; when it
-- is NULL, ingestion restarts from `ledger` via `startLedger` (set after a
-- backfill that is known to be complete through `ledger - 1`).
CREATE TABLE checkpoints (
    name       TEXT PRIMARY KEY,
    cursor     TEXT,
    ledger     BIGINT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Immutable audit copy of every ingested contract event. `id` is the RPC
-- event id, whose zero-padded form sorts in chain order.
CREATE TABLE raw_events (
    id               TEXT PRIMARY KEY,
    contract_id      TEXT NOT NULL,
    ledger           BIGINT NOT NULL,
    ledger_closed_at TIMESTAMPTZ NOT NULL,
    tx_hash          TEXT NOT NULL,
    name             TEXT,
    topics           TEXT[] NOT NULL,
    value            TEXT NOT NULL,
    decoded          JSONB NOT NULL,
    ingested_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX raw_events_ledger_idx ON raw_events (ledger);

CREATE FUNCTION raw_events_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'raw_events is append-only';
END
$$;
CREATE TRIGGER raw_events_append_only
    BEFORE UPDATE OR DELETE ON raw_events
    FOR EACH ROW EXECUTE FUNCTION raw_events_append_only();

-- Attester lifecycle. The contract stores allowlist membership and the
-- suspension flag independently (`add_attester` does not clear a
-- suspension; `remove_attester` does), so both flags are tracked and the
-- status is derived from them.
CREATE TABLE attesters (
    address           TEXT PRIMARY KEY,
    allowlisted       BOOLEAN NOT NULL,
    suspended         BOOLEAN NOT NULL,
    status            TEXT GENERATED ALWAYS AS (
        CASE WHEN NOT allowlisted THEN 'removed'
             WHEN suspended THEN 'suspended'
             ELSE 'active' END
    ) STORED,
    region            TEXT,
    license_hash      TEXT,
    -- Set by `AttesterInfoUpdated` (which carries no data); cleared once the
    -- reconciler has read the new info from chain.
    info_stale        BOOLEAN NOT NULL DEFAULT false,
    first_seen_ledger BIGINT NOT NULL,
    updated_ledger    BIGINT NOT NULL,
    updated_event_id  TEXT NOT NULL
);
CREATE INDEX attesters_region_status_idx ON attesters (region, status);
CREATE INDEX attesters_status_idx ON attesters (status);

-- One row per `AttestationRecorded`. The current attestation for a record is
-- the latest row whose `revoked_event_id` is NULL.
CREATE TABLE attestations (
    event_id         TEXT PRIMARY KEY,
    record_hash      TEXT NOT NULL,
    attester         TEXT NOT NULL,
    attested_at      BIGINT NOT NULL,
    ledger           BIGINT NOT NULL,
    tx_hash          TEXT NOT NULL,
    revoked_event_id TEXT
);
CREATE INDEX attestations_record_idx ON attestations (record_hash, event_id);
CREATE INDEX attestations_attester_idx ON attestations (attester, event_id);

CREATE TABLE revocations (
    event_id    TEXT PRIMARY KEY,
    record_hash TEXT NOT NULL,
    ledger      BIGINT NOT NULL,
    tx_hash     TEXT NOT NULL
);
CREATE INDEX revocations_record_idx ON revocations (record_hash, event_id);

-- Administration events (admin transfer, pause/unpause, upgrade, registry
-- repointing, initialization) with their decoded topic fields.
CREATE TABLE admin_events (
    event_id    TEXT PRIMARY KEY,
    contract_id TEXT NOT NULL,
    name        TEXT NOT NULL,
    fields      JSONB NOT NULL,
    ledger      BIGINT NOT NULL,
    tx_hash     TEXT NOT NULL
);

-- Push delivery subscriptions. Filters are nullable: a NULL filter matches
-- everything on that dimension. `event_types` is an array of decoded event
-- names (e.g. 'AttestationRecorded', 'AttesterAdded'); an empty array means
-- "all event types". `secret_ref` names the HMAC secret in the secret store
-- (never the secret itself) used to sign deliveries.
CREATE TABLE subscriptions (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    contract_id TEXT,
    event_types TEXT[] NOT NULL DEFAULT '{}',
    attester    TEXT,
    callback_url TEXT NOT NULL,
    secret_ref  TEXT NOT NULL,
    active      BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX subscriptions_active_idx ON subscriptions (active) WHERE active;

-- One row per (subscription, event) delivery. The composite primary key makes
-- replays idempotent: re-enqueueing an already-delivered event is a no-op.
-- `next_attempt_at` drives exponential backoff; `attempts` counts failed
-- attempts. A row is terminal when `delivered_at` is set or it has been moved
-- to `webhook_dead_letters`.
CREATE TABLE webhook_deliveries (
    subscription_id BIGINT NOT NULL REFERENCES subscriptions (id) ON DELETE CASCADE,
    event_id        TEXT NOT NULL,
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error      TEXT,
    delivered_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (subscription_id, event_id)
);
CREATE INDEX webhook_deliveries_due_idx
    ON webhook_deliveries (next_attempt_at)
    WHERE delivered_at IS NULL;

-- Deliveries that exhausted their retry budget. Kept for operator inspection
-- and manual replay; `payload` is the exact signed body that was attempted.
CREATE TABLE webhook_dead_letters (
    subscription_id BIGINT NOT NULL,
    event_id        TEXT NOT NULL,
    attempts        INTEGER NOT NULL,
    last_error      TEXT,
    payload         JSONB NOT NULL,
    dead_lettered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (subscription_id, event_id)
);

-- Bookkeeping for the retention/pruning job. One row per run so operators can
-- audit what was pruned and confirm idempotent re-runs.
CREATE TABLE prune_runs (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    started_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ,
    table_name  TEXT NOT NULL,
    rows_pruned BIGINT NOT NULL DEFAULT 0,
    status      TEXT NOT NULL DEFAULT 'running'
);
CREATE INDEX prune_runs_table_idx ON prune_runs (table_name, started_at);
