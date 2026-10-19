//! Postgres storage: applying event pages atomically with the checkpoint.

use serde_json::Value;
use sqlx::{PgPool, Postgres, Transaction};

use crate::decode::{cursor_ledger, decode, DecodeError, LafiyaEvent, RawEvent};

/// Default number of rows deleted per batch by [`prune`].
pub const PRUNE_BATCH_SIZE: i64 = 500;
/// Default maximum number of batches [`prune`] will run per table per call.
pub const PRUNE_MAX_BATCHES: i64 = 20;
/// Default retention window (in seconds) for operational tables.
pub const DEFAULT_RETENTION_SECS: i64 = 7 * 24 * 60 * 60;
/// Maximum delivery attempts before a delivery is dead-lettered.
pub const MAX_DELIVERY_ATTEMPTS: i32 = 8;
/// Base backoff (seconds) for the first retry; doubles per attempt.
pub const BACKOFF_BASE_SECS: i64 = 5;
/// Cap on the exponential backoff (seconds).
pub const BACKOFF_MAX_SECS: i64 = 60 * 60;

pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

const LIVE: &str = "live";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    /// Last RPC cursor, or `None` to resume from `ledger` via `startLedger`.
    pub cursor: Option<String>,
    pub ledger: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error(transparent)]
    Db(#[from] sqlx::Error),
    #[error(transparent)]
    Decode(#[from] DecodeError),
}

/// A push-delivery subscription. Filters are optional; `None` matches all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscription {
    pub id: i64,
    pub url: String,
    pub secret: String,
    pub contract_id: Option<String>,
    pub event_type: Option<String>,
    pub attester: Option<String>,
    pub active: bool,
}

/// A delivery claimed for sending.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivery {
    pub id: i64,
    pub subscription_id: i64,
    pub event_id: String,
    pub url: String,
    pub secret: String,
    pub attempts: i32,
}

/// Retention configuration for [`prune`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retention {
    /// Delete deliveries/dead letters older than this many seconds.
    pub retention_secs: i64,
    /// Rows deleted per batch (bounded lock duration).
    pub batch_size: i64,
    /// Maximum batches per table per call.
    pub max_batches: i64,
}

impl Default for Retention {
    fn default() -> Self {
        Retention {
            retention_secs: DEFAULT_RETENTION_SECS,
            batch_size: PRUNE_BATCH_SIZE,
            max_batches: PRUNE_MAX_BATCHES,
        }
    }
}

/// Rows removed by a [`prune`] call, per table.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Pruned {
    pub deliveries: u64,
    pub dead_letters: u64,
}

/// Exponential backoff in seconds for a given attempt count (1-based).
pub fn backoff_secs(attempts: i32) -> i64 {
    let shift = attempts.saturating_sub(1).clamp(0, 20) as u32;
    BACKOFF_BASE_SECS
        .saturating_mul(1i64 << shift)
        .min(BACKOFF_MAX_SECS)
}

pub async fn checkpoint(pool: &PgPool) -> Result<Option<Checkpoint>, sqlx::Error> {
    let row: Option<(Option<String>, i64)> =
        sqlx::query_as("SELECT cursor, ledger FROM checkpoints WHERE name = $1")
            .bind(LIVE)
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|(cursor, ledger)| Checkpoint {
        cursor,
        ledger: ledger as u32,
    }))
}

/// Apply `events` (in chain order) and move the checkpoint to `next`, in one
/// transaction: a crash either keeps or discards the whole page, and events
/// already in `raw_events` are never applied twice. Returns the number of
/// newly applied events.
pub async fn apply_page(
    pool: &PgPool,
    events: &[RawEvent],
    next: &Checkpoint,
) -> Result<usize, StoreError> {
    let mut tx = pool.begin().await?;
    let mut applied = 0;
    for raw in events.iter().filter(|e| e.in_successful_contract_call) {
        let event = decode(raw)?;
        let inserted = sqlx::query(
            "INSERT INTO raw_events
                 (id, contract_id, ledger, ledger_closed_at, tx_hash, name, topics, value, decoded)
             VALUES ($1, $2, $3, $4::text::timestamptz, $5, $6, $7, $8, $9)
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(&raw.id)
        .bind(&raw.contract_id)
        .bind(i64::from(raw.ledger))
        .bind(&raw.ledger_closed_at)
        .bind(&raw.tx_hash)
        .bind(event.name())
        .bind(&raw.topic)
        .bind(&raw.value)
        .bind(serde_json::to_value(&event).unwrap_or(Value::Null))
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if inserted == 1 {
            apply_event(&mut tx, raw, &event).await?;
            enqueue_deliveries(&mut tx, raw, &event).await?;
            applied += 1;
        }
    }
    sqlx::query(
        "INSERT INTO checkpoints (name, cursor, ledger) VALUES ($1, $2, $3)
         ON CONFLICT (name) DO UPDATE
         SET cursor = EXCLUDED.cursor, ledger = EXCLUDED.ledger, updated_at = now()",
    )
    .bind(LIVE)
    .bind(&next.cursor)
    .bind(i64::from(next.ledger))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(applied)
}

/// Create a subscription and return its id.
pub async fn create_subscription(
    pool: &PgPool,
    url: &str,
    secret: &str,
    contract_id: Option<&str>,
    event_type: Option<&str>,
    attester: Option<&str>,
) -> Result<i64, sqlx::Error> {
    let (id,): (i64,) = sqlx::query_as(
        "INSERT INTO subscriptions (url, secret, contract_id, event_type, attester)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id",
    )
    .bind(url)
    .bind(secret)
    .bind(contract_id)
    .bind(event_type)
    .bind(attester)
    .fetch_one(pool)
    .await?;
    Ok(id)
}

/// List all subscriptions, active or not.
pub async fn list_subscriptions(pool: &PgPool) -> Result<Vec<Subscription>, sqlx::Error> {
    let rows: Vec<(i64, String, String, Option<String>, Option<String>, Option<String>, bool)> =
        sqlx::query_as(
            "SELECT id, url, secret, contract_id, event_type, attester, active
             FROM subscriptions ORDER BY id",
        )
        .fetch_all(pool)
        .await?;
    Ok(rows
        .into_iter()
        .map(
            |(id, url, secret, contract_id, event_type, attester, active)| Subscription {
                id,
                url,
                secret,
                contract_id,
                event_type,
                attester,
                active,
            },
        )
        .collect())
}

/// Delete a subscription and its pending deliveries.
pub async fn delete_subscription(pool: &PgPool, id: i64) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM deliveries WHERE subscription_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    let deleted = sqlx::query("DELETE FROM subscriptions WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    tx.commit().await?;
    Ok(deleted == 1)
}

/// Enqueue a delivery for every active subscription matching `raw`/`event`.
/// Idempotent on `(subscription_id, event_id)`: re-enqueuing the same event
/// inserts nothing. Returns the number of newly queued deliveries.
pub async fn enqueue_deliveries(
    tx: &mut Transaction<'_, Postgres>,
    raw: &RawEvent,
    event: &LafiyaEvent,
) -> Result<u64, sqlx::Error> {
    let attester = event.attester();
    let inserted = sqlx::query(
        "INSERT INTO deliveries (subscription_id, event_id, contract_id, event_type, attester)
         SELECT s.id, $1, $2, $3, $4
         FROM subscriptions s
         WHERE s.active
           AND (s.contract_id IS NULL OR s.contract_id = $2)
           AND (s.event_type IS NULL OR s.event_type = $3)
           AND (s.attester IS NULL OR s.attester = $4)
         ON CONFLICT (subscription_id, event_id) DO NOTHING",
    )
    .bind(&raw.id)
    .bind(&raw.contract_id)
    .bind(event.name())
    .bind(attester)
    .execute(&mut **tx)
    .await?
    .rows_affected();
    Ok(inserted)
}

/// Claim up to `limit` deliveries that are due, marking them in-flight and
/// scheduling the next attempt with exponential backoff. Exhausted deliveries
/// are moved to `dead_letters` instead. Returns the claimed deliveries.
pub async fn claim_due_deliveries(
    pool: &PgPool,
    limit: i64,
) -> Result<Vec<Delivery>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    // Move exhausted deliveries to the dead-letter table first.
    sqlx::query(
        "WITH exhausted AS (
             DELETE FROM deliveries
             WHERE attempts >= $1 AND next_attempt_at <= now()
             RETURNING id, subscription_id, event_id, attempts, last_error
         )
         INSERT INTO dead_letters (delivery_id, subscription_id, event_id, attempts, last_error)
         SELECT id, subscription_id, event_id, attempts, last_error FROM exhausted",
    )
    .bind(MAX_DELIVERY_ATTEMPTS)
    .execute(&mut *tx)
    .await?;
    let rows: Vec<(i64, i64, String, i32)> = sqlx::query_as(
        "UPDATE deliveries d
         SET attempts = d.attempts + 1,
             next_attempt_at = now() + make_interval(secs => $2)
         FROM subscriptions s
         WHERE s.id = d.subscription_id AND s.active
           AND d.attempts < $1
           AND d.next_attempt_at <= now()
           AND d.id IN (
               SELECT id FROM deliveries
               WHERE attempts < $1 AND next_attempt_at <= now()
               ORDER BY next_attempt_at
               LIMIT $3
               FOR UPDATE SKIP LOCKED
           )
         RETURNING d.id, d.subscription_id, d.event_id, d.attempts",
    )
    .bind(MAX_DELIVERY_ATTEMPTS)
    .bind(BACKOFF_BASE_SECS)
    .bind(limit)
    .fetch_all(&mut *tx)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for (id, subscription_id, event_id, attempts) in rows {
        let (url, secret): (String, String) =
            sqlx::query_as("SELECT url, secret FROM subscriptions WHERE id = $1")
                .bind(subscription_id)
                .fetch_one(&mut *tx)
                .await?;
        out.push(Delivery {
            id,
            subscription_id,
            event_id,
            url,
            secret,
            attempts,
        });
    }
    tx.commit().await?;
    Ok(out)
}

/// Record a successful delivery: remove it from the queue.
pub async fn complete_delivery(pool: &PgPool, id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM deliveries WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Record a failed delivery attempt, scheduling the next retry with backoff.
pub async fn fail_delivery(
    pool: &PgPool,
    id: i64,
    attempts: i32,
    error: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE deliveries
         SET last_error = $2, next_attempt_at = now() + make_interval(secs => $3)
         WHERE id = $1",
    )
    .bind(id)
    .bind(error)
    .bind(backoff_secs(attempts))
    .execute(pool)
    .await?;
    Ok(())
}

/// Prune operational tables older than the retention window in bounded
/// batches. Idempotent: running it twice deletes nothing the second time.
/// Each batch is a separate statement so locks are short and ingestion is
/// not blocked.
pub async fn prune(pool: &PgPool, retention: Retention) -> Result<Pruned, sqlx::Error> {
    let mut pruned = Pruned::default();
    pruned.deliveries +=
        prune_table(pool, "deliveries", "created_at", retention).await?;
    pruned.dead_letters +=
        prune_table(pool, "dead_letters", "created_at", retention).await?;
    Ok(pruned)
}

async fn prune_table(
    pool: &PgPool,
    table: &str,
    ts_column: &str,
    retention: Retention,
) -> Result<u64, sqlx::Error> {
    // `table`/`ts_column` are fixed literals from `prune`, never user input.
    let sql = format!(
        "DELETE FROM {table}
         WHERE ctid IN (
             SELECT ctid FROM {table}
             WHERE {ts_column} < now() - make_interval(secs => $1)
             LIMIT $2
         )"
    );
    let mut total = 0u64;
    for _ in 0..retention.max_batches.max(0) {
        let deleted = sqlx::query(&sql)
            .bind(retention.retention_secs)
            .bind(retention.batch_size)
            .execute(pool)
            .await?
            .rows_affected();
        total += deleted;
        if deleted < retention.batch_size as u64 {
            break;
        }
    }
    Ok(total)
}

/// Checkpoint to store after a page ending at RPC `cursor`.
pub fn checkpoint_after(cursor: &str, events: &[RawEvent], previous_ledger: u32) -> Checkpoint {
    let ledger = cursor_ledger(cursor)
        .or_else(|| events.last().map(|e| e.ledger))
        .unwrap_or(previous_ledger);
    Checkpoint {
        cursor: Some(cursor.to_string()),
        ledger,
    }
}

/// Flags of an attester row first created by a given event.
struct NewAttester {
    allowlisted: bool,
    suspended: bool,
    info_stale: bool,
}

/// Insert an attester row, or apply `set` to the existing one.
async fn upsert_attester(
    tx: &mut Transaction<'_, Postgres>,
    raw: &RawEvent,
    attester: &str,
    new: NewAttester,
    set: &str,
) -> Result<(), sqlx::Error> {
    // `set` is one of the fixed fragments in `apply_event`, never user input.
    let sql = format!(
        "INSERT INTO attesters (address, allowlisted, suspended, info_stale,
                                first_seen_ledger, updated_ledger, updated_event_id)
         VALUES ($1, $2, $3, $4, $5, $5, $6)
         ON CONFLICT (address) DO UPDATE SET {set},
             updated_ledger = EXCLUDED.updated_ledger,
             updated_event_id = EXCLUDED.updated_event_id"
    );
    sqlx::query(&sql)
        .bind(attester)
        .bind(new.allowlisted)
        .bind(new.suspended)
        .bind(new.info_stale)
        .bind(i64::from(raw.ledger))
        .bind(&raw.id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn apply_event(
    tx: &mut Transaction<'_, Postgres>,
    raw: &RawEvent,
    event: &LafiyaEvent,
) -> Result<(), sqlx::Error> {
    let ledger = i64::from(raw.ledger);
    match event {
        // `add_attester` resets info but keeps an existing suspension;
        // `remove_attester` clears both.
        LafiyaEvent::AttesterAdded { attester } => {
            let new = NewAttester {
                allowlisted: true,
                suspended: false,
                info_stale: false,
            };
            let set = "allowlisted = true, region = NULL, license_hash = NULL, info_stale = false";
            upsert_attester(tx, raw, attester, new, set).await?;
        }
        LafiyaEvent::AttesterRemoved { attester } => {
            let new = NewAttester {
                allowlisted: false,
                suspended: false,
                info_stale: false,
            };
            let set = "allowlisted = false, suspended = false";
            upsert_attester(tx, raw, attester, new, set).await?;
        }
        LafiyaEvent::AttesterSuspended { attester } => {
            let new = NewAttester {
                allowlisted: true,
                suspended: true,
                info_stale: false,
            };
            upsert_attester(tx, raw, attester, new, "suspended = true").await?;
        }
        LafiyaEvent::AttesterReinstated { attester } => {
            let new = NewAttester {
                allowlisted: true,
                suspended: false,
                info_stale: false,
            };
            upsert_attester(tx, raw, attester, new, "suspended = false").await?;
        }
        LafiyaEvent::AttesterInfoUpdated { attester } => {
            let new = NewAttester {
                allowlisted: true,
                suspended: false,
                info_stale: true,
            };
            upsert_attester(tx, raw, attester, new, "info_stale = true").await?;
        }
        LafiyaEvent::AttestationRecorded {
            record_hash,
            attester,
            timestamp,
        } => {
            sqlx::query(
                "INSERT INTO attestations (event_id, record_hash, attester, attested_at, ledger, tx_hash)
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(&raw.id)
            .bind(record_hash)
            .bind(attester)
            .bind(*timestamp as i64)
            .bind(ledger)
            .bind(&raw.tx_hash)
            .execute(&mut **tx)
            .await?;
        }
        // `revoke_attestation` deletes the record's whole history on chain.
        LafiyaEvent::AttestationRevoked { record_hash } => {
            sqlx::query(
                "INSERT INTO revocations (event_id, record_hash, ledger, tx_hash)
                 VALUES ($1, $2, $3, $4)",
            )
            .bind(&raw.id)
            .bind(record_hash)
            .bind(ledger)
            .bind(&raw.tx_hash)
            .execute(&mut **tx)
            .await?;
            sqlx::query(
                "UPDATE attestations SET revoked_event_id = $1
                 WHERE record_hash = $2 AND revoked_event_id IS NULL",
            )
            .bind(&raw.id)
            .bind(record_hash)
            .execute(&mut **tx)
            .await?;
        }
        LafiyaEvent::Admin { name, fields } => {
            sqlx::query(
                "INSERT INTO admin_events (event_id, contract_id, name, fields, ledger, tx_hash)
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(&raw.id)
            .bind(&raw.contract_id)
            .bind(name)
            .bind(Value::Object(fields.clone()))
            .bind(ledger)
            .bind(&raw.tx_hash)
            .execute(&mut **tx)
            .await?;
        }
        LafiyaEvent::Unknown { .. } => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_and_caps() {
        assert_eq!(backoff_secs(1), BACKOFF_BASE_SECS);
        assert_eq!(backoff_secs(2), BACKOFF_BASE_SECS * 2);
        assert_eq!(backoff_secs(3), BACKOFF_BASE_SECS * 4);
        assert_eq!(backoff_secs(100), BACKOFF_MAX_SECS);
    }

    #[test]
    fn retention_defaults_are_bounded() {
        let r = Retention::default();
        assert!(r.batch_size > 0);
        assert!(r.max_batches > 0);
        assert!(r.retention_secs > 0);
    }

    /// Pruning is idempotent and bounded: a second run over an already-pruned
    /// table deletes nothing, and each call issues at most `max_batches`
    /// statements (short locks).
    #[sqlx::test]
    async fn prune_is_idempotent_and_bounded(pool: PgPool) -> sqlx::Result<()> {
        MIGRATOR.run(&pool).await.unwrap();
        let sub = create_subscription(&pool, "https://example.test/hook", "s", None, None, None)
            .await?;
        for i in 0..10 {
            sqlx::query(
                "INSERT INTO deliveries (subscription_id, event_id, created_at)
                 VALUES ($1, $2, now() - interval '30 days')",
            )
            .bind(sub)
            .bind(format!("evt-{i}"))
            .execute(&pool)
            .await?;
        }
        let retention = Retention {
            retention_secs: 60,
            batch_size: 3,
            max_batches: 10,
        };
        let first = prune(&pool, retention).await?;
        assert_eq!(first.deliveries, 10);
        let second = prune(&pool, retention).await?;
        assert_eq!(second.deliveries, 0);
        Ok(())
    }

    /// Enqueueing the same event twice for the same subscription is a no-op.
    #[sqlx::test]
    async fn enqueue_is_idempotent(pool: PgPool) -> sqlx::Result<()> {
        MIGRATOR.run(&pool).await.unwrap();
        let sub = create_subscription(&pool, "https://example.test/hook", "s", None, None, None)
            .await?;
        let mut tx = pool.begin().await?;
        let raw = RawEvent {
            id: "evt-1".into(),
            contract_id: "C".into(),
            ledger: 1,
            ledger_closed_at: "2024-01-01T00:00:00Z".into(),
            tx_hash: "tx".into(),
            topic: vec![],
            value: Value::Null,
            in_successful_contract_call: true,
        };
        let event = LafiyaEvent::AttesterAdded {
            attester: "G".into(),
        };
        assert_eq!(enqueue_deliveries(&mut tx, &raw, &event).await?, 1);
        assert_eq!(enqueue_deliveries(&mut tx, &raw, &event).await?, 0);
        tx.commit().await?;
        let (count,): (i64,) =
            sqlx::query_as("SELECT count(*) FROM deliveries WHERE subscription_id = $1")
                .bind(sub)
                .fetch_one(&pool)
                .await?;
        assert_eq!(count, 1);
        Ok(())
    }
}
