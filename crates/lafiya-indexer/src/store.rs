//! Postgres storage: applying event pages atomically with the checkpoint.

use serde_json::Value;
use sqlx::{PgPool, Postgres, Transaction};

use crate::decode::{cursor_ledger, decode, DecodeError, LafiyaEvent, RawEvent};

pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

const LIVE: &str = "live";

/// Advisory lock key identifying the single active ingester. Chosen as a
/// fixed, application-specific constant so replicas agree on it.
pub const LEADER_LOCK_KEY: i64 = 0x6c616669_7961_0001;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    /// Last RPC cursor, or `None` to resume from `ledger` via `startLedger`.
    pub cursor: Option<String>,
    pub ledger: u32,
    /// Hash of the ledger checkpoint covering `ledger`, when known. Used to
    /// verify archive data against the chain and to hand off archive -> live.
    pub checkpoint_hash: Option<String>,
    /// Monotonically increasing fencing token; stale writers are rejected.
    pub fencing_token: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error(transparent)]
    Db(#[from] sqlx::Error),
    #[error(transparent)]
    Decode(#[from] DecodeError),
    /// A checkpoint write carried a fencing token older than the stored one:
    /// another writer has taken over, so this page must be discarded.
    #[error("stale writer: fencing token {attempted} < current {current}")]
    StaleWriter { attempted: i64, current: i64 },
    /// Archive data did not match the on-chain checkpoint hash.
    #[error("checkpoint hash mismatch at ledger {ledger}: expected {expected}, got {actual}")]
    CheckpointMismatch {
        ledger: u32,
        expected: String,
        actual: String,
    },
}

pub async fn checkpoint(pool: &PgPool) -> Result<Option<Checkpoint>, sqlx::Error> {
    let row: Option<(Option<String>, i64, Option<String>, i64)> = sqlx::query_as(
        "SELECT cursor, ledger, checkpoint_hash, fencing_token
         FROM checkpoints WHERE name = $1",
    )
    .bind(LIVE)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(cursor, ledger, checkpoint_hash, fencing_token)| Checkpoint {
        cursor,
        ledger: ledger as u32,
        checkpoint_hash,
        fencing_token,
    }))
}

/// Try to become the single active ingester. Returns `true` if this session
/// holds the leader advisory lock. The lock is session-scoped, so it is
/// released automatically if the connection drops (leader crash).
pub async fn try_acquire_leadership(pool: &PgPool) -> Result<bool, sqlx::Error> {
    let (acquired,): (bool,) = sqlx::query_as("SELECT pg_try_advisory_lock($1)")
        .bind(LEADER_LOCK_KEY)
        .fetch_one(pool)
        .await?;
    Ok(acquired)
}

/// Release the leader advisory lock, if held by this session.
pub async fn release_leadership(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(LEADER_LOCK_KEY)
        .execute(pool)
        .await?;
    Ok(())
}

/// Bump the fencing token and return the new value. Called by the leader when
/// it takes over so that any in-flight writes from a previous leader are
/// rejected by `apply_page`.
pub async fn bump_fencing_token(pool: &PgPool) -> Result<i64, sqlx::Error> {
    let (token,): (i64,) = sqlx::query_as(
        "INSERT INTO checkpoints (name, cursor, ledger, fencing_token)
         VALUES ($1, NULL, 0, 1)
         ON CONFLICT (name) DO UPDATE
         SET fencing_token = checkpoints.fencing_token + 1, updated_at = now()
         RETURNING fencing_token",
    )
    .bind(LIVE)
    .fetch_one(pool)
    .await?;
    Ok(token)
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
    // Reject stale writers: the stored fencing token must not exceed ours.
    let current: Option<(i64,)> =
        sqlx::query_as("SELECT fencing_token FROM checkpoints WHERE name = $1 FOR UPDATE")
            .bind(LIVE)
            .fetch_optional(&mut *tx)
            .await?;
    if let Some((current,)) = current {
        if next.fencing_token < current {
            return Err(StoreError::StaleWriter {
                attempted: next.fencing_token,
                current,
            });
        }
    }
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
            applied += 1;
        }
    }
    sqlx::query(
        "INSERT INTO checkpoints (name, cursor, ledger, checkpoint_hash, fencing_token)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (name) DO UPDATE
         SET cursor = EXCLUDED.cursor, ledger = EXCLUDED.ledger,
             checkpoint_hash = EXCLUDED.checkpoint_hash,
             fencing_token = EXCLUDED.fencing_token, updated_at = now()",
    )
    .bind(LIVE)
    .bind(&next.cursor)
    .bind(i64::from(next.ledger))
    .bind(&next.checkpoint_hash)
    .bind(next.fencing_token)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(applied)
}

/// Verify that archive data for `ledger` matches the expected on-chain
/// checkpoint hash. Refuses unverifiable sources.
pub fn verify_checkpoint_hash(
    ledger: u32,
    expected: &str,
    actual: &str,
) -> Result<(), StoreError> {
    if expected != actual {
        return Err(StoreError::CheckpointMismatch {
            ledger,
            expected: expected.to_string(),
            actual: actual.to_string(),
        });
    }
    Ok(())
}

/// Checkpoint to store after a page ending at RPC `cursor`.
pub fn checkpoint_after(cursor: &str, events: &[RawEvent], previous_ledger: u32) -> Checkpoint {
    let ledger = cursor_ledger(cursor)
        .or_else(|| events.last().map(|e| e.ledger))
        .unwrap_or(previous_ledger);
    Checkpoint {
        cursor: Some(cursor.to_string()),
        ledger,
        checkpoint_hash: None,
        fencing_token: 0,
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
