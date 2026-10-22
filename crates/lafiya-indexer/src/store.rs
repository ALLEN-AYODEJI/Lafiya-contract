//! Postgres storage: applying event pages atomically with the checkpoint.

use serde_json::Value;
use sqlx::{PgPool, Postgres, Transaction};

use crate::decode::{cursor_ledger, decode, DecodeError, LafiyaEvent, RawEvent};

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
    /// The stored ledger hash for `ledger` differs from the one the provider
    /// served: the chain tip diverged and derived state must be rolled back.
    #[error("ledger {ledger} hash mismatch: stored {stored}, provider {observed}")]
    Reorg {
        ledger: u32,
        stored: String,
        observed: String,
    },
}

/// A ledger hash recorded at ingest time, used to verify chain continuity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerHash {
    pub ledger: u32,
    pub hash: String,
}

/// A work item in the incentive pool.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct WorkItem {
    pub id: String,
    pub attester: String,
    pub amount: i64,
    pub status: String,
    pub created_ledger: i64,
    pub updated_ledger: i64,
}

/// A payout from the incentive pool.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct Payout {
    pub id: String,
    pub work_item_id: String,
    pub attester: String,
    pub amount: i64,
    pub ledger: i64,
    pub tx_hash: String,
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

/// Record the hash of an ingested ledger. Returns `Err(StoreError::Reorg)` if a
/// different hash was already stored for the same ledger, so the caller can
/// roll back to the common ancestor before re-ingesting.
pub async fn record_ledger_hash(
    pool: &PgPool,
    ledger: u32,
    hash: &str,
) -> Result<(), StoreError> {
    let mut tx = pool.begin().await?;
    let existing: Option<String> =
        sqlx::query_scalar("SELECT hash FROM ledger_hashes WHERE ledger = $1")
            .bind(i64::from(ledger))
            .fetch_optional(&mut *tx)
            .await?;
    if let Some(stored) = existing {
        if stored != hash {
            return Err(StoreError::Reorg {
                ledger,
                stored,
                observed: hash.to_string(),
            });
        }
    } else {
        sqlx::query("INSERT INTO ledger_hashes (ledger, hash) VALUES ($1, $2)")
            .bind(i64::from(ledger))
            .bind(hash)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Verify that every ledger in `hashes` matches what is stored, returning the
/// first mismatch (if any) as a `StoreError::Reorg`.
pub async fn verify_ledger_hashes(
    pool: &PgPool,
    hashes: &[LedgerHash],
) -> Result<(), StoreError> {
    for expected in hashes {
        let stored: Option<String> =
            sqlx::query_scalar("SELECT hash FROM ledger_hashes WHERE ledger = $1")
                .bind(i64::from(expected.ledger))
                .fetch_optional(pool)
                .await?;
        if let Some(stored) = stored {
            if stored != expected.hash {
                return Err(StoreError::Reorg {
                    ledger: expected.ledger,
                    stored,
                    observed: expected.hash.clone(),
                });
            }
        }
    }
    Ok(())
}

/// Highest ledger whose hash is recorded, i.e. the last known-good tip.
pub async fn last_hashed_ledger(pool: &PgPool) -> Result<Option<u32>, sqlx::Error> {
    let ledger: Option<i64> = sqlx::query_scalar("SELECT MAX(ledger) FROM ledger_hashes")
        .fetch_one(pool)
        .await?;
    Ok(ledger.map(|l| l as u32))
}

/// Insert a work item, or update its status/amount if it already exists.
pub async fn upsert_work_item(
    pool: &PgPool,
    item: &WorkItem,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO pool_work_items
             (id, attester, amount, status, created_ledger, updated_ledger)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (id) DO UPDATE SET
             amount = EXCLUDED.amount,
             status = EXCLUDED.status,
             updated_ledger = EXCLUDED.updated_ledger",
    )
    .bind(&item.id)
    .bind(&item.attester)
    .bind(item.amount)
    .bind(&item.status)
    .bind(item.created_ledger)
    .bind(item.updated_ledger)
    .execute(pool)
    .await?;
    Ok(())
}

/// Insert a payout, ignoring duplicates by `id`.
pub async fn insert_payout(pool: &PgPool, payout: &Payout) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO pool_payouts
             (id, work_item_id, attester, amount, ledger, tx_hash)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(&payout.id)
    .bind(&payout.work_item_id)
    .bind(&payout.attester)
    .bind(payout.amount)
    .bind(payout.ledger)
    .bind(&payout.tx_hash)
    .execute(pool)
    .await?;
    Ok(())
}

/// Fetch a work item by id.
pub async fn work_item(pool: &PgPool, id: &str) -> Result<Option<WorkItem>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, attester, amount, status, created_ledger, updated_ledger
         FROM pool_work_items WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

/// List work items, optionally filtered by attester, newest first.
pub async fn work_items(
    pool: &PgPool,
    attester: Option<&str>,
    limit: i64,
) -> Result<Vec<WorkItem>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, attester, amount, status, created_ledger, updated_ledger
         FROM pool_work_items
         WHERE ($1::text IS NULL OR attester = $1)
         ORDER BY created_ledger DESC, id DESC
         LIMIT $2",
    )
    .bind(attester)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// List payouts, optionally filtered by attester, newest first.
pub async fn payouts(
    pool: &PgPool,
    attester: Option<&str>,
    limit: i64,
) -> Result<Vec<Payout>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, work_item_id, attester, amount, ledger, tx_hash
         FROM pool_payouts
         WHERE ($1::text IS NULL OR attester = $1)
         ORDER BY ledger DESC, id DESC
         LIMIT $2",
    )
    .bind(attester)
    .bind(limit)
    .fetch_all(pool)
    .await
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
        LafiyaEvent::PoolWorkItemCreated {
            work_item_id,
            attester,
            amount,
        } => {
            sqlx::query(
                "INSERT INTO pool_work_items
                     (id, attester, amount, status, created_ledger, updated_ledger)
                 VALUES ($1, $2, $3, 'pending', $4, $4)
                 ON CONFLICT (id) DO UPDATE SET
                     amount = EXCLUDED.amount,
                     updated_ledger = EXCLUDED.updated_ledger",
            )
            .bind(work_item_id)
            .bind(attester)
            .bind(*amount as i64)
            .bind(ledger)
            .execute(&mut **tx)
            .await?;
        }
        LafiyaEvent::PoolWorkItemApproved { work_item_id } => {
            sqlx::query(
                "UPDATE pool_work_items SET status = 'approved', updated_ledger = $1
                 WHERE id = $2",
            )
            .bind(ledger)
            .bind(work_item_id)
            .execute(&mut **tx)
            .await?;
        }
        LafiyaEvent::PoolClaimed {
            work_item_id,
            attester,
            amount,
        } => {
            sqlx::query(
                "UPDATE pool_work_items SET status = 'claimed', updated_ledger = $1
                 WHERE id = $2",
            )
            .bind(ledger)
            .bind(work_item_id)
            .execute(&mut **tx)
            .await?;
            sqlx::query(
                "INSERT INTO pool_payouts
                     (id, work_item_id, attester, amount, ledger, tx_hash)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT (id) DO NOTHING",
            )
            .bind(&raw.id)
            .bind(work_item_id)
            .bind(attester)
            .bind(*amount as i64)
            .bind(ledger)
            .bind(&raw.tx_hash)
            .execute(&mut **tx)
            .await?;
        }
        LafiyaEvent::PoolWithdrawn {
            work_item_id,
            attester,
            amount,
        } => {
            sqlx::query(
                "UPDATE pool_work_items SET status = 'withdrawn', updated_ledger = $1
                 WHERE id = $2",
            )
            .bind(ledger)
            .bind(work_item_id)
            .execute(&mut **tx)
            .await?;
            sqlx::query(
                "INSERT INTO pool_payouts
                     (id, work_item_id, attester, amount, ledger, tx_hash)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT (id) DO NOTHING",
            )
            .bind(&raw.id)
            .bind(work_item_id)
            .bind(attester)
            .bind(*amount as i64)
            .bind(ledger)
            .bind(&raw.tx_hash)
            .execute(&mut **tx)
            .await?;
        }
        LafiyaEvent::PoolPaused { paused } => {
            sqlx::query(
                "INSERT INTO pool_state (contract_id, paused, updated_ledger)
                 VALUES ($1, $2, $3)
                 ON CONFLICT (contract_id) DO UPDATE SET
                     paused = EXCLUDED.paused,
                     updated_ledger = EXCLUDED.updated_ledger",
            )
            .bind(&raw.contract_id)
            .bind(*paused)
            .bind(ledger)
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
