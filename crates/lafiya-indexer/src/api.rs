//! Read-only HTTP/JSON API (spec: `openapi.yaml`, served at `/openapi.yaml`).

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgPool;

use crate::metrics::Metrics;
use crate::store;

pub const OPENAPI: &str = include_str!("../openapi.yaml");

const DEFAULT_LIMIT: i64 = 50;
const MAX_LIMIT: i64 = 500;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub metrics: Arc<Metrics>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .route("/openapi.yaml", get(openapi))
        .route("/attesters", get(attesters))
        .route("/attestations", get(attestations))
        .route("/records/{hash}/history", get(record_history))
        .route("/work-items", get(work_items))
        .route("/payouts", get(payouts))
        .with_state(state)
}

pub enum ApiError {
    BadRequest(String),
    Db(sqlx::Error),
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        Self::Db(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            Self::Db(e) => {
                tracing::error!(error = %e, "api query failed");
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "database unavailable".into(),
                )
            }
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}

/// A page of results; pass `next_cursor` back as `cursor` for the next one.
///
/// `finalized_ledger` is the highest ledger the indexer considers final; events
/// at or below it will never be rolled back, so consumers can treat them as
/// settled. It is `None` when no finality boundary is known yet.
#[derive(Serialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
    pub finalized_ledger: Option<i64>,
}

fn page<T>(mut items: Vec<T>, limit: i64, key: impl Fn(&T) -> String) -> Page<T> {
    let next_cursor = if items.len() as i64 > limit {
        items.truncate(limit as usize);
        items.last().map(key)
    } else {
        None
    };
    Page {
        items,
        next_cursor,
        finalized_ledger: None,
    }
}

/// Attach the current finality boundary to a page of results.
async fn with_finality<T>(
    pool: &PgPool,
    mut page: Page<T>,
) -> Result<Json<Page<T>>, ApiError> {
    page.finalized_ledger = store::finalized_ledger(pool).await?;
    Ok(Json(page))
}

fn limit(requested: Option<i64>) -> Result<i64, ApiError> {
    match requested.unwrap_or(DEFAULT_LIMIT) {
        l @ 1..=MAX_LIMIT => Ok(l),
        _ => Err(ApiError::BadRequest(format!(
            "limit must be 1..={MAX_LIMIT}"
        ))),
    }
}

async fn health(State(s): State<AppState>) -> Response {
    match store::checkpoint(&s.pool).await {
        Ok(cp) => Json(json!({
            "status": "ok",
            "checkpoint_ledger": cp.map(|c| c.ledger),
            "lag_ledgers": s.metrics.lag_ledgers.get(),
        }))
        .into_response(),
        Err(e) => ApiError::Db(e).into_response(),
    }
}

async fn metrics(State(s): State<AppState>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        s.metrics.render(),
    )
}

async fn openapi() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "application/yaml")], OPENAPI)
}

#[derive(Deserialize)]
pub struct AttesterQuery {
    region: Option<String>,
    status: Option<String>,
    limit: Option<i64>,
    cursor: Option<String>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct Attester {
    address: String,
    status: String,
    region: Option<String>,
    license_hash: Option<String>,
    first_seen_ledger: i64,
    updated_ledger: i64,
}

async fn attesters(
    State(s): State<AppState>,
    Query(q): Query<AttesterQuery>,
) -> Result<Json<Page<Attester>>, ApiError> {
    let limit = limit(q.limit)?;
    if let Some(status) = &q.status {
        if !["active", "suspended", "removed"].contains(&status.as_str()) {
            return Err(ApiError::BadRequest(
                "status must be active, suspended, or removed".into(),
            ));
        }
    }
    let rows: Vec<Attester> = sqlx::query_as(
        "SELECT address, status, region, license_hash, first_seen_ledger, updated_ledger
         FROM attesters
         WHERE ($1::text IS NULL OR region = $1)
           AND ($2::text IS NULL OR status = $2)
           AND ($3::text IS NULL OR address > $3)
         ORDER BY address LIMIT $4",
    )
    .bind(&q.region)
    .bind(&q.status)
    .bind(&q.cursor)
    .bind(limit + 1)
    .fetch_all(&s.pool)
    .await?;
    with_finality(&s.pool, page(rows, limit, |a| a.address.clone())).await
}

#[derive(Deserialize)]
pub struct AttestationQuery {
    attester: Option<String>,
    record_hash: Option<String>,
    limit: Option<i64>,
    cursor: Option<String>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct Attestation {
    event_id: String,
    record_hash: String,
    attester: String,
    timestamp: i64,
    ledger: i64,
    tx_hash: String,
    revoked: bool,
}

async fn attestations(
    State(s): State<AppState>,
    Query(q): Query<AttestationQuery>,
) -> Result<Json<Page<Attestation>>, ApiError> {
    let limit = limit(q.limit)?;
    let rows: Vec<Attestation> = sqlx::query_as(
        "SELECT event_id, record_hash, attester, attested_at AS timestamp, ledger, tx_hash,
                revoked_event_id IS NOT NULL AS revoked
         FROM attestations
         WHERE ($1::text IS NULL OR attester = $1)
           AND ($2::text IS NULL OR record_hash = $2)
           AND ($3::text IS NULL OR event_id > $3)
         ORDER BY event_id LIMIT $4",
    )
    .bind(&q.attester)
    .bind(q.record_hash.as_ref().map(|h| h.to_ascii_lowercase()))
    .bind(&q.cursor)
    .bind(limit + 1)
    .fetch_all(&s.pool)
    .await?;
    with_finality(&s.pool, page(rows, limit, |a| a.event_id.clone())).await
}

#[derive(Deserialize)]
pub struct HistoryQuery {
    limit: Option<i64>,
    cursor: Option<String>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct HistoryEntry {
    event_id: String,
    /// `attested` or `revoked`.
    kind: String,
    attester: Option<String>,
    timestamp: Option<i64>,
    ledger: i64,
    tx_hash: String,
}

async fn record_history(
    State(s): State<AppState>,
    Path(hash): Path<String>,
    Query(q): Query<HistoryQuery>,
) -> Result<Json<Page<HistoryEntry>>, ApiError> {
    let limit = limit(q.limit)?;
    let hash = hash.to_ascii_lowercase();
    if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ApiError::BadRequest(
            "hash must be 64 hex characters".into(),
        ));
    }
    let rows: Vec<HistoryEntry> = sqlx::query_as(
        "SELECT * FROM (
             SELECT event_id, 'attested' AS kind, attester, attested_at AS timestamp, ledger, tx_hash
             FROM attestations WHERE record_hash = $1
             UNION ALL
             SELECT event_id, 'revoked', NULL, NULL, ledger, tx_hash
             FROM revocations WHERE record_hash = $1
         ) h
         WHERE ($2::text IS NULL OR event_id > $2)
         ORDER BY event_id LIMIT $3",
    )
    .bind(&hash)
    .bind(&q.cursor)
    .bind(limit + 1)
    .fetch_all(&s.pool)
    .await?;
    with_finality(&s.pool, page(rows, limit, |h| h.event_id.clone())).await
}

#[derive(Deserialize)]
pub struct WorkItemQuery {
    pool: Option<String>,
    status: Option<String>,
    limit: Option<i64>,
    cursor: Option<String>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct WorkItem {
    work_item_id: String,
    pool: String,
    attester: String,
    /// `pending`, `approved`, `claimed`, or `withdrawn`.
    status: String,
    amount: String,
    created_ledger: i64,
    updated_ledger: i64,
    tx_hash: String,
}

async fn work_items(
    State(s): State<AppState>,
    Query(q): Query<WorkItemQuery>,
) -> Result<Json<Page<WorkItem>>, ApiError> {
    let limit = limit(q.limit)?;
    if let Some(status) = &q.status {
        if !["pending", "approved", "claimed", "withdrawn"].contains(&status.as_str()) {
            return Err(ApiError::BadRequest(
                "status must be pending, approved, claimed, or withdrawn".into(),
            ));
        }
    }
    let rows: Vec<WorkItem> = sqlx::query_as(
        "SELECT work_item_id, pool, attester, status, amount::text AS amount,
                created_ledger, updated_ledger, tx_hash
         FROM work_items
         WHERE ($1::text IS NULL OR pool = $1)
           AND ($2::text IS NULL OR status = $2)
           AND ($3::text IS NULL OR work_item_id > $3)
         ORDER BY work_item_id LIMIT $4",
    )
    .bind(&q.pool)
    .bind(&q.status)
    .bind(&q.cursor)
    .bind(limit + 1)
    .fetch_all(&s.pool)
    .await?;
    with_finality(&s.pool, page(rows, limit, |w| w.work_item_id.clone())).await
}

#[derive(Deserialize)]
pub struct PayoutQuery {
    pool: Option<String>,
    attester: Option<String>,
    limit: Option<i64>,
    cursor: Option<String>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct Payout {
    event_id: String,
    pool: String,
    work_item_id: String,
    attester: String,
    amount: String,
    ledger: i64,
    tx_hash: String,
}

async fn payouts(
    State(s): State<AppState>,
    Query(q): Query<PayoutQuery>,
) -> Result<Json<Page<Payout>>, ApiError> {
    let limit = limit(q.limit)?;
    let rows: Vec<Payout> = sqlx::query_as(
        "SELECT event_id, pool, work_item_id, attester, amount::text AS amount, ledger, tx_hash
         FROM payouts
         WHERE ($1::text IS NULL OR pool = $1)
           AND ($2::text IS NULL OR attester = $2)
           AND ($3::text IS NULL OR event_id > $3)
         ORDER BY event_id LIMIT $4",
    )
    .bind(&q.pool)
    .bind(&q.attester)
    .bind(&q.cursor)
    .bind(limit + 1)
    .fetch_all(&s.pool)
    .await?;
    with_finality(&s.pool, page(rows, limit, |p| p.event_id.clone())).await
}
