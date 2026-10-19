//! Read-only HTTP/JSON API (spec: `openapi.yaml`, served at `/openapi.yaml`).

use std::convert::Infallible;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures::stream::Stream;
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
        .route("/events/stream", get(events_stream))
        .route("/subscriptions", get(list_subscriptions).post(create_subscription))
        .route(
            "/subscriptions/{id}",
            get(get_subscription).delete(delete_subscription),
        )
        .route("/subscriptions/{id}/deliveries", get(list_deliveries))
        .with_state(state)
}

pub enum ApiError {
    BadRequest(String),
    NotFound(String),
    Db(sqlx::Error),
    Delivery(String),
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
            Self::NotFound(m) => (StatusCode::NOT_FOUND, m),
            Self::Delivery(m) => (StatusCode::BAD_GATEWAY, m),
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
#[derive(Serialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
}

fn page<T>(mut items: Vec<T>, limit: i64, key: impl Fn(&T) -> String) -> Page<T> {
    let next_cursor = if items.len() as i64 > limit {
        items.truncate(limit as usize);
        items.last().map(key)
    } else {
        None
    };
    Page { items, next_cursor }
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
    Ok(Json(page(rows, limit, |a| a.address.clone())))
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
    Ok(Json(page(rows, limit, |a| a.event_id.clone())))
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
    Ok(Json(page(rows, limit, |h| h.event_id.clone())))
}

/// Parse a `Last-Event-ID` value into the ledger/event index used by
/// `raw_events`. Accepts either a bare event id or `<ledger>:<event_id>`.
fn parse_last_event_id(raw: &str) -> Result<Option<(i64, String)>, ApiError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    if let Some((ledger, event_id)) = raw.split_once(':') {
        let ledger: i64 = ledger
            .parse()
            .map_err(|_| ApiError::BadRequest("Last-Event-ID ledger must be an integer".into()))?;
        if event_id.is_empty() {
            return Err(ApiError::BadRequest(
                "Last-Event-ID event id must not be empty".into(),
            ));
        }
        return Ok(Some((ledger, event_id.to_string())));
    }
    Ok(Some((0, raw.to_string())))
}

#[derive(Deserialize)]
pub struct StreamQuery {
    contract: Option<String>,
    event_type: Option<String>,
    attester: Option<String>,
}

#[derive(Serialize, sqlx::FromRow)]
struct RawEvent {
    event_id: String,
    ledger: i64,
    contract_id: String,
    event_type: String,
    attester: Option<String>,
    payload: serde_json::Value,
}

/// Server-sent events over `raw_events`, resumable via `Last-Event-ID`.
///
/// The SSE `id` field is the ledger event id, so a client that reconnects with
/// `Last-Event-ID` never observes a duplicate event id (replays are idempotent).
async fn events_stream(
    State(s): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<StreamQuery>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, ApiError> {
    let resume = match headers.get("last-event-id") {
        Some(v) => v
            .to_str()
            .map_err(|_| ApiError::BadRequest("Last-Event-ID must be ASCII".into()))
            .and_then(parse_last_event_id)?,
        None => None,
    };
    let (start_ledger, start_event_id) = resume.unwrap_or((0, String::new()));
    let attester = q.attester.map(|a| a.to_ascii_lowercase());

    let stream = async_stream::stream! {
        let mut cursor_ledger = start_ledger;
        let mut cursor_event = start_event_id;
        loop {
            let rows: Result<Vec<RawEvent>, sqlx::Error> = sqlx::query_as(
                "SELECT event_id, ledger, contract_id, event_type, attester, payload
                 FROM raw_events
                 WHERE (ledger > $1 OR (ledger = $1 AND event_id > $2))
                   AND ($3::text IS NULL OR contract_id = $3)
                   AND ($4::text IS NULL OR event_type = $4)
                   AND ($5::text IS NULL OR attester = $5)
                 ORDER BY ledger, event_id LIMIT 100",
            )
            .bind(cursor_ledger)
            .bind(&cursor_event)
            .bind(&q.contract)
            .bind(&q.event_type)
            .bind(&attester)
            .fetch_all(&s.pool)
            .await;

            match rows {
                Ok(rows) if rows.is_empty() => {
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
                Ok(rows) => {
                    for row in rows {
                        cursor_ledger = row.ledger;
                        cursor_event = row.event_id.clone();
                        let data = json!({
                            "event_id": row.event_id,
                            "ledger": row.ledger,
                            "contract": row.contract_id,
                            "event_type": row.event_type,
                            "attester": row.attester,
                            "payload": row.payload,
                        });
                        yield Ok(Event::default()
                            .id(format!("{}:{}", row.ledger, row.event_id))
                            .event(row.event_type)
                            .data(data.to_string()));
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "sse query failed");
                    yield Ok(Event::default()
                        .event("error")
                        .data(json!({ "error": "database unavailable" }).to_string()));
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
            }
        }
    };

    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

#[derive(Deserialize)]
pub struct SubscriptionQuery {
    limit: Option<i64>,
    cursor: Option<String>,
}

#[derive(Deserialize)]
pub struct CreateSubscription {
    /// Webhook target; must be `https://`.
    pub url: String,
    pub contract: Option<String>,
    pub event_type: Option<String>,
    pub attester: Option<String>,
    /// Optional caller-supplied secret; generated when omitted.
    pub secret: Option<String>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct Subscription {
    id: String,
    url: String,
    contract: Option<String>,
    event_type: Option<String>,
    attester: Option<String>,
    created_at: i64,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct Delivery {
    id: i64,
    subscription_id: String,
    event_id: String,
    attempts: i32,
    status: String,
    last_error: Option<String>,
    next_attempt_at: Option<i64>,
}

async fn list_subscriptions(
    State(s): State<AppState>,
    Query(q): Query<SubscriptionQuery>,
) -> Result<Json<Page<Subscription>>, ApiError> {
    let limit = limit(q.limit)?;
    let rows: Vec<Subscription> = sqlx::query_as(
        "SELECT id, url, contract, event_type, attester, created_at
         FROM subscriptions
         WHERE ($1::text IS NULL OR id > $1)
         ORDER BY id LIMIT $2",
    )
    .bind(&q.cursor)
    .bind(limit + 1)
    .fetch_all(&s.pool)
    .await?;
    Ok(Json(page(rows, limit, |s| s.id.clone())))
}

async fn create_subscription(
    State(s): State<AppState>,
    Json(body): Json<CreateSubscription>,
) -> Result<(StatusCode, Json<Subscription>), ApiError> {
    if !body.url.starts_with("https://") {
        return Err(ApiError::BadRequest(
            "subscription url must use https".into(),
        ));
    }
    let attester = body.attester.map(|a| a.to_ascii_lowercase());
    let secret = body
        .secret
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let row: Subscription = sqlx::query_as(
        "INSERT INTO subscriptions (url, contract, event_type, attester, secret)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, url, contract, event_type, attester, created_at",
    )
    .bind(&body.url)
    .bind(&body.contract)
    .bind(&body.event_type)
    .bind(&attester)
    .bind(&secret)
    .fetch_one(&s.pool)
    .await?;
    Ok((StatusCode::CREATED, Json(row)))
}

async fn get_subscription(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Subscription>, ApiError> {
    let row: Option<Subscription> = sqlx::query_as(
        "SELECT id, url, contract, event_type, attester, created_at
         FROM subscriptions WHERE id = $1",
    )
    .bind(&id)
    .fetch_optional(&s.pool)
    .await?;
    row.map(Json)
        .ok_or_else(|| ApiError::NotFound("subscription not found".into()))
}

async fn delete_subscription(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let res = sqlx::query("DELETE FROM subscriptions WHERE id = $1")
        .bind(&id)
        .execute(&s.pool)
        .await?;
    if res.rows_affected() == 0 {
        return Err(ApiError::NotFound("subscription not found".into()));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn list_deliveries(
    State(s): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<SubscriptionQuery>,
) -> Result<Json<Page<Delivery>>, ApiError> {
    let limit = limit(q.limit)?;
    let rows: Vec<Delivery> = sqlx::query_as(
        "SELECT id, subscription_id, event_id, attempts, status, last_error, next_attempt_at
         FROM webhook_deliveries
         WHERE subscription_id = $1 AND ($2::bigint IS NULL OR id > $2)
         ORDER BY id LIMIT $3",
    )
    .bind(&id)
    .bind(q.cursor.as_ref().and_then(|c| c.parse::<i64>().ok()))
    .bind(limit + 1)
    .fetch_all(&s.pool)
    .await?;
    Ok(Json(page(rows, limit, |d| d.id.to_string())))
}
