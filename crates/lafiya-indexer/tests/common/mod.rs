#![allow(dead_code)]

use sqlx::postgres::PgPoolOptions;
use sqlx::{Executor, PgPool};

/// A pool on a fresh, migrated schema, or `None` (test skipped) when
/// `DATABASE_URL` is not set.
pub async fn test_pool() -> Option<PgPool> {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL not set; skipping database test");
        return None;
    };
    let schema = format!("test_{}", rand::random::<u32>());
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    admin
        .execute(format!("CREATE SCHEMA {schema}").as_str())
        .await
        .unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .after_connect(move |conn, _| {
            let schema = schema.clone();
            Box::pin(async move {
                conn.execute(format!("SET search_path TO {schema}").as_str())
                    .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    lafiya_indexer::store::MIGRATOR.run(&pool).await.unwrap();
    Some(pool)
}

/// Number of attestations in the full synthetic dataset (10M).
pub const FULL_ATTESTATIONS: i64 = 10_000_000;
/// Number of attesters in the full synthetic dataset (50k).
pub const FULL_ATTESTERS: i64 = 50_000;

/// Number of attestations in the CI smoke dataset. Small enough to seed in a
/// few seconds, large enough that the planner prefers index scans.
pub const SMOKE_ATTESTATIONS: i64 = 50_000;
/// Number of attesters in the CI smoke dataset.
pub const SMOKE_ATTESTERS: i64 = 2_000;

/// Proposed p99 latency budget for the CI smoke test, in milliseconds.
///
/// Rationale: on the smoke dataset (50k rows) every supported query should
/// complete in well under a millisecond of server time; 50ms leaves generous
/// headroom for CI noise, connection setup, and slower shared runners while
/// still catching accidental sequential scans or missing indexes.
pub const P99_BUDGET_MS: f64 = 50.0;

/// Seed the synthetic dataset into the current schema.
///
/// The generator uses `generate_series` so it runs entirely server-side, and
/// introduces realistic skew:
///   * attester ids are drawn from a Zipf-like distribution (a handful of
///     attesters dominate), and
///   * timestamps are clustered around a few "hot" windows rather than being
///     uniform.
pub async fn seed_synthetic(pool: &PgPool, attestations: i64, attesters: i64) {
    assert!(attesters > 0, "attesters must be positive");
    assert!(attestations > 0, "attestations must be positive");

    // Attesters: a stable id space with a skewed "weight" column so we can
    // pick hot attesters deterministically.
    sqlx::query(
        r#"
        INSERT INTO attesters (id, address)
        SELECT g,
               '0x' || lpad(to_hex(g), 40, '0')
        FROM generate_series(1, $1) AS g
        "#,
    )
    .bind(attesters)
    .execute(pool)
    .await
    .unwrap();

    // Attestations: skew attester selection toward low ids (Zipf-ish via
    // power distribution) and cluster timestamps into a few hot windows.
    sqlx::query(
        r#"
        INSERT INTO attestations (id, attester_id, schema_id, created_at, revoked)
        SELECT g,
               -- Zipf-like skew: pow(u, 3) biases toward small attester ids.
               1 + floor(pow(random(), 3) * $2)::bigint,
               -- A small set of schemas, also skewed.
               1 + floor(pow(random(), 2) * 8)::bigint,
               -- Cluster timestamps: 70% within the last day, 30% spread over
               -- the prior 30 days.
               CASE
                 WHEN random() < 0.7
                   THEN now() - (random() * interval '1 day')
                 ELSE now() - interval '1 day' - (random() * interval '30 days')
               END,
               -- ~2% revoked.
               (random() < 0.02)
        FROM generate_series(1, $1) AS g
        "#,
    )
    .bind(attestations)
    .bind(attesters)
    .execute(pool)
    .await
    .unwrap();

    // Refresh planner statistics so EXPLAIN reflects the seeded data.
    pool.execute("ANALYZE attesters").await.unwrap();
    pool.execute("ANALYZE attestations").await.unwrap();
}

/// A single endpoint filter set to exercise.
#[derive(Clone, Copy, Debug)]
pub struct FilterSet {
    pub name: &'static str,
    pub sql: &'static str,
}

/// Every supported endpoint filter set. Each query is parameterized with
/// `$1 = limit + 1` (the page helper fetches one extra row to detect a next
/// page) and, where relevant, a keyset cursor.
pub const FILTER_SETS: &[FilterSet] = &[
    FilterSet {
        name: "list_all",
        sql: "SELECT id, attester_id, schema_id, created_at, revoked \
              FROM attestations ORDER BY created_at DESC, id DESC LIMIT $1",
    },
    FilterSet {
        name: "by_attester",
        sql: "SELECT id, attester_id, schema_id, created_at, revoked \
              FROM attestations WHERE attester_id = $2 \
              ORDER BY created_at DESC, id DESC LIMIT $1",
    },
    FilterSet {
        name: "by_schema",
        sql: "SELECT id, attester_id, schema_id, created_at, revoked \
              FROM attestations WHERE schema_id = $2 \
              ORDER BY created_at DESC, id DESC LIMIT $1",
    },
    FilterSet {
        name: "by_attester_and_schema",
        sql: "SELECT id, attester_id, schema_id, created_at, revoked \
              FROM attestations WHERE attester_id = $2 AND schema_id = $3 \
              ORDER BY created_at DESC, id DESC LIMIT $1",
    },
    FilterSet {
        name: "by_revoked",
        sql: "SELECT id, attester_id, schema_id, created_at, revoked \
              FROM attestations WHERE revoked = $2 \
              ORDER BY created_at DESC, id DESC LIMIT $1",
    },
    FilterSet {
        name: "keyset_all",
        sql: "SELECT id, attester_id, schema_id, created_at, revoked \
              FROM attestations WHERE (created_at, id) < ($2, $3) \
              ORDER BY created_at DESC, id DESC LIMIT $1",
    },
    FilterSet {
        name: "keyset_by_attester",
        sql: "SELECT id, attester_id, schema_id, created_at, revoked \
              FROM attestations \
              WHERE attester_id = $2 AND (created_at, id) < ($3, $4) \
              ORDER BY created_at DESC, id DESC LIMIT $1",
    },
];

/// Capture `EXPLAIN (ANALYZE, BUFFERS)` for every filter set and return the
/// plans keyed by filter name.
pub async fn explain_all(pool: &PgPool) -> Vec<(String, String)> {
    let mut out = Vec::with_capacity(FILTER_SETS.len());
    for fs in FILTER_SETS {
        let plan = explain_one(pool, fs).await;
        out.push((fs.name.to_string(), plan));
    }
    out
}

/// Run `EXPLAIN (ANALYZE, BUFFERS)` for a single filter set.
pub async fn explain_one(pool: &PgPool, fs: &FilterSet) -> String {
    let sql = format!("EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT) {}", fs.sql);
    let mut q = sqlx::query_scalar::<_, String>(&sql).bind(21_i64);
    // Bind the remaining placeholders with representative values. The exact
    // values matter less than the shape; we use a hot attester and schema.
    q = q.bind(1_i64).bind(1_i64).bind(1_i64);
    let rows: Vec<String> = q.fetch_all(pool).await.unwrap();
    rows.join("\n")
}

/// Returns true if the plan text contains a sequential scan on a large table.
pub fn has_seq_scan_on_large_table(plan: &str) -> bool {
    plan.lines().any(|line| {
        let l = line.to_ascii_lowercase();
        l.contains("seq scan on attestations") || l.contains("seq scan on attesters")
    })
}

/// Measure per-query latency (in milliseconds) over `iterations` runs for a
/// single filter set, returning the sorted samples.
pub async fn measure_latencies(
    pool: &PgPool,
    fs: &FilterSet,
    iterations: usize,
) -> Vec<f64> {
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = std::time::Instant::now();
        let mut q = sqlx::query_scalar::<_, i64>(fs.sql).bind(21_i64);
        q = q.bind(1_i64).bind(1_i64).bind(1_i64);
        let _ = q.fetch_all(pool).await.unwrap();
        samples.push(start.elapsed().as_secs_f64() * 1000.0);
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    samples
}

/// Compute the p99 (nearest-rank) of a sorted sample set.
pub fn p99(sorted_ms: &[f64]) -> f64 {
    if sorted_ms.is_empty() {
        return 0.0;
    }
    let rank = ((sorted_ms.len() as f64) * 0.99).ceil() as usize;
    let idx = rank.saturating_sub(1).min(sorted_ms.len() - 1);
    sorted_ms[idx]
}