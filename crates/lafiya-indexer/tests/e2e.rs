//! End-to-end: index real contracts on a local quickstart and assert the API
//! agrees with on-chain storage. Driven by `tests/e2e.sh`, which deploys the
//! contracts, runs a scenario, and sets:
//!
//!   DATABASE_URL, LAFIYA_E2E_RPC_URL, LAFIYA_E2E_START_LEDGER,
//!   LAFIYA_E2E_ATTESTER_REGISTRY, LAFIYA_E2E_ATTESTATION_REGISTRY
//!
//! Skipped unless those variables are set.

mod common;

use std::collections::BTreeSet;
use std::sync::Arc;

use lafiya_indexer::api::{router, AppState};
use lafiya_indexer::archive::ArchiveSource;
use lafiya_indexer::ingest::Ingestor;
use lafiya_indexer::metrics::Metrics;
use lafiya_indexer::reconcile::{ChainAttestation, Reconciler};
use lafiya_indexer::rpc::{EventSource, RpcClient};
use serde_json::Value;

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

async fn get_all(base: &str, path: &str) -> Vec<Value> {
    let sep = if path.contains('?') { '&' } else { '?' };
    let mut items = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let mut url = format!("{base}{path}{sep}limit=2");
        if let Some(c) = &cursor {
            url.push_str(&format!("&cursor={c}"));
        }
        let body: Value = reqwest::get(url).await.unwrap().json().await.unwrap();
        items.extend(body["items"].as_array().unwrap().iter().cloned());
        match body["next_cursor"].as_str() {
            Some(c) => cursor = Some(c.to_string()),
            None => return items,
        }
    }
}

#[tokio::test]
async fn api_matches_contract_state() {
    let (Some(rpc_url), Some(start), Some(attester_registry), Some(attestation_registry)) = (
        env("LAFIYA_E2E_RPC_URL"),
        env("LAFIYA_E2E_START_LEDGER"),
        env("LAFIYA_E2E_ATTESTER_REGISTRY"),
        env("LAFIYA_E2E_ATTESTATION_REGISTRY"),
    ) else {
        eprintln!("LAFIYA_E2E_* not set; skipping (run tests/e2e.sh)");
        return;
    };
    let Some(pool) = common::test_pool().await else {
        return;
    };
    let metrics = Arc::new(Metrics::new());
    let rpc = RpcClient::new(
        rpc_url,
        vec![attester_registry.clone(), attestation_registry.clone()],
    );

    let ingestor = Ingestor {
        pool: pool.clone(),
        source: rpc.clone(),
        metrics: metrics.clone(),
        start_ledger: Some(start.parse().unwrap()),
        page_limit: 5,
    };
    while !ingestor.step().await.unwrap().caught_up {}

    let reconciler = Reconciler {
        pool: pool.clone(),
        rpc,
        metrics: metrics.clone(),
        attester_registry,
        attestation_registry,
        sample_size: 1_000,
        max_lag_ledgers: i64::MAX,
    };
    assert_eq!(
        reconciler.cycle().await.unwrap(),
        0,
        "reconciler mismatches"
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let app = router(AppState { pool, metrics });
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    // Attesters: status and region equal `get_attester_status`.
    let attesters = get_all(&base, "/attesters").await;
    let statuses: BTreeSet<&str> = attesters
        .iter()
        .map(|a| a["status"].as_str().unwrap())
        .collect();
    assert_eq!(
        statuses,
        BTreeSet::from(["active", "removed", "suspended"]),
        "scenario should cover every attester status"
    );
    for a in &attesters {
        let chain = reconciler
            .chain_attester(a["address"].as_str().unwrap())
            .await
            .unwrap();
        let expected = match &chain {
            None => "removed",
            Some(c) if c.suspended => "suspended",
            Some(_) => "active",
        };
        assert_eq!(a["status"], expected, "{a}");
        assert_eq!(
            a["region"].as_str(),
            chain.as_ref().and_then(|c| c.region.as_deref()),
            "{a}"
        );
    }

    // Records: the current attestation from history equals `get_attestation`.
    let hashes: BTreeSet<String> = get_all(&base, "/attestations")
        .await
        .iter()
        .map(|a| a["record_hash"].as_str().unwrap().to_string())
        .collect();
    let mut saw_revoked = false;
    for hash in &hashes {
        let history = get_all(&base, &format!("/records/{hash}/history")).await;
        let mut current = None;
        for h in &history {
            current = match h["kind"].as_str().unwrap() {
                "revoked" => {
                    saw_revoked = true;
                    None
                }
                _ => Some(ChainAttestation {
                    attester: h["attester"].as_str().unwrap().into(),
                    timestamp: h["timestamp"].as_u64().unwrap(),
                }),
            };
        }
        let chain = reconciler.chain_attestation(hash).await.unwrap();
        assert_eq!(current, chain, "record {hash}");
    }
    assert!(saw_revoked, "scenario should include a revocation");
}

/// Golden comparison: a fresh database backfilled from genesis via the ledger
/// archive must equal one built live from RPC. Driven by `tests/e2e.sh`, which
/// additionally sets:
///
///   LAFIYA_E2E_ARCHIVE_URL, LAFIYA_E2E_ARCHIVE_CHECKPOINT
///
/// Skipped unless the archive variables are set.
#[tokio::test]
async fn archive_backfill_matches_live() {
    let (Some(rpc_url), Some(start), Some(attester_registry), Some(attestation_registry)) = (
        env("LAFIYA_E2E_RPC_URL"),
        env("LAFIYA_E2E_START_LEDGER"),
        env("LAFIYA_E2E_ATTESTER_REGISTRY"),
        env("LAFIYA_E2E_ATTESTATION_REGISTRY"),
    ) else {
        eprintln!("LAFIYA_E2E_* not set; skipping (run tests/e2e.sh)");
        return;
    };
    let (Some(archive_url), Some(checkpoint)) = (
        env("LAFIYA_E2E_ARCHIVE_URL"),
        env("LAFIYA_E2E_ARCHIVE_CHECKPOINT"),
    ) else {
        eprintln!("LAFIYA_E2E_ARCHIVE_* not set; skipping archive backfill test");
        return;
    };
    let Some(live_pool) = common::test_pool().await else {
        return;
    };
    let Some(archive_pool) = common::test_pool().await else {
        return;
    };
    let metrics = Arc::new(Metrics::new());
    let contracts = vec![attester_registry.clone(), attestation_registry.clone()];
    let start_ledger: u32 = start.parse().unwrap();

    // Live build straight from RPC.
    let live_rpc = RpcClient::new(rpc_url.clone(), contracts.clone());
    let live = Ingestor {
        pool: live_pool.clone(),
        source: live_rpc.clone(),
        metrics: metrics.clone(),
        start_ledger: Some(start_ledger),
        page_limit: 5,
    };
    while !live.step().await.unwrap().caught_up {}

    // Archive build from genesis, then hand off to live RPC at the verified
    // checkpoint boundary.
    let archive = ArchiveSource::new(archive_url, checkpoint, contracts.clone())
        .await
        .expect("archive source must verify against checkpoint hashes");
    let boundary = archive.verified_boundary();
    let backfill = Ingestor {
        pool: archive_pool.clone(),
        source: archive.clone(),
        metrics: metrics.clone(),
        start_ledger: Some(start_ledger),
        page_limit: 5,
    };
    while !backfill.step().await.unwrap().caught_up {}
    assert!(
        backfill.checkpoint_ledger().await.unwrap() >= boundary,
        "archive backfill must reach the verified boundary"
    );
    let handoff = Ingestor {
        pool: archive_pool.clone(),
        source: live_rpc,
        metrics: metrics.clone(),
        start_ledger: Some(boundary),
        page_limit: 5,
    };
    while !handoff.step().await.unwrap().caught_up {}

    // Golden comparison: both databases must agree exactly.
    let live_state = common::dump_state(&live_pool).await;
    let archive_state = common::dump_state(&archive_pool).await;
    assert_eq!(
        archive_state, live_state,
        "archive backfill diverged from live build"
    );
}

/// Rate limits must hold under 10x the configured rate.
#[tokio::test]
async fn rate_limits_hold_under_10x_load() {
    let Some(pool) = common::test_pool().await else {
        return;
    };
    let metrics = Arc::new(Metrics::new());
    let config = lafiya_indexer::api::RateLimitConfig {
        per_ip_per_second: 5,
        per_key_per_second: 5,
        burst: 5,
        disabled: false,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let app = router(AppState {
        pool,
        metrics,
        rate_limits: config,
    });
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    // Fire 10x the configured rate concurrently and count successes.
    let client = reqwest::Client::new();
    let mut tasks = Vec::new();
    for _ in 0..50 {
        let client = client.clone();
        let url = format!("{base}/attesters?limit=1");
        tasks.push(tokio::spawn(async move {
            client.get(url).send().await.unwrap().status().as_u16()
        }));
    }
    let mut allowed = 0;
    for t in tasks {
        if t.await.unwrap() == 200 {
            allowed += 1;
        }
    }
    assert!(
        allowed <= config.burst + config.per_ip_per_second,
        "rate limit exceeded: {allowed} allowed"
    );
    assert!(allowed > 0, "rate limiter must not deny everything");
}

/// Killing the leader mid-page must not duplicate or lose ingestion; a
/// follower takes over and the final state matches a single-writer build.
#[tokio::test]
async fn leader_failover_is_exactly_once() {
    let (Some(rpc_url), Some(start), Some(attester_registry), Some(attestation_registry)) = (
        env("LAFIYA_E2E_RPC_URL"),
        env("LAFIYA_E2E_START_LEDGER"),
        env("LAFIYA_E2E_ATTESTER_REGISTRY"),
        env("LAFIYA_E2E_ATTESTATION_REGISTRY"),
    ) else {
        eprintln!("LAFIYA_E2E_* not set; skipping (run tests/e2e.sh)");
        return;
    };
    let Some(pool) = common::test_pool().await else {
        return;
    };
    let metrics = Arc::new(Metrics::new());
    let contracts = vec![attester_registry, attestation_registry];
    let start_ledger: u32 = start.parse().unwrap();

    let leader = Ingestor {
        pool: pool.clone(),
        source: RpcClient::new(rpc_url.clone(), contracts.clone()),
        metrics: metrics.clone(),
        start_ledger: Some(start_ledger),
        page_limit: 5,
    };
    // Advance one page, then simulate a crash mid-page.
    leader.step().await.unwrap();
    drop(leader);

    // Follower acquires leadership and resumes from the committed checkpoint.
    let follower = Ingestor {
        pool: pool.clone(),
        source: RpcClient::new(rpc_url, contracts),
        metrics: metrics.clone(),
        start_ledger: Some(start_ledger),
        page_limit: 5,
    };
    while !follower.step().await.unwrap().caught_up {}

    // Exactly-once: a full single-writer build must match the failover build.
    let Some(reference_pool) = common::test_pool().await else {
        return;
    };
    let reference = Ingestor {
        pool: reference_pool.clone(),
        source: RpcClient::new(
            env("LAFIYA_E2E_RPC_URL").unwrap(),
            vec![
                env("LAFIYA_E2E_ATTESTER_REGISTRY").unwrap(),
                env("LAFIYA_E2E_ATTESTATION_REGISTRY").unwrap(),
            ],
        ),
        metrics,
        start_ledger: Some(start_ledger),
        page_limit: 5,
    };
    while !reference.step().await.unwrap().caught_up {}

    assert_eq!(
        common::dump_state(&pool).await,
        common::dump_state(&reference_pool).await,
        "failover build diverged from single-writer build"
    );
}
