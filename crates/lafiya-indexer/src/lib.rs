//! Reference event indexer for the Lafiya contracts.
//!
//! Ingests `getEvents` with cursor checkpointing into Postgres, reconciles
//! derived state against on-chain storage, and serves a read-only query API.
//! See `docs/indexer.md` for deployment.

pub mod api;
pub mod archive;
pub mod decode;
pub mod ingest;
pub mod metrics;
pub mod reconcile;
pub mod rpc;
pub mod store;

pub use api::{ApiAuthConfig, RateLimitConfig, RateLimitTier};
pub use archive::{ArchiveConfig, ArchiveEventSource, ArchiveVerification};
pub use rpc::EventSource;
pub use store::{FencingToken, LeaderLease, LeadershipConfig, LeadershipRole};