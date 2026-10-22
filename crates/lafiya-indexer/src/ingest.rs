//! Cursor-checkpointed ingestion from `getEvents`, and backfill from an
//! archived export.

use std::sync::Arc;
use std::time::Duration;

use sqlx::PgPool;

use crate::decode::{cursor_ledger, RawEvent};
use crate::metrics::Metrics;
use crate::reconcile::{self, ReorgOutcome};
use crate::rpc::{EventSource, RpcError, Start};
use crate::store::{self, Checkpoint, StoreError};

#[derive(Debug, thiserror::Error)]
pub enum IngestError {
    /// Ingestion cannot continue without losing history. Never skipped.
    #[error(
        "retention gap: ingestion must resume at ledger {resume}, but RPC only retains \
         ledgers from {oldest}; backfill ledgers {resume}..{oldest} from archived history \
         (`lafiya-indexer backfill`) before restarting"
    )]
    RetentionGap { resume: u32, oldest: u32 },
    #[error("no checkpoint and no start ledger configured (set LAFIYA_START_LEDGER)")]
    NoStart,
    #[error("backfill: {0}")]
    Backfill(String),
    #[error(
        "ledger hash mismatch at ledger {ledger}: checkpoint has {expected}, RPC serves \
         {actual}; rollback to the common ancestor failed"
    )]
    Reorg { ledger: u32, expected: String, actual: String },
    #[error(transparent)]
    Rpc(#[from] RpcError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Db(#[from] sqlx::Error),
    #[error(transparent)]
    Reconcile(#[from] reconcile::ReconcileError),
}

impl IngestError {
    /// Errors that retrying cannot fix; the process must stop.
    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            Self::RetentionGap { .. } | Self::NoStart | Self::Store(StoreError::Decode(_))
        )
    }
}

/// Fail unless RPC still serves `resume` (the first ledger not yet ingested).
pub fn check_retention(resume: u32, oldest: u32) -> Result<(), IngestError> {
    if resume < oldest {
        Err(IngestError::RetentionGap { resume, oldest })
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Step {
    pub applied: usize,
    /// The page was not full, so ingestion has reached the RPC's tip.
    pub caught_up: bool,
}

pub struct Ingestor<S> {
    pub pool: PgPool,
    pub source: S,
    pub metrics: Arc<Metrics>,
    /// First ledger to ingest when there is no checkpoint yet (the contracts'
    /// deployment ledger).
    pub start_ledger: Option<u32>,
    pub page_limit: u32,
}

impl<S: EventSource> Ingestor<S> {
    /// Fetch and apply one page of events.
    pub async fn step(&self) -> Result<Step, IngestError> {
        let checkpoint = store::checkpoint(&self.pool).await?;
        let (start, resume) = match &checkpoint {
            Some(Checkpoint {
                cursor: Some(c),
                ledger,
            }) => (
                Start::Cursor(c.clone()),
                cursor_ledger(c).unwrap_or(*ledger),
            ),
            Some(Checkpoint {
                cursor: None,
                ledger,
            }) => (Start::Ledger(*ledger), *ledger),
            None => {
                let l = self.start_ledger.ok_or(IngestError::NoStart)?;
                (Start::Ledger(l), l)
            }
        };

        let window = self.source.ledger_window().await?;
        check_retention(resume, window.oldest_ledger)?;

        // Verify hash continuity before touching derived tables: if the RPC's
        // tip diverged from what we recorded, roll back and re-ingest instead
        // of persisting events from a ledger that may be dropped.
        let page = match self.fetch_verified_page(&start, resume).await? {
            Some(page) => page,
            None => {
                // A reorg was rolled back; the next step re-reads the
                // checkpoint and re-ingests from the common ancestor.
                return Ok(Step {
                    applied: 0,
                    caught_up: false,
                });
            }
        };

        let next = store::checkpoint_after(&page.cursor, &page.events, resume);
        let applied = store::apply_page(&self.pool, &page.events, &next).await?;

        self.metrics.events_total.inc_by(applied as u64);
        self.metrics.checkpoint_ledger.set(i64::from(next.ledger));
        self.metrics
            .lag_ledgers
            .set(i64::from(page.latest_ledger.saturating_sub(next.ledger)));
        Ok(Step {
            applied,
            caught_up: page.events.len() < self.page_limit as usize,
        })
    }

    /// Fetch one page and verify its ledger hash chain against the recorded
    /// hashes. Returns `None` when a reorg was detected and rolled back (the
    /// caller must re-read the checkpoint and re-ingest).
    async fn fetch_verified_page(
        &self,
        start: &Start,
        resume: u32,
    ) -> Result<Option<crate::rpc::EventPage>, IngestError> {
        let page = match self.source.get_events(start, self.page_limit).await {
            Err(e) if e.is_out_of_retention() => {
                let window = self.source.ledger_window().await?;
                return Err(IngestError::RetentionGap {
                    resume,
                    oldest: window.oldest_ledger,
                });
            }
            other => other?,
        };

        // The page's first ledger hash must match what we recorded for that
        // ledger (if we have it). A mismatch means the provider serves a
        // divergent history.
        if let Some(first) = page.events.first() {
            if let Some(expected) = store::ledger_hash(&self.pool, first.ledger).await? {
                if expected != first.ledger_hash {
                    self.handle_reorg(first.ledger, &expected, &first.ledger_hash)
                        .await?;
                    return Ok(None);
                }
            }
        }

        Ok(Some(page))
    }

    /// Roll back derived tables to the common ancestor and record the reorg.
    async fn handle_reorg(
        &self,
        ledger: u32,
        expected: &str,
        actual: &str,
    ) -> Result<(), IngestError> {
        self.metrics.reorg_detected_total.inc();
        tracing::warn!(
            ledger,
            expected,
            actual,
            "ledger hash mismatch; rolling back to common ancestor"
        );
        match reconcile::rollback_to_common_ancestor(&self.pool, ledger).await? {
            ReorgOutcome::RolledBack { depth, ancestor } => {
                self.metrics.reorg_rollback_depth.set(i64::from(depth));
                self.metrics
                    .checkpoint_ledger
                    .set(i64::from(ancestor.unwrap_or(0)));
                Ok(())
            }
            ReorgOutcome::NoCommonAncestor => Err(IngestError::Reorg {
                ledger,
                expected: expected.to_string(),
                actual: actual.to_string(),
            }),
        }
    }

    /// Ingest until a fatal error. Transient errors are logged and retried.
    pub async fn run(&self, poll_interval: Duration) -> IngestError {
        let mut backoff = poll_interval;
        loop {
            match self.step().await {
                Ok(step) => {
                    backoff = poll_interval;
                    if step.caught_up {
                        tokio::time::sleep(poll_interval).await;
                    }
                }
                Err(e) if e.is_fatal() => return e,
                Err(e) => {
                    self.metrics.ingest_errors_total.inc();
                    tracing::warn!(error = %e, "ingestion step failed; retrying");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(300));
                }
            }
        }
    }
}

/// Load archived events (RPC `getEvents` event objects, one JSON per line)
/// that precede everything already ingested.
///
/// With `through_ledger`, the export is declared complete through that
/// ledger and live ingestion resumes at `through_ledger + 1`; otherwise it
/// resumes after the last exported event.
pub async fn backfill(
    pool: &PgPool,
    mut events: Vec<RawEvent>,
    through_ledger: Option<u32>,
) -> Result<usize, IngestError> {
    events.sort_by(|a, b| a.id.cmp(&b.id));
    events.dedup_by(|a, b| a.id == b.id);
    let (Some(first), Some(last)) = (events.first(), events.last()) else {
        return Err(IngestError::Backfill("no events to load".into()));
    };
    if let Some(cp) = store::checkpoint(pool).await? {
        // Derived state must be built in chain order.
        if cp.ledger >= first.ledger {
            return Err(IngestError::Backfill(format!(
                "checkpoint is already at ledger {}, not before the export's first ledger {}",
                cp.ledger, first.ledger
            )));
        }
    }
    if let Some(t) = through_ledger {
        if t < last.ledger {
            return Err(IngestError::Backfill(format!(
                "--through-ledger {t} is before the export's last event (ledger {})",
                last.ledger
            )));
        }
    }

    let mut applied = 0;
    let chunks: Vec<&[RawEvent]> = events.chunks(500).collect();
    for (i, chunk) in chunks.iter().enumerate() {
        let tail = chunk.last().expect("non-empty chunk");
        let next = match through_ledger {
            Some(t) if i + 1 == chunks.len() => Checkpoint {
                cursor: None,
                ledger: t + 1,
            },
            _ => Checkpoint {
                cursor: Some(tail.id.clone()),
                ledger: tail.ledger,
            },
        };
        applied += store::apply_page(pool, chunk, &next).await?;
    }
    Ok(applied)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retention_check_fails_below_oldest_ledger() {
        assert!(check_retention(500, 500).is_ok());
        assert!(check_retention(900, 500).is_ok());
        let err = check_retention(100, 500).unwrap_err();
        assert!(matches!(
            err,
            IngestError::RetentionGap {
                resume: 100,
                oldest: 500
            }
        ));
        assert!(err.is_fatal());
    }
}
