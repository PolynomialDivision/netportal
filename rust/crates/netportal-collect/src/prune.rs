//! The job `prune` (Python `collect/prune.py`, INVENTORY 9.10.4): the retention of
//! `registry::prune`, once a day, also while Authentik cannot be read.

use indexmap::IndexMap;
use netportal_core::registry;
use serde::{Deserialize, Serialize};

use crate::scheduler::{Context, JobResult, to_cursor};

pub const NAME: &str = "prune";
const LOG: &str = "netportal.collect.prune";

/// The cursor: `{"last_run": {table: rows deleted}}` (informational).
#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Cursor {
    #[serde(default)]
    pub last_run: IndexMap<String, u64>,
}

pub async fn run(ctx: &mut Context) -> JobResult {
    // In batches, each committed: a backlog (a flood of rejects, a first run after a long pause)
    // is many short statements, never one that runs into the statement timeout.
    let deleted =
        registry::prune(&mut ctx.db, Some(ctx.now), registry::AUDIT_DAYS, registry::PRUNE_BATCH, true).await?;
    ctx.db.commit().await?;
    let done: Vec<String> = deleted.iter().filter(|(_, n)| **n > 0).map(|(t, n)| format!("{t} {n}")).collect();
    if !done.is_empty() {
        tracing::info!(target: LOG, "prune: {}", done.join(", "));
    }
    to_cursor(&Cursor { last_run: deleted.into_iter().map(|(t, n)| (t.to_string(), n)).collect() })
}
