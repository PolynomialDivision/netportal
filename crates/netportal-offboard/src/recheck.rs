//! The Disconnect reconciliation (owner's review 2026-10-29): a revocation, a policy move or an
//! offboarding takes effect for new authentications at once (FreeRADIUS asks the registry every
//! time, TLS resumption is off), but a revoked certificate does not end an association the
//! access point already has: only a Disconnect-Request (or the RADIUS Session-Timeout, 12 h in
//! production) does. When that Disconnect fails (timeout, NAK, the process dying between the
//! commit and the send, a forged or lost ACK), the device would stay connected. This loop finds
//! such sessions in the accounting and disconnects them again.
//!
//! A round (every `NETPORTAL_DISCONNECT_RECHECK_S`, 30 s, in `netportal offboard --every N`, the
//! process that already holds the DAE secret):
//!
//! 1. reads the live accounting sessions of locked devices (`registry::locked_live_sessions`):
//!    no Stop and a Start or Interim-Update within two accounting intervals plus 60 s
//!    (`NETPORTAL_ACCT_INTERIM_S`, or the session's measured interval when longer); locked:
//!    the device is revoked, the certificate of the session's login is retired or expired (or
//!    the device has no valid one), or the login's VLAN is no longer the policy's. Locks younger
//!    than [`registry::RECHECK_GRACE`] are left to the Disconnect of whoever locked;
//! 2. sends a Disconnect-Request for each session that is due, naming that one session
//!    (Acct-Session-Id and the MAC), at most [`PER_ROUND`] per round, [`AT_ONCE`] at a time.
//!    Each result is audited `disconnect:<result>` by `recheck` and recorded per session
//!    (`disconnect_recheck`): an ACK settles it; a NAK with Error-Cause 503
//!    Session-Context-Not-Found settles it for good (the access point has no such session: a
//!    stale record, never asked again); any other answer is tried again after a backoff
//!    ([`backoff`]: the interval, doubled per try, at most [`MAX_BACKOFF`]), and after
//!    [`MAX_TRIES`] tries the session is given up (logged as an error; it stays in
//!    `netportal_locked_sessions_live` until it ends). A session settled by an ACK that the
//!    access point still reports afterwards is tried again, within the same cap;
//! 3. settles open entries whose session is no longer live (`settled_stale`).
//!
//! So a stale accounting record (an access point that lost a session without a Stop) costs at
//! most one request (NAK 503) or goes stale by itself; nothing is retried without end. The round
//! is the job `disconnect_recheck` (`job_begin`/`job_end`, the cursor holds the running totals
//! the portal exports as `netportal_disconnect_rechecks_total{result}`), one at a time (advisory
//! lock `netportal-job:disconnect_recheck`).

use std::collections::BTreeMap;
use std::future::Future;
use std::time::{Duration, Instant};

use futures::StreamExt;
use netportal_core::Db;
use netportal_core::config::OffboardSettings;
use netportal_core::registry::{self, LockedSession, RECHECK_GRACE};
use serde_json::{Value, json};
use sqlx::Executor;
use time::OffsetDateTime;

use crate::disconnect::{DisconnectResult, Disconnector};
use crate::offboarding::OffboardError;

const LOG: &str = "netportal.recheck";

/// The job name in the registry (`netportal_job_*{job="disconnect_recheck"}`).
pub const JOB: &str = "disconnect_recheck";
/// The actor of the audit rows.
pub const ACTOR: &str = "recheck";
/// `pg_try_advisory_lock(hashtext(LOCK_KEY))`, the collector's key scheme.
pub const LOCK_KEY: &str = "netportal-job:disconnect_recheck";
/// Disconnect-Requests per session at most; then it is given up.
pub const MAX_TRIES: i32 = 8;
/// The longest wait between two tries of one session.
pub const MAX_BACKOFF: Duration = Duration::from_secs(15 * 60);
/// Disconnect-Requests per round at most.
pub const PER_ROUND: usize = 64;
/// ... and at a time.
pub const AT_ONCE: usize = 16;
/// The results of `netportal_disconnect_rechecks_total{result}` (the cursor's totals).
pub const RESULTS: [&str; 7] = ["ack", "not_found", "nak", "timeout", "error", "settled_stale", "given_up"];
const STATEMENT_TIMEOUT: &str = "SET statement_timeout = '60s'";
const LOCK_TIMEOUT: &str = "SET lock_timeout = '10s'";

/// What one round did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecheckReport {
    /// live sessions of locked devices (past the grace)
    pub live: usize,
    /// Disconnect-Requests sent
    pub sent: usize,
    /// per label of [`RESULTS`]
    pub counts: BTreeMap<&'static str, u64>,
}

/// The wait after the `tries`-th try (1, 2, ...): `every` doubled per try, at most
/// [`MAX_BACKOFF`].
pub fn backoff(every: Duration, tries: i32) -> Duration {
    let doubled = 1u32.checked_shl(u32::try_from(tries.saturating_sub(1)).unwrap_or(0)).unwrap_or(u32::MAX);
    every.max(Duration::from_secs(1)).saturating_mul(doubled).min(MAX_BACKOFF)
}

/// A result's label (`disconnect_recheck.last_result`, the totals) and whether it settles the
/// session; the try that reaches [`MAX_TRIES`] without settling it gives it up.
pub fn verdict(result: DisconnectResult, tries_after: i32) -> (&'static str, Option<&'static str>) {
    let (label, settled) = match result {
        DisconnectResult::Ack => ("ack", Some("ack")),
        DisconnectResult::NotFound => ("not_found", Some("not_found")),
        DisconnectResult::Nak => ("nak", None),
        DisconnectResult::Timeout => ("timeout", None),
        DisconnectResult::Error | DisconnectResult::NoSession => ("error", None),
        DisconnectResult::Skipped => ("skipped", None),
    };
    match settled {
        None if tries_after >= MAX_TRIES => (label, Some("given_up")),
        other => (label, other),
    }
}

/// One round against the database (see the module documentation). `every`: the loop's interval
/// (the backoff's unit).
pub async fn round<D: Disconnector>(
    database_url: &str,
    disconnector: &D,
    interim_s: u32,
    every: Duration,
) -> Result<RecheckReport, OffboardError> {
    let started = Instant::now();
    let mut db = Db::connect(database_url).await?;
    let held: bool = {
        let conn = db.autocommit().await?;
        conn.execute(STATEMENT_TIMEOUT).await?;
        conn.execute(LOCK_TIMEOUT).await?;
        sqlx::query_scalar("SELECT pg_try_advisory_lock(hashtext($1))").bind(LOCK_KEY).fetch_one(&mut *conn).await?
    };
    if !held {
        let _ = db.close().await;
        return Err(OffboardError::Locked(JOB));
    }
    let result = async {
        registry::job_begin(&mut db, JOB).await?;
        db.commit().await?;
        reconcile(&mut db, disconnector, interim_s, every).await
    }
    .await;
    let duration = Some(started.elapsed().as_secs_f64());
    let result = match result {
        Ok(report) => match record(&mut db, &report, duration).await {
            Ok(()) => Ok(report),
            Err(e) => Err(e.into()),
        },
        Err(error) => {
            let _ = db.rollback().await;
            if let Err(e) = registry::job_end(&mut db, JOB, false, Some(&error.to_string()), duration, None).await {
                tracing::warn!(target: LOG, "could not record the failed round: {e}");
            }
            let _ = db.commit().await;
            Err(error)
        }
    };
    let _ = db.rollback().await;
    if let Ok(conn) = db.autocommit().await {
        let _ = sqlx::query("SELECT pg_advisory_unlock(hashtext($1))").bind(LOCK_KEY).execute(conn).await;
    }
    let _ = db.close().await;
    result
}

/// The round's work on an open connection (commits per step).
pub async fn reconcile<D: Disconnector>(
    db: &mut Db,
    disconnector: &D,
    interim_s: u32,
    every: Duration,
) -> Result<RecheckReport, OffboardError> {
    let now: OffsetDateTime = sqlx::query_scalar("SELECT now()").fetch_one(db.tx().await?).await?;
    let live = registry::locked_live_sessions(db, interim_s, RECHECK_GRACE).await?;
    db.commit().await?;
    let mut report = RecheckReport { live: live.len(), ..RecheckReport::default() };
    let due: Vec<&LockedSession> = live.iter().filter(|s| s.due(now, MAX_TRIES)).take(PER_ROUND).collect();
    let results: Vec<(&LockedSession, DisconnectResult)> = futures::stream::iter(due)
        .map(|session| async move { (session, disconnector.disconnect(&session.target()).await) })
        .buffer_unordered(AT_ONCE)
        .collect()
        .await;
    for (session, result) in results {
        let tries = session.tries.saturating_add(1);
        let (label, settled) = verdict(result, tries);
        let retry_in = time::Duration::try_from(backoff(every, tries)).unwrap_or(time::Duration::minutes(15));
        registry::record_recheck(db, session, label, settled, retry_in).await?;
        registry::audit(db, ACTOR, &format!("disconnect:{}", result.as_str()), Some(session.device_id)).await?;
        db.commit().await?;
        report.sent += 1;
        *report.counts.entry(if label == "skipped" { "error" } else { label }).or_default() += 1;
        if settled == Some("given_up") {
            *report.counts.entry("given_up").or_default() += 1;
            tracing::error!(
                target: LOG,
                "gave up on session {} at {} of device {} ({}) after {tries} Disconnect-Requests: it may stay \
                 connected until the RADIUS Session-Timeout",
                session.acct_session_id,
                session.nas_ip,
                session.device_id,
                session.reason
            );
        } else {
            tracing::info!(
                target: LOG,
                "device {} ({}) still live at {} (session {}): disconnect {label} (try {tries})",
                session.device_id,
                session.reason,
                session.nas_ip,
                session.acct_session_id
            );
        }
    }
    let stale = registry::settle_rechecks(db, &live).await?;
    db.commit().await?;
    if stale > 0 {
        report.counts.insert("settled_stale", stale);
    }
    Ok(report)
}

/// `job_end` with the running totals (the previous cursor's plus this round's) and the round.
async fn record(db: &mut Db, report: &RecheckReport, duration: Option<f64>) -> Result<(), registry::RegistryError> {
    db.rollback().await?;
    let previous = registry::job_cursor(db, JOB).await?.unwrap_or(Value::Null);
    let mut totals = serde_json::Map::new();
    for label in RESULTS {
        let before = previous.get("totals").and_then(|t| t.get(label)).and_then(Value::as_u64).unwrap_or(0);
        let now = before.saturating_add(report.counts.get(label).copied().unwrap_or(0));
        totals.insert(label.to_string(), json!(now));
    }
    let cursor =
        json!({"totals": totals, "last_round": {"live": report.live, "sent": report.sent, "results": report.counts}});
    registry::job_end(db, JOB, true, None, duration, Some(&cursor)).await?;
    db.commit().await?;
    Ok(())
}

/// Rounds every `NETPORTAL_DISCONNECT_RECHECK_S` until `stop` completes (a round in progress
/// finishes). Off (returns at once) without a DAE secret or with the interval 0.
pub async fn run_loop<D: Disconnector>(settings: &OffboardSettings, disconnector: &D, stop: impl Future<Output = ()>) {
    let every = settings.disconnect_recheck;
    if every.is_zero() {
        tracing::info!(target: LOG, "the Disconnect reconciliation is off (NETPORTAL_DISCONNECT_RECHECK_S=0)");
        return;
    }
    if settings.dae.secret.is_none() {
        tracing::warn!(target: LOG, "the Disconnect reconciliation is off: NETPORTAL_DAE_SECRET is not set");
        return;
    }
    let mut stop = std::pin::pin!(stop);
    loop {
        match round(settings.database_url.expose(), disconnector, settings.acct_interim_s, every).await {
            Ok(report) if report.sent > 0 => tracing::info!(
                target: LOG,
                "{} live session(s) of locked devices, {} Disconnect-Request(s) sent",
                report.live,
                report.sent
            ),
            Ok(_) => {}
            Err(e) => tracing::error!(target: LOG, "Disconnect reconciliation failed: {e}"),
        }
        tokio::select! {
            biased;
            () = &mut stop => return,
            () = tokio::time::sleep(every) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backoff() {
        let every = Duration::from_secs(30);
        let waits: Vec<u64> = (1..=8).map(|n| backoff(every, n).as_secs()).collect();
        assert_eq!(waits, [30, 60, 120, 240, 480, 900, 900, 900]);
        assert_eq!(backoff(every, 0), every);
        assert_eq!(backoff(every, i32::MAX), MAX_BACKOFF);
        assert_eq!(backoff(Duration::ZERO, 1), Duration::from_secs(1));
    }

    #[test]
    fn test_verdicts() {
        assert_eq!(verdict(DisconnectResult::Ack, 1), ("ack", Some("ack")));
        assert_eq!(verdict(DisconnectResult::NotFound, 1), ("not_found", Some("not_found")));
        assert_eq!(verdict(DisconnectResult::Ack, MAX_TRIES), ("ack", Some("ack")));
        for result in [DisconnectResult::Nak, DisconnectResult::Timeout, DisconnectResult::Error] {
            assert_eq!(verdict(result, MAX_TRIES - 1).1, None, "{result:?}");
            assert_eq!(verdict(result, MAX_TRIES).1, Some("given_up"), "{result:?}");
        }
        assert_eq!(verdict(DisconnectResult::NoSession, 1), ("error", None));
    }
}
