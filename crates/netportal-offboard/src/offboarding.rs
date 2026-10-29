//! One reconciliation round and the sidecar loop (Python `netportal/offboarding.py` and
//! `__main__.cmd_offboard`, INVENTORY 8).
//!
//! A round: read the whole directory ([`crate::directory`]); refuse to act on a directory that
//! names nobody ([`check_guards`]); hold back a mass removal ([`MassRemoval`]: at least 3, and
//! more than half, of the people with active devices would lose them at once: nothing changes,
//! the round fails with HELD BACK); then, for the registry's subjects
//! (`registry::subjects_to_check`: people not offboarded, owners of active devices and of live
//! app grants), in this order:
//!
//! 1. no longer allowed (deactivated, deleted, or out of every policy's groups), and found so by
//!    the previous round too (`person.absent_since`; the first such round only notes it, so an
//!    Authentik edit in progress costs nobody a re-enrolment): `registry::offboard_person`
//!    (portal session and admin right end, app grants revoked), committed; then every active
//!    device revoked with Disconnect-Requests ([`actions::revoke_now`]). Someone offboarded
//!    before with devices left loses them at once;
//! 2. still allowed: the absence note goes, [`actions::apply_policy`] (devices of another
//!    policy move, Disconnect so they authenticate into the new VLAN) and `registry::set_admin`
//!    from the admin groups (losing the right ends the person's portal sessions), committed per
//!    person.
//!
//! `netportal offboard --allow-mass` (one round, by hand, after checking the directory) waives
//! the hold and the second round: everyone the directory no longer allows is offboarded now.
//! `NETPORTAL_OFFBOARD_ALLOW_MASS=1` waives the hold only.
//!
//! People only in Authentik are ignored. The round is recorded as the job `offboarding`
//! (`job_begin` / `job_end`: attempt, success or error, duration, counts as cursor) and holds the
//! advisory lock `hashtext('netportal-job:offboarding')`, so two processes never reconcile at
//! once. Without `NETPORTAL_AUTHENTIK_API` or the token the offboarding is off: nothing is read,
//! changed or recorded (the staleness alert on `netportal_offboarding_last_success_timestamp_seconds`
//! fires).

use std::collections::BTreeSet;
use std::future::Future;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime};

use netportal_core::Db;
use netportal_core::config::{MassRemoval, OffboardSettings, Policies};
use netportal_core::registry::{self, RegistryError};
use serde_json::json;
use sqlx::Executor;
use time::OffsetDateTime;

use crate::actions;
use crate::directory::{Access, Directory, DirectoryError, REQUEST_TIMEOUT, UsersApi};
use crate::disconnect::{Disconnector, RadiusDisconnector};

const LOG: &str = "netportal.offboarding";

/// The job name in the registry (`job.name`, `netportal_job_*{job="offboarding"}`).
pub const JOB: &str = "offboarding";
/// The actor of the round's audit rows.
pub const ACTOR: &str = "offboarding";
/// `pg_try_advisory_lock(hashtext(LOCK_KEY))`, the collector's key scheme (`netportal-job:<name>`).
pub const LOCK_KEY: &str = "netportal-job:offboarding";
const STATEMENT_TIMEOUT: &str = "SET statement_timeout = '60s'";
const LOCK_TIMEOUT: &str = "SET lock_timeout = '10s'";

/// A failed round. The messages are complete in themselves (no error sources), so the CLI's
/// `netportal: offboard: <message>` shows each cause once.
#[derive(Debug, thiserror::Error)]
pub enum OffboardError {
    #[error("{0}")]
    Directory(DirectoryError),
    #[error("{0}")]
    Registry(RegistryError),
    /// Nothing was changed: the directory does not look like the house's.
    #[error("refusing to offboard: {0}")]
    Guard(String),
    #[error("another offboarding round is running")]
    Locked,
    /// Nothing was changed: the directory would offboard too many people at once.
    #[error("HELD BACK, nothing changed: {0}")]
    HeldBack(String),
    #[error("heartbeat {path}: {error}")]
    Heartbeat { path: String, error: std::io::Error },
    #[error("signal handler: {0}")]
    Signal(std::io::Error),
}

impl From<DirectoryError> for OffboardError {
    fn from(e: DirectoryError) -> Self {
        OffboardError::Directory(e)
    }
}

impl From<RegistryError> for OffboardError {
    fn from(e: RegistryError) -> Self {
        OffboardError::Registry(e)
    }
}

impl From<sqlx::Error> for OffboardError {
    fn from(e: sqlx::Error) -> Self {
        OffboardError::Registry(RegistryError::Db(e))
    }
}

/// What a round did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoundReport {
    /// users in the directory
    pub users: usize,
    /// registry subjects looked at
    pub checked: usize,
    /// subjects without access (offboarded now, or earlier with devices left)
    pub offboarded: usize,
    /// devices revoked
    pub revoked: usize,
    /// devices moved to another policy
    pub moved: usize,
    /// subjects without access found for the first time (offboarded at the next round)
    pub pending: usize,
    /// people who lost the admin right (their portal sessions ended)
    pub admins_removed: usize,
}

/// How a round treats removals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RoundOptions {
    /// the mass-removal hold (`NETPORTAL_OFFBOARD_MASS_*`)
    pub mass: MassRemoval,
    /// `--allow-mass`: no hold, and no second round needed (an admin checked the directory)
    pub confirm_now: bool,
}

impl RoundOptions {
    pub fn new(mass: MassRemoval, confirm_now: bool) -> RoundOptions {
        RoundOptions { mass, confirm_now }
    }
}

/// The mass-removal hold: `Err(HeldBack)` when `losing` of the `base` people with active
/// devices would lose them in this round and that is a mass removal (`--allow-mass` waives it).
pub fn check_mass(losing: usize, base: usize, options: &RoundOptions) -> Result<(), OffboardError> {
    if options.confirm_now || !options.mass.holds(losing, base) {
        return Ok(());
    }
    Err(OffboardError::HeldBack(format!(
        "{losing} of the {base} people with active devices would lose them at once (at least {} and more than {} %); \
         check the directory (the API token's rights, renamed groups, members moved into subgroups); if it is \
         right, run one round with `netportal offboard --allow-mass`",
        options.mass.min, options.mass.percent
    )))
}

/// Refuse a directory that would offboard everyone, before anything is changed:
/// - no users at all (Python's guard);
/// - nobody active in a policy's groups (a renamed group, a token that sees no groups);
/// - none of the registry's people in the directory although it knows two or more (another
///   Authentik, or a changed OIDC subject mode: the uids no longer match the subs).
pub fn check_guards(directory: &Directory, access: &Access, subjects: &BTreeSet<String>) -> Result<(), OffboardError> {
    if directory.is_empty() {
        return Err(OffboardError::Guard("Authentik returned no users".into()));
    }
    if access.allowed.is_empty() {
        return Err(OffboardError::Guard(format!(
            "none of the {} users in Authentik is active in a Wi-Fi policy's groups",
            directory.len()
        )));
    }
    if subjects.len() >= 2 && !subjects.iter().any(|s| directory.contains(s)) {
        return Err(OffboardError::Guard(format!(
            "none of the {} people in the registry is in Authentik (another directory, or a changed subject mode?)",
            subjects.len()
        )));
    }
    Ok(())
}

/// Bring the registry in line with this (complete) directory. Commits per step; a registry
/// error stops the round (what is committed stays, the next round finishes the rest).
pub async fn reconcile<D: Disconnector>(
    db: &mut Db,
    directory: &Directory,
    policies: &Policies,
    disconnector: &D,
    options: &RoundOptions,
) -> Result<RoundReport, OffboardError> {
    let access = directory.access(policies);
    let round_started: OffsetDateTime = sqlx::query_scalar("SELECT now()").fetch_one(db.tx().await?).await?;
    let subjects = registry::subjects_to_check(db).await?;
    let owners = registry::owners_of_active_devices(db).await?;
    let lost: Vec<String> = subjects.iter().filter(|s| !access.allowed.contains_key(*s)).cloned().collect();
    let absence = registry::absence(db, &lost).await?;
    db.commit().await?;
    check_guards(directory, &access, &subjects)?;
    check_mass(lost.iter().filter(|s| owners.contains(*s)).count(), owners.len(), options)?;
    let mut report = RoundReport { users: directory.len(), checked: subjects.len(), ..RoundReport::default() };
    // first those who lost access: the revocations matter most if the round stops half-way
    for sub in &lost {
        let known = absence.get(sub);
        let confirmed = options.confirm_now
            || known.is_some_and(|a| a.offboarded || a.absent_since.is_some_and(|t| t < round_started));
        if !confirmed {
            registry::mark_absent(db, sub).await?;
            db.commit().await?;
            report.pending += 1;
            tracing::info!(target: LOG, "{sub} has no access in the directory: offboarded at the next round if still so");
            continue;
        }
        registry::offboard_person(db, sub).await?;
        db.commit().await?;
        report.offboarded += 1;
        let devices = registry::devices(db, Some(sub), false).await?;
        db.commit().await?;
        for device in devices {
            actions::revoke_now(db, device.id, ACTOR, disconnector).await?;
            report.revoked += 1;
        }
    }
    for (sub, policy) in subjects.iter().filter_map(|s| access.allowed.get(s).map(|p| (s, p))) {
        registry::clear_absent(db, sub).await?;
        report.moved += actions::apply_policy(db, sub, policy, ACTOR, disconnector).await?.len();
        // out of it-admins: no /admin from now on, and the portal sessions end (log in again)
        if registry::set_admin(db, sub, access.admins.contains(sub)).await? {
            report.admins_removed += 1;
            tracing::info!(target: LOG, "{sub} is no longer an admin: their portal sessions ended");
        }
        db.commit().await?;
    }
    Ok(report)
}

/// One round against the database: lock, `job_begin`, read the directory, reconcile,
/// `job_end` (success with the counts, or the error). The directory is read in full before
/// anything is changed.
pub async fn round<D: Disconnector>(
    database_url: &str,
    api: &UsersApi,
    policies: &Policies,
    disconnector: &D,
    options: &RoundOptions,
) -> Result<RoundReport, OffboardError> {
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
        return Err(OffboardError::Locked);
    }
    let result = async {
        registry::job_begin(&mut db, JOB).await?;
        db.commit().await?;
        let directory = api.read().await?;
        reconcile(&mut db, &directory, policies, disconnector, options).await
    }
    .await;
    let duration = Some(started.elapsed().as_secs_f64());
    let result = match result {
        Ok(report) => {
            let cursor = json!({"last_round": {"users": report.users, "checked": report.checked,
                "offboarded": report.offboarded, "revoked": report.revoked, "moved": report.moved,
                "pending": report.pending, "admins_removed": report.admins_removed}});
            match record(&mut db, true, None, duration, Some(&cursor)).await {
                Ok(()) => Ok(report),
                Err(e) => Err(e.into()),
            }
        }
        Err(error) => {
            if matches!(error, OffboardError::HeldBack(_)) {
                tracing::error!(target: LOG, "{error}");
            }
            if let Err(e) = record(&mut db, false, Some(&error.to_string()), duration, None).await {
                tracing::warn!(target: LOG, "could not record the failed round: {e}");
            }
            Err(error)
        }
    };
    let _ = db.rollback().await;
    if let Ok(conn) = db.autocommit().await {
        let _ = sqlx::query("SELECT pg_advisory_unlock(hashtext($1))").bind(LOCK_KEY).execute(conn).await;
    }
    let _ = db.close().await; // closing releases the lock anyway
    result
}

async fn record(
    db: &mut Db,
    ok: bool,
    error: Option<&str>,
    duration: Option<f64>,
    cursor: Option<&serde_json::Value>,
) -> Result<(), RegistryError> {
    db.rollback().await?;
    registry::job_end(db, JOB, ok, error, duration, cursor).await?;
    db.commit().await?;
    Ok(())
}

/// The users API of the settings, `None` when the offboarding is off.
fn users_api(settings: &OffboardSettings) -> Result<Option<UsersApi>, OffboardError> {
    match (&settings.authentik_api, &settings.authentik_token) {
        (Some(api), Some(token)) => Ok(Some(UsersApi::new(api, token.clone(), REQUEST_TIMEOUT)?)),
        _ => Ok(None),
    }
}

/// One round, or nothing when the offboarding is off (`Ok(None)`). Logs what was changed.
async fn one_round<D: Disconnector>(
    settings: &OffboardSettings,
    api: Option<&UsersApi>,
    disconnector: &D,
    options: &RoundOptions,
) -> Result<Option<RoundReport>, OffboardError> {
    let Some(api) = api else {
        return Ok(None);
    };
    let report = round(settings.database_url.expose(), api, &settings.policies, disconnector, options).await?;
    if report.revoked > 0 || report.moved > 0 || report.pending > 0 {
        tracing::info!(
            target: LOG,
            "offboarding revoked {} device(s), moved {} to another policy; {} without access for the first time",
            report.revoked,
            report.moved,
            report.pending
        );
    }
    Ok(Some(report))
}

/// Create the heartbeat file or set its modification time to now.
pub fn touch(path: &Path) -> Result<(), OffboardError> {
    let error = |error| OffboardError::Heartbeat { path: path.display().to_string(), error };
    let file = std::fs::OpenOptions::new().create(true).append(true).open(path).map_err(error)?;
    file.set_modified(SystemTime::now()).map_err(error)
}

/// `netportal offboard [--every SECONDS] [--allow-mass]`: one round (`every` 0) or a round every
/// `every` seconds until SIGTERM/SIGINT. The heartbeat file is touched after every round, also a
/// failed one: it says the sidecar is alive (the container healthcheck); whether rounds succeed
/// is `job.offboarding` (the staleness alert; a held-back round is a failed one). One round:
/// `Ok(0)`, or its error (exit 1). `allow_mass` (one round only) waives the mass-removal hold and
/// the second round.
pub async fn run(settings: &OffboardSettings, every: u64, allow_mass: bool) -> Result<i32, OffboardError> {
    if allow_mass && every != 0 {
        return Err(OffboardError::Guard("--allow-mass is for one round, not with --every".into()));
    }
    let options = RoundOptions::new(settings.mass, allow_mass);
    let disconnector = RadiusDisconnector::new(&settings.dae);
    let api = users_api(settings)?;
    if api.is_none() {
        tracing::warn!(
            target: LOG,
            "offboarding is off: NETPORTAL_AUTHENTIK_API or NETPORTAL_AUTHENTIK_TOKEN is not set"
        );
    }
    if every == 0 {
        let result = one_round(settings, api.as_ref(), &disconnector, &options).await;
        let beat = touch(&settings.heartbeat);
        result?;
        beat?;
        return Ok(0);
    }
    let stop = shutdown_signal().map_err(OffboardError::Signal)?;
    Ok(run_loop(settings, api.as_ref(), &disconnector, &options, Duration::from_secs(every), stop).await)
}

/// Rounds every `every` until `stop` completes (checked between rounds: a round in progress
/// finishes, so no revoked device misses its Disconnect-Request). Returns the exit code 0.
pub async fn run_loop<D: Disconnector>(
    settings: &OffboardSettings,
    api: Option<&UsersApi>,
    disconnector: &D,
    options: &RoundOptions,
    every: Duration,
    stop: impl Future<Output = ()>,
) -> i32 {
    let mut stop = std::pin::pin!(stop);
    loop {
        if let Err(e) = one_round(settings, api, disconnector, options).await {
            tracing::error!(target: LOG, "offboarding failed: {e}");
        }
        if let Err(e) = touch(&settings.heartbeat) {
            tracing::error!(target: LOG, "{e}");
        }
        tokio::select! {
            biased;
            () = &mut stop => {
                tracing::info!(target: LOG, "stopping");
                return 0;
            }
            () = tokio::time::sleep(every) => {}
        }
    }
}

/// Completes at the first SIGTERM or SIGINT (registered now, so a signal during a round is not
/// lost). The container's PID 1 has no default action for SIGTERM, so this is the clean stop.
fn shutdown_signal() -> std::io::Result<impl Future<Output = ()>> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    Ok(async move {
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
        }
    })
}
