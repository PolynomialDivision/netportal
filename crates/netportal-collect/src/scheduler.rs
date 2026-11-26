//! The collector's scheduler (Python `collect/scheduler.py`, INVENTORY 9.10.2): one process,
//! jobs one after another, each on its interval.
//!
//! Per run of a job ([`execute`]):
//! - its own database connection (`statement_timeout` [`STATEMENT_TIMEOUT`], `lock_timeout`
//!   [`LOCK_TIMEOUT`]) and the session lock `pg_try_advisory_lock(hashtext('netportal-job:<name>'))`,
//!   so two collectors (a second container, `netportal job x` by hand) never run the same job at
//!   once: the second one skips it ([`Outcome::Locked`]);
//! - `registry::job_begin` (last_attempt), the job with its previous cursor and one time budget
//!   for its Prometheus/Loki requests, `registry::job_end` with ok/error text, duration and the
//!   new cursor. A failed run keeps the cursor of the progress it committed ([`Context::save`]),
//!   nothing more. A job that panics is a failed run (recorded over a new connection);
//! - the next run is due one interval after this one started (a failure: after [`RETRY`] at
//!   most).
//!
//! SIGTERM/SIGINT set the stop flag: the running job finishes its current step (jobs ask
//! [`Context::stopping`] between pages and days) and is recorded, then the process exits 0. The
//! heartbeat file is touched every [`HEARTBEAT`] by a task (also while a job runs, for at most
//! [`MAX_JOB`] of it), at every turn of the loop and after every job, so the container's
//! healthcheck (`find <file> -mmin -10`) can tell a living scheduler from a hung one.

use std::collections::HashMap;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use netportal_core::config::CollectSettings;
use netportal_core::registry::{self, JobStatus, RegistryError};
use netportal_core::{Db, conventions};
use serde_json::Value;
use time::OffsetDateTime;
use tokio::sync::watch;
use tokio::time::Instant;

use crate::jobs;
use crate::sources::{Budget, Loki, Prometheus, SourceError};

const LOG: &str = "netportal.collect";

/// The longest sleep between two looks at the job list.
pub const TICK: Duration = Duration::from_secs(15);
/// A failed job is tried again after at most this (daily jobs too).
pub const RETRY: Duration = Duration::from_secs(900);
/// No statement of a job may hold the database longer.
pub const STATEMENT_TIMEOUT: &str = "120s";
/// A job waits this long at most for a row lock (then its run fails and is retried): it never
/// queues behind a migration or a long transaction while holding locks of its own that
/// FreeRADIUS's logging functions need (`device_mac`).
pub const LOCK_TIMEOUT: &str = "5s";
/// The heartbeat file is touched this often while the loop lives ...
pub const HEARTBEAT: Duration = Duration::from_secs(30);
/// ... and while a job has run no longer than this (a hung one: no heartbeat).
pub const MAX_JOB: Duration = Duration::from_secs(600);
/// `job.last_error` holds at most this many characters of the error.
pub const ERROR_CHARS: usize = 500;

// --- stop flag --------------------------------------------------------------------------------------

/// The stop flag (SIGTERM/SIGINT): checked between steps, awaited instead of sleeping.
#[derive(Clone, Debug)]
pub struct Stop(Arc<watch::Sender<bool>>);

impl Default for Stop {
    fn default() -> Self {
        Stop(Arc::new(watch::channel(false).0))
    }
}

impl Stop {
    pub fn new() -> Stop {
        Stop::default()
    }

    pub fn set(&self) {
        self.0.send_replace(true);
    }

    pub fn is_set(&self) -> bool {
        *self.0.borrow()
    }

    /// Sleeps `duration` or until the flag is set; returns whether it is set.
    pub async fn wait(&self, duration: Duration) -> bool {
        let mut rx = self.0.subscribe();
        let _ = tokio::time::timeout(duration, rx.wait_for(|set| *set)).await;
        self.is_set()
    }
}

// --- jobs ------------------------------------------------------------------------------------------

/// Why a job run failed (stored in `job.last_error`, [`describe`]).
#[derive(Debug, thiserror::Error)]
pub enum JobError {
    #[error("source: {0}")]
    Source(#[from] SourceError),
    #[error("{0}")]
    Registry(#[from] RegistryError),
    #[error("database: {0}")]
    Db(#[from] sqlx::Error),
    #[error("{0}")]
    Other(String),
}

/// What a job returns: the new cursor (a JSON object), or `None` to keep the previous one.
pub type JobResult = Result<Option<Value>, JobError>;
pub type JobFuture<'a> = Pin<Box<dyn Future<Output = JobResult> + Send + 'a>>;
/// A job's work: `run(ctx)`.
pub type JobFn = Arc<dyn for<'a> Fn(&'a mut Context) -> JobFuture<'a> + Send + Sync>;

/// A job of the table ([`crate::jobs::JOBS`]) or of a test.
#[derive(Clone)]
pub struct Job {
    pub name: &'static str,
    pub every: Duration,
    /// all Prometheus/Loki requests of one run together
    pub budget: Duration,
    pub run: JobFn,
}

impl std::fmt::Debug for Job {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Job").field("name", &self.name).field("every", &self.every).finish_non_exhaustive()
    }
}

impl Job {
    pub fn new<F>(name: &'static str, every: Duration, budget: Duration, run: F) -> Job
    where
        F: for<'a> Fn(&'a mut Context) -> JobFuture<'a> + Send + Sync + 'static,
    {
        Job { name, every, budget, run: Arc::new(run) }
    }
}

/// What a job run gets.
pub struct Context {
    pub db: Db,
    pub settings: Arc<CollectSettings>,
    pub job_name: &'static str,
    /// the cursor the previous run left (a JSON object, `{}` for none)
    pub cursor: Value,
    /// the time of this run (UTC)
    pub now: OffsetDateTime,
    stop: Stop,
    saved: Option<Value>,
    budget: Arc<Budget>,
}

impl Context {
    pub fn stopping(&self) -> bool {
        self.stop.is_set()
    }

    /// Progress up to `cursor` is committed: a later failure of this run keeps it.
    pub fn save(&mut self, cursor: Value) {
        self.saved = Some(cursor);
    }

    /// The Prometheus client of this run (its requests share the run's budget).
    pub fn prometheus(&self) -> Result<Prometheus, SourceError> {
        let Some(url) = self.settings.prometheus_url.as_deref() else {
            return Err(SourceError("NETPORTAL_PROMETHEUS_URL is not set".into()));
        };
        Ok(Prometheus::new(http()?, url, self.settings.query_timeout, self.budget.clone()))
    }

    /// The Loki client of this run.
    pub fn loki(&self) -> Result<Loki, SourceError> {
        let Some(url) = self.settings.loki_url.as_deref() else {
            return Err(SourceError("NETPORTAL_LOKI_URL is not set".into()));
        };
        Ok(Loki::new(http()?, url, self.settings.query_timeout, self.budget.clone()))
    }

    /// The cursor as the job's own type; a cursor that does not parse (an older format) is
    /// ignored with a warning, as if there were none.
    pub fn cursor_as<T: serde::de::DeserializeOwned + Default>(&self) -> T {
        if self.cursor.as_object().is_some_and(|o| o.is_empty()) {
            return T::default();
        }
        match serde_json::from_value(self.cursor.clone()) {
            Ok(cursor) => cursor,
            Err(e) => {
                tracing::warn!(target: LOG, "job {}: the stored cursor is ignored ({e})", self.job_name);
                T::default()
            }
        }
    }
}

/// One HTTP client for the process (no redirects: a query never goes anywhere else).
fn http() -> Result<reqwest::Client, SourceError> {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    if let Some(client) = CLIENT.get() {
        return Ok(client.clone());
    }
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("netportal-collect/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|_| SourceError("no HTTP client".into()))?;
    Ok(CLIENT.get_or_init(|| client).clone())
}

/// The serialisation of a job's typed cursor.
pub fn to_cursor<T: serde::Serialize>(cursor: &T) -> JobResult {
    serde_json::to_value(cursor).map(Some).map_err(|e| JobError::Other(format!("cursor: {e}")))
}

// --- one run ---------------------------------------------------------------------------------------

/// How a run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Ok,
    Failed,
    /// another process holds the job's lock: skipped, nothing recorded
    Locked,
}

pub fn lock_key(name: &str) -> String {
    format!("netportal-job:{name}")
}

/// The error text stored in `job.last_error` (short; never a query).
pub fn describe(error: &JobError) -> String {
    error.to_string().chars().take(ERROR_CHARS).collect()
}

async fn previous_cursor(db: &mut Db, name: &str) -> Result<Value, RegistryError> {
    let rows = registry::job_status(db).await?;
    Ok(rows.into_iter().find(|r| r.name == name).map(|r| r.cursor.0).filter(Value::is_object).unwrap_or_else(empty))
}

fn empty() -> Value {
    Value::Object(Default::default())
}

async fn session_lock(db: &mut Db, name: &str) -> Result<bool, sqlx::Error> {
    use sqlx::Executor;
    let conn = db.autocommit().await?;
    conn.execute(sqlx::AssertSqlSafe(format!("SET statement_timeout = '{STATEMENT_TIMEOUT}'"))).await?;
    conn.execute(sqlx::AssertSqlSafe(format!("SET lock_timeout = '{LOCK_TIMEOUT}'"))).await?;
    // a session lock: it outlives transactions and goes with the connection
    sqlx::query_scalar("SELECT pg_try_advisory_lock(hashtext($1))").bind(lock_key(name)).fetch_one(conn).await
}

async fn session_unlock(db: &mut Db, name: &str) -> Result<(), sqlx::Error> {
    db.rollback().await?;
    sqlx::query("SELECT pg_advisory_unlock(hashtext($1))").bind(lock_key(name)).execute(db.autocommit().await?).await?;
    Ok(())
}

fn seconds_since(began: Instant) -> f64 {
    conventions::round_to(began.elapsed().as_secs_f64(), 3)
}

/// One run of `job`, recorded in the job table. Never fails: a lost database connection is a
/// failed run, the scheduler goes on.
pub async fn execute(job: &Job, settings: &Arc<CollectSettings>, stop: &Stop, now: Option<OffsetDateTime>) -> Outcome {
    let began = Instant::now();
    let mut db = match Db::connect(settings.database_url.expose()).await {
        Ok(db) => db,
        Err(e) => {
            tracing::error!(target: LOG, "job {}: no database connection: {}", job.name, kind_of(&e));
            return Outcome::Failed;
        }
    };
    let held = match session_lock(&mut db, job.name).await {
        Ok(held) => held,
        Err(e) => {
            tracing::error!(target: LOG, "job {}: no lock: {}", job.name, kind_of(&e));
            return Outcome::Failed;
        }
    };
    if !held {
        tracing::info!(target: LOG, "job {}: running elsewhere, skipped", job.name);
        let _ = db.close().await;
        return Outcome::Locked;
    }
    let (db, outcome) = run_locked(db, job, settings, stop, now, began).await;
    if let Some(mut db) = db {
        // closing the connection releases the lock anyway
        let _ = session_unlock(&mut db, job.name).await;
        let _ = db.close().await;
    }
    outcome
}

/// A database error's kind only (its text may hold values).
fn kind_of(error: &sqlx::Error) -> &'static str {
    match error {
        sqlx::Error::Io(_) | sqlx::Error::Tls(_) => "connection failed",
        sqlx::Error::Configuration(_) => "bad database URL",
        sqlx::Error::Database(_) => "refused by the database",
        sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed => "no connection",
        _ => "database error",
    }
}

async fn begin(ctx: &mut Context) -> Result<(), JobError> {
    ctx.cursor = previous_cursor(&mut ctx.db, ctx.job_name).await?;
    registry::job_begin(&mut ctx.db, ctx.job_name).await?;
    ctx.db.commit().await?;
    Ok(())
}

async fn record(
    db: &mut Db,
    name: &str,
    result: &Result<Option<Value>, JobError>,
    saved: Option<&Value>,
    began: Instant,
) -> Result<(), JobError> {
    match result {
        Ok(cursor) => {
            db.commit().await?;
            registry::job_end(db, name, true, None, Some(seconds_since(began)), cursor.as_ref().or(saved)).await?;
        }
        Err(e) => {
            db.rollback().await?;
            registry::job_end(db, name, false, Some(&describe(e)), Some(seconds_since(began)), saved).await?;
        }
    }
    db.commit().await?;
    Ok(())
}

async fn run_locked(
    db: Db,
    job: &Job,
    settings: &Arc<CollectSettings>,
    stop: &Stop,
    now: Option<OffsetDateTime>,
    began: Instant,
) -> (Option<Db>, Outcome) {
    let mut ctx = Context {
        db,
        settings: settings.clone(),
        job_name: job.name,
        cursor: empty(),
        now: now.unwrap_or_else(OffsetDateTime::now_utc),
        stop: stop.clone(),
        saved: None,
        budget: Arc::new(Budget::new(job.budget)),
    };
    let run = job.run.clone();
    let task = tokio::spawn(async move {
        let result = match begin(&mut ctx).await {
            Ok(()) => run(&mut ctx).await,
            Err(e) => Err(e),
        };
        (ctx, result)
    });
    let (mut ctx, result) = match task.await {
        Ok(done) => done,
        Err(_) => {
            // the connection went with the task: the lock and the transaction are gone
            tracing::error!(target: LOG, "job {}: internal error (panic)", job.name);
            record_panic(job.name, settings, began).await;
            return (None, Outcome::Failed);
        }
    };
    let saved = ctx.saved.take();
    let outcome = if result.is_ok() { Outcome::Ok } else { Outcome::Failed };
    if let Err(e) = &result {
        tracing::warn!(target: LOG, "job {} failed: {}", job.name, describe(e));
    }
    match record(&mut ctx.db, job.name, &result, saved.as_ref(), began).await {
        Ok(()) if outcome == Outcome::Ok => {
            tracing::info!(target: LOG, "job {} ok ({:.1} s)", job.name, began.elapsed().as_secs_f64());
            (Some(ctx.db), Outcome::Ok)
        }
        Ok(()) => (Some(ctx.db), outcome),
        Err(e) => {
            let _ = ctx.db.rollback().await;
            tracing::error!(target: LOG, "job {}: could not record the run: {}", job.name, describe(&e));
            (Some(ctx.db), Outcome::Failed)
        }
    }
}

async fn record_panic(name: &str, settings: &CollectSettings, began: Instant) {
    let Ok(mut db) = Db::connect(settings.database_url.expose()).await else {
        return;
    };
    let error = Some("internal error (panic)");
    if registry::job_end(&mut db, name, false, error, Some(seconds_since(began)), None).await.is_ok() {
        let _ = db.commit().await;
    }
    let _ = db.close().await;
}

// --- heartbeat and signals ---------------------------------------------------------------------------

/// Creates the file or sets its modification time to now (a failure is logged).
pub fn touch(path: &Path) {
    let result = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .and_then(|f| f.set_modified(std::time::SystemTime::now()));
    if let Err(e) = result {
        tracing::warn!(target: LOG, "heartbeat {}: {e}", path.display());
    }
}

/// SIGTERM (docker stop) and SIGINT end the loop after the running step.
pub fn install_signal_handlers(stop: &Stop) -> std::io::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    let stop = stop.clone();
    tokio::spawn(async move {
        loop {
            let name = tokio::select! {
                _ = term.recv() => "SIGTERM",
                _ = int.recv() => "SIGINT",
            };
            tracing::info!(target: LOG, "{name}: stopping after the current step");
            stop.set();
        }
    });
    Ok(())
}

// --- the loop ------------------------------------------------------------------------------------------

/// What runs one job for the scheduler ([`execute`], or a test's stand-in).
pub type Runner =
    Arc<dyn Fn(Job, Arc<CollectSettings>, Stop) -> Pin<Box<dyn Future<Output = Outcome> + Send>> + Send + Sync>;

fn default_runner() -> Runner {
    Arc::new(|job, settings, stop| Box::pin(async move { execute(&job, &settings, &stop, None).await }))
}

/// The next due times from the job table (a restart does not rerun a daily job at once): every
/// job is due `now`, one with a `last_attempt` one interval after it (but not later than one
/// interval from now).
pub fn due_times(
    jobs: &[Job],
    rows: &[JobStatus],
    wall_now: OffsetDateTime,
    now: Instant,
) -> HashMap<&'static str, Instant> {
    let mut due = HashMap::new();
    for job in jobs {
        let last = rows.iter().find(|r| r.name == job.name).and_then(|r| r.last_attempt);
        let at = match last {
            Some(last) => {
                let since = (wall_now - last).as_seconds_f64().max(0.0);
                now + job.every.saturating_sub(Duration::from_secs_f64(since))
            }
            None => now,
        };
        due.insert(job.name, at);
    }
    due
}

pub struct Scheduler {
    settings: Arc<CollectSettings>,
    jobs: Vec<Job>,
    pub stop: Stop,
    runner: Runner,
    pub tick: Duration,
    pub heartbeat_every: Duration,
    pub max_job: Duration,
    pub next_due: HashMap<&'static str, Instant>,
}

impl Scheduler {
    pub fn new(settings: Arc<CollectSettings>, jobs: Vec<Job>, stop: Stop) -> Scheduler {
        Scheduler {
            settings,
            jobs,
            stop,
            runner: default_runner(),
            tick: TICK,
            heartbeat_every: HEARTBEAT,
            max_job: MAX_JOB,
            next_due: HashMap::new(),
        }
    }

    /// The same with another way of running a job (tests).
    pub fn with_runner(mut self, runner: Runner) -> Scheduler {
        self.runner = runner;
        self
    }

    fn beat(&self) {
        touch(&self.settings.heartbeat);
    }

    /// Next due times from the job table; an unreadable table: everything is due now.
    pub async fn load_due(&mut self) {
        let now = Instant::now();
        let rows = async {
            let mut db = Db::connect(self.settings.database_url.expose()).await.map_err(RegistryError::from)?;
            let rows = registry::job_status(&mut db).await;
            let _ = db.close().await;
            rows
        }
        .await;
        let rows = rows.unwrap_or_else(|e| {
            let why = match &e {
                RegistryError::Db(e) => kind_of(e),
                _ => "registry error",
            };
            tracing::warn!(target: LOG, "job status unreadable ({why}): every job is due");
            Vec::new()
        });
        self.next_due = due_times(&self.jobs, &rows, OffsetDateTime::now_utc(), now);
    }

    /// Every job once, in order (`--once`, `job NAME`): 0 if none failed, else 1.
    pub async fn run_once(&self) -> i32 {
        let mut failed = false;
        for job in &self.jobs {
            if self.stop.is_set() {
                break;
            }
            failed |= (self.runner)(job.clone(), self.settings.clone(), self.stop.clone()).await == Outcome::Failed;
            self.beat();
        }
        i32::from(failed)
    }

    /// Runs due jobs until the stop flag is set; returns 0.
    pub async fn run_forever(&mut self) -> i32 {
        self.load_due().await;
        let running: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));
        let heartbeat = {
            let (stop, every, max_job, path, running) = (
                self.stop.clone(),
                self.heartbeat_every,
                self.max_job,
                self.settings.heartbeat.clone(),
                running.clone(),
            );
            tokio::spawn(async move {
                while !stop.wait(every).await {
                    let started = running.lock().map(|r| *r).unwrap_or(None);
                    if started.is_none_or(|s| s.elapsed() < max_job) {
                        touch(&path);
                    }
                }
            })
        };
        while !self.stop.is_set() {
            self.beat();
            let now = Instant::now();
            let due = self
                .jobs
                .iter()
                .enumerate()
                .filter_map(|(i, j)| self.next_due.get(j.name).filter(|t| **t <= now).map(|t| (*t, i)))
                .min();
            let Some((_, index)) = due else {
                let next = self.next_due.values().min().copied().unwrap_or(now + self.tick);
                let wait = self.tick.min(next.saturating_duration_since(now)).max(Duration::from_millis(100));
                self.stop.wait(wait).await;
                continue;
            };
            let job = self.jobs[index].clone();
            if let Ok(mut r) = running.lock() {
                *r = Some(Instant::now());
            }
            let outcome = (self.runner)(job.clone(), self.settings.clone(), self.stop.clone()).await;
            if let Ok(mut r) = running.lock() {
                *r = None;
            }
            self.beat();
            let every = if outcome == Outcome::Failed { job.every.min(RETRY) } else { job.every };
            self.next_due.insert(job.name, now + every);
        }
        heartbeat.abort();
        self.beat();
        0
    }
}

// --- entry points ----------------------------------------------------------------------------------------

/// Why `collect` or `job` could not start.
#[derive(Debug, thiserror::Error)]
pub enum CollectError {
    #[error("{0}")]
    UnknownJobs(String),
    #[error("signal handlers: {0}")]
    Signals(#[from] std::io::Error),
}

async fn start(settings: &CollectSettings, selected: Vec<Job>, once: bool) -> Result<i32, CollectError> {
    let stop = Stop::new();
    install_signal_handlers(&stop)?;
    let mut scheduler = Scheduler::new(Arc::new(settings.clone()), selected, stop);
    Ok(if once { scheduler.run_once().await } else { scheduler.run_forever().await })
}

/// `netportal collect [--once] [--jobs a,b]`: the selected jobs (all for an empty list) once, or
/// forever. Returns the exit code (once: 1 if a job failed).
pub async fn run(settings: &CollectSettings, once: bool, jobs: &str) -> Result<i32, CollectError> {
    let selected = jobs::select(jobs).map_err(CollectError::UnknownJobs)?;
    start(settings, selected, once).await
}

/// `netportal job NAME`: one job once through the scheduler (the same recording and heartbeat).
pub async fn run_job(settings: &CollectSettings, name: &str) -> Result<i32, CollectError> {
    let name = name.trim();
    if name.is_empty() || name.contains(',') {
        return Err(CollectError::UnknownJobs(format!("{name:?} is not one job name")));
    }
    let selected = jobs::select(name).map_err(CollectError::UnknownJobs)?;
    start(settings, selected, true).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use sqlx::types::Json;

    fn job(name: &'static str, every_s: u64) -> Job {
        Job::new(name, Duration::from_secs(every_s), Duration::from_secs(60), |_ctx| Box::pin(async { Ok(None) }))
    }

    fn status(name: &str, last_attempt: Option<OffsetDateTime>) -> JobStatus {
        JobStatus {
            name: name.into(),
            last_success: None,
            last_attempt,
            last_error: None,
            duration_s: None,
            cursor: Json(json!({})),
        }
    }

    /// Python test_collect.py SchedulerTests.test_restart_does_not_rerun_a_daily_job_at_once
    #[tokio::test]
    async fn test_restart_does_not_rerun_a_daily_job_at_once() {
        let wall = OffsetDateTime::now_utc();
        let now = Instant::now();
        let jobs = [job("prune", 86400), job("incidents", 120)];
        let due = due_times(&jobs, &[status("prune", Some(wall - time::Duration::hours(1)))], wall, now);
        let prune = due["prune"].duration_since(now).as_secs_f64();
        assert!((prune - (86400.0 - 3600.0)).abs() < 1.0, "{prune}");
        assert_eq!(due["incidents"], now);
        // a last attempt in the future (a clock jump) is not later than one interval from now
        let due = due_times(&jobs, &[status("prune", Some(wall + time::Duration::hours(5)))], wall, now);
        assert_eq!(due["prune"].duration_since(now), Duration::from_secs(86400));
    }

    #[test]
    fn test_describe_is_short() {
        let long = JobError::Other("x".repeat(900));
        assert_eq!(describe(&long).chars().count(), ERROR_CHARS);
        assert_eq!(
            describe(&JobError::Source(SourceError("/api/v1/query HTTP 500".into()))),
            "source: /api/v1/query HTTP 500"
        );
        assert_eq!(lock_key("rollup"), "netportal-job:rollup");
    }

    #[tokio::test]
    async fn test_stop_wait() {
        let stop = Stop::new();
        assert!(!stop.wait(Duration::from_millis(10)).await);
        let other = stop.clone();
        tokio::spawn(async move { other.set() });
        assert!(stop.wait(Duration::from_secs(5)).await);
        assert!(stop.is_set());
    }

    #[test]
    fn test_touch() {
        let dir = std::env::temp_dir().join(format!("np-collect-touch-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("beat");
        touch(&file);
        assert!(file.exists());
        touch(&dir.join("missing-dir").join("beat")); // logged, no panic
        let _ = std::fs::remove_dir_all(&dir);
    }
}
