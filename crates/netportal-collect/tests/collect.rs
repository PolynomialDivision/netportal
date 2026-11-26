//! The collector's scheduler, entry points and prune wiring (Python tests/test_collect.py:
//! RunJobTests, SchedulerTests, CliTests, PruneTests). The job runs go against a real database
//! (`NETPORTAL_TEST_DATABASE_URL`); the loop tests use a stand-in runner and need none. The job
//! metrics (JobMetricsTests) belong to the web's `/metrics`, the "offboarding no longer prunes"
//! test to netportal-offboard.

mod common;
mod fakes;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{Case, settings};
use netportal_collect::jobs;
use netportal_collect::scheduler::{
    self, Context, Job, JobError, JobFuture, Outcome, Runner, Scheduler, Stop, execute, lock_key,
};
use serde_json::{Value, json};
use sqlx::{Connection, PgConnection};
use time::macros::datetime;

fn job<F>(name: &'static str, run: F) -> Job
where
    F: for<'a> Fn(&'a mut Context) -> JobFuture<'a> + Send + Sync + 'static,
{
    Job::new(name, Duration::from_secs(60), Duration::from_secs(60), run)
}

fn returning(name: &'static str, cursor: Option<Value>) -> Job {
    job(name, move |_ctx| {
        let cursor = cursor.clone();
        Box::pin(async move { Ok(cursor) })
    })
}

async fn advisory_locks(case: &mut Case) -> i64 {
    case.i64(
        "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory'
         AND database = (SELECT oid FROM pg_database WHERE datname = current_database())",
    )
    .await
}

// --- RunJobTests ---------------------------------------------------------------------------------

#[tokio::test]
async fn test_ok_records_begin_end_cursor_and_releases_the_lock() {
    let admin = need_db!();
    let mut case = Case::new(&admin).await;
    let settings = case.settings(None, None);
    let seen: Arc<Mutex<Vec<Value>>> = Arc::default();
    let record = seen.clone();
    let work = job("x", move |ctx| {
        let record = record.clone();
        Box::pin(async move {
            let rows = netportal_core::registry::job_status(&mut ctx.db).await?;
            let begun = rows.iter().find(|r| r.name == "x").is_some_and(|r| r.last_attempt.is_some());
            let timeouts: (String, String) =
                sqlx::query_as("SELECT current_setting('statement_timeout'), current_setting('lock_timeout')")
                    .fetch_one(ctx.db.tx().await?)
                    .await?;
            record
                .lock()
                .map_err(|_| JobError::Other("lock".into()))?
                .push(json!([ctx.cursor, begun, timeouts.0, timeouts.1]));
            Ok(Some(json!({"until": 5})))
        })
    });
    assert_eq!(execute(&work, &settings, &Stop::new(), None).await, Outcome::Ok);
    // job_begin before the work, no cursor yet; the session's timeouts
    assert_eq!(*seen.lock().expect("seen"), [json!([{}, true, "2min", "5s"])]);
    let row = case.job("x").await.expect("row");
    assert!(row.last_success.is_some());
    assert_eq!(row.last_error, None);
    assert_eq!(row.cursor.0, json!({"until": 5}));
    assert!(row.duration_s.is_some());
    assert_eq!(advisory_locks(&mut case).await, 0);
}

#[tokio::test]
async fn test_cursor_advances_from_run_to_run() {
    let admin = need_db!();
    let mut case = Case::new(&admin).await;
    let settings = case.settings(None, None);
    let work = job("x", |ctx| {
        Box::pin(async move {
            let n = ctx.cursor.get("n").and_then(Value::as_i64).unwrap_or(0);
            Ok(Some(json!({"n": n + 1})))
        })
    });
    for _ in 0..3 {
        execute(&work, &settings, &Stop::new(), None).await;
    }
    assert_eq!(case.job("x").await.expect("row").cursor.0, json!({"n": 3}));
}

#[tokio::test]
async fn test_none_keeps_the_previous_cursor() {
    let admin = need_db!();
    let mut case = Case::new(&admin).await;
    let settings = case.settings(None, None);
    execute(&returning("x", Some(json!({"a": 1}))), &settings, &Stop::new(), None).await;
    execute(&returning("x", None), &settings, &Stop::new(), None).await;
    assert_eq!(case.job("x").await.expect("row").cursor.0, json!({"a": 1}));
}

#[tokio::test]
async fn test_error_is_recorded_with_the_committed_progress() {
    let admin = need_db!();
    let mut case = Case::new(&admin).await;
    let settings = case.settings(None, None);
    execute(&returning("x", Some(json!({"until": 1}))), &settings, &Stop::new(), None).await;
    let before = case.job("x").await.expect("row").last_success;
    let work = job("x", |ctx| {
        Box::pin(async move {
            ctx.save(json!({"until": 7}));
            // uncommitted work of the failed run is rolled back
            netportal_core::registry::job_begin(&mut ctx.db, "never_committed").await?;
            Err(JobError::Other("Loki said no".into()))
        })
    });
    assert_eq!(execute(&work, &settings, &Stop::new(), None).await, Outcome::Failed);
    let row = case.job("x").await.expect("row");
    assert_eq!(row.last_error.as_deref(), Some("Loki said no"));
    assert_eq!(row.last_success, before);
    assert_eq!(row.cursor.0, json!({"until": 7}));
    assert!(case.job("never_committed").await.is_none());
    assert_eq!(advisory_locks(&mut case).await, 0);
}

#[tokio::test]
async fn test_failure_without_progress_keeps_the_cursor() {
    let admin = need_db!();
    let mut case = Case::new(&admin).await;
    let settings = case.settings(None, None);
    execute(&returning("x", Some(json!({"until": 1}))), &settings, &Stop::new(), None).await;
    let boom = job("x", |_ctx| Box::pin(async { Err(JobError::Other("bad reply".into())) }));
    assert_eq!(execute(&boom, &settings, &Stop::new(), None).await, Outcome::Failed);
    let row = case.job("x").await.expect("row");
    assert_eq!(row.cursor.0, json!({"until": 1}));
    assert_eq!(row.last_error.as_deref(), Some("bad reply"));
}

#[tokio::test]
async fn test_a_panicking_job_is_a_failed_run() {
    let admin = need_db!();
    let mut case = Case::new(&admin).await;
    let settings = case.settings(None, None);
    let work = job("x", |_ctx| Box::pin(async { panic!("a bug") }));
    assert_eq!(execute(&work, &settings, &Stop::new(), None).await, Outcome::Failed);
    let row = case.job("x").await.expect("row");
    assert_eq!(row.last_error.as_deref(), Some("internal error (panic)"));
    // the next run gets the lock again
    assert_eq!(execute(&returning("x", None), &settings, &Stop::new(), None).await, Outcome::Ok);
}

#[tokio::test]
async fn test_a_job_held_elsewhere_is_skipped() {
    let admin = need_db!();
    let mut case = Case::new(&admin).await;
    let settings = case.settings(None, None);
    let mut other = PgConnection::connect(&case.url).await.expect("connect");
    let held: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock(hashtext($1))")
        .bind(lock_key("x"))
        .fetch_one(&mut other)
        .await
        .expect("lock");
    assert!(held);
    let ran: Arc<Mutex<bool>> = Arc::default();
    let flag = ran.clone();
    let work = job("x", move |_ctx| {
        if let Ok(mut f) = flag.lock() {
            *f = true;
        }
        Box::pin(async { Ok(None) })
    });
    assert_eq!(execute(&work, &settings, &Stop::new(), None).await, Outcome::Locked);
    assert!(!*ran.lock().expect("ran"));
    assert!(case.job("x").await.is_none()); // no job_begin: nothing to record
    // not released by the skipper
    let still: bool =
        sqlx::query_scalar("SELECT count(*) = 1 FROM pg_locks WHERE locktype = 'advisory' AND pid = pg_backend_pid()")
            .fetch_one(&mut other)
            .await
            .expect("locks");
    assert!(still);
    // per job
    assert_eq!(execute(&returning("y", None), &settings, &Stop::new(), None).await, Outcome::Ok);
}

#[tokio::test]
async fn test_no_database_is_a_failed_run_not_a_crash() {
    let dir = tempfile::tempdir().expect("tempdir");
    let settings = Arc::new(settings("postgresql://nobody@127.0.0.1:1/none", dir.path().join("hb"), None, None));
    assert_eq!(execute(&returning("x", None), &settings, &Stop::new(), None).await, Outcome::Failed);
}

#[tokio::test]
async fn test_sources_need_their_urls() {
    let admin = need_db!();
    let mut case = Case::new(&admin).await;
    let settings = case.settings(None, None);
    let work = job("x", |ctx| {
        Box::pin(async move {
            ctx.prometheus()?.vector("up", None).await?;
            Ok(None)
        })
    });
    execute(&work, &settings, &Stop::new(), None).await;
    let error = case.job("x").await.expect("row").last_error.unwrap_or_default();
    assert_eq!(error, "source: NETPORTAL_PROMETHEUS_URL is not set");
}

#[tokio::test]
async fn test_a_bad_stored_cursor_is_ignored() {
    let admin = need_db!();
    let mut case = Case::new(&admin).await;
    let settings = case.settings(None, None);
    case.exec(r#"INSERT INTO job (name, cursor) VALUES ('unifi_events', '{"until_ns": "soon"}')"#).await;
    let loki = fakes::FakeLoki::start().await;
    let settings =
        Arc::new(netportal_core::config::CollectSettings { loki_url: Some(loki.url.clone()), ..(*settings).clone() });
    let now = datetime!(2026-10-25 12:00 UTC);
    let job = jobs::by_name("unifi_events").expect("job");
    assert_eq!(execute(&job, &settings, &Stop::new(), Some(now)).await, Outcome::Ok);
    let start: i64 = loki.request(0)["start"].parse().expect("start");
    assert_eq!(start, now.unix_timestamp() * 1_000_000_000 - netportal_collect::unifi_events::FIRST_RUN_NS);
}

// --- SchedulerTests --------------------------------------------------------------------------------

type Calls = Arc<Mutex<Vec<(&'static str, tokio::time::Instant)>>>;

fn recording_runner(
    calls: Calls,
    outcome: fn(&str) -> Outcome,
    sleep: Duration,
    stop_after: Option<(usize, Stop)>,
) -> Runner {
    Arc::new(move |job: Job, _settings, _stop| {
        let (calls, stop_after) = (calls.clone(), stop_after.clone());
        Box::pin(async move {
            let n = {
                let mut c = calls.lock().expect("calls");
                c.push((job.name, tokio::time::Instant::now()));
                c.len()
            };
            tokio::time::sleep(sleep).await;
            if let Some((limit, stop)) = stop_after
                && n >= limit
            {
                stop.set();
            }
            outcome(job.name)
        })
    })
}

fn noop(name: &'static str, every_s: u64) -> Job {
    Job::new(name, Duration::from_secs(every_s), Duration::from_secs(60), |_ctx| Box::pin(async { Ok(None) }))
}

fn no_db_settings(dir: &tempfile::TempDir) -> Arc<netportal_core::config::CollectSettings> {
    Arc::new(settings("postgresql://nobody@127.0.0.1:1/none", dir.path().join("beat"), None, None))
}

#[tokio::test]
async fn test_run_once_runs_each_job_and_reports_failures() {
    let dir = tempfile::tempdir().expect("tempdir");
    let calls: Calls = Arc::default();
    let runner =
        recording_runner(calls.clone(), |n| if n == "b" { Outcome::Failed } else { Outcome::Ok }, Duration::ZERO, None);
    let sched =
        Scheduler::new(no_db_settings(&dir), vec![noop("a", 60), noop("b", 60)], Stop::new()).with_runner(runner);
    assert_eq!(sched.run_once().await, 1);
    let names: Vec<&str> = calls.lock().expect("calls").iter().map(|c| c.0).collect();
    assert_eq!(names, ["a", "b"]);
    assert!(dir.path().join("beat").exists());
    // a locked job is not a failure
    let runner = recording_runner(Arc::default(), |_| Outcome::Locked, Duration::ZERO, None);
    let sched = Scheduler::new(no_db_settings(&dir), vec![noop("a", 60)], Stop::new()).with_runner(runner);
    assert_eq!(sched.run_once().await, 0);
}

#[tokio::test(start_paused = true)]
async fn test_loop_runs_due_jobs_in_turn() {
    let dir = tempfile::tempdir().expect("tempdir");
    let calls: Calls = Arc::default();
    let stop = Stop::new();
    let runner = recording_runner(
        calls.clone(),
        |n| if n == "b" { Outcome::Failed } else { Outcome::Ok },
        Duration::from_secs(10),
        Some((5, stop.clone())),
    );
    let mut sched =
        Scheduler::new(no_db_settings(&dir), vec![noop("a", 30), noop("b", 3600)], stop).with_runner(runner);
    assert_eq!(sched.run_forever().await, 0);
    let calls = calls.lock().expect("calls");
    let names: Vec<&str> = calls.iter().map(|c| c.0).collect();
    assert_eq!(names[..2], ["a", "b"]);
    assert_eq!(names.iter().filter(|n| **n == "b").count(), 1); // failed: retried after RETRY, not within minutes
    assert!(names[2..].iter().all(|n| *n == "a"));
    // a runs every 30 s from its start
    let a: Vec<_> = calls.iter().filter(|c| c.0 == "a").map(|c| c.1).collect();
    assert_eq!(a[2] - a[1], Duration::from_secs(30));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_heartbeat_while_a_job_runs_but_not_for_a_hung_one() {
    let dir = tempfile::tempdir().expect("tempdir");
    let beat = dir.path().join("beat");
    let stop = Stop::new();
    let release = Stop::new();
    let gate = release.clone();
    let runner: Runner = Arc::new(move |_job, _settings, _stop| {
        let gate = gate.clone();
        Box::pin(async move {
            gate.wait(Duration::from_secs(5)).await;
            Outcome::Ok
        })
    });
    let mut sched = Scheduler::new(no_db_settings(&dir), vec![noop("a", 3600)], stop.clone()).with_runner(runner);
    sched.heartbeat_every = Duration::from_millis(100);
    sched.max_job = Duration::from_millis(800);
    let handle = tokio::spawn(async move { sched.run_forever().await });
    tokio::time::sleep(Duration::from_millis(300)).await;
    std::fs::remove_file(&beat).expect("unlink");
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(beat.exists()); // the job runs: still beating
    tokio::time::sleep(Duration::from_millis(500)).await;
    std::fs::remove_file(&beat).expect("unlink");
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(!beat.exists()); // longer than max_job: hung, no beat
    release.set();
    stop.set();
    assert_eq!(handle.await.expect("join"), 0);
    assert!(beat.exists());
}

#[tokio::test]
async fn test_restart_does_not_rerun_a_daily_job_at_once() {
    let admin = need_db!();
    let mut case = Case::new(&admin).await;
    case.exec("INSERT INTO job (name, last_attempt) VALUES ('prune', now() - interval '1 hour')").await;
    let mut sched =
        Scheduler::new(case.settings(None, None), vec![noop("prune", 86400), noop("incidents", 120)], Stop::new());
    let now = tokio::time::Instant::now();
    sched.load_due().await;
    let prune = sched.next_due["prune"].duration_since(now).as_secs_f64();
    assert!((prune - 82800.0).abs() < 5.0, "{prune}");
    assert!(sched.next_due["incidents"].duration_since(now) < Duration::from_secs(5));
}

// --- CliTests ------------------------------------------------------------------------------------------

#[tokio::test]
async fn test_job_command_runs_one_job() {
    let admin = need_db!();
    let mut case = Case::new(&admin).await;
    let settings = case.settings(None, None);
    assert_eq!(scheduler::run_job(&settings, "prune").await.expect("run"), 0);
    let names: Vec<String> =
        netportal_core::registry::job_status(&mut case.db).await.expect("jobs").into_iter().map(|j| j.name).collect();
    assert_eq!(names, ["offboarding", "prune"]); // offboarding: seeded by init
    assert!(case.job("prune").await.expect("prune").last_success.is_some());
    assert!(case.heartbeat().exists());
}

#[tokio::test]
async fn test_collect_once_with_a_job_list() {
    let admin = need_db!();
    let mut case = Case::new(&admin).await;
    let settings = case.settings(None, None);
    // incidents: no Prometheus configured
    assert_eq!(scheduler::run(&settings, true, "prune,incidents").await.expect("run"), 1);
    let incidents = case.job("incidents").await.expect("incidents");
    assert!(incidents.last_error.unwrap_or_default().contains("NETPORTAL_PROMETHEUS_URL"));
    assert!(case.job("prune").await.expect("prune").last_success.is_some());
}

#[tokio::test]
async fn test_unknown_job() {
    let dir = tempfile::tempdir().expect("tempdir");
    let settings = no_db_settings(&dir);
    let error = scheduler::run_job(&settings, "nope").await.err().map(|e| e.to_string());
    assert_eq!(error.as_deref(), Some("unknown job(s): nope (known: unifi_events, incidents, rollup, prune)"));
    assert!(scheduler::run_job(&settings, "prune,rollup").await.is_err());
    assert!(scheduler::run(&settings, true, "prune,nope").await.is_err());
}

// --- PruneTests ------------------------------------------------------------------------------------------

#[tokio::test]
async fn test_prune_job_calls_the_registry_with_the_run_time() {
    let admin = need_db!();
    let mut case = Case::new(&admin).await;
    let settings = case.settings(None, None);
    let now = datetime!(2026-10-25 03:00 UTC);
    // older than 400 days at the run's time: gone; younger: kept (also if older than 400 days
    // at the real now)
    let old = now - time::Duration::days(401);
    let young = now - time::Duration::days(399);
    for at in [old, old, old, young, young] {
        sqlx::query("INSERT INTO radius_auth (at, result, reason) VALUES ($1, 'reject', 'no_cert')")
            .bind(at)
            .execute(case.db.tx().await.expect("tx"))
            .await
            .expect("insert");
    }
    case.db.commit().await.expect("commit");
    let prune = jobs::by_name("prune").expect("prune");
    assert_eq!(execute(&prune, &settings, &Stop::new(), Some(now)).await, Outcome::Ok);
    let cursor = case.job("prune").await.expect("prune").cursor.0;
    assert_eq!(cursor["last_run"]["radius_auth"], 3);
    assert_eq!(cursor["last_run"]["connection_event"], 0);
    assert_eq!(case.i64("SELECT count(*) FROM radius_auth").await, 2);
}
