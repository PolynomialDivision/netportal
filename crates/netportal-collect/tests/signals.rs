//! SIGTERM ends the loop after the running job (Python tests/test_collect.py
//! SchedulerTests.test_sigterm_ends_the_loop_after_the_running_job). A test binary of its own:
//! the handler is process-wide.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use netportal_collect::scheduler::{Job, Outcome, Runner, Scheduler, Stop, install_signal_handlers};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sigterm_ends_the_loop_after_the_running_job() {
    let dir = tempfile::tempdir().expect("tempdir");
    let settings =
        Arc::new(common::settings("postgresql://nobody@127.0.0.1:1/none", dir.path().join("beat"), None, None));
    let stop = Stop::new();
    let started = Stop::new();
    let finished: Arc<Mutex<Vec<bool>>> = Arc::default();
    let (flag, done) = (started.clone(), finished.clone());
    let runner: Runner = Arc::new(move |_job, _settings, stop| {
        let (flag, done) = (flag.clone(), done.clone());
        Box::pin(async move {
            flag.set();
            tokio::time::sleep(Duration::from_millis(300)).await;
            done.lock().expect("done").push(stop.is_set());
            Outcome::Ok
        })
    });
    let job = Job::new("a", Duration::from_secs(3600), Duration::from_secs(60), |_ctx| Box::pin(async { Ok(None) }));
    let mut sched = Scheduler::new(settings, vec![job], stop.clone()).with_runner(runner);
    sched.tick = Duration::from_millis(50);
    install_signal_handlers(&stop).expect("handlers");
    let handle = tokio::spawn(async move { sched.run_forever().await });
    assert!(started.wait(Duration::from_secs(5)).await);
    let status =
        std::process::Command::new("kill").args(["-TERM", &std::process::id().to_string()]).status().expect("kill");
    assert!(status.success());
    let rc = tokio::time::timeout(Duration::from_secs(5), handle).await.expect("stopped in time").expect("join");
    assert_eq!(rc, 0);
    assert_eq!(*finished.lock().expect("finished"), [true]); // the job finished, it saw the stop
    assert!(dir.path().join("beat").exists());
}
