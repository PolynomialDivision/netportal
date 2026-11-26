//! `netportal iot [--every N]`: the heartbeat after a round, also a failed one; the exit codes;
//! the loop stops at its signal. No database needed (a round that reaches it fails at once).

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, SystemTime};

use netportal_core::config::IotSettings;
use netportal_iot::reconcile::{Backends, IotError, Memory};
use netportal_iot::run::{self, touch};

fn settings(heartbeat: &Path) -> IotSettings {
    let beat = heartbeat.to_str().expect("path").to_string();
    let env: BTreeMap<&str, &str> = [
        // nothing listens on port 9: a round that gets as far as the database fails at once
        ("NETPORTAL_DATABASE_URL", "postgresql://u:p@127.0.0.1:9/n"),
        ("NETPORTAL_HEARTBEAT", beat.as_str()),
    ]
    .into();
    IotSettings::from_env(&env).expect("settings")
}

#[tokio::test]
async fn test_heartbeat_even_when_the_round_fails() {
    let tmp = tempfile::tempdir().expect("tmp");
    let beat = tmp.path().join("beat");
    let result = run::run(&settings(&beat), 0).await;
    assert!(matches!(result, Err(IotError::Registry(_))), "{result:?}");
    assert!(beat.exists());
}

#[tokio::test]
async fn test_heartbeat_failure_is_reported() {
    let tmp = tempfile::tempdir().expect("tmp");
    let beat = tmp.path().join("missing-dir").join("beat");
    let result = touch(&beat);
    assert!(matches!(result, Err(IotError::Heartbeat { .. })), "{result:?}");
}

#[tokio::test]
async fn test_touch_moves_the_modification_time() {
    let tmp = tempfile::tempdir().expect("tmp");
    let beat = tmp.path().join("beat");
    std::fs::write(&beat, b"").expect("file");
    let old = SystemTime::now() - Duration::from_secs(600);
    std::fs::File::open(&beat).expect("open").set_modified(old).expect("set");
    touch(&beat).expect("touch");
    let modified = std::fs::metadata(&beat).expect("meta").modified().expect("mtime");
    assert!(modified > old + Duration::from_secs(500));
}

#[tokio::test]
async fn test_loop_stops_at_the_signal_after_the_round() {
    let tmp = tempfile::tempdir().expect("tmp");
    let beat = tmp.path().join("beat");
    let s = settings(&beat);
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let stop = async move {
        let _ = rx.await;
    };
    let mut memory = Memory::default();
    let backends = Backends::default();
    let looping = run::run_loop(&s, &backends, &mut memory, Duration::from_secs(3600), stop);
    let stopper = async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = tx.send(());
    };
    let (code, ()) = tokio::time::timeout(Duration::from_secs(30), async { tokio::join!(looping, stopper) })
        .await
        .expect("the loop stops");
    assert_eq!(code, 0);
    assert!(beat.exists(), "the heartbeat after the (failed) round");
}
