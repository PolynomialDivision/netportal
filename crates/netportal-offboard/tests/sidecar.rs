//! `netportal offboard [--every N]` (Python test_units.OffboardSidecarTests, INVENTORY 8.3): the
//! heartbeat after every round, also a failed one; exit codes; the loop. No database needed.

mod common;

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, SystemTime};

use common::FakeDisconnector;
use netportal_core::config::OffboardSettings;
use netportal_offboard::disconnect::DisconnectResult;
use netportal_offboard::offboarding::{self, OffboardError, RoundOptions};

fn settings(heartbeat: &Path, extra: &[(&'static str, &str)]) -> OffboardSettings {
    let beat = heartbeat.to_str().expect("path").to_string();
    let mut env: BTreeMap<&str, &str> = [
        // nothing listens on port 9: a round that gets as far as the database fails at once
        ("NETPORTAL_DATABASE_URL", "postgresql://u:p@127.0.0.1:9/n"),
        ("NETPORTAL_POLICIES", "residents=30:residents"),
        ("NETPORTAL_HEARTBEAT", beat.as_str()),
    ]
    .into();
    env.extend(extra.iter().copied());
    OffboardSettings::from_env(&env).expect("settings")
}

#[tokio::test]
async fn test_heartbeat_after_a_round() {
    // the off switch: a round that does nothing, successfully
    let tmp = tempfile::tempdir().expect("tmp");
    let beat = tmp.path().join("beat");
    assert_eq!(offboarding::run(&settings(&beat, &[]), 0, false).await.expect("round"), 0);
    assert!(beat.exists());
}

#[tokio::test]
async fn test_heartbeat_even_when_the_round_fails() {
    let tmp = tempfile::tempdir().expect("tmp");
    let beat = tmp.path().join("beat");
    let s = settings(
        &beat,
        &[("NETPORTAL_AUTHENTIK_API", "http://127.0.0.1:9/api/v3"), ("NETPORTAL_AUTHENTIK_TOKEN", "t")],
    );
    let result = offboarding::run(&s, 0, false).await;
    assert!(matches!(result, Err(OffboardError::Registry(_))), "{result:?}");
    assert!(beat.exists());
}

#[tokio::test]
async fn test_heartbeat_failure_fails_a_single_round() {
    let tmp = tempfile::tempdir().expect("tmp");
    let beat = tmp.path().join("missing-dir").join("beat");
    let result = offboarding::run(&settings(&beat, &[]), 0, false).await;
    assert!(matches!(result, Err(OffboardError::Heartbeat { .. })), "{result:?}");
}

#[tokio::test]
async fn test_touch_moves_the_modification_time() {
    let tmp = tempfile::tempdir().expect("tmp");
    let beat = tmp.path().join("beat");
    std::fs::write(&beat, b"").expect("write");
    let old = SystemTime::now() - Duration::from_secs(3600);
    std::fs::File::options().write(true).open(&beat).expect("open").set_modified(old).expect("set");
    offboarding::touch(&beat).expect("touch");
    let modified = std::fs::metadata(&beat).expect("metadata").modified().expect("mtime");
    assert!(modified > old + Duration::from_secs(3000));
}

#[tokio::test]
async fn test_every_n_seconds() {
    // rounds go on (also failing ones) and touch the heartbeat after each, until the stop signal
    let tmp = tempfile::tempdir().expect("tmp");
    let beat = tmp.path().join("beat");
    let s = settings(
        &beat,
        &[("NETPORTAL_AUTHENTIK_API", "http://127.0.0.1:9/api/v3"), ("NETPORTAL_AUTHENTIK_TOKEN", "t")],
    );
    let nas = FakeDisconnector::new(DisconnectResult::Ack);
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let watch = {
        let beat = beat.clone();
        tokio::spawn(async move {
            let mut seen = std::collections::BTreeSet::new();
            let end = tokio::time::Instant::now() + Duration::from_secs(20);
            while seen.len() < 3 && tokio::time::Instant::now() < end {
                if let Ok(m) = std::fs::metadata(&beat).and_then(|m| m.modified()) {
                    seen.insert(m);
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let _ = tx.send(());
            seen.len()
        })
    };
    let api = netportal_offboard::directory::UsersApi::new(
        "http://127.0.0.1:9/api/v3",
        netportal_core::config::Secret::new("t".into()),
        Duration::from_secs(1),
    )
    .expect("client");
    let code =
        offboarding::run_loop(&s, Some(&api), &nas, &RoundOptions::default(), Duration::from_millis(100), async {
            let _ = rx.await;
        })
        .await;
    assert_eq!(code, 0);
    assert!(watch.await.expect("watch") >= 3, "the heartbeat must be touched after every round");
}

#[tokio::test]
async fn test_allow_mass_is_for_one_round() {
    let tmp = tempfile::tempdir().expect("tmp");
    let beat = tmp.path().join("beat");
    let result = offboarding::run(&settings(&beat, &[]), 900, true).await;
    assert!(matches!(&result, Err(OffboardError::Guard(m)) if m.contains("--allow-mass")), "{result:?}");
}
