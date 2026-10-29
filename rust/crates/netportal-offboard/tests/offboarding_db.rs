//! The round against a real registry (INVENTORY 8.2, 8.1 guards, 7.1 Disconnect): the Python
//! offboarding tests (test_units.PolicyTests, test_web.OffboardingAdminTests) and the
//! contract suite's scenarios (rust/tests/contract/test_offboarding.py) in process, with a fake
//! users API and a recording Disconnector.
//!
//! Needs `NETPORTAL_TEST_DATABASE_URL` (`eval "$(rust/tools/test-db.sh)"`); skipped without it.

mod common;

use common::{Case, FakeDisconnector, FakeIdp, policies, user};
use netportal_core::config::MassRemoval;
use netportal_core::registry;
use netportal_offboard::actions;
use netportal_offboard::directory::{Directory, DirectoryUser};
use netportal_offboard::disconnect::DisconnectResult;
use netportal_offboard::offboarding::{self, LOCK_KEY, OffboardError, RoundOptions, RoundReport};
use sqlx::{Connection, PgConnection};

/// The sidecar's rounds: the mass-removal hold, two rounds before a removal.
fn sidecar() -> RoundOptions {
    RoundOptions::default()
}

/// `netportal offboard --allow-mass`: everything at once (the scenarios of the Python tests,
/// which offboard in one round).
fn at_once() -> RoundOptions {
    RoundOptions::new(MassRemoval::default(), true)
}

fn dir(users: &[(&str, bool, &[&str])]) -> Directory {
    Directory::from_users(users.iter().map(|(uid, active, groups)| DirectoryUser {
        uid: uid.to_string(),
        active: *active,
        groups: groups.iter().map(|g| g.to_string()).collect(),
    }))
    .expect("directory")
}

#[tokio::test]
async fn test_lost_access_is_offboarded() {
    let admin = need_db!();
    let mut case = Case::new(&admin).await;
    for sub in ["inactive", "nogroup", "deleted", "keeper"] {
        case.person(sub, false).await;
    }
    let dev1 = case.device("inactive", Some("192.0.2.7")).await;
    let dev2 = case.device("nogroup", None).await;
    let dev3 = case.device("deleted", None).await;
    let dev4 = case.device("keeper", Some("192.0.2.8")).await;
    let grant = registry::create_grant(&mut case.db, "deleted", "app.geteduroam.sh", "Laptop").await.expect("grant");
    let access = registry::issue_token(&mut case.db, grant, "access", 3600, None, None).await.expect("token");
    case.db.commit().await.expect("commit");
    let directory = dir(&[
        ("inactive", false, &["residents"]),
        ("nogroup", true, &["vpn-users"]),
        ("keeper", true, &["residents"]),
    ]);
    let nas = FakeDisconnector::new(DisconnectResult::Ack);
    let report = offboarding::reconcile(&mut case.db, &directory, &policies(), &nas, &at_once()).await.expect("round");
    assert_eq!(
        report,
        RoundReport { users: 3, checked: 4, offboarded: 3, revoked: 3, moved: 0, pending: 0, admins_removed: 0 }
    );
    for (sub, dev) in [("inactive", dev1), ("nogroup", dev2), ("deleted", dev3)] {
        assert!(case.offboarded(sub).await, "{sub}");
        assert!(case.revoked(dev).await, "{sub}");
        assert!(case.audit(dev).await.contains(&("offboarding".into(), "revoke".into())), "{sub}");
    }
    assert!(!case.offboarded("keeper").await);
    assert!(!case.revoked(dev4).await);
    // the app's tokens stop at once
    assert!(registry::use_token(&mut case.db, &access, "access", false).await.expect("token").valid().is_none());
    case.db.commit().await.expect("commit");
    // the access point got a Disconnect-Request for the device with a session
    let sent = nas.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].nas_ip, "192.0.2.7");
    assert_eq!(sent[0].calling_station, "AA-BB-CC-DD-EE-01");
    assert_eq!(sent[0].user_name, "anonymous@example.org");
    assert_eq!(
        case.audit(dev1).await,
        [("offboarding".to_string(), "revoke".to_string()), ("offboarding".to_string(), "disconnect:ack".to_string())]
    );
    assert!(case.audit(dev2).await.contains(&("offboarding".into(), "disconnect:no-session".into())));
    // a second round changes nothing and sends nothing
    let again = offboarding::reconcile(&mut case.db, &directory, &policies(), &nas, &at_once()).await.expect("round");
    assert_eq!((again.revoked, again.moved, again.offboarded), (0, 0, 0));
    assert_eq!(nas.sent().len(), 1);
}

#[tokio::test]
async fn test_moved_out_keeps_the_devices_in_the_guests_vlan() {
    let admin = need_db!();
    let mut case = Case::new(&admin).await;
    case.person("mover", false).await;
    case.person("stays", false).await;
    let dev = case.device("mover", Some("192.0.2.9")).await;
    let other = case.device("stays", Some("192.0.2.10")).await;
    let nas = FakeDisconnector::new(DisconnectResult::Nak);
    let directory = dir(&[("mover", true, &["former-residents"]), ("stays", true, &["residents"])]);
    let report = offboarding::reconcile(&mut case.db, &directory, &policies(), &nas, &at_once()).await.expect("round");
    assert_eq!((report.moved, report.revoked, report.offboarded), (1, 0, 0));
    assert_eq!(registry::person_policy(&mut case.db, "mover").await.expect("policy").as_deref(), Some("guests"));
    assert_eq!(case.device_policy(dev).await, "guests");
    assert!(!case.revoked(dev).await);
    assert!(!case.offboarded("mover").await);
    assert_eq!(
        case.audit(dev).await,
        [
            ("offboarding".to_string(), "policy:guests".to_string()),
            ("offboarding".to_string(), "disconnect:nak".to_string())
        ]
    );
    assert_eq!(nas.sent().iter().map(|s| s.nas_ip.as_str()).collect::<Vec<_>>(), ["192.0.2.9"]);
    assert_eq!(case.device_policy(other).await, "residents");
    assert!(case.audit(other).await.is_empty());
}

#[tokio::test]
async fn test_run_sets_the_flag_per_person() {
    // test_web.OffboardingAdminTests / contract test_admin_rights_follow_the_groups
    let admin = need_db!();
    let mut case = Case::new(&admin).await;
    case.person("a", false).await;
    case.person("r", true).await;
    let nas = FakeDisconnector::new(DisconnectResult::Ack);
    let directory = dir(&[("a", true, &["it-admins"]), ("r", true, &["residents"])]);
    offboarding::reconcile(&mut case.db, &directory, &policies(), &nas, &at_once()).await.expect("round");
    assert_eq!(case.is_admin("a").await, Some(true));
    assert_eq!(case.is_admin("r").await, Some(false));
    // an inactive admin loses everything
    let directory = dir(&[("a", false, &["it-admins"]), ("r", true, &["residents"])]);
    offboarding::reconcile(&mut case.db, &directory, &policies(), &nas, &at_once()).await.expect("round");
    assert_eq!(case.is_admin("a").await, None);
    assert!(case.offboarded("a").await);
    assert_eq!(case.count("SELECT count(*) FROM person WHERE sub = 'a' AND is_admin").await, 0);
}

#[tokio::test]
async fn test_people_only_in_authentik_are_ignored() {
    let admin = need_db!();
    let mut case = Case::new(&admin).await;
    case.person("known", false).await;
    let nas = FakeDisconnector::new(DisconnectResult::Ack);
    let directory = dir(&[("known", true, &["residents"]), ("stranger", true, &["residents"])]);
    let report = offboarding::reconcile(&mut case.db, &directory, &policies(), &nas, &at_once()).await.expect("round");
    assert_eq!(report.checked, 1);
    assert_eq!(case.count("SELECT count(*) FROM person WHERE sub = 'stranger'").await, 0);
}

#[tokio::test]
async fn test_devices_left_by_an_earlier_round_are_revoked() {
    // a round that stopped between offboard_person and the revocations: the next one finishes
    let admin = need_db!();
    let mut case = Case::new(&admin).await;
    case.person("gone", false).await;
    case.person("keeper", false).await;
    let dev = case.device("gone", None).await;
    registry::offboard_person(&mut case.db, "gone").await.expect("offboard");
    case.db.commit().await.expect("commit");
    let nas = FakeDisconnector::new(DisconnectResult::Ack);
    let report =
        offboarding::reconcile(&mut case.db, &dir(&[("keeper", true, &["residents"])]), &policies(), &nas, &at_once())
            .await
            .expect("round");
    assert_eq!(report.revoked, 1);
    assert!(case.revoked(dev).await);
}

/// The registry before and after a refused round: nothing may differ.
async fn snapshot(case: &mut Case) -> (i64, i64, i64, i64) {
    (
        case.count("SELECT count(*) FROM person WHERE offboarded_at IS NOT NULL").await,
        case.count("SELECT count(*) FROM device WHERE revoked_at IS NOT NULL").await,
        case.count("SELECT count(*) FROM audit").await,
        case.count("SELECT count(*) FROM person WHERE is_admin").await,
    )
}

#[tokio::test]
async fn test_guards_change_nothing() {
    let admin = need_db!();
    let mut case = Case::new(&admin).await;
    case.person("p1", true).await;
    case.person("p2", false).await;
    let dev = case.device("p1", Some("192.0.2.11")).await;
    let before = snapshot(&mut case).await;
    let nas = FakeDisconnector::new(DisconnectResult::Ack);
    let cases: [(&str, Directory); 3] = [
        ("no users", dir(&[])),
        ("nobody in a Wi-Fi group", dir(&[("p1", true, &["vpn-users"]), ("p2", false, &["residents"])])),
        ("none of the registry's people", dir(&[("other-1", true, &["residents"]), ("other-2", true, &["it-admins"])])),
    ];
    for (why, directory) in cases {
        let result = offboarding::reconcile(&mut case.db, &directory, &policies(), &nas, &at_once()).await;
        assert!(matches!(result, Err(OffboardError::Guard(_))), "{why}: {result:?}");
        assert_eq!(snapshot(&mut case).await, before, "{why}");
    }
    assert!(!case.revoked(dev).await);
    assert!(nas.sent().is_empty());
}

#[tokio::test]
async fn test_a_round_reads_the_api_and_records_the_job() {
    let admin = need_db!();
    let mut case = Case::new(&admin).await;
    case.person("stay", false).await;
    case.person("leave", false).await;
    let dev = case.device("leave", None).await;
    let idp =
        FakeIdp::start(vec![user("stay", true, &["residents"]), user("x", true, &[]), user("y", false, &[])]).await;
    idp.with(|s| s.page_size = 1);
    let before = case.job().await.expect("seeded").last_success;
    let nas = FakeDisconnector::new(DisconnectResult::Ack);
    let report = offboarding::round(&case.url, &idp.client(), &policies(), &nas, &at_once()).await.expect("round");
    assert_eq!((report.users, report.revoked), (3, 1));
    assert!(case.revoked(dev).await);
    assert_eq!(idp.requests().len(), 3);
    let job = case.job().await.expect("job");
    assert!(job.last_success > before);
    assert!(job.last_attempt.is_some() && job.last_error.is_none() && job.duration_s.is_some());
    assert_eq!(job.cursor.0["last_round"]["revoked"], 1);
}

#[tokio::test]
async fn test_api_failure_changes_nothing() {
    let admin = need_db!();
    let mut case = Case::new(&admin).await;
    case.person("p", false).await;
    case.person("q", false).await;
    let dev = case.device("p", None).await;
    let idp = FakeIdp::start(vec![user("q", true, &["residents"])]).await; // p would be offboarded
    let nas = FakeDisconnector::new(DisconnectResult::Ack);
    let success = case.job().await.expect("seeded").last_success;
    let before = snapshot(&mut case).await;
    for (why, fail, size) in [("HTTP 500", Some(500), 100), ("a later page", None, 1)] {
        idp.with(|s| {
            s.fail = fail;
            s.page_size = size;
            s.tweak = if fail.is_none() {
                Some(std::sync::Arc::new(|page, body| {
                    if page == 2 {
                        body["pagination"]["count"] = serde_json::json!(3);
                    }
                }))
            } else {
                None
            };
            s.users = vec![user("q", true, &["residents"]), user("z", true, &["residents"])];
        });
        let result = offboarding::round(&case.url, &idp.client(), &policies(), &nas, &at_once()).await;
        assert!(matches!(result, Err(OffboardError::Directory(_))), "{why}: {result:?}");
        assert_eq!(snapshot(&mut case).await, before, "{why}");
        let job = case.job().await.expect("job");
        assert_eq!(job.last_success, success, "{why}");
        assert!(job.last_error.as_deref().is_some_and(|e| e.contains("users API") || e.contains("changed")), "{why}");
    }
    assert!(!case.revoked(dev).await);
    assert!(nas.sent().is_empty());
}

#[tokio::test]
async fn test_a_second_process_is_locked_out() {
    let admin = need_db!();
    let mut case = Case::new(&admin).await;
    case.person("p", false).await;
    case.person("q", false).await;
    let idp = FakeIdp::start(vec![user("q", true, &["residents"])]).await;
    let mut other = PgConnection::connect(&case.url).await.expect("connect");
    let held: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock(hashtext($1))")
        .bind(LOCK_KEY)
        .fetch_one(&mut other)
        .await
        .expect("lock");
    assert!(held);
    let nas = FakeDisconnector::new(DisconnectResult::Ack);
    let result = offboarding::round(&case.url, &idp.client(), &policies(), &nas, &at_once()).await;
    assert!(matches!(result, Err(OffboardError::Locked)), "{result:?}");
    assert!(idp.requests().is_empty());
    assert!(!case.offboarded("p").await);
    sqlx::query("SELECT pg_advisory_unlock(hashtext($1))").bind(LOCK_KEY).execute(&mut other).await.expect("unlock");
    // released: the next round runs (and releases the lock itself)
    offboarding::round(&case.url, &idp.client(), &policies(), &nas, &at_once()).await.expect("round");
    assert!(case.offboarded("p").await);
    let free: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock(hashtext($1))")
        .bind(LOCK_KEY)
        .fetch_one(&mut other)
        .await
        .expect("lock");
    assert!(free);
}

// --- security review 2026-10-29: M1 (mass removals, two rounds), L2 (admin loss), L4 (every session)

#[tokio::test]
async fn test_two_rounds_before_a_removal() {
    let admin = need_db!();
    let mut case = Case::new(&admin).await;
    for sub in ["leaving", "editing", "k1", "k2"] {
        case.person(sub, false).await;
    }
    let leaving = case.device("leaving", Some("192.0.2.20")).await;
    let editing = case.device("editing", None).await;
    let keepers = [("k1", true, &["residents"][..]), ("k2", true, &["residents"][..])];
    let nas = FakeDisconnector::new(DisconnectResult::Ack);
    // round 1: both are out of the groups (one leaves, one is being moved in Authentik): noted only
    let directory = dir(&[keepers[0], keepers[1]]);
    let first = offboarding::reconcile(&mut case.db, &directory, &policies(), &nas, &sidecar()).await.expect("round");
    assert_eq!((first.pending, first.offboarded, first.revoked), (2, 0, 0));
    assert!(!case.offboarded("leaving").await && !case.revoked(leaving).await);
    assert_eq!(case.count("SELECT count(*) FROM person WHERE absent_since IS NOT NULL").await, 2);
    assert!(nas.sent().is_empty());
    // round 2: the move is done (editing is in former-residents now), leaving is still out
    let directory = dir(&[keepers[0], keepers[1], ("editing", true, &["former-residents"])]);
    let second = offboarding::reconcile(&mut case.db, &directory, &policies(), &nas, &sidecar()).await.expect("round");
    assert_eq!((second.pending, second.offboarded, second.revoked, second.moved), (0, 1, 1, 1));
    assert!(case.offboarded("leaving").await && case.revoked(leaving).await);
    assert!(!case.revoked(editing).await, "a move in progress must not cost a re-enrolment");
    assert_eq!(case.device_policy(editing).await, "guests");
    assert_eq!(case.count("SELECT count(*) FROM person WHERE absent_since IS NOT NULL AND sub = 'editing'").await, 0);
    assert_eq!(nas.sent().iter().map(|s| s.nas_ip.as_str()).collect::<Vec<_>>(), ["192.0.2.20"]);
    // a login clears the note too
    let directory = dir(&[keepers[0], keepers[1]]);
    offboarding::reconcile(&mut case.db, &directory, &policies(), &nas, &sidecar()).await.expect("round");
    assert_eq!(case.count("SELECT count(*) FROM person WHERE absent_since IS NOT NULL AND sub = 'editing'").await, 1);
    registry::upsert_person(&mut case.db, "editing", "editing", "editing", false).await.expect("login");
    case.db.commit().await.expect("commit");
    assert_eq!(case.count("SELECT count(*) FROM person WHERE absent_since IS NOT NULL AND sub = 'editing'").await, 0);
}

#[tokio::test]
async fn test_a_mass_removal_is_held_back() {
    // the reviewer's case: a token that sees only one of five residents (consistent paging)
    let admin = need_db!();
    let mut case = Case::new(&admin).await;
    let subs = ["m0", "m1", "m2", "m3", "m4"];
    let mut devices = Vec::new();
    for sub in subs {
        case.person(sub, false).await;
        devices.push(case.device(sub, Some("192.0.2.30")).await);
    }
    let nas = FakeDisconnector::new(DisconnectResult::Ack);
    let partial = dir(&[("m0", true, &["residents"])]);
    let absent = "SELECT count(*) FROM person WHERE absent_since IS NOT NULL";
    let before = (snapshot(&mut case).await, case.count(absent).await);
    for _ in 0..2 {
        let result = offboarding::reconcile(&mut case.db, &partial, &policies(), &nas, &sidecar()).await;
        match &result {
            Err(e @ OffboardError::HeldBack(_)) => {
                let text = e.to_string();
                assert!(text.starts_with("HELD BACK, nothing changed: 4 of the 5 people"), "{text}");
                assert!(text.contains("--allow-mass"), "{text}");
            }
            other => panic!("not held back: {other:?}"),
        }
        assert_eq!((snapshot(&mut case).await, case.count(absent).await), before);
    }
    assert!(nas.sent().is_empty());
    // fewer than 3, or not more than half: no hold (two of five leave)
    let mostly = dir(&[("m0", true, &["residents"]), ("m1", true, &["residents"]), ("m2", true, &["residents"])]);
    let report = offboarding::reconcile(&mut case.db, &mostly, &policies(), &nas, &sidecar()).await.expect("round");
    assert_eq!(report.pending, 2);
    // NETPORTAL_OFFBOARD_ALLOW_MASS waives the hold, not the second round
    let allow = RoundOptions::new(MassRemoval { allow: true, ..MassRemoval::default() }, false);
    let report = offboarding::reconcile(&mut case.db, &partial, &policies(), &nas, &allow).await.expect("round");
    assert_eq!((report.offboarded, report.pending), (2, 2)); // m3, m4 from the round before; m1, m2 new
    // --allow-mass: everything now
    let report = offboarding::reconcile(&mut case.db, &partial, &policies(), &nas, &at_once()).await.expect("round");
    assert_eq!(report.offboarded, 2);
    for (sub, dev) in subs.iter().zip(&devices).skip(1) {
        assert!(case.offboarded(sub).await && case.revoked(*dev).await, "{sub}");
    }
    assert!(!case.revoked(devices[0]).await);
}

#[tokio::test]
async fn test_a_held_back_round_fails_the_job() {
    let admin = need_db!();
    let mut case = Case::new(&admin).await;
    for sub in ["h0", "h1", "h2", "h3"] {
        case.person(sub, false).await;
        case.device(sub, None).await;
    }
    let idp = FakeIdp::start(vec![user("h0", true, &["residents"])]).await;
    let success = case.job().await.expect("seeded").last_success;
    let nas = FakeDisconnector::new(DisconnectResult::Ack);
    let result = offboarding::round(&case.url, &idp.client(), &policies(), &nas, &sidecar()).await;
    assert!(matches!(result, Err(OffboardError::HeldBack(_))), "{result:?}");
    let job = case.job().await.expect("job");
    assert_eq!(job.last_success, success, "the staleness alert must fire");
    assert!(job.last_error.as_deref().is_some_and(|e| e.starts_with("HELD BACK")), "{:?}", job.last_error);
    assert_eq!(case.count("SELECT count(*) FROM device WHERE revoked_at IS NOT NULL").await, 0);
}

#[tokio::test]
async fn test_losing_the_admin_right_ends_the_portal_sessions() {
    let admin = need_db!();
    let mut case = Case::new(&admin).await;
    case.person("boss", true).await;
    case.person("res", false).await;
    let epoch = "SELECT session_epoch FROM person WHERE sub = 'boss'";
    assert_eq!(case.count(epoch).await, 0);
    let nas = FakeDisconnector::new(DisconnectResult::Ack);
    // still an admin: nothing ends
    let directory = dir(&[("boss", true, &["it-admins"]), ("res", true, &["residents"])]);
    let report = offboarding::reconcile(&mut case.db, &directory, &policies(), &nas, &sidecar()).await.expect("round");
    assert_eq!((report.admins_removed, case.count(epoch).await), (0, 0));
    // out of it-admins: no admin, and every portal session of the person ends
    let directory = dir(&[("boss", true, &["residents"]), ("res", true, &["residents"])]);
    let report = offboarding::reconcile(&mut case.db, &directory, &policies(), &nas, &sidecar()).await.expect("round");
    assert_eq!(report.admins_removed, 1);
    assert_eq!(case.is_admin("boss").await, Some(false));
    assert_eq!(case.count(epoch).await, 1);
    // the next round changes nothing
    offboarding::reconcile(&mut case.db, &directory, &policies(), &nas, &sidecar()).await.expect("round");
    assert_eq!(case.count(epoch).await, 1);
    assert_eq!(case.count("SELECT session_epoch FROM person WHERE sub = 'res'").await, 0);
}

#[tokio::test]
async fn test_every_open_session_of_a_revoked_device_is_disconnected() {
    // a Mac on Wi-Fi (its latest login) and on the wired port (an open accounting session of the
    // switch); a stopped and a stale session are left alone
    let admin = need_db!();
    let mut case = Case::new(&admin).await;
    case.person("mac", false).await;
    let dev = case.device("mac", Some("192.0.2.40")).await;
    for (nas, session, mac, stopped, age_h) in [
        ("192.0.2.40", "wifi-1", "aa:bb:cc:dd:ee:01", false, 0), // the same as the latest login
        ("192.0.2.41", "wired-1", "aa:bb:cc:dd:ee:02", false, 0),
        ("192.0.2.42", "old-stopped", "aa:bb:cc:dd:ee:02", true, 0),
        ("192.0.2.43", "stale", "aa:bb:cc:dd:ee:03", false, 48),
    ] {
        sqlx::query(
            "INSERT INTO radius_acct (nas_ip, acct_session_id, device_id, link, mac, started, updated, stopped)
             VALUES ($1::inet, $2, $3, 'class', $4::macaddr, now() - make_interval(hours => $6),
                     now() - make_interval(hours => $6), CASE WHEN $5 THEN now() END)",
        )
        .bind(nas)
        .bind(session)
        .bind(dev)
        .bind(mac)
        .bind(stopped)
        .bind(age_h)
        .execute(case.db.tx().await.expect("tx"))
        .await
        .expect("acct");
    }
    case.db.commit().await.expect("commit");
    let nas = FakeDisconnector::new(DisconnectResult::Ack);
    let results = actions::revoke_now(&mut case.db, dev, "offboarding", &nas).await.expect("revoke");
    assert_eq!(results, [DisconnectResult::Ack, DisconnectResult::Ack]);
    let sent: Vec<(String, String, String)> =
        nas.sent().into_iter().map(|s| (s.nas_ip, s.calling_station, s.user_name)).collect();
    assert_eq!(
        sent,
        [
            ("192.0.2.40".to_string(), "AA-BB-CC-DD-EE-01".to_string(), "anonymous@example.org".to_string()),
            ("192.0.2.41".to_string(), "AA-BB-CC-DD-EE-02".to_string(), String::new()),
        ]
    );
    let audit = case.audit(dev).await;
    assert_eq!(audit.iter().filter(|(_, a)| a == "disconnect:ack").count(), 2);
}
