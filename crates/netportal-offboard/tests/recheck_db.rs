//! The Disconnect reconciliation (`netportal_offboard::recheck`, owner's review 2026-10-29)
//! against the throwaway registry and a fake access point: a lost or refused Disconnect of a
//! revocation or a policy move is sent again while the accounting shows the session live; an
//! ACK and a NAK 503 settle it (the latter for good), other answers back off and are given up
//! after the cap; a session that stops being live settles as stale; one round at a time.

mod common;

use std::time::Duration;

use common::{Case, FakeDisconnector};
use netportal_core::registry;
use netportal_offboard::actions;
use netportal_offboard::disconnect::DisconnectResult;
use netportal_offboard::offboarding::OffboardError;
use netportal_offboard::recheck::{self, MAX_TRIES};
use sqlx::{Connection, PgConnection};
use uuid::Uuid;

const EVERY: Duration = Duration::from_secs(30);
const NAS: &str = "192.0.2.50";

/// An accounting session of the device as FreeRADIUS records it: a login (with its VLAN) and a
/// Start echoing its Class, from NAS.
async fn live_session(case: &mut Case, dev: Uuid, sid: &str, mac: &str, vlan: &str) {
    let serial: String = sqlx::query_scalar("SELECT serial FROM credential WHERE device_id = $1 LIMIT 1")
        .bind(dev)
        .fetch_optional(case.db.tx().await.expect("tx"))
        .await
        .expect("serial")
        .unwrap_or_default();
    let class: Option<String> =
        sqlx::query_scalar("SELECT radius.login($1, $2, $3, 'AA-BB-CC-00-00-01:Scharni', $4, $5, 'anonymous@x', $6)")
            .bind(dev.to_string())
            .bind(&serial)
            .bind(mac)
            .bind(NAS)
            .bind(sid)
            .bind(vlan)
            .fetch_one(case.db.tx().await.expect("tx"))
            .await
            .expect("login");
    sqlx::query(
        "SELECT radius.accounting('Start', $1, $2, $3, 'AA-BB-CC-00-00-01:Scharni', $4, '', '', '', '', '', '', '', '')",
    )
    .bind(sid)
    .bind(class.unwrap_or_default())
    .bind(mac)
    .bind(NAS)
    .execute(case.db.tx().await.expect("tx"))
    .await
    .expect("accounting");
    case.db.commit().await.expect("commit");
}

/// A device of a new person with a certificate, created a day ago (so its locks can be dated
/// back past the grace).
async fn device(case: &mut Case, owner: &str) -> Uuid {
    case.person(owner, false).await;
    let dev = case.device(owner, None).await;
    sqlx::query("INSERT INTO credential (serial, device_id, not_after) VALUES ($1, $2, now() + interval '1 day')")
        .bind(Uuid::new_v4().simple().to_string())
        .bind(dev)
        .execute(case.db.tx().await.expect("tx"))
        .await
        .expect("credential");
    sqlx::query("UPDATE device SET created_at = now() - interval '1 day' WHERE id = $1")
        .bind(dev)
        .execute(case.db.tx().await.expect("tx"))
        .await
        .expect("age");
    case.db.commit().await.expect("commit");
    dev
}

/// The device's locks happened a minute ago (past `registry::RECHECK_GRACE`).
async fn a_minute_ago(case: &mut Case, dev: Uuid) {
    sqlx::query("UPDATE device SET revoked_at = now() - interval '1 minute' WHERE id = $1 AND revoked_at IS NOT NULL;")
        .bind(dev)
        .execute(case.db.tx().await.expect("tx"))
        .await
        .expect("revoked");
    sqlx::query("UPDATE audit SET at = now() - interval '1 minute' WHERE device_id = $1")
        .bind(dev)
        .execute(case.db.tx().await.expect("tx"))
        .await
        .expect("audit");
    case.db.commit().await.expect("commit");
}

async fn round(case: &Case, nas: &FakeDisconnector) -> recheck::RecheckReport {
    recheck::round(&case.url, nas, 300, EVERY).await.expect("round")
}

async fn entry(case: &mut Case, sid: &str) -> (i64, Option<String>, Option<String>) {
    let row: Option<(i32, Option<String>, Option<String>)> =
        sqlx::query_as("SELECT tries, last_result, settled FROM disconnect_recheck WHERE acct_session_id = $1")
            .bind(sid)
            .fetch_optional(case.db.tx().await.expect("tx"))
            .await
            .expect("entry");
    case.db.commit().await.expect("commit");
    row.map(|(t, r, s)| (i64::from(t), r, s)).unwrap_or((0, None, None))
}

async fn due_now(case: &mut Case) {
    sqlx::query("UPDATE disconnect_recheck SET next_at = now() - interval '1 second'")
        .execute(case.db.tx().await.expect("tx"))
        .await
        .expect("due");
    case.db.commit().await.expect("commit");
}

#[tokio::test]
async fn test_a_lost_disconnect_of_a_revocation_is_sent_again() {
    let admin = need_db!();
    let mut case = Case::new(&admin).await;
    let dev = device(&mut case, "lost").await;
    live_session(&mut case, dev, "5E2F0001", "AA-BB-CC-DD-EE-11", "30").await;
    // the revocation's own Disconnect is lost
    let nas = FakeDisconnector::new(DisconnectResult::Timeout);
    let results = actions::revoke_now(&mut case.db, dev, "lost", &nas).await.expect("revoke");
    assert!(results.iter().all(|r| *r == DisconnectResult::Timeout), "{results:?}");
    // within the grace the reconciliation leaves it to the revocation
    nas.answer(DisconnectResult::Ack);
    nas.clear();
    assert_eq!(round(&case, &nas).await.sent, 0);
    a_minute_ago(&mut case, dev).await;
    let report = round(&case, &nas).await;
    assert_eq!((report.live, report.sent, report.counts.get("ack").copied()), (1, 1, Some(1)));
    let sent = nas.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(
        (sent[0].nas_ip.as_str(), sent[0].calling_station.as_str(), sent[0].acct_session_id.as_str()),
        (NAS, "AA-BB-CC-DD-EE-11", "5E2F0001"),
        "the one session, by Acct-Session-Id"
    );
    assert_eq!(entry(&mut case, "5E2F0001").await, (1, Some("ack".into()), Some("ack".into())));
    assert_eq!(case.audit(dev).await.last().cloned(), Some(("recheck".to_string(), "disconnect:ack".to_string())));
    // settled: the next rounds send nothing while the access point does not report it again
    nas.clear();
    round(&case, &nas).await;
    assert!(nas.sent().is_empty());
    // the job record and its running totals (the portal's netportal_disconnect_rechecks_total)
    let jobs = registry::job_status(&mut case.db).await.expect("jobs");
    case.db.commit().await.expect("commit");
    let job = jobs.into_iter().find(|j| j.name == recheck::JOB).expect("job");
    assert!(job.last_success.is_some() && job.last_error.is_none());
    assert_eq!(job.cursor.0["totals"]["ack"], 1);
    assert_eq!(job.cursor.0["totals"]["timeout"], 0);
    // the access point reports it again after the ACK: tried again
    sqlx::query("UPDATE disconnect_recheck SET settled_at = now() - interval '5 minutes'")
        .execute(case.db.tx().await.expect("tx"))
        .await
        .expect("age");
    case.db.commit().await.expect("commit");
    round(&case, &nas).await;
    assert_eq!(nas.sent().len(), 1);
    assert_eq!(entry(&mut case, "5E2F0001").await.0, 2);
}

#[tokio::test]
async fn test_no_such_session_settles_it_for_good() {
    let admin = need_db!();
    let mut case = Case::new(&admin).await;
    let dev = device(&mut case, "stale").await;
    live_session(&mut case, dev, "5E2F0002", "AA-BB-CC-DD-EE-12", "30").await;
    let nas = FakeDisconnector::new(DisconnectResult::Ack);
    actions::revoke_now(&mut case.db, dev, "stale", &nas).await.expect("revoke");
    a_minute_ago(&mut case, dev).await;
    // the access point lost the session without a Stop: NAK 503
    nas.answer(DisconnectResult::NotFound);
    nas.clear();
    let report = round(&case, &nas).await;
    assert_eq!((report.sent, report.counts.get("not_found").copied()), (1, Some(1)));
    assert_eq!(entry(&mut case, "5E2F0002").await, (1, Some("not_found".into()), Some("not_found".into())));
    // never asked again, even when it looks due and the access point still reports it
    for _ in 0..3 {
        due_now(&mut case).await;
        sqlx::query("UPDATE disconnect_recheck SET settled_at = now() - interval '5 minutes'")
            .execute(case.db.tx().await.expect("tx"))
            .await
            .expect("age");
        case.db.commit().await.expect("commit");
        round(&case, &nas).await;
    }
    assert_eq!(nas.sent().len(), 1);
    assert_eq!(
        case.audit(dev).await.last().cloned(),
        Some(("recheck".to_string(), "disconnect:not-found".to_string()))
    );
}

#[tokio::test]
async fn test_refusals_back_off_and_are_given_up() {
    let admin = need_db!();
    let mut case = Case::new(&admin).await;
    let dev = device(&mut case, "refuse").await;
    live_session(&mut case, dev, "5E2F0003", "AA-BB-CC-DD-EE-13", "30").await;
    let nas = FakeDisconnector::new(DisconnectResult::Nak);
    actions::revoke_now(&mut case.db, dev, "refuse", &nas).await.expect("revoke");
    a_minute_ago(&mut case, dev).await;
    nas.clear();
    round(&case, &nas).await;
    assert_eq!(entry(&mut case, "5E2F0003").await, (1, Some("nak".into()), None));
    // the backoff: not again before its time
    round(&case, &nas).await;
    assert_eq!(nas.sent().len(), 1);
    let next: f64 =
        case.count("SELECT round(extract(epoch FROM next_at - last_at))::bigint FROM disconnect_recheck").await as f64;
    assert_eq!(next, 30.0);
    nas.answer(DisconnectResult::Timeout);
    due_now(&mut case).await;
    round(&case, &nas).await;
    assert_eq!(entry(&mut case, "5E2F0003").await, (2, Some("timeout".into()), None));
    let next = case.count("SELECT round(extract(epoch FROM next_at - last_at))::bigint FROM disconnect_recheck").await;
    assert_eq!(next, 60, "doubled");
    // the cap: the last try gives it up, and nothing is sent after that
    for _ in 3..=MAX_TRIES {
        due_now(&mut case).await;
        round(&case, &nas).await;
    }
    assert_eq!(
        entry(&mut case, "5E2F0003").await,
        (i64::from(MAX_TRIES), Some("timeout".into()), Some("given_up".into()))
    );
    due_now(&mut case).await;
    let report = round(&case, &nas).await;
    assert_eq!(report.sent, 0);
    assert_eq!(nas.sent().len(), MAX_TRIES as usize);
    // still live in the accounting after every try: the alert's gauge counts it
    assert_eq!(registry::locked_live_counts(&mut case.db, 300).await.expect("counts")[0], ("revoked", 1));
    case.db.commit().await.expect("commit");
    let jobs = registry::job_status(&mut case.db).await.expect("jobs");
    case.db.commit().await.expect("commit");
    let job = jobs.into_iter().find(|j| j.name == recheck::JOB).expect("job");
    assert_eq!(job.cursor.0["totals"]["given_up"], 1);
    assert_eq!(job.cursor.0["totals"]["nak"], 1);
    assert_eq!(job.cursor.0["totals"]["timeout"], i64::from(MAX_TRIES) - 1);
}

#[tokio::test]
async fn test_a_session_that_ends_settles_as_stale() {
    let admin = need_db!();
    let mut case = Case::new(&admin).await;
    let dev = device(&mut case, "ends").await;
    live_session(&mut case, dev, "5E2F0004", "AA-BB-CC-DD-EE-14", "30").await;
    let nas = FakeDisconnector::new(DisconnectResult::Timeout);
    actions::revoke_now(&mut case.db, dev, "ends", &nas).await.expect("revoke");
    a_minute_ago(&mut case, dev).await;
    round(&case, &nas).await;
    assert_eq!(entry(&mut case, "5E2F0004").await.2, None);
    // the access point's Stop arrives (or its updates stop): settled, nothing sent
    sqlx::query("UPDATE radius_acct SET updated = now() - interval '11 minutes' WHERE acct_session_id = '5E2F0004'")
        .execute(case.db.tx().await.expect("tx"))
        .await
        .expect("quiet");
    case.db.commit().await.expect("commit");
    nas.clear();
    due_now(&mut case).await;
    let report = round(&case, &nas).await;
    assert_eq!((report.live, report.sent, report.counts.get("settled_stale").copied()), (0, 0, Some(1)));
    assert_eq!(entry(&mut case, "5E2F0004").await.2.as_deref(), Some("stale"));
}

#[tokio::test]
async fn test_a_policy_move_whose_disconnect_failed() {
    // the device moved to the guests' VLAN, its session still in VLAN 30
    let admin = need_db!();
    let mut case = Case::new(&admin).await;
    let dev = device(&mut case, "moves").await;
    live_session(&mut case, dev, "5E2F0005", "AA-BB-CC-DD-EE-15", "30").await;
    let other = device(&mut case, "stays").await;
    live_session(&mut case, other, "5E2F0006", "AA-BB-CC-DD-EE-16", "30").await;
    let nas = FakeDisconnector::new(DisconnectResult::Error);
    let moved = actions::apply_policy(&mut case.db, "moves", "guests", "offboarding", &nas).await.expect("move");
    assert_eq!(moved.len(), 1);
    assert!(moved[0].1.iter().all(|r| !r.confirmed()));
    a_minute_ago(&mut case, dev).await;
    nas.answer(DisconnectResult::Ack);
    nas.clear();
    let report = round(&case, &nas).await;
    assert_eq!((report.live, report.sent), (1, 1));
    assert_eq!(nas.sent()[0].acct_session_id, "5E2F0005");
    // the device reconnects into its new VLAN: that session is not touched
    live_session(&mut case, dev, "5E2F0007", "AA-BB-CC-DD-EE-15", "50").await;
    nas.clear();
    let report = round(&case, &nas).await;
    assert_eq!(report.sent, 0, "{:?}", nas.sent());
}

#[tokio::test]
async fn test_one_round_at_a_time() {
    let admin = need_db!();
    let case = Case::new(&admin).await;
    let mut other = PgConnection::connect(&case.url).await.expect("connect");
    let held: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock(hashtext($1))")
        .bind(recheck::LOCK_KEY)
        .fetch_one(&mut other)
        .await
        .expect("lock");
    assert!(held);
    let nas = FakeDisconnector::new(DisconnectResult::Ack);
    let result = recheck::round(&case.url, &nas, 300, EVERY).await;
    assert!(matches!(result, Err(OffboardError::Locked("disconnect_recheck"))), "{result:?}");
    assert_eq!(result.err().map(|e| e.to_string()).as_deref(), Some("another disconnect_recheck round is running"));
}
