//! The telemetry over the real registry (`Store` for `netportal_core::Db`, the schema of
//! `rust/migrations`): windows, conflicts, presence evidence, history events and rollups, the
//! admin overview's sections.
//!
//! Needs `NETPORTAL_TEST_DATABASE_URL` (a superuser's URL, `eval "$(tools/test-db.sh)"`); without
//! it every test is skipped with a message. Each test makes its own database.

use std::sync::LazyLock;

use netportal_core::Db;
use netportal_core::config::Policy;
use netportal_core::conventions;
use netportal_core::registry::{self, DeviceRow};
use netportal_telemetry::telemetry::Telemetry;
use netportal_telemetry::telemetry::admin;
use netportal_telemetry::telemetry::history::{self, HistoryOptions, Range};
use netportal_telemetry::telemetry::identity;
use netportal_telemetry::telemetry::live::{self, DashboardOptions};
use sqlx::{Connection, Executor, PgConnection};
use tokio::sync::Mutex;
use uuid::Uuid;

/// Schema setups of concurrent tests run one at a time (the grants are cluster-wide).
static INIT: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

const MAC: &str = "02:00:00:00:00:0a";
const SSID: &str = "Example";

fn admin_url() -> Option<String> {
    std::env::var("NETPORTAL_TEST_DATABASE_URL").ok().filter(|u| !u.is_empty())
}

macro_rules! need_db {
    () => {
        match admin_url() {
            Some(url) => url,
            None => {
                eprintln!("skipped: NETPORTAL_TEST_DATABASE_URL is not set (eval \"$(rust/tools/test-db.sh)\")");
                return;
            }
        }
    };
}

/// The URL of another database on the same server.
fn with_database(url: &str, name: &str) -> String {
    let (base, query) = url.split_once('?').map_or((url, None), |(b, q)| (b, Some(q)));
    let base = base.rsplit_once('/').map_or(base, |(b, _)| b);
    match query {
        Some(q) => format!("{base}/{name}?{q}"),
        None => format!("{base}/{name}"),
    }
}

async fn fresh(admin: &str) -> Db {
    let name = format!("t_{}", &Uuid::new_v4().simple().to_string()[..12]);
    let mut conn = PgConnection::connect(admin).await.expect("connect as admin");
    conn.execute(sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))).await.expect("create database");
    let mut db = Db::connect(&with_database(admin, &name)).await.expect("connect");
    let policies = [Policy { name: "residents".into(), vlan: 30, groups: ["residents".to_string()].into() }];
    {
        let _one = INIT.lock().await;
        registry::init(&mut db, &policies).await.expect("init");
    }
    db
}

async fn exec(db: &mut Db, sql: &str) {
    db.tx().await.expect("tx").execute(sqlx::raw_sql(sqlx::AssertSqlSafe(sql.to_string()))).await.expect(sql);
}

/// A resident's device that logged in with MAC a minute ago (window, session, an open
/// accounting session started 10 minutes ago).
async fn device(db: &mut Db, owner: &str, name: &str, mac: &str) -> Uuid {
    registry::upsert_person(db, owner, owner, owner, false).await.expect("person");
    let id = registry::create_device(db, owner, name, "android", "residents").await.expect("device");
    exec(
        db,
        &format!(
            "INSERT INTO device_mac (device_id, mac, first_seen, last_seen, auth_count, randomized)
             VALUES ('{id}', '{mac}', now() - interval '1 day', now() - interval '1 minute', 3, true);
             INSERT INTO radius_session (device_id, nas_ip, calling_station, user_name, first_seen, updated)
             VALUES ('{id}', '10.0.10.27', upper(replace('{mac}', ':', '-')), 'anonymous@example.org',
                     now() - interval '1 day', now() - interval '1 minute');
             INSERT INTO radius_acct (nas_ip, acct_session_id, device_id, link, mac, ssid, started, updated)
             VALUES ('10.0.10.27', 's-{name}', '{id}', 'class', '{mac}', '{SSID}', now() - interval '10 minutes',
                     now() - interval '1 minute');"
        ),
    )
    .await;
    id
}

async fn row(db: &mut Db, id: Uuid) -> DeviceRow {
    registry::device(db, id, None).await.expect("device").expect("found")
}

fn now() -> f64 {
    conventions::unix(time::OffsetDateTime::now_utc())
}

#[tokio::test]
async fn test_the_dashboard_reads_the_registry() {
    let admin = need_db!();
    let mut db = fresh(&admin).await;
    let id = device(&mut db, "sub-resident", "phone", MAC).await;
    let r = row(&mut db, id).await;
    let t = Telemetry::new(None, SSID); // telemetry off: the registry's evidence decides
    let opts = DashboardOptions { interim_s: Some(300), ..DashboardOptions::default() };
    let payload = live::dashboard(&t.page(), &mut db, std::slice::from_ref(&r), &opts).await.expect("dashboard");
    let d = &payload.devices[0];
    assert_eq!(payload.telemetry, "off");
    assert_eq!((d.state, d.presence.confirmed_by, d.presence.reason), ("online", Some("radius_acct"), "acct_interim"));
    assert_eq!(d.mac.as_deref(), Some(MAC));
    assert_eq!(d.macs.len(), 1);
    assert!(d.macs[0].current);
    // the current window's end is the database's now: open
    let ids = identity::from_registry(&mut db, std::slice::from_ref(&r), now(), false, None).await.unwrap();
    assert_eq!(ids[&id].windows[0].end, None);
    assert!(ids[&id].live_bounds().contains_key(MAC));
}

/// Another owner's device on the same MAC now: the overlap's end is capped at the database's now
/// (the transaction's start, before the request's now) and still withholds the data.
#[tokio::test]
async fn test_a_conflict_now_withholds_over_the_real_view() {
    let admin = need_db!();
    let mut db = fresh(&admin).await;
    let mine = device(&mut db, "sub-resident", "phone", MAC).await;
    device(&mut db, "sub-other", "spoof", MAC).await;
    // last logins 20 minutes ago: both windows end at the database's now()
    exec(&mut db, "UPDATE device_mac SET last_seen = now() - interval '20 minutes'").await;
    let r = row(&mut db, mine).await;
    db.commit().await.unwrap();
    // a transaction that began a moment before the request's now
    registry::people(&mut db).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let t = Telemetry::new(None, SSID);
    let payload =
        live::dashboard(&t.page(), &mut db, std::slice::from_ref(&r), &DashboardOptions::default()).await.unwrap();
    let d = &payload.devices[0];
    assert_eq!((d.state, d.presence.reason), ("unknown", "mac_conflict"));
    let codes: Vec<&str> = d.diagnostics().iter().map(|f| f.code).collect();
    assert_eq!(codes, ["mac_conflict"]);
    let opts = DashboardOptions { admin: true, ..DashboardOptions::default() };
    let payload = live::dashboard(&t.page(), &mut db, std::slice::from_ref(&r), &opts).await.unwrap();
    assert_eq!(payload.devices[0].diagnostics()[0].params["owners"], serde_json::json!(1));
    let h = history::history(&t.page(), &mut db, &r, Range::H24, HistoryOptions::default()).await.unwrap();
    assert_eq!(h.withheld, Some("mac_conflict"));
}

#[tokio::test]
async fn test_history_events_and_rollups() {
    let admin = need_db!();
    let mut db = fresh(&admin).await;
    let id = device(&mut db, "sub-resident", "phone", MAC).await;
    exec(
        &mut db,
        &format!(
            "INSERT INTO radius_acct (nas_ip, acct_session_id, device_id, link, mac, ssid, started, updated, stopped,
                                      session_time_s, input_octets, output_octets, terminate_cause)
             VALUES ('10.0.10.27', 'old', '{id}', 'class', '{MAC}', '{SSID}', now() - interval '3 hours',
                     now() - interval '2 hours', now() - interval '2 hours', 3600, 1000, 9000, 'User-Request');
             INSERT INTO incident (kind, subject, started, ended, basis)
             VALUES ('internet_down', '', now() - interval '90 minutes', now() - interval '80 minutes', 'measured');
             INSERT INTO device_day (device_id, day, online_s, stale_s, signal_avg_dbm, rx_bytes)
             VALUES ('{id}', (now() AT TIME ZONE 'Europe/Berlin')::date - 1, 43200, 0, -61.26, 8640000000);"
        ),
    )
    .await;
    let r = row(&mut db, id).await;
    let t = Telemetry::new(None, SSID);
    let h = history::history(&t.page(), &mut db, &r, Range::H24, HistoryOptions::default()).await.unwrap();
    let kinds: Vec<&str> = h.timeline.iter().map(|e| e.kind).collect();
    assert_eq!(kinds, ["connected", "session_ended", "incident", "connected"], "{kinds:?}");
    assert_eq!(h.sources, ["incident", "radius_acct"]);
    assert_eq!(h.telemetry, "off");
    let tz = history::zone(Some("Europe/Berlin"));
    let opts = HistoryOptions { tz: Some(tz.clone()), ..HistoryOptions::default() };
    let y = history::history(&t.page(), &mut db, &r, Range::Y1, opts).await.unwrap();
    let today = history::local_day(y.end, &tz);
    let yesterday = history::local_midnight(today.checked_sub(jiff::Span::new().days(1)).unwrap(), &tz);
    let signal = y.series["signal_dbm"].iter().find(|(t, _)| *t == yesterday).and_then(|(_, v)| *v).map(|v| v.as_f64());
    assert_eq!(signal, Some(-61.3));
    assert!(y.sources.contains(&"device_day".to_string()));
}

#[tokio::test]
async fn test_the_admin_overview_over_the_registry() {
    let admin = need_db!();
    let mut db = fresh(&admin).await;
    let id = device(&mut db, "sub-resident", "phone", MAC).await;
    exec(
        &mut db,
        &format!(
            "INSERT INTO radius_auth (at, result, reason, device_id, mac) VALUES (now() - interval '5 minutes', 'reject',
                 'revoked', '{id}', '{MAC}');
             INSERT INTO incident (kind, subject, subject_name, started, basis)
             VALUES ('ap_down', '60:22:32:37:48:00', 'ap-scharni-2-corner', now() - interval '10 minutes', 'measured');"
        ),
    )
    .await;
    registry::job_begin(&mut db, "rollup").await.unwrap();
    registry::job_end(&mut db, "rollup", true, None, Some(1.5), None).await.unwrap();
    let t = Telemetry::new(None, SSID);
    let o = admin::overview(&t.page(), &mut db, now()).await;
    assert!(o.incidents.available && o.auth.available && o.jobs_available);
    assert_eq!(o.incidents.open.iter().map(|i| i.kind.as_str()).collect::<Vec<_>>(), ["ap_down"]);
    assert_eq!((o.auth.count, o.auth.devices), (1, 1));
    assert_eq!(o.auth.recent[0].device_name.as_deref(), Some("phone"));
    assert_eq!(
        o.jobs.iter().map(|j| (j.name.as_str(), j.ok)).collect::<Vec<_>>(),
        [("offboarding", true), ("rollup", true)]
    );
    let raw_row = row(&mut db, id).await;
    let ids = identity::from_registry(&mut db, std::slice::from_ref(&raw_row), now(), true, None).await.unwrap();
    let people = registry::people(&mut db).await.unwrap();
    let raw = admin::raw(&mut db, &raw_row, &ids[&id], now() - 86400.0, now(), &people, &history::zone(None), now())
        .await
        .unwrap();
    assert_eq!((raw.auth.len(), raw.acct.len(), raw.windows.len()), (1, 1, 1));
    assert_eq!(raw.auth[0].matched, "device");
}
