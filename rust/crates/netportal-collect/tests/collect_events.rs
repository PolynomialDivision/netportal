//! The job unifi_events: UniFi system log lines (as unpoller pushes them to Loki, FakeLoki) ->
//! connection_event (Python tests/test_collect_events.py JobTests; MappingTests are unit tests
//! in src/unifi_events.rs). Needs `NETPORTAL_TEST_DATABASE_URL`.

mod common;
mod fakes;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{Case, ts};
use fakes::{FakeLoki, Labels, labels};
use netportal_collect::scheduler::{Job, Outcome, Stop, execute};
use netportal_collect::unifi_events::{self, Limits, OVERLAP_NS};
use netportal_core::config::CollectSettings;
use serde_json::{Value, json};
use time::OffsetDateTime;
use uuid::Uuid;

const NOW: i64 = 1_792_929_600; // 2026-10-25 12:00 UTC
const NS: i64 = 1_000_000_000;
const PHONE: &str = "02:11:22:33:44:55";
const LAPTOP: &str = "a4:83:e7:00:00:01";
const STRANGER: &str = "3c:22:fb:99:88:77";
const AP_A: (&str, &str) = ("60:22:32:37:48:00", "ap-scharni-2-corner");
const AP_B: (&str, &str) = ("68:d7:9a:1c:61:46", "ap-scharni-4-corner");

fn stream() -> Labels {
    labels(&[
        ("application", "unifi_system_log"),
        ("job", "unpoller"),
        ("site_name", "Default (default)"),
        ("source", "https://unifi.scharni.org"),
        ("category", "CLIENT_DEVICES"),
        ("severity", "LOW"),
    ])
}

fn ms(minutes_ago: i64) -> i64 {
    (NOW - minutes_ago * 60) * 1000
}

/// A line as unpoller writes it.
fn entry(
    (key, id): (&str, &str),
    mac: &str,
    minutes_ago: i64,
    ap: Option<(&str, &str)>,
    from: Option<(&str, &str)>,
    wlan: Option<&str>,
    message: &str,
) -> String {
    let client_id = if mac == LAPTOP { mac.to_uppercase().replace(':', "-") } else { mac.to_string() };
    let mut params = serde_json::Map::new();
    params.insert(
        "CLIENT".into(),
        json!({"id": client_id, "name": "Nicks Phone", "hostname": "nicks-phone", "ip": "10.0.30.140"}),
    );
    if let Some(ap) = ap {
        let key = if from.is_some() { "DEVICE_TO" } else { "DEVICE" };
        params.insert(key.into(), json!({"id": ap.0, "name": ap.1, "model": "UAL6"}));
    }
    if let Some(from) = from {
        params.insert("DEVICE_FROM".into(), json!({"id": from.0, "name": from.1}));
    }
    if let Some(wlan) = wlan {
        params.insert("WLAN".into(), json!({"id": "65f0aa", "name": wlan}));
    }
    json!({
        "category": "CLIENT_DEVICES", "event": key.replace("WIRELESS_", ""), "id": id, "key": key,
        "message": message, "parameters": params, "severity": "LOW", "show_on_dashboard": false,
        "status": "", "subcategory": "WIFI", "target": "", "timestamp": ms(minutes_ago),
        "title_raw": key.replace('_', " "), "type": "CLIENT", "site_name": "Default (default)",
        "source_name": "https://unifi.scharni.org",
    })
    .to_string()
}

fn connect(mac: &str, minutes_ago: i64, id: &str) -> String {
    entry(("WIRELESS_CLIENT_CONNECTED", id), mac, minutes_ago, Some(AP_A), None, Some("Scharni"), "")
}

fn lines() -> Vec<String> {
    vec![
        entry(("WIRELESS_CLIENT_CONNECTED", "6720aa01"), PHONE, 30, Some(AP_A), None, Some("Scharni"),
              "Nicks Phone connected to Scharni on ap-scharni-2-corner. Connection Info: Ch. 36 (5 GHz, 80 MHz), -61 dBm"),
        entry(("WIRELESS_CLIENT_ROAMED", "6720aa02"), PHONE, 20, Some(AP_B), Some(AP_A), Some("Scharni"),
              "Nicks Phone roamed from ap-scharni-2-corner to ap-scharni-4-corner. Ch. 6 (2.4 GHz), -70 dBm"),
        entry(("WIRELESS_CLIENT_DISCONNECTED", "6720aa03"), PHONE, 10, Some(AP_B), None, None,
              "Nicks Phone disconnected from Scharni. Connected for 1h 2m 3s."),
        entry(("CLIENT_BLOCKED_BY_POLICY", "6720aa04"), PHONE, 9, Some(AP_A), None, Some("Scharni"), "something new"),
        entry(("WIRELESS_CLIENT_CONNECTED", "6720aa05"), LAPTOP, 8, Some(AP_B), None, Some("Scharni"), ""),
        entry(("WIRELESS_CLIENT_CONNECTED", "6720aa06"), STRANGER, 7, Some(AP_A), None, Some("Brantsovsky"), ""),
        entry(("WIRELESS_CLIENT_DISCONNECTED", "6720aa07"), STRANGER, 6, Some(AP_A), None, None, ""),
        json!({"key": "WIRELESS_CLIENT_CONNECTED", "id": "6720aa08", "parameters": {"WLAN": {"name": "Scharni"}}, "timestamp": ms(5)})
            .to_string(),
        "garbage".to_string(),
    ]
}

struct World {
    case: Case,
    loki: FakeLoki,
    settings: Arc<CollectSettings>,
    phone: Uuid,
}

async fn world(admin: &url::Url) -> World {
    let mut case = Case::new(admin).await;
    let loki = FakeLoki::start().await;
    let settings = case.settings(None, Some(&loki.url));
    // the phone's device has a window (it logged in): its entries without WLAN count too
    let phone = case.device("alice", false).await;
    case.window(phone, PHONE, ts(NOW - 2 * 3600), ts(NOW)).await;
    for line in lines() {
        let at = serde_json::from_str::<Value>(&line).ok().and_then(|v| v["timestamp"].as_i64()).unwrap_or(ms(4));
        loki.push(&stream(), at * 1_000_000, &line);
    }
    let mut other = stream();
    other.insert("category".into(), "UNIFI_DEVICES".into());
    loki.push(
        &other,
        ms(3) * 1_000_000,
        &entry(("DEVICE_RESTARTED", "6720aa09"), PHONE, 3, Some(AP_A), None, Some("Scharni"), ""),
    );
    World { case, loki, settings, phone }
}

/// The limits of the tests: no cursor reads from a day back (one window).
fn limits() -> Limits {
    Limits { first_run_ns: 86400 * NS, ..Limits::default() }
}

/// The job with these limits; the number of commits of its last run lands in `commits`.
fn job(limits: Limits, commits: Arc<Mutex<u64>>) -> Job {
    Job::new(unifi_events::NAME, Duration::from_secs(120), Duration::from_secs(60), move |ctx| {
        let commits = commits.clone();
        Box::pin(async move {
            let before = ctx.db.commits();
            let result = unifi_events::run_with(ctx, limits).await;
            if let Ok(mut c) = commits.lock() {
                *c = ctx.db.commits() - before;
            }
            result
        })
    })
}

impl World {
    async fn run(&self, limits: Limits, now: i64) -> Outcome {
        execute(&job(limits, Arc::default()), &self.settings, &Stop::new(), Some(ts(now))).await
    }

    async fn events(&mut self) -> Vec<(OffsetDateTime, String, String, Option<Uuid>)> {
        let rows = sqlx::query_as("SELECT at, kind, mac::text, device_id FROM connection_event ORDER BY at")
            .fetch_all(self.case.db.tx().await.expect("tx"))
            .await
            .expect("events");
        self.case.db.commit().await.expect("commit");
        rows
    }

    async fn cursor(&mut self) -> Value {
        self.case.job(unifi_events::NAME).await.map(|j| j.cursor.0).unwrap_or(Value::Null)
    }
}

#[tokio::test]
async fn test_ingest() {
    let admin = need_db!();
    let mut w = world(&admin).await;
    assert_eq!(w.run(limits(), NOW).await, Outcome::Ok);
    let events = w.events().await;
    let kinds: Vec<(&str, &str)> = events.iter().map(|e| (e.1.as_str(), e.2.as_str())).collect();
    assert_eq!(
        kinds,
        [("connected", PHONE), ("roamed", PHONE), ("disconnected", PHONE), ("other", PHONE), ("connected", LAPTOP)]
    );
    let devices: Vec<Option<Uuid>> = events.iter().map(|e| e.3).collect();
    assert_eq!(devices, [Some(w.phone), Some(w.phone), Some(w.phone), Some(w.phone), None]);
    let cursor = w.cursor().await;
    assert_eq!(cursor["until_ns"], NOW * NS);
    assert!(cursor.get("paging").is_none());
    assert_eq!(cursor["last_run"]["inserted"], 5);
    assert_eq!(cursor["last_run"]["read"], 9);
    assert_eq!(cursor["last_run"]["skipped"], json!({"other_network": 2, "no_client_mac": 1, "malformed": 1}));
    let query = w.loki.request(0);
    assert_eq!(query["query"], r#"{application="unifi_system_log",category="CLIENT_DEVICES"}"#);
    assert_eq!(query["direction"], "forward");
    // no cursor yet: from Loki's retention (here a day)
    assert_eq!(query["start"].parse::<i64>().ok(), Some(NOW * NS - 86400 * NS));
    // the detail is stored without the client's names
    let detail: Value =
        sqlx::query_scalar("SELECT detail FROM connection_event WHERE dedup_key = 'unifi_syslog:id:6720aa01'")
            .fetch_one(w.case.db.tx().await.expect("tx"))
            .await
            .expect("detail");
    assert_eq!(detail["parameters"]["CLIENT"], json!({"ip": "10.0.30.140"}));
    assert!(!detail.to_string().contains("Nicks Phone"));
}

#[tokio::test]
async fn test_the_registered_job_reads_from_the_retention() {
    let admin = need_db!();
    let w = world(&admin).await;
    let job = netportal_collect::jobs::by_name("unifi_events").expect("job");
    assert_eq!(execute(&job, &w.settings, &Stop::new(), Some(ts(NOW))).await, Outcome::Ok);
    assert_eq!(w.loki.request(0)["start"].parse::<i64>().ok(), Some(NOW * NS - unifi_events::FIRST_RUN_NS));
}

#[tokio::test]
async fn test_overlapping_windows_do_not_duplicate() {
    let admin = need_db!();
    let mut w = world(&admin).await;
    w.run(limits(), NOW).await;
    w.loki.push(&stream(), ms(-1) * 1_000_000, &connect(PHONE, -1, "6720aa10"));
    assert_eq!(w.run(limits(), NOW + 120).await, Outcome::Ok);
    assert_eq!(w.events().await.len(), 6);
    assert_eq!(w.loki.last_request()["start"].parse::<i64>().ok(), Some(NOW * NS - OVERLAP_NS));
    assert_eq!(w.cursor().await["last_run"]["inserted"], 1);
}

#[tokio::test]
async fn test_paging_with_equal_timestamps() {
    let admin = need_db!();
    let mut w = world(&admin).await;
    for i in 0..5 {
        w.loki.push(&stream(), ms(2) * 1_000_000, &connect(PHONE, 2, &format!("same{i:02}")));
    }
    assert_eq!(w.run(Limits { page_limit: 2, ..limits() }, NOW).await, Outcome::Ok);
    assert_eq!(w.events().await.len(), 10);
    assert!(w.loki.request_count() > 5);
    assert!(w.cursor().await.get("paging").is_none());
}

#[tokio::test]
async fn test_page_limit_per_run_continues_next_time() {
    let admin = need_db!();
    let mut w = world(&admin).await;
    let small = Limits { page_limit: 2, max_pages: 2, ..limits() };
    w.run(small, NOW).await;
    let cursor = w.cursor().await;
    let until = cursor["until_ns"].as_i64().expect("until_ns");
    assert!(until < NOW * NS);
    assert_eq!(cursor["paging"], true);
    let asked = w.loki.request_count();
    w.run(small, NOW).await;
    // stopped inside its range: the next run goes on exactly there (no overlap), so paging moves
    // forward however many entries the overlap would hold
    assert_eq!(w.loki.request(asked)["start"].parse::<i64>().ok(), Some(until));
    for _ in 0..6 {
        w.run(small, NOW).await;
    }
    assert_eq!(w.events().await.len(), 5);
    for _ in 0..10 {
        if w.cursor().await.get("paging").is_none() {
            break;
        }
        w.run(small, NOW).await;
    }
    assert!(w.cursor().await.get("paging").is_none()); // read to the end at last
}

#[tokio::test]
async fn test_a_line_arriving_late_is_read_by_the_next_run() {
    // unpoller pushes up to 8 minutes back after an outage (and every 2 minutes): an entry 10
    // minutes old that arrives after a run's end is still within the next run's overlap
    let admin = need_db!();
    let mut w = world(&admin).await;
    assert_eq!(w.run(limits(), NOW).await, Outcome::Ok);
    assert_eq!(w.cursor().await["until_ns"], NOW * NS);
    w.loki.push(&stream(), ms(10) * 1_000_000, &connect(PHONE, 10, "6720aa11"));
    assert_eq!(w.run(limits(), NOW + 120).await, Outcome::Ok);
    assert_eq!(w.cursor().await["last_run"]["inserted"], 1);
    const { assert!(OVERLAP_NS >= 15 * 60 * NS) };
}

#[tokio::test]
async fn test_commits_in_small_batches() {
    // resolved events extend device_mac rows that every RADIUS login updates too: committed
    // every batch of rows, the row locks are held briefly
    let admin = need_db!();
    let mut w = world(&admin).await;
    let commits: Arc<Mutex<u64>> = Arc::default();
    let job = job(Limits { batch: 2, ..limits() }, commits.clone());
    assert_eq!(execute(&job, &w.settings, &Stop::new(), Some(ts(NOW))).await, Outcome::Ok);
    assert_eq!(w.events().await.len(), 5);
    assert!(*commits.lock().expect("commits") >= 3); // 2 + 2 + 1 rows (the page's own commit has nothing left)
}

#[tokio::test]
async fn test_long_pause_is_caught_up_a_week_per_run() {
    let admin = need_db!();
    let mut w = world(&admin).await;
    let until = (NOW - 10 * 86400) * NS;
    w.case.exec(&format!(r#"INSERT INTO job (name, cursor) VALUES ('unifi_events', '{{"until_ns": {until}}}')"#)).await;
    let month = Limits { first_run_ns: 30 * 86400 * NS, ..Limits::default() };
    w.run(month, NOW).await;
    assert_eq!(w.cursor().await["until_ns"], (NOW - 3 * 86400) * NS - OVERLAP_NS);
    assert!(w.events().await.is_empty());
    w.run(month, NOW).await;
    assert_eq!(w.events().await.len(), 5);
}

#[tokio::test]
async fn test_loki_down_is_recorded_and_the_cursor_kept() {
    let admin = need_db!();
    let mut w = world(&admin).await;
    w.case.exec(r#"INSERT INTO job (name, cursor) VALUES ('unifi_events', '{"until_ns": 5}')"#).await;
    w.loki.fail(502);
    assert_eq!(w.run(limits(), NOW).await, Outcome::Failed);
    let row = w.case.job(unifi_events::NAME).await.expect("row");
    assert_eq!(row.last_error.as_deref(), Some("source: /loki/api/v1/query_range HTTP 502"));
    assert_eq!(row.cursor.0, json!({"until_ns": 5}));
    assert!(w.events().await.is_empty());
}

#[tokio::test]
async fn test_loki_not_configured() {
    let admin = need_db!();
    let mut case = Case::new(&admin).await;
    let settings = case.settings(None, None);
    assert_eq!(execute(&job(limits(), Arc::default()), &settings, &Stop::new(), Some(ts(NOW))).await, Outcome::Failed);
    let error = case.job(unifi_events::NAME).await.and_then(|j| j.last_error);
    assert_eq!(error.as_deref(), Some("source: NETPORTAL_LOKI_URL is not set"));
}
