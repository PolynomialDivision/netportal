//! The job rollup: per-minute Prometheus data (FakePrometheus) -> device_day / ap_day on
//! Europe/Berlin days (Python tests/test_collect_rollup.py DeviceDayTests, ApDayTests,
//! BackfillTests; DayTests is a unit test in src/days.rs). Needs `NETPORTAL_TEST_DATABASE_URL`.
//!
//! The windows come from the real view `device_mac_window`: the devices of the base case are
//! revoked, so their windows end 15 minutes after the last login (the rule of every window but a
//! device's current one); the current window's longer end has a test of its own.

mod common;
mod fakes;

use std::collections::BTreeMap;
use std::sync::Arc;

use common::{Case, ts};
use fakes::{FakePrometheus, labels, pts};
use netportal_collect::days::bounds;
use netportal_collect::incidents::{self as inc, FROZEN_S};
use netportal_collect::jobs;
use netportal_collect::rollup::{self, AP_SIGNALS, AP_STATIONS, AP_UTIL, HORIZON, ap_weak, device_queries};
use netportal_collect::scheduler::{Outcome, Stop, execute};
use netportal_core::config::CollectSettings;
use netportal_core::registry::{self, ApDay, DeviceDay};
use serde_json::{Value, json};
use time::macros::date;
use time::{Date, OffsetDateTime};
use uuid::Uuid;

const M1: &str = "02:11:22:33:44:55";
const AP_X: &str = "60:22:32:37:48:00";
const AP_Y: &str = "68:d7:9a:1c:61:46";
/// the end of summer time: 25 hours
const DAY: Date = date!(2026 - 10 - 25);

fn day_bounds() -> (i64, i64) {
    let tz = netportal_core::conventions::zone("Europe/Berlin").expect("zone");
    bounds(DAY, &tz).expect("bounds")
}

struct World {
    start: i64,
    end: i64,
    t0: i64,
    grid: Vec<i64>,
    ages: BTreeMap<i64, f64>,
    /// `{t: (uptime, ap name)}`
    presence: BTreeMap<i64, (f64, &'static str)>,
    info: Vec<(&'static str, &'static str, Vec<i64>)>,
    ap_uptime: Vec<(&'static str, BTreeMap<i64, f64>)>,
}

impl World {
    fn new() -> World {
        let (start, end) = day_bounds();
        let t0 = start + 3 * 3600;
        let grid: Vec<i64> = (start - FROZEN_S..=end - 60).step_by(60).collect();
        let ages = grid.iter().map(|t| (*t, if t0 + 600 <= *t && *t < t0 + 1200 { 900.0 } else { 30.0 })).collect();
        let presence = (t0..=t0 + 7200)
            .step_by(60)
            .map(|t| {
                let uptime = if t < t0 + 3000 { t - t0 } else { t - (t0 + 3000) };
                (t, (uptime as f64, if t < t0 + 1800 { "ap-x" } else { "ap-y" }))
            })
            .collect();
        let info = vec![
            ("ap-x", AP_X, grid.clone()),
            ("ap-y", AP_Y, grid.iter().copied().filter(|t| !(t0..t0 + 300).contains(t)).collect()),
        ];
        let ap_uptime = vec![
            (
                "ap-x",
                grid.iter().map(|t| (*t, if *t < t0 { 50_000 + t - start } else { t - t0 + 10 } as f64)).collect(),
            ),
            ("ap-y", grid.iter().map(|t| (*t, (90_000 + t - start) as f64)).collect()),
        ];
        World { start, end, t0, grid, ages, presence, info, ap_uptime }
    }

    fn load(&self, prom: &FakePrometheus, ssid: &str) {
        prom.range_series(rollup::AGE, vec![(labels(&[]), pts(self.ages.clone()))]);
        prom.range_series(
            inc::Q_AP_INFO,
            self.info
                .iter()
                .map(|(name, mac, ts)| (labels(&[("mac", mac), ("name", name)]), pts(ts.iter().map(|t| (*t, 1.0)))))
                .collect(),
        );
        prom.range_series(
            inc::Q_AP_UPTIME,
            self.ap_uptime.iter().map(|(n, p)| (labels(&[("name", n)]), pts(p.clone()))).collect(),
        );
        prom.range_series(inc::Q_SITE_DISCONNECTED, vec![(labels(&[]), pts(self.grid.iter().map(|t| (*t, 0.0))))]);
        let q: BTreeMap<&str, String> = device_queries(ssid, &[M1]).expect("queries").into_iter().collect();
        prom.range_series(
            &q["presence"],
            ["ap-x", "ap-y"]
                .iter()
                .map(|ap| {
                    let points = self.presence.iter().filter(|(_, (_, a))| a == ap).map(|(t, (up, _))| (*t, *up));
                    (labels(&[("mac", M1), ("ap_name", ap), ("radio", "na")]), pts(points))
                })
                .collect(),
        );
        for (name, value) in [
            ("signal", -60.0),
            ("snr", 30.0),
            ("health", 80.0),
            ("retry", 0.1),
            ("rx", 1000.0),
            ("tx", 10.0),
            ("link_rx", 300e6),
        ] {
            prom.range_series(&q[name], vec![(labels(&[("mac", M1)]), pts(self.presence.keys().map(|t| (*t, value))))]);
        }
        let day: Vec<i64> = (self.start..self.end).step_by(60).collect();
        let all = |v: f64| pts(day.iter().map(|t| (*t, v)));
        prom.range_series(AP_STATIONS, vec![(labels(&[("mac", AP_X)]), all(5.0))]);
        prom.range_series(
            AP_UTIL,
            vec![
                (labels(&[("mac", AP_X), ("radio", "ng")]), all(0.3)),
                (labels(&[("mac", AP_X), ("radio", "na")]), all(0.1)),
            ],
        );
        prom.range_series(&ap_weak(), vec![(labels(&[("ap_name", "ap-x")]), all(1.0))]);
        prom.range_series(AP_SIGNALS, vec![(labels(&[("ap_name", "ap-x")]), all(4.0))]);
        prom.vector(HORIZON, vec![(labels(&[]), Some((self.start + 60) as f64))]);
    }
}

struct T {
    case: Case,
    prom: FakePrometheus,
    settings: Arc<CollectSettings>,
    world: World,
    d1: Uuid,
    d2: Uuid,
    now: OffsetDateTime,
}

impl T {
    /// The phone M1 of d1 on the house network on DAY, two APs; d1 and d2 revoked unless
    /// `current`.
    async fn new(admin: &url::Url, current: bool) -> T {
        let mut case = Case::new(admin).await;
        let prom = FakePrometheus::start().await;
        let settings = case.settings(Some(&prom.url), None);
        let world = World::new();
        let d1 = case.device("alice", !current).await;
        let d2 = case.device("bob", true).await;
        let t0 = world.t0;
        case.window(d1, M1, ts(t0 - 600), ts(t0 + 3600)).await;
        case.auth(d1, ts(t0), true, 1).await;
        case.auth(d1, ts(world.start - 10), false, 1).await;
        let now = ts(world.end + 11 * 3600); // the next day, 10:00 local
        T { case, prom, settings, world, d1, d2, now }
    }

    async fn run_at(&mut self, now: OffsetDateTime) -> Value {
        self.world.load(&self.prom, "Scharni");
        let outcome = self.run_raw(now).await;
        assert_eq!(outcome, Outcome::Ok, "{:?}", self.case.job("rollup").await);
        self.cursor().await
    }

    async fn run_raw(&self, now: OffsetDateTime) -> Outcome {
        let job = jobs::by_name("rollup").expect("job");
        execute(&job, &self.settings, &Stop::new(), Some(now)).await
    }

    async fn cursor(&mut self) -> Value {
        self.case.job("rollup").await.map(|j| j.cursor.0).unwrap_or(Value::Null)
    }

    async fn device_day(&mut self, device: Uuid, day: Date) -> Option<DeviceDay> {
        let rows = registry::device_days(&mut self.case.db, device, day, day).await.expect("device_days");
        self.case.db.commit().await.expect("commit");
        rows.into_iter().next()
    }

    async fn ap_day(&mut self, mac: &str, day: Date) -> Option<ApDay> {
        let rows = registry::ap_days(&mut self.case.db, day, day, Some(&[mac])).await.expect("ap_days");
        self.case.db.commit().await.expect("commit");
        rows.into_iter().next()
    }

    fn last_run_days(cursor: &Value) -> Vec<String> {
        cursor["last_run"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|d| d["day"].as_str().map(str::to_string))
            .collect()
    }
}

// --- DeviceDayTests -----------------------------------------------------------------------------------

#[tokio::test]
async fn test_device_day() {
    let admin = need_db!();
    let mut t = T::new(&admin, false).await;
    let now = t.now;
    t.run_at(now).await;
    let row = t.device_day(t.d1, DAY).await.expect("row");
    // in the window T0-10 min .. T0+60 min + 15 min; present from T0; 10 stale minutes
    assert_eq!((row.online_s, row.stale_s), (Some(66 * 60), Some(10 * 60)));
    assert_eq!(row.aps.0, json!({AP_X: 20 * 60, AP_Y: 46 * 60})); // by MAC, not by name
    assert_eq!(row.bands.0, json!({"5": 66 * 60}));
    assert_eq!((row.roams, row.reconnects), (Some(1), Some(1)));
    assert_eq!((row.signal_avg_dbm, row.signal_p10_dbm, row.snr_avg_db), (Some(-60.0), Some(-60.0), Some(30.0)));
    assert_eq!((row.health_avg, row.health_min, row.retry_ratio_avg), (Some(80.0), Some(80.0), Some(0.1)));
    assert_eq!((row.rx_bytes, row.tx_bytes, row.link_rx_avg_bps), (Some(66_000), Some(660), Some(300e6)));
    assert_eq!((row.macs, row.auth_ok, row.auth_failed, row.disconnects), (Some(1), Some(1), Some(0), None));
    assert!(t.device_day(t.d2, DAY).await.is_none()); // nothing of the day is d2's
}

#[tokio::test]
async fn test_disconnects_from_connection_events() {
    let admin = need_db!();
    let mut t = T::new(&admin, false).await;
    let t0 = t.world.t0;
    for (key, at, kind) in [("k1", t0 + 100, "disconnected"), ("k2", t0 + 200, "connected")] {
        sqlx::query(
            "INSERT INTO connection_event (at, mac, device_id, kind, source, dedup_key)
             VALUES ($1, $2::macaddr, $3, $4, 'unifi_syslog', $5)",
        )
        .bind(ts(at))
        .bind(M1)
        .bind(t.d1)
        .bind(kind)
        .bind(key)
        .execute(t.case.db.tx().await.expect("tx"))
        .await
        .expect("event");
    }
    t.case.db.commit().await.expect("commit");
    let now = t.now;
    t.run_at(now).await;
    assert_eq!(t.device_day(t.d1, DAY).await.expect("row").disconnects, Some(1));
}

#[tokio::test]
async fn test_the_window_end_is_the_registrys() {
    // the current window reaches 12 h 15 min past last_seen (device_mac_window, the rule the
    // pages use): online_s counts it the same way; repeated rejects count their tries
    let admin = need_db!();
    let mut t = T::new(&admin, true).await;
    let t0 = t.world.t0;
    t.case.auth(t.d1, ts(t0 + 60), false, 5).await;
    let now = t.now;
    t.run_at(now).await;
    let row = t.device_day(t.d1, DAY).await.expect("row");
    // present T0 .. T0+120 min, all in the window now; 10 of those minutes stale
    assert_eq!((row.online_s, row.stale_s), (Some(111 * 60), Some(10 * 60)));
    assert_eq!((row.auth_ok, row.auth_failed), (Some(1), Some(5)));
}

#[tokio::test]
async fn test_overlapping_windows_belong_to_nobody() {
    let admin = need_db!();
    let mut t = T::new(&admin, false).await;
    let t0 = t.world.t0;
    let d2 = t.d2;
    t.case.window(d2, M1, ts(t0 + 3000), ts(t0 + 3600)).await;
    let now = t.now;
    t.run_at(now).await;
    assert_eq!(t.device_day(t.d1, DAY).await.expect("d1").online_s, Some(40 * 60));
    let d2 = t.device_day(d2, DAY).await.expect("d2");
    assert_eq!((d2.online_s, d2.stale_s, d2.aps.0, d2.roams), (Some(0), Some(0), json!({}), None));
}

#[tokio::test]
async fn test_only_the_house_network() {
    let admin = need_db!();
    let mut t = T::new(&admin, false).await;
    let now = t.now;
    t.run_at(now).await;
    let asked: Vec<String> =
        t.prom.queries(Some("/api/v1/query_range")).into_iter().filter(|q| q.contains(M1)).collect();
    // only DAY (yesterday) has a window: each device query once
    assert_eq!(asked.len(), rollup::DEVICE_QUERIES.len());
    assert!(asked.iter().all(|q| q.contains(r#"essid="Scharni""#)), "{asked:?}");
    // another SSID's data (other query texts) is never read
    let other = Arc::new(CollectSettings { ssid: "Other".into(), ..(*t.settings).clone() });
    t.world.load(&t.prom, "Scharni");
    assert_eq!(execute(&jobs::by_name("rollup").expect("job"), &other, &Stop::new(), Some(now)).await, Outcome::Ok);
    assert_eq!(t.device_day(t.d1, DAY).await.expect("row").online_s, Some(0));
}

#[tokio::test]
async fn test_rerun_is_idempotent() {
    let admin = need_db!();
    let mut t = T::new(&admin, false).await;
    let now = t.now;
    t.run_at(now).await;
    let first = t.device_day(t.d1, DAY).await.expect("row");
    t.run_at(now).await;
    let second = t.device_day(t.d1, DAY).await.expect("row");
    assert_eq!(DeviceDay { computed_at: None, ..second }, DeviceDay { computed_at: None, ..first });
    assert_eq!(t.case.i64("SELECT count(*) FROM device_day").await, 1);
}

#[tokio::test]
async fn test_today_stops_at_now() {
    let admin = need_db!();
    let mut t = T::new(&admin, false).await;
    let now = t.world.t0 + 1800 + 30; // during DAY
    t.run_at(ts(now)).await;
    let row = t.device_day(t.d1, DAY).await.expect("row");
    assert_eq!(row.online_s, Some((30 - 10) * 60)); // T0 .. T0+29 min, without the stale 10
    let requests = t.prom.requests.lock().expect("requests").clone();
    let last = requests
        .iter()
        .filter(|(p, _)| p == "/api/v1/query_range")
        .filter_map(|(_, q)| q.get("end").and_then(|e| e.parse::<i64>().ok()))
        .max()
        .expect("queries");
    assert!(last <= now - 60);
}

// --- ApDayTests ----------------------------------------------------------------------------------------

#[tokio::test]
async fn test_ap_day() {
    let admin = need_db!();
    let mut t = T::new(&admin, false).await;
    let now = t.now;
    t.run_at(now).await;
    let x = t.ap_day(AP_X, DAY).await.expect("x");
    let y = t.ap_day(AP_Y, DAY).await.expect("y");
    assert_eq!((x.ap_name.as_deref(), x.clients_avg, x.clients_max), (Some("ap-x"), Some(5.0), Some(5)));
    assert_eq!(x.channel_util_avg.0, json!({"na": 0.1, "ng": 0.3}));
    assert_eq!(x.weak_client_share, Some(0.25));
    assert_eq!((x.restarts, x.down_s), (Some(1), Some(0)));
    assert_eq!((y.restarts, y.down_s, y.clients_avg), (Some(0), Some(5 * 60), None));
}

#[tokio::test]
async fn test_a_restart_in_the_first_minute_of_the_day_counts() {
    let admin = need_db!();
    let mut t = T::new(&admin, false).await;
    let start = t.world.start;
    // ap-y restarts at midnight: seen at the day's first minute against the minute before it
    t.world.ap_uptime[1].1 =
        t.world.grid.iter().map(|tt| (*tt, if *tt < start { 90_000.0 } else { (tt - start + 5) as f64 })).collect();
    let now = t.now;
    t.run_at(now).await;
    assert_eq!(t.ap_day(AP_Y, DAY).await.expect("y").restarts, Some(1));
}

// --- BackfillTests --------------------------------------------------------------------------------------

#[tokio::test]
async fn test_missing_days_back_to_the_horizon_bounded_per_run() {
    let admin = need_db!();
    let mut t = T::new(&admin, false).await;
    let horizon = t.world.start - 4 * 86400 + 3600; // 2026-10-21 local
    let now = t.now;
    let run = async |t: &mut T| {
        t.world.load(&t.prom, "Scharni");
        t.prom.vector(HORIZON, vec![(labels(&[]), Some(horizon as f64))]);
        assert_eq!(t.run_raw(now).await, Outcome::Ok);
        T::last_run_days(&t.cursor().await)
    };
    assert_eq!(run(&mut t).await, ["2026-10-26", "2026-10-25", "2026-10-24", "2026-10-23"]);
    assert_eq!(run(&mut t).await, ["2026-10-26", "2026-10-25", "2026-10-22", "2026-10-21"]);
    assert_eq!(run(&mut t).await, ["2026-10-26", "2026-10-25"]);
    let cursor = t.cursor().await;
    assert_eq!(cursor["horizon"], "2026-10-21");
    // the 24th has AP data in its last minutes (the world's series start 3 minutes before DAY)
    assert_eq!(cursor["empty_days"], json!(["2026-10-21", "2026-10-22", "2026-10-23"]));
}

#[tokio::test]
async fn test_a_device_day_lost_is_refilled() {
    let admin = need_db!();
    let mut t = T::new(&admin, false).await;
    let later = t.now + time::Duration::days(1); // DAY is now the day before yesterday
    let horizon = t.world.start - 86400;
    t.world.load(&t.prom, "Scharni");
    t.prom.vector(HORIZON, vec![(labels(&[]), Some(horizon as f64))]);
    assert_eq!(t.run_raw(later).await, Outcome::Ok);
    assert!(t.device_day(t.d1, DAY).await.is_some());
    let d1 = t.d1;
    t.case.exec(&format!("DELETE FROM device_day WHERE device_id = '{d1}'")).await;
    assert_eq!(t.run_raw(later).await, Outcome::Ok);
    let cursor = t.cursor().await;
    assert!(T::last_run_days(&cursor).contains(&"2026-10-25".to_string()));
    assert!(t.device_day(t.d1, DAY).await.is_some());
}

#[tokio::test]
async fn test_prometheus_down_fails_the_run() {
    let admin = need_db!();
    let mut t = T::new(&admin, false).await;
    t.prom.fail(None, 500);
    let now = t.now;
    assert_eq!(t.run_raw(now).await, Outcome::Failed);
    assert_eq!(t.case.i64("SELECT count(*) FROM device_day").await, 0);
}
