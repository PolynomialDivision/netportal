//! The job incidents: per-minute monitoring signals (FakePrometheus) -> incident rows, opened and
//! closed idempotently (Python tests/test_collect_incidents.py HouseTests, ApTests,
//! ApRecordTests, SwitchTests; ReconcileTests are unit tests in src/incidents.rs). Needs
//! `NETPORTAL_TEST_DATABASE_URL`.

mod common;
mod fakes;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use common::{Case, ts};
use fakes::{FakePrometheus, labels, pts};
use netportal_collect::incidents::{self as inc, AP_KNOWN, AP_UP_RECORD, AP_UPTIME_RECORD, radius_query};
use netportal_collect::jobs;
use netportal_collect::scheduler::{Outcome, Stop, execute};
use netportal_core::config::CollectSettings;
use serde_json::{Value, json};
use time::OffsetDateTime;

const T0: i64 = 1_792_929_600; // 2026-10-25 12:00 UTC (a minute boundary)
const AP1: (&str, &str) = ("60:22:32:37:48:00", "ap-scharni-2-corner");
const AP2: (&str, &str) = ("68:d7:9a:1c:61:46", "ap-scharni-4-corner");

fn at(minute: i64) -> i64 {
    T0 + 60 * minute
}

fn dt(unix: i64) -> OffsetDateTime {
    ts(unix)
}

const MINUTES: std::ops::RangeInclusive<i64> = -60..=60;

/// The house's signals per minute from -60 to +60 around T0, all fine by default.
struct World {
    values: BTreeMap<&'static str, BTreeMap<i64, f64>>,
    aps: Vec<(&'static str, &'static str)>,
    ap_present: BTreeMap<&'static str, BTreeSet<i64>>,
    uptime: BTreeMap<&'static str, BTreeMap<i64, f64>>,
    switches_icmp: BTreeMap<&'static str, BTreeMap<i64, f64>>,
    web_switches: BTreeMap<&'static str, BTreeMap<i64, f64>>,
}

const SIGNALS: [(&str, &str); 10] = [
    ("gateway", inc::Q_GATEWAY),
    ("internet", inc::Q_INTERNET),
    ("loss", inc::Q_LOSS),
    ("rtt", inc::Q_RTT),
    ("dns", inc::Q_DNS),
    ("unifi_up", inc::Q_UNIFI_UP),
    ("age", inc::Q_AGE),
    ("site_disconnected", inc::Q_SITE_DISCONNECTED),
    ("web_exporter", inc::Q_WEB_EXPORTER),
    ("cadvisor", inc::Q_CADVISOR),
];

impl World {
    fn new() -> World {
        let defaults = [
            ("gateway", 1.0),
            ("internet", 1.0),
            ("loss", 0.0),
            ("rtt", 5.0),
            ("dns", 1.0),
            ("unifi_up", 1.0),
            ("age", 12.0),
            ("site_disconnected", 0.0),
            ("web_exporter", 1.0),
            ("cadvisor", 1.0),
            ("radius", 1_792_900_000.0),
        ];
        let all = |v: f64| MINUTES.map(|m| (m, v)).collect::<BTreeMap<_, _>>();
        World {
            values: defaults.iter().map(|(n, v)| (*n, all(*v))).collect(),
            aps: vec![AP1, AP2],
            ap_present: [AP1.0, AP2.0].iter().map(|m| (*m, MINUTES.collect())).collect(),
            uptime: [AP1.0, AP2.0]
                .iter()
                .map(|m| (*m, MINUTES.map(|i| (i, 100_000.0 + 60.0 * i as f64)).collect()))
                .collect(),
            switches_icmp: BTreeMap::from([("sw-cellar", all(1.0))]),
            web_switches: BTreeMap::from([("sw-colbe-2", all(1.0))]),
        }
    }

    fn set(&mut self, name: &str, minutes: impl IntoIterator<Item = i64>, value: Option<f64>) {
        let series = self.values.get_mut(name).expect("signal");
        for m in minutes {
            match value {
                Some(v) => {
                    series.insert(m, v);
                }
                None => {
                    series.remove(&m);
                }
            }
        }
    }

    fn load(&self, prom: &FakePrometheus) {
        let p = |d: &BTreeMap<i64, f64>| pts(d.iter().map(|(m, v)| (at(*m), *v)));
        for (name, q) in SIGNALS {
            prom.range_series(q, vec![(labels(&[]), p(&self.values[name]))]);
        }
        prom.range_series(&radius_query("netaccess-radius"), vec![(labels(&[]), p(&self.values["radius"]))]);
        prom.range_series(
            inc::Q_AP_INFO,
            self.aps
                .iter()
                .map(|(mac, name)| {
                    (labels(&[("mac", mac), ("name", name)]), pts(self.ap_present[mac].iter().map(|m| (at(*m), 1.0))))
                })
                .collect(),
        );
        prom.range_series(
            inc::Q_AP_UPTIME,
            self.aps.iter().map(|(mac, name)| (labels(&[("name", name)]), p(&self.uptime[mac]))).collect(),
        );
        prom.vector(
            AP_KNOWN,
            self.aps.iter().map(|(mac, name)| (labels(&[("mac", mac), ("name", name)]), Some(1.0))).collect(),
        );
        prom.range_series(
            inc::Q_SWITCH_ICMP,
            self.switches_icmp.iter().map(|(k, v)| (labels(&[("switch", k)]), p(v))).collect(),
        );
        prom.range_series(
            inc::Q_WEB_SWITCH,
            self.web_switches.iter().map(|(k, v)| (labels(&[("switch", k)]), p(v))).collect(),
        );
        prom.range_series(
            inc::Q_WEB_SWITCH_BLOCKED,
            self.web_switches
                .iter()
                .map(|(k, v)| (labels(&[("switch", k)]), pts(v.keys().map(|m| (at(*m), 0.0)))))
                .collect(),
        );
    }
}

struct T {
    case: Case,
    prom: FakePrometheus,
    settings: Arc<CollectSettings>,
    world: World,
}

type Row = (String, String, OffsetDateTime, Option<OffsetDateTime>);

impl T {
    async fn new(admin: &url::Url) -> T {
        let case = Case::new(admin).await;
        let prom = FakePrometheus::start().await;
        let settings = case.settings(Some(&prom.url), None);
        T { case, prom, settings, world: World::new() }
    }

    async fn run_raw(&self, minute: i64) -> Outcome {
        let job = jobs::by_name("incidents").expect("job");
        execute(&job, &self.settings, &Stop::new(), Some(dt(at(minute) + 5))).await
    }

    async fn run_at(&mut self, minute: i64) {
        self.world.load(&self.prom);
        let outcome = self.run_raw(minute).await;
        assert_eq!(outcome, Outcome::Ok, "{:?}", self.case.job("incidents").await);
    }

    async fn rows(&mut self, kind: Option<&str>) -> Vec<Row> {
        let rows: Vec<Row> = sqlx::query_as("SELECT kind, subject, started, ended FROM incident ORDER BY id")
            .fetch_all(self.case.db.tx().await.expect("tx"))
            .await
            .expect("rows");
        self.case.db.commit().await.expect("commit");
        rows.into_iter().filter(|r| kind.is_none_or(|k| r.0 == k)).collect()
    }

    async fn first(&mut self) -> (Option<String>, String, Value) {
        let row: (Option<String>, String, Value) =
            sqlx::query_as("SELECT subject_name, basis, detail FROM incident ORDER BY id LIMIT 1")
                .fetch_one(self.case.db.tx().await.expect("tx"))
                .await
                .expect("row");
        self.case.db.commit().await.expect("commit");
        row
    }
}

fn row(kind: &str, subject: &str, started: i64, ended: Option<i64>) -> Row {
    (kind.into(), subject.into(), dt(started), ended.map(dt))
}

// --- HouseTests ------------------------------------------------------------------------------------

#[tokio::test]
async fn test_all_fine_opens_nothing() {
    let admin = need_db!();
    let mut t = T::new(&admin).await;
    t.run_at(0).await;
    assert_eq!(t.rows(None).await, []);
    assert_eq!(t.case.job("incidents").await.expect("job").cursor.0["evaluated_until"], at(0));
}

#[tokio::test]
async fn test_internet_down_opens_then_closes() {
    let admin = need_db!();
    let mut t = T::new(&admin).await;
    t.world.set("internet", -6..=60, Some(0.0));
    t.run_at(0).await;
    assert_eq!(t.rows(None).await, [row("internet_down", "", at(-6), None)]);
    let (name, basis, _) = t.first().await;
    assert_eq!((name, basis.as_str()), (None, "measured"));
    // the same minutes again: nothing new (idempotent)
    t.run_at(0).await;
    t.run_at(1).await;
    assert_eq!(t.rows(None).await.len(), 1);
    // back at minute 5; closed once the next run sees it stay up
    t.world.set("internet", 5..=60, Some(1.0));
    t.run_at(6).await;
    assert_eq!(t.rows(None).await[0].3, None); // 1 minute ok: not confirmed yet
    t.run_at(8).await;
    assert_eq!(t.rows(None).await, [row("internet_down", "", at(-6), Some(at(5)))]);
    t.run_at(10).await;
    assert_eq!(t.rows(None).await.len(), 1);
    assert_eq!(t.case.job("incidents").await.expect("job").cursor.0["last_run"], json!({"opened": 0, "closed": 0}));
}

#[tokio::test]
async fn test_short_blips_are_no_incident() {
    let admin = need_db!();
    let mut t = T::new(&admin).await;
    t.world.set("internet", [-5], Some(0.0));
    t.world.set("gateway", [-3], Some(0.0));
    t.run_at(0).await;
    assert_eq!(t.rows(None).await, []);
}

#[tokio::test]
async fn test_a_one_minute_success_does_not_split_an_outage() {
    let admin = need_db!();
    let mut t = T::new(&admin).await;
    t.world.set("internet", -12..=60, Some(0.0));
    t.world.set("internet", [-7], Some(1.0));
    t.run_at(0).await;
    assert_eq!(t.rows(None).await, [row("internet_down", "", at(-12), None)]);
}

#[tokio::test]
async fn test_router_down_hides_internet_and_dns() {
    let admin = need_db!();
    let mut t = T::new(&admin).await;
    for name in ["gateway", "internet", "dns"] {
        t.world.set(name, -8..=60, Some(0.0));
    }
    t.run_at(0).await;
    assert_eq!(t.rows(None).await, [row("router_down", "", at(-8), None)]);
}

#[tokio::test]
async fn test_degraded_and_dns() {
    let admin = need_db!();
    let mut t = T::new(&admin).await;
    t.world.set("loss", -10..=60, Some(0.2));
    t.world.set("dns", -9..=60, Some(0.0));
    t.run_at(0).await;
    let rows = t.rows(None).await;
    let started = |kind: &str| rows.iter().find(|r| r.0 == kind).map(|r| r.2);
    assert_eq!(started("internet_degraded"), Some(dt(at(-10))));
    assert_eq!(started("dns_down"), Some(dt(at(-9))));
    let detail: Value = sqlx::query_scalar("SELECT detail FROM incident WHERE kind = 'internet_degraded'")
        .fetch_one(t.case.db.tx().await.expect("tx"))
        .await
        .expect("detail");
    assert_eq!(detail, json!({"loss_ratio_max": 0.2, "rtt_ms_max": 5.0}));
}

#[tokio::test]
async fn test_degraded_below_five_minutes_is_nothing() {
    let admin = need_db!();
    let mut t = T::new(&admin).await;
    t.world.set("rtt", -3..=60, Some(250.0)); // 4 minutes up to now
    t.run_at(0).await;
    assert_eq!(t.rows(None).await, []);
}

#[tokio::test]
async fn test_stale_unifi_data() {
    let admin = need_db!();
    let mut t = T::new(&admin).await;
    t.world.set("age", -5..=60, Some(900.0));
    t.world.set("unifi_up", -3..=60, Some(0.0));
    t.run_at(0).await;
    assert_eq!(t.rows(None).await, [row("unifi_data_stale", "", at(-5), None)]);
}

#[tokio::test]
async fn test_radius_container_gone() {
    let admin = need_db!();
    let mut t = T::new(&admin).await;
    t.world.set("radius", -4..=60, None);
    t.run_at(0).await;
    assert_eq!(t.rows(None).await, [row("radius_down", "", at(-4), None)]);
}

#[tokio::test]
async fn test_cadvisor_down_says_nothing_about_radius() {
    let admin = need_db!();
    let mut t = T::new(&admin).await;
    t.world.set("radius", -4..=60, None);
    t.world.set("cadvisor", -4..=60, Some(0.0));
    t.run_at(0).await;
    assert_eq!(t.rows(None).await, []);
}

#[tokio::test]
async fn test_prometheus_failing_is_recorded() {
    let admin = need_db!();
    let mut t = T::new(&admin).await;
    t.prom.fail(None, 500);
    t.world.load(&t.prom);
    assert_eq!(t.run_raw(0).await, Outcome::Failed);
    let error = t.case.job("incidents").await.and_then(|j| j.last_error).unwrap_or_default();
    assert!(error.contains("HTTP 500"), "{error}");
    assert!(!error.contains("probe_success"), "no query in the error: {error}");
}

#[tokio::test]
async fn test_a_long_pause_is_evaluated_from_the_cursor() {
    let admin = need_db!();
    let mut t = T::new(&admin).await;
    t.run_at(-40).await;
    t.world.set("internet", -35..-25, Some(0.0)); // while the collector was away
    t.run_at(0).await;
    assert_eq!(t.rows(None).await, [row("internet_down", "", at(-35), Some(at(-25)))]);
}

// --- ApTests -----------------------------------------------------------------------------------------

#[tokio::test]
async fn test_ap_missing_while_data_is_fresh() {
    let admin = need_db!();
    let mut t = T::new(&admin).await;
    t.world.ap_present.get_mut(AP1.0).expect("ap").retain(|m| *m < -5);
    t.run_at(0).await;
    assert_eq!(t.rows(None).await, [row("ap_down", AP1.0, at(-5), None)]);
    let (name, _, detail) = t.first().await;
    assert_eq!((name.as_deref(), detail), (Some(AP1.1), json!({"signal": ["device_missing"]})));
}

#[tokio::test]
async fn test_ap_missing_while_unifi_is_stale_is_unifi_data_stale() {
    let admin = need_db!();
    let mut t = T::new(&admin).await;
    t.world.ap_present.get_mut(AP1.0).expect("ap").retain(|m| *m < -5);
    t.world.set("age", -5..=60, Some(900.0));
    t.run_at(0).await;
    let kinds: Vec<String> = t.rows(None).await.into_iter().map(|r| r.0).collect();
    assert_eq!(kinds, ["unifi_data_stale"]);
}

fn freeze(world: &mut World, mac: &str, from: i64) {
    let uptime = world.uptime.get_mut(mac).expect("ap");
    let frozen = uptime[&from];
    for m in from..=60 {
        uptime.insert(m, frozen);
    }
}

#[tokio::test]
async fn test_disconnected_ap_with_frozen_uptime() {
    let admin = need_db!();
    let mut t = T::new(&admin).await;
    freeze(&mut t.world, AP2.0, -8);
    t.world.set("site_disconnected", -6..=60, Some(1.0));
    t.run_at(0).await;
    // down once the uptime has not moved for 3 minutes (-8 .. -5) while the site counts one
    assert_eq!(t.rows(Some("ap_down")).await, [row("ap_down", AP2.0, at(-5), None)]);
    assert_eq!(t.first().await.2, json!({"signal": ["site_disconnected"]}));
}

#[tokio::test]
async fn test_frozen_uptime_alone_is_not_down() {
    let admin = need_db!();
    let mut t = T::new(&admin).await;
    freeze(&mut t.world, AP2.0, -8);
    t.run_at(0).await;
    assert_eq!(t.rows(None).await, []);
}

#[tokio::test]
async fn test_restart() {
    let admin = need_db!();
    let mut t = T::new(&admin).await;
    let uptime = t.world.uptime.get_mut(AP1.0).expect("ap");
    for m in -4..=60 {
        uptime.insert(m, 30.0 + 60.0 * (m + 4) as f64);
    }
    t.run_at(0).await;
    let restarts = t.rows(Some("ap_restarted")).await;
    // snapshot (minus its age) minus uptime; back at the snapshot
    assert_eq!(restarts, [row("ap_restarted", AP1.0, at(-4) - 12 - 30, Some(at(-4) - 12))]);
    t.run_at(1).await;
    t.run_at(2).await;
    assert_eq!(t.rows(Some("ap_restarted")).await.len(), 1);
}

// --- ApRecordTests (house-infra's records unifi_ap:up / unifi_ap:uptime:seconds, by ap_mac) -------

#[tokio::test]
async fn test_record_zero_is_down() {
    let admin = need_db!();
    let mut t = T::new(&admin).await;
    t.world.load(&t.prom);
    t.prom.range_series(
        AP_UP_RECORD,
        vec![(
            labels(&[("ap_mac", AP2.0), ("ap_name", AP2.1)]),
            pts(MINUTES.map(|m| (at(m), if m >= -5 { 0.0 } else { 1.0 }))),
        )],
    );
    assert_eq!(t.run_raw(0).await, Outcome::Ok);
    assert_eq!(t.rows(None).await, [row("ap_down", AP2.0, at(-5), None)]);
    assert_eq!(t.first().await.2, json!({"signal": ["unifi_ap_up"]}));
}

#[tokio::test]
async fn test_restart_from_the_record_alone() {
    let admin = need_db!();
    let mut t = T::new(&admin).await;
    t.world.load(&t.prom);
    t.prom.range_series(inc::Q_AP_UPTIME, vec![]); // no raw series (only the record)
    t.prom.range_series(
        AP_UPTIME_RECORD,
        vec![(
            labels(&[("ap_mac", AP1.0), ("ap_name", AP1.1)]),
            pts(MINUTES
                .map(|m| (at(m), if m < -3 { 500_000.0 + 60.0 * m as f64 } else { 20.0 + 60.0 * (m + 3) as f64 }))),
        )],
    );
    assert_eq!(t.run_raw(0).await, Outcome::Ok);
    let rows: Vec<(String, String, OffsetDateTime)> = t.rows(None).await.into_iter().map(|r| (r.0, r.1, r.2)).collect();
    assert_eq!(rows, [("ap_restarted".to_string(), AP1.0.to_string(), dt(at(-3) - 12 - 20))]);
    assert_eq!(t.first().await.0.as_deref(), Some(AP1.1));
}

// --- SwitchTests ---------------------------------------------------------------------------------------

#[tokio::test]
async fn test_icmp_switch_down() {
    let admin = need_db!();
    let mut t = T::new(&admin).await;
    for m in -4..=60 {
        t.world.switches_icmp.get_mut("sw-cellar").expect("switch").insert(m, 0.0);
    }
    t.run_at(0).await;
    assert_eq!(t.rows(None).await, [row("switch_down", "sw-cellar", at(-4), None)]);
    let (name, _, detail) = t.first().await;
    assert_eq!((name.as_deref(), detail), (Some("sw-cellar"), json!({"source": "switches_icmp"})));
}

#[tokio::test]
async fn test_web_switch_down_unless_the_exporter_is() {
    let admin = need_db!();
    let mut t = T::new(&admin).await;
    for m in -10..=60 {
        t.world.web_switches.get_mut("sw-colbe-2").expect("switch").insert(m, 0.0);
    }
    t.world.set("web_exporter", MINUTES, Some(0.0));
    t.run_at(0).await;
    assert_eq!(t.rows(None).await, []);
    t.world.set("web_exporter", MINUTES, Some(1.0));
    t.run_at(0).await;
    assert_eq!(t.rows(None).await, [row("switch_down", "sw-colbe-2", at(-10), None)]);
}

#[tokio::test]
async fn test_web_switch_short_timeouts_and_busy_sessions_are_no_incident() {
    let admin = need_db!();
    let mut t = T::new(&admin).await;
    for m in -8..=60 {
        t.world.web_switches.get_mut("sw-colbe-2").expect("switch").insert(m, 0.0); // 9 minutes: below the 10
    }
    t.run_at(0).await;
    assert_eq!(t.rows(None).await, []);
    for m in -30..=60 {
        t.world.web_switches.get_mut("sw-colbe-2").expect("switch").insert(m, 0.0);
    }
    t.world.load(&t.prom);
    t.prom.range_series(
        inc::Q_WEB_SWITCH_REASON,
        vec![(labels(&[("switch", "sw-colbe-2"), ("reason", "session_busy")]), pts((-30..=60).map(|m| (at(m), 1.0))))],
    );
    assert_eq!(t.run_raw(0).await, Outcome::Ok);
    assert_eq!(t.rows(None).await, []);
}

#[tokio::test]
async fn test_a_switch_answering_ping_is_not_down_for_its_web_ui() {
    // a switch in both: ICMP decides where it is known (its slow web UI is no outage)
    let admin = need_db!();
    let mut t = T::new(&admin).await;
    t.world.web_switches.insert("sw-cellar", (-5..=60).map(|m| (m, 0.0)).collect());
    t.run_at(0).await;
    assert_eq!(t.rows(None).await, []);
}

#[tokio::test]
async fn test_a_reason_sample_of_zero_is_no_reason() {
    let admin = need_db!();
    let mut t = T::new(&admin).await;
    for m in -12..=60 {
        t.world.web_switches.get_mut("sw-colbe-2").expect("switch").insert(m, 0.0);
    }
    t.world.load(&t.prom);
    t.prom.range_series(
        inc::Q_WEB_SWITCH_REASON,
        vec![
            (labels(&[("switch", "sw-colbe-2"), ("reason", "session_busy")]), pts((-12..=60).map(|m| (at(m), 0.0)))),
            (labels(&[("switch", "sw-colbe-2"), ("reason", "timeout")]), pts((-12..=60).map(|m| (at(m), 1.0)))),
        ],
    );
    assert_eq!(t.run_raw(0).await, Outcome::Ok);
    assert_eq!(t.rows(None).await, [row("switch_down", "sw-colbe-2", at(-12), None)]);
}
