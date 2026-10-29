//! The telemetry parts of Python tests/test_dashboard_api.py: what the routes get from the
//! telemetry (the routes themselves, their status codes, sessions, CSRF, CSP and the parameter
//! parsing are the web crate's): ownership of the data (SpoofedMacTests, FirstSeenTests), the
//! admin list's search, the house, the admin views (AdminApiTests) and the rollups for long
//! ranges (BudgetSharingTests).

use std::collections::BTreeSet;

use indexmap::IndexMap;
use netportal_core::registry::{AuthEvent, DeviceRow, Person};
use serde_json::{Value, json};
use sqlx::types::Json;
use uuid::Uuid;

use super::fakes::*;
use crate::telemetry::Telemetry;
use crate::telemetry::admin;
use crate::telemetry::history::{self, HistoryOptions, Range};
use crate::telemetry::house::{empty_house, house};
use crate::telemetry::identity;
use crate::telemetry::live::{self, DashboardOptions};

const RESIDENT: &str = "sub-resident";
const OTHER: &str = "sub-other";
const AP1_MAC: &str = "60:22:32:37:48:00";
const EARLY: f64 = 1_577_836_800.0; // 2020-01-01

fn mine() -> Uuid {
    id("mine")
}
fn theirs() -> Uuid {
    id("theirs")
}
fn spoof() -> Uuid {
    id("spoof")
}

fn device_row(id: Uuid, mac: &str, owner: &str, name: &str) -> DeviceRow {
    DeviceRow { id, owner: owner.into(), name: name.into(), calling_station: Some(mac.into()), ..row("x") }
}

fn people() -> IndexMap<String, Person> {
    IndexMap::from([
        (RESIDENT.to_string(), person(RESIDENT, "resident", "Rea Resident")),
        (OTHER.to_string(), person(OTHER, "other", "Otto Other")),
    ])
}

/// Python's DevicesRegistry: each device's MAC from its first login (or 2020) until now (current,
/// logged in just now); another person's active device with the same MAC is a conflict for all
/// that time.
fn devices_registry(devices: &[DeviceRow]) -> FakeRegistry {
    let mut fake = FakeRegistry::new();
    for d in devices {
        let Some(mac) = d.calling_station.as_deref().and_then(crate::telemetry::common::normalise_mac) else {
            continue;
        };
        let first = d.first_seen.map(t).unwrap_or(EARLY);
        fake.windows.insert(
            d.id,
            vec![Win { current: Some(true), window_end: Some(NOW + 900.0), auth_count: 3, ..window(&mac, first, NOW) }],
        );
        let others: BTreeSet<&str> = devices
            .iter()
            .filter(|o| {
                o.id != d.id
                    && o.revoked_at.is_none()
                    && o.calling_station.as_deref().and_then(crate::telemetry::common::normalise_mac).as_deref()
                        == Some(&mac)
            })
            .map(|o| o.owner.as_str())
            .filter(|o| *o != d.owner)
            .collect();
        if !others.is_empty() {
            fake.conflicts.insert(d.id, vec![clash(&mac, others.len() as i64, EARLY, None)]);
        }
    }
    fake.devices = devices.to_vec();
    fake.people = people();
    fake
}

fn devices() -> Vec<DeviceRow> {
    vec![
        device_row(mine(), "02-00-00-00-00-0A", RESIDENT, "My phone"),
        device_row(theirs(), "02-00-00-00-00-0B", OTHER, "Their laptop"),
    ]
}

fn with_spoof() -> Vec<DeviceRow> {
    let mut all = devices();
    all.push(device_row(spoof(), MAC_A, OTHER, "Not my phone"));
    all
}

fn both_live() -> Vec<(String, Value)> {
    live(true)
}

async fn one(t: &Telemetry, fake: &mut FakeRegistry, r: &DeviceRow, admin: bool) -> live::Device {
    let owners = people();
    let opts = DashboardOptions {
        owners: admin.then_some(&owners),
        admin,
        detail: true,
        now: Some(NOW),
        ..DashboardOptions::default()
    };
    let payload = live::dashboard(&t.page(), fake, std::slice::from_ref(r), &opts).await.unwrap();
    payload.into_one().unwrap().device
}

async fn hist(t: &Telemetry, fake: &mut FakeRegistry, r: &DeviceRow, range: Range, admin: bool) -> history::History {
    history::history(&t.page(), fake, r, range, HistoryOptions { admin, now: Some(NOW), ..HistoryOptions::default() })
        .await
        .unwrap()
}

// --- SpoofedMacTests -----------------------------------------------------------------------------------

#[tokio::test]
async fn test_neither_resident_sees_the_macs_data() {
    let all = with_spoof();
    let prom = FakePrometheus::start(both_live()).await;
    let t = prom.telemetry();
    for r in [&all[0], &all[2]] {
        let mut fake = devices_registry(&all);
        let d = one(&t, &mut fake, r, false).await;
        assert_eq!(d.state, "unknown", "{}", r.name);
        let got: Vec<(&str, Value)> =
            d.diagnostics().iter().map(|f| (f.code, Value::Object(f.params.clone()))).collect();
        assert_eq!(got, [("mac_conflict", json!({}))]);
        assert!(d.live.ap.is_none());
        let h = hist(&t, &mut fake, r, Range::D30, false).await;
        assert_eq!((h.telemetry, h.withheld, h.timeline.len()), ("ok", Some("mac_conflict"), 0));
        assert!(h.series.values().all(Vec::is_empty));
    }
    assert!(prom.queries(MAC_A).is_empty()); // never asked
}

#[tokio::test]
async fn test_an_admin_sees_the_data_and_the_conflict() {
    let all = with_spoof();
    let prom = FakePrometheus::start(both_live()).await;
    let t = prom.telemetry();
    let mut fake = devices_registry(&all);
    let d = one(&t, &mut fake, &all[0], true).await;
    assert_eq!(d.state, "online");
    assert_eq!(
        (d.diagnostics()[0].code, Value::Object(d.diagnostics()[0].params.clone())),
        ("mac_conflict", json!({"owners": 1}))
    );
    assert_eq!(hist(&t, &mut fake, &all[0], Range::H24, true).await.withheld, None);
    let owners = people();
    let opts = DashboardOptions { owners: Some(&owners), admin: true, now: Some(NOW), ..DashboardOptions::default() };
    let listed = live::dashboard(&t.page(), &mut fake, &all, &opts).await.unwrap();
    let spoofed = listed.devices.iter().find(|d| d.id == spoof().to_string()).unwrap();
    assert_eq!(Value::Object(spoofed.diagnostics()[0].params.clone()), json!({"owners": 1}));
}

#[tokio::test]
async fn test_a_revoked_claim_is_no_conflict() {
    let mut all = with_spoof();
    all[2].revoked_at = Some(dt(NOW - 86400.0));
    let prom = FakePrometheus::start(both_live()).await;
    let mut fake = devices_registry(&all);
    assert_eq!(one(&prom.telemetry(), &mut fake, &all[0], false).await.state, "online");
}

// --- FirstSeenTests ---------------------------------------------------------------------------------------

#[tokio::test]
async fn test_the_history_starts_at_the_first_login_with_this_mac() {
    let (created, first) = (1_790_000_000.0, 1_791_600_000.0);
    let mut all = devices();
    all[0].created_at = dt(created);
    all[0].first_seen = Some(dt(first));
    let prom = FakePrometheus::start(both_live()).await;
    let mut fake = devices_registry(&all);
    let h = hist(&prom.telemetry(), &mut fake, &all[0], Range::H24, false).await;
    assert_eq!(h.data_from, Some(first as i64));
}

// --- OwnershipTests (the telemetry's part) ----------------------------------------------------------------

#[tokio::test]
async fn test_admin_search_and_state() {
    let all = devices();
    let prom = FakePrometheus::start(both_live()).await;
    let t = prom.telemetry();
    let owners = people();
    let ids = |q: &'static str, state: &'static str| {
        let t = t.clone();
        let all = all.clone();
        let owners = owners.clone();
        async move {
            let mut fake = devices_registry(&all);
            let opts =
                DashboardOptions { owners: Some(&owners), admin: true, now: Some(NOW), ..DashboardOptions::default() };
            let mut payload = live::dashboard(&t.page(), &mut fake, &all, &opts).await.unwrap();
            payload.filter(q, state);
            payload.devices.into_iter().map(|d| d.id).collect::<Vec<_>>()
        }
    };
    assert_eq!(ids("otto", "").await, [theirs().to_string()]);
    assert_eq!(ids("MY PHONE", "").await, [mine().to_string()]);
    assert_eq!(ids("02-00-00-00-00-0B", "").await, [theirs().to_string()]);
    assert_eq!(ids("", "online").await, [mine().to_string()]);
    assert_eq!(ids("", "offline").await, [theirs().to_string()]);
    assert_eq!(ids("", "nonsense").await.len(), 2);
}

#[tokio::test]
async fn test_the_house() {
    let prom = FakePrometheus::start(both_live()).await;
    let body = serde_json::to_value(house(prom.telemetry().page().budget.as_ref()).await).unwrap();
    let keys: BTreeSet<String> = body.as_object().unwrap().keys().cloned().collect();
    let empty: BTreeSet<String> =
        serde_json::to_value(empty_house()).unwrap().as_object().unwrap().keys().cloned().collect();
    assert_eq!(keys, empty);
    assert_eq!(body["internet"], json!("ok"));
}

// --- AdminApiTests ------------------------------------------------------------------------------------------

fn admin_registry() -> FakeRegistry {
    let mut fake = devices_registry(&devices());
    let mut internet = incident(2, "internet_down", "", None, NOW - 2.0 * 86400.0, Some(NOW - 2.0 * 86400.0 + 300.0));
    internet.detail = Json(json!({"probe": "icmp"}));
    fake.incidents = vec![incident(1, "ap_down", AP1_MAC, Some("ap-scharni-2-corner"), NOW - 600.0, None), internet];
    let mut theirs_reject = failure(NOW - 100.0, "revoked", Some(theirs()), Some(MAC_B));
    theirs_reject.owner = Some(OTHER.into());
    theirs_reject.serial = Some("0a".into());
    theirs_reject.nas_ip = Some("10.0.10.27".into());
    fake.failures = vec![theirs_reject, failure(NOW - 50.0, "no_cert", None, Some("02:00:00:00:00:99"))];
    let mut unifi_job = job("unifi_events", Some(NOW - 3600.0), Some(NOW - 60.0), Some("Loki: timeout"), 10.0);
    unifi_job.cursor = Json(json!({"ts": 1}));
    fake.jobs = vec![job("rollup", Some(NOW - 60.0), Some(NOW - 60.0), None, 1.5), unifi_job];
    fake
}

fn tz() -> jiff::tz::TimeZone {
    history::zone(None)
}

#[tokio::test]
async fn test_overview() {
    let prom = FakePrometheus::start(both_live()).await;
    let mut fake = admin_registry();
    let body = serde_json::to_value(admin::overview(&prom.telemetry().page(), &mut fake, NOW).await).unwrap();
    let keys: BTreeSet<&str> = body.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        BTreeSet::from([
            "generated_at",
            "telemetry",
            "stale",
            "house",
            "incidents",
            "aps",
            "auth",
            "jobs",
            "jobs_available",
            "freshness"
        ])
    );
    let ids = |v: &Value| v.as_array().unwrap().iter().map(|i| i["id"].clone()).collect::<Vec<_>>();
    assert_eq!(ids(&body["incidents"]["open"]), [json!(1)]);
    assert_eq!(ids(&body["incidents"]["recent"]), [json!(2)]);
    assert_eq!(body["incidents"]["counts_7d"], json!({"ap_down": 1, "internet_down": 1}));
    assert_eq!(
        (body["auth"]["count"].clone(), body["auth"]["by_reason"].clone()),
        (json!(2), json!({"revoked": 1, "no_cert": 1}))
    );
    assert_eq!(body["auth"]["recent"][1]["owner"], json!({"username": "other", "display": "Otto Other"}));
    assert_eq!(body["auth"]["recent"][1]["device_id"], json!(theirs().to_string()));
    let jobs: Vec<(Value, Value)> =
        body["jobs"].as_array().unwrap().iter().map(|j| (j["name"].clone(), j["ok"].clone())).collect();
    assert_eq!(jobs, [(json!("rollup"), json!(true)), (json!("unifi_events"), json!(false))]);
    assert_eq!(body["jobs_available"], json!(true));
    assert_eq!(body["freshness"]["jobs_ok"], json!(false));
    assert_eq!(body["telemetry"], json!("ok"));
}

#[tokio::test]
async fn test_a_failing_section_is_unavailable_not_an_error() {
    let prom = FakePrometheus::start(both_live()).await;
    let mut fake = admin_registry();
    fake.failing = vec!["job_status"];
    let o = admin::overview(&prom.telemetry().page(), &mut fake, NOW).await;
    assert_eq!((o.jobs.len(), o.jobs_available), (0, false));
    assert!(o.incidents.available);
    assert!(!fake.called("rollback").is_empty()); // the next section gets a working transaction
}

/// A job that runs now (attempted after its last success, no error) is not failed (Python: `ok`
/// false while every run lasts).
#[test]
fn test_a_running_job_is_ok() {
    let running = admin::public_job(&job("rollup", Some(NOW - 1800.0), Some(NOW - 5.0), None, 3.0), NOW);
    assert!(running.ok);
    assert_eq!(running.age_s, Some(1800));
    let failed = admin::public_job(&job("rollup", Some(NOW - 1800.0), Some(NOW - 5.0), Some("boom"), 3.0), NOW);
    assert!(!failed.ok);
    let never = admin::public_job(&job("rollup", None, None, None, 0.0), NOW);
    assert!(never.ok);
}

fn ap_handlers() -> Vec<(String, Value)> {
    let mut out = vec![
        h(
            "unpoller_device_info",
            vector(&[(
                json!({"mac": AP1_MAC, "name": "ap-scharni-2-corner", "ip": "10.0.10.27", "model": "UAL6"}),
                json!(1),
            )]),
        ),
        h("sum by (name) (unpoller_device_stations", vector(&[(json!({"name": "ap-scharni-2-corner"}), json!(12))])),
    ];
    out.extend(both_live());
    out
}

#[tokio::test]
async fn test_aps() {
    let prom = FakePrometheus::start(ap_handlers()).await;
    let t = prom.telemetry();
    let mut fake = admin_registry();
    let body = admin::aps(&t.page(), &mut fake, NOW, &tz()).await.unwrap();
    let ap = &body.aps[0];
    assert_eq!(
        (ap.name.as_str(), ap.mac.as_deref(), ap.clients, ap.state.as_str()),
        ("ap-scharni-2-corner", Some(AP1_MAC), Some(12), "down")
    );
    assert_eq!(ap.open_incidents.iter().map(|i| i.id).collect::<Vec<_>>(), [1]);
    assert_eq!(ap.days.as_ref().map(Vec::len), Some(0));
    assert_eq!((ap.warnings.clone(), ap.warning_details[0].code), (vec!["down"], "down")); // its open ap_down
    let mut handlers = vec![
        h(
            "min by (name) (unpoller_device_uplink_speed_mbps",
            vector(&[(json!({"name": "ap-scharni-2-corner"}), json!(100))]),
        ),
        h(
            "max by (name) (unpoller_device_uptime_seconds",
            vector(&[(json!({"name": "ap-scharni-2-corner"}), json!(3600))]),
        ),
    ];
    handlers.extend(ap_handlers());
    prom.set_handlers(handlers);
    prom.client().reset();
    let t = prom.telemetry();
    let body = admin::aps(&t.page(), &mut fake, NOW, &tz()).await.unwrap();
    assert_eq!(body.aps[0].warnings, ["down"]);
    fake.incidents.remove(0); // the AP is back
    let body = admin::aps(&t.page(), &mut fake, NOW, &tz()).await.unwrap();
    let ap = &body.aps[0];
    assert_eq!(ap.warnings, ["uplink", "restarted"]);
    assert_eq!(Value::Object(ap.warning_details[0].params.clone()), json!({"uplink_mbps": 100}));
    let overview = admin::overview(&t.page(), &mut fake, NOW).await;
    assert_eq!(overview.aps[0].warnings, ["uplink", "restarted"]);
}

/// An AP unpoller does not list (it is down) but the rollups know is marked down by its open
/// incident too (Python appended such APs after the incidents were matched).
#[tokio::test]
async fn test_a_rollup_only_ap_gets_its_incident() {
    let prom = FakePrometheus::start(both_live()).await;
    let mut fake = admin_registry();
    let today = history::local_day(NOW as i64, &tz());
    fake.ap_days = vec![netportal_core::registry::ApDay {
        ap_mac: AP1_MAC.into(),
        day: history::to_civil_time(today),
        ap_name: Some("ap-scharni-2-corner".into()),
        clients_avg: Some(3.5),
        clients_max: Some(7),
        channel_util_avg: Json(json!({"na": 0.2})),
        weak_client_share: None,
        restarts: Some(0),
        down_s: Some(0),
        computed_at: None,
    }];
    let body = admin::aps(&prom.telemetry().page(), &mut fake, NOW, &tz()).await.unwrap();
    let ap = &body.aps[0];
    assert_eq!((ap.state.as_str(), ap.clients_house, ap.warnings.clone()), ("down", None, vec!["down"]));
    assert_eq!(ap.days.as_ref().map(Vec::len), Some(1));
}

fn drop_outs(fake: &mut FakeRegistry) {
    let ev = |at: f64, ap_mac: Option<&str>, ap: Option<&str>, kind: &str| {
        unifi(at, kind, ap, ap_mac, None, None, MAC_B, "na")
    };
    fake.events.insert(
        theirs(),
        vec![
            ev(NOW - 590.0, Some(AP1_MAC), Some("ap-scharni-2-corner"), "disconnected"),
            ev(NOW - 2.0 * 86400.0 + 60.0, None, None, "disconnected"),
        ],
    );
    fake.events.insert(
        mine(),
        vec![
            ev(NOW - 580.0, Some("68:d7:9a:1c:61:46"), Some("ap-colbe-2-far"), "disconnected"), // another AP
            ev(NOW - 570.0, Some(AP1_MAC), Some("ap-scharni-2-corner"), "connected"),           // no drop-out
        ],
    );
}

#[tokio::test]
async fn test_incident_devices() {
    let prom = FakePrometheus::start(both_live()).await;
    let t = prom.telemetry();
    let mut fake = admin_registry();
    drop_outs(&mut fake);
    let body = serde_json::to_value(
        admin::incidents(&t.page(), &mut fake, NOW - 7.0 * 86400.0, NOW, None, NOW).await.unwrap(),
    )
    .unwrap();
    let (ap_down, internet) = (&body["incidents"][0], &body["incidents"][1]);
    assert_eq!(
        ap_down["devices"],
        json!([{"id": theirs().to_string(), "name": "Their laptop", "owner": {"username": "other", "display": "Otto Other"}}])
    );
    assert_eq!(
        (ap_down["devices_truncated"].clone(), ap_down["devices_basis"].clone()),
        (json!(false), json!("inferred"))
    );
    assert_eq!(
        internet["devices"].as_array().unwrap().iter().map(|d| d["id"].clone()).collect::<Vec<_>>(),
        [json!(theirs().to_string())]
    ); // house-wide: anyone's
    let overview = serde_json::to_value(admin::overview(&t.page(), &mut fake, NOW).await).unwrap();
    assert_eq!(overview["incidents"]["open"][0]["devices"][0]["id"], json!(theirs().to_string()));
    // two registry queries per active device for the whole list, not per incident
    assert_eq!(fake.called("connection_events").len(), 2 * 2); // incidents + overview
}

#[tokio::test]
async fn test_incident_devices_bounded() {
    let prom = FakePrometheus::start(both_live()).await;
    let t = prom.telemetry();
    let mut fake = admin_registry();
    drop_outs(&mut fake);
    let body =
        admin::incidents_bounded(&t.page(), &mut fake, NOW - 7.0 * 86400.0, NOW, None, NOW, 0, admin::DEVICES_SPAN_S)
            .await
            .unwrap();
    let first = body.incidents[0].attached.as_ref().unwrap();
    assert_eq!((first.devices.as_ref().map(Vec::len), first.devices_truncated), (Some(0), true));
    let body = admin::incidents_bounded(
        &t.page(),
        &mut fake,
        NOW - 7.0 * 86400.0,
        NOW,
        None,
        NOW,
        admin::INCIDENT_DEVICES_MAX,
        3600.0,
    )
    .await
    .unwrap();
    assert!(body.incidents[1].attached.as_ref().unwrap().devices.is_none()); // older: not computed
}

#[tokio::test]
async fn test_incidents_range_and_kind() {
    let prom = FakePrometheus::start(both_live()).await;
    let t = prom.telemetry();
    let mut fake = admin_registry();
    let ids = |b: &admin::Incidents| b.incidents.iter().map(|i| i.id).collect::<Vec<_>>();
    let body = admin::incidents(&t.page(), &mut fake, NOW - 7.0 * 86400.0, NOW, None, NOW).await.unwrap();
    assert_eq!(ids(&body), [1, 2]);
    assert_eq!(body.incidents[1].duration_s, 300);
    let body = admin::incidents(&t.page(), &mut fake, NOW - 7.0 * 86400.0, NOW, Some("ap_down"), NOW).await.unwrap();
    assert_eq!((ids(&body), body.kind.as_deref()), (vec![1], Some("ap_down")));
    let body = admin::incidents(&t.page(), &mut fake, NOW - 3600.0, NOW, None, NOW).await.unwrap();
    assert_eq!(ids(&body), [1]);
    let body = admin::incidents(&t.page(), &mut fake, NOW - 365.0 * 86400.0, NOW, None, NOW).await.unwrap();
    assert_eq!(body.incidents.len(), 2);
    assert_eq!(body.from, crate::telemetry::common::iso(Some(NOW - 365.0 * 86400.0)));
}

#[tokio::test]
async fn test_auth() {
    let prom = FakePrometheus::start(both_live()).await;
    let t = prom.telemetry();
    let mut fake = admin_registry();
    let body = admin::auth(&t.page(), &mut fake, NOW - 86400.0, NOW, admin::AUTH_LIMIT).await.unwrap();
    let reasons: Vec<&str> = body.events.iter().map(|e| e.reason.as_str()).collect();
    assert_eq!(reasons, ["no_cert", "revoked"]);
    assert_eq!(body.events[1].device_name.as_deref(), Some("Their laptop"));
    assert_eq!(fake.called("auth_failures").last().and_then(|c| c.limit), Some(500));
    admin::auth(&t.page(), &mut fake, NOW - 86400.0, NOW, 20).await.unwrap();
    assert_eq!(fake.called("auth_failures").last().and_then(|c| c.limit), Some(20));
    assert_eq!(body.result, "reject");
}

#[tokio::test]
async fn test_raw() {
    let mut fake = admin_registry();
    fake.auth
        .insert(theirs(), vec![AuthEvent { bssid: None, ..auth_event(NOW - 60.0, "accept", "ok", MAC_B, "device") }]);
    let all = devices();
    let found = identity::from_registry(&mut fake, &all[1..2], NOW, true, None).await.unwrap();
    let body =
        admin::raw(&mut fake, &all[1], &found[&theirs()], NOW - 86400.0, NOW, &people(), &tz(), NOW).await.unwrap();
    let v = serde_json::to_value(&body).unwrap();
    let keys: BTreeSet<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        BTreeSet::from([
            "device",
            "from",
            "to",
            "windows",
            "conflicts",
            "auth",
            "acct",
            "events",
            "days",
            "incidents",
            "limits",
            "truncated"
        ])
    );
    assert_eq!(v["device"]["owner"], json!({"username": "other", "display": "Otto Other"}));
    assert_eq!(v["windows"][0]["mac"], json!(MAC_B));
    assert_eq!(v["auth"][0]["reason"], json!("ok"));
    assert_eq!((v["auth"][0]["match"].clone(), v["auth"][0]["count"].clone()), (json!("device"), json!(1)));
    assert_eq!(v["truncated"], json!({"auth": false, "acct": false, "events": false}));
    assert_eq!(v["limits"], json!({"auth": 1000, "acct": 1000, "events": 2000}));
}

// --- BudgetSharingTests -----------------------------------------------------------------------------------------

#[tokio::test]
async fn test_long_ranges_come_from_the_rollups() {
    let all = devices();
    let prom = FakePrometheus::start(both_live()).await;
    let mut fake = devices_registry(&all);
    let body = hist(&prom.telemetry(), &mut fake, &all[0], Range::Y1, false).await;
    assert_eq!((body.range, body.step), ("1y", Some("day")));
    assert!(prom.ranges().is_empty());
    assert_eq!(fake.called("device_days").len(), 1);
}

/// One page, one budget: the device page's live data and history share it (Python counted
/// `within` calls; here the budget is the page's).
#[tokio::test]
async fn test_the_device_page_has_one_budget_for_live_and_history() {
    let all = devices();
    let prom = FakePrometheus::start(both_live()).await;
    prom.edit(|s| s.delay_s = 0.15); // 28 queries of the dashboard: 4.2 s of the 5
    let t = prom.telemetry();
    let page = t.page();
    let mut fake = devices_registry(&all);
    let opts = DashboardOptions { detail: true, now: Some(NOW), ..DashboardOptions::default() };
    let live = live::dashboard(&page, &mut fake, &all[..1], &opts).await.unwrap();
    assert_eq!(live.telemetry, "ok");
    // the dashboard used most of the 5 s: the history on the same page runs out
    let h = history::history(
        &page,
        &mut fake,
        &all[0],
        Range::D7,
        HistoryOptions { now: Some(NOW), ..HistoryOptions::default() },
    )
    .await
    .unwrap();
    assert_eq!(h.telemetry, "unavailable");
    assert!(page.budget.as_ref().is_some_and(|b| b.left() <= 0.0));
}
