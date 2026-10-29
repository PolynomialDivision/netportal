//! Python tests/test_telemetry.py: the dashboard's Prometheus client and what it derives, against
//! a fake Prometheus. The v1 calls (a MAC without the registry) are made with the registry's
//! windows instead (the Rust version always has them): one current window per MAC.

use std::sync::Arc;

use netportal_core::registry::{DeviceRow, MacWindow};
use serde_json::{Value, json};

use super::fakes::*;
use crate::telemetry::Telemetry;
use crate::telemetry::client::Unavailable;
use crate::telemetry::common::{self, ap_info, iso, mac_selector, normalise_mac, promql_string, selectors};
use crate::telemetry::history::{self, HistoryOptions, Range};
use crate::telemetry::house::{empty_house, house, house_status};
use crate::telemetry::identity::{data_bound, windows_of};
use crate::telemetry::live::{self, DashboardOptions, LIVE_FIELDS, device_status};
use crate::telemetry::timeline::{Point, derive_timeline};

fn rows() -> Vec<DeviceRow> {
    let mut a = row("a");
    a.calling_station = Some("02-00-00-00-00-0A".into());
    let mut b = row("b");
    b.calling_station = Some("02-00-00-00-00-0B".into());
    let mut d = row("d");
    d.calling_station = Some("not a mac".into());
    vec![a, b, row("c"), d]
}

/// The registry of [`rows`]: MAC_A and MAC_B logged in 10 minutes ago (open windows).
fn registry() -> FakeRegistry {
    let mut fake = FakeRegistry::new();
    fake.windows.insert(id("a"), vec![window(MAC_A, NOW - 30.0 * 86400.0, NOW - 600.0)]);
    fake.windows.insert(id("b"), vec![window(MAC_B, NOW - 30.0 * 86400.0, NOW - 600.0)]);
    fake
}

async fn dashboard(t: &Telemetry, fake: &mut FakeRegistry, rows: &[DeviceRow]) -> live::Dashboard {
    let opts = DashboardOptions { now: Some(NOW), ..DashboardOptions::default() };
    live::dashboard(&t.page(), fake, rows, &opts).await.expect("dashboard")
}

fn codes(d: &live::Device) -> Vec<&'static str> {
    d.diagnostics().iter().map(|f| f.code).collect()
}

fn brief(d: &live::Device) -> Vec<(&'static str, crate::diagnostics::Severity, Value)> {
    d.diagnostics().iter().map(|f| (f.code, f.severity, Value::Object(f.params.clone()))).collect()
}

// --- MacTests ------------------------------------------------------------------------------------------

#[test]
fn test_normalise() {
    for raw in ["02-00-00-00-00-0A", "02:00:00:00:00:0a", "02000000000A", " 02-00-00-00-00-0a\n"] {
        assert_eq!(normalise_mac(raw).as_deref(), Some(MAC_A), "{raw:?}");
    }
}

#[test]
fn test_refused() {
    for raw in [
        "",
        "02-00-00-00-00",
        "02:00:00:00:00:0a:0b",
        "02-00:00-00-00-0a",
        "0200.0000.000a",
        "02:00:00:00:00:0g",
        "zz:zz:zz:zz:zz:zz",
        "02:00:00:00:00:0a\"} or vector(1) #",
        "02:00:00:00:00:0a|.*",
        ".*",
        "02:00:00:00:00:0a\\",
        "\u{ff10}\u{ff12}:00:00:00:00:0a",
    ] {
        assert_eq!(normalise_mac(raw), None, "{raw:?}");
    }
}

#[test]
fn test_selector_takes_only_normalised_macs() {
    assert_eq!(mac_selector(&[MAC_A]).unwrap(), format!("mac=\"{MAC_A}\""));
    assert_eq!(mac_selector(&[MAC_B, MAC_A, MAC_B]).unwrap(), format!("mac=~\"{MAC_A}|{MAC_B}\""));
    let bad: [&[&str]; 4] = [&[], &["02-00-00-00-00-0A"], &[MAC_A, ".*\"} or vector(1) #"], &[MAC_A, ".*"]];
    for macs in bad {
        assert!(mac_selector(macs).is_err(), "{macs:?}");
    }
}

/// Python: `history(prom, '.*"}', "24h")` raises before any query. Here a MAC only reaches a
/// query through a window, and a window whose MAC is not normalised is no window.
#[tokio::test]
async fn test_history_refuses_a_raw_mac() {
    let bad = MacWindow {
        mac: ".*\"}".into(),
        first_seen: dt(NOW - 86400.0),
        last_seen: dt(NOW - 60.0),
        window_end: dt(NOW),
        current: true,
        randomized: false,
        auth_count: 1,
    };
    assert!(windows_of(&row("a"), &[bad], NOW).is_empty());
    let prom = FakePrometheus::start(vec![]).await;
    let mut fake = FakeRegistry::new();
    let h = history::history(
        &prom.telemetry().page(),
        &mut fake,
        &row("a"),
        Range::H24,
        HistoryOptions { now: Some(NOW), ..Default::default() },
    )
    .await
    .unwrap();
    assert_eq!(h.timeline.len(), 0);
    assert!(prom.ranges().is_empty());
}

#[test]
fn test_ap_names() {
    let a = ap_info(Some("ap-scharni-2-corner")).unwrap();
    assert_eq!(
        serde_json::to_value(&a).unwrap(),
        json!({"name": "ap-scharni-2-corner", "house": "scharni", "floor": 2, "spot": "corner"})
    );
    assert_eq!(ap_info(Some("ap-scharni-0-schlaglicht")).unwrap().spot.as_deref(), Some("schlaglicht"));
    let other = ap_info(Some("2. stock scharni mitte")).unwrap();
    assert_eq!(
        serde_json::to_value(&other).unwrap(),
        json!({"name": "2. stock scharni mitte", "house": null, "floor": null, "spot": null})
    );
    assert!(ap_info(None).is_none());
}

// --- ClientTests -------------------------------------------------------------------------------------------

#[tokio::test]
async fn test_cached_for_15_seconds() {
    let prom = FakePrometheus::start(vec![h("up", vector(&[(json!({}), json!(1))]))]).await;
    let client = prom.client();
    let answer = client.within().vector("up", None, 15.0).await.unwrap();
    assert_eq!(answer, vec![(Default::default(), Some(1.0))]);
    prom.clock.advance(14.0);
    client.within().vector("up", None, 15.0).await.unwrap();
    assert_eq!(prom.calls().len(), 1);
    prom.clock.advance(2.0);
    client.within().vector("up", None, 15.0).await.unwrap();
    assert_eq!(prom.calls().len(), 2);
}

#[tokio::test]
async fn test_timeout_and_one_session() {
    let prom = FakePrometheus::start(vec![h("up", vector(&[(json!({}), json!(1))]))]).await;
    prom.client().within().vector("up", None, 15.0).await.unwrap();
    let (path, params) = prom.calls().remove(0);
    assert_eq!(path, "/api/v1/query");
    assert_eq!(params.get("timeout").map(String::as_str), Some("4s"));
}

#[tokio::test]
async fn test_down_answers_unavailable_and_is_not_asked_again_for_15_seconds() {
    let prom = FakePrometheus::start(vec![h("up", vector(&[(json!({}), json!(1))]))]).await;
    prom.edit(|s| s.raw = Some((503, "unavailable".into())));
    let client = prom.client();
    assert!(client.within().vector("up", None, 15.0).await.is_err());
    assert!(client.within().vector("other", None, 15.0).await.is_err());
    assert_eq!(prom.calls().len(), 1);
    assert_eq!(client.queries_total(), (0, 1));
    prom.clock.advance(16.0);
    prom.edit(|s| s.raw = None);
    client.within().vector("up", None, 15.0).await.unwrap();
    assert_eq!(prom.calls().len(), 2);
    // a refused connection is "down" as well
    let (down, _clock) = down_client().await;
    assert!(down.within().vector("up", None, 15.0).await.is_err());
    assert_eq!(down.within().vector("up", None, 15.0).await, Err(Unavailable("failed less than 15 s ago".into())));
}

#[tokio::test]
async fn test_error_replies() {
    let prom = FakePrometheus::start(vec![h("up", vector(&[(json!({}), json!(1))]))]).await;
    prom.edit(|s| s.raw = Some((400, r#"{"status":"error","errorType":"bad_data"}"#.into())));
    let client = prom.client();
    assert!(client.within().vector("bad(", None, 15.0).await.is_err());
    // a 4xx says the query is wrong, not that Prometheus is down: no cool-down
    prom.edit(|s| s.raw = None);
    assert!(client.within().vector("up", None, 15.0).await.is_ok());
    let matrix_for_vector = FakePrometheus::start(vec![h("up", matrix(&[(json!({}), vec![(1.0, json!(1))])]))]).await;
    assert!(matrix_for_vector.client().within().vector("up", None, 15.0).await.is_err());
    let html = FakePrometheus::start(vec![]).await;
    html.edit(|s| s.raw = Some((200, "<html>".into())));
    assert!(html.client().within().vector("up", None, 15.0).await.is_err());
}

#[tokio::test]
async fn test_nan_and_inf_are_none() {
    let prom = FakePrometheus::start(vec![h(
        "x",
        vector(&[
            (json!({"a": "1"}), json!("NaN")),
            (json!({"a": "2"}), json!("+Inf")),
            (json!({"a": "3"}), json!("1.5")),
        ]),
    )])
    .await;
    let values: Vec<Option<f64>> =
        prom.client().within().vector("x", None, 15.0).await.unwrap().into_iter().map(|(_, v)| v).collect();
    assert_eq!(values, vec![None, None, Some(1.5)]);
}

#[tokio::test]
async fn test_ok_counted() {
    let prom = FakePrometheus::start(vec![h("up", vector(&[(json!({}), json!(1))]))]).await;
    let client = prom.client();
    client.within().vector("up", None, 15.0).await.unwrap();
    client.within().vector("up", None, 15.0).await.unwrap(); // cached: not a query
    assert_eq!(client.queries_total(), (1, 0));
}

// --- DashboardTests ------------------------------------------------------------------------------------------

#[tokio::test]
async fn test_one_query_per_metric_for_all_macs() {
    let prom = FakePrometheus::start(live(true)).await;
    dashboard(&prom.telemetry(), &mut registry(), &rows()).await;
    let sel = format!("mac=~\"{MAC_A}|{MAC_B}\"");
    for metric in [
        "max by (mac) (unpoller_client_radio_signal_db",
        "wifi_client_health_score",
        "wifi_client_retry_ratio",
        "rate(unpoller_client_transmit_bytes_total",
        "max by (mac, radio)",
        "avg by (mac, ap_name) (avg_over_time(unpoller_client_radio_signal_db",
    ] {
        let queries = prom.queries(metric);
        assert_eq!(queries.len(), 1, "{metric}");
        assert!(queries[0].contains(&sel), "{metric}");
    }
    // only the absent device's last sighting is looked up
    assert!(prom.queries("max by (mac) (max_over_time(timestamp(")[0].contains(&format!("mac=\"{MAC_B}\"")));
    // nothing but normalised MACs in any query
    for q in prom.queries("") {
        assert!(!q.contains("not a mac") && !q.contains("02-00"), "{q}");
    }
}

#[tokio::test]
async fn test_online_offline_never() {
    let prom = FakePrometheus::start(live(true)).await;
    let payload = dashboard(&prom.telemetry(), &mut registry(), &rows()).await;
    assert_eq!((payload.telemetry, payload.stale), ("ok", false));
    let [a, b, c, d] = &payload.devices[..] else { panic!("four devices") };
    assert_eq!(a.state, "online");
    assert_eq!(a.mac.as_deref(), Some(MAC_A));
    assert_eq!(a.since, iso(Some(NOW - 3600.0)));
    assert_eq!(a.last_seen, iso(Some(NOW - 42.0))); // the snapshot's time
    assert_eq!(
        serde_json::to_value(&a.live.ap).unwrap(),
        json!({"name": "ap-scharni-2-corner", "house": "scharni", "floor": 2, "spot": "corner"})
    );
    assert_eq!(
        (a.live.ssid.as_deref(), a.live.band.as_deref(), a.live.channel, a.live.proto.as_deref()),
        (Some("Scharni"), Some("5"), Some(56), Some("ax"))
    );
    assert_eq!(
        (a.live.signal_dbm, a.live.snr_db, a.live.health, a.live.retry_ratio),
        (Some(-58.0), Some(38.0), Some(91.2), Some(0.0312))
    );
    assert_eq!((a.live.link_rx_bps, a.live.link_tx_bps), (Some(864000000), Some(576000000)));
    assert_eq!((a.live.rx_bps, a.live.tx_bps), (Some(125000), Some(2500)));
    assert_eq!((a.live.rx_24h_bytes, a.live.tx_24h_bytes), (Some(9000000000), Some(300000000)));
    assert_eq!(a.live.roams_1h, Some(1));
    assert!(a.diagnostics().is_empty(), "{:?}", codes(a));
    assert_eq!(b.state, "offline");
    assert_eq!(b.last_seen, iso(Some(NOW - 7200.0)));
    assert_eq!(b.live.signal_dbm, None);
    assert_eq!(b.live.roams_1h, None); // no data: unknown, not 0
    assert_eq!(codes(b), ["offline"]);
    for never in [c, d] {
        assert_eq!(never.state, "never_connected");
        assert_eq!(never.mac, None);
        assert_eq!(codes(never), ["never_connected"]);
    }
    assert_eq!(
        serde_json::to_value(&payload.house.speedtest).unwrap(),
        json!({"download_bps": 236752744, "upload_bps": 86375664, "ping_ms": 4.2, "at": iso(Some(NOW - 120.0))})
    );
}

#[tokio::test]
async fn test_offline_last_seen_falls_back_to_the_registry() {
    let radius = NOW - 30.0 * 86400.0;
    let handlers: Vec<_> = live(false).into_iter().filter(|(n, _)| n != "max_over_time(timestamp(").collect();
    let prom = FakePrometheus::start(handlers).await;
    let mut fake = FakeRegistry::new();
    fake.windows.insert(id("a"), vec![window(MAC_A, NOW - 60.0 * 86400.0, radius)]);
    let mut a = row("a");
    a.last_seen = Some(dt(radius));
    let payload = dashboard(&prom.telemetry(), &mut fake, &[a]).await;
    assert_eq!(payload.devices[0].state, "offline");
    assert_eq!(payload.devices[0].last_seen, iso(Some(radius)));
}

#[tokio::test]
async fn test_unavailable_prometheus() {
    let (client, clock) = down_client().await;
    let t = Telemetry::with_clock(Some(client), SSID, clock.clock());
    let payload = dashboard(&t, &mut registry(), &rows()).await;
    assert_eq!((payload.telemetry, payload.stale), ("unavailable", false));
    assert_eq!(payload.house, empty_house());
    let states: Vec<&str> = payload.devices.iter().map(|d| d.state).collect();
    assert_eq!(states, ["unknown", "unknown", "never_connected", "never_connected"]);
    assert!(payload.devices[0].diagnostics().is_empty());
    assert_eq!(house(t.page().budget.as_ref()).await, empty_house());
}

#[tokio::test]
async fn test_telemetry_off() {
    let payload = dashboard(&Telemetry::new(None, SSID), &mut registry(), &rows()).await;
    assert_eq!(payload.telemetry, "off");
    assert_eq!(payload.devices[0].state, "unknown");
    assert_eq!(payload.devices[2].state, "never_connected");
}

#[tokio::test]
async fn test_stale_wifi_data() {
    let mut handlers = vec![age(4000.0)];
    handlers.extend(live(true));
    let prom = FakePrometheus::start(handlers).await;
    let payload = dashboard(&prom.telemetry(), &mut registry(), &rows()).await;
    assert!(payload.stale);
    let a = &payload.devices[0];
    assert_eq!(a.state, "unknown"); // frozen presence is no proof
    assert_eq!(brief(a), vec![("stale_data", crate::diagnostics::Severity::Warn, json!({"age_s": 4000}))]);
    assert_eq!(a.diagnostics()[0].basis, crate::diagnostics::Basis::Measured);
    assert_eq!(Value::Object(a.diagnostics()[0].evidence.clone()), json!({"age_s": 4000, "threshold_s": 600}));
}

#[tokio::test]
async fn test_no_unpoller_data_is_stale_too() {
    let handlers: Vec<_> = live(true).into_iter().filter(|(n, _)| !n.contains("time() - timestamp")).collect();
    let prom = FakePrometheus::start(handlers).await;
    let payload = dashboard(&prom.telemetry(), &mut registry(), &rows()).await;
    assert!(payload.stale);
    assert_eq!(payload.house.wifi_data_age_s, None);
    assert_eq!(payload.devices[0].state, "unknown");
}

#[tokio::test]
async fn test_owners_for_admins() {
    let owners = indexmap::IndexMap::from([("sub-resident".to_string(), person("sub-resident", "res", "Resident"))]);
    let mut gone = row("b");
    gone.owner = "gone".into();
    let t = Telemetry::new(None, SSID);
    let opts = DashboardOptions { owners: Some(&owners), now: Some(NOW), ..DashboardOptions::default() };
    let payload = live::dashboard(&t.page(), &mut registry(), &[row("a"), gone], &opts).await.unwrap();
    let v = serde_json::to_value(&payload).unwrap();
    assert_eq!(v["devices"][0]["owner"], json!({"username": "res", "display": "Resident"}));
    assert_eq!(v["devices"][1]["owner"], json!({"username": null, "display": null}));
    let payload = dashboard(&t, &mut registry(), &[row("a")]).await;
    assert!(serde_json::to_value(&payload).unwrap()["devices"][0].get("owner").is_none());
}

#[tokio::test]
async fn test_reconnects_counted_from_association_starts() {
    let prom = FakePrometheus::start(live(true)).await;
    let (_status, summary) =
        device_status(&prom.client().within(), &[MAC_A.to_string()], &Default::default(), NOW).await.unwrap();
    assert_eq!(summary[MAC_A].reconnects_24h, Some(1)); // NOW-9000/-9010 one, then a new one
    let mut bands = summary[MAC_A].bands_7d.clone();
    bands.sort();
    assert_eq!(bands, ["2.4", "5"]);
}

// --- HouseTests ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn test_states() {
    let prom = FakePrometheus::start(house_ok()).await;
    let house = house_status(&prom.client().within()).await.unwrap();
    assert_eq!((house.internet.as_str(), house.router.as_str(), house.dns.as_str()), ("ok", "ok", "ok"));
    assert_eq!(
        (house.internet_loss_ratio, house.internet_rtt_ms, house.wifi_data_age_s),
        (Some(0.0), Some(5.0), Some(42))
    );
}

async fn with_probes(internet: f64, loss: f64, rtt: f64) -> crate::telemetry::house::House {
    let probes = vector(&[
        (json!({"job": "blackbox_icmp", "role": "gateway"}), json!(1)),
        (json!({"job": "blackbox_icmp", "role": "internet"}), json!(internet)),
    ]);
    let line = vector(&[
        (json!({"__name__": "network_internet_packet_loss_ratio_5m"}), json!(loss)),
        (json!({"__name__": "network_internet_rtt_ms"}), json!(rtt)),
    ]);
    let mut handlers = vec![h("probe_success", probes), h("network_internet_packet_loss_ratio_5m|", line)];
    handlers.extend(house_ok());
    let prom = FakePrometheus::start(handlers).await;
    house_status(&prom.client().within()).await.unwrap()
}

#[tokio::test]
async fn test_internet_down_degraded() {
    assert_eq!(with_probes(0.0, 0.0, 5.0).await.internet, "down");
    assert_eq!(with_probes(1.0, 0.2, 5.0).await.internet, "degraded");
    assert_eq!(with_probes(1.0, 0.0, 250.0).await.internet, "degraded");
    assert_eq!(with_probes(1.0, 0.0, 5.0).await.dns, "unknown"); // no DNS probe answer
}

#[tokio::test]
async fn test_nothing_known() {
    let prom = FakePrometheus::start(vec![]).await;
    assert_eq!(house_status(&prom.client().within()).await.unwrap(), empty_house());
}

#[tokio::test]
async fn test_speedtest_result_older_than_the_window() {
    let mut handlers = vec![h(
        "max(speedtest_tracker_result_id",
        matrix(&[(json!({}), vec![(NOW - 120.0, json!(126)), (NOW - 60.0, json!(126))])]),
    )];
    handlers.extend(house_ok());
    let prom = FakePrometheus::start(handlers).await;
    let house = house_status(&prom.client().within()).await.unwrap();
    assert_eq!(house.speedtest.and_then(|s| s.at), None);
}

// --- TimelineTests ----------------------------------------------------------------------------------------------

fn p(t: f64, start: f64) -> Point {
    pa(t, start, "ap-scharni-2-corner", "na")
}

fn pa(t: f64, start: f64, ap: &str, radio: &str) -> Point {
    Point { t, start, ap_name: Some(ap.into()), radio: Some(radio.into()), mac: None }
}

fn kinds(events: &[crate::telemetry::timeline::Inferred]) -> Vec<&'static str> {
    events.iter().map(|e| e.kind).collect()
}

#[test]
fn test_one_connection() {
    let points: Vec<Point> =
        (0..10).map(|i| p(1000.0 + 60.0 * f64::from(i), 900.0 + f64::from(i % 2) * 30.0)).collect();
    let (events, spans) = derive_timeline(&points, 60.0, Some(1540.0), None);
    assert_eq!(kinds(&events), ["connected"]);
    assert_eq!((events[0].at, events[0].duration_s), (900.0, Some(1540 - 900)));
    assert_eq!(spans, [(900.0, 1540.0)]);
}

#[test]
fn test_gap_with_a_new_association_is_a_disconnect() {
    let points = [p(1000.0, 900.0), p(1060.0, 900.0), p(2000.0, 1950.0), p(2060.0, 1950.0)];
    let (events, spans) = derive_timeline(&points, 60.0, Some(2060.0), None);
    assert_eq!(kinds(&events), ["connected", "disconnected", "connected"]);
    assert_eq!((events[1].at, events[1].duration_s), (1060.0, Some(1950 - 1060)));
    assert_eq!(events[0].duration_s, Some(160));
    assert_eq!(spans, [(900.0, 1060.0), (1950.0, 2060.0)]);
}

#[test]
fn test_gap_with_the_same_association_is_missing_data() {
    let (events, spans) =
        derive_timeline(&[p(1000.0, 900.0), p(1060.0, 900.0), p(3000.0, 920.0)], 60.0, Some(3000.0), None);
    assert_eq!(kinds(&events), ["connected"]);
    assert_eq!(spans, [(900.0, 3000.0)]);
}

#[test]
fn test_uptime_reset_without_a_gap_is_a_reconnect() {
    let points = [p(1000.0, 100.0), p(1060.0, 100.0), p(1120.0, 1100.0), p(1180.0, 1100.0)];
    let (events, _) = derive_timeline(&points, 60.0, Some(1180.0), None);
    assert_eq!(kinds(&events), ["connected", "disconnected", "connected"]);
    assert_eq!(events[2].at, 1100.0);
    assert_eq!(events[1].duration_s, Some(40));
}

#[test]
fn test_roam_and_band_change() {
    let points = [
        p(1000.0, 900.0),
        pa(1060.0, 900.0, "ap-colbe-2-far", "na"),
        pa(1120.0, 900.0, "ap-colbe-2-far", "ng"),
        pa(1180.0, 900.0, "ap-colbe-2-far", "ng"),
    ];
    let (events, _) = derive_timeline(&points, 60.0, Some(1180.0), None);
    assert_eq!(kinds(&events), ["connected", "roamed", "band_changed"]);
    let (roam, band) = (&events[1], &events[2]);
    assert_eq!(
        (roam.ap.as_deref(), roam.from_ap.as_deref(), roam.band, roam.from_band),
        (Some("ap-colbe-2-far"), Some("ap-scharni-2-corner"), Some("5"), Some("5"))
    );
    assert_eq!(roam.duration_s, Some(1060 - 900)); // time on the previous AP
    assert_eq!((band.band, band.from_band), (Some("2.4"), Some("5")));
}

#[test]
fn test_reconnect_on_another_ap_is_not_a_roam() {
    let (events, _) =
        derive_timeline(&[p(1000.0, 900.0), pa(1060.0, 1050.0, "ap-colbe-2-far", "na")], 60.0, Some(1060.0), None);
    assert_eq!(kinds(&events), ["connected", "disconnected", "connected"]);
    assert_eq!(events[2].ap.as_deref(), Some("ap-colbe-2-far"));
}

#[test]
fn test_gone_at_the_end() {
    let (events, _) = derive_timeline(&[p(1000.0, 900.0), p(1060.0, 900.0)], 60.0, Some(2000.0), None);
    assert_eq!(kinds(&events), ["connected", "disconnected"]);
    assert_eq!(events[1].duration_s, Some(940));
    let (events, _) = derive_timeline(&[p(1000.0, 900.0), p(1060.0, 900.0)], 60.0, Some(1120.0), None); // one scrape late
    assert_eq!(kinds(&events), ["connected"]);
}

#[test]
fn test_nothing() {
    let (events, spans) = derive_timeline(&[], 60.0, None, None);
    assert!(events.is_empty() && spans.is_empty());
}

// --- HistoryTests -------------------------------------------------------------------------------------------------

const END: f64 = 1_800_000_000.0; // NOW // 60 * 60

/// Python HistoryTests.fake: connected 2 h ago .. 1 h ago on corner, then (the same association)
/// on the 2.4 GHz radio until now; ages fresh unless `stale_from`.
pub(super) fn history_fake(stale_from: Option<f64>) -> Vec<(String, Value)> {
    let (end, start) = (END, END - 86400.0);
    let grid: Vec<f64> = (0..).map(|i| start - 300.0 + 60.0 + 60.0 * f64::from(i)).take_while(|t| *t <= end).collect();
    let ages: Vec<(f64, Value)> =
        grid.iter().map(|t| (*t, json!(if stale_from.is_some_and(|s| *t >= s) { 5000 } else { 30 }))).collect();
    let assoc_a: Vec<(f64, Value)> =
        grid.iter().filter(|t| end - 7200.0 <= **t && **t < end - 3600.0).map(|t| (*t, json!(end - 7200.0))).collect();
    let assoc_b: Vec<(f64, Value)> =
        grid.iter().filter(|t| **t >= end - 3600.0).map(|t| (*t, json!(end - 7200.0))).collect();
    let chart: Vec<(f64, Value)> = (0..=288)
        .map(|i| start + 300.0 * f64::from(i))
        .filter(|t| *t >= end - 7200.0)
        .map(|t| (t, json!(-60)))
        .collect();
    vec![
        h("max(unpoller_prometheus_cache_age_seconds{job=\"unifi\"})[", matrix(&[(json!({}), ages)])),
        h(
            "max by (mac, ap_name, radio) (timestamp(",
            matrix(&[
                (json!({"mac": MAC_A, "ap_name": "ap-scharni-2-corner", "radio": "na"}), assoc_a),
                (json!({"mac": MAC_A, "ap_name": "ap-scharni-2-corner", "radio": "ng"}), assoc_b),
            ]),
        ),
        h("unpoller_client_radio_signal_db", matrix(&[(json!({"mac": MAC_A}), chart)])),
    ]
}

/// One device with MAC_A for a month (an open window) or from `first`.
fn one_window(first: f64) -> FakeRegistry {
    let mut fake = FakeRegistry::new();
    fake.windows.insert(id("a"), vec![window(MAC_A, first, NOW - 60.0)]);
    fake
}

async fn history_of(t: &Telemetry, fake: &mut FakeRegistry, range: Range) -> history::History {
    let opts = HistoryOptions { now: Some(NOW), ..HistoryOptions::default() };
    history::history(&t.page(), fake, &row("a"), range, opts).await.expect("history")
}

fn at(series: &history::Series, t: f64) -> Option<f64> {
    series.iter().find(|(x, _)| *x == t as i64).and_then(|(_, v)| v.map(|v| v.as_f64()))
}

#[tokio::test]
async fn test_series_and_timeline() {
    let prom = FakePrometheus::start(history_fake(None)).await;
    let h = history_of(&prom.telemetry(), &mut one_window(NOW - 30.0 * 86400.0), Range::H24).await;
    assert_eq!((h.range, h.step_s, h.end, h.start), ("24h", 300, END as i64, (END - 86400.0) as i64));
    assert_eq!(h.telemetry, "ok");
    let signal = &h.series["signal_dbm"];
    assert_eq!(signal.len(), 289);
    assert_eq!(at(signal, END), Some(-60.0));
    assert_eq!(signal[0].1, None); // no data: null, not zero
    let online = &h.series["online"];
    assert_eq!(at(online, END), Some(1.0));
    assert_eq!(at(online, END - 3.0 * 3600.0), Some(0.0));
    let kinds: Vec<&str> = h.timeline.iter().map(|e| e.kind).collect();
    assert_eq!(kinds, ["connected", "band_changed"]);
    assert_eq!(h.timeline[0].at, iso(Some(END - 7200.0)));
    assert_eq!(h.timeline[1].ap.as_ref().and_then(|a| a.name.as_deref()), Some("ap-scharni-2-corner"));
    let mut names: Vec<&str> = h.series.keys().copied().collect();
    names.sort();
    assert_eq!(
        names,
        ["health", "link_rx_bps", "link_tx_bps", "online", "retry_ratio", "rx_bps", "signal_dbm", "snr_db", "tx_bps"]
    );
    assert_eq!(
        (h.timeline[0].source.as_str(), h.timeline[0].basis),
        ("prometheus", crate::telemetry::timeline::Basis::Inferred)
    );
    assert_eq!(h.timeline[0].mac.as_deref(), Some(MAC_A));
    // one MAC, exactly matched; every chart one range query with the range's step
    for q in prom.queries("unpoller_client_") {
        assert!(q.contains(&format!("mac=\"{MAC_A}\"")), "{q}");
    }
    let ranges = prom.ranges();
    assert_eq!(ranges.len(), 8);
    assert!(ranges.iter().all(|p| p.get("step").map(String::as_str) == Some("300")));
}

#[tokio::test]
async fn test_stale_windows_are_null() {
    let prom = FakePrometheus::start(history_fake(Some(END - 1800.0))).await;
    let h = history_of(&prom.telemetry(), &mut one_window(NOW - 30.0 * 86400.0), Range::H24).await;
    assert_eq!(h.series["signal_dbm"].last().and_then(|p| p.1), None);
    assert_eq!(h.series["online"].last().and_then(|p| p.1), None);
    assert_eq!(at(&h.series["online"], END - 3600.0), Some(1.0));
    // no disconnect is made up for the time without fresh data
    assert!(!h.timeline.iter().any(|e| e.kind == "disconnected"));
}

#[tokio::test]
async fn test_ranges() {
    for (range, step) in [(Range::D7, 1800), (Range::D30, 7200), (Range::D90, 21600)] {
        let prom = FakePrometheus::start(vec![]).await;
        let h = history_of(&prom.telemetry(), &mut one_window(NOW - 30.0 * 86400.0), range).await;
        assert_eq!(h.step_s, step);
        assert!(h.timeline.is_empty());
        assert!(h.series["online"].iter().all(|(_, v)| v.is_none())); // nothing known
    }
    assert_eq!(Range::parse("2y"), None);
}

#[tokio::test]
async fn test_unavailable_off_and_never_connected() {
    let (client, clock) = down_client().await;
    let t = Telemetry::with_clock(Some(client), SSID, clock.clock());
    assert_eq!(history_of(&t, &mut one_window(NOW - 86400.0), Range::H24).await.telemetry, "unavailable");
    assert_eq!(
        history_of(&Telemetry::new(None, SSID), &mut one_window(NOW - 86400.0), Range::H24).await.telemetry,
        "off"
    );
    let prom = FakePrometheus::start(vec![]).await;
    let h = history_of(&prom.telemetry(), &mut FakeRegistry::new(), Range::H24).await;
    assert_eq!((h.telemetry, h.timeline.len()), ("ok", 0));
    // a never-connected device: no chart, no client query (the AP map is the house's)
    assert!(prom.ranges().is_empty());
    assert!(prom.queries("unpoller_client_").is_empty());
}

// --- EssidTests --------------------------------------------------------------------------------------------------

fn client_queries(prom: &FakePrometheus) -> Vec<String> {
    prom.queries("").into_iter().filter(|q| q.contains("unpoller_client_") || q.contains("wifi_client_")).collect()
}

#[tokio::test]
async fn test_every_client_query_names_the_ssid() {
    let prom = FakePrometheus::start(live(true)).await;
    dashboard(&prom.telemetry(), &mut registry(), &rows()).await;
    let prom2 = FakePrometheus::start(history_fake(None)).await;
    history_of(&prom2.telemetry(), &mut one_window(NOW - 30.0 * 86400.0), Range::H24).await;
    history_of(&prom2.telemetry(), &mut one_window(NOW - 30.0 * 86400.0), Range::D7).await;
    let mut queries = client_queries(&prom);
    queries.extend(client_queries(&prom2));
    assert!(queries.len() > 20);
    for q in queries {
        assert!(q.contains("essid=\"Example\""), "{q}");
    }
}

#[tokio::test]
async fn test_metrics_without_essid_are_joined_to_the_uptime_series() {
    let prom = FakePrometheus::start(live(true)).await;
    dashboard(&prom.telemetry(), &mut registry(), &rows()).await;
    for needle in
        ["wifi_client_retry_ratio", "unpoller_client_transmit_bytes_total", "unpoller_client_receive_bytes_total"]
    {
        for q in prom.queries(needle) {
            let (_, joined) = q.split_once("and on (mac)").unwrap_or_else(|| panic!("{q}"));
            assert!(joined.contains("unpoller_client_uptime_seconds{job=\"unifi\",essid=\"Example\""), "{q}");
        }
    }
}

#[test]
fn test_string_literal() {
    assert_eq!(promql_string("Scharni").unwrap(), "\"Scharni\"");
    assert_eq!(promql_string("a\"b\\c").unwrap(), "\"a\\\"b\\\\c\"");
    for bad in ["a\nb", "a\u{0}"] {
        assert!(promql_string(bad).is_err());
    }
    let sel = selectors("x\",mac=~\".*", &[MAC_A]).unwrap().sel;
    assert_eq!(sel, format!("essid=\"x\\\",mac=~\\\".*\",mac=\"{MAC_A}\"")); // stays one literal
}

// --- ConflictTests -----------------------------------------------------------------------------------------------

#[tokio::test]
async fn test_withheld_from_residents() {
    let prom = FakePrometheus::start(live(true)).await;
    let mut fake = registry();
    fake.conflicts.insert(id("a"), vec![clash(MAC_A, 1, NOW - 86400.0, None)]);
    let payload = dashboard(&prom.telemetry(), &mut fake, &[row("a"), row("b")]).await;
    let (a, b) = (&payload.devices[0], &payload.devices[1]);
    assert_eq!(a.state, "unknown");
    assert_eq!(brief(a), vec![("mac_conflict", crate::diagnostics::Severity::Warn, json!({}))]);
    let fields = a.live.entries();
    assert_eq!(fields.len(), LIVE_FIELDS.len());
    assert!(fields.iter().all(|(_, v)| v.is_null()));
    assert_eq!(b.state, "offline");
    assert!(prom.queries(MAC_A).is_empty()); // not even asked
}

#[tokio::test]
async fn test_admins_see_the_data_and_the_conflict() {
    let prom = FakePrometheus::start(live(true)).await;
    let mut fake = registry();
    fake.conflicts.insert(id("a"), vec![clash(MAC_A, 2, NOW - 86400.0, None)]);
    let opts = DashboardOptions { admin: true, now: Some(NOW), ..DashboardOptions::default() };
    let payload = live::dashboard(&prom.telemetry().page(), &mut fake, &[row("a")], &opts).await.unwrap();
    let a = &payload.devices[0];
    assert_eq!(a.state, "online");
    assert_eq!(brief(a)[0], ("mac_conflict", crate::diagnostics::Severity::Warn, json!({"owners": 2})));
}

#[tokio::test]
async fn test_the_same_persons_devices_are_no_conflict() {
    let prom = FakePrometheus::start(live(true)).await;
    let mut fake = registry();
    fake.windows.insert(id("a2"), vec![window(MAC_A, NOW - 30.0 * 86400.0, NOW - 600.0)]);
    let payload = dashboard(&prom.telemetry(), &mut fake, &[row("a"), row("a2")]).await;
    let states: Vec<&str> = payload.devices.iter().map(|d| d.state).collect();
    assert_eq!(states, ["online", "online"]);
}

#[tokio::test]
async fn test_withheld_history() {
    let prom = FakePrometheus::start(history_fake(None)).await;
    let mut fake = one_window(NOW - 30.0 * 86400.0);
    fake.conflicts.insert(id("a"), vec![clash(MAC_A, 1, NOW - 40.0 * 86400.0, None)]);
    let h = history_of(&prom.telemetry(), &mut fake, Range::H24).await;
    assert_eq!((h.telemetry, h.withheld, h.timeline.len()), ("ok", Some("mac_conflict"), 0));
    assert!(h.series.values().all(Vec::is_empty));
    assert!(prom.calls().is_empty());
}

// --- BoundTests -------------------------------------------------------------------------------------------------

#[tokio::test]
async fn test_live_values_from_the_bound_on() {
    let prom = FakePrometheus::start(live(true)).await;
    let mut fake = FakeRegistry::new();
    fake.windows.insert(id("a"), vec![window(MAC_A, NOW - 550.0, NOW - 60.0)]);
    fake.windows.insert(id("b"), vec![window(MAC_B, NOW - 30.0 * 86400.0, NOW - 60.0)]);
    let mut a = row("a");
    a.first_seen = Some(dt(NOW - 550.0));
    let mut b = row("b");
    b.created_at = dt(NOW - 3600.0);
    let payload = dashboard(&prom.telemetry(), &mut fake, &[a, b]).await;
    let (a, b) = (&payload.devices[0], &payload.devices[1]);
    assert_eq!(a.live.rx_24h_bytes, None); // partly someone else's day: not shown
    assert_eq!(a.live.roams_1h, Some(0)); // the roam at NOW-600 was before
    assert_eq!(a.since, iso(Some(NOW - 550.0))); // not before its first login
    assert!(codes(a).is_empty(), "{:?}", codes(a));
    assert_eq!(b.last_seen, None); // seen at NOW-7200: before it existed
    assert!(prom.queries("increase(").iter().all(|q| !q.contains(MAC_A) && !q.contains(MAC_B)));
}

#[tokio::test]
async fn test_summary_bound() {
    let prom = FakePrometheus::start(live(true)).await;
    let bounds = [(MAC_A.to_string(), NOW - 3600.0)].into_iter().collect();
    let (_status, summary) = device_status(&prom.client().within(), &[MAC_A.to_string()], &bounds, NOW).await.unwrap();
    assert_eq!(summary[MAC_A].reconnects_24h, Some(0));
    assert_eq!(summary[MAC_A].bands_7d, ["5"]); // 2.4 GHz only before the bound
}

#[test]
fn test_data_bound() {
    let (created, first) = (dt(1_790_000_000.0), dt(1_791_600_000.0));
    let r = |c, f| DeviceRow { created_at: c, first_seen: f, ..row("a") };
    assert_eq!(data_bound(&r(created, Some(first))), t(first));
    assert_eq!(data_bound(&r(first, Some(created))), t(first));
    assert_eq!(data_bound(&r(created, None)), t(created));
}

#[tokio::test]
async fn test_history_from_the_bound_on() {
    let prom = FakePrometheus::start(history_fake(None)).await;
    let h = history_of(&prom.telemetry(), &mut one_window(END - 1800.0), Range::H24).await;
    assert_eq!(h.data_from, Some((END - 1800.0) as i64));
    let kinds: Vec<&str> = h.timeline.iter().map(|e| e.kind).collect();
    assert_eq!(kinds, ["connected"]); // the band change was before
    assert_eq!(h.timeline[0].at, iso(Some(END - 1800.0)));
    assert_eq!(at(&h.series["online"], END - 3600.0), None); // before: not this device's
    assert_eq!(at(&h.series["online"], END), Some(1.0));
    assert_eq!(at(&h.series["signal_dbm"], END - 3600.0), None);
}

// --- BudgetTests ---------------------------------------------------------------------------------------------------

fn timeouts(prom: &FakePrometheus) -> Vec<String> {
    prom.calls().into_iter().filter_map(|(_, p)| p.get("timeout").cloned()).collect()
}

#[tokio::test]
async fn test_a_slow_prometheus_uses_up_the_budget() {
    let prom = FakePrometheus::start(live(true)).await;
    prom.edit(|s| s.delay_s = 2.0);
    let t = prom.telemetry();
    let mut fake = one_window(NOW - 30.0 * 86400.0);
    let payload = dashboard(&t, &mut fake, &[row("a")]).await;
    assert_eq!(payload.telemetry, "unavailable");
    assert_eq!(prom.calls().len(), 3); // 2 s each: the third ends after 5 s
    let sent = timeouts(&prom);
    assert_eq!(sent, ["4s", "3s", "1s"]); // at most the configured 4 s, then what is left
    assert_eq!(sent.last().map(String::as_str), Some("1s")); // only what was left of the budget
    // deviation: one page's budget is its own; the next page asks Prometheus (no cool-down)
    prom.edit(|s| s.delay_s = 0.0);
    assert!(t.page().budget.unwrap().vector("up", None, 15.0).await.is_ok());
    assert_eq!(prom.calls().len(), 4);
}

#[tokio::test]
async fn test_prometheus_is_told_the_timeout() {
    let prom = FakePrometheus::start(vec![h("up", vector(&[(json!({}), json!(1))]))]).await;
    let client = prom.client();
    client.within().vector("up", None, 15.0).await.unwrap();
    assert_eq!(prom.calls()[0].1.get("timeout").map(String::as_str), Some("4s"));
    // not part of the cache key: a page with less time left gets the cached answer
    client.within_s(1.5).vector("up", None, 15.0).await.unwrap();
    assert_eq!(prom.calls().len(), 1);
}

#[tokio::test]
async fn test_a_fast_prometheus_fits() {
    let prom = FakePrometheus::start(live(true)).await;
    prom.edit(|s| s.delay_s = 0.01);
    let payload = dashboard(&prom.telemetry(), &mut one_window(NOW - 30.0 * 86400.0), &[row("a")]).await;
    assert_eq!(payload.telemetry, "ok");
}

// --- ReplyShapeTests --------------------------------------------------------------------------------------------------

#[tokio::test]
async fn test_malformed_items_are_unavailable() {
    for result in [
        json!([{"metric": {"a": 1}, "value": [1, "1"]}]),
        json!([{"metric": {}, "value": "x"}]),
        json!([{"metric": {}}]),
        json!(["x"]),
        Value::Null,
    ] {
        let prom =
            FakePrometheus::start(vec![h("up", json!({"resultType": "vector", "result": result.clone()}))]).await;
        assert!(prom.client().within().vector("up", None, 15.0).await.is_err(), "{result}");
    }
    let prom = FakePrometheus::start(vec![h(
        "up",
        json!({"resultType": "matrix", "result": [{"metric": {}, "values": [["t", "1"]]}]}),
    )])
    .await;
    assert!(prom.client().within().matrix("up[5m:1m]", None, 15.0).await.is_err());
}

#[tokio::test]
async fn test_not_json_or_not_a_dict() {
    let prom = FakePrometheus::start(vec![]).await;
    prom.edit(|s| s.raw = Some((200, "[\"x\"]".into())));
    assert!(prom.client().within().vector("up", None, 15.0).await.is_err());
}

// --- CacheTests -------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn test_one_fetch_per_query_at_a_time() {
    let prom = FakePrometheus::start(vec![h("up", vector(&[(json!({}), json!(1))]))]).await;
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    if let Ok(mut g) = prom.gate.lock() {
        *g = Some(gate.clone());
    }
    let client = prom.client();
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..5 {
        let budget = client.within();
        tasks.spawn(async move { budget.vector("up", None, 15.0).await });
    }
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    gate.add_permits(10);
    let mut results = Vec::new();
    while let Some(r) = tasks.join_next().await {
        results.push(r.expect("task").expect("answer"));
    }
    assert_eq!(prom.calls().len(), 1);
    assert_eq!(results, vec![vec![(Default::default(), Some(1.0))]; 5]);
}

#[tokio::test]
async fn test_summaries_live_a_minute() {
    let prom = FakePrometheus::start(live(true)).await;
    let client = prom.client();
    let macs = [MAC_A.to_string()];
    device_status(&client.within(), &macs, &Default::default(), NOW).await.unwrap();
    prom.clock.advance(20.0);
    device_status(&client.within(), &macs, &Default::default(), NOW).await.unwrap();
    assert_eq!(prom.queries("[24h:5m]").len(), 1);
    assert_eq!(prom.queries("max by (mac, radio)").len(), 1);
    assert_eq!(prom.queries("unpoller_client_radio_signal_db").len(), 2);
    prom.clock.advance(41.0);
    device_status(&client.within(), &macs, &Default::default(), NOW).await.unwrap();
    assert_eq!(prom.queries("[24h:5m]").len(), 2);
}

// --- new: the client's deliberate deviations ----------------------------------------------------------------------------

/// Each caller's TTL counts: a 15 s caller does not get a 60 s caller's older answer (Python: the
/// first caller's TTL decided).
#[tokio::test]
async fn test_each_callers_ttl_counts() {
    let prom = FakePrometheus::start(vec![h("up", vector(&[(json!({}), json!(1))]))]).await;
    let client = prom.client();
    client.within().vector("up", None, 60.0).await.unwrap();
    prom.clock.advance(20.0);
    client.within().vector("up", None, 60.0).await.unwrap(); // the 60 s caller: cached
    assert_eq!(prom.calls().len(), 1);
    client.within().vector("up", None, 15.0).await.unwrap(); // the 15 s caller: too old for it
    assert_eq!(prom.calls().len(), 2);
}

/// A request cut short by the page's budget that times out says nothing about Prometheus: no
/// cool-down for the other pages.
#[tokio::test]
async fn test_a_budget_cut_timeout_does_not_cool_down() {
    // a server that accepts and never answers
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((sock, _)) = listener.accept().await {
            held.push(sock);
        }
    });
    let clock = FakeClock::new();
    let client =
        crate::telemetry::client::Prometheus::with_clock(&url, std::time::Duration::from_secs(4), SSID, clock.clock())
            .unwrap();
    // 0.2 s left of the page's budget: the request times out after 0.2 s
    assert!(client.within_s(0.2).vector("up", None, 15.0).await.is_err());
    let err = client.within_s(0.2).vector("up", None, 15.0).await.unwrap_err();
    assert_ne!(err, Unavailable("failed less than 15 s ago".into()));
    assert_eq!(client.queries_total(), (0, 2));
}

#[test]
fn test_band_codes() {
    assert_eq!(
        (common::band(Some("ng")), common::band(Some("6e")), common::band(Some("be"))),
        (Some("2.4"), Some("6"), None)
    );
    assert_eq!(common::radio_of(Some("5")), Some("na"));
}

#[tokio::test]
async fn test_redirects_are_not_followed_and_answers_are_bounded() {
    // security review 2026-10-29 I3
    let target = FakePrometheus::start(vec![h("up", vector(&[(json!({}), json!(1))]))]).await;
    let location = format!("{}/api/v1/query", target.url);
    let app = axum::Router::new().fallback(move || {
        let location = location.clone();
        async move { (axum::http::StatusCode::TEMPORARY_REDIRECT, [(axum::http::header::LOCATION, location)]) }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("addr"));
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    let redirecting =
        crate::telemetry::client::Prometheus::new(&url, std::time::Duration::from_secs(2), "S").expect("client");
    assert!(redirecting.within().vector("up", None, 15.0).await.is_err());
    assert!(target.calls().is_empty(), "the redirect was followed");
    // an answer over MAX_ANSWER is refused, not read into memory
    let huge = FakePrometheus::start(vec![]).await;
    let body = format!(
        r#"{{"status":"success","data":{{"resultType":"vector","result":[]}},"pad":"{}"}}"#,
        "x".repeat(crate::telemetry::client::MAX_ANSWER)
    );
    huge.edit(|s| s.raw = Some((200, body)));
    assert_eq!(
        huge.client().within().vector("up", None, 15.0).await.err().map(|e| e.0),
        Some("answer too large".to_string())
    );
}
