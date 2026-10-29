//! Python tests/test_telemetry_v2.py: the timeline merge across sources, the history stitched
//! over MAC windows, the day ranges from the rollups, and the DEVICE additions of the dashboard.

use std::collections::{BTreeSet, HashMap};

use netportal_core::registry::{AuthEvent, AuthFailure, DeviceDay, DeviceRow};
use serde_json::{Value, json};
use sqlx::types::Json;

use super::fakes::*;
use crate::telemetry::Telemetry;
use crate::telemetry::common::iso;
use crate::telemetry::history::{
    self, CHARTS, HistoryOptions, Range, local_day, local_midnight, relevant_incidents, zone,
};
use crate::telemetry::identity::{CURRENT_WINDOW_S, Identity, WINDOW_GRACE_S, Window};
use crate::telemetry::live::{self, DashboardOptions};
use crate::telemetry::timeline::{self as tl, ApMap, Basis, Inferred};

const AP1: &str = "ap-scharni-2-corner";
const AP2: &str = "ap-colbe-2-far";
const AP1_MAC: &str = "60:22:32:37:48:00";
const AP2_MAC: &str = "68:d7:9a:1c:61:46";
const AP1_BSSID: &str = "60:22:32:38:48:00";
const AP2_BSSID: &str = "68:d7:9a:1d:61:46";
const M1: &str = "02:00:00:00:00:0a";
const M2: &str = "02:00:00:00:00:0b";
const M3: &str = "02:00:00:00:00:0c";
const END: f64 = NOW; // NOW // 60 * 60

fn aps() -> ApMap {
    ApMap {
        bssids: HashMap::from([
            (AP1_BSSID.into(), (Some(AP1.into()), Some(AP1_MAC.into()), Some("5"))),
            (AP2_BSSID.into(), (Some(AP2.into()), Some(AP2_MAC.into()), Some("5"))),
        ]),
        nas: HashMap::from([("10.0.10.27".into(), (AP1.into(), AP1_MAC.into()))]),
        names: HashMap::from([(AP1_MAC.into(), AP1.into()), (AP2_MAC.into(), AP2.into())]),
    }
}

fn kinds(events: &[tl::Event]) -> Vec<&'static str> {
    events.iter().map(|e| e.kind).collect()
}

fn ev(kind: &'static str, at: f64, ap: &str, band: &'static str, mac: &str) -> Inferred {
    Inferred {
        kind,
        at,
        ap: Some(ap.into()),
        band: Some(band),
        from_ap: None,
        from_band: None,
        duration_s: None,
        mac: Some(mac.into()),
    }
}

fn a1(started: f64) -> netportal_core::registry::AcctSession {
    acct(Some(started), None, AP1_BSSID, None, "s1", "class", M1)
}

fn u(at: f64, kind: &str) -> netportal_core::registry::ConnectionEvent {
    unifi(at, kind, Some(AP1), Some(AP1_MAC), None, None, M1, "na")
}

// --- MergeTests -----------------------------------------------------------------------------------------

#[test]
fn test_the_same_connection_from_three_sources_is_one_event() {
    let t = NOW - 3600.0;
    let mut events = tl::from_presence(&[ev("connected", t + 50.0, AP1, "5", M1)]);
    events.extend(tl::from_acct(&[a1(t + 5.0)], &aps()));
    events.extend(tl::from_unifi(&[u(t, "connected")], &aps()));
    let (merged, truncated) = tl::merge(events, Some(tl::MAX_EVENTS));
    assert!(!truncated);
    assert_eq!(kinds(&merged), ["connected"]);
    let e = &merged[0];
    assert_eq!(e.sources, ["unifi_syslog", "radius_acct", "prometheus"]);
    assert_eq!((e.source.as_str(), e.basis, e.at), ("unifi_syslog", Basis::Measured, t)); // measured wins
    assert_eq!(e.detail["rssi"], json!(-60));
    assert_eq!(e.detail["framed_ip"], json!("10.30.0.5")); // filled in
}

#[test]
fn test_events_further_apart_or_on_other_aps_stay_apart() {
    let t = NOW - 3600.0;
    let mut events = tl::from_unifi(&[u(t, "connected")], &aps());
    events.extend(tl::from_acct(&[a1(t + 300.0)], &aps()));
    let roam = Inferred { from_ap: Some(AP1.into()), from_band: Some("5"), ..ev("roamed", t + 10.0, AP2, "5", M1) };
    events.extend(tl::from_presence(&[roam]));
    let (merged, _) = tl::merge(events, Some(tl::MAX_EVENTS));
    assert_eq!(kinds(&merged), ["connected", "roamed", "connected"]);
}

#[test]
fn test_measured_beats_inferred() {
    let t = NOW - 7200.0;
    let inferred =
        tl::from_presence(&[Inferred { duration_s: Some(600), ..ev("disconnected", t + 30.0, AP1, "5", M1) }]);
    let mut events = inferred.clone();
    events.extend(tl::from_unifi(&[u(t, "disconnected")], &aps()));
    let (merged, _) = tl::merge(events, Some(tl::MAX_EVENTS));
    assert_eq!(merged.len(), 1);
    assert_eq!((merged[0].basis, merged[0].source.as_str()), (Basis::Measured, "unifi_syslog"));
    assert_eq!(merged[0].duration_s, Some(600)); // what the measured one lacked
    // an inferred disconnect covered by an accounting Stop is dropped (its source noted)
    let mut events = inferred;
    events.extend(tl::from_acct(
        &[acct(Some(t - 3600.0), Some(t), AP1_BSSID, Some("User-Request"), "s1", "class", M1)],
        &aps(),
    ));
    let (merged, _) = tl::merge(events, Some(tl::MAX_EVENTS));
    assert_eq!(kinds(&merged), ["connected", "session_ended"]);
    assert_eq!(merged[1].detail["cause"], json!("User-Request"));
    assert!(merged[1].sources.contains(&"prometheus".to_string()));
}

#[test]
fn test_accounting_stop_causes_and_roams() {
    let t = NOW - 7200.0;
    let sessions = [
        acct(Some(t), Some(t + 600.0), AP1_BSSID, Some("Lost-Carrier"), "a", "class", M1),
        acct(Some(t + 630.0), Some(t + 1200.0), AP2_BSSID, Some("User-Request"), "b", "class", M1),
        acct(Some(t + 1260.0), Some(t + 2000.0), AP2_BSSID, Some("Idle-Timeout"), "c", "class", M1),
        acct(Some(t + 5000.0), Some(t + 6000.0), AP1_BSSID, Some("NAS-Reboot"), "d", "class", M1),
    ];
    let events = tl::from_acct(&sessions, &aps());
    assert_eq!(kinds(&events), ["connected", "roamed", "reconnected", "session_ended", "connected", "session_ended"]);
    let roam = &events[1];
    assert_eq!(
        (roam.ap.as_deref(), roam.from_ap.as_deref(), roam.detail["from_cause"].clone()),
        (Some(AP2), Some(AP1), json!("Lost-Carrier"))
    );
    assert_eq!(events[2].detail["gap_s"], json!(60));
    assert_eq!(events[3].detail["cause"], json!("Idle-Timeout"));
    assert_eq!(
        (events[3].detail["rx_bytes"].clone(), events[3].detail["tx_bytes"].clone()),
        (json!(9000), json!(1000))
    );
    assert_eq!(events[5].detail["cause"], json!("NAS-Reboot"));
    let d: Vec<(f64, Basis, Option<String>, Option<String>)> =
        tl::disconnects(&events, None).into_iter().map(|d| (d.at, d.basis, d.source, d.cause)).collect();
    let m = |at: f64, cause: &str| (at, Basis::Measured, Some("radius_acct".to_string()), Some(cause.to_string()));
    assert_eq!(d, [m(t + 1260.0, "User-Request"), m(t + 2000.0, "Idle-Timeout"), m(t + 6000.0, "NAS-Reboot")]);
}

#[test]
fn test_a_unifi_roam_between_radios_is_a_band_change() {
    let events = tl::from_unifi(
        &[unifi(NOW - 60.0, "roamed", Some(AP1), Some(AP1_MAC), Some(AP1), Some(AP1_MAC), M1, "ng")],
        &aps(),
    );
    assert_eq!((events[0].kind, events[0].band), ("band_changed", Some("2.4")));
}

#[test]
fn test_a_disconnect_and_a_connection_close_together_are_a_reconnect() {
    let t = NOW - 600.0;
    let rows = [u(t, "disconnected"), unifi(t + 40.0, "connected", Some(AP2), Some(AP2_MAC), None, None, M2, "na")];
    let (merged, _) = tl::merge(tl::from_unifi(&rows, &aps()), Some(tl::MAX_EVENTS));
    assert_eq!(kinds(&merged), ["reconnected"]);
    let r = &merged[0];
    assert_eq!(
        (r.from_ap.as_deref(), r.ap.as_deref(), r.detail["gap_s"].clone(), r.detail["from_mac"].clone()),
        (Some(AP1), Some(AP2), json!(40), json!(M1))
    );
    assert_eq!(r.basis, Basis::Measured);
}

#[test]
fn test_authentication_and_rejects() {
    let rows = [
        AuthEvent { bssid: Some(AP1_BSSID.into()), ..auth_event(NOW - 100.0, "accept", "ok", M1, "device") },
        auth_event(NOW - 50.0, "reject", "expired", M1, "device"),
    ];
    let events = tl::from_auth(&rows, &aps());
    assert_eq!(kinds(&events), ["authenticated", "auth_rejected"]);
    assert_eq!(
        (events[0].ap.as_deref(), events[0].ap_mac.as_deref(), events[0].band),
        (Some(AP1), Some(AP1_MAC), Some("5"))
    );
    assert_eq!(events[1].ap.as_deref(), Some(AP1)); // from the NAS when no BSSID
    assert_eq!(events[1].detail["reason"], json!("expired"));
}

fn w(mac: &str, first: f64, last: f64) -> Window {
    Window {
        mac: mac.into(),
        start: first,
        end: Some(last),
        first_seen: first,
        last_seen: last,
        randomized: true,
        auth_count: Some(1),
        current: false,
    }
}

#[test]
fn test_mac_changes() {
    let identity = Identity::new(
        "a",
        vec![
            w(M1, NOW - 5.0 * 86400.0, NOW - 4.0 * 86400.0),
            w(M2, NOW - 3.0 * 86400.0, NOW - 2.0 * 86400.0),
            w(M3, NOW - 3600.0, NOW),
        ],
        vec![],
        false,
        NOW,
    );
    let events = tl::from_windows(&identity, NOW - 4.0 * 86400.0, NOW);
    let got: Vec<(&str, Option<&str>, Value, Basis)> =
        events.iter().map(|e| (e.kind, e.mac.as_deref(), e.detail["from_mac"].clone(), e.basis)).collect();
    assert_eq!(
        got,
        [("mac_changed", Some(M2), json!(M1), Basis::Inferred), ("mac_changed", Some(M3), json!(M2), Basis::Inferred)]
    );
}

#[test]
fn test_bounded_sorted_and_flagged() {
    let mut rows: Vec<_> = (0..30)
        .map(|i| {
            let kind = if i % 2 == 1 { "connected" } else { "roamed" };
            unifi(
                NOW - 10000.0 + f64::from(i) * 300.0,
                kind,
                Some(AP1),
                Some(AP1_MAC),
                Some(AP2),
                Some(AP2_MAC),
                M1,
                "na",
            )
        })
        .collect();
    rows.reverse();
    let (merged, truncated) = tl::merge(tl::from_unifi(&rows, &aps()), Some(10));
    assert!(truncated);
    assert_eq!(merged.len(), 10);
    let at: Vec<f64> = merged.iter().map(|e| e.at).collect();
    let mut sorted = at.clone();
    sorted.sort_by(f64::total_cmp);
    assert_eq!(at, sorted);
    assert_eq!(merged.last().map(|e| e.at), Some(NOW - 10000.0 + 29.0 * 300.0)); // the latest kept
}

fn conflict(mac: &str, owners: i64, from: f64, to: f64) -> crate::telemetry::identity::Conflict {
    crate::telemetry::identity::Conflict { mac: mac.into(), other_owners: owners, from: Some(from), to: Some(to) }
}

#[test]
fn test_conflicts_withhold_mac_events_from_residents_and_mark_them_for_admins() {
    let conflicts = vec![conflict(M1, 2, NOW - 7200.0, NOW - 3600.0)];
    let mut events = tl::from_unifi(&[u(NOW - 5000.0, "connected"), u(NOW - 100.0, "disconnected")], &aps());
    events.extend(tl::from_auth(&[auth_event(NOW - 5000.0, "accept", "ok", M1, "device")], &ApMap::default()));
    events.extend(tl::from_acct(
        &[
            acct(Some(NOW - 4000.0), None, AP1_BSSID, None, "s1", "mac_window", M1),
            acct(Some(NOW - 4100.0), None, AP1_BSSID, None, "x", "class", M1),
        ],
        &aps(),
    ));
    let resident = tl::restrict(events.clone(), Some(&Identity::new("a", vec![], conflicts.clone(), false, NOW)));
    let mut got: Vec<(&str, String)> = resident.iter().map(|e| (e.kind, e.source.clone())).collect();
    got.sort();
    assert_eq!(
        got,
        [
            ("authenticated", "radius_auth".into()),
            ("connected", "radius_acct".into()),
            ("disconnected", "unifi_syslog".into())
        ]
    );
    let admin = tl::restrict(events.clone(), Some(&Identity::new("a", vec![], conflicts, true, NOW)));
    assert_eq!(admin.len(), events.len());
    assert_eq!(admin[0].detail["conflict"], json!(2));
}

#[test]
fn test_a_reject_found_by_the_mac_alone_is_withheld_in_a_conflict() {
    let conflicts = vec![conflict(M1, 1, NOW - 7200.0, NOW - 3600.0)];
    let rows = [
        AuthEvent {
            tries: 7,
            last_at: Some(dt(NOW - 4900.0)),
            ..auth_event(NOW - 5000.0, "reject", "no_cert", M1, "mac")
        },
        auth_event(NOW - 4800.0, "reject", "revoked", M1, "device"),
        auth_event(NOW - 600.0, "reject", "no_cert", M1, "mac"),
    ];
    let events = tl::from_auth(&rows, &ApMap::default());
    let got: Vec<(Value, Value)> =
        events.iter().map(|e| (e.detail["match"].clone(), e.detail["count"].clone())).collect();
    assert_eq!(got, [(json!("mac"), json!(7)), (json!("device"), json!(1)), (json!("mac"), json!(1))]);
    assert_eq!(events[0].detail["last_at"], json!(iso(Some(NOW - 4900.0))));
    assert!(!events[1].detail.contains_key("last_at"));
    let resident = tl::restrict(events.clone(), Some(&Identity::new("a", vec![], conflicts.clone(), false, NOW)));
    let reasons: Vec<Value> = resident.iter().map(|e| e.detail["reason"].clone()).collect();
    assert_eq!(reasons, [json!("revoked"), json!("no_cert")]); // outside: kept
    let admin = tl::restrict(events, Some(&Identity::new("a", vec![], conflicts.clone(), true, NOW)));
    let marks: Vec<Option<Value>> = admin.iter().map(|e| e.detail.get("conflict").cloned()).collect();
    assert_eq!(marks, [Some(json!(1)), Some(json!(1)), None]);
    // a row whose match is neither (no "device") is not taken as the device's own
    let bare = tl::from_auth(&[auth_event(NOW - 5000.0, "accept", "ok", M1, "")], &ApMap::default());
    assert!(tl::restrict(bare, Some(&Identity::new("a", vec![], conflicts, false, NOW))).is_empty());
}

#[test]
fn test_public_shape() {
    let e =
        serde_json::to_value(tl::public(&tl::from_unifi(&[u(NOW - 60.0, "connected")], &aps()))).unwrap()[0].clone();
    let keys: BTreeSet<&str> = e.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        BTreeSet::from([
            "kind",
            "at",
            "source",
            "sources",
            "basis",
            "ap",
            "band",
            "from_ap",
            "from_band",
            "mac",
            "duration_s",
            "detail"
        ])
    );
    assert_eq!(e["ap"], json!({"name": AP1, "house": "scharni", "floor": 2, "spot": "corner", "mac": AP1_MAC}));
    assert_eq!(e["at"], json!(iso(Some(NOW - 60.0))));
}

// --- IncidentTests ----------------------------------------------------------------------------------------

#[test]
fn test_relevant_incidents() {
    let mut switch = incident(5, "switch_port_down", "sw1:3", None, NOW, None);
    switch.detail = Json(json!({"ap_macs": [AP1_MAC]}));
    let rows = vec![
        incident(1, "internet_down", "", None, NOW, None),
        incident(2, "ap_restarted", AP1_MAC, Some(AP1), NOW, None),
        incident(3, "ap_down", AP2_MAC, Some(AP2), NOW, None),
        incident(4, "ap_down", "aa:aa:aa:aa:aa:aa", Some(AP2), NOW, None),
        switch,
    ];
    let ids = |macs: &[&str], names: &[&str]| -> Vec<i64> {
        let macs: BTreeSet<String> = macs.iter().map(|s| s.to_string()).collect();
        let names: BTreeSet<String> = names.iter().map(|s| s.to_string()).collect();
        relevant_incidents(&rows, &macs, &names).into_iter().map(|r| r.id).collect()
    };
    assert_eq!(ids(&[AP1_MAC], &[]), [1, 2, 5]);
    assert_eq!(ids(&[], &[&AP2.to_lowercase()]), [1, 3, 4]);
}

// --- HistoryCase / StitchingTests ----------------------------------------------------------------------------

/// A device with two (rotating) MACs: M1 until 12 h ago, M2 since 10 h ago; the fake Prometheus has
/// data for both MACs for the whole day (M1's after its window is someone else's, M2's before its
/// window was nobody's).
fn case() -> FakeRegistry {
    let mut fake = FakeRegistry::new();
    fake.windows.insert(
        id("a"),
        vec![
            Win { randomized: true, ..window(M1, NOW - 30.0 * 86400.0, END - 12.0 * 3600.0 - WINDOW_GRACE_S) },
            Win { randomized: true, ..window(M2, END - 10.0 * 3600.0, NOW - 60.0) },
        ],
    );
    fake
}

fn prometheus(extra: Vec<(String, Value)>) -> Vec<(String, Value)> {
    let start = END - 86400.0;
    let grid: Vec<f64> = (0..).map(|i| start - 300.0 + 60.0 + 60.0 * f64::from(i)).take_while(|t| *t <= END).collect();
    let chart = |v: i64| (0..=288).map(|i| (start + 300.0 * f64::from(i), json!(v))).collect::<Vec<_>>();
    let mut out = extra;
    out.extend([
        h(
            "max(unpoller_prometheus_cache_age_seconds{job=\"unifi\"})[",
            matrix(&[(json!({}), grid.iter().map(|t| (*t, json!(30))).collect())]),
        ),
        h(
            "max by (mac, ap_name, radio) (timestamp(",
            matrix(&[
                (
                    json!({"mac": M1, "ap_name": AP1, "radio": "na"}),
                    grid.iter().map(|t| (*t, json!(start - 3600.0))).collect(),
                ),
                (
                    json!({"mac": M2, "ap_name": AP2, "radio": "na"}),
                    grid.iter().map(|t| (*t, json!(start - 7200.0))).collect(),
                ),
            ]),
        ),
        h(
            "unpoller_client_radio_signal_db",
            matrix(&[(json!({"mac": M1}), chart(-50)), (json!({"mac": M2}), chart(-70))]),
        ),
        h(
            "rate(unpoller_client_transmit_bytes_total",
            matrix(&[(json!({"mac": M1}), chart(1000)), (json!({"mac": M2}), chart(2000))]),
        ),
    ]);
    out
}

async fn run(
    t: &Telemetry,
    fake: &mut FakeRegistry,
    range: Range,
    admin: bool,
    tz: Option<jiff::tz::TimeZone>,
) -> history::History {
    let opts = HistoryOptions { admin, now: Some(NOW), tz, ..HistoryOptions::default() };
    history::history(&t.page(), fake, &row("a"), range, opts).await.expect("history")
}

async fn hist(
    fake: &mut FakeRegistry,
    range: Range,
    admin: bool,
    extra: Vec<(String, Value)>,
) -> (history::History, FakePrometheus) {
    let prom = FakePrometheus::start(prometheus(extra)).await;
    let h = run(&prom.telemetry(), fake, range, admin, None).await;
    (h, prom)
}

fn at(series: &history::Series, t: f64) -> Option<f64> {
    series.iter().find(|(x, _)| *x == t as i64).and_then(|(_, v)| v.map(|v| v.as_f64()))
}

#[tokio::test]
async fn test_one_by_mac_query_per_chart_for_both_macs() {
    let (_h, prom) = hist(&mut case(), Range::H24, false, vec![]).await;
    let sel = format!("mac=~\"{M1}|{M2}\"");
    let ranges = prom.ranges();
    assert_eq!(ranges.len(), CHARTS.len());
    for p in ranges {
        let q = p.get("query").cloned().unwrap_or_default();
        assert!(q.contains(&sel) && q.contains("by (mac)"), "{q}");
    }
    for q in prom.queries("unpoller_client_") {
        assert!(q.contains("essid=\"Example\""), "{q}");
    }
}

#[tokio::test]
async fn test_each_macs_data_only_in_its_window() {
    let (h, _) = hist(&mut case(), Range::H24, false, vec![]).await;
    let signal = &h.series["signal_dbm"];
    assert_eq!(at(signal, END - 13.0 * 3600.0), Some(-50.0)); // M1's time
    assert_eq!(at(signal, END - 11.0 * 3600.0), None); // between the windows: nobody's
    assert_eq!(at(signal, END - 3600.0), Some(-70.0)); // M2's time
    assert_eq!(at(&h.series["rx_bps"], END - 3600.0), Some(2000.0)); // not summed with M1
    assert_eq!(at(&h.series["online"], END - 11.0 * 3600.0), None);
    assert_eq!(at(&h.series["online"], END - 3600.0), Some(1.0));
    assert_eq!(h.data_from, Some((NOW - 30.0 * 86400.0) as i64));
    assert!(h.timeline.iter().any(|e| e.kind == "mac_changed" && e.mac.as_deref() == Some(M2)));
    let sources: Vec<&str> = h.timeline.iter().filter(|e| e.kind == "mac_changed").map(|e| e.source.as_str()).collect();
    assert_eq!(sources, ["device_mac"]);
    assert!(h.timeline.iter().all(|e| matches!(e.mac.as_deref(), Some(M1) | Some(M2) | None)));
}

#[tokio::test]
async fn test_a_recycled_mac_before_its_owners_window_is_not_shown() {
    let (h, _) = hist(&mut case(), Range::H24, false, vec![]).await;
    for (t, v) in &h.series["signal_dbm"] {
        if (*t as f64) < END - 10.0 * 3600.0 - 300.0 {
            assert!(matches!(v.map(|v| v.as_f64()), None | Some(-50.0)), "{t}");
        }
    }
}

#[tokio::test]
async fn test_withheld_spans_for_residents_marked_for_admins() {
    let mut fake = case();
    fake.conflicts.insert(id("a"), vec![clash(M2, 1, END - 4.0 * 3600.0, Some(END - 2.0 * 3600.0))]);
    let (h, _) = hist(&mut fake, Range::H24, false, vec![]).await;
    assert_eq!(at(&h.series["signal_dbm"], END - 3.0 * 3600.0), None);
    assert_eq!(at(&h.series["signal_dbm"], END - 3600.0), Some(-70.0));
    assert_eq!(
        serde_json::to_value(&h.withheld_spans).unwrap(),
        json!([{"mac": M2, "from": iso(Some(END - 4.0 * 3600.0)), "to": iso(Some(END - 2.0 * 3600.0))}])
    );
    assert!(h.conflicts.is_empty());
    let (h, _) = hist(&mut fake, Range::H24, true, vec![]).await;
    assert_eq!(at(&h.series["signal_dbm"], END - 3.0 * 3600.0), Some(-70.0));
    assert_eq!(h.conflicts[0].other_owners, Some(1));
}

#[tokio::test]
async fn test_all_withheld_asks_nothing() {
    let mut fake = FakeRegistry::new();
    fake.windows.insert(id("a"), vec![window(M2, NOW - 86400.0, NOW - 60.0)]);
    fake.conflicts.insert(id("a"), vec![clash(M2, 1, NOW - 2.0 * 86400.0, None)]);
    let (h, prom) = hist(&mut fake, Range::H24, false, vec![]).await;
    assert_eq!(h.withheld, Some("mac_conflict"));
    assert!(h.timeline.is_empty() && prom.calls().is_empty());
    assert!(h.series.values().all(Vec::is_empty));
}

#[tokio::test]
async fn test_registry_events_and_incidents_join_the_timeline() {
    let mut fake = case();
    fake.events
        .insert(id("a"), vec![unifi(END - 1800.0, "disconnected", Some(AP2), Some(AP2_MAC), None, None, M2, "na")]);
    fake.incidents = vec![
        incident(7, "ap_restarted", AP2_MAC, Some(AP2), END - 1850.0, Some(END - 1700.0)),
        incident(8, "ap_restarted", "aa:aa:aa:aa:aa:aa", Some("ap-x-1-y"), END - 1850.0, Some(END - 1700.0)),
    ];
    let (h, _) = hist(&mut fake, Range::H24, false, vec![]).await;
    let ids: Vec<Value> = h.timeline.iter().filter(|e| e.kind == "incident").map(|e| e.detail["id"].clone()).collect();
    assert_eq!(ids, [json!(7)]);
    assert!(h.sources.contains(&"unifi_syslog".to_string()) && h.sources.contains(&"incident".to_string()));
    assert_eq!(fake.called("auth_events").len(), 1);
    assert_eq!(fake.called("connection_events")[0].limit, Some(2000)); // bounded
}

#[tokio::test]
async fn test_logins_are_placed_at_their_ap_by_bssid() {
    let mut fake = case();
    let login = AuthEvent {
        bssid: Some(AP2_BSSID.into()),
        nas_ip: Some("10.0.10.47".into()),
        ..auth_event(END - 600.0, "accept", "ok", M2, "device")
    };
    fake.auth.insert(id("a"), vec![login]);
    let vaps = h(
        "max by (bssid, mac, name, radio) (unpoller_device_vap_transmit_power",
        vector(&[(json!({"bssid": AP2_BSSID, "mac": AP2_MAC, "name": AP2, "radio": "na"}), json!(17))]),
    );
    let (hist, _) = hist(&mut fake, Range::H24, false, vec![vaps]).await;
    let login = hist.timeline.iter().find(|e| e.kind == "authenticated").unwrap();
    let ap = login.ap.as_ref().unwrap();
    assert_eq!((ap.name.as_deref(), ap.mac.as_deref(), login.band), (Some(AP2), Some(AP2_MAC), Some("5")));
    assert_eq!(login.detail["bssid"], json!(AP2_BSSID));
}

#[tokio::test]
async fn test_prometheus_down_keeps_the_registrys_events() {
    let mut fake = case();
    fake.events.insert(id("a"), vec![unifi(END - 1800.0, "connected", Some(AP1), Some(AP1_MAC), None, None, M2, "na")]);
    let (client, clock) = down_client().await;
    let t = Telemetry::with_clock(Some(client), SSID, clock.clock());
    let h = run(&t, &mut fake, Range::H24, false, None).await;
    assert_eq!(h.telemetry, "unavailable");
    let kinds: Vec<&str> = h.timeline.iter().map(|e| e.kind).collect();
    assert_eq!(kinds, ["mac_changed", "connected"]);
}

#[tokio::test]
async fn test_90_days() {
    let (h, prom) = hist(&mut case(), Range::D90, false, vec![]).await;
    assert_eq!((h.step_s, h.step, h.series["online"].len()), (21600, None, 361));
    assert!(prom.ranges().iter().all(|p| p.get("step").map(String::as_str) == Some("21600")));
}

// --- DayRangeTests -----------------------------------------------------------------------------------------------

fn day_row(day: time::Date) -> DeviceDay {
    DeviceDay {
        device_id: id("a"),
        day,
        online_s: None,
        stale_s: None,
        signal_avg_dbm: None,
        signal_p10_dbm: None,
        snr_avg_db: None,
        health_avg: None,
        health_min: None,
        retry_ratio_avg: None,
        rx_bytes: None,
        tx_bytes: None,
        link_rx_avg_bps: None,
        roams: None,
        reconnects: None,
        disconnects: None,
        aps: Json(json!({})),
        bands: Json(json!({})),
        macs: None,
        auth_ok: None,
        auth_failed: None,
        computed_at: None,
    }
}

fn days() -> (jiff::tz::TimeZone, jiff::civil::Date, Vec<DeviceDay>) {
    let tz = zone(Some("Europe/Berlin"));
    let today = local_day(END as i64, &tz);
    let back = |n: i64| history::to_civil_time(today.checked_sub(jiff::Span::new().days(n)).unwrap());
    let rows = vec![
        DeviceDay {
            online_s: Some(43200),
            stale_s: Some(0),
            signal_avg_dbm: Some(-61.26),
            signal_p10_dbm: Some(-70.04),
            snr_avg_db: Some(35.0),
            health_avg: Some(90.0),
            retry_ratio_avg: Some(0.031),
            rx_bytes: Some(8_640_000_000),
            tx_bytes: Some(864_000_000),
            link_rx_avg_bps: Some(400e6),
            ..day_row(back(1))
        },
        DeviceDay { online_s: Some(3600), stale_s: Some(82800), signal_avg_dbm: Some(-70.0), ..day_row(back(3)) },
    ];
    (tz, today, rows)
}

fn midnight(today: jiff::civil::Date, back: i64, tz: &jiff::tz::TimeZone) -> f64 {
    local_midnight(today.checked_sub(jiff::Span::new().days(back)).unwrap(), tz) as f64
}

#[tokio::test]
async fn test_a_year_from_the_rollups() {
    let (tz, today, rows) = days();
    let mut fake = case();
    fake.days.insert(id("a"), rows);
    let prom = FakePrometheus::start(prometheus(vec![])).await;
    let h = run(&prom.telemetry(), &mut fake, Range::Y1, false, Some(tz.clone())).await;
    assert_eq!((h.range, h.step, h.step_s), ("1y", Some("day"), 86400));
    assert!(prom.ranges().is_empty()); // no Prometheus charts
    assert_eq!(h.series["online"].len(), 365);
    let t_yesterday = midnight(today, 1, &tz);
    assert_eq!(at(&h.series["signal_dbm"], t_yesterday), Some(-61.3));
    assert_eq!(at(&h.series["signal_p10_dbm"], t_yesterday), Some(-70.0));
    assert_eq!(h.timeline_days, None); // a year: all of it
    assert_eq!(at(&h.series["online"], t_yesterday), Some(0.5));
    assert_eq!(at(&h.series["rx_bps"], t_yesterday), Some(800_000.0)); // 8.64 GB a day: 0.8 Mbit/s
    let t3 = midnight(today, 3, &tz);
    assert_eq!(at(&h.series["online"], t3), Some(1.0)); // an hour of the hour with fresh data
    assert_eq!(at(&h.series["signal_dbm"], t3 - 86400.0), None);
    assert_eq!(h.start, h.series["online"][0].0);
    assert!(h.sources.contains(&"device_day".to_string()));
    let first = history::to_civil_time(today.checked_sub(jiff::Span::new().days(364)).unwrap());
    assert_eq!(fake.called("device_days")[0].days.map(|d| d.0), Some(first));
}

#[tokio::test]
async fn test_all_since_the_first_window() {
    let (tz, _, rows) = days();
    let mut fake = case();
    fake.days.insert(id("a"), rows);
    let prom = FakePrometheus::start(prometheus(vec![])).await;
    let h = run(&prom.telemetry(), &mut fake, Range::All, false, Some(tz)).await;
    assert_eq!(h.series["online"].len(), 31); // the first window is 30 days old
}

#[tokio::test]
async fn test_timeline_days() {
    let mut fake = FakeRegistry::new();
    fake.windows.insert(id("a"), vec![window(M1, NOW - 600.0 * 86400.0, NOW - 60.0)]);
    let prom = FakePrometheus::start(prometheus(vec![])).await;
    let t = prom.telemetry();
    // enrolled 400 days ago: 401 day points, the events of 400 days
    let h = run(&t, &mut fake, Range::All, false, None).await;
    assert_eq!((h.series["online"].len(), h.timeline_days), (401, Some(400)));
    let h = run(&t, &mut fake, Range::H24, false, None).await;
    assert_eq!(h.timeline_days, None);
    assert!(!h.series.contains_key("signal_p10_dbm"));
    // cut to the newest events: from the oldest one kept
    let events = (0..2100)
        .map(|i| {
            let kind = if i % 2 == 1 { "connected" } else { "disconnected" };
            unifi(NOW - 100.0 * 86400.0 + f64::from(i) * 3600.0, kind, Some(AP1), Some(AP1_MAC), None, None, M1, "na")
        })
        .collect();
    fake.events.insert(id("a"), events);
    let h = run(&t, &mut fake, Range::Y1, false, None).await;
    assert!(h.timeline_truncated);
    assert!(h.timeline_days.is_some_and(|d| d < 100), "{:?}", h.timeline_days);
}

#[tokio::test]
async fn test_a_resident_sees_no_day_with_a_conflict() {
    let (tz, today, rows) = days();
    let mut fake = case();
    fake.days.insert(id("a"), rows);
    let t0 = midnight(today, 1, &tz);
    fake.conflicts.insert(id("a"), vec![clash(M2, 1, t0 + 3600.0, Some(t0 + 7200.0))]);
    let prom = FakePrometheus::start(prometheus(vec![])).await;
    let t = prom.telemetry();
    let h = run(&t, &mut fake, Range::Y1, false, Some(tz.clone())).await;
    assert_eq!(at(&h.series["signal_dbm"], t0), None);
    let h = run(&t, &mut fake, Range::Y1, true, Some(tz)).await;
    assert_eq!(at(&h.series["signal_dbm"], t0), Some(-61.3));
}

// --- DashboardV2Tests ---------------------------------------------------------------------------------------------

fn v2() -> FakeRegistry {
    let mut fake = FakeRegistry::new();
    fake.windows.insert(id("a"), vec![window(M1, NOW - 20.0 * 86400.0, NOW - 600.0)]);
    fake
}

fn seen_row() -> DeviceRow {
    DeviceRow { last_seen: Some(dt(NOW - 600.0)), ..row("a") }
}

async fn device(
    fake: &mut FakeRegistry,
    handlers: Vec<(String, Value)>,
    rows: Vec<DeviceRow>,
    admin: bool,
    detail: bool,
) -> (live::Device, FakePrometheus) {
    let prom = FakePrometheus::start(handlers).await;
    let opts = DashboardOptions { admin, detail, now: Some(NOW), ..DashboardOptions::default() };
    let mut payload = live::dashboard(&prom.telemetry().page(), fake, &rows, &opts).await.expect("dashboard");
    (payload.devices.remove(0), prom)
}

fn finding<'a>(d: &'a live::Device, code: &str) -> &'a crate::diagnostics::Finding {
    d.diagnostics().iter().find(|f| f.code == code).unwrap_or_else(|| panic!("{code}: {:?}", d.diagnostics()))
}

#[tokio::test]
async fn test_device_additions() {
    let mut fake = v2();
    let (d, _) = device(&mut fake, live(true), vec![seen_row()], false, false).await;
    assert_eq!((d.state, d.mac.as_deref(), d.mac_mode.map(|m| m.as_str())), ("online", Some(M1), Some("random_fixed")));
    assert_eq!(
        serde_json::to_value(&d.macs).unwrap(),
        json!([{"mac": M1, "randomized": true, "first_seen": iso(Some(NOW - 20.0 * 86400.0)), "last_seen": iso(Some(NOW - 600.0)), "current": true}])
    );
    assert_eq!(
        serde_json::to_value(&d.last_auth).unwrap(),
        json!({"at": iso(Some(NOW - 600.0)), "result": "accept", "reason": "ok"})
    );
    assert_eq!(
        serde_json::to_value(&d.facts["signal_dbm"]).unwrap(),
        json!({"value": -58.0, "source": "prometheus", "basis": "measured"})
    );
    assert_eq!(d.facts["last_auth"].source, "radius_auth");
    assert_eq!(d.sources, ["prometheus", "radius_auth", "registry"]);
    let v = serde_json::to_value(&d).unwrap();
    assert_eq!(v["findings"], v["diagnostics"]);
    assert_eq!(d.data_from, iso(Some(NOW - 20.0 * 86400.0)));
    assert!(v.get("conflicts").is_none());
    assert_eq!(fake.called("device_windows").len(), 1);
    assert_eq!(fake.called("auth_failures").len(), 1); // one for the page
}

#[tokio::test]
async fn test_auth_failures_by_certificate_or_mac() {
    let mut fake = v2();
    fake.failures = vec![
        failure(NOW - 300.0, "expired", Some(id("a")), None),
        failure(NOW - 299.0, "expired", Some(id("a")), None),
        failure(NOW - 200.0, "no_cert", None, Some(M1)),
        failure(NOW - 100.0, "no_cert", None, Some("02:00:00:00:00:99")),
    ];
    let (d, _) = device(&mut fake, live(true), vec![seen_row()], false, false).await;
    let f = finding(&d, "auth_failures");
    assert_eq!(
        (f.severity, f.basis, f.params["count"].clone()),
        (crate::diagnostics::Severity::Warn, Basis::Measured, json!(3))
    );
    assert_eq!(f.evidence["reasons"], json!({"expired": 2, "no_cert": 1}));
    assert_eq!(f.evidence["locked_out"], json!(true)); // rejected after the last login
    assert_eq!(
        serde_json::to_value(&d.last_auth).unwrap(),
        json!({"at": iso(Some(NOW - 200.0)), "result": "reject", "reason": "no_cert"})
    );
}

#[tokio::test]
async fn test_rejects_of_another_certificate_are_not_this_devices() {
    let mut fake = v2();
    fake.failures = vec![
        AuthFailure {
            tries: 40,
            last_at: Some(dt(NOW - 100.0)),
            mac: Some(M1.into()),
            ..failure(NOW - 300.0, "revoked", Some(id("other")), None)
        },
        AuthFailure { tries: 4, last_at: Some(dt(NOW - 120.0)), ..failure(NOW - 900.0, "no_cert", None, Some(M1)) },
    ];
    let (d, _) = device(&mut fake, live(true), vec![seen_row()], false, false).await;
    let f = finding(&d, "auth_failures");
    assert_eq!((f.params["count"].clone(), f.evidence["reasons"].clone()), (json!(4), json!({"no_cert": 4})));
    assert_eq!(f.evidence["last_at"], json!(iso(Some(NOW - 120.0))));
    // the latest try of the repeats is after the last login (NOW - 600)
    assert_eq!(
        serde_json::to_value(&d.last_auth).unwrap(),
        json!({"at": iso(Some(NOW - 120.0)), "result": "reject", "reason": "no_cert"})
    );
}

#[tokio::test]
async fn test_incident_correlated_with_a_reconnect() {
    let mut fake = v2();
    fake.incidents = vec![incident(3, "ap_restarted", AP1_MAC, Some(AP1), NOW - 3550.0, Some(NOW - 3200.0))];
    let (d, _) = device(&mut fake, live(true), vec![seen_row()], false, false).await; // reconnect at NOW-3600 (live())
    let f = finding(&d, "incident_correlated");
    assert_eq!((f.basis, f.evidence["incident"]["id"].clone()), (Basis::Inferred, json!(3)));
    assert_eq!(f.evidence["disconnects"], json!([iso(Some(NOW - 3600.0))]));
}

#[tokio::test]
async fn test_ap_overloaded() {
    let mut handlers = vec![
        h("sum by (name) (unpoller_device_stations", vector(&[(json!({"name": AP1}), json!(41))])),
        h(
            "unpoller_device_radio_channel_utilization_total_ratio",
            vector(&[(json!({"name": AP1, "radio": "na"}), json!(0.5))]),
        ),
    ];
    handlers.extend(live(true));
    let (d, _) = device(&mut v2(), handlers, vec![seen_row()], false, false).await;
    let f = finding(&d, "ap_overloaded");
    assert_eq!(
        (f.severity, f.evidence["clients"].clone(), f.evidence["channel_util"].clone()),
        (crate::diagnostics::Severity::Bad, json!(41), json!(0.5))
    );
}

#[tokio::test]
async fn test_poor_coverage_needs_a_whole_day() {
    let coverage = || {
        let mut out = vec![
            h(
                "avg by (mac, ap_name) (avg_over_time",
                vector(&[
                    (json!({"mac": M1, "ap_name": AP1}), json!(-79)),
                    (json!({"mac": M1, "ap_name": AP2}), json!(-74)),
                ]),
            ),
            h(
                "sum by (mac, ap_name) (count_over_time",
                vector(&[
                    (json!({"mac": M1, "ap_name": AP1}), json!(600)),
                    (json!({"mac": M1, "ap_name": AP2}), json!(120)),
                ]),
            ),
        ];
        out.extend(live(true));
        out
    };
    let (d, _) = device(&mut v2(), coverage(), vec![seen_row()], false, false).await;
    let f = finding(&d, "poor_coverage");
    assert_eq!((f.severity, f.params["best_signal_dbm"].clone()), (crate::diagnostics::Severity::Warn, json!(-74.0)));
    let mut fake = FakeRegistry::new();
    fake.windows.insert(id("a"), vec![window(M1, NOW - 3600.0, NOW - 600.0)]); // not a whole day its own
    let (d, prom) = device(&mut fake, coverage(), vec![seen_row()], false, false).await;
    assert!(!d.diagnostics().iter().any(|f| f.code == "poor_coverage"));
    assert!(prom.queries("count_over_time").is_empty());
}

#[tokio::test]
async fn test_conflict_now_withholds_for_residents() {
    let mut fake = v2();
    fake.conflicts.insert(id("a"), vec![clash(M1, 1, NOW - 3600.0, None)]);
    let (d, prom) = device(&mut fake, live(true), vec![seen_row()], false, false).await;
    let codes: Vec<&str> = d.diagnostics().iter().map(|f| f.code).collect();
    assert_eq!((d.state, codes), ("unknown", vec!["mac_conflict"]));
    assert!(prom.queries(M1).is_empty());
    assert!(!d.facts.contains_key("signal_dbm"));
    let (d, _) = device(&mut fake, live(true), vec![seen_row()], true, false).await;
    assert_eq!((d.state, Value::Object(d.diagnostics()[0].params.clone())), ("online", json!({"owners": 1})));
    assert_eq!(d.conflicts.as_ref().map(|c| c[0].other_owners), Some(Some(1)));
}

#[tokio::test]
async fn test_an_ended_window_asks_when_it_was_last_there_inside_it() {
    let mut fake = FakeRegistry::new();
    fake.windows.insert(id("a"), vec![window(M1, NOW - 20.0 * 86400.0, NOW - 3.0 * 86400.0)]);
    let mut handlers = vec![h(
        "max by (mac) (max_over_time(timestamp(",
        vector(&[(json!({"mac": M1}), json!(NOW - 3.0 * 86400.0 + 3600.0))]),
    )];
    handlers.extend(house_ok());
    let rows = vec![DeviceRow { last_seen: Some(dt(NOW - 3.0 * 86400.0)), ..row("a") }];
    let (d, prom) = device(&mut fake, handlers, rows, false, false).await;
    assert_eq!((d.state, d.last_seen.clone()), ("offline", iso(Some(NOW - 3.0 * 86400.0 + 3600.0))));
    let asked: Vec<_> = prom
        .calls()
        .into_iter()
        .filter(|(_, p)| p.get("query").is_some_and(|q| q.contains("max_over_time(timestamp(")))
        .collect();
    let expected = ((NOW - 3.0 * 86400.0 + CURRENT_WINDOW_S) as i64).to_string();
    assert_eq!(asked[0].1.get("time"), Some(&expected)); // at the window's end
}

#[tokio::test]
async fn test_detail_reads_a_day_of_events() {
    let mut fake = v2();
    let events = (0..8)
        .map(|i| {
            let (ap, mac, from, from_mac) =
                if i % 2 == 1 { (AP2, AP2_MAC, AP1, AP1_MAC) } else { (AP1, AP1_MAC, AP2, AP2_MAC) };
            unifi(
                NOW - 1000.0 + f64::from(i) * 60.0,
                "roamed",
                Some(ap),
                Some(mac),
                Some(from),
                Some(from_mac),
                M1,
                "na",
            )
        })
        .collect();
    fake.events.insert(id("a"), events);
    let (d, _) = device(&mut fake, live(true), vec![seen_row()], false, true).await;
    let f = finding(&d, "unstable_roaming");
    assert_eq!((f.basis, f.params["roams_1h"].clone()), (Basis::Measured, json!(8)));
    assert!(d.sources.contains(&"unifi_syslog".to_string()));
}
