//! Python tests/test_diagnostics.py: every finding rule at its thresholds, and only on data that
//! is there.

use std::collections::BTreeMap;

use indexmap::IndexMap;
use serde_json::json;

use crate::diagnostics::{
    self as dx, ApFacts, ApLoad, Basis, Context, Coverage, DeviceView, Disconnect, IncidentRef, PresenceView, Reject,
    Severity, Summary,
};

const NOW: f64 = 1_800_000_000.0;

/// A healthy online device; the closure changes it.
fn online() -> DeviceView {
    DeviceView {
        state: "online".into(),
        mac: Some("02:00:00:00:00:0a".into()),
        band: Some("5".into()),
        channel: Some(56),
        signal_dbm: Some(-55.0),
        noise_dbm: Some(-96.0),
        snr_db: Some(41.0),
        retry_ratio: Some(0.02),
        channel_util: Some(0.2),
        link_rx_bps: Some(600_000_000),
        rx_bps: Some(50_000),
        tx_bps: Some(10_000),
        roams_1h: Some(0),
        last_seen: Some("2026-10-25T10:00:00Z".into()),
        presence: None,
    }
}

fn with(f: impl FnOnce(&mut DeviceView)) -> DeviceView {
    let mut d = online();
    f(&mut d);
    d
}

fn state(state: &str) -> DeviceView {
    DeviceView { state: state.into(), mac: Some("02:00:00:00:00:0a".into()), ..DeviceView::default() }
}

fn busy() -> Summary {
    Summary { tx_attempts_per_s: Some(200.0), ..Summary::default() }
}

fn codes_full(
    device: &DeviceView,
    summary: Option<&Summary>,
    age: Option<i64>,
    telemetry: &str,
) -> BTreeMap<String, Severity> {
    dx::findings(device, summary, age, telemetry, &Context::default())
        .into_iter()
        .map(|f| (f.code.to_string(), f.severity))
        .collect()
}

fn codes(device: &DeviceView, summary: Option<&Summary>) -> BTreeMap<String, Severity> {
    codes_full(device, summary, Some(30), "ok")
}

fn ctx() -> Context {
    Context { now: Some(NOW), ..Context::default() }
}

fn find(device: &DeviceView, context: &Context, code: &str, summary: Option<&Summary>) -> Option<dx::Finding> {
    dx::findings(device, summary, Some(30), "ok", context).into_iter().find(|f| f.code == code)
}

use Severity::{Bad, Info, Warn};

// --- StateTests -----------------------------------------------------------------------------------

#[test]
fn test_healthy_device_has_no_findings() {
    assert_eq!(dx::findings(&online(), Some(&busy()), Some(30), "ok", &Context::default()), vec![]);
}

#[test]
fn test_never_connected() {
    let d = DeviceView { state: "never_connected".into(), ..DeviceView::default() };
    assert_eq!(codes(&d, None), BTreeMap::from([("never_connected".into(), Info)]));
}

#[test]
fn test_offline() {
    let d = DeviceView { last_seen: Some("x".into()), ..state("offline") };
    let found = dx::findings(&d, None, Some(30), "ok", &Context::default());
    assert_eq!(found.len(), 1);
    let f = &found[0];
    assert_eq!((f.code, f.severity, f.basis), ("offline", Info, Basis::Measured));
    assert_eq!(serde_json::to_value(&f.params).unwrap(), json!({"last_seen": "x"}));
    assert_eq!(
        serde_json::to_value(&f.evidence).unwrap(),
        json!({"last_seen": "x", "confirmed_at": null, "confirmed_by": null, "reason": null})
    );
    // presence's confirmation is what the finding rests on
    let d = DeviceView {
        presence: Some(PresenceView {
            confirmed_at: Some("y".into()),
            confirmed_by: Some("radius_acct".into()),
            reason: Some("acct_stop".into()),
            basis: Some(Basis::Measured),
        }),
        ..d
    };
    let found = dx::findings(&d, None, Some(30), "ok", &Context::default());
    assert_eq!(
        serde_json::to_value(&found[0].evidence).unwrap(),
        json!({"last_seen": "x", "confirmed_at": "y", "confirmed_by": "radius_acct", "reason": "acct_stop"})
    );
    // connecting and unknown are never "not connected"
    for s in ["connecting", "unknown"] {
        assert!(!codes(&state(s), None).contains_key("offline"));
    }
}

#[test]
fn test_stale_only_while_prometheus_answers() {
    let unknown = state("unknown");
    assert_eq!(codes_full(&unknown, None, Some(601), "ok"), BTreeMap::from([("stale_data".into(), Warn)]));
    assert_eq!(codes_full(&unknown, None, None, "ok"), BTreeMap::from([("stale_data".into(), Warn)]));
    assert!(codes_full(&unknown, None, None, "unavailable").is_empty());
    assert!(codes_full(&unknown, None, None, "off").is_empty());
    assert!(!dx::is_stale(Some(600)));
    assert!(dx::is_stale(Some(601)));
}

#[test]
fn test_radio_rules_only_while_online() {
    let bad = with(|d| {
        d.signal_dbm = Some(-90.0);
        d.snr_db = Some(5.0);
        d.retry_ratio = Some(0.9);
        d.channel_util = Some(0.95);
    });
    let offline = DeviceView { state: "offline".into(), ..bad.clone() };
    assert_eq!(codes(&offline, Some(&busy())), BTreeMap::from([("offline".into(), Info)]));
    let unknown = DeviceView { state: "unknown".into(), ..bad };
    assert!(codes(&unknown, Some(&busy())).is_empty());
}

#[test]
fn test_worst_first() {
    let d = with(|d| {
        d.signal_dbm = Some(-76.0);
        d.retry_ratio = Some(0.3);
    });
    let found = dx::findings(&d, Some(&busy()), Some(30), "ok", &Context::default());
    assert_eq!(found.iter().map(|f| f.severity).collect::<Vec<_>>(), vec![Bad, Warn]);
}

// --- ThresholdTests ---------------------------------------------------------------------------------

#[test]
fn test_weak_signal() {
    assert!(!codes(&with(|d| d.signal_dbm = Some(-74.0)), None).contains_key("weak_signal"));
    assert_eq!(codes(&with(|d| d.signal_dbm = Some(-75.0)), None)["weak_signal"], Warn);
    assert_eq!(codes(&with(|d| d.signal_dbm = Some(-80.0)), None)["weak_signal"], Bad);
    let d = with(|d| {
        d.signal_dbm = Some(-80.0);
        d.snr_db = Some(16.0);
    });
    let found = dx::findings(&d, None, Some(30), "ok", &Context::default());
    assert_eq!(serde_json::to_value(&found[0].params).unwrap(), json!({"signal_dbm": -80.0}));
}

#[test]
fn test_low_snr_only_with_a_good_signal() {
    assert!(!codes(&with(|d| d.snr_db = Some(21.0)), None).contains_key("low_snr"));
    assert_eq!(codes(&with(|d| d.snr_db = Some(20.0)), None)["low_snr"], Warn);
    assert_eq!(codes(&with(|d| d.snr_db = Some(15.0)), None)["low_snr"], Bad);
    let far = with(|d| {
        d.signal_dbm = Some(-78.0);
        d.snr_db = Some(15.0);
    });
    assert!(!codes(&far, None).contains_key("low_snr")); // the distance, said already
}

#[test]
fn test_high_retries_only_with_traffic() {
    let r = |v: f64| with(|d| d.retry_ratio = Some(v));
    assert!(!codes(&r(0.09), Some(&busy())).contains_key("high_retries"));
    assert_eq!(codes(&r(0.10), Some(&busy()))["high_retries"], Warn);
    assert_eq!(codes(&r(0.25), Some(&busy()))["high_retries"], Bad);
    let idle = Summary { tx_attempts_per_s: Some(9.9), ..Summary::default() };
    assert!(!codes(&r(0.5), Some(&idle)).contains_key("high_retries"));
    assert!(!codes(&r(0.5), None).contains_key("high_retries"));
}

#[test]
fn test_busy_channel() {
    let u = |v: f64| with(|d| d.channel_util = Some(v));
    assert!(!codes(&u(0.59), None).contains_key("busy_channel"));
    assert_eq!(codes(&u(0.6), None)["busy_channel"], Warn);
    assert_eq!(codes(&u(0.8), None)["busy_channel"], Bad);
}

#[test]
fn test_slow_link_needs_good_signal_and_traffic() {
    let slow = with(|d| {
        d.link_rx_bps = Some(6_000_000);
        d.signal_dbm = Some(-60.0);
        d.rx_bps = Some(2_000_000);
    });
    assert_eq!(codes(&slow, None)["slow_link"], Warn);
    let change = |f: fn(&mut DeviceView)| {
        let mut d = slow.clone();
        f(&mut d);
        d
    };
    assert!(!codes(&change(|d| d.signal_dbm = Some(-70.0)), None).contains_key("slow_link"));
    assert!(
        !codes(
            &change(|d| {
                d.rx_bps = Some(1000);
                d.tx_bps = Some(1000);
            }),
            None
        )
        .contains_key("slow_link")
    ); // idle: low rates are normal
    assert!(!codes(&change(|d| d.link_rx_bps = Some(20_000_000)), None).contains_key("slow_link"));
    assert!(!codes(&change(|d| d.link_rx_bps = None), None).contains_key("slow_link"));
}

#[test]
fn test_unstable_roaming() {
    let r = |n: i64| with(|d| d.roams_1h = Some(n));
    assert!(!codes(&r(5), None).contains_key("unstable_roaming"));
    assert_eq!(codes(&r(6), None)["unstable_roaming"], Warn);
    assert_eq!(codes(&r(15), None)["unstable_roaming"], Bad);
}

#[test]
fn test_frequent_disconnects() {
    let s = |n: i64| Summary { reconnects_24h: Some(n), ..Summary::default() };
    assert!(!codes(&online(), Some(&s(5))).contains_key("frequent_disconnects"));
    assert_eq!(codes(&online(), Some(&s(6)))["frequent_disconnects"], Warn);
    assert_eq!(codes(&online(), Some(&s(20)))["frequent_disconnects"], Bad);
    assert_eq!(codes(&state("offline"), Some(&s(30)))["frequent_disconnects"], Bad);
}

#[test]
fn test_stuck_on_2ghz() {
    let stuck = with(|d| {
        d.band = Some("2.4".into());
        d.signal_dbm = Some(-50.0);
        d.roams_1h = Some(0);
    });
    let seen = Summary { bands_7d: vec!["2.4".into(), "5".into()], associated_s: Some(7200.0), ..Summary::default() };
    assert_eq!(codes(&stuck, Some(&seen))["stuck_on_2ghz"], Info);
    let only_24 = Summary { bands_7d: vec!["2.4".into()], ..seen.clone() };
    assert!(!codes(&stuck, Some(&only_24)).contains_key("stuck_on_2ghz")); // cannot do better
    let arrived = Summary { associated_s: Some(1800.0), ..seen.clone() };
    assert!(!codes(&stuck, Some(&arrived)).contains_key("stuck_on_2ghz")); // just arrived
    let steering = DeviceView { roams_1h: Some(2), ..stuck.clone() };
    assert!(!codes(&steering, Some(&seen)).contains_key("stuck_on_2ghz")); // band steering at work
    let far = DeviceView { signal_dbm: Some(-70.0), ..stuck.clone() };
    assert!(!codes(&far, Some(&seen)).contains_key("stuck_on_2ghz")); // 5 GHz would not reach
    let five = DeviceView { band: Some("5".into()), ..stuck };
    assert!(!codes(&five, Some(&seen)).contains_key("stuck_on_2ghz"));
}

#[test]
fn test_missing_values_say_nothing() {
    let empty = DeviceView { state: "online".into(), mac: Some("02:00:00:00:00:0a".into()), ..DeviceView::default() };
    assert!(dx::findings(&empty, None, Some(30), "ok", &Context::default()).is_empty());
    let s = Summary { reconnects_24h: None, bands_7d: vec![], ..Summary::default() };
    assert!(dx::findings(&empty, Some(&s), Some(30), "ok", &Context::default()).is_empty());
}

// --- BasisTests ----------------------------------------------------------------------------------------

#[test]
fn test_every_finding_has_basis_and_evidence() {
    let d = with(|d| {
        d.signal_dbm = Some(-81.0);
        d.snr_db = Some(10.0);
        d.retry_ratio = Some(0.5);
        d.channel_util = Some(0.9);
        d.roams_1h = Some(20);
    });
    let s = Summary { reconnects_24h: Some(30), ..busy() };
    let found: IndexMap<&str, dx::Finding> =
        dx::findings(&d, Some(&s), Some(30), "ok", &Context::default()).into_iter().map(|f| (f.code, f)).collect();
    assert_eq!(
        serde_json::to_value(&found["weak_signal"].evidence).unwrap(),
        json!({"signal_dbm": -81.0, "warn_dbm": -75.0, "bad_dbm": -80.0})
    );
    assert_eq!(found["weak_signal"].basis, Basis::Measured);
    assert_eq!(found["unstable_roaming"].basis, Basis::Inferred); // from AP label changes
    assert_eq!(found["frequent_disconnects"].basis, Basis::Inferred); // from association starts
}

// --- AuthFailureTests -------------------------------------------------------------------------------------

fn rejects(n: usize, reason: &str, last: f64) -> Vec<Reject> {
    (0..n)
        .map(|i| Reject { at: last - i as f64 * 60.0, last_at: None, count: 1, reason: reason.into(), mac: None })
        .collect()
}

#[test]
fn test_thresholds() {
    let accepted = |n| Context { last_accept: Some(NOW), rejects: rejects(n, "expired", NOW - 60.0), ..ctx() };
    assert!(find(&online(), &accepted(2), "auth_failures", None).is_none());
    assert_eq!(find(&online(), &accepted(3), "auth_failures", None).map(|f| f.severity), Some(Warn));
    assert_eq!(find(&online(), &accepted(20), "auth_failures", None).map(|f| f.severity), Some(Bad));
}

#[test]
fn test_a_row_of_repeats_counts_its_tries() {
    let rows = vec![
        Reject { at: NOW - 3000.0, last_at: Some(NOW - 100.0), count: 25, reason: "no_cert".into(), mac: None },
        Reject { at: NOW - 2000.0, last_at: None, count: 1, reason: "expired".into(), mac: None },
    ];
    let f =
        find(&online(), &Context { last_accept: Some(NOW - 1000.0), rejects: rows, ..ctx() }, "auth_failures", None)
            .unwrap();
    assert_eq!((f.severity, f.params["count"].clone(), f.evidence["count_24h"].clone()), (Bad, json!(26), json!(26)));
    assert_eq!(f.evidence["reasons"], json!({"no_cert": 25, "expired": 1}));
    assert_eq!(f.params["reason"], json!("no_cert"));
    assert_eq!(f.evidence["last_at"], json!(crate::telemetry::common::iso(Some(NOW - 100.0))));
    assert_eq!(f.evidence["locked_out"], json!(true)); // its last try is after the login
}

#[test]
fn test_rejected_since_the_last_login_is_a_warning_at_once() {
    let d = DeviceView { state: "never_connected".into(), ..DeviceView::default() };
    let f = find(
        &d,
        &Context { last_accept: None, rejects: rejects(1, "revoked", NOW - 60.0), ..ctx() },
        "auth_failures",
        None,
    )
    .unwrap();
    assert_eq!((f.severity, f.basis, f.params["reason"].clone()), (Warn, Basis::Measured, json!("revoked")));
    assert_eq!(f.evidence["reasons"], json!({"revoked": 1}));
    assert_eq!(f.evidence["locked_out"], json!(true));
}

// --- CertTests -------------------------------------------------------------------------------------------

#[test]
fn test_expiring_and_expired() {
    let exp = |days: f64| Context { expires: Some(NOW + days * 86400.0), ..ctx() };
    assert!(find(&online(), &exp(31.0), "cert_expiring", None).is_none());
    assert_eq!(find(&online(), &exp(30.0), "cert_expiring", None).map(|f| f.severity), Some(Info));
    let f = find(&online(), &exp(7.0), "cert_expiring", None).unwrap();
    assert_eq!(
        (f.severity, f.params["days_left"].clone(), f.evidence["days_left"].clone()),
        (Warn, json!(7), json!(7))
    );
    let d = DeviceView { state: "never_connected".into(), ..DeviceView::default() };
    let f = find(&d, &exp(-1.0), "cert_expired", None).unwrap();
    assert_eq!((f.severity, f.evidence["days_left"].clone()), (Bad, json!(-1)));
}

// --- IdentityFindingTests ---------------------------------------------------------------------------------

#[test]
fn test_rotating_mac() {
    let macs: Vec<String> = (0..4).map(|i| format!("02:00:00:00:00:{i:02x}")).collect();
    let c = Context { mac_mode: Some("rotating".into()), randomized_macs_30d: macs, ..ctx() };
    let f = find(&online(), &c, "rotating_mac", None).unwrap();
    assert_eq!(
        (f.severity, serde_json::to_value(&f.params).unwrap(), f.basis),
        (Info, json!({"macs_30d": 4}), Basis::Measured)
    );
    let c = Context { mac_mode: Some("random_fixed".into()), ..ctx() };
    assert!(find(&online(), &c, "rotating_mac", None).is_none());
}

// --- LoadTests ---------------------------------------------------------------------------------------------

fn load(clients: i64, util: Option<f64>) -> Context {
    Context {
        ap_load: Some(ApLoad {
            ap: Some("ap-scharni-2-corner".into()),
            clients: Some(clients),
            channel_util: util,
            band: Some("5".into()),
        }),
        ..ctx()
    }
}

#[test]
fn test_clients() {
    assert!(find(&online(), &load(24, None), "ap_overloaded", None).is_none());
    assert_eq!(find(&online(), &load(25, None), "ap_overloaded", None).map(|f| f.severity), Some(Warn));
    assert_eq!(find(&online(), &load(40, None), "ap_overloaded", None).map(|f| f.severity), Some(Bad));
}

#[test]
fn test_utilisation_counts_only_with_many_clients() {
    assert!(find(&online(), &load(9, Some(0.95)), "ap_overloaded", None).is_none());
    assert_eq!(find(&online(), &load(10, Some(0.80)), "ap_overloaded", None).map(|f| f.severity), Some(Warn));
    let f = find(&online(), &load(10, Some(0.90)), "ap_overloaded", None).unwrap();
    assert_eq!(
        (f.severity, f.evidence["ap"].clone(), f.evidence["clients"].clone()),
        (Bad, json!("ap-scharni-2-corner"), json!(10))
    );
    assert!(find(&state("offline"), &load(60, None), "ap_overloaded", None).is_none());
}

// --- CoverageTests -----------------------------------------------------------------------------------------

fn cover(signals: &[f64], samples: f64) -> Context {
    let coverage = signals
        .iter()
        .enumerate()
        .map(|(i, s)| (format!("ap-{i}"), Coverage { signal_dbm: Some(*s), samples }))
        .collect();
    Context { coverage, ..ctx() }
}

#[test]
fn test_weak_at_every_ap() {
    assert!(find(&online(), &cover(&[-71.9, -80.0], 120.0), "poor_coverage", None).is_none()); // one AP is fine
    assert_eq!(find(&online(), &cover(&[-72.0, -80.0], 120.0), "poor_coverage", None).map(|f| f.severity), Some(Warn));
    let f = find(&state("offline"), &cover(&[-78.0, -85.0], 120.0), "poor_coverage", None).unwrap();
    assert_eq!((f.severity, f.params["aps"].clone(), f.evidence["aps"]["ap-0"].clone()), (Bad, json!(2), json!(-78.0)));
}

#[test]
fn test_short_visits_do_not_count() {
    assert!(find(&online(), &cover(&[-85.0], 59.0), "poor_coverage", None).is_none());
}

// --- IncidentFindingTests ------------------------------------------------------------------------------------

fn the_incident(ended: Option<f64>) -> IncidentRef {
    IncidentRef {
        id: Some(9),
        kind: "ap_restarted".into(),
        subject: Some("60:22:32:37:48:00".into()),
        subject_name: Some("ap-scharni-2-corner".into()),
        started: NOW - 3600.0,
        ended,
        basis: Some("measured".into()),
    }
}

fn disconnect(at: f64, basis: Basis) -> Disconnect {
    Disconnect { at, basis, source: None, cause: None }
}

#[test]
fn test_a_disconnect_near_an_incident() {
    let c = Context {
        incidents: vec![the_incident(Some(NOW - 3500.0))],
        disconnects: vec![disconnect(NOW - 3590.0, Basis::Measured), disconnect(NOW - 600.0, Basis::Inferred)],
        ..ctx()
    };
    let f = find(&online(), &c, "incident_correlated", None).unwrap();
    assert_eq!((f.basis, f.severity, f.params["kind"].clone()), (Basis::Inferred, Info, json!("ap_restarted")));
    assert_eq!(f.evidence["incident"]["id"], json!(9));
    assert_eq!(f.evidence["disconnects"].as_array().map(Vec::len), Some(1));
}

#[test]
fn test_the_margins() {
    for (at, hit) in [
        (NOW - 3600.0 - 120.0, true),
        (NOW - 3600.0 - 121.0, false),
        (NOW - 3500.0 + 120.0, true),
        (NOW - 3500.0 + 121.0, false),
    ] {
        let c = Context {
            incidents: vec![the_incident(Some(NOW - 3500.0))],
            disconnects: vec![disconnect(at, Basis::Inferred)],
            ..ctx()
        };
        assert_eq!(find(&online(), &c, "incident_correlated", None).is_some(), hit, "{at}");
    }
}

#[test]
fn test_a_long_incident_counts_only_its_first_15_minutes() {
    let c = Context {
        incidents: vec![the_incident(None)],
        disconnects: vec![disconnect(NOW - 3600.0 + 900.0 + 121.0, Basis::Inferred)],
        ..ctx()
    };
    assert!(find(&online(), &c, "incident_correlated", None).is_none());
}

// --- MeasuredHistoryTests ----------------------------------------------------------------------------------------

#[test]
fn test_measured_disconnects_with_causes() {
    let disconnects = (0..6)
        .map(|i| Disconnect {
            at: NOW - f64::from(i) * 600.0,
            basis: Basis::Measured,
            source: None,
            cause: Some(if i % 2 == 1 { "Lost-Carrier" } else { "User-Request" }.into()),
        })
        .collect();
    let s = Summary { reconnects_24h: Some(2), ..Summary::default() };
    let f = find(&online(), &Context { disconnects, ..ctx() }, "frequent_disconnects", Some(&s)).unwrap();
    assert_eq!((f.basis, f.severity, f.params["reconnects_24h"].clone()), (Basis::Measured, Warn, json!(6)));
    assert_eq!(f.evidence["causes"], json!({"User-Request": 3, "Lost-Carrier": 3}));
}

#[test]
fn test_measured_roams() {
    let f = find(
        &with(|d| d.roams_1h = Some(2)),
        &Context { roams_1h_measured: Some(15), ..ctx() },
        "unstable_roaming",
        None,
    )
    .unwrap();
    assert_eq!((f.basis, f.severity, f.params["roams_1h"].clone()), (Basis::Measured, Bad, json!(15)));
}

// --- ApWarningTests ------------------------------------------------------------------------------------------------

fn ap() -> ApFacts {
    ApFacts {
        state: "ok".into(),
        clients: Some(10),
        weak_clients: Some(0),
        uptime_s: Some(5 * 86400),
        uplink_mbps: Some(1000),
        utils: vec![0.3],
        open_incidents: vec![],
    }
}

fn ap_codes(a: &ApFacts) -> BTreeMap<String, Severity> {
    dx::ap_warnings(a).into_iter().map(|f| (f.code.to_string(), f.severity)).collect()
}

#[test]
fn test_a_healthy_ap_has_none() {
    assert!(dx::ap_warnings(&ap()).is_empty());
}

#[test]
fn test_down_says_it_all() {
    let a = ApFacts { state: "down".into(), clients: Some(60), uptime_s: Some(10), ..ap() };
    assert_eq!(ap_codes(&a), BTreeMap::from([("down".into(), Bad)]));
}

#[test]
fn test_poor_coverage() {
    let w = |clients, weak| ApFacts { clients: Some(clients), weak_clients: Some(weak), ..ap() };
    assert!(!ap_codes(&w(8, 1)).contains_key("poor_coverage"));
    assert_eq!(ap_codes(&w(8, 2))["poor_coverage"], Warn); // 25 %
    assert!(!ap_codes(&w(3, 3)).contains_key("poor_coverage")); // too few
    let f = dx::ap_warnings(&w(4, 1)).remove(0);
    assert_eq!(
        (f.params["share"].clone(), f.basis, f.evidence["threshold"].clone()),
        (json!(0.25), Basis::Measured, json!(0.25))
    );
}

#[test]
fn test_restarted_and_uplink() {
    assert_eq!(ap_codes(&ApFacts { uptime_s: Some(86399), ..ap() })["restarted"], Info);
    assert!(!ap_codes(&ApFacts { uptime_s: Some(86400), ..ap() }).contains_key("restarted"));
    assert_eq!(ap_codes(&ApFacts { uplink_mbps: Some(100), ..ap() })["uplink"], Warn);
    assert!(!ap_codes(&ApFacts { uplink_mbps: None, ..ap() }).contains_key("uplink"));
    assert!(!ap_codes(&ApFacts { uplink_mbps: Some(2500), ..ap() }).contains_key("uplink"));
}

#[test]
fn test_overloaded_as_for_a_device_else_busy() {
    assert_eq!(ap_codes(&ApFacts { clients: Some(25), ..ap() })["overloaded"], Warn);
    assert_eq!(ap_codes(&ApFacts { clients: Some(40), ..ap() })["overloaded"], Bad);
    assert_eq!(ap_codes(&ApFacts { clients: Some(10), utils: vec![0.91], ..ap() })["overloaded"], Bad);
    assert_eq!(
        ap_codes(&ApFacts { clients: Some(9), utils: vec![0.95], ..ap() }),
        BTreeMap::from([("busy_channel".into(), Warn)])
    );
    assert_eq!(ap_codes(&ApFacts { utils: vec![0.6], ..ap() }), BTreeMap::from([("busy_channel".into(), Warn)]));
    for (clients, util) in [(24, 0.5), (25, 0.5), (12, 0.85)] {
        let c = Context {
            ap_load: Some(ApLoad {
                ap: Some("x".into()),
                clients: Some(clients),
                channel_util: Some(util),
                band: None,
            }),
            ..ctx()
        };
        let device = find(&online(), &c, "ap_overloaded", None).map(|f| f.severity);
        let ap = dx::ap_warnings(&ApFacts { clients: Some(clients), utils: vec![util], ..ap() })
            .into_iter()
            .find(|f| f.code == "overloaded")
            .map(|f| f.severity);
        assert_eq!(device, ap);
    }
}
