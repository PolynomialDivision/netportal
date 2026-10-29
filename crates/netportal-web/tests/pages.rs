//! The pages from sample payloads, rendered by `netportal_web::render::Templates` (port of
//! `tests/test_dashboard_pages.py`, 53 tests, and the template parts of `tests/test_web.py`
//! HouseLookTests and BrowserNoticeTests). The pages must be complete without JavaScript, in
//! every language, for every device state and telemetry state, and keep the strict CSP (no inline
//! code: the scripts' texts and data are JSON blocks). Example values only.
//!
//! Python went through Flask's routes with the registry and telemetry mocked; here [`Site`] plays
//! the handlers' part (which registry rows, which payload, which page values for which address),
//! so the tests assert the HTML only. Left to the handlers' tests: status codes (404 for another
//! resident's device, 403 for the admin pages), the CSP header, the incidents page's time span
//! from `?range=` and the kind passed to the backend.

use std::sync::LazyLock;

use indexmap::IndexMap;
use jiff::Timestamp;
use minijinja::value::Serde;
use netportal_core::i18n::{self, Text};
use netportal_web::render::{Base, RequestView, SettingsView, Templates, User, escape, format as fmt};
use regex::Regex;
use serde_json::{Value, json};

static TEMPLATES: LazyLock<Templates> = LazyLock::new(|| match Templates::new() {
    Ok(t) => t,
    Err(e) => panic!("templates: {e:#}"),
});

const RESIDENT_SUB: &str = "sub-resident";
const ADMIN_SUB: &str = "sub-admin";
const LANGS: [&str; 3] = ["en", "de", "uk"];

fn now() -> Timestamp {
    "2026-10-25T12:00:00Z".parse().expect("a constant moment")
}

fn now_s() -> i64 {
    now().as_second()
}

fn rfc3339(unix: i64) -> String {
    Timestamp::from_second(unix).expect("a moment of the tests").strftime("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// The moment `delta_s` seconds before NOW.
fn iso(delta_s: i64) -> String {
    rfc3339(now_s() - delta_s)
}

fn id(i: u32) -> String {
    format!("00000000-0000-4000-8000-{i:012x}")
}

fn ids() -> Vec<String> {
    (1..=5).map(id).collect()
}

fn t(lang: &str, key: &str) -> String {
    i18n::text(lang, key).unwrap_or_else(|| panic!("no text {lang} {key}")).to_string()
}

fn fill(template: &str, values: &[(&str, &str)]) -> String {
    i18n::fill(template, values)
}

fn esc(text: &str) -> String {
    escape(text)
}

fn merge(target: &mut Value, extra: Value) {
    if let (Some(map), Value::Object(extra)) = (target.as_object_mut(), extra) {
        for (k, v) in extra {
            map.insert(k, v);
        }
    }
}

fn codes(table: &str) -> Vec<String> {
    fmt::codes(table).into_iter().map(String::from).collect()
}

// --- sample payloads (the shapes of the JSON API) ---------------------------------------------

/// ap-<house>-<floor>-<spot> as the backend splits it (unknown names: house none).
fn ap(name: &str) -> Value {
    let parts: Vec<&str> = name.split('-').collect();
    if parts.len() == 4 && parts[0] == "ap" {
        json!({"name": name, "house": parts[1], "floor": parts[2].parse::<i64>().unwrap_or(0), "spot": parts[3]})
    } else {
        json!({"name": name, "house": null, "floor": null, "spot": null})
    }
}

fn device(i: usize, name: &str, state: &str, values: Value) -> Value {
    let mut d = json!({
        "id": ids()[i], "name": name, "platform": "android", "policy": "residents", "created": iso(40 * 86400),
        "expires": iso(-300 * 86400), "expires_soon": false, "revoked": false, "mac": format!("02:00:00:00:00:{i:02x}"),
        "state": state, "last_seen": null, "since": null, "ap": null, "ssid": null, "band": null, "channel": null,
        "proto": null, "ip": null, "signal_dbm": null, "noise_dbm": null, "snr_db": null, "health": null,
        "retry_ratio": null, "channel_util": null, "link_rx_bps": null, "link_tx_bps": null, "rx_bps": null,
        "tx_bps": null, "rx_24h_bytes": null, "tx_24h_bytes": null, "roams_1h": null, "diagnostics": [],
    });
    merge(&mut d, values);
    d
}

fn sample_devices() -> Vec<Value> {
    vec![
        device(
            0,
            "Pixel 8",
            "online",
            json!({
            "last_seen": iso(0), "since": iso(8130), "ap": ap("ap-scharni-2-corner"), "ssid": "Example", "band": "5",
            "channel": 36, "proto": "ax", "ip": "10.30.0.23", "signal_dbm": -58, "noise_dbm": -95, "snr_db": 37,
            "health": 88, "retry_ratio": 0.03, "channel_util": 0.21, "link_rx_bps": 866_000_000,
            "link_tx_bps": 720_000_000, "rx_bps": 2_400_000, "tx_bps": 180_000, "rx_24h_bytes": 1_830_000_000_i64,
            "tx_24h_bytes": 221_000_000, "roams_1h": 0}),
        ),
        device(
            1,
            "MacBook Air",
            "online",
            json!({
            "platform": "apple-mac", "last_seen": iso(0), "since": iso(3 * 86400 + 4000), "ap": ap("ap-colbe-0-far"),
            "ssid": "Example", "band": "2.4", "channel": 6, "proto": "n", "ip": "10.30.0.41", "signal_dbm": -79,
            "noise_dbm": -88, "snr_db": 9, "health": 41, "retry_ratio": 0.24, "channel_util": 0.72,
            "link_rx_bps": 52_000_000, "link_tx_bps": 26_000_000, "rx_bps": 310_000, "tx_bps": 41_000,
            "rx_24h_bytes": 640_000_000, "tx_24h_bytes": 95_000_000, "roams_1h": 7,
            "diagnostics": [{"code": "weak_signal", "severity": "warn", "params": {"signal_dbm": -79}},
                            {"code": "high_retries", "severity": "bad", "params": {"retry_ratio": 0.24}},
                            {"code": "busy_channel", "severity": "warn", "params": {"channel_util": 0.72}},
                            {"code": "unstable_roaming", "severity": "warn", "params": {"roams_1h": 7}},
                            {"code": "stuck_on_2ghz", "severity": "info", "params": {}}]}),
        ),
        device(
            2,
            "iPad",
            "offline",
            json!({
            "platform": "apple", "last_seen": iso(3 * 3600 + 600), "ssid": "Example", "expires": iso(-12 * 86400),
            "expires_soon": true, "rx_24h_bytes": 120_000_000, "tx_24h_bytes": 8_000_000,
            "diagnostics": [{"code": "offline", "severity": "info", "params": {}},
                            {"code": "frequent_disconnects", "severity": "warn", "params": {"reconnects_24h": 6}}]}),
        ),
        device(
            3,
            "Kindle",
            "never_connected",
            json!({
            "platform": "eap-config", "mac": null,
            "diagnostics": [{"code": "never_connected", "severity": "info", "params": {}}]}),
        ),
        device(
            4,
            "Sensor <&> \"Werkstatt\"",
            "online",
            json!({
            "platform": "letswifi", "last_seen": iso(0), "since": iso(30), "ap": ap("ap-scharni-0-schlaglicht"),
            "band": "6", "channel": 37, "proto": "ax", "signal_dbm": -66, "health": 72,
            "diagnostics": [{"code": "slow_link", "severity": "warn", "params": {"link_rx_bps": 6_500_000, "signal_dbm": -66}},
                            {"code": "low_snr", "severity": "warn", "params": {"snr_db": 14}},
                            {"code": "stale_data", "severity": "info", "params": {"age_s": 900}}]}),
        ),
    ]
}

fn sample_house(overrides: Value) -> Value {
    let mut house = json!({
        "internet": "ok", "internet_loss_ratio": 0.0, "internet_rtt_ms": 11.4, "dns": "ok", "router": "ok",
        "speedtest": {"download_bps": 248_000_000, "upload_bps": 41_500_000, "ping_ms": 9.8, "at": iso(5400)},
        "wifi_data_age_s": 45});
    merge(&mut house, overrides);
    house
}

fn sample_dashboard(telemetry: &str, devices: Option<Vec<Value>>, overrides: Value) -> Value {
    let mut devices = devices.unwrap_or_else(sample_devices);
    let mut house = sample_house(json!({}));
    if telemetry != "ok" {
        house = sample_house(json!({"internet": "unknown", "dns": "unknown", "router": "unknown", "speedtest": null,
                                    "internet_rtt_ms": null, "internet_loss_ratio": null, "wifi_data_age_s": null}));
        for d in &mut devices {
            for key in [
                "signal_dbm",
                "health",
                "rx_bps",
                "tx_bps",
                "link_rx_bps",
                "link_tx_bps",
                "ap",
                "band",
                "channel",
                "proto",
                "rx_24h_bytes",
                "tx_24h_bytes",
                "since",
            ] {
                d[key] = Value::Null;
            }
            if d["state"] == "online" {
                d["state"] = json!("unknown");
            }
            let kept: Vec<Value> = d["diagnostics"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|f| f["code"] == "never_connected")
                .cloned()
                .collect();
            d["diagnostics"] = Value::Array(kept);
        }
    }
    let mut payload = json!({"generated_at": iso(0), "telemetry": telemetry, "stale": false, "house": house,
                             "devices": devices});
    merge(&mut payload, overrides);
    payload
}

/// A day (or more) of samples: two connections, a roam, a band change and gaps.
fn sample_history(range: &str) -> Value {
    let span: i64 = match range {
        "24h" => 86400,
        "7d" => 7 * 86400,
        _ => 30 * 86400,
    };
    let step: i64 = match range {
        "24h" => 300,
        "7d" => 1800,
        _ => 7200,
    };
    let end = now_s();
    let start = end - span;
    let part = |f: f64| (span as f64 * f) as i64;
    let (off_from, off_to) = (end - part(0.62), end - part(0.55));
    let (hole_from, hole_to) = (end - part(0.30), end - part(0.28));
    let keys = ["signal_dbm", "health", "rx_bps", "tx_bps", "online", "link_rx_bps", "link_tx_bps"];
    let mut series: IndexMap<&str, Vec<Value>> = keys.iter().map(|k| (*k, Vec::new())).collect();
    let mut push = |k: &str, t: i64, v: Value| series.get_mut(k).expect("a series of the sample").push(json!([t, v]));
    for t in (start..=end).step_by(step as usize) {
        if (hole_from..hole_to).contains(&t) {
            continue;
        }
        let online = !(off_from..off_to).contains(&t);
        let phase = (t - start) as f64 / span as f64;
        push("online", t, json!(i64::from(online)));
        if !online {
            for k in ["signal_dbm", "health", "rx_bps", "tx_bps", "link_rx_bps", "link_tx_bps"] {
                push(k, t, Value::Null);
            }
            continue;
        }
        let weak = phase > 0.8;
        let sig = (if weak { -74.0 } else { -58.0 }) + 4.0 * (phase * 40.0).sin();
        push("signal_dbm", t, json!((sig * 10.0).round() / 10.0));
        push("health", t, json!((100.0 + (sig + 55.0) * 2.2).clamp(0.0, 100.0).round() as i64));
        let busy = 0.5 + 0.5 * (phase * 12.0).sin();
        push("rx_bps", t, json!((busy * 4e6 + 1e5).round() as i64));
        push("tx_bps", t, json!((busy * 6e5 + 2e4).round() as i64));
        push("link_rx_bps", t, json!(if weak { 173_000_000 } else { 866_000_000 }));
        push("link_tx_bps", t, json!(if weak { 144_000_000 } else { 720_000_000 }));
    }
    let first = start - 3600;
    let timeline = json!([
        {"kind": "connected", "at": rfc3339(first), "ap": ap("ap-scharni-2-corner"), "band": "5", "from_ap": null,
         "from_band": null, "duration_s": off_from - first},
        {"kind": "disconnected", "at": rfc3339(off_from), "ap": ap("ap-scharni-2-corner"), "band": "5", "from_ap": null,
         "from_band": null, "duration_s": off_to - off_from},
        {"kind": "connected", "at": rfc3339(off_to), "ap": ap("ap-scharni-1-middle"), "band": "5", "from_ap": null,
         "from_band": null, "duration_s": null},
        {"kind": "roamed", "at": rfc3339(end - part(0.2)), "ap": ap("ap-colbe-0-far"), "band": "5",
         "from_ap": ap("ap-scharni-1-middle"), "from_band": "5", "duration_s": null},
        {"kind": "band_changed", "at": rfc3339(end - part(0.1)), "ap": ap("ap-colbe-0-far"), "band": "2.4",
         "from_ap": ap("ap-colbe-0-far"), "from_band": "5", "duration_s": null},
    ]);
    json!({"range": range, "step_s": step, "start": start, "end": end, "telemetry": "ok", "series": series,
           "timeline": timeline, "timeline_truncated": false})
}

// --- telemetry v2 samples ---------------------------------------------------------------------

/// diagnostics.finding: evidence defaults to the params.
fn finding(code: &str, severity: &str, basis: &str, evidence: Option<Value>, params: Value) -> Value {
    let evidence = evidence.unwrap_or_else(|| params.clone());
    json!({"code": code, "severity": severity, "params": params, "basis": basis, "evidence": evidence})
}

/// sample_devices with v2's identity, login, sources and evidence-based findings.
fn v2_devices() -> Vec<Value> {
    let mut devices = sample_devices();
    merge(
        &mut devices[0],
        json!({
        "mac_mode": "random_fixed", "sources": ["radius_auth", "radius_acct", "unifi_syslog", "prometheus"],
        "last_auth": {"at": iso(1500), "result": "accept", "reason": "ok"},
        "macs": [{"mac": "02:00:00:00:00:00", "randomized": true, "first_seen": iso(40 * 86400), "last_seen": iso(60),
                  "current": true}]}),
    );
    merge(
        &mut devices[1],
        json!({
        "mac_mode": "hardware", "sources": ["radius_auth", "prometheus"],
        "last_auth": {"at": iso(4000), "result": "accept", "reason": "ok"},
        "macs": [{"mac": "a4:83:e7:00:00:01", "randomized": false, "first_seen": iso(90 * 86400), "last_seen": iso(30),
                  "current": true}],
        "diagnostics": [
            finding("high_retries", "bad", "measured", Some(json!({"retry_ratio": 0.24, "tx_attempts_per_s": 41.5, "warn": 0.1})),
                    json!({"retry_ratio": 0.24})),
            finding("weak_signal", "warn", "measured", Some(json!({"signal_dbm": -79, "warn_dbm": -75, "bad_dbm": -80})),
                    json!({"signal_dbm": -79})),
            finding("poor_coverage", "warn", "measured",
                    Some(json!({"aps": {"ap-colbe-0-far": -77.4, "ap-colbe-1-middle": -80.2},
                                "minutes": {"ap-colbe-0-far": 900}, "warn_dbm": -72})),
                    json!({"best_signal_dbm": -77.4, "aps": 2})),
            finding("ap_overloaded", "warn", "measured",
                    Some(json!({"ap": "ap-colbe-0-far", "clients": 31, "channel_util": 0.84, "band": "2.4",
                                "clients_warn": 25, "util_warn": 0.8})),
                    json!({"ap": "ap-colbe-0-far", "clients": 31, "channel_util": 0.84})),
            finding("unstable_roaming", "warn", "inferred", Some(json!({"roams_1h": 7, "roams_1h_measured": null, "warn": 6})),
                    json!({"roams_1h": 7})),
            finding("stuck_on_2ghz", "info", "measured",
                    Some(json!({"bands_7d": ["2.4", "5"], "signal_dbm": -58, "associated_s": 5400})),
                    json!({"bands_7d": ["2.4", "5"]})),
        ]}),
    );
    let macs: Vec<Value> = (0..4i64)
        .map(|i| {
            json!({"mac": format!("06:11:22:33:44:{i:02x}"), "randomized": true, "first_seen": iso((i + 1) * 7 * 86400),
                        "last_seen": iso(i * 7 * 86400 + 3 * 3600), "current": i == 0})
        })
        .collect();
    merge(
        &mut devices[2],
        json!({
        "mac_mode": "rotating", "sources": ["radius_auth", "radius_acct", "unifi_syslog", "prometheus", "device_mac"],
        "last_auth": {"at": iso(3 * 3600 + 900), "result": "accept", "reason": "ok"}, "macs": macs,
        "diagnostics": [
            finding("frequent_disconnects", "warn", "measured",
                    Some(json!({"reconnects_24h": 8, "disconnects_24h_measured": 7, "warn": 6,
                                "causes": {"Lost-Carrier": 5, "User-Request": 2}})),
                    json!({"reconnects_24h": 7})),
            finding("incident_correlated", "info", "inferred",
                    Some(json!({"incident": {"id": 7, "kind": "ap_restarted", "subject": "d0:21:f9:00:00:01",
                                             "subject_name": "ap-scharni-2-corner", "started": iso(5 * 3600),
                                             "ended": iso(5 * 3600 - 180), "basis": "measured"},
                                "disconnects": [iso(5 * 3600 - 40)], "incidents_correlated": 1, "margin_s": 120})),
                    json!({"kind": "ap_restarted", "subject_name": "ap-scharni-2-corner", "started": iso(5 * 3600),
                           "disconnects": 1})),
            finding("rotating_mac", "info", "measured", Some(json!({"macs_30d": 4, "min_macs": 3})), json!({"macs_30d": 4})),
            finding("cert_expiring", "warn", "measured", Some(json!({"expires": iso(-6 * 86400), "days_left": 6})),
                    json!({"expires": iso(-6 * 86400), "days_left": 6})),
            finding("offline", "info", "measured", None, json!({"last_seen": iso(3 * 3600 + 600)})),
        ]}),
    );
    merge(
        &mut devices[3],
        json!({
        "mac_mode": "hardware", "sources": ["radius_auth"],
        "last_auth": {"at": iso(420), "result": "reject", "reason": "unknown_cert"},
        "macs": [{"mac": "f0:27:2d:00:00:03", "randomized": false, "first_seen": iso(2 * 86400), "last_seen": iso(420),
                  "current": true}],
        "diagnostics": [
            finding("auth_failures", "bad", "measured",
                    Some(json!({"count_24h": 23, "reasons": {"unknown_cert": 23}, "last_at": iso(420),
                                "last_reason": "unknown_cert", "last_accept": null, "locked_out": true, "warn": 3})),
                    json!({"count": 23, "reason": "unknown_cert", "last_at": iso(420)})),
            finding("never_connected", "info", "measured", Some(json!({"logins": 0})), json!({})),
        ]}),
    );
    devices
}

/// Every event kind from every source, measured and inferred, in the API's EVENT shape.
fn v2_timeline(start: i64, end: i64) -> Value {
    let span = (end - start) as f64;
    let at = |fraction: f64| rfc3339((start as f64 + span * fraction) as i64);
    #[allow(clippy::too_many_arguments)]
    fn e(
        at: String,
        kind: &str,
        source: &str,
        basis: &str,
        ap_name: Option<&str>,
        band: Option<&str>,
        from: (Option<&str>, Option<&str>),
        duration_s: Option<i64>,
        mac: &str,
        sources: Option<Vec<&str>>,
        detail: Value,
    ) -> Value {
        json!({"kind": kind, "at": at, "source": source, "sources": sources.unwrap_or_else(|| vec![source]),
               "basis": basis, "ap": ap_name.map(ap), "band": band, "from_ap": from.0.map(ap), "from_band": from.1,
               "mac": mac, "duration_s": duration_s, "detail": detail})
    }
    let mac = "02:00:00:00:00:00";
    json!([
        e(
            at(0.02),
            "authenticated",
            "radius_auth",
            "measured",
            Some("ap-scharni-2-corner"),
            Some("5"),
            (None, None),
            None,
            mac,
            None,
            json!({"reason": "ok", "bssid": "d2:21:f9:00:00:11", "ssid": "Example"})
        ),
        e(
            at(0.021),
            "connected",
            "unifi_syslog",
            "measured",
            Some("ap-scharni-2-corner"),
            Some("5"),
            (None, None),
            None,
            mac,
            Some(vec!["unifi_syslog", "radius_acct"]),
            json!({"rssi": -58, "channel": 36})
        ),
        e(
            at(0.2),
            "roamed",
            "radius_acct",
            "measured",
            Some("ap-scharni-1-middle"),
            Some("5"),
            (Some("ap-scharni-2-corner"), Some("5")),
            None,
            mac,
            None,
            json!({"from_cause": "Lost-Service", "gap_s": 4})
        ),
        e(
            at(0.3),
            "band_changed",
            "prometheus",
            "inferred",
            Some("ap-scharni-1-middle"),
            Some("2.4"),
            (Some("ap-scharni-1-middle"), Some("5")),
            None,
            mac,
            None,
            json!({})
        ),
        e(
            at(0.38),
            "incident",
            "incident",
            "measured",
            Some("ap-scharni-1-middle"),
            None,
            (None, None),
            Some(240),
            mac,
            None,
            json!({"id": 7, "incident": "ap_restarted", "subject": "d0:21:f9:00:00:01", "subject_name": "ap-scharni-1-middle",
                 "ended": at(0.385), "open": false})
        ),
        e(
            at(0.381),
            "session_ended",
            "radius_acct",
            "measured",
            Some("ap-scharni-1-middle"),
            Some("2.4"),
            (None, None),
            Some(14_000),
            mac,
            None,
            json!({"cause": "NAS-Reboot", "session_time_s": 14_000, "rx_bytes": 812_000_000, "tx_bytes": 96_000_000})
        ),
        e(
            at(0.45),
            "disconnected",
            "prometheus",
            "inferred",
            Some("ap-scharni-1-middle"),
            Some("2.4"),
            (None, None),
            Some(3000),
            mac,
            None,
            json!({})
        ),
        e(
            at(0.5),
            "auth_rejected",
            "radius_auth",
            "measured",
            None,
            None,
            (None, None),
            None,
            mac,
            None,
            json!({"reason": "retired", "bssid": "d2:21:f9:00:00:12", "ssid": "Example"})
        ),
        e(
            at(0.55),
            "reconnected",
            "unifi_syslog",
            "measured",
            Some("ap-colbe-0-far"),
            Some("5"),
            (None, None),
            None,
            mac,
            Some(vec!["unifi_syslog", "prometheus"]),
            json!({})
        ),
        e(
            at(0.7),
            "mac_changed",
            "device_mac",
            "inferred",
            None,
            None,
            (None, None),
            None,
            "06:11:22:33:44:01",
            None,
            json!({"from_mac": "02:00:00:00:00:00", "randomized": true})
        ),
        e(
            at(0.9),
            "incident",
            "incident",
            "measured",
            None,
            None,
            (None, None),
            None,
            mac,
            None,
            json!({"id": 9, "incident": "internet_degraded", "subject": "", "subject_name": null, "ended": null,
                 "open": true})
        ),
    ])
}

/// A /history payload of telemetry v2: ranges up to 90 days in steps, 1y and all in days.
fn v2_history(range: &str) -> Value {
    let end = now_s();
    let mut payload = match range {
        "24h" | "7d" | "30d" => sample_history(range),
        "90d" => {
            let mut p = sample_history("30d");
            merge(&mut p, json!({"range": "90d", "step_s": 21600, "start": end - 90 * 86400}));
            p
        }
        _ => {
            let days: i64 = if range == "1y" { 365 } else { 420 };
            let start = end - days * 86400;
            let keys = [
                "signal_dbm",
                "health",
                "rx_bps",
                "tx_bps",
                "link_rx_bps",
                "link_tx_bps",
                "snr_db",
                "retry_ratio",
                "online",
            ];
            let mut series: IndexMap<&str, Vec<Value>> = keys.iter().map(|k| (*k, Vec::new())).collect();
            for i in 0..days {
                let t = start + i * 86400;
                let gone = (150..165).contains(&i) || (range == "all" && i < 40);
                let wave = (i as f64 / 9.0).sin();
                let round = |x: f64, d: i32| (x * 10f64.powi(d)).round() / 10f64.powi(d);
                for k in keys {
                    let v = if gone {
                        Value::Null
                    } else {
                        match k {
                            "signal_dbm" => json!(round(-63.0 + 6.0 * wave, 1)),
                            "health" => json!(round(78.0 + 12.0 * wave, 1)),
                            "rx_bps" => {
                                json!(((1.2e9 + 0.8e9 * (1.0 + (i as f64 / 3.0).sin())) * 8.0 / 86400.0) as i64)
                            }
                            "tx_bps" => json!(((1.5e8 + 1e8 * (1.0 + (i as f64 / 4.0).cos())) * 8.0 / 86400.0) as i64),
                            "link_rx_bps" => json!((520e6 + 200e6 * wave) as i64),
                            "snr_db" => json!(round(31.0 + 5.0 * wave, 1)),
                            "retry_ratio" => json!(round(0.05 + 0.03 * (1.0 - wave), 4)),
                            "online" => json!(round((0.55 + 0.35 * (1.0 + (i as f64 / 5.0).sin()) / 2.0).min(1.0), 3)),
                            _ => Value::Null,
                        }
                    };
                    series.get_mut(k).expect("a series of the sample").push(json!([t, v]));
                }
            }
            json!({"range": range, "step_s": 86400, "step": "day", "start": start, "end": end, "telemetry": "ok",
                   "series": series, "timeline": [], "timeline_truncated": false, "sources": ["device_day"]})
        }
    };
    if payload.get("step").is_none() {
        payload["step"] = Value::Null;
    }
    let days = payload["step"] == "day";
    let (start, end) = (payload["start"].as_i64().unwrap_or(0), payload["end"].as_i64().unwrap_or(0));
    payload["timeline"] = if days { v2_timeline(end - 90 * 86400, end) } else { v2_timeline(start, end) };
    payload["sources"] = json!(["radius_auth", "radius_acct", "unifi_syslog", "prometheus", "device_mac", "incident"]);
    if !days {
        let signal = payload["series"]["signal_dbm"].as_array().cloned().unwrap_or_default();
        let snr: Vec<Value> =
            signal.iter().map(|p| json!([p[0], p[1].as_f64().map(|v| ((v + 95.0) * 10.0).round() / 10.0)])).collect();
        let grid: Vec<Value> =
            payload["series"]["online"].as_array().into_iter().flatten().map(|p| p[0].clone()).collect();
        let retries: Vec<Value> = grid
            .iter()
            .enumerate()
            .map(|(i, t)| json!([t, ((0.04 + 0.03 * (i as f64 / 7.0).sin()) * 1e4).round() / 1e4]))
            .collect();
        payload["series"]["snr_db"] = json!(snr);
        payload["series"]["retry_ratio"] = json!(retries);
    }
    payload
}

fn ap_mac(name: &str) -> &'static str {
    match name {
        "ap-scharni-2-corner" => "d0:21:f9:00:00:01",
        "ap-scharni-1-middle" => "d0:21:f9:00:00:02",
        "ap-colbe-0-far" => "d0:21:f9:00:00:03",
        _ => "d0:21:f9:00:00:04",
    }
}

/// ap_day rows of the last days (newest last).
fn ap_days(name: &str, days: i64, seed: i64) -> Vec<Value> {
    let today = now().to_zoned(jiff::tz::TimeZone::UTC).date();
    let round = |x: f64, d: i32| (x * 10f64.powi(d)).round() / 10f64.powi(d);
    (0..days)
        .map(|i| {
            let day = today.checked_sub(jiff::Span::new().days(days - 1 - i)).expect("a day of the sample");
            let w = ((i + seed) as f64 / 4.0).sin();
            let s = seed as f64;
            let restart = (i + seed) % 11 == 0;
            json!({"ap_mac": ap_mac(name), "day": day.to_string(), "ap_name": name,
                   "clients_avg": round(9.0 + 5.0 * w + s, 1), "clients_max": (16.0 + 8.0 * w + s * 2.0) as i64,
                   "channel_util_avg": {"ng": round(0.45 + 0.2 * w, 3), "na": round(0.18 + 0.1 * w, 3)},
                   "weak_client_share": round((0.08 + 0.06 * w + s * 0.05).max(0.0), 3),
                   "restarts": i64::from(restart), "down_s": if restart { 180 } else { 0 }})
        })
        .collect()
}

/// APs as telemetry/admin shows them (OVERVIEW "aps"; APS with "days").
fn sample_aps(with_days: bool) -> Vec<Value> {
    #[allow(clippy::too_many_arguments)]
    fn one(
        name: &str,
        state: &str,
        clients: Option<i64>,
        radios: Value,
        weak: Option<i64>,
        uptime: Option<i64>,
        seed: i64,
        uplink: Option<i64>,
        signal: f64,
        open_incidents: Value,
        with_days: bool,
    ) -> Value {
        let mut a = ap(name);
        merge(
            &mut a,
            json!({
            "mac": ap_mac(name), "ip": format!("10.10.0.{}", 21 + seed), "model": "U7 Pro", "state": state,
            "clients": clients, "clients_house": clients.map(|c| (c - 3).max(0)), "weak_clients": weak,
            "signal_avg_dbm": clients.map(|_| signal), "uptime_s": uptime, "uplink_mbps": uplink, "radios": radios,
            "open_incidents": open_incidents}),
        );
        if with_days {
            a["days"] = json!(ap_days(name, 7, seed));
        }
        a
    }
    let down = json!({"id": 8, "kind": "ap_down", "subject": ap_mac("ap-scharni-0-schlaglicht"),
                      "subject_name": "ap-scharni-0-schlaglicht", "started": iso(2 * 3600), "ended": null, "open": true,
                      "duration_s": 7200, "basis": "measured", "detail": {}});
    vec![
        one(
            "ap-scharni-2-corner",
            "ok",
            Some(14),
            json!([{"radio": "na", "band": "5", "channel": 36, "clients": 10, "channel_util": 0.21},
                   {"radio": "ng", "band": "2.4", "channel": 1, "clients": 4, "channel_util": 0.52}]),
            Some(1),
            Some(9 * 86400),
            0,
            Some(2500),
            -63.5,
            json!([]),
            with_days,
        ),
        one(
            "ap-scharni-1-middle",
            "ok",
            Some(9),
            json!([{"radio": "na", "band": "5", "channel": 52, "clients": 7, "channel_util": 0.12},
                   {"radio": "ng", "band": "2.4", "channel": 6, "clients": 2, "channel_util": 0.38}]),
            Some(0),
            Some(3 * 3600),
            1,
            Some(100),
            -63.5,
            json!([]),
            with_days,
        ),
        one(
            "ap-colbe-0-far",
            "ok",
            Some(31),
            json!([{"radio": "na", "band": "5", "channel": 100, "clients": 12, "channel_util": 0.64},
                   {"radio": "ng", "band": "2.4", "channel": 11, "clients": 19, "channel_util": 0.86}]),
            Some(10),
            Some(22 * 86400),
            2,
            Some(2500),
            -71.2,
            json!([]),
            with_days,
        ),
        one("ap-scharni-0-schlaglicht", "down", None, json!([]), None, None, 3, None, -63.5, json!([down]), with_days),
    ]
}

/// INCIDENT rows plus "devices": the ones that dropped out at the time.
fn sample_incidents() -> Vec<Value> {
    let names = sample_devices();
    #[allow(clippy::too_many_arguments)]
    let inc = |i: i64,
               kind: &str,
               subject: &str,
               name: Option<&str>,
               start_s: i64,
               end_s: Option<i64>,
               basis: &str,
               devices: &[usize],
               detail: Value| {
        json!({"id": i, "kind": kind, "subject": subject, "subject_name": name, "started": iso(start_s),
               "ended": end_s.map(iso), "open": end_s.is_none(), "duration_s": start_s - end_s.unwrap_or(0), "basis": basis,
               "detail": detail,
               "devices": devices.iter().map(|d| json!({"id": ids()[*d], "name": names[*d]["name"],
                                                         "owner": {"display": "Resi Example", "username": "resi"}}))
                                 .collect::<Vec<_>>()})
    };
    vec![
        inc(9, "internet_degraded", "", None, 1800, None, "measured", &[], json!({"loss_ratio": 0.07, "rtt_ms": 84})),
        inc(
            8,
            "ap_down",
            ap_mac("ap-scharni-0-schlaglicht"),
            Some("ap-scharni-0-schlaglicht"),
            2 * 3600,
            None,
            "measured",
            &[4],
            json!({"last_seen": iso(2 * 3600)}),
        ),
        inc(
            7,
            "ap_restarted",
            ap_mac("ap-scharni-2-corner"),
            Some("ap-scharni-2-corner"),
            5 * 3600,
            Some(5 * 3600 - 180),
            "measured",
            &[0, 2],
            json!({"uptime_before_s": 812_000}),
        ),
        inc(
            6,
            "switch_port_down",
            "sw-keller/7",
            Some("sw-keller port 7"),
            26 * 3600,
            Some(26 * 3600 - 600),
            "inferred",
            &[],
            json!({}),
        ),
        inc(5, "dns_down", "", None, 3 * 86400, Some(3 * 86400 - 300), "measured", &[], json!({})),
        inc(4, "radius_down", "", None, 6 * 86400, Some(6 * 86400 - 120), "measured", &[1, 2, 3], json!({})),
    ]
}

/// OVERVIEW.
fn sample_overview() -> Value {
    let incidents = sample_incidents();
    let jobs = json!([
        {"name": "unifi_events", "last_success": iso(100), "last_attempt": iso(100), "last_error": null, "duration_s": 0.84,
         "ok": true, "age_s": 100, "cursor": {}},
        {"name": "incidents", "last_success": iso(5400), "last_attempt": iso(80),
         "last_error": "Prometheus: timeout after 4.0 s <query>", "duration_s": 4.02, "ok": false, "age_s": 5400, "cursor": {}},
        {"name": "rollup", "last_success": iso(1500), "last_attempt": iso(1500), "last_error": null, "duration_s": 12.7,
         "ok": true, "age_s": 1500, "cursor": {}},
        {"name": "prune", "last_success": null, "last_attempt": null, "last_error": null, "duration_s": null, "ok": true,
         "age_s": null, "cursor": {}},
    ]);
    let mut corner = ap("ap-scharni-2-corner");
    corner["mac"] = json!(ap_mac("ap-scharni-2-corner"));
    json!({
        "generated_at": iso(0), "telemetry": "ok", "stale": false, "house": sample_house(json!({})),
        "incidents": {"available": true, "open": incidents.iter().filter(|i| i["open"] == true).collect::<Vec<_>>(),
                      "recent": incidents.iter().filter(|i| i["open"] == false).collect::<Vec<_>>(),
                      "counts_7d": {"ap_down": 1}},
        "aps": sample_aps(false),
        "auth": {"available": true, "since": iso(86400), "count": 27, "truncated": false, "devices": 2, "macs": 3,
                 "by_reason": {"unknown_cert": 23, "retired": 3, "not_eap": 1},
                 "recent": [
                     {"at": iso(420), "reason": "unknown_cert", "serial": "4f1c2a9b77e0", "device_id": ids()[3],
                      "device_name": "Kindle", "owner": {"display": "Resi Example", "username": "resi"},
                      "mac": "f0:27:2d:00:00:03", "bssid": "d2:21:f9:00:00:11", "ssid": "Example", "nas_ip": "10.10.0.21",
                      "ap": corner, "count": 4, "last_at": iso(300)},
                     {"at": iso(5400), "reason": "retired", "serial": "77aa01", "device_id": ids()[2], "device_name": "iPad",
                      "owner": {"display": "Resi Example", "username": "resi"}, "mac": "06:11:22:33:44:00", "bssid": null,
                      "ssid": "Example", "nas_ip": "10.10.0.22", "ap": null},
                     {"at": iso(20000), "reason": "not_eap", "serial": null, "device_id": null, "device_name": null,
                      "owner": null, "mac": "3c:22:fb:00:00:09", "bssid": "d2:21:f9:00:00:31", "ssid": "Example",
                      "nas_ip": "10.10.0.23", "ap": null}]},
        "jobs": jobs, "jobs_available": true,
        "freshness": {"wifi_data_age_s": 45, "prometheus": "ok", "jobs_ok": false, "oldest_job_success_age_s": 5400},
    })
}

/// RAW: every source row of the device in a time span.
fn sample_raw(device_id: &str) -> Value {
    let yesterday = now().to_zoned(jiff::tz::TimeZone::UTC).date().yesterday().expect("a day").to_string();
    json!({
        "device": {"id": device_id, "name": "Pixel 8", "revoked": false, "owner": {"username": "resi", "display": "Resi Example"}},
        "from": iso(86400), "to": iso(0),
        "windows": [{"mac": "02:00:00:00:00:00", "first_seen": iso(40 * 86400), "last_seen": iso(60), "randomized": true,
                     "auth_count": 212, "current": true, "start": iso(40 * 86400), "end": null},
                    {"mac": "06:11:22:33:44:01", "first_seen": iso(60 * 86400), "last_seen": iso(41 * 86400),
                     "randomized": true, "auth_count": 31, "current": false, "start": iso(60 * 86400),
                     "end": iso(41 * 86400 - 900)}],
        "conflicts": [{"mac": "06:11:22:33:44:01", "other_owners": 1, "from": iso(45 * 86400), "to": iso(41 * 86400)}],
        "auth": [{"at": iso(1500), "result": "accept", "reason": "ok", "mac": "02:00:00:00:00:00",
                  "bssid": "d2:21:f9:00:00:11", "ssid": "Example", "nas_ip": "10.10.0.21"},
                 {"at": iso(9000), "result": "reject", "reason": "retired", "mac": "02:00:00:00:00:00",
                  "bssid": "d2:21:f9:00:00:12", "ssid": "Example", "nas_ip": "10.10.0.22"}],
        "acct": [{"nas_ip": "10.10.0.21", "acct_session_id": "5F3A1C2B-00000042", "link": "class",
                  "mac": "02:00:00:00:00:00", "bssid": "d2:21:f9:00:00:11", "ssid": "Example", "framed_ip": "10.30.0.23",
                  "started": iso(1500), "updated": iso(60), "stopped": null, "session_time_s": null,
                  "input_octets": 12_400_000, "output_octets": 184_000_000, "terminate_cause": null},
                 {"nas_ip": "10.10.0.22", "acct_session_id": "5F3A1C2B-00000041", "link": "mac_window",
                  "mac": "02:00:00:00:00:00", "bssid": "d2:21:f9:00:00:12", "ssid": "Example", "framed_ip": null,
                  "started": iso(16000), "updated": iso(1600), "stopped": iso(1600), "session_time_s": 14400,
                  "input_octets": 96_000_000, "output_octets": 812_000_000, "terminate_cause": "Lost-Carrier"}],
        "events": [{"at": iso(1490), "kind": "connected", "source": "unifi_syslog", "mac": "02:00:00:00:00:00",
                    "ap_mac": ap_mac("ap-scharni-2-corner"), "ap_name": "ap-scharni-2-corner", "from_ap_mac": null,
                    "from_ap_name": null, "ssid": "Example", "radio": "na", "channel": 36, "rssi": -58,
                    "duration_s": null, "rx_bytes": null, "tx_bytes": null},
                   {"at": iso(1610), "kind": "disconnected", "source": "unifi_syslog", "mac": "02:00:00:00:00:00",
                    "ap_mac": ap_mac("ap-scharni-1-middle"), "ap_name": "ap-scharni-1-middle", "from_ap_mac": null,
                    "from_ap_name": null, "ssid": "Example", "radio": "ng", "channel": 6, "rssi": -71,
                    "duration_s": 14390, "rx_bytes": 812_000_000, "tx_bytes": 96_000_000}],
        "days": [{"device_id": device_id, "day": yesterday, "online_s": 61_200, "stale_s": 0, "signal_avg_dbm": -61.2,
                  "signal_p10_dbm": -70.5, "snr_avg_db": 33.1, "health_avg": 84.0, "health_min": 52.0,
                  "retry_ratio_avg": 0.05, "rx_bytes": 1_900_000_000_i64, "tx_bytes": 240_000_000,
                  "link_rx_avg_bps": 610_000_000, "roams": 4, "reconnects": 2, "disconnects": 3, "aps": {}, "bands": {},
                  "macs": 1, "auth_ok": 9, "auth_failed": 1, "computed": iso(1500)}],
        "incidents": [sample_incidents()[2]],
        "limits": {"auth": 1000, "acct": 1000, "events": 2000},
        "truncated": {"auth": false, "acct": false, "events": true},
    })
}

/// Registry rows (registry.DEVICE_LIST) for these DEVICEs.
fn registry_rows(devices: &[Value], owners: &[&str]) -> Vec<Value> {
    devices
        .iter()
        .enumerate()
        .map(|(i, d)| json!({"id": d["id"], "owner": owners[i % owners.len()], "name": d["name"], "platform": d["platform"],
                             "policy": "residents", "created": iso(40 * 86400), "revoked": null, "expires": d["expires"],
                             "certificates": 1, "last_seen": iso(0), "calling_station": d["mac"]}))
        .collect()
}

// --- the handlers' part -----------------------------------------------------------------------

fn people() -> Value {
    json!({RESIDENT_SUB: {"sub": RESIDENT_SUB, "username": "resi", "display": "Resi Example"},
           ADMIN_SUB: {"sub": ADMIN_SUB, "username": "admin", "display": "Admin Example"}})
}

fn settings() -> SettingsView {
    SettingsView {
        display_name: "Example".into(),
        home: "https://example.org/".into(),
        ssid: "Example".into(),
        passpoint: true,
    }
}

fn base(lang: &str, sub: Option<&str>, url: &str) -> Base {
    let (path, query) = url.split_once('?').unwrap_or((url, ""));
    let mut args = IndexMap::new();
    for (k, v) in url::form_urlencoded::parse(query.as_bytes()) {
        args.entry(k.into_owned()).or_insert_with(|| v.into_owned());
    }
    Base {
        lang: lang.into(),
        user: sub.map(|s| User { sub: s.into(), username: s.into(), name: s.into(), admin: s == ADMIN_SUB }),
        csrf: "example-csrf".into(),
        settings: settings(),
        host: "wifi.example.org".into(),
        no_passpoint_browser: false,
        request: RequestView { path: path.into(), args },
    }
}

fn render(name: &str, base: &Base, page: Value) -> String {
    match TEMPLATES.render(name, base, minijinja::Value::from(Serde(page))) {
        Ok(html) => html,
        Err(e) => panic!("{name}: {e:#}\n{}", e.display_debug_info()),
    }
}

/// The pages as the handlers render them, from the samples (Python DashboardPagesTestCase).
struct Site {
    devices: Vec<Value>,
    overview: Value,
    aps: Value,
    telemetry: &'static str,
    rows: Vec<Value>,
    incidents: Option<Value>,
}

impl Site {
    fn new() -> Site {
        let devices = sample_devices();
        // the resident owns the first four, the admin the sensor; one more row of somebody else
        let mut rows = registry_rows(&devices, &[RESIDENT_SUB, RESIDENT_SUB, RESIDENT_SUB, RESIDENT_SUB, ADMIN_SUB]);
        let mut other = registry_rows(&[device(0, "Other", "offline", json!({}))], &[RESIDENT_SUB]).remove(0);
        merge(&mut other, json!({"id": id(99), "owner": "sub-other"}));
        rows.push(other);
        Site {
            devices,
            overview: sample_overview(),
            aps: json!({"generated_at": iso(0), "telemetry": "ok", "aps": sample_aps(true)}),
            telemetry: "ok",
            rows,
            incidents: None,
        }
    }

    fn v2() -> Site {
        Site { devices: v2_devices(), ..Site::new() }
    }

    /// telemetry.dashboard: the sample DEVICEs of these rows, in their order, with owners and
    /// the renewal hint (web.py dashboard()).
    fn dashboard(&self, rows: &[&Value], owners: Option<&Value>) -> Value {
        let mut payload = sample_dashboard(self.telemetry, Some(self.devices.clone()), json!({}));
        let all = payload["devices"].as_array().cloned().unwrap_or_default();
        let mut devices = Vec::new();
        for r in rows {
            if let Some(d) = all.iter().find(|d| d["id"] == r["id"]) {
                let mut d = d.clone();
                if let Some(owners) = owners {
                    let person = &owners[r["owner"].as_str().unwrap_or("")];
                    d["owner"] = json!({"username": person["username"], "display": person["display"]});
                }
                d["expires_soon"] = json!(netportal_web::render::views::expires_soon(&r["expires"]));
                devices.push(d);
            }
        }
        payload["devices"] = json!(devices);
        payload
    }

    fn history(range: &str) -> Value {
        if ["24h", "7d", "30d"].contains(&range) { sample_history(range) } else { v2_history(range) }
    }

    fn device_page(&self, url: &str, lang: &str, sub: &str, id: &str, admin_view: bool) -> String {
        let is_admin = sub == ADMIN_SUB;
        let row = self
            .rows
            .iter()
            .find(|r| r["id"] == id && (is_admin || r["owner"] == sub))
            .unwrap_or_else(|| panic!("{url}: not found"));
        let payload = self.dashboard(&[row], is_admin.then(people).as_ref());
        let b = base(lang, Some(sub), url);
        let asked = b.request.args.get("range").cloned().unwrap_or_else(|| "24h".into());
        let range = if codes("RANGES").contains(&asked) { asked } else { "24h".into() };
        let mut page = json!({"dashboard": payload, "device": payload["devices"][0], "row": row,
                              "history": Site::history(&range), "ranges": codes("RANGES")});
        if admin_view {
            merge(&mut page, json!({"admin_view": true, "raw": sample_raw(id)}));
        }
        render("device.html", &b, page)
    }

    /// GET `url` as `sub` in `lang`.
    fn get(&self, url: &str, lang: &str, sub: &str) -> String {
        let path = url.split('?').next().unwrap_or(url);
        let b = base(lang, Some(sub), url);
        if let Some(id) = path.strip_prefix("/admin/devices/") {
            assert_eq!(sub, ADMIN_SUB, "{url}: admins only");
            return self.device_page(url, lang, sub, id, true);
        }
        if let Some(id) = path.strip_prefix("/devices/") {
            return self.device_page(url, lang, sub, id, false);
        }
        match path {
            "/" => {
                let own: Vec<&Value> = self.rows.iter().filter(|r| r["owner"] == sub).collect();
                let page = json!({"devices": own, "dashboard": self.dashboard(&own, None),
                                  "options": ["apple", "apple-mac", "android", "android-app", "windows", "linux"]});
                render("devices.html", &b, page)
            }
            "/admin" => {
                assert_eq!(sub, ADMIN_SUB, "{url}: admins only");
                let all: Vec<&Value> = self.rows.iter().collect();
                let page = json!({"devices": all, "people": people(), "dashboard": self.dashboard(&all, Some(&people())),
                                  "overview": self.overview});
                render("admin.html", &b, page)
            }
            "/admin/aps" => render("admin_aps.html", &b, json!({"aps": self.aps})),
            "/admin/incidents" => {
                let payload = self.incidents.clone().unwrap_or_else(|| {
                    let until = Timestamp::now().as_second();
                    let span = match b.request.args.get("range").map(String::as_str) {
                        Some("30d") => 30 * 86400,
                        Some("90d") => 90 * 86400,
                        Some("1y") => 365 * 86400,
                        _ => 7 * 86400,
                    };
                    let kind = b.request.args.get("kind").filter(|k| !k.is_empty()).cloned();
                    let items: Vec<Value> = sample_incidents()
                        .into_iter()
                        .filter(|i| kind.as_deref().is_none_or(|k| i["kind"] == k))
                        .collect();
                    json!({"from": rfc3339(until - span), "to": rfc3339(until), "kind": kind, "incidents": items,
                           "truncated": false, "counts": {}})
                });
                let span = json!({"from": payload["from"], "to": payload["to"], "kind": payload["kind"].as_str().unwrap_or("")});
                let page = json!({"incidents": payload, "span": span, "incident_kinds": codes("INCIDENT_KINDS")});
                render("admin_incidents.html", &b, page)
            }
            other => panic!("no page {other}"),
        }
    }
}

// --- assertions -------------------------------------------------------------------------------

/// The page without its JSON blocks (they hold every text).
fn visible(page: &str) -> String {
    static SCRIPTS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?s)<script.*?</script>").expect("a pattern"));
    SCRIPTS.replace_all(page, "").into_owned()
}

fn json_block(page: &str, block_id: &str) -> Value {
    let re = Regex::new(&format!(r#"(?s)<script type="application/json" id="{block_id}">(.*?)</script>"#))
        .expect("a pattern");
    let body = re.captures(page).and_then(|c| c.get(1)).unwrap_or_else(|| panic!("no block {block_id}")).as_str();
    serde_json::from_str(body).unwrap_or_else(|e| panic!("{block_id}: {e}"))
}

/// No inline code: scripts are static files (modules) or JSON data blocks; no event handler
/// attributes, no inline styles; the CSRF token is in a meta tag for the rename. (The CSP header
/// itself is the handlers'.)
fn assert_csp_safe(page: &str) {
    static SCRIPT: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?s)<script\b([^>]*)>(.*?)</script>").expect("a pattern"));
    static MODULE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#"type="module" src="/static/[a-z]+\.js""#).expect("a pattern"));
    static HANDLER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\son[a-z]+=").expect("a pattern"));
    for c in SCRIPT.captures_iter(page) {
        let (attrs, body) = (&c[1], &c[2]);
        if attrs.contains("src=") {
            assert!(MODULE.is_match(attrs), "{attrs}");
            assert_eq!(body.trim(), "");
        } else {
            assert!(attrs.contains(r#"type="application/json""#), "{attrs}");
            assert!(serde_json::from_str::<Value>(body).is_ok(), "a JSON block that is not JSON: {attrs}");
        }
    }
    assert!(!HANDLER.is_match(page), "an inline event handler");
    assert!(!page.contains("style="), "an inline style");
    assert!(page.contains(r#"<meta name="csrf" content="example-csrf">"#));
}

fn unescape(text: &str) -> String {
    text.replace("&lt;", "<").replace("&gt;", ">").replace("&#34;", "\"").replace("&#39;", "'").replace("&amp;", "&")
}

/// (name, hidden) of the admin list in page order.
fn names(page: &str) -> Vec<(String, bool)> {
    static ITEM: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?s)<li class="adm-item"([^>]*)>.*?class="adm-name" data-part="sum-name">(.*?)</strong>"#)
            .expect("a pattern")
    });
    ITEM.captures_iter(page).map(|c| (unescape(&c[2]), c[1].contains("hidden"))).collect()
}

fn shown_names(page: &str) -> Vec<String> {
    names(page).into_iter().filter(|(_, hidden)| !hidden).map(|(n, _)| n).collect()
}

fn index(page: &str, needle: &str) -> usize {
    page.find(needle).unwrap_or_else(|| panic!("not in the page: {needle}"))
}

fn index_from(page: &str, needle: &str, from: usize) -> usize {
    from + page[from..].find(needle).unwrap_or_else(|| panic!("not in the page: {needle}"))
}

/// The page from device i's card to device j's.
fn between(page: &str, i: usize, j: usize) -> String {
    let start = index(page, &format!(r#"id="device-{}""#, ids()[i]));
    let end = index(page, &format!(r#"id="device-{}""#, ids()[j]));
    page[start..end].to_string()
}

/// Device i's card (to its `</article>`).
fn card(page: &str, i: usize) -> String {
    let start = index(page, &format!(r#"id="device-{}""#, ids()[i]));
    page[start..index_from(page, "</article>", start)].to_string()
}

fn texts_json(lang: &str) -> Value {
    let map: serde_json::Map<String, Value> = i18n::texts(lang)
        .iter()
        .map(|(k, v)| {
            let v = match v {
                Text::One(s) => json!(s),
                Text::List(items) => json!(items),
            };
            (k.clone(), v)
        })
        .collect();
    Value::Object(map)
}

/// A source file of another crate of the workspace (the backend these pages show), if present.
fn sibling_source(path: &str) -> Option<String> {
    let file = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(path);
    match std::fs::read_to_string(&file) {
        Ok(text) => Some(text),
        Err(e) => {
            eprintln!("skipped: {} not readable ({e})", file.display());
            None
        }
    }
}

// === DevicesPageTests ===========================================================================

mod devices_page_tests {
    use super::*;

    #[test]
    fn test_every_language_renders_every_state() {
        let site = Site::new();
        for lang in LANGS {
            let page = site.get("/", lang, RESIDENT_SUB);
            assert_csp_safe(&page);
            assert!(page.contains(&format!(r#"<html lang="{lang}">"#)));
            for state in ["online", "offline", "never_connected"] {
                assert!(page.contains(&format!(r#"class="dev-state state-{state}""#)), "{state}");
                assert!(page.contains(&t(lang, &format!("state_{state}"))));
            }
            for key in ["house_title", "house_speed_note", "diag_weak_signal", "diag_weak_signal_do", "f_link_note"] {
                assert!(page.contains(&esc(&t(lang, key))), "{lang} {key}");
            }
            assert!(!visible(&page).contains('{'), "every placeholder filled");
        }
    }

    #[test]
    fn test_the_cards_are_complete_without_javascript() {
        let page = Site::new().get("/", "de", RESIDENT_SUB);
        for text in [
            "Scharni · 2. Stock · Ecke",
            "5 GHz · Kanal 36 · Wi-Fi 6",
            "\u{2212}58 dBm",
            "88 von 100",
            "2,4 Mbit/s",
            "1,8 GB",
            "866 Mbit/s",
            "verbunden seit",
            "zuletzt gesehen",
            "Stand",
        ] {
            assert!(page.contains(text), "{text}");
        }
        assert!(page.contains(&format!(r#"href="/devices/{}""#, ids()[0])));
        assert!(page.contains(&format!(r#"action="/devices/{}/rename""#, ids()[0])));
        assert!(page.contains(&esc(&t("de", "diag_never_connected_do"))));
        assert!(page.contains(&t("de", "expires_badge")));
        assert!(page.contains(&format!(r#"action="/devices/{}/renew""#, ids()[2])));
        assert!(page.contains(r#"value="android""#));
        assert!(page.contains(r#"id="add""#));
    }

    #[test]
    fn test_a_card_shows_two_findings_and_links_to_the_rest() {
        let page = Site::new().get("/", "en", RESIDENT_SUB);
        let card = between(&page, 1, 2);
        assert_eq!(card.matches(r#"class="finding sev-"#).count(), 2);
        assert!(card.contains(&fill(&t("en", "diag_more"), &[("n", "3")])));
    }

    #[test]
    fn test_the_name_is_a_heading_with_an_edit_button() {
        let page = Site::new().get("/", "en", RESIDENT_SUB);
        let card = between(&page, 0, 1);
        assert!(card.contains(r#"<h2 class="dev-name-text" data-name>Pixel 8</h2>"#));
        assert!(card.contains(r#"<summary class="edit-button" title="Rename">"#));
        assert!(card.contains(r#"<span class="sr" data-name-label>Rename: Pixel 8</span>"#));
        let form = &card[index(&card, &format!(r#"<form method="post" action="/devices/{}/rename""#, ids()[0]))..];
        let form = &form[..index(form, "</form>")];
        assert!(form.contains(r#"name="csrf" value="example-csrf""#));
        assert!(form.contains(r#"name="name" value="Pixel 8""#));
        assert!(form.contains(r#"class="button small needs-js" data-cancel"#));
        assert!(!page.contains(r#"class="pill">Save"#));
    }

    #[test]
    fn test_a_conflicting_address_shows_the_finding_not_no_data() {
        let mut site = Site::new();
        merge(
            &mut site.devices[0],
            json!({
            "state": "unknown", "signal_dbm": null, "health": null, "ap": null, "rx_bps": null, "tx_bps": null,
            "link_rx_bps": null, "link_tx_bps": null, "rx_24h_bytes": null, "tx_24h_bytes": null, "since": null,
            "last_seen": null, "diagnostics": [{"code": "mac_conflict", "severity": "warn", "params": {"owners": 2}}]}),
        );
        for lang in LANGS {
            let page = site.get("/", lang, RESIDENT_SUB);
            let card = between(&page, 0, 1);
            assert!(card.contains(&esc(&t(lang, "diag_mac_conflict"))));
            assert!(card.contains(&esc(&t(lang, "diag_mac_conflict_do"))));
            assert!(!card.contains(&esc(&t(lang, "unknown_line"))));
            assert!(!card.contains(&esc(&t(lang, "diag_mac_conflict_admin_do"))), "the residents' text");
            let page = site.get(&format!("/devices/{}", ids()[0]), lang, RESIDENT_SUB);
            assert!(page.contains(&esc(&t(lang, "diag_mac_conflict_why"))));
            let page = site.get("/admin", lang, ADMIN_SUB);
            assert!(page.contains(&esc(&fill(&t(lang, "diag_mac_conflict_admin_why"), &[("n", "2")]))));
            assert!(page.contains(&esc(&t(lang, "diag_mac_conflict_admin_do"))));
        }
    }

    #[test]
    fn test_names_are_escaped() {
        let page = Site::new().get("/admin", "en", ADMIN_SUB);
        assert!(page.contains("Sensor &lt;&amp;&gt; &#34;Werkstatt&#34;"));
        assert!(!page.contains(r#"Sensor <&> "Werkstatt""#));
        let data = json_block(&page, "np-data");
        assert!(data["devices"].as_array().into_iter().flatten().any(|d| d["name"] == r#"Sensor <&> "Werkstatt""#));
    }

    #[test]
    fn test_the_scripts_get_texts_config_and_data() {
        let page = Site::new().get("/", "uk", RESIDENT_SUB);
        assert_eq!(json_block(&page, "np-texts"), texts_json("uk"));
        let config = json_block(&page, "np-config");
        assert_eq!(config["api"], "/api/devices");
        assert_eq!(config["page"], "devices");
        let shown: Vec<Value> =
            json_block(&page, "np-data")["devices"].as_array().into_iter().flatten().map(|d| d["id"].clone()).collect();
        assert_eq!(shown, ids()[..4].iter().map(|i| json!(i)).collect::<Vec<_>>());
    }

    #[test]
    fn test_no_devices() {
        let site = Site { devices: vec![], ..Site::new() };
        let page = site.get("/", "en", RESIDENT_SUB);
        assert!(page.contains(&t("en", "no_devices")));
        assert!(index(&page, r#"id="add""#) < index(&page, r#"id="devices-h""#), "enrolment first");
    }

    /// Python removed the `fmt` global and checked the crude fallback. The Rust templates always
    /// have the formatting (it is registered by the render module itself): the page shows the
    /// formatted value and the state.
    #[test]
    fn test_without_the_formatting_global_the_page_still_renders() {
        let page = Site::new().get("/", "en", RESIDENT_SUB);
        assert!(page.contains("\u{2212}58 dBm"));
        assert!(page.contains(&t("en", "state_online")));
    }
}

// === TelemetryStatesTests =======================================================================

mod telemetry_states_tests {
    use super::*;

    #[test]
    fn test_off() {
        let site = Site { telemetry: "off", ..Site::new() };
        for lang in LANGS {
            let page = site.get("/", lang, RESIDENT_SUB);
            assert!(page.contains(&esc(&t(lang, "telemetry_off"))));
            assert!(page.contains(r#"data-part="house" hidden"#), "no house strip of unknowns");
            assert!(page.contains("state-unknown"));
            assert!(page.contains("state-never_connected"));
            assert!(!visible(&page).contains(&esc(&t(lang, "all_good"))), "no \"all good\" without data");
        }
    }

    #[test]
    fn test_unavailable() {
        let site = Site { telemetry: "unavailable", ..Site::new() };
        let page = site.get("/", "de", RESIDENT_SUB);
        assert!(page.contains(&esc(&t("de", "telemetry_unavailable"))));
        assert!(page.contains(r#"data-part="house" hidden"#));
        assert!(page.contains(&t("de", "st_unknown")));
        assert!(page.contains(&t("de", "house_speed_none")));
    }

    #[test]
    fn test_stale() {
        let dashboard = sample_dashboard(
            "ok",
            None,
            json!({"stale": true, "house": sample_house(json!({"wifi_data_age_s": 1500}))}),
        );
        let page = render(
            "devices.html",
            &base("en", None, "/"),
            json!({"dashboard": dashboard, "devices": [], "options": ["apple"]}),
        );
        let stale = t("en", "live_stale");
        assert!(page.contains(&esc(stale.split('{').next().unwrap_or(""))));
        assert!(page.contains(&esc(&fill(&t("en", "house_wifi_age"), &[("age", "25 min")]))));
    }
}

// === DevicePageTests ============================================================================

mod device_page_tests {
    use super::*;

    #[test]
    fn test_every_language_and_state() {
        let site = Site::new();
        for lang in LANGS {
            for i in 0..site.devices.len() {
                let page = site.get(&format!("/devices/{}", ids()[i]), lang, ADMIN_SUB);
                assert_csp_safe(&page);
                assert!(page.contains(&esc(&t(lang, "history_title"))));
                for key in ["signal", "quality", "traffic", "link", "online"] {
                    assert!(page.contains(&format!(r#"data-chart="{key}""#)));
                    assert!(page.contains(&esc(&t(lang, &format!("ch_{key}")))));
                }
                assert!(page.contains(&esc(&t(lang, "ch_needs_js"))), "in <noscript>: the list works without");
                assert!(page.contains(r#"class="chart-grid needs-js""#));
                assert!(page.contains(&format!(r#"aria-current="true">{}<"#, t(lang, "range_24h"))));
                let config = json_block(&page, "np-config");
                assert_eq!(config["device"], ids()[i]);
                assert_eq!(config["history"], format!("/api/devices/{}/history", ids()[i]));
            }
        }
    }

    #[test]
    fn test_details_and_full_findings() {
        let page = Site::new().get(&format!("/devices/{}", ids()[1]), "en", RESIDENT_SUB);
        for code in ["weak_signal", "high_retries", "busy_channel", "unstable_roaming", "stuck_on_2ghz"] {
            assert!(page.contains(&esc(&t("en", &format!("diag_{code}_why")))), "{code}");
            assert!(page.contains(&esc(&t("en", &format!("diag_{code}_do")))), "{code}");
        }
        for text in [
            "02:00:00:00:00:01",
            "10.30.0.41",
            "ap-colbe-0-far",
            "Colbe · ground floor · far end",
            "2.4 GHz · channel 6 · Wi-Fi 4",
            "7 per hour",
            "24%",
        ] {
            assert!(page.contains(text), "{text}");
        }
    }

    #[test]
    fn test_range_from_the_address() {
        let site = Site::new();
        let page = site.get(&format!("/devices/{}?range=7d", ids()[0]), "en", RESIDENT_SUB);
        assert!(page.contains(r#"aria-current="true">7 days<"#));
        assert_eq!(json_block(&page, "np-config")["range"], "7d");
        let page = site.get(&format!("/devices/{}?range=1y", ids()[0]), "en", RESIDENT_SUB);
        assert!(page.contains(r#"aria-current="true">1 year<"#), "telemetry v2: up to \"all\"");
        let page = site.get(&format!("/devices/{}?range=2y", ids()[0]), "en", RESIDENT_SUB);
        assert!(page.contains(r#"aria-current="true">24 hours<"#));
    }

    #[test]
    fn test_from_the_admin_page() {
        let page = Site::new().get(&format!("/devices/{}?from=admin", ids()[0]), "en", ADMIN_SUB);
        assert!(page.contains(r#"href="/admin""#));
        assert!(page.contains(r#"name="back" value="/admin""#));
        assert_eq!(json_block(&page, "np-config")["admin"], true);
        assert!(page.contains("Resi Example"), "the owner");
    }

    #[test]
    fn test_the_event_list_without_javascript() {
        let dashboard = sample_dashboard("ok", None, json!({}));
        let page = render(
            "device.html",
            &base("en", None, "/devices/x"),
            json!({"device": dashboard["devices"][0], "dashboard": dashboard, "history": sample_history("24h")}),
        );
        assert!(page.contains("Connected: Scharni · 2nd floor · corner (5 GHz)"));
        assert!(page.contains("Moved from Scharni · 1st floor · middle to Colbe · ground floor · far end"));
        assert!(page.contains("Switched from 5 GHz to 2.4 GHz"));
        assert!(page.contains(&t("en", "tl_disconnected")));
        assert!(index(&page, "Switched from") < index(&page, "Moved from"), "newest first");
        assert!(page.contains(&esc(&t("en", "ch_needs_js"))));
        assert!(page.contains(r#"class="card timeline-card""#), "shown without scripting");
    }
}

// === AdminPageTests =============================================================================

mod admin_page_tests {
    use super::*;

    #[test]
    fn test_every_language() {
        let site = Site::new();
        for lang in LANGS {
            let page = site.get("/admin", lang, ADMIN_SUB);
            assert_csp_safe(&page);
            assert_eq!(
                page.matches(r#"class="adm-item""#).count(),
                site.rows.len() - 1,
                "\"Other\" has no telemetry sample"
            );
            assert!(page.contains(&esc(&t(lang, "adm_search_ph"))));
            assert_eq!(page.matches(r#"action="/devices/"#).count(), site.rows.len() - 1, "a revoke form per device");
            assert!(page.contains(r#"name="back" value="/admin""#));
            for code in codes("DIAGNOSES") {
                assert!(page.contains(&format!(r#"<option value="{code}""#)), "{code}");
            }
        }
    }

    #[test]
    fn test_search_filters_and_sorting_without_javascript() {
        let site = Site::new();
        let get = |url: &str| site.get(url, "en", ADMIN_SUB);
        assert_eq!(shown_names(&get("/admin?q=MAC")), ["MacBook Air"]);
        assert_eq!(shown_names(&get("/admin?q=02-00-00-00-00-02")), ["iPad"], "a MAC as the AP writes it");
        assert_eq!(shown_names(&get("/admin?q=admin%20example")), [r#"Sensor <&> "Werkstatt""#], "the owner");
        assert_eq!(shown_names(&get("/admin?state=offline")), ["iPad"]);
        assert_eq!(
            shown_names(&get("/admin?problem=with&sort=signal")),
            ["MacBook Air", r#"Sensor <&> "Werkstatt""#, "iPad"]
        );
        let page = get("/admin?problem=slow_link");
        assert_eq!(shown_names(&page), [r#"Sensor <&> "Werkstatt""#]);
        assert!(page.contains("1 of 5 shown"));
        let all = names(&get("/admin?sort=seen"));
        assert_eq!(all.last().map(|(n, _)| n.as_str()), Some("Kindle"), "never seen: last");
        assert!(!get("/admin?q=nothing-matches").contains("data-none hidden"));
    }

    #[test]
    fn test_problem_badges() {
        let page = Site::new().get("/admin", "en", ADMIN_SUB);
        assert!(page.contains("problems: 4"), "MacBook: warn and bad only, not the info");
        assert!(page.contains("badge sev-bad"));
    }
}

// === TextTests ==================================================================================

mod text_tests {
    use super::*;

    /// Python scanned diagnostics.py for its codes; here the Rust backend's (netportal-telemetry).
    #[test]
    fn test_every_diagnosis_has_its_texts_in_every_language() {
        if let Some(source) = sibling_source("netportal-telemetry/src/diagnostics.rs") {
            let re = Regex::new(r#"finding\(\s*"([a-z_0-9]+)""#).expect("a pattern");
            let reported: Vec<String> = re.captures_iter(&source).map(|c| c[1].to_string()).collect();
            assert!(!reported.is_empty());
            for code in &reported {
                assert!(codes("DIAGNOSES").contains(code), "reported without a text: {code}");
            }
        }
        for lang in i18n::languages() {
            for code in codes("DIAGNOSES") {
                for suffix in ["", "_why", "_do"] {
                    assert!(
                        i18n::text(lang, &format!("diag_{code}{suffix}")).is_some_and(|s| !s.is_empty()),
                        "{lang} {code}{suffix}"
                    );
                }
            }
        }
    }

    #[test]
    fn test_rooms() {
        let a = json!({"name": "ap-scharni-0-corner", "house": "scharni", "floor": 0, "spot": "corner"});
        assert_eq!(fmt::room(&a, "en"), "Scharni · ground floor · corner");
        assert_eq!(fmt::room(&a, "de"), "Scharni · Erdgeschoss · Ecke");
        assert_eq!(fmt::room(&a, "uk"), "Scharni · перший поверх · кут");
        assert_eq!(
            fmt::room(&json!({"name": "2. stock scharni mitte", "house": null}), "de"),
            "2. stock scharni mitte"
        );
        assert_eq!(
            fmt::room(&json!({"name": "ap-x-9-y", "house": "x", "floor": 9, "spot": "y"}), "en"),
            "X · floor 9 · y"
        );
        for lang in LANGS {
            for spot in ["corner", "middle", "far"] {
                assert!(i18n::text(lang, &format!("room_spot_{spot}")).is_some());
            }
        }
    }

    #[test]
    fn test_formatting() {
        let at = |s: i64| json!(iso(s));
        assert_eq!(fmt::bytes(Some(1_830_000_000.0), "de"), "1,8 GB");
        assert_eq!(fmt::bitrate(Some(950.0), "en"), "950 bit/s");
        assert_eq!(fmt::duration(Some(8130.0), "uk", 2), "2 год 15 хв");
        assert_eq!(fmt::ago(&at(3 * 3600), "en", Some(now())), "3 h ago");
        assert_eq!(fmt::when(&at(0), "en", Some(now())), "13:00", "the house's time (CET)");
        assert_eq!(fmt::number(Some(12345.6), "uk", 1), "12\u{a0}345,6");
        assert_eq!(fmt::bytes(None, "en"), "\u{2013}");
        assert_eq!(fmt::bitrate(None, "en"), "\u{2013}");
        assert_eq!(fmt::dbm(None, "en"), "\u{2013}");
        assert_eq!(fmt::percent(None, "en", 0), "\u{2013}");
        assert_eq!(fmt::duration(None, "en", 2), "\u{2013}");
        assert_eq!(fmt::date(&Value::Null, "en"), "\u{2013}");
        assert_eq!(fmt::signal(Some(-70.0)), Some((2, "sig_fair", "warn")));
        assert_eq!(fmt::health(None), None);
    }
}

// === telemetry v2 ===============================================================================

/// One finding of every code the backend can report, as it reports them.
fn all_findings() -> Vec<Value> {
    let mut by_code: IndexMap<String, Value> = IndexMap::new();
    for d in v2_devices() {
        for f in d["diagnostics"].as_array().into_iter().flatten() {
            by_code.insert(f["code"].as_str().unwrap_or("").to_string(), f.clone());
        }
    }
    for f in [
        finding(
            "low_snr",
            "warn",
            "measured",
            Some(json!({"snr_db": 14, "noise_dbm": -88, "signal_dbm": -70, "warn_db": 20})),
            json!({}),
        ),
        finding("busy_channel", "warn", "measured", None, json!({"channel_util": 0.72, "channel": 6})),
        finding(
            "slow_link",
            "warn",
            "measured",
            Some(json!({"link_rx_bps": 6_500_000, "signal_dbm": -62, "throughput_bps": 2e6})),
            json!({}),
        ),
        finding(
            "stale_data",
            "warn",
            "measured",
            Some(json!({"age_s": 900, "threshold_s": 600})),
            json!({"age_s": 900}),
        ),
        finding(
            "cert_expired",
            "bad",
            "measured",
            Some(json!({"expires": iso(86400), "days_left": -1})),
            json!({"expires": iso(86400)}),
        ),
        finding(
            "mac_conflict",
            "warn",
            "measured",
            Some(json!({"owners": 2, "macs": ["02:00:00:00:00:00"]})),
            json!({"owners": 2}),
        ),
    ] {
        by_code.insert(f["code"].as_str().unwrap_or("").to_string(), f);
    }
    codes("DIAGNOSES").iter().map(|c| by_code.get(c).cloned().unwrap_or_else(|| panic!("no sample {c}"))).collect()
}

fn events_of(page: &str) -> String {
    let start = index(page, "data-events>");
    page[start..index_from(page, "</ol>", start)].to_string()
}

mod v2_device_pages_tests {
    use super::*;

    #[test]
    fn test_how_each_device_connects_in_every_language() {
        let site = Site::v2();
        for lang in LANGS {
            let page = site.get("/", lang, RESIDENT_SUB);
            assert_csp_safe(&page);
            assert!(!visible(&page).contains('{'));
            for (i, mode) in [(0, "random_fixed"), (1, "hardware"), (2, "rotating"), (3, "hardware")] {
                let card = card(&page, i);
                assert!(card.contains(&format!(r#"class="conn-line mm-{mode}""#)), "{lang} {mode}");
                assert!(card.contains(&esc(&t(lang, &format!("mm_{mode}")))));
            }
            let ipad = card(&page, 2);
            assert!(ipad.contains(&esc(&t(lang, "mm_rotating_do"))));
            assert!(ipad.contains(&esc(&fill(&t(lang, "mm_how_apple"), &[("ssid", "Example")]))));
            assert!(!ipad.contains(&esc(&t(lang, "mm_admin_rotating"))), "the admins' words stay theirs");
            assert!(!card(&page, 0).contains(r#"class="advice""#), "a fixed address needs no advice");
        }
    }

    #[test]
    fn test_the_advice_follows_the_platform() {
        let mut site = Site::v2();
        for (platform, key) in [
            ("apple-mac", "mm_how_apple-mac"),
            ("android", "mm_how_android"),
            ("letswifi", "mm_how_other"),
            ("eap-config", "mm_how_other"),
        ] {
            site.devices[2]["platform"] = json!(platform);
            let page = site.get("/", "de", RESIDENT_SUB);
            assert!(card(&page, 2).contains(&esc(&fill(&t("de", key), &[("ssid", "Example")]))), "{platform}");
        }
    }

    #[test]
    fn test_rejected_logins_say_why_and_what_to_do() {
        let mut site = Site::v2();
        for lang in LANGS {
            let page = site.get("/", lang, RESIDENT_SUB);
            let kindle = card(&page, 3);
            assert!(kindle.contains(r#"class="alert tone-bad""#));
            for key in ["la_rejected_title", "rr_unknown_cert", "rr_unknown_cert_do"] {
                assert!(kindle.contains(&esc(&t(lang, key))), "{lang} {key}");
            }
            assert!(!kindle.contains(&esc(&t(lang, "rr_unknown_cert_admin"))));
            assert!(kindle.contains(r#"class="conn-line la-reject""#));
            assert!(!card(&page, 0).contains(r#"class="alert"#), "an accepted login: a line, no alert");
            assert!(card(&page, 0).contains(r#"class="conn-line la-accept""#));
        }
        let mut reasons = codes("REJECT_REASONS");
        reasons.push("something-unknown".into());
        for reason in reasons {
            site.devices[3]["last_auth"] = json!({"at": iso(60), "result": "reject", "reason": reason});
            let page = site.get(&format!("/devices/{}", ids()[3]), "uk", RESIDENT_SUB);
            let key = fmt::reason_key(&json!(reason));
            assert!(page.contains(&esc(&t("uk", &format!("rr_{key}")))), "{reason}");
            assert!(!visible(&page).contains('{'));
        }
    }

    #[test]
    fn test_cards_show_the_evidence_and_the_estimated_tag() {
        let site = Site::v2();
        let page = site.get("/", "en", RESIDENT_SUB);
        assert!(card(&page, 1).contains(r#"<span class="evidence">24%</span>"#));
        let ipad = card(&page, 2);
        assert!(ipad.contains(r#"<span class="evidence">8 times in 24 hours</span>"#));
        assert!(!ipad.contains(&esc(&t("en", "ev_based_on"))), "the full line only on the device page");
        let page = site.get(&format!("/devices/{}", ids()[2]), "en", RESIDENT_SUB);
        assert!(page.contains(&esc(&t("en", "ev_based_on"))));
        assert!(page.contains("drop-outs reported by the access points <b>7</b>"));
        assert!(page.contains(&esc(&t("en", "cause_lost_carrier"))));
        assert!(page.contains(r#"class="finding sev-info inferred""#));
        assert!(page.contains(&format!(
            r#"<span class="basis-tag" title="{}">{}"#,
            esc(&t("en", "basis_inferred_hint")),
            t("en", "basis_inferred")
        )));
        assert!(page.contains(&esc(&t("en", "ev_last_24h"))));
        assert!(!visible(&page).contains("reconnects_24h"), "no field names for residents");
        assert!(!visible(&page).contains("margin_s"));
    }

    #[test]
    fn test_every_finding_code_renders_in_every_language() {
        let mut site = Site::v2();
        site.devices[1]["diagnostics"] = json!(all_findings());
        site.devices[1]["state"] = json!("offline");
        for lang in LANGS {
            for (url, sub, admin) in [
                (format!("/devices/{}", ids()[1]), RESIDENT_SUB, false),
                (format!("/admin/devices/{}", ids()[1]), ADMIN_SUB, true),
            ] {
                let page = site.get(&url, lang, sub);
                assert_csp_safe(&page);
                let shown = visible(&page);
                assert!(!shown.contains('{'), "{url} {lang}");
                for f in all_findings() {
                    let key = format!("diag_{}", f["code"].as_str().unwrap_or(""));
                    assert!(shown.contains(&esc(&t(lang, &key))), "{lang} {key}");
                    let admin_do = i18n::text(lang, &format!("{key}_admin_do")).filter(|s| !s.is_empty());
                    let todo = match admin_do {
                        Some(text) if admin => text.to_string(),
                        _ => t(lang, &format!("{key}_do")),
                    };
                    assert!(shown.contains(&esc(&todo)), "{lang} {key} do");
                    for (label, value) in fmt::evidence_items(&f, lang, admin).0 {
                        assert!(shown.contains(&esc(&value)), "{lang} {key} {label}: {value}");
                    }
                }
                if !admin {
                    for word in ["count_24h", "tx_attempts_per_s", "min_macs", "locked_out", "threshold_s"] {
                        assert!(!shown.contains(word), "{word}");
                    }
                }
            }
        }
    }

    #[test]
    fn test_the_merged_timeline_without_javascript() {
        let site = Site::v2();
        for lang in LANGS {
            let page = site.get(&format!("/devices/{}?range=90d", ids()[0]), lang, RESIDENT_SUB);
            let events = events_of(&page);
            for kind in codes("EVENT_KINDS") {
                assert!(events.contains(&format!(r#"class="ev ev-{kind}"#)), "{lang} {kind}");
            }
            assert!(events.contains(r#"class="ev ev-band_changed ev-inferred""#));
            assert!(events.contains(&esc(&fill(&t(lang, "tl_auth_rejected"), &[("reason", &t(lang, "rr_retired"))]))));
            assert!(
                events.contains(&esc(&fill(&t(lang, "tl_session_ended"), &[("cause", &t(lang, "cause_nas_reboot"))])))
            );
            for key in ["src_unifi_syslog", "inc_internet_degraded", "inc_open"] {
                assert!(events.contains(&esc(&t(lang, key))), "{lang} {key}");
            }
            assert!(!events.contains("NAS-Reboot"), "the raw cause is the admins'");
            assert!(!visible(&page).contains('{'));
        }
        let page = site.get(&format!("/admin/devices/{}?range=90d", ids()[0]), "en", ADMIN_SUB);
        let events = events_of(&page);
        assert!(events.contains("NAS-Reboot"));
        assert!(events.contains(&esc(&t("en", "src_admin_unifi_syslog"))));
        assert!(events.contains(&esc(&t("en", "rr_retired_admin"))));
        assert!(events.contains("06:11:22:33:44:01"), "the new MAC");
    }

    #[test]
    fn test_every_range() {
        let site = Site::v2();
        for lang in LANGS {
            for r in codes("RANGES") {
                let page = site.get(&format!("/devices/{}?range={r}", ids()[0]), lang, RESIDENT_SUB);
                assert_csp_safe(&page);
                assert!(page.contains(&format!(r#"aria-current="true">{}<"#, t(lang, &format!("range_{r}")))));
                assert_eq!(json_block(&page, "np-config")["range"], r.as_str());
                assert_eq!(json_block(&page, "np-data")["history"]["range"], r.as_str());
                let days = r == "1y" || r == "all";
                assert_eq!(page.contains("data-days-note hidden"), !days, "{r}");
                if days {
                    assert!(page.contains(&esc(&t(lang, "ch_signal_sub_day"))));
                }
                for key in ["signal", "quality", "traffic", "link", "online", "retries", "snr"] {
                    assert!(page.contains(&format!(r#"data-chart="{key}""#)));
                }
            }
        }
    }

    #[test]
    fn test_identity_details() {
        let page = Site::v2().get(&format!("/devices/{}", ids()[2]), "en", RESIDENT_SUB);
        let shown = visible(&page);
        let details = &shown[index(&shown, r#"id="details-h""#)..];
        assert!(details.contains(&esc(&t("en", "dt_macs"))));
        for i in 0..4 {
            assert!(details.contains(&format!("06:11:22:33:44:{i:02x}")));
        }
        assert_eq!(details.matches(r#"class="badge-plain on""#).count(), 1, "the one in use");
        assert!(details.contains(&esc(&t("en", "src_device_mac"))));
        assert!(!details.contains(&esc(&t("en", "src_admin_prometheus"))));
        assert!(!page.contains("data-raw"), "raw data: admins only");
        assert!(json_block(&page, "np-config")["raw"].is_null());
    }

    #[test]
    fn test_names_and_reasons_are_escaped() {
        let mut site = Site::v2();
        site.devices[3]["last_auth"] =
            json!({"at": iso(60), "result": "reject", "reason": "<script>alert(1)</script>"});
        site.devices[3]["name"] = json!("<img src=x onerror=alert(1)>");
        let page = site.get(&format!("/admin/devices/{}", ids()[3]), "en", ADMIN_SUB);
        let shown = visible(&page);
        assert!(!shown.contains("<script>alert"));
        assert!(!shown.contains("<img src=x"));
        assert!(shown.contains("&lt;script&gt;alert(1)&lt;/script&gt;"), "the admin sees the raw value, escaped");
    }
}

mod v2_admin_pages_tests {
    use super::*;

    #[test]
    fn test_the_overview_in_every_language() {
        let site = Site::v2();
        for lang in LANGS {
            let page = site.get("/admin", lang, ADMIN_SUB);
            assert_csp_safe(&page);
            let shown = visible(&page);
            assert!(!shown.contains('{'));
            assert!(page.contains(r#"<nav class="adm-tabs""#));
            assert!(page.contains(r#"href="/admin" aria-current="page""#));
            for key in [
                "ov_title",
                "ov_incidents",
                "ov_open",
                "ov_recent",
                "ov_aps",
                "ov_auth",
                "ov_fresh",
                "inc_internet_degraded",
                "inc_ap_down",
                "ap_warn_overloaded",
                "ap_warn_uplink",
                "ap_warn_restarted",
                "rr_unknown_cert_admin",
                "fresh_wifi",
                "fresh_jobs_failed",
                "job_failed",
                "job_never",
                "job_ok",
                "ov_devices",
            ] {
                assert!(shown.contains(&esc(&t(lang, key))), "{lang} {key}");
            }
            assert!(shown.contains("Prometheus: timeout after 4.0 s &lt;query&gt;"), "the job's error, escaped");
            assert!(
                shown.contains(&format!(r#"href="/admin/devices/{}""#, ids()[3])),
                "a rejected device: its deep view"
            );
            assert!(shown.contains("Sensor &lt;&amp;&gt; &#34;Werkstatt&#34;"), "dropped out in an incident");
            assert_eq!(page.matches(r#"class="adm-item""#).count(), site.rows.len() - 1, "v1's device list stays");
            assert_eq!(json_block(&page, "np-data")["overview"]["auth"]["count"], 27);
            assert!(shown.contains(&format!(">{}</span>", esc(&fill(&t(lang, "ov_auth_repeats"), &[("n", "4")])))));
            assert_eq!(json_block(&page, "np-config")["overview"], "/api/admin/overview");
        }
    }

    #[test]
    fn test_sections_that_are_not_available() {
        let mut site = Site::v2();
        merge(
            &mut site.overview,
            json!({
            "incidents": {"available": false, "open": [], "recent": [], "counts_7d": {}},
            "auth": {"available": false, "since": iso(0), "count": 0, "truncated": false, "by_reason": {}, "devices": 0,
                     "macs": 0, "recent": []},
            "jobs": [], "jobs_available": false, "aps": [],
            "freshness": {"wifi_data_age_s": null, "prometheus": "unavailable", "jobs_ok": null,
                          "oldest_job_success_age_s": null}}),
        );
        let page = site.get("/admin", "de", ADMIN_SUB);
        assert_eq!(visible(&page).matches(&esc(&t("de", "ov_unavailable"))).count(), 3);
        for key in ["aps_empty", "fresh_state_unavailable", "fresh_jobs_none"] {
            assert!(page.contains(&esc(&t("de", key))), "{key}");
        }
    }

    #[test]
    fn test_the_access_points() {
        let site = Site::v2();
        for lang in LANGS {
            let page = site.get("/admin/aps", lang, ADMIN_SUB);
            assert_csp_safe(&page);
            let shown = visible(&page);
            assert!(!shown.contains('{'));
            assert_eq!(page.matches(r#"class="card ap-card"#).count(), 4);
            assert!(page.contains(r#"href="/admin/aps" aria-current="page""#));
            assert!(page.contains(r#"id="ap-d021f9000003""#), "the overview's links land here");
            assert!(page.contains(r#"class="card ap-card ap-down""#));
            for key in ["ap_state_up", "ap_state_down", "ap_warn_poor_coverage", "ap_warn_overloaded", "ch_ap_util"] {
                assert!(shown.contains(&esc(&t(lang, key))), "{lang} {key}");
            }
            assert!(shown.contains(&esc(&fill(&t(lang, "ap_clients_house"), &[("n", "28")]))));
            assert!(page.contains("data-ap-chart"));
            assert_eq!(json_block(&page, "np-data")["aps"].as_array().map(Vec::len), Some(4));
        }
        let page = site.get("/admin/aps?q=colbe&sort=clients", "en", ADMIN_SUB);
        let hidden = Regex::new(r#"<article class="card ap-card[^"]*"[^>]*hidden>"#).expect("a pattern");
        assert_eq!(hidden.find_iter(&page).count(), 3);
        assert!(page.contains("1 of 4 shown"));
    }

    #[test]
    fn test_the_incidents() {
        let site = Site::v2();
        for lang in LANGS {
            let page = site.get("/admin/incidents?range=30d", lang, ADMIN_SUB);
            assert_csp_safe(&page);
            let shown = visible(&page);
            assert!(!shown.contains('{'));
            for kind in ["internet_degraded", "ap_down", "ap_restarted", "switch_port_down", "dns_down", "radius_down"]
            {
                assert!(shown.contains(&esc(&t(lang, &format!("inc_{kind}")))), "{lang} {kind}");
            }
            for kind in codes("INCIDENT_KINDS") {
                assert!(page.contains(&format!(r#"<option value="{kind}""#)));
            }
            assert!(page.contains(&format!(r#"aria-current="true">{}<"#, t(lang, "range_30d"))));
            assert!(shown.contains(&esc(&t(lang, "inc_affected_list"))));
            assert!(shown.contains(&format!(r#"href="/admin/devices/{}""#, ids()[1])));
            assert!(page.contains(r#"class="inc inc-closed inferred""#));
            let lasted = fill(&t(lang, "inc_lasted"), &[("duration", &fmt::duration(Some(600.0), lang, 2))]);
            assert!(shown.contains(&esc(&lasted)));
        }
        let page = site.get("/admin/incidents?kind=ap_down&state=open", "en", ADMIN_SUB);
        assert!(page.contains(r#"<option value="ap_down" selected>"#));
        assert!(page.contains("1 of 1 shown"));
        assert_eq!(json_block(&page, "np-config")["kind"], "ap_down");
    }

    #[test]
    fn test_without_affected_devices_nothing_is_claimed() {
        let mut incidents = sample_incidents();
        for i in &mut incidents {
            if let Some(map) = i.as_object_mut() {
                map.remove("devices");
            }
        }
        let site = Site {
            incidents: Some(json!({"from": iso(86400), "to": iso(0), "kind": null, "incidents": incidents})),
            ..Site::v2()
        };
        let page = site.get("/admin/incidents", "en", ADMIN_SUB);
        assert!(!visible(&page).contains(&esc(&t("en", "inc_affected_none"))));
        assert!(page.contains(&esc(&t("en", "inc_ap_down"))));
    }

    #[test]
    fn test_the_deep_view_with_raw_data() {
        let site = Site::v2();
        for lang in LANGS {
            let page = site.get(&format!("/admin/devices/{}", ids()[0]), lang, ADMIN_SUB);
            assert_csp_safe(&page);
            let shown = visible(&page);
            assert!(!shown.contains('{'));
            assert!(page.contains(r##"href="/admin#devices" aria-current="page""##));
            for part in ["auth", "acct", "events", "macs", "days", "incidents"] {
                assert!(page.contains(&format!(r#"id="raw-{part}""#)));
                assert!(shown.contains(&esc(&t(lang, &format!("raw_tab_{part}")))));
            }
            assert!(shown.contains("5F3A1C2B-00000041"), "an accounting session");
            assert!(shown.contains("Lost-Carrier"));
            assert!(shown.contains(&esc(&t(lang, "cause_lost_carrier"))));
            assert!(page.contains(r#"class="row-bad""#), "the rejected login");
            assert!(shown.contains(&esc(&fill(&t(lang, "raw_conflict"), &[("n", "1")]))), "the MAC window's conflict");
            assert!(
                shown.contains(&esc(&fill(&t(lang, "raw_truncated"), &[("n", "2000")]))),
                "UniFi events cut at the limit"
            );
            assert!(shown.contains(&esc(&t(lang, "mm_admin_random_fixed"))));
            let config = json_block(&page, "np-config");
            assert_eq!(config["admin"], true);
            assert_eq!(config["raw"], format!("/api/admin/devices/{}/raw", ids()[0]));
            assert_eq!(json_block(&page, "np-data")["raw"]["acct"][1]["terminate_cause"], "Lost-Carrier");
        }
        let page = site.get(&format!("/devices/{}?from=admin", ids()[0]), "en", ADMIN_SUB);
        assert!(page.contains("data-raw"), "v1's link still works");
        assert!(page.contains("data-raw-load"));
    }
}

mod v2_text_tests {
    use super::*;

    #[test]
    fn test_codes_have_texts() {
        let mut causes = codes("TERMINATE_CAUSES");
        causes.push("unknown".into());
        let need: Vec<(String, Vec<String>)> = vec![
            ("diag_%s".into(), codes("DIAGNOSES")),
            ("diag_%s_why".into(), codes("DIAGNOSES")),
            ("diag_%s_do".into(), codes("DIAGNOSES")),
            ("tl_kind_%s".into(), codes("EVENT_KINDS")),
            ("rr_%s".into(), codes("REJECT_REASONS")),
            ("rr_%s_admin".into(), codes("REJECT_REASONS")),
            ("cause_%s".into(), causes),
            ("mm_%s".into(), codes("MAC_MODES")),
            ("mm_%s_sub".into(), codes("MAC_MODES")),
            ("mm_admin_%s".into(), codes("MAC_MODES")),
            ("inc_%s".into(), codes("INCIDENT_KINDS")),
            ("src_%s".into(), codes("SOURCES")),
            ("src_admin_%s".into(), codes("SOURCES")),
            ("job_%s".into(), codes("JOBS")),
            ("fresh_%s".into(), codes("FRESHNESS")),
            ("range_%s".into(), codes("RANGES")),
            ("ap_warn_%s".into(), codes("AP_WARNINGS")),
        ];
        let tables = i18n::tables();
        for lang in i18n::languages() {
            for (pattern, list) in &need {
                for code in list {
                    let key = pattern.replace("%s", code);
                    assert!(i18n::text(lang, &key).is_some_and(|s| !s.is_empty()), "{lang} {key}");
                }
            }
            for code in codes("REJECT_REASONS") {
                assert!(i18n::text(lang, &format!("rr_{code}_do")).is_some(), "\"\" for ok: nothing to do");
            }
            for spec in tables["EVIDENCE_SPEC"].as_object().into_iter().flat_map(|m| m.values()) {
                for pair in spec.as_array().into_iter().flatten() {
                    let (key, kind) = (pair[0].as_str().unwrap_or(""), pair[1].as_str().unwrap_or(""));
                    let label = if kind.starts_with("limit_") { "evk_limit".to_string() } else { format!("evk_{key}") };
                    assert!(i18n::text(lang, &label).is_some_and(|s| !s.is_empty()), "{lang} {label}");
                }
            }
            for key in tables["EVIDENCE_FORMAT"].as_object().into_iter().flat_map(|m| m.keys()) {
                assert!(i18n::text(lang, &format!("evk_{key}")).is_some_and(|s| !s.is_empty()), "{lang} {key}");
            }
        }
    }

    /// Python checked diagnostics, timeline and web tables of the Python backend; here the Rust
    /// backend's finding codes and the AP limits the admin pages repeat (format.rs).
    #[test]
    fn test_the_backends_codes_are_known() {
        let Some(source) = sibling_source("netportal-telemetry/src/diagnostics.rs") else {
            return;
        };
        let re = Regex::new(r#"finding\(\s*"([a-z_0-9]+)""#).expect("a pattern");
        for c in re.captures_iter(&source) {
            assert!(codes("DIAGNOSES").contains(&c[1].to_string()), "{}", &c[1]);
        }
        let limit = |name: &str| -> f64 {
            let re = Regex::new(&format!(r"pub const {name}: \w+ = ([0-9_.]+);")).expect("a pattern");
            let c = re.captures(&source).unwrap_or_else(|| panic!("{name} not in diagnostics.rs"));
            c[1].replace('_', "").parse().unwrap_or(f64::NAN)
        };
        for (name, here) in fmt::AP_LIMITS {
            assert_eq!(limit(name), here, "{name}");
        }
        assert_eq!(i18n::tables()["AP_WEAK_SHARE_WARN"].as_f64(), Some(limit("AP_WEAK_SHARE_WARN")));
    }

    #[test]
    fn test_formatting() {
        assert_eq!(fmt::cause_key(&json!("Lost-Carrier")), "lost_carrier");
        assert_eq!(fmt::cause_key(&json!("19")), "supplicant_restart");
        assert_eq!(fmt::cause_key(&json!("99")), "unknown");
        assert_eq!(fmt::cause_key(&json!("²")), "unknown", "a digit, but no ASCII number");
        assert_eq!(fmt::reason_key(&json!("nope")), "other");
        assert_eq!(
            fmt::incident_text(&json!({"kind": "ap_down", "subject_name": "ap-colbe-0-far"}), "de"),
            "Access Point offline (Colbe · Erdgeschoss · hinten)"
        );
        assert_eq!(
            fmt::incident_text(&json!({"kind": "internet_down", "subject": ""}), "en"),
            "Internet down (whole house)"
        );
        assert_eq!(fmt::ap_warnings(&json!({"state": "down"})), ["down"]);
        assert_eq!(
            fmt::ap_warnings(&json!({"state": "ok", "clients": 31, "radios": [], "weak_clients": 10, "uptime_s": 60,
                                            "uplink_mbps": 100})),
            ["overloaded", "poor_coverage", "restarted", "uplink"]
        );
        assert_eq!(
            fmt::ap_warnings(&json!({"state": "ok", "clients": 5, "radios": [{"channel_util": 0.7}]})),
            ["busy_channel"]
        );
        assert_eq!(
            fmt::span_key(&json!(iso(30 * 86400)), &json!(iso(0)), &["7d", "30d", "90d", "1y"]).as_deref(),
            Some("30d")
        );
        let (items, window) = fmt::evidence_items(
            &finding(
                "unstable_roaming",
                "warn",
                "inferred",
                Some(json!({"roams_1h": 7, "roams_1h_measured": null, "warn": 6})),
                json!({}),
            ),
            "en",
            false,
        );
        assert_eq!(
            items,
            [
                ("access point changes".to_string(), "7 per hour".to_string()),
                ("limit".to_string(), "6 per hour".to_string())
            ]
        );
        assert_eq!(window.as_deref(), Some("in the last hour"));
        assert_eq!(
            fmt::evidence_short(
                &finding("frequent_disconnects", "warn", "measured", Some(json!({"reconnects_24h": 8})), json!({})),
                "de"
            )
            .as_deref(),
            Some("8-mal in 24 Stunden")
        );
        assert_eq!(
            fmt::evidence_short(
                &finding("weak_signal", "warn", "measured", Some(json!({"signal_dbm": -79})), json!({})),
                "en"
            )
            .as_deref(),
            Some("\u{2212}79 dBm")
        );
    }
}

// === device presence ============================================================================

/// DEVICE.presence as the backend sends it (times seconds before NOW).
#[allow(clippy::too_many_arguments)]
fn presence(
    state: &str,
    reason: Option<&str>,
    confirmed_by: Option<&str>,
    confirmed_s: Option<i64>,
    since_s: Option<i64>,
    session: Value,
    evidence: &[(&str, i64, &str)],
    poll_s: i64,
    basis: &str,
) -> Value {
    json!({"state": state, "since": since_s.map(iso), "confirmed_at": confirmed_s.map(iso), "confirmed_by": confirmed_by,
           "basis": basis, "reason": reason, "session": session, "stale_after_s": 660, "poll_s": poll_s,
           "evidence": evidence.iter().map(|(src, at, kind)| json!({"source": src, "at": iso(*at), "kind": kind}))
                               .collect::<Vec<_>>()})
}

fn acct_session(started_s: i64, updated_s: i64, stopped_s: Option<i64>, cause: Option<&str>) -> Value {
    json!({"nas_ip": "10.10.0.21", "acct_session_id": "5F3A1C2B-00000042", "ap": ap("ap-scharni-2-corner"),
           "started": iso(started_s), "updated": iso(updated_s), "stopped": stopped_s.map(iso), "cause": cause,
           "interim_s": 300, "interim_basis": "measured"})
}

mod presence_pages_tests {
    use super::*;

    /// Device i's card up to the next device's (without its JSON blocks).
    fn card(page: &str, i: usize) -> String {
        let start = index(page, &format!(r#"id="device-{}""#, ids()[i]));
        let next = ids()
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .filter_map(|(_, other)| page[start + 1..].find(&format!(r#"id="device-{other}""#)).map(|p| start + 1 + p))
            .min()
            .unwrap_or(page.len());
        visible(&page[start..next])
    }

    fn state_html(page: &str, i: Option<usize>) -> String {
        let part = match i {
            Some(i) => &page[index(page, &format!(r#"id="device-{}""#, ids()[i]))..],
            None => page,
        };
        let start = index(part, r#"<p class="dev-state"#);
        part[start..index_from(part, "</p>", start)].to_string()
    }

    fn tags_removed(html: &str) -> String {
        Regex::new(r"<[^>]+>").expect("a pattern").replace_all(html, "").into_owned()
    }

    fn first_part(text: &str) -> String {
        text.split('{').next().unwrap_or("").trim().to_string()
    }

    /// The real report: the laptop logged in a few seconds ago; the session's Start is in, the
    /// association snapshot (1-3 min late) not yet; a stale diagnostics run still says offline.
    fn just_logged_in(site: &mut Site) {
        merge(
            &mut site.devices[1],
            json!({
            "state": "online", "last_seen": iso(12), "since": iso(14),
            "presence": presence("online", Some("acct_start"), Some("radius_acct"), Some(12), Some(14),
                                 acct_session(14, 12, None, None),
                                 &[("radius_auth", 15, "accept"), ("radius_acct", 12, "acct_start"),
                                   ("prometheus", 95, "association_gone")], 5, "measured"),
            "diagnostics": [finding("offline", "info", "measured", None, json!({"last_seen": iso(12)}))]}),
        );
    }

    #[test]
    fn test_a_fresh_login_is_online_with_its_source_never_offline() {
        let mut site = Site::new();
        just_logged_in(&mut site);
        for lang in LANGS {
            for url in ["/".to_string(), format!("/devices/{}", ids()[1])] {
                let page = site.get(&url, lang, RESIDENT_SUB);
                assert_csp_safe(&page);
                let line = state_html(&page, Some(1));
                assert!(line.contains(r#"class="dev-state state-online""#));
                assert!(line.contains(&t(lang, "state_online")));
                assert!(!line.contains(&t(lang, "state_offline")));
                let confirmed = fmt::recent(&json!(iso(12)), lang, Some(now()));
                assert!(line.contains(&first_part(&t(lang, "pr_confirmed"))));
                assert!(line.contains(&format!(">{confirmed}</time>")));
                assert!(line.contains(&esc(&t(lang, "pr_src_radius_acct"))));
                assert!(line.contains(r#"data-rel="recent""#), "the script keeps it current");
                assert!(line.contains(&format!(r#"title="{}""#, fmt::stamp(&json!(iso(12)), lang))), "to the second");
                let shown = if url == "/" { card(&page, 1) } else { visible(&page) };
                assert!(!shown.contains(&esc(&t(lang, "diag_offline"))), "no \"Not connected\" note");
                assert!(!shown.contains(&esc(&t(lang, "diag_offline_why"))));
            }
        }
        let page = site.get("/", "en", RESIDENT_SUB);
        assert!(tags_removed(&state_html(&page, Some(1))).contains("Confirmed 12 s ago by Wi-Fi session records"));
    }

    #[test]
    fn test_connecting_is_neutral_and_says_what_happens() {
        let mut site = Site::new();
        merge(
            &mut site.devices[2],
            json!({
            "state": "connecting", "last_seen": iso(3),
            "presence": presence("connecting", Some("accept_pending"), Some("radius_auth"), Some(3), Some(3), Value::Null, &[],
                                 5, "measured"),
            "diagnostics": [finding("offline", "info", "measured", None, json!({"last_seen": iso(3 * 3600)}))]}),
        );
        for lang in LANGS {
            let page = site.get("/", lang, RESIDENT_SUB);
            let line = state_html(&page, Some(2));
            assert!(line.contains(r#"class="dev-state state-connecting""#));
            assert!(line.contains(r##"<use href="#i-refresh"/>"##));
            for key in ["state_connecting", "pr_connecting_line", "pr_src_radius_auth"] {
                assert!(line.contains(&esc(&t(lang, key))), "{lang} {key}");
            }
            assert!(!line.contains(&t(lang, "state_offline")));
            let card = card(&page, 2);
            assert!(!card.contains(&esc(&t(lang, "diag_offline"))));
            assert!(!card[..index(&card, r#"data-part="diag""#)].contains("sev-bad"), "not shown as an error");
            assert!(card.contains(r#"class="dev-icon state-connecting""#));
        }
    }

    #[test]
    fn test_offline_says_since_when_and_keeps_its_note() {
        let mut site = Site::new();
        merge(
            &mut site.devices[2],
            json!({
            "state": "offline", "last_seen": iso(130),
            "presence": presence("offline", Some("acct_stop"), Some("radius_acct"), Some(130), Some(130),
                                 acct_session(4000, 400, Some(130), Some("User-Request")), &[], 30, "measured"),
            "diagnostics": [finding("offline", "info", "measured",
                                    Some(json!({"last_seen": iso(130), "confirmed_at": iso(130), "confirmed_by": "radius_acct"})),
                                    json!({"last_seen": iso(130)}))]}),
        );
        for lang in LANGS {
            let page = site.get(&format!("/devices/{}", ids()[2]), lang, RESIDENT_SUB);
            let line = state_html(&page, None);
            assert!(line.contains(r#"class="dev-state state-offline""#));
            assert!(line.contains(&esc(&first_part(&t(lang, "pr_offline_since")))));
            assert!(line.contains(&fmt::recent(&json!(iso(130)), lang, Some(now()))));
            assert!(line.contains(&esc(&t(lang, "pr_src_radius_acct"))));
            let shown = visible(&page);
            assert!(shown.contains(&esc(&t(lang, "diag_offline"))), "the note, while offline");
            assert!(shown.contains(&esc(&t(lang, "evk_confirmed_by"))), "\"based on\" the confirmation");
            assert!(shown[index(&shown, r#"class="diag""#)..].contains(&esc(&t(lang, "pr_src_radius_acct"))));
            assert!(!shown.contains(&esc(&t(lang, "pr_admin_title"))), "the evidence is the admins'");
        }
        let page = site.get(&format!("/devices/{}", ids()[2]), "en", RESIDENT_SUB);
        assert!(
            tags_removed(&state_html(&page, None))
                .contains("Offline disconnected 2 min ago Confirmed 2 min ago by Wi-Fi session records")
        );
    }

    #[test]
    fn test_unknown_says_why() {
        let mut site = Site::new();
        let mut reasons = codes("PRESENCE_REASONS");
        reasons.push("brand_new_code".into());
        for reason in reasons {
            merge(
                &mut site.devices[0],
                json!({
                "state": "unknown", "since": null, "ap": null, "last_seen": null, "signal_dbm": null, "health": null,
                "presence": presence("unknown", Some(&reason), None, None, None, Value::Null, &[], 30, "inferred"),
                "diagnostics": []}),
            );
            for lang in LANGS {
                let page = site.get("/", lang, RESIDENT_SUB);
                let line = state_html(&page, Some(0));
                assert!(line.contains(r#"class="dev-state state-unknown""#));
                let known = codes("PRESENCE_REASONS").contains(&reason);
                let key = format!("pr_reason_{}", if known { reason.as_str() } else { "other" });
                assert!(line.contains(&esc(&t(lang, &key))), "{lang} {reason}");
                assert!(!line.contains(&t(lang, "state_offline")));
                assert!(!line.contains(&first_part(&t(lang, "pr_confirmed"))), "nothing confirmed");
                assert!(
                    !visible(&line).replace(&esc(&t(lang, &key)), "").contains(reason.as_str()),
                    "no code for residents"
                );
            }
        }
    }

    #[test]
    fn test_every_state_in_every_language() {
        let mut site = Site::new();
        let states = [
            presence(
                "online",
                Some("association"),
                Some("prometheus"),
                Some(40),
                Some(8130),
                Value::Null,
                &[],
                30,
                "measured",
            ),
            presence(
                "connecting",
                Some("accept_pending"),
                Some("radius_auth"),
                Some(2),
                None,
                Value::Null,
                &[],
                5,
                "measured",
            ),
            presence(
                "offline",
                Some("association_gone"),
                Some("prometheus"),
                Some(50),
                Some(3 * 3600),
                Value::Null,
                &[],
                30,
                "measured",
            ),
            presence("never_connected", None, None, None, None, Value::Null, &[], 30, "inferred"),
            presence("unknown", Some("telemetry_unavailable"), None, None, None, Value::Null, &[], 30, "inferred"),
        ];
        for (i, p) in states.iter().enumerate() {
            merge(&mut site.devices[i], json!({"state": p["state"], "presence": p}));
        }
        for lang in LANGS {
            let page = site.get("/admin", lang, ADMIN_SUB);
            assert_csp_safe(&page);
            assert!(!visible(&page).contains('{'));
            for (i, p) in states.iter().enumerate() {
                let state = p["state"].as_str().unwrap_or("");
                let item = &page[index(&page, &format!(r#"<li class="adm-item" data-device="{}""#, ids()[i]))..];
                let item = &item[..index(item, "</li>\n")];
                assert!(item.contains(&format!(r#"data-state="{state}""#)), "{lang} {state}");
                assert!(item.contains(&format!(r#"class="dev-state state-{state}""#)));
                assert!(item.contains(&esc(&t(lang, &format!("state_{state}")))));
            }
            assert!(
                page.contains(&format!(r#"<option value="connecting">{}</option>"#, esc(&t(lang, "state_connecting"))))
            );
        }
        assert_eq!(shown_names(&site.get("/admin?state=connecting", "en", ADMIN_SUB)), ["MacBook Air"]);
    }

    #[test]
    fn test_admins_see_how_the_state_was_decided() {
        let mut site = Site::new();
        just_logged_in(&mut site);
        for lang in LANGS {
            for url in [format!("/admin/devices/{}", ids()[1]), "/admin".to_string()] {
                let page = site.get(&url, lang, ADMIN_SUB);
                assert_csp_safe(&page);
                let shown = visible(&page);
                let shown = &shown[index(&shown, &format!(r#"data-device="{}""#, ids()[1]))..];
                let block = &shown[index(shown, r#"data-part="presence""#)..];
                let block = &block[..index(block, "</details>")];
                assert!(block.contains(&esc(&t(lang, "pr_admin_title"))));
                assert!(block.contains(r#"<span class="mono">acct_start</span>"#), "the reason code");
                assert!(block.contains(&esc(&t(lang, "pr_reason_acct_start"))));
                assert!(block.contains("10.10.0.21"), "the session");
                assert!(block.contains("5F3A1C2B-00000042"));
                assert!(block.contains(&esc(&fmt::room(&ap("ap-scharni-2-corner"), lang))));
                assert!(block.contains(&esc(&first_part(&t(lang, "pr_admin_started")))));
                assert!(block.contains(&esc(&first_part(&t(lang, "pr_admin_updated")))));
                assert!(block.contains("660 s"), "stale_after_s");
                let stale =
                    fill(&t(lang, "pr_admin_stale_value"), &[("duration", &fmt::duration(Some(660.0), lang, 2))]);
                assert!(block.contains(&esc(&stale)));
                assert!(block.contains(&esc(&t(lang, "src_admin_radius_acct"))), "confirmed by");
                for kind in ["accept", "acct_start", "association_gone"] {
                    assert!(block.contains(&format!(r#"<span class="mono">{kind}</span>"#)), "the evidence: {kind}");
                }
                assert!(index(block, ">accept<") < index(block, ">association_gone<"), "newest first");
                assert!(!block.contains('{'));
            }
        }
        let page = site.get(&format!("/devices/{}", ids()[1]), "en", RESIDENT_SUB);
        assert!(!page.contains(r#"data-part="presence""#), "the resident");
    }

    #[test]
    fn test_without_presence_the_v1_line_stays() {
        let page = Site::new().get("/", "en", RESIDENT_SUB);
        assert!(state_html(&page, Some(0)).contains(t("en", "since_line").split('{').next().unwrap_or("")));
        assert!(state_html(&page, Some(2)).contains(t("en", "seen_line").split('{').next().unwrap_or("")));
        assert!(!visible(&page).contains(&first_part(&t("en", "pr_confirmed"))), "nothing claimed");
        assert!(!page.contains(r#"data-part="presence""#));
    }

    #[test]
    fn test_texts_and_formatting() {
        let sprite = Regex::new(r#"id="i-([a-z0-9-]+)""#).expect("a pattern");
        let base_html = include_str!("../templates/base.html");
        let icons: Vec<&str> = sprite.captures_iter(base_html).filter_map(|c| c.get(1)).map(|m| m.as_str()).collect();
        let tables = i18n::tables();
        for lang in i18n::languages() {
            for state in codes("PRESENCE_STATES") {
                assert!(i18n::text(lang, &format!("state_{state}")).is_some_and(|s| !s.is_empty()), "{lang} {state}");
                let icon = tables["PRESENCE_ICON"][&state].as_str().unwrap_or("");
                assert!(icons.contains(&icon), "{state}: {icon}");
            }
            for code in codes("PRESENCE_REASONS") {
                assert!(i18n::text(lang, &format!("pr_reason_{code}")).is_some_and(|s| !s.is_empty()), "{lang} {code}");
            }
            for src in codes("PRESENCE_SOURCES") {
                assert!(i18n::text(lang, &format!("pr_src_{src}")).is_some_and(|s| !s.is_empty()), "{lang} {src}");
                assert!(i18n::text(lang, &format!("src_admin_{src}")).is_some_and(|s| !s.is_empty()), "{lang} {src}");
            }
        }
        let n = Some(now());
        assert_eq!(fmt::recent(&json!(iso(2)), "en", n), "just now");
        assert_eq!(fmt::recent(&json!(iso(12)), "en", n), "12 s ago");
        assert_eq!(fmt::recent(&json!(iso(12)), "de", n), "vor 12 Sek.");
        assert_eq!(fmt::recent(&json!(iso(12)), "uk", n), "12 с тому");
        assert_eq!(fmt::recent(&json!(iso(300)), "en", n), "5 min ago");
        assert_eq!(fmt::stamp(&json!("2026-10-25T14:52:13Z"), "de"), "25.10.2026 15:52:13");
        let parts =
            fmt::parts(&json!({"text": "a {x} b {y}", "values": {"x": "<1>", "y": {"time": "t", "text": "now"}}}));
        assert_eq!(
            parts,
            [
                ("text", json!("a ")),
                ("text", json!("<1>")),
                ("text", json!(" b ")),
                ("time", json!({"time": "t", "text": "now"}))
            ]
        );
    }

    /// The backend's presence for the reported case and the other ways a state comes about,
    /// through the templates: the shapes fit, nothing contradicts. The payloads are the Python
    /// backend's (`presence.decide` + `public`, a frozen fixture, made by the Python version at 578a2ba).
    #[test]
    fn test_the_backends_presence_renders() {
        let fixture: Value =
            serde_json::from_str(include_str!("fixtures/presence_backend.json")).expect("the fixture is JSON");
        let mut site = Site::new();
        for state in ["online", "connecting", "offline", "unknown"] {
            let public = &fixture["cases"][state];
            assert_eq!(public["state"], state);
            let last_seen = if state == "unknown" { Value::Null } else { public["since"].clone() };
            merge(
                &mut site.devices[1],
                json!({
                "state": state, "presence": public, "last_seen": last_seen,
                "diagnostics": [finding("offline", "info", "measured", Some(json!({"last_seen": iso(3700)})), json!({}))]}),
            );
            for lang in LANGS {
                for (url, sub) in [("/".to_string(), RESIDENT_SUB), (format!("/admin/devices/{}", ids()[1]), ADMIN_SUB)]
                {
                    let page = site.get(&url, lang, sub);
                    assert_csp_safe(&page);
                    let line = state_html(&page, if url == "/" { Some(1) } else { None });
                    assert!(line.contains(&format!(r#"class="dev-state state-{state}""#)), "{state} {lang}");
                    for other in codes("PRESENCE_STATES") {
                        if other != state {
                            assert!(
                                !line.contains(&format!(">{}<", esc(&t(lang, &format!("state_{other}"))))),
                                "{state} {lang} {other}"
                            );
                        }
                    }
                    let shown = if url == "/" { card(&page, 1) } else { visible(&page) };
                    assert_eq!(shown.contains(&esc(&t(lang, "diag_offline"))), state == "offline", "{state} {lang}");
                    assert!(!visible(&page).contains('{'));
                }
            }
        }
        let page = site.get(&format!("/admin/devices/{}", ids()[1]), "en", ADMIN_SUB);
        assert!(page.contains("session_stale"));
    }

    /// Python scanned presence.py; here the Rust backend (netportal-telemetry/src/presence.rs).
    #[test]
    fn test_the_backends_codes_are_known() {
        let Some(source) = sibling_source("netportal-telemetry/src/presence.rs") else {
            return;
        };
        let state = Regex::new(r#"pub const (?:ONLINE|CONNECTING|OFFLINE|UNKNOWN|NEVER): &str = "([a-z_]+)";"#)
            .expect("a pattern");
        let mut states: Vec<String> = state.captures_iter(&source).map(|c| c[1].to_string()).collect();
        let mut known = codes("PRESENCE_STATES");
        states.sort();
        known.sort();
        assert_eq!(states, known);
        let reasons = Regex::new(
            r#""(acct_(?:start|interim|stop)|association[a-z_]*|accept_pending|unifi_disconnect|session_stale|ap_down|telemetry_unavailable|no_data|mac_conflict)""#,
        )
        .expect("a pattern");
        for c in reasons.captures_iter(&source) {
            assert!(codes("PRESENCE_REASONS").contains(&c[1].to_string()), "{}", &c[1]);
        }
        let by = Regex::new(r#""(prometheus|radius_acct|radius_auth|unifi_syslog)""#).expect("a pattern");
        for c in by.captures_iter(&source) {
            assert!(codes("PRESENCE_SOURCES").contains(&c[1].to_string()), "{}", &c[1]);
        }
    }
}

// === tests/test_web.py: HouseLookTests, BrowserNoticeTests (the template parts) =================

mod house_look_tests {
    use super::*;

    fn welcome(accept_language: &str, house_lang: Option<&str>) -> String {
        render("landing.html", &base(i18n::pick(Some(accept_language), house_lang), None, "/welcome"), json!({}))
    }

    #[test]
    fn test_house_lang_cookie_wins_over_the_browser() {
        assert!(welcome("de", Some("uk")).contains(r#"<html lang="uk">"#));
    }

    #[test]
    fn test_unknown_cookie_falls_back_to_the_browser() {
        assert!(welcome("de", Some("xx")).contains(r#"<html lang="de">"#));
    }

    #[test]
    fn test_kit_and_house_bar() {
        let page = welcome("en", None);
        assert!(page.contains(r#"href="/_house/ui.css""#));
        assert!(index(&page, "/_house/ui.css") < index(&page, "style.css"));
        assert!(page.contains(r#"<nav class="h-bar""#));
        assert!(page.contains(r#"href="https://example.org/""#));
    }
}

mod browser_notice_tests {
    use super::*;

    /// The devices page as the handler renders it for this browser (its options and the
    /// Passpoint notice come from the User-Agent: web.py enrol_options, no_passpoint_browser).
    fn page(options: &[&str], no_passpoint_browser: bool) -> String {
        let mut b = base("de", Some(RESIDENT_SUB), "/");
        b.no_passpoint_browser = no_passpoint_browser;
        let dashboard =
            json!({"generated_at": iso(0), "telemetry": "off", "stale": false, "house": null, "devices": []});
        render("devices.html", &b, json!({"devices": [], "dashboard": dashboard, "options": options}))
    }

    #[test]
    fn test_firefox_on_android_is_told_and_gets_the_app_first() {
        let page = page(&["android-app", "android"], true);
        assert!(page.contains(&t("de", "other_browser")));
        assert!(index(&page, r#"value="eap-config""#) < index(&page, r#"value="android""#));
    }

    #[test]
    fn test_chrome_on_android_is_not() {
        let page = page(&["android", "android-app"], false);
        // the visible page: np-texts holds every text as UTF-8 (Python's ASCII-escaped JSON hid it)
        assert!(!visible(&page).contains(&t("de", "other_browser")));
        assert!(index(&page, r#"value="android""#) < index(&page, r#"value="eap-config""#));
    }
}

// === pages the dashboard tests do not cover =====================================================

mod other_pages {
    use super::*;

    #[test]
    fn test_install_steps_and_the_download_link() {
        for (profile, button, steps) in [
            ("apple", "load_profile", "steps_apple"),
            ("apple-mac", "load_profile", "steps_mac"),
            ("android", "install", "steps_android"),
            ("eap-config", "install", "steps_android_app"),
        ] {
            let mut b = base("en", Some(RESIDENT_SUB), "/enroll");
            b.no_passpoint_browser = true;
            let page =
                render("install.html", &b, json!({"profile": profile, "token": "tok-EN_1", "name": "Pixel <8>"}));
            assert!(page.contains(r#"href="/download/tok-EN_1""#), "a plain GET link");
            assert!(page.contains(&esc(&t("en", button))));
            assert!(page.contains("<h1>Pixel &lt;8&gt;</h1>"));
            let items = i18n::list("en", steps).unwrap_or_default();
            assert_eq!(page.matches("<li>").count(), items.len(), "{profile}");
            for step in items {
                let step = fill(step, &[("ssid", "Example"), ("host", "wifi.example.org")]);
                assert!(page.contains(&esc(&step)), "{profile}: {step}");
            }
            assert_eq!(
                page.contains(&esc(&t("en", "other_browser"))),
                profile == "android",
                "the notice only for Passpoint"
            );
            assert_csp_safe(&page);
        }
    }

    #[test]
    fn test_consent_carries_the_request_back() {
        let page = render(
            "consent.html",
            &base("en", Some(RESIDENT_SUB), "/oauth/authorize"),
            json!({
            "args": {"client_id": "app.geteduroam.sh", "redirect_uri": "http://127.0.0.1:8080/\"x", "response_type": "code",
                     "state": "", "scope": "eap-metadata"},
            "consent_args": ["client_id", "redirect_uri", "response_type", "code_challenge", "code_challenge_method", "state",
                             "scope"],
            "name": "geteduroam (resi)"}),
        );
        assert!(page.contains(r#"<form method="post" action="/oauth/authorize">"#));
        assert!(page.contains(r#"<input type="hidden" name="client_id" value="app.geteduroam.sh">"#));
        assert!(page.contains(r#"<input type="hidden" name="redirect_uri" value="http://127.0.0.1:8080/&#34;x">"#));
        assert!(!page.contains(r#"name="state""#), "empty values are left out");
        assert!(!page.contains(r#"name="code_challenge""#));
        assert!(page.contains(r#"<input name="name" value="geteduroam (resi)" maxlength="60">"#));
        assert!(page.contains(&esc(&fill(&t("en", "consent_note"), &[("ssid", "Example")]))));
        assert_csp_safe(&page);
    }

    #[test]
    fn test_message_and_the_session_header() {
        let mut b = base("de", Some(ADMIN_SUB), "/x");
        let page = render("message.html", &b, json!({"message": "Fehler <1> & 'zwei'"}));
        assert!(page.contains("<p>Fehler &lt;1&gt; &amp; &#39;zwei&#39;</p>"));
        assert!(page.contains(r#"<form method="post" action="/logout" class="inline">"#));
        assert!(page.contains(r#"<a class="pill" href="/admin">"#), "the admin pill");
        assert!(page.contains(r#"<a href="/">"#));
        b.user = None;
        let page = render("message.html", &b, json!({"message": "x"}));
        assert!(!page.contains("/logout"), "no session header without a login");
        assert_csp_safe(&page);
    }
}
