//! Telemetry: the live dashboard (`telemetry/live.py`, INVENTORY 9.1.5): DEVICE (a device's live
//! state from Prometheus, its identity and login data from the registry, the findings on both)
//! and the `/api/devices` payload.
//!
//! Live values come from the MACs whose windows hold now ([`Identity::live_bounds`]), one query
//! per metric for all MACs of a page. Sources (checked against the house's Prometheus on
//! 2026-10-25):
//! - unpoller (job `unifi`, scraped every 60 s): one series per client and association, labels
//!   `mac, ap_name, essid, radio (ng/na/6e), radio_proto, channel, ip, bssid`. A roam or a band
//!   change starts a new series, so per-device values are aggregated by mac. unpoller answers
//!   from a snapshot; `unpoller_prometheus_cache_age_seconds` is its age (a frozen snapshot goes
//!   on with frozen values: presence alone is no proof of being online).
//! - `unpoller_client_uptime_seconds`: present while associated; its value is the time since the
//!   association, which survives a roam and restarts with a new association. The association
//!   start (snapshot time - uptime) identifies a connection.
//! - Direction: unpoller's client counters are the AP's view (transmit = to the device). Every
//!   rx/tx here is the DEVICE's view: rx = what it receives (download), tx = what it sends.
//!   `*_rate_bps` are LINK rates, not throughput.
//! - The house's rules: `wifi_client_snr_db`, `wifi_client_retry_ratio` (by mac only),
//!   `wifi_client_channel_utilization_ratio`, `wifi_client_health_score` (0-100).
//! - The APs: `unpoller_device_info{type="uap"}`, `unpoller_device_stations`,
//!   `unpoller_device_radio_channel_utilization_total_ratio`, `unpoller_device_vap_*`.
//!
//! Only the house's EAP-TLS network counts (`essid` on every client selector; the byte counters
//! and the retry ratio carry no essid and are joined to the uptime series that does).
//!
//! The query texts are those of INVENTORY 9.3 with the fragments as placeholders: `$SEL`
//! (essid and mac matchers), `$MAC` (the mac matcher), `$U` (the house network's uptime series),
//! `$AGE` (the snapshot age).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use indexmap::IndexMap;
use netportal_core::registry::{AuthFailure, DeviceRow, Incident, Person, RegistryError};
use serde::Serialize;
use serde::ser::SerializeMap;
use serde_json::Value;
use uuid::Uuid;

use super::Page;
use super::client::{Budget, CACHE_SECONDS, SUMMARY_CACHE_SECONDS, Unavailable};
use super::common::{
    ApRef, Selectors, ap_info, band, by_mac, fit, fit_int, iso, label, normalise_mac, radio_of, selectors, small_int,
    trunc_int, unix, unix_opt,
};
use super::history::relevant_incidents;
use super::house::{House, empty_house, house_status};
use super::identity::{self, Identity, MacMode, PublicConflict, PublicMac};
use super::store::{Result, Store};
use super::timeline::{self as tl, ApMap, Basis, Event};
use crate::diagnostics::{self, Context, Coverage, DeviceView, Finding, PresenceView, Reject, Severity, Summary};
use crate::presence::{self, Decision, Inputs, Presence, Sighting};

pub const OK: &str = "ok";
pub const UNAVAILABLE: &str = "unavailable";
pub const OFF: &str = "off";

/// The diagnostics' limit: an older snapshot is the past.
pub const STALE_AFTER_S: i64 = diagnostics::STALE_AFTER_S;
pub const SAME_ASSOCIATION_S: f64 = tl::SAME_ASSOCIATION_S;
/// The absent MACs' last sighting is looked up this far back.
pub const LAST_SEEN_LOOKBACK_S: f64 = 7.0 * 86400.0;
/// The states the admin list filters by.
pub const DEVICE_STATES: [&str; 5] = ["online", "connecting", "offline", "never_connected", "unknown"];

/// AGE: the Wi-Fi snapshot's age.
pub const CACHE_AGE: &str = r#"max(unpoller_prometheus_cache_age_seconds{job="unifi"})"#;
/// L1: the association start per series: snapshot time (scrape time - snapshot age) - uptime.
pub const ASSOCIATION_START: &str = "(timestamp($U) - $U) - on() group_left() ($AGE or vector(0))";

/// The live fields of DEVICE, in order (INVENTORY 9.12).
pub const LIVE_FIELDS: [&str; 19] = [
    "ap",
    "ssid",
    "band",
    "channel",
    "proto",
    "ip",
    "signal_dbm",
    "noise_dbm",
    "snr_db",
    "health",
    "retry_ratio",
    "channel_util",
    "link_rx_bps",
    "link_tx_bps",
    "rx_bps",
    "tx_bps",
    "rx_24h_bytes",
    "tx_24h_bytes",
    "roams_1h",
];

/// How a gauge is rounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Digits {
    Int,
    Dp(u32),
}

/// L2-L11: field -> (PromQL, rounding). Metrics without an essid label (byte counters, the retry
/// rule) only count `and on (mac)` the house network's uptime series.
pub const GAUGES: [(&str, &str, Digits); 10] = [
    ("signal_dbm", r#"max by (mac) (unpoller_client_radio_signal_db{job="unifi",$SEL})"#, Digits::Dp(1)),
    ("noise_dbm", r#"max by (mac) (unpoller_client_noise_db{job="unifi",$SEL})"#, Digits::Dp(1)),
    ("snr_db", "max by (mac) (wifi_client_snr_db{$SEL})", Digits::Dp(1)),
    ("health", "min by (mac) (wifi_client_health_score{$SEL})", Digits::Dp(1)),
    ("retry_ratio", "max by (mac) (wifi_client_retry_ratio{$MAC} and on (mac) $U)", Digits::Dp(4)),
    ("channel_util", "max by (mac) (wifi_client_channel_utilization_ratio{$SEL})", Digits::Dp(4)),
    // the device's view: it receives what the AP transmits
    ("link_rx_bps", r#"max by (mac) (unpoller_client_radio_transmit_rate_bps{job="unifi",$SEL})"#, Digits::Int),
    ("link_tx_bps", r#"max by (mac) (unpoller_client_radio_receive_rate_bps{job="unifi",$SEL})"#, Digits::Int),
    (
        "rx_bps",
        r#"sum by (mac) (rate(unpoller_client_transmit_bytes_total{job="unifi",$MAC}[5m]) and on (mac) $U) * 8"#,
        Digits::Int,
    ),
    (
        "tx_bps",
        r#"sum by (mac) (rate(unpoller_client_receive_bytes_total{job="unifi",$MAC}[5m]) and on (mac) $U) * 8"#,
        Digits::Int,
    ),
];

/// L12-L13: over 24 h, only for devices whose data bound is older than that.
pub const DAY_TOTALS: [(&str, &str); 2] = [
    (
        "rx_24h_bytes",
        r#"sum by (mac) (increase(unpoller_client_transmit_bytes_total{job="unifi",$MAC}[24h]) and on (mac) last_over_time($U[24h]))"#,
    ),
    (
        "tx_24h_bytes",
        r#"sum by (mac) (increase(unpoller_client_receive_bytes_total{job="unifi",$MAC}[24h]) and on (mac) last_over_time($U[24h]))"#,
    ),
];
/// L14: the AP and band per minute of the last hour.
pub const WHERE_1H: &str = "max by (mac, ap_name, radio) ($U)[1h:1m]";
/// L15: transmit attempts per second.
pub const ATTEMPTS: &str = r#"sum by (mac) (rate(unpoller_client_wifi_attempts_transmit_total{job="unifi",$SEL}[5m]))"#;
/// L16: the association starts of 24 h, only while the snapshot is fresh (600: STALE_AFTER_S).
pub const FRESH_STARTS: &str =
    "((max by (mac) (timestamp($U) - $U) - on() group_left() $AGE) and on() ($AGE <= 600))[24h:5m]";
/// L17: when each band was last seen in 7 days.
pub const BANDS_7D: &str = "max by (mac, radio) (max_over_time(timestamp($U)[7d:5m]))";
/// L18: when the absent MACs were last there (7 days).
pub const LAST_SEEN: &str = "max by (mac) (max_over_time(timestamp($U)[7d:5m]))";
/// L19: when a MAC was last there inside its ended window (`$LOOKBACK` seconds back from `time`).
pub const LAST_SEEN_UNTIL: &str = "max by (mac) (max_over_time(timestamp($U)[$LOOKBACKs:5m]))";
/// L20-L21: the device's signal per AP over 24 h (poor_coverage), same rule for the bound.
pub const COVERAGE: [(&str, &str); 2] = [
    ("signal_dbm", r#"avg by (mac, ap_name) (avg_over_time(unpoller_client_radio_signal_db{job="unifi",$SEL}[24h]))"#),
    ("samples", r#"sum by (mac, ap_name) (count_over_time(unpoller_client_radio_signal_db{job="unifi",$SEL}[24h]))"#),
];
/// L22: clients per AP (all SSIDs).
pub const AP_CLIENTS: &str = r#"sum by (name) (unpoller_device_stations{job="unifi",type="uap"})"#;
/// L23: channel utilisation per AP radio.
pub const AP_RADIO_UTIL: &str =
    r#"max by (name, radio) (unpoller_device_radio_channel_utilization_total_ratio{job="unifi"})"#;
/// L24: the APs (MAC, name, address, model).
pub const AP_INFO: &str = r#"max by (mac, name, ip, model) (unpoller_device_info{job="unifi",type="uap"})"#;
/// L25: BSSID -> AP.
pub const AP_BSSIDS: &str = r#"max by (bssid, mac, name, radio) (unpoller_device_vap_transmit_power{job="unifi"})"#;

/// A query template with its fragments filled in.
pub fn fill(template: &str, parts: &Selectors) -> String {
    template.replace("$SEL", &parts.sel).replace("$MAC", &parts.mac).replace("$U", &parts.u).replace("$AGE", CACHE_AGE)
}

// --- live values ---------------------------------------------------------------------------------

/// The 19 live fields of DEVICE (INVENTORY 9.12).
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct LiveFields {
    pub ap: Option<ApRef>,
    pub ssid: Option<String>,
    pub band: Option<String>,
    pub channel: Option<i64>,
    pub proto: Option<String>,
    pub ip: Option<String>,
    /// dBm, 1 decimal
    pub signal_dbm: Option<f64>,
    pub noise_dbm: Option<f64>,
    pub snr_db: Option<f64>,
    /// 0-100, 1 decimal
    pub health: Option<f64>,
    /// ratio, 4 decimals
    pub retry_ratio: Option<f64>,
    pub channel_util: Option<f64>,
    /// bit/s (the radio's link rate)
    pub link_rx_bps: Option<i64>,
    pub link_tx_bps: Option<i64>,
    /// bit/s (5 min rate; rx = download)
    pub rx_bps: Option<i64>,
    pub tx_bps: Option<i64>,
    /// bytes, only when the whole 24 h is the device's
    pub rx_24h_bytes: Option<i64>,
    pub tx_24h_bytes: Option<i64>,
    /// AP or band changes in the last hour; null when no data
    pub roams_1h: Option<i64>,
}

impl LiveFields {
    fn set(&mut self, field: &str, value: Option<f64>, digits: Digits) {
        let (f, i) = match digits {
            Digits::Int => (None, fit_int(value)),
            Digits::Dp(d) => (fit(value, d), None),
        };
        match field {
            "signal_dbm" => self.signal_dbm = f,
            "noise_dbm" => self.noise_dbm = f,
            "snr_db" => self.snr_db = f,
            "health" => self.health = f,
            "retry_ratio" => self.retry_ratio = f,
            "channel_util" => self.channel_util = f,
            "link_rx_bps" => self.link_rx_bps = i,
            "link_tx_bps" => self.link_tx_bps = i,
            "rx_bps" => self.rx_bps = i,
            "tx_bps" => self.tx_bps = i,
            "rx_24h_bytes" => self.rx_24h_bytes = i,
            "tx_24h_bytes" => self.tx_24h_bytes = i,
            _ => {}
        }
    }

    /// `(field, value)` in [`LIVE_FIELDS`] order (JSON values; null when unknown).
    pub fn entries(&self) -> Vec<(&'static str, Value)> {
        let all = match serde_json::to_value(self) {
            Ok(Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        };
        LIVE_FIELDS.iter().map(|f| (*f, all.get(*f).cloned().unwrap_or(Value::Null))).collect()
    }
}

/// One MAC's live status: the fields, present now, its association start (bounded by the data
/// bound), when it was last seen (absent ones).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LiveStatus {
    pub fields: LiveFields,
    pub present: bool,
    pub start: Option<f64>,
    pub last_seen: Option<f64>,
}

impl LiveStatus {
    pub fn sighting(&self) -> Sighting {
        Sighting { present: self.present, start: self.start, last_seen: self.last_seen }
    }
}

/// AP or band changes in `[(t, ap_name, radio)]` (sorted by t).
pub fn count_changes(points: &[(i64, Option<String>, Option<String>)]) -> i64 {
    let mut changes = 0;
    let mut prev: Option<(&Option<String>, &Option<String>)> = None;
    for (_, ap, radio) in points {
        if prev.is_some_and(|p| p != (ap, radio)) {
            changes += 1;
        }
        prev = Some((ap, radio));
    }
    changes
}

/// The new association starts in `[(t, association start)]`: a start later than the previous
/// one by more than [`SAME_ASSOCIATION_S`] (whether or not the data has a gap in between).
pub fn reconnect_times(starts: &[(i64, Option<f64>)]) -> Vec<f64> {
    let mut times = Vec::new();
    let mut prev: Option<f64> = None;
    for (_, start) in starts {
        let Some(start) = *start else {
            continue;
        };
        if prev.is_some_and(|p| start - p > SAME_ASSOCIATION_S) {
            times.push(start);
        }
        prev = Some(start);
    }
    times
}

/// The MACs whose data of the last 24 h is all the device's.
pub fn full_day(macs: &[String], bounds: &BTreeMap<String, f64>, now: f64) -> Vec<String> {
    macs.iter().filter(|m| bounds.get(*m).is_none_or(|b| *b <= now - 86400.0)).cloned().collect()
}

/// `({mac: live values}, {mac: summary})` for normalised MACs, one query per metric for all of
/// them. `bounds`: data before it is not the device's.
pub async fn device_status(
    client: &Budget,
    macs: &[String],
    bounds: &BTreeMap<String, f64>,
    now: f64,
) -> std::result::Result<(IndexMap<String, LiveStatus>, IndexMap<String, Summary>), Unavailable> {
    let parts = selectors(client.ssid(), macs)?;
    let mut status: IndexMap<String, LiveStatus> = macs.iter().map(|m| (m.clone(), LiveStatus::default())).collect();
    let after = |mac: Option<&str>, t: f64| mac.and_then(|m| bounds.get(m)).is_none_or(|b| t >= *b);
    // where it is now: the series with the newest association start
    for (labels, start) in client.vector(&fill(ASSOCIATION_START, &parts), None, CACHE_SECONDS).await? {
        let Some(start) = start else {
            continue;
        };
        let Some(st) = label(&labels, "mac").and_then(|m| status.get_mut(m)) else {
            continue;
        };
        if st.start.is_some_and(|s| s >= start) {
            continue;
        }
        st.present = true;
        st.start = Some(start);
        st.fields.ap = ap_info(label(&labels, "ap_name"));
        st.fields.ssid = labels.get("essid").cloned();
        st.fields.band = band(label(&labels, "radio")).map(str::to_string);
        st.fields.channel = small_int(label(&labels, "channel"));
        st.fields.proto = labels.get("radio_proto").cloned();
        st.fields.ip = labels.get("ip").cloned();
    }
    for (mac, st) in status.iter_mut() {
        if let (Some(start), Some(bound)) = (st.start, bounds.get(mac)) {
            st.start = Some(start.max(*bound));
        }
    }
    for (field, promql, digits) in GAUGES {
        for (mac, value) in by_mac(&client.vector(&fill(promql, &parts), None, CACHE_SECONDS).await?) {
            if let Some(st) = status.get_mut(&mac) {
                st.fields.set(field, value, digits);
            }
        }
    }
    let day = full_day(macs, bounds, now);
    if !day.is_empty() {
        let day_parts = selectors(client.ssid(), &day)?;
        for (field, promql) in DAY_TOTALS {
            for (mac, value) in by_mac(&client.vector(&fill(promql, &day_parts), None, CACHE_SECONDS).await?) {
                if let Some(st) = status.get_mut(&mac) {
                    st.fields.set(field, value, Digits::Int);
                }
            }
        }
    }
    // AP/band changes in the last hour, from the per-minute AP of each device
    type Minute = (f64, Option<String>, Option<String>);
    let mut seen: IndexMap<String, BTreeMap<i64, Vec<Minute>>> = IndexMap::new();
    for (labels, points) in client.matrix(&fill(WHERE_1H, &parts), None, CACHE_SECONDS).await? {
        let mac = labels.get("mac").cloned();
        for (t, uptime) in points {
            if let (Some(uptime), Some(mac)) = (uptime, &mac)
                && after(Some(mac), t as f64)
            {
                seen.entry(mac.clone()).or_default().entry(t).or_default().push((
                    uptime,
                    labels.get("ap_name").cloned(),
                    labels.get("radio").cloned(),
                ));
            }
        }
    }
    let mut summary: IndexMap<String, Summary> = macs.iter().map(|m| (m.clone(), Summary::default())).collect();
    for (mac, by_t) in seen {
        if let Some(st) = status.get_mut(&mac) {
            // two series at one minute (rare): the newer association (smaller uptime)
            let newest: Vec<(i64, Option<String>, Option<String>)> = by_t
                .into_iter()
                .filter_map(|(t, v)| {
                    let mut best: Option<&Minute> = None;
                    for m in &v {
                        if best.is_none_or(|b| m.0 < b.0) {
                            best = Some(m);
                        }
                    }
                    best.map(|(_, ap, radio)| (t, ap.clone(), radio.clone()))
                })
                .collect();
            st.fields.roams_1h = Some(count_changes(&newest));
            if let Some(s) = summary.get_mut(&mac) {
                let aps: BTreeSet<String> =
                    newest.into_iter().filter_map(|(_, ap, _)| ap.filter(|a| !a.is_empty())).collect();
                s.aps_1h = aps.into_iter().collect();
            }
        }
    }
    for (mac, value) in by_mac(&client.vector(&fill(ATTEMPTS, &parts), None, CACHE_SECONDS).await?) {
        if let Some(s) = summary.get_mut(&mac) {
            s.tx_attempts_per_s = fit(value, 2);
        }
    }
    for (labels, points) in client.matrix(&fill(FRESH_STARTS, &parts), None, SUMMARY_CACHE_SECONDS).await? {
        let mac = label(&labels, "mac");
        if let Some(s) = mac.and_then(|m| summary.get_mut(m)) {
            let own: Vec<(i64, Option<f64>)> = points.into_iter().filter(|(t, _)| after(mac, *t as f64)).collect();
            let times = reconnect_times(&own);
            s.reconnects_24h = Some(times.len() as i64);
            s.reconnect_times_24h = times;
        }
    }
    // the bands seen in 7 days: when each was last seen, only from the device's own time
    for (labels, t) in client.vector(&fill(BANDS_7D, &parts), None, SUMMARY_CACHE_SECONDS).await? {
        let mac = label(&labels, "mac");
        let b = band(label(&labels, "radio"));
        if let (Some(s), Some(b), Some(t)) = (mac.and_then(|m| summary.get_mut(m)), b, t)
            && after(mac, t)
            && !s.bands_7d.iter().any(|x| x == b)
        {
            s.bands_7d.push(b.to_string());
        }
    }
    // when the absent ones were last there (7 days, exact to the scrape; older: the registry)
    let absent: Vec<String> = status.iter().filter(|(_, st)| !st.present).map(|(m, _)| m.clone()).collect();
    if !absent.is_empty() {
        let absent_parts = selectors(client.ssid(), &absent)?;
        for (mac, t) in by_mac(&client.vector(&fill(LAST_SEEN, &absent_parts), None, SUMMARY_CACHE_SECONDS).await?) {
            if let (Some(st), Some(t)) = (status.get_mut(&mac), t)
                && after(Some(&mac), t)
            {
                st.last_seen = Some(t);
            }
        }
    }
    Ok((status, summary))
}

/// When a MAC whose window has ended (`start..end`) was last there inside it, from the 7 days
/// before the end (`None` if not then).
pub async fn last_seen_until(
    client: &Budget,
    mac: &str,
    start: f64,
    end: f64,
) -> std::result::Result<Option<f64>, Unavailable> {
    let lookback = trunc_int(LAST_SEEN_LOOKBACK_S.min((end - start).max(300.0))).unwrap_or(300);
    let parts = selectors(client.ssid(), &[mac])?;
    let promql = fill(LAST_SEEN_UNTIL, &parts).replace("$LOOKBACK", &lookback.to_string());
    let rows = client.vector(&promql, trunc_int(end), SUMMARY_CACHE_SECONDS).await?;
    let seen = by_mac(&rows).get(mac).copied().flatten();
    Ok(seen.filter(|s| start <= *s && *s <= end))
}

/// `(mac, start, end)` of the current MAC's last piece when it has ended (the device has not
/// logged in for longer than a session) but less than [`LAST_SEEN_LOOKBACK_S`] ago.
pub fn ended_window(identity: &Identity, now: f64) -> Option<(String, f64, f64)> {
    let current = identity.current()?;
    if identity.withheld_now() || !identity.live_bounds().is_empty() {
        return None;
    }
    let mut last: Option<identity::Segment> = None;
    for s in identity.segments(None, None).into_iter().filter(|s| s.mac == current.mac) {
        if last.as_ref().is_none_or(|l| s.end > l.end) {
            last = Some(s);
        }
    }
    let last = last?;
    if last.end < now - LAST_SEEN_LOOKBACK_S || !last.start.is_finite() {
        return None;
    }
    Some((last.mac, last.start, last.end))
}

/// `{mac: {ap name: coverage}}` over 24 h, for the MACs whose whole day is theirs.
pub async fn coverage(
    client: &Budget,
    macs: &[String],
    bounds: &BTreeMap<String, f64>,
    now: f64,
) -> std::result::Result<IndexMap<String, IndexMap<String, Coverage>>, Unavailable> {
    let day = full_day(macs, bounds, now);
    let mut out: IndexMap<String, IndexMap<String, Coverage>> = IndexMap::new();
    if day.is_empty() {
        return Ok(out);
    }
    let parts = selectors(client.ssid(), &day)?;
    for (field, promql) in COVERAGE {
        for (labels, value) in client.vector(&fill(promql, &parts), None, SUMMARY_CACHE_SECONDS).await? {
            let (Some(mac), Some(ap), Some(value)) =
                (label(&labels, "mac"), label(&labels, "ap_name").filter(|a| !a.is_empty()), value)
            else {
                continue;
            };
            if !day.iter().any(|d| d == mac) {
                continue;
            }
            let c = out.entry(mac.to_string()).or_default().entry(ap.to_string()).or_default();
            if field == "signal_dbm" {
                c.signal_dbm = Some(value);
            } else {
                c.samples = value;
            }
        }
    }
    Ok(out)
}

/// One AP's load now.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ApLoadNow {
    pub clients: Option<i64>,
    /// radio -> channel utilisation (3 decimals)
    pub radios: IndexMap<String, Option<f64>>,
}

/// `{ap name: load}` now (L22, L23).
pub async fn ap_load(client: &Budget) -> std::result::Result<IndexMap<String, ApLoadNow>, Unavailable> {
    let mut out: IndexMap<String, ApLoadNow> = IndexMap::new();
    for (labels, value) in client.vector(AP_CLIENTS, None, CACHE_SECONDS).await? {
        if let (Some(name), Some(value)) = (label(&labels, "name").filter(|n| !n.is_empty()), value) {
            out.entry(name.to_string()).or_default().clients = trunc_int(value);
        }
    }
    for (labels, value) in client.vector(AP_RADIO_UTIL, None, CACHE_SECONDS).await? {
        if let (Some(name), Some(radio)) =
            (label(&labels, "name").filter(|n| !n.is_empty()), label(&labels, "radio").filter(|r| !r.is_empty()))
        {
            out.entry(name.to_string()).or_default().radios.insert(radio.to_string(), fit(value, 3));
        }
    }
    Ok(out)
}

/// The ApMap from the APs' BSSIDs, addresses and MACs (cached a minute; empty when Prometheus does
/// not answer). A non-empty one is kept for [`super::Shared::known_aps`].
pub async fn ap_map(page: &Page) -> ApMap {
    let Some(client) = page.budget.as_ref() else {
        return ApMap::default();
    };
    let answers = async {
        let info = client.vector(AP_INFO, None, SUMMARY_CACHE_SECONDS).await?;
        let vaps = client.vector(AP_BSSIDS, None, SUMMARY_CACHE_SECONDS).await?;
        Ok::<_, Unavailable>((info, vaps))
    };
    let Ok((info, vaps)) = answers.await else {
        return ApMap::default();
    };
    let mut found = ApMap::default();
    for (labels, _) in &info {
        if let (Some(mac), Some(name)) =
            (label(labels, "mac").and_then(normalise_mac), label(labels, "name").filter(|n| !n.is_empty()))
        {
            found.names.insert(mac.clone(), name.to_string());
            if let Some(ip) = label(labels, "ip").filter(|i| !i.is_empty()) {
                found.nas.insert(ip.to_string(), (name.to_string(), mac));
            }
        }
    }
    for (labels, _) in &vaps {
        if let Some(bssid) = label(labels, "bssid").and_then(normalise_mac) {
            let mac = label(labels, "mac").and_then(normalise_mac);
            found.bssids.insert(bssid, (labels.get("name").cloned(), mac, band(label(labels, "radio"))));
        }
    }
    if !found.is_empty() {
        page.shared().set_known_aps(&found);
    }
    found
}

// --- DEVICE ----------------------------------------------------------------------------------------

/// Ts: the Wi-Fi snapshot's time (`house.wifi_data_at`; else now - its age; `None`: unknown).
pub fn snapshot_time(house: &House, now: f64) -> Option<f64> {
    house.snapshot_at.or_else(|| house.wifi_data_age_s.map(|age| now - age as f64))
}

/// DEVICE.last_auth.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LastAuth {
    pub at: Option<String>,
    /// `accept` / `reject`
    pub result: &'static str,
    pub reason: String,
}

/// A device's owner (admin views).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Owner {
    pub username: Option<String>,
    pub display: Option<String>,
}

impl Owner {
    pub fn of(person: Option<&Person>) -> Owner {
        Owner { username: person.map(|p| p.username.clone()), display: person.map(|p| p.display_name.clone()) }
    }
}

/// A measured value with where it comes from.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Fact {
    pub value: Value,
    /// `prometheus` / `registry` / `radius_auth`
    pub source: &'static str,
    pub basis: Basis,
}

/// The findings, serialised twice: as `diagnostics` and as `findings` (the same list).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Findings(pub Vec<Finding>);

impl Serialize for Findings {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("diagnostics", &self.0)?;
        map.serialize_entry("findings", &self.0)?;
        map.end()
    }
}

/// DEVICE (INVENTORY 9.12).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub platform: String,
    pub policy: String,
    pub created: Option<String>,
    /// the newest non-retired certificate's expiry
    pub expires: Option<String>,
    pub revoked: bool,
    /// the live MAC shown, else the current window's
    pub mac: Option<String>,
    pub state: &'static str,
    pub last_seen: Option<String>,
    /// only while online
    pub since: Option<String>,
    #[serde(flatten)]
    pub live: LiveFields,
    pub presence: Presence,
    pub macs: Vec<PublicMac>,
    pub mac_mode: Option<MacMode>,
    pub data_from: Option<String>,
    pub last_auth: Option<LastAuth>,
    /// admins only (the key is left out for residents)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conflicts: Option<Vec<PublicConflict>>,
    /// worst first; serialised as `diagnostics` and `findings`
    #[serde(flatten)]
    pub findings: Findings,
    pub facts: IndexMap<String, Fact>,
    pub sources: Vec<String>,
    /// admins only (the key is left out for residents)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<Owner>,
    /// set by the web (`netportal_pki::enroll::expires_soon`); left out until then
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_soon: Option<bool>,
}

impl Device {
    pub fn diagnostics(&self) -> &[Finding] {
        &self.findings.0
    }

    /// What the diagnostics read of it.
    pub fn view(&self) -> DeviceView {
        DeviceView {
            state: self.state.to_string(),
            mac: self.mac.clone(),
            band: self.live.band.clone(),
            channel: self.live.channel,
            signal_dbm: self.live.signal_dbm,
            noise_dbm: self.live.noise_dbm,
            snr_db: self.live.snr_db,
            retry_ratio: self.live.retry_ratio,
            channel_util: self.live.channel_util,
            link_rx_bps: self.live.link_rx_bps,
            rx_bps: self.live.rx_bps,
            tx_bps: self.live.tx_bps,
            roams_1h: self.live.roams_1h,
            last_seen: self.last_seen.clone(),
            presence: Some(PresenceView {
                confirmed_at: self.presence.confirmed_at.clone(),
                confirmed_by: self.presence.confirmed_by.map(str::to_string),
                reason: Some(self.presence.reason.to_string()),
                basis: Some(self.presence.basis),
            }),
        }
    }
}

/// What [`device_entry`] gets besides the row and the live status.
#[derive(Debug, Clone, Default)]
pub struct Extra<'a> {
    pub identity: Option<&'a Identity>,
    pub context: Context,
    pub last_auth: Option<LastAuth>,
    /// sources with rows read for the device (detail: radius_acct, unifi_syslog)
    pub sources: Vec<&'static str>,
    pub sessions: Vec<presence::Session>,
    pub events: Vec<presence::ConnEvent>,
    pub ap_down: HashMap<String, f64>,
    /// the configured accounting interval
    pub interim_s: Option<i64>,
}

/// DEVICE from a registry row and its live status. `conflict`: the number of other people whose
/// devices claim the same MAC now; residents then see no telemetry. The state, last_seen and
/// since are [`presence::decide`]'s (the only place a state is derived).
#[allow(clippy::too_many_arguments)]
pub fn device_entry(
    row: &DeviceRow,
    mac: Option<&str>,
    status: Option<&LiveStatus>,
    telemetry: &'static str,
    house: &House,
    now: f64,
    summary: Option<&Summary>,
    conflict: i64,
    admin: bool,
    extra: Extra<'_>,
) -> Device {
    let stale = telemetry == OK && diagnostics::is_stale(house.wifi_data_age_s);
    let withheld = conflict != 0 && !admin;
    let sighting = status.map(LiveStatus::sighting);
    let decided = presence::decide(
        now,
        &Inputs {
            assoc: presence::association(sighting.as_ref(), telemetry, snapshot_time(house, now), stale),
            sessions: extra.sessions,
            accept: unix_opt(row.last_seen),
            events: extra.events,
            down: extra.ap_down,
            interim_s: extra.interim_s,
            withheld,
            never: mac.is_none(),
        },
    );
    let state = decided.state;
    let empty = LiveStatus::default();
    let status = if withheld { &empty } else { status.unwrap_or(&empty) };
    let identity = extra.identity;
    let mut device = Device {
        id: row.id.to_string(),
        name: row.name.clone(),
        platform: row.platform.clone(),
        policy: row.policy.clone(),
        created: iso(Some(unix(row.created_at))),
        expires: iso(unix_opt(row.expires)),
        revoked: row.revoked_at.is_some(),
        mac: mac.map(str::to_string),
        state,
        last_seen: iso(decided.last_seen),
        since: if state == presence::ONLINE { iso(decided.since) } else { None },
        live: status.fields.clone(),
        presence: presence::public(&decided),
        macs: identity.map(Identity::public_macs).unwrap_or_default(),
        mac_mode: identity.and_then(Identity::mac_mode),
        data_from: identity.and_then(|i| iso(i.data_from())),
        last_auth: extra.last_auth,
        conflicts: admin.then(|| identity.map(Identity::public_conflicts).unwrap_or_default()),
        findings: Findings::default(),
        facts: IndexMap::new(),
        sources: Vec::new(),
        owner: None,
        expires_soon: None,
    };
    let context = extra.context;
    let mut found = if withheld {
        let mut found = vec![diagnostics::finding(
            "mac_conflict",
            Severity::Warn,
            Basis::Measured,
            Some(serde_json::json!({})),
            serde_json::json!({}),
        )];
        found.extend(diagnostics::auth_findings(&context));
        found.extend(diagnostics::cert_findings(&context));
        found
    } else {
        let since = decided.since;
        let mut summary = summary.cloned().unwrap_or_default();
        summary.associated_s = if state == presence::ONLINE { since.map(|s| now - s) } else { None };
        let mut found =
            diagnostics::findings(&device.view(), Some(&summary), house.wifi_data_age_s, telemetry, &context);
        if conflict != 0 {
            let macs: Vec<String> = match identity {
                Some(i) => {
                    i.conflicts_at(now).iter().map(|c| c.mac.clone()).collect::<BTreeSet<_>>().into_iter().collect()
                }
                None => mac.map(str::to_string).into_iter().collect(),
            };
            found.insert(
                0,
                diagnostics::finding(
                    "mac_conflict",
                    Severity::Warn,
                    Basis::Measured,
                    Some(serde_json::json!({"owners": conflict, "macs": macs})),
                    serde_json::json!({"owners": conflict}),
                ),
            );
        }
        found
    };
    // worst first (Python put an admin's mac_conflict before everything, also a bad finding)
    found.sort_by_key(|f| f.severity);
    device.findings = Findings(found);
    device.facts = facts(&device, house, telemetry, withheld);
    device.sources = sources(&device, status, telemetry, &extra.sources, &decided);
    device
}

/// The measured values of a DEVICE with where each comes from (only what is known).
pub fn facts(device: &Device, house: &House, telemetry: &str, withheld: bool) -> IndexMap<String, Fact> {
    let mut out = IndexMap::new();
    if !withheld && telemetry == OK {
        for (field, value) in device.live.entries() {
            if !value.is_null() {
                out.insert(field.to_string(), Fact { value, source: "prometheus", basis: Basis::Measured });
            }
        }
        if let Some(age) = house.wifi_data_age_s {
            out.insert(
                "wifi_data_age_s".into(),
                Fact { value: age.into(), source: "prometheus", basis: Basis::Measured },
            );
        }
    }
    if let Some(expires) = &device.expires {
        out.insert(
            "expires".into(),
            Fact { value: expires.clone().into(), source: "registry", basis: Basis::Measured },
        );
    }
    if let Some(mode) = device.mac_mode {
        out.insert("mac_mode".into(), Fact { value: mode.as_str().into(), source: "registry", basis: Basis::Inferred });
    }
    if let Some(last) = &device.last_auth {
        let value = serde_json::to_value(last).unwrap_or(Value::Null);
        out.insert("last_auth".into(), Fact { value, source: "radius_auth", basis: Basis::Measured });
    }
    out
}

/// The sources a DEVICE rests on, sorted.
pub fn sources(
    device: &Device,
    status: &LiveStatus,
    telemetry: &str,
    extra: &[&str],
    decided: &Decision,
) -> Vec<String> {
    let mut found: BTreeSet<String> = BTreeSet::from(["registry".to_string()]);
    if device.last_auth.is_some() {
        found.insert("radius_auth".into());
    }
    let any_live = status.fields.entries().iter().any(|(_, v)| !v.is_null());
    if telemetry == OK && (status.present || status.last_seen.is_some() || any_live) {
        found.insert("prometheus".into());
    }
    found.extend(extra.iter().map(|s| s.to_string()));
    for e in &decided.evidence {
        if matches!(e.source, "radius_acct" | "unifi_syslog") {
            found.insert(e.source.to_string());
        }
    }
    found.into_iter().collect()
}

/// The newer of the last accept (the row's last_seen) and the last reject (a row of repeats: its
/// latest try).
pub fn last_auth(row: &DeviceRow, rejects: &[Reject]) -> Option<LastAuth> {
    let accept = unix_opt(row.last_seen);
    let mut reject: Option<&Reject> = None;
    for r in rejects {
        if reject.is_none_or(|b| r.last() > b.last()) {
            reject = Some(r);
        }
    }
    if let Some(r) = reject
        && accept.is_none_or(|a| r.last() > a)
    {
        return Some(LastAuth { at: iso(Some(r.last())), result: "reject", reason: r.reason.clone() });
    }
    accept.map(|a| LastAuth { at: iso(Some(a)), result: "accept", reason: "ok".into() })
}

/// The house's rejects (24 h) that are this device's: by its certificate (`device_id`) or,
/// without a certificate the registry knows (`no_cert`, `not_eap`, `unknown_cert`, `bad_chain`),
/// by one of its MACs inside its (unwithheld) windows at the reject's first time. A reject of
/// another device's certificate is that device's, whatever MAC it came from.
pub fn rejects_of(row: &DeviceRow, identity: Option<&Identity>, failures: &[AuthFailure]) -> Vec<Reject> {
    let segments = identity.map(|i| i.segments(None, None)).unwrap_or_default();
    let mut out = Vec::new();
    for r in failures {
        let at = unix(r.at);
        let mac = r.mac.as_deref().and_then(normalise_mac);
        let mine = match r.device_id {
            Some(device) => device == row.id,
            None => match (&mac, identity) {
                (Some(mac), Some(identity)) => identity.contains(mac, at, Some(&segments)),
                _ => false,
            },
        };
        if mine {
            out.push(Reject {
                at,
                last_at: unix_opt(r.last_at),
                count: i64::from(r.tries.max(1)),
                reason: r.reason.clone(),
                mac,
            });
        }
    }
    out
}

/// The diagnostics' context of one device.
#[allow(clippy::too_many_arguments)]
fn context(
    row: &DeviceRow,
    identity: Option<&Identity>,
    summary: Option<&Summary>,
    status: Option<&LiveStatus>,
    rejects: Vec<Reject>,
    load: &IndexMap<String, ApLoadNow>,
    cover: IndexMap<String, Coverage>,
    incidents: &[Incident],
    now: f64,
    detail: Option<(&[Event], bool)>,
) -> Context {
    let mut context = Context {
        now: Some(now),
        expires: unix_opt(row.expires),
        rejects,
        last_accept: unix_opt(row.last_seen),
        mac_mode: identity.and_then(Identity::mac_mode).map(|m| m.as_str().to_string()),
        randomized_macs_30d: identity.map(Identity::recent_randomized).unwrap_or_default(),
        coverage: cover,
        ..Context::default()
    };
    if let Some(st) = status.filter(|s| s.present)
        && let Some(ap) = &st.fields.ap
        && !load.is_empty()
    {
        let name = ap.name.clone().unwrap_or_default();
        let here = load.get(&name);
        let radio = radio_of(st.fields.band.as_deref());
        context.ap_load = Some(diagnostics::ApLoad {
            ap: Some(name),
            clients: here.and_then(|a| a.clients),
            band: st.fields.band.clone(),
            channel_util: here.and_then(|a| radio.and_then(|r| a.radios.get(r).copied().flatten())),
        });
    }
    let times = summary.map(|s| s.reconnect_times_24h.clone()).unwrap_or_default();
    context.disconnects = times
        .into_iter()
        .map(|at| diagnostics::Disconnect {
            at,
            basis: Basis::Inferred,
            source: Some("prometheus".into()),
            cause: None,
        })
        .collect();
    let mut names: BTreeSet<String> = summary.map(|s| s.aps_1h.iter().cloned().collect()).unwrap_or_default();
    if let Some(name) = status.and_then(|s| s.fields.ap.as_ref()).and_then(|a| a.name.clone()) {
        names.insert(name);
    }
    let mut ap_macs: BTreeSet<String> = BTreeSet::new();
    if let Some((merged, have_rows)) = detail {
        let measured: Vec<Event> = merged.iter().filter(|e| e.basis == Basis::Measured).cloned().collect();
        let measured = tl::disconnects(&measured, Some(now - 86400.0));
        let inferred: Vec<diagnostics::Disconnect> = std::mem::take(&mut context.disconnects)
            .into_iter()
            .filter(|d| !measured.iter().any(|m| (d.at - m.at).abs() <= tl::MERGE_S))
            .collect();
        context.disconnects = measured.into_iter().chain(inferred).collect();
        // measured roams: a count when the registry had events to count, else unknown
        let roams = merged
            .iter()
            .filter(|e| {
                e.basis == Basis::Measured && e.at >= now - 3600.0 && matches!(e.kind, "roamed" | "band_changed")
            })
            .count() as i64;
        context.roams_1h_measured = have_rows.then_some(roams);
        names.extend(merged.iter().filter_map(|e| e.ap.clone()));
        ap_macs.extend(merged.iter().filter_map(|e| e.ap_mac.clone()));
    }
    let lower: BTreeSet<String> = names.iter().map(|n| n.to_lowercase()).collect();
    context.incidents = relevant_incidents(incidents, &ap_macs, &lower)
        .into_iter()
        .map(|r| diagnostics::IncidentRef {
            id: Some(r.id),
            kind: r.kind.clone(),
            subject: Some(r.subject.clone()),
            subject_name: r.subject_name.clone(),
            started: unix(r.started),
            ended: unix_opt(r.ended),
            basis: Some(r.basis.clone()),
        })
        .collect();
    context
}

/// The last 24 h of the registry's measured events of one device (the detail page), merged; and
/// the sources that had rows.
async fn detail_events<S: Store>(
    store: &mut S,
    row: &DeviceRow,
    identity: Option<&Identity>,
    now: f64,
    aps: &ApMap,
) -> Result<(Vec<Event>, Vec<&'static str>)> {
    let (since, until) = (super::common::moment(now - 86400.0), super::common::moment(now));
    let acct = store.acct_sessions(row.id, since, until, 200).await?;
    let unifi = store.connection_events(row.id, since, until, 500).await?;
    let mut events = tl::from_acct(&acct, aps);
    events.extend(tl::from_unifi(&unifi, aps));
    let (events, _) = tl::merge(tl::restrict(events, identity), None);
    let mut found = Vec::new();
    if !acct.is_empty() {
        found.push("radius_acct");
    }
    if !unifi.is_empty() {
        found.push("unifi_syslog");
    }
    Ok((events, found))
}

/// The MAC a DEVICE shows: of its live MACs the one present with the newest association, else the
/// current window's, else the latest seen.
fn primary(macs: &[String], statuses: &IndexMap<String, LiveStatus>, identity: &Identity) -> Option<String> {
    let mut present: Option<(&String, f64)> = None;
    for m in macs {
        if let Some(st) = statuses.get(m).filter(|s| s.present) {
            let start = st.start.unwrap_or(f64::NEG_INFINITY);
            if present.is_none_or(|(_, s)| start > s) {
                present = Some((m, start));
            }
        }
    }
    if let Some((m, _)) = present {
        return Some(m.clone());
    }
    if let Some(current) = identity.current_mac().filter(|c| macs.iter().any(|m| m == c)) {
        return Some(current.to_string());
    }
    let mut seen: Option<(&String, f64)> = None;
    for m in macs {
        if let Some(t) = statuses.get(m).and_then(|s| s.last_seen)
            && seen.is_none_or(|(_, s)| t > s)
        {
            seen = Some((m, t));
        }
    }
    seen.map(|(m, _)| m.clone()).or_else(|| macs.first().cloned())
}

// --- the payload ------------------------------------------------------------------------------------

/// DASHBOARD (`/api/devices`, `/api/admin/devices`; INVENTORY 9.12).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Dashboard {
    pub generated_at: Option<String>,
    /// `ok` / `unavailable` / `off`
    pub telemetry: &'static str,
    /// telemetry ok and the Wi-Fi data old or its age unknown
    pub stale: bool,
    pub house: House,
    pub devices: Vec<Device>,
    /// the shortest of the devices' poll hints (30 without devices)
    pub poll_s: i64,
    /// `{state: n}` of all devices (before an admin filter)
    pub counts: IndexMap<String, i64>,
}

/// `/api/devices/<id>`: DASHBOARD with `device` instead of `devices` and without `counts`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct OneDevice {
    pub device: Device,
    pub generated_at: Option<String>,
    pub house: House,
    pub poll_s: i64,
    pub stale: bool,
    pub telemetry: &'static str,
}

impl Dashboard {
    /// The payload of one device (its first device; `None` without one). `poll_s` is its own.
    pub fn into_one(self) -> Option<OneDevice> {
        let device = self.devices.into_iter().next()?;
        let poll_s = presence::poll_s([Some(device.presence.poll_s)]);
        Some(OneDevice {
            device,
            generated_at: self.generated_at,
            house: self.house,
            poll_s,
            stale: self.stale,
            telemetry: self.telemetry,
        })
    }

    /// The admin list's filter: a search in the name, the owner's username and display name and
    /// the MAC (an AP's `AA-BB-...` form too), and a state of [`DEVICE_STATES`] (anything else is
    /// ignored). `poll_s` becomes the shown devices' hint; `counts` stay those of all devices.
    pub fn filter(&mut self, q: &str, state: &str) {
        let q = q.trim().to_lowercase();
        if !q.is_empty() {
            let mac_q = q.replace('-', ":");
            self.devices.retain(|d| {
                let owner = d.owner.as_ref();
                d.name.to_lowercase().contains(&q)
                    || owner.and_then(|o| o.username.as_ref()).is_some_and(|u| u.to_lowercase().contains(&q))
                    || owner.and_then(|o| o.display.as_ref()).is_some_and(|u| u.to_lowercase().contains(&q))
                    || d.mac.as_ref().is_some_and(|m| m.contains(&mac_q))
            });
        }
        if DEVICE_STATES.contains(&state) {
            self.devices.retain(|d| d.state == state);
        }
        self.poll_s = poll_s(&self.devices);
    }
}

/// `{state: n}` over DEVICEs (every state a key).
pub fn counts(devices: &[Device]) -> IndexMap<String, i64> {
    presence::counts(devices.iter().map(|d| d.state))
}

/// The page's poll interval: the shortest of its devices' hints.
pub fn poll_s(devices: &[Device]) -> i64 {
    presence::poll_s(devices.iter().map(|d| Some(d.presence.poll_s)))
}

/// What the dashboard is asked for.
#[derive(Debug, Clone, Default)]
pub struct DashboardOptions<'a> {
    /// adds each device's owner (admin views)
    pub owners: Option<&'a IndexMap<String, Person>>,
    pub admin: bool,
    /// one device's page: its accounting sessions and UniFi events of 24 h too
    pub detail: bool,
    /// the configured accounting interval (`NETPORTAL_ACCT_INTERIM_S`)
    pub interim_s: Option<i64>,
    /// the request's time (default: now)
    pub now: Option<f64>,
}

/// The current Unix time.
pub fn now() -> f64 {
    netportal_core::conventions::unix(time::OffsetDateTime::now_utc())
}

async fn shared_failures<S: Store>(page: &Page, store: &mut S, since: f64) -> Result<Vec<AuthFailure>> {
    if let Some(rows) = page.shared().failures() {
        return Ok(rows);
    }
    let rows = store.auth_failures(super::common::moment(since), None, 500).await?;
    page.shared().set_failures(&rows);
    Ok(rows)
}

async fn shared_incidents<S: Store>(page: &Page, store: &mut S, since: f64) -> Result<Vec<Incident>> {
    if let Some(rows) = page.shared().incidents() {
        return Ok(rows);
    }
    let rows = store.incidents(super::common::moment(since), None, None).await?;
    page.shared().set_incidents(&rows);
    Ok(rows)
}

/// The `/api/devices` payload for these registry rows (INVENTORY 9.1.5, "dashboard() algorithm").
///
/// The devices' MAC windows and conflicts of [`identity::RECENT_S`] (two queries), the house's
/// RADIUS rejects and incidents of 24 h (shared for [`super::SHARED_S`] between requests), every
/// device's newest accounting sessions and UniFi events (two queries, `presence::load`), the open
/// ap_down incidents; `detail` (one device's page): its accounting sessions and UniFi events of
/// 24 h too. A MAC in a conflict now is not asked for a resident (state `unknown`,
/// `mac_conflict`); an admin sees the data and the conflict. Prometheus down: telemetry
/// `unavailable`, the registry's evidence still decides the presence.
pub async fn dashboard<S: Store>(
    page: &Page,
    store: &mut S,
    rows: &[DeviceRow],
    opts: &DashboardOptions<'_>,
) -> Result<Dashboard> {
    let now = opts.now.unwrap_or_else(now);
    let mut telemetry = page.telemetry();
    let mut house = empty_house();
    let identities = identity::from_registry(store, rows, now, opts.admin, Some(now - identity::RECENT_S)).await?;
    let (failures, incidents) = if rows.is_empty() {
        (Vec::new(), Vec::new())
    } else {
        (shared_failures(page, store, now - 86400.0).await?, shared_incidents(page, store, now - 86400.0).await?)
    };
    let mut bounds: BTreeMap<String, f64> = BTreeMap::new();
    for identity in identities.values() {
        if identity.withheld_now() {
            continue;
        }
        for (mac, bound) in identity.live_bounds() {
            // several devices, one MAC: the latest
            let b = bounds.entry(mac).or_insert(bound);
            *b = b.max(bound);
        }
    }
    let wanted: Vec<String> = bounds.keys().cloned().collect();
    let ended: IndexMap<Uuid, (String, f64, f64)> =
        identities.iter().filter_map(|(id, i)| ended_window(i, now).map(|w| (*id, w))).collect();
    let mut statuses: IndexMap<String, LiveStatus> = IndexMap::new();
    let mut summaries: IndexMap<String, Summary> = IndexMap::new();
    let mut load: IndexMap<String, ApLoadNow> = IndexMap::new();
    let mut cover: IndexMap<String, IndexMap<String, Coverage>> = IndexMap::new();
    let mut ended_seen: IndexMap<Uuid, Option<f64>> = IndexMap::new();
    if let Some(client) = page.budget.as_ref() {
        let asked = async {
            house = house_status(client).await?;
            if !wanted.is_empty() {
                let finite: BTreeMap<String, f64> =
                    bounds.iter().filter(|(_, b)| b.is_finite()).map(|(m, b)| (m.clone(), *b)).collect();
                let (s, m) = device_status(client, &wanted, &finite, now).await?;
                statuses = s;
                summaries = m;
                cover = coverage(client, &wanted, &finite, now).await?;
                if statuses.values().any(|s| s.present) {
                    load = ap_load(client).await?;
                }
            }
            for (id, (mac, start, end)) in &ended {
                ended_seen.insert(*id, last_seen_until(client, mac, *start, *end).await?);
            }
            Ok::<(), Unavailable>(())
        };
        if asked.await.is_err() {
            // the house keeps what was read (it is valid); the devices' Prometheus data goes
            telemetry = UNAVAILABLE;
            statuses.clear();
            summaries.clear();
            load.clear();
            cover.clear();
            ended_seen.clear();
        }
    }
    let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    let ssid = Some(page.ssid.as_str()).filter(|s| !s.is_empty());
    let found = if rows.is_empty() { IndexMap::new() } else { presence::load(store, &ids, ssid).await? };
    let has_sessions = found.values().any(|f| !f.sessions.is_empty());
    let aps = if opts.detail || has_sessions {
        if telemetry == OK { ap_map(page).await } else { page.shared().known_aps() }
    } else {
        ApMap::default()
    };
    let down = presence::ap_down(&incidents);
    let mut devices = Vec::with_capacity(rows.len());
    for row in rows {
        let identity = identities.get(&row.id);
        let withheld = identity.is_some_and(Identity::withheld_now);
        let raw = found.get(&row.id);
        let sessions =
            raw.map(|f| f.sessions.iter().map(|s| presence::session(s, Some(&aps))).collect()).unwrap_or_default();
        let events = raw.map(|f| f.events.iter().map(presence::event).collect()).unwrap_or_default();
        let macs: Vec<String> = if withheld {
            Vec::new()
        } else {
            identity.map(|i| i.live_bounds().into_keys().collect()).unwrap_or_default()
        };
        let mac = identity.and_then(|i| primary(&macs, &statuses, i));
        let conflict = if opts.admin {
            identity.map_or(0, Identity::conflict_owners_now)
        } else if withheld {
            1
        } else {
            0
        };
        let rejects = rejects_of(row, identity, &failures);
        let detail =
            if opts.detail && !withheld { Some(detail_events(store, row, identity, now, &aps).await?) } else { None };
        let mut status = mac.as_ref().and_then(|m| statuses.get(m)).cloned();
        if status.is_none()
            && let Some(Some(seen)) = ended_seen.get(&row.id)
        {
            status = Some(LiveStatus { last_seen: Some(*seen), ..LiveStatus::default() });
        }
        let summary = mac.as_ref().and_then(|m| summaries.get(m));
        let mut cov: IndexMap<String, Coverage> = IndexMap::new();
        for m in &macs {
            for (ap, c) in cover.get(m).into_iter().flatten() {
                if cov.get(ap).is_none_or(|have| c.samples > have.samples) {
                    cov.insert(ap.clone(), c.clone());
                }
            }
        }
        let detail_ref = detail.as_ref().map(|(events, found)| (events.as_slice(), !found.is_empty()));
        let ctx =
            context(row, identity, summary, status.as_ref(), rejects.clone(), &load, cov, &incidents, now, detail_ref);
        let extra = Extra {
            identity,
            context: ctx,
            last_auth: last_auth(row, &rejects),
            sources: detail.map(|(_, found)| found).unwrap_or_default(),
            sessions: presence::own_sessions(sessions, identity),
            events: presence::own_events(events, identity),
            ap_down: down.clone(),
            interim_s: opts.interim_s,
        };
        let shown = mac.clone().or_else(|| identity.and_then(|i| i.current_mac().map(str::to_string)));
        let mut device = device_entry(
            row,
            shown.as_deref(),
            status.as_ref(),
            telemetry,
            &house,
            now,
            summary,
            conflict,
            opts.admin,
            extra,
        );
        if let Some(owners) = opts.owners {
            device.owner = Some(Owner::of(owners.get(&row.owner)));
        }
        devices.push(device);
    }
    let stale = telemetry == OK && diagnostics::is_stale(house.wifi_data_age_s);
    Ok(Dashboard {
        generated_at: iso(Some(now)),
        telemetry,
        stale,
        poll_s: poll_s(&devices),
        counts: counts(&devices),
        house,
        devices,
    })
}

/// The identities of rows (the admin's raw view needs the one of a device).
pub async fn identities<S: Store>(
    store: &mut S,
    rows: &[DeviceRow],
    now: f64,
    admin: bool,
) -> std::result::Result<IndexMap<Uuid, Identity>, RegistryError> {
    identity::from_registry(store, rows, now, admin, None).await
}
