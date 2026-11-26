//! Findings per device and AP warnings (Python `netportal/diagnostics.py`, INVENTORY 9.8): what
//! the dashboard says about a device's Wi-Fi, from the data that is there.
//!
//! A finding is `{code, severity: info|warn|bad, params, basis, evidence}`: params are what the
//! frontend's texts fill in; basis is `measured` (samples, RADIUS packets, UniFi events, registry
//! rows) or `inferred` (an association-start reset, a change of the AP label, a correlation in
//! time); evidence holds the values it rests on, with the threshold that made it a finding. A rule
//! whose data is missing says nothing: no data is not a problem. Each threshold below says why it
//! is where it is.

use std::collections::BTreeSet;

use indexmap::IndexMap;
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::telemetry::common::{iso, trunc_int};
pub use crate::telemetry::timeline::Basis;

/// `bad` < `warn` < `info` (worst first).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Bad,
    Warn,
    Info,
}

/// unpoller serves its last snapshot when the controller does not answer: older than this, the
/// values are the past (the same limit as house-infra's UnifiMetricsStale alert).
pub const STALE_AFTER_S: i64 = 600;

/// Signal (dBm at the AP). -67 dBm is the usual target for calls and video; below -75 the rate
/// drops and the device holds on to a far AP; below -80 the link itself becomes unreliable.
pub const WEAK_SIGNAL_WARN_DBM: f64 = -75.0;
pub const WEAK_SIGNAL_BAD_DBM: f64 = -80.0;
/// Signal-to-noise: 25 dB and more is good; below 20 dB only the slow rates work, below 15 dB
/// hardly any. Only said when the signal itself is fine (then the noise is the cause).
pub const LOW_SNR_WARN_DB: f64 = 20.0;
pub const LOW_SNR_BAD_DB: f64 = 15.0;
/// Retries (retries / attempts over 5 min): above 10 % latency is noticeable, above 25 % every
/// fourth frame is sent again. Only with at least this many transmit attempts per second: an
/// idle device's ratio comes from a handful of frames.
pub const HIGH_RETRIES_WARN: f64 = 0.10;
pub const HIGH_RETRIES_BAD: f64 = 0.25;
pub const RETRIES_MIN_ATTEMPTS: f64 = 10.0;
/// Channel utilisation of the device's AP radio: the health score penalises above 60 %; above
/// 80 % the air is nearly always busy.
pub const BUSY_CHANNEL_WARN: f64 = 0.60;
pub const BUSY_CHANNEL_BAD: f64 = 0.80;
/// AP or band changes in the last hour: every 10 minutes or more often is ping-pong.
pub const UNSTABLE_ROAMING_WARN: i64 = 6;
pub const UNSTABLE_ROAMING_BAD: i64 = 15;
/// New associations in 24 h: more than 5 is unusual, more than 20 (about hourly) means the
/// connection keeps dropping.
pub const FREQUENT_DISCONNECTS_WARN: i64 = 6;
pub const FREQUENT_DISCONNECTS_BAD: i64 = 20;
/// Slow link: the receive link rate below this although the signal is good and data flows.
pub const SLOW_LINK_BPS: i64 = 20_000_000;
pub const SLOW_LINK_GOOD_SIGNAL_DBM: f64 = -65.0;
pub const SLOW_LINK_ACTIVE_BPS: i64 = 1_000_000;
/// Stuck on 2.4 GHz: there for the whole last hour with a signal good enough for 5 GHz, and seen
/// on 5 or 6 GHz in 7 days (so it can).
pub const STUCK_2GHZ_MIN_SIGNAL_DBM: f64 = -60.0;
pub const STUCK_2GHZ_MIN_S: f64 = 3600.0;
/// RADIUS rejects in 24 h: three and more mean the device keeps trying with something the
/// server refuses, twenty that it tries all the time; one after the last accept warns at once.
pub const AUTH_FAILURES_WARN: i64 = 3;
pub const AUTH_FAILURES_BAD: i64 = 20;
/// The certificate: a renewal hint from 30 days, warn from 7 days, bad once expired.
pub const CERT_EXPIRING_INFO_DAYS: f64 = 30.0;
pub const CERT_EXPIRING_WARN_DAYS: f64 = 7.0;
/// AP load while the device is on it: Wi-Fi 6 APs share the air well up to about 25 active
/// clients, beyond 40 every client waits; utilisation counts only with at least 10 clients (a
/// busy channel with few clients is interference: busy_channel).
pub const AP_CLIENTS_WARN: i64 = 25;
pub const AP_CLIENTS_BAD: i64 = 40;
pub const AP_UTIL_WARN: f64 = 0.80;
pub const AP_UTIL_BAD: f64 = 0.90;
pub const AP_LOAD_MIN_CLIENTS: i64 = 10;
/// AP warnings: a quarter or more of an AP's clients below -75 dBm (with at least 4 clients); up
/// for less than a day; a wired uplink below 1000 Mbit/s.
pub const AP_WEAK_SHARE_WARN: f64 = 0.25;
pub const AP_WEAK_MIN_CLIENTS: i64 = 4;
pub const AP_RESTARTED_S: i64 = 86400;
pub const AP_UPLINK_MIN_MBPS: i64 = 1000;
/// Poor coverage: the 24 h average signal at every AP used for at least 60 minutes is weak
/// (averages sit above the momentary values, so the limits are a few dB higher).
pub const POOR_COVERAGE_WARN_DBM: f64 = -72.0;
pub const POOR_COVERAGE_BAD_DBM: f64 = -78.0;
pub const COVERAGE_MIN_SAMPLES: f64 = 60.0;
/// Incident correlation: a disconnect from 2 minutes before an incident's start until 2 minutes
/// after its end, at most 15 minutes after the start.
pub const INCIDENT_MARGIN_S: f64 = 120.0;
pub const INCIDENT_SPAN_MAX_S: f64 = 900.0;

/// A finding (the API's FINDING, INVENTORY 9.12).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Finding {
    pub code: &'static str,
    pub severity: Severity,
    pub params: Map<String, Value>,
    pub basis: Basis,
    pub evidence: Map<String, Value>,
}

/// A JSON object of a `json!({...})` literal.
pub(crate) fn object(v: Value) -> Map<String, Value> {
    match v {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

/// A finding; evidence defaults to the params (the values it rests on).
pub fn finding(
    code: &'static str,
    severity: Severity,
    basis: Basis,
    evidence: Option<Value>,
    params: Value,
) -> Finding {
    let params = object(params);
    let evidence = evidence.map(object).unwrap_or_else(|| params.clone());
    Finding { code, severity, params, basis, evidence }
}

fn below(value: Option<f64>, warn: f64, bad: f64) -> Option<Severity> {
    let v = value?;
    if v <= bad {
        Some(Severity::Bad)
    } else if v <= warn {
        Some(Severity::Warn)
    } else {
        None
    }
}

fn above(value: Option<f64>, warn: f64, bad: f64) -> Option<Severity> {
    let v = value?;
    if v >= bad {
        Some(Severity::Bad)
    } else if v >= warn {
        Some(Severity::Warn)
    } else {
        None
    }
}

fn worst(a: Option<Severity>, b: Option<Severity>) -> Option<Severity> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// The Wi-Fi data is old or its age unknown (unpoller not scraped).
pub fn is_stale(wifi_data_age_s: Option<i64>) -> bool {
    wifi_data_age_s.is_none_or(|a| a > STALE_AFTER_S)
}

// --- the inputs -------------------------------------------------------------------------------------

/// What the rules read of a DEVICE (`live::Device`): its state and live values.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DeviceView {
    pub state: String,
    pub mac: Option<String>,
    pub band: Option<String>,
    pub channel: Option<i64>,
    pub signal_dbm: Option<f64>,
    pub noise_dbm: Option<f64>,
    pub snr_db: Option<f64>,
    pub retry_ratio: Option<f64>,
    pub channel_util: Option<f64>,
    pub link_rx_bps: Option<i64>,
    pub rx_bps: Option<i64>,
    pub tx_bps: Option<i64>,
    pub roams_1h: Option<i64>,
    /// ISO
    pub last_seen: Option<String>,
    pub presence: Option<PresenceView>,
}

/// What the rules read of DEVICE.presence (ISO times).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PresenceView {
    pub confirmed_at: Option<String>,
    pub confirmed_by: Option<String>,
    pub reason: Option<String>,
    pub basis: Option<Basis>,
}

/// A device's recent history (`live::device_status`): reconnects in 24 h and their times, the
/// bands seen in 7 days, transmit attempts per second, the APs of the last hour, seconds since
/// the association.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Summary {
    pub reconnects_24h: Option<i64>,
    pub reconnect_times_24h: Vec<f64>,
    pub bands_7d: Vec<String>,
    pub tx_attempts_per_s: Option<f64>,
    pub aps_1h: Vec<String>,
    pub associated_s: Option<f64>,
}

/// A RADIUS reject of the device (Unix times): `count` tries, the latest at `last_at`.
#[derive(Debug, Clone, PartialEq)]
pub struct Reject {
    pub at: f64,
    pub last_at: Option<f64>,
    pub count: i64,
    pub reason: String,
    pub mac: Option<String>,
}

impl Reject {
    /// The latest try (a row of repeats: its last_at).
    pub fn last(&self) -> f64 {
        self.last_at.unwrap_or(self.at)
    }
}

/// The load of the AP the device is on.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ApLoad {
    pub ap: Option<String>,
    pub clients: Option<i64>,
    pub band: Option<String>,
    pub channel_util: Option<f64>,
}

/// The device's 24 h average signal at one AP and the number of samples (minutes).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Coverage {
    pub signal_dbm: Option<f64>,
    pub samples: f64,
}

/// A disconnect (`timeline::disconnects`, or an inferred association reset).
#[derive(Debug, Clone, PartialEq)]
pub struct Disconnect {
    pub at: f64,
    pub basis: Basis,
    pub source: Option<String>,
    pub cause: Option<String>,
}

/// An incident that concerns the device (Unix times).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct IncidentRef {
    pub id: Option<i64>,
    pub kind: String,
    pub subject: Option<String>,
    pub subject_name: Option<String>,
    pub started: f64,
    pub ended: Option<f64>,
    pub basis: Option<String>,
}

/// The registry's and the house's data of one device (`live`'s `_context`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Context {
    pub now: Option<f64>,
    /// the certificate's expiry (Unix)
    pub expires: Option<f64>,
    pub rejects: Vec<Reject>,
    pub last_accept: Option<f64>,
    /// `hardware` | `random_fixed` | `rotating`
    pub mac_mode: Option<String>,
    pub randomized_macs_30d: Vec<String>,
    pub ap_load: Option<ApLoad>,
    /// by AP name
    pub coverage: IndexMap<String, Coverage>,
    pub disconnects: Vec<Disconnect>,
    pub roams_1h_measured: Option<i64>,
    pub incidents: Vec<IncidentRef>,
}

// --- the rules -----------------------------------------------------------------------------------------

/// never_connected, offline, stale_data: what is known about the device at all. The state is
/// presence's: offline only when presence says so (never for unknown or connecting), its
/// evidence the presence's confirmation. stale_data only while Prometheus answers: for an unknown
/// state, and for one that RADIUS or UniFi's log decided while the snapshot is old.
pub fn state_findings(device: &DeviceView, wifi_data_age_s: Option<i64>, telemetry: &str) -> Vec<Finding> {
    if device.state == "never_connected" {
        return vec![finding(
            "never_connected",
            Severity::Info,
            Basis::Measured,
            Some(json!({"logins": 0})),
            json!({}),
        )];
    }
    let mut out = Vec::new();
    let presence = device.presence.clone().unwrap_or_default();
    let from_radius = matches!(presence.confirmed_by.as_deref(), Some("radius_acct" | "radius_auth" | "unifi_syslog"));
    if telemetry == "ok" && is_stale(wifi_data_age_s) && (device.state == "unknown" || from_radius) {
        out.push(finding(
            "stale_data",
            Severity::Warn,
            Basis::Measured,
            Some(json!({"age_s": wifi_data_age_s, "threshold_s": STALE_AFTER_S})),
            json!({"age_s": wifi_data_age_s}),
        ));
    }
    if device.state == "offline" {
        out.push(finding(
            "offline",
            Severity::Info,
            presence.basis.unwrap_or(Basis::Measured),
            Some(json!({"last_seen": device.last_seen, "confirmed_at": presence.confirmed_at,
                        "confirmed_by": presence.confirmed_by, "reason": presence.reason})),
            json!({"last_seen": device.last_seen}),
        ));
    }
    out
}

/// weak_signal, low_snr, high_retries, busy_channel, slow_link: only while online.
pub fn radio_findings(device: &DeviceView, summary: Option<&Summary>) -> Vec<Finding> {
    if device.state != "online" {
        return Vec::new();
    }
    let mut out = Vec::new();
    let signal = device.signal_dbm;
    let weak = below(signal, WEAK_SIGNAL_WARN_DBM, WEAK_SIGNAL_BAD_DBM);
    if let Some(level) = weak {
        out.push(finding(
            "weak_signal",
            level,
            Basis::Measured,
            Some(json!({"signal_dbm": signal, "warn_dbm": WEAK_SIGNAL_WARN_DBM, "bad_dbm": WEAK_SIGNAL_BAD_DBM})),
            json!({"signal_dbm": signal}),
        ));
    }
    let snr = device.snr_db;
    if let Some(level) = below(snr, LOW_SNR_WARN_DB, LOW_SNR_BAD_DB)
        && weak.is_none()
    {
        out.push(finding(
            "low_snr",
            level,
            Basis::Measured,
            Some(
                json!({"snr_db": snr, "noise_dbm": device.noise_dbm, "signal_dbm": signal, "warn_db": LOW_SNR_WARN_DB}),
            ),
            json!({"snr_db": snr, "noise_dbm": device.noise_dbm}),
        ));
    }
    let retries = device.retry_ratio;
    let attempts = summary.and_then(|s| s.tx_attempts_per_s);
    if let Some(level) = above(retries, HIGH_RETRIES_WARN, HIGH_RETRIES_BAD)
        && attempts.is_some_and(|a| a >= RETRIES_MIN_ATTEMPTS)
    {
        out.push(finding(
            "high_retries",
            level,
            Basis::Measured,
            Some(json!({"retry_ratio": retries, "tx_attempts_per_s": attempts, "warn": HIGH_RETRIES_WARN})),
            json!({"retry_ratio": retries}),
        ));
    }
    let util = device.channel_util;
    if let Some(level) = above(util, BUSY_CHANNEL_WARN, BUSY_CHANNEL_BAD) {
        out.push(finding(
            "busy_channel",
            level,
            Basis::Measured,
            None,
            json!({"channel_util": util, "channel": device.channel}),
        ));
    }
    if let (Some(link), Some(signal), Some(rx), Some(tx)) = (device.link_rx_bps, signal, device.rx_bps, device.tx_bps)
        && link < SLOW_LINK_BPS
        && signal >= SLOW_LINK_GOOD_SIGNAL_DBM
        && rx + tx >= SLOW_LINK_ACTIVE_BPS
    {
        out.push(finding(
            "slow_link",
            Severity::Warn,
            Basis::Measured,
            Some(json!({"link_rx_bps": link, "signal_dbm": signal, "throughput_bps": rx + tx})),
            json!({"link_rx_bps": link, "signal_dbm": signal}),
        ));
    }
    out
}

fn as_f64(v: Option<i64>) -> Option<f64> {
    v.map(|v| v as f64)
}

/// unstable_roaming, frequent_disconnects, stuck_on_2ghz: from the recent history. The counts
/// from Prometheus are inferred; measured roams and disconnects (UniFi events, accounting) count
/// when they say more.
pub fn history_findings(device: &DeviceView, summary: Option<&Summary>, context: &Context) -> Vec<Finding> {
    if !matches!(device.state.as_str(), "online" | "offline") {
        return Vec::new();
    }
    let mut out = Vec::new();
    let roams = device.roams_1h;
    let measured_roams = context.roams_1h_measured;
    let level = above(as_f64(roams), UNSTABLE_ROAMING_WARN as f64, UNSTABLE_ROAMING_BAD as f64);
    let measured_level = above(as_f64(measured_roams), UNSTABLE_ROAMING_WARN as f64, UNSTABLE_ROAMING_BAD as f64);
    if level.is_some() || measured_level.is_some() {
        let measured =
            measured_level.is_some() && (level.is_none() || measured_roams.unwrap_or(0) >= roams.unwrap_or(0));
        let (basis, count) = if measured { (Basis::Measured, measured_roams) } else { (Basis::Inferred, roams) };
        out.push(finding(
            "unstable_roaming",
            worst(level, measured_level).unwrap_or(Severity::Warn),
            basis,
            Some(json!({"roams_1h": roams, "roams_1h_measured": measured_roams, "warn": UNSTABLE_ROAMING_WARN})),
            json!({"roams_1h": count}),
        ));
    }
    let reconnects = summary.and_then(|s| s.reconnects_24h);
    let measured: Vec<&Disconnect> = context.disconnects.iter().filter(|d| d.basis == Basis::Measured).collect();
    let n = measured.len() as i64;
    let level = above(as_f64(reconnects), FREQUENT_DISCONNECTS_WARN as f64, FREQUENT_DISCONNECTS_BAD as f64);
    let measured_level = above(
        (!measured.is_empty()).then_some(n as f64),
        FREQUENT_DISCONNECTS_WARN as f64,
        FREQUENT_DISCONNECTS_BAD as f64,
    );
    if level.is_some() || measured_level.is_some() {
        let mut causes: IndexMap<String, i64> = IndexMap::new();
        for d in &measured {
            if let Some(cause) = d.cause.as_ref().filter(|c| !c.is_empty()) {
                *causes.entry(cause.clone()).or_default() += 1;
            }
        }
        let is_measured = measured_level.is_some() && n >= reconnects.unwrap_or(0);
        let (basis, count) = if is_measured { (Basis::Measured, Some(n)) } else { (Basis::Inferred, reconnects) };
        out.push(finding(
            "frequent_disconnects",
            worst(level, measured_level).unwrap_or(Severity::Warn),
            basis,
            Some(json!({"reconnects_24h": reconnects, "disconnects_24h_measured": n, "causes": causes,
                        "warn": FREQUENT_DISCONNECTS_WARN})),
            json!({"reconnects_24h": count}),
        ));
    }
    let bands: BTreeSet<&str> = summary.map(|s| s.bands_7d.iter().map(String::as_str).collect()).unwrap_or_default();
    let associated = summary.and_then(|s| s.associated_s);
    if device.state == "online"
        && device.band.as_deref() == Some("2.4")
        && (bands.contains("5") || bands.contains("6"))
        && roams == Some(0)
        && associated.is_some_and(|a| a >= STUCK_2GHZ_MIN_S)
        && device.signal_dbm.is_some_and(|s| s >= STUCK_2GHZ_MIN_SIGNAL_DBM)
    {
        let sorted: Vec<&str> = bands.into_iter().collect();
        out.push(finding(
            "stuck_on_2ghz",
            Severity::Info,
            Basis::Measured,
            Some(json!({"bands_7d": sorted, "signal_dbm": device.signal_dbm,
                        "associated_s": associated.and_then(trunc_int)})),
            json!({"bands_7d": sorted}),
        ));
    }
    out
}

/// auth_failures: RADIUS rejects of the device's certificate or MACs in 24 h; a row of repeats
/// counts as its tries.
pub fn auth_findings(context: &Context) -> Vec<Finding> {
    let mut rejects: Vec<&Reject> = context.rejects.iter().collect();
    rejects.sort_by(|a, b| a.last().total_cmp(&b.last()));
    let Some(last) = rejects.last() else {
        return Vec::new();
    };
    let count: i64 = rejects.iter().map(|r| r.count.max(1)).sum();
    let locked_out = context.last_accept.is_none_or(|a| last.last() > a);
    let mut level = above(Some(count as f64), AUTH_FAILURES_WARN as f64, AUTH_FAILURES_BAD as f64);
    if locked_out {
        level = worst(level, Some(Severity::Warn));
    }
    let Some(level) = level else {
        return Vec::new();
    };
    let mut reasons: IndexMap<&str, i64> = IndexMap::new();
    for r in &rejects {
        *reasons.entry(r.reason.as_str()).or_default() += r.count.max(1);
    }
    let last_at = iso(Some(last.last()));
    vec![finding(
        "auth_failures",
        level,
        Basis::Measured,
        Some(json!({"count_24h": count, "reasons": reasons, "last_at": last_at, "last_reason": last.reason,
                    "last_accept": iso(context.last_accept), "locked_out": locked_out, "warn": AUTH_FAILURES_WARN})),
        json!({"count": count, "reason": last.reason, "last_at": last_at}),
    )]
}

/// cert_expired, cert_expiring: the device's certificate (registry).
pub fn cert_findings(context: &Context) -> Vec<Finding> {
    let (Some(expires), Some(now)) = (context.expires, context.now) else {
        return Vec::new();
    };
    let days_left = (expires - now) / 86400.0;
    let days = trunc_int(days_left);
    let evidence = json!({"expires": iso(Some(expires)), "days_left": days});
    if expires <= now {
        return vec![finding(
            "cert_expired",
            Severity::Bad,
            Basis::Measured,
            Some(evidence),
            json!({"expires": iso(Some(expires))}),
        )];
    }
    let params = json!({"expires": iso(Some(expires)), "days_left": days});
    if days_left <= CERT_EXPIRING_WARN_DAYS {
        return vec![finding("cert_expiring", Severity::Warn, Basis::Measured, Some(evidence), params)];
    }
    if days_left <= CERT_EXPIRING_INFO_DAYS {
        return vec![finding("cert_expiring", Severity::Info, Basis::Measured, Some(evidence), params)];
    }
    Vec::new()
}

/// rotating_mac: the device changes its private address (history only per address).
pub fn identity_findings(context: &Context) -> Vec<Finding> {
    if context.mac_mode.as_deref() != Some("rotating") {
        return Vec::new();
    }
    let n = context.randomized_macs_30d.len();
    vec![finding(
        "rotating_mac",
        Severity::Info,
        Basis::Measured,
        Some(json!({"macs_30d": n, "min_macs": crate::telemetry::identity::ROTATING_MIN_MACS})),
        json!({"macs_30d": n}),
    )]
}

/// bad/warn/None of an AP's load: its clients, or its radio's utilisation with many clients.
pub fn ap_load_level(clients: Option<i64>, util: Option<f64>) -> Option<Severity> {
    let clients = clients?;
    let mut level = above(Some(clients as f64), AP_CLIENTS_WARN as f64, AP_CLIENTS_BAD as f64);
    if clients >= AP_LOAD_MIN_CLIENTS {
        level = worst(level, above(util, AP_UTIL_WARN, AP_UTIL_BAD));
    }
    level
}

/// ap_overloaded: many clients on the device's AP (or a full channel with many clients).
pub fn load_findings(device: &DeviceView, context: &Context) -> Vec<Finding> {
    let Some(load) = context.ap_load.as_ref().filter(|l| l.clients.is_some()) else {
        return Vec::new();
    };
    if device.state != "online" {
        return Vec::new();
    }
    let Some(level) = ap_load_level(load.clients, load.channel_util) else {
        return Vec::new();
    };
    vec![finding(
        "ap_overloaded",
        level,
        Basis::Measured,
        Some(json!({"ap": load.ap, "clients": load.clients, "channel_util": load.channel_util, "band": load.band,
                    "clients_warn": AP_CLIENTS_WARN, "util_warn": AP_UTIL_WARN})),
        json!({"ap": load.ap, "clients": load.clients, "channel_util": load.channel_util}),
    )]
}

/// poor_coverage: weak on average at every AP the device used in 24 h (a gap at its place).
pub fn coverage_findings(device: &DeviceView, context: &Context) -> Vec<Finding> {
    if !matches!(device.state.as_str(), "online" | "offline") {
        return Vec::new();
    }
    let mut used: Vec<(&String, f64, f64)> = context
        .coverage
        .iter()
        .filter_map(|(ap, c)| c.signal_dbm.filter(|_| c.samples >= COVERAGE_MIN_SAMPLES).map(|s| (ap, s, c.samples)))
        .collect();
    if used.is_empty() {
        return Vec::new();
    }
    used.sort_by(|a, b| a.0.cmp(b.0));
    let best = used.iter().map(|(_, s, _)| *s).fold(f64::NEG_INFINITY, f64::max);
    let Some(level) = below(Some(best), POOR_COVERAGE_WARN_DBM, POOR_COVERAGE_BAD_DBM) else {
        return Vec::new();
    };
    let round1 = |v: f64| netportal_core::conventions::round_to(v, 1);
    let aps: Map<String, Value> = used.iter().map(|(ap, s, _)| ((*ap).clone(), json!(round1(*s)))).collect();
    let minutes: Map<String, Value> = used.iter().map(|(ap, _, n)| ((*ap).clone(), json!(trunc_int(*n)))).collect();
    vec![finding(
        "poor_coverage",
        level,
        Basis::Measured,
        Some(json!({"aps": aps, "minutes": minutes, "warn_dbm": POOR_COVERAGE_WARN_DBM})),
        json!({"best_signal_dbm": round1(best), "aps": used.len()}),
    )]
}

/// incident_correlated (inferred): disconnects of the device around an incident of its AP, the
/// house's router or internet. One finding, about the latest such incident.
pub fn incident_findings(context: &Context) -> Vec<Finding> {
    let mut disconnects: Vec<f64> = context.disconnects.iter().map(|d| d.at).collect();
    disconnects.sort_by(f64::total_cmp);
    let mut hits: Vec<(f64, &IncidentRef, Vec<f64>)> = Vec::new();
    for inc in &context.incidents {
        let started = inc.started;
        let end = inc.ended.or(context.now).unwrap_or(started).min(started + INCIDENT_SPAN_MAX_S);
        let times: Vec<f64> = disconnects
            .iter()
            .copied()
            .filter(|t| started - INCIDENT_MARGIN_S <= *t && *t <= end + INCIDENT_MARGIN_S)
            .collect();
        if !times.is_empty() {
            hits.push((started, inc, times));
        }
    }
    // the latest-started (Python's max keeps the first of equals)
    let mut chosen: Option<&(f64, &IncidentRef, Vec<f64>)> = None;
    for h in &hits {
        if chosen.is_none_or(|c| h.0 > c.0) {
            chosen = Some(h);
        }
    }
    let Some((_, inc, times)) = chosen else {
        return Vec::new();
    };
    let incident = json!({"id": inc.id, "kind": inc.kind, "subject": inc.subject, "subject_name": inc.subject_name,
                          "started": iso(Some(inc.started)), "ended": iso(inc.ended), "basis": inc.basis});
    let at: Vec<Option<String>> = times.iter().map(|t| iso(Some(*t))).collect();
    vec![finding(
        "incident_correlated",
        Severity::Info,
        Basis::Inferred,
        Some(json!({"incident": incident, "disconnects": at, "incidents_correlated": hits.len(),
                    "margin_s": INCIDENT_MARGIN_S})),
        json!({"kind": inc.kind, "subject_name": inc.subject_name, "started": iso(Some(inc.started)),
               "disconnects": times.len()}),
    )]
}

/// Every finding for a device, the worst first (a stable sort).
pub fn findings(
    device: &DeviceView,
    summary: Option<&Summary>,
    wifi_data_age_s: Option<i64>,
    telemetry: &str,
    context: &Context,
) -> Vec<Finding> {
    let mut out = state_findings(device, wifi_data_age_s, telemetry);
    if device.state != "never_connected" {
        // the radio and the AP's load only from a fresh snapshot (a frozen one is the past)
        let live = !(wifi_data_age_s.is_some() && is_stale(wifi_data_age_s));
        if live {
            out.extend(radio_findings(device, summary));
        }
        out.extend(history_findings(device, summary, context));
        out.extend(identity_findings(context));
        if live {
            out.extend(load_findings(device, context));
        }
        out.extend(coverage_findings(device, context));
        out.extend(incident_findings(context));
    }
    out.extend(auth_findings(context));
    out.extend(cert_findings(context));
    out.sort_by_key(|f| f.severity);
    out
}

// --- the APs' own warnings --------------------------------------------------------------------------

/// What the AP warnings read of an admin AP (`admin::Ap`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ApFacts {
    /// `ok` / `down` / `unknown`
    pub state: String,
    pub clients: Option<i64>,
    pub weak_clients: Option<i64>,
    pub uptime_s: Option<i64>,
    pub uplink_mbps: Option<i64>,
    /// the radios' channel utilisation
    pub utils: Vec<f64>,
    pub open_incidents: Vec<i64>,
}

fn ap_warning(code: &'static str, severity: Severity, evidence: Value, params: Value) -> Finding {
    finding(code, severity, Basis::Measured, Some(evidence), params)
}

/// The AP's warnings, the worst first: down (an open ap_down incident; then nothing else),
/// overloaded (as for a device on it) else busy_channel (a radio at 60 % or more: interference),
/// poor_coverage (a quarter of its clients below -75 dBm), restarted (up for less than a day),
/// uplink (below 1000 Mbit/s).
pub fn ap_warnings(ap: &ApFacts) -> Vec<Finding> {
    if ap.state == "down" {
        return vec![ap_warning("down", Severity::Bad, json!({"open_incidents": ap.open_incidents}), json!({}))];
    }
    let mut out = Vec::new();
    let clients = ap.clients;
    let util = ap.utils.iter().copied().reduce(f64::max);
    if let Some(level) = ap_load_level(clients, util) {
        out.push(ap_warning(
            "overloaded",
            level,
            json!({"clients": clients, "channel_util": util, "clients_warn": AP_CLIENTS_WARN, "util_warn": AP_UTIL_WARN}),
            json!({"clients": clients, "channel_util": util}),
        ));
    } else if let Some(u) = util.filter(|u| *u >= BUSY_CHANNEL_WARN) {
        out.push(ap_warning(
            "busy_channel",
            Severity::Warn,
            json!({"channel_util": u, "threshold": BUSY_CHANNEL_WARN}),
            json!({"channel_util": u}),
        ));
    }
    if let (Some(clients), Some(weak)) = (clients, ap.weak_clients)
        && clients > 0
        && clients >= AP_WEAK_MIN_CLIENTS
        && weak as f64 / clients as f64 >= AP_WEAK_SHARE_WARN
    {
        let share = netportal_core::conventions::round_to(weak as f64 / clients as f64, 3);
        out.push(ap_warning(
            "poor_coverage",
            Severity::Warn,
            json!({"weak_clients": weak, "clients": clients, "share": share, "threshold": AP_WEAK_SHARE_WARN,
                   "signal_dbm": WEAK_SIGNAL_WARN_DBM}),
            json!({"share": share, "weak_clients": weak, "clients": clients}),
        ));
    }
    if let Some(uptime) = ap.uptime_s.filter(|u| *u < AP_RESTARTED_S) {
        out.push(ap_warning(
            "restarted",
            Severity::Info,
            json!({"uptime_s": uptime, "threshold_s": AP_RESTARTED_S}),
            json!({"uptime_s": uptime}),
        ));
    }
    if let Some(uplink) = ap.uplink_mbps.filter(|u| *u < AP_UPLINK_MIN_MBPS) {
        out.push(ap_warning(
            "uplink",
            Severity::Warn,
            json!({"uplink_mbps": uplink, "threshold_mbps": AP_UPLINK_MIN_MBPS}),
            json!({"uplink_mbps": uplink}),
        ));
    }
    out.sort_by_key(|f| f.severity);
    out
}
