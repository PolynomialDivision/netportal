//! Telemetry: the admins' views (`telemetry/admin.py`, INVENTORY 9.1.6, 9.12): the house's
//! overview, the APs, incidents, RADIUS rejects, and all source rows of one device. Admin-only
//! (the web checks); counts and lists from the registry, live AP load from Prometheus under the
//! page's budget.

use std::collections::{BTreeSet, HashMap};

use indexmap::IndexMap;
use jiff::tz::TimeZone;
use netportal_core::registry::{
    AcctSession, ApDay, AuthEvent, AuthFailure, ConnectionEvent, DeviceDay, DeviceRow, Incident, JobStatus, Person,
    RegistryError,
};
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

use super::Page;
use super::client::{Budget, CACHE_SECONDS, Unavailable};
use super::common::{
    ApRef, ap_info, ap_ref, band, fit, iso, iso_dt, label, mac_of, moment, normalise_mac, promql_string, trunc_int,
    unix, unix_opt,
};
use super::history::{local_day, to_civil_time};
use super::house::{House, empty_house, house_status};
use super::identity::{Identity, PublicConflict};
use super::live::{AP_CLIENTS, AP_INFO, AP_RADIO_UTIL, OK, Owner, UNAVAILABLE, ap_map};
use super::store::{Result, Store};
use super::timeline::{self as tl, ApMap};
use crate::diagnostics::{self, ApFacts, Finding, INCIDENT_MARGIN_S, INCIDENT_SPAN_MAX_S};

const LOG: &str = "netportal.telemetry";

pub const RECENT_INCIDENTS_S: f64 = 7.0 * 86400.0;
pub const RECENT_INCIDENTS_MAX: usize = 50;
pub const AUTH_RECENT: usize = 20;
/// `/api/admin/auth`: at most this many rows (`?limit=`), a span of at most 31 days.
pub const AUTH_LIMIT: i64 = 500;
pub const AUTH_MAX_SPAN_S: f64 = 31.0 * 86400.0;
/// `/api/admin/incidents`: at most this many, a span of at most 400 days.
pub const INCIDENT_LIMIT: usize = 1000;
pub const INCIDENT_MAX_SPAN_S: f64 = 400.0 * 86400.0;
/// RAW: rows per source, a span of at most 31 days.
pub const RAW_LIMIT_AUTH: i64 = 1000;
pub const RAW_LIMIT_ACCT: i64 = 1000;
pub const RAW_LIMIT_EVENTS: i64 = 2000;
pub const RAW_MAX_SPAN_S: f64 = 31.0 * 86400.0;
/// APS: the days of ap_day shown.
pub const AP_DAYS: i64 = 7;
/// Incident devices: at most this many per incident, for the incidents of the newest
/// [`DEVICES_SPAN_S`] of a list (each active device's events of that span: two registry queries
/// per device, however many incidents), at most [`DEVICES_INCIDENTS`] incidents.
pub const INCIDENT_DEVICES_MAX: usize = 200;
pub const DEVICES_SPAN_S: f64 = 7.0 * 86400.0;
pub const DEVICES_INCIDENTS: usize = 100;
pub const DROPOUT_LIMIT_UNIFI: i64 = 2000;
pub const DROPOUT_LIMIT_ACCT: i64 = 1000;

// --- the APs' queries (INVENTORY 9.3, A1-A7 with L22-L24) ---------------------------------------------

/// A1: clients per radio (all SSIDs).
pub const AP_RADIO_CLIENTS: &str = r#"sum by (name, radio) (unpoller_device_radio_stations{job="unifi"})"#;
/// A2: the radios' channels.
pub const AP_RADIO_CHANNEL: &str = r#"max by (name, radio) (unpoller_device_radio_channel{job="unifi"})"#;
/// A3: the APs' uptime.
pub const AP_UPTIME: &str = r#"max by (name) (unpoller_device_uptime_seconds{job="unifi",type="uap"})"#;
/// A4: the wired uplink.
pub const AP_UPLINK: &str = r#"min by (name) (unpoller_device_uplink_speed_mbps{job="unifi"})"#;
/// A5: the clients' average signal per AP (all SSIDs).
pub const AP_SIGNAL: &str =
    r#"avg by (ap_name) (max by (ap_name, mac) (unpoller_client_radio_signal_db{job="unifi"}))"#;
/// A6: the clients at -75 dBm or below per AP (`diagnostics::WEAK_SIGNAL_WARN_DBM`).
pub const AP_WEAK: &str =
    r#"count by (ap_name) (max by (ap_name, mac) (unpoller_client_radio_signal_db{job="unifi"}) <= -75)"#;
/// A7: the clients on the house's SSID per AP (`$SSID`: the literal).
pub const AP_HOUSE_CLIENTS: &str =
    r#"count by (ap_name) (max by (ap_name, mac) (unpoller_client_uptime_seconds{job="unifi",essid=$SSID}))"#;

// --- shapes -------------------------------------------------------------------------------------------

/// The devices that dropped out around an incident (lists only).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct IncidentDevices {
    /// `null`: not computed (older than [`DEVICES_SPAN_S`] before the newest one shown)
    pub devices: Option<Vec<IncidentDevice>>,
    pub devices_truncated: bool,
    pub devices_basis: &'static str,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct IncidentDevice {
    pub id: String,
    pub name: Option<String>,
    pub owner: Owner,
}

/// INCIDENT (INVENTORY 9.12).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PublicIncident {
    pub id: i64,
    pub kind: String,
    /// `""` for house-wide ones
    pub subject: String,
    pub subject_name: Option<String>,
    pub started: Option<String>,
    pub ended: Option<String>,
    pub open: bool,
    /// to now when open
    pub duration_s: i64,
    pub basis: String,
    pub detail: Value,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub attached: Option<IncidentDevices>,
}

pub fn public_incident(r: &Incident, now: f64) -> PublicIncident {
    let (started, ended) = (unix(r.started), unix_opt(r.ended));
    let end = ended.unwrap_or(now);
    PublicIncident {
        id: r.id,
        kind: r.kind.clone(),
        subject: r.subject.clone(),
        subject_name: r.subject_name.clone(),
        started: iso(Some(started)),
        ended: iso(ended),
        open: ended.is_none(),
        duration_s: trunc_int(end - started).unwrap_or(0),
        basis: r.basis.clone(),
        detail: r.detail.0.clone(),
        attached: None,
    }
}

/// JOB (INVENTORY 9.12).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PublicJob {
    pub name: String,
    pub last_success: Option<String>,
    pub last_attempt: Option<String>,
    pub last_error: Option<String>,
    pub duration_s: Option<f64>,
    /// no error and a success (or never attempted); a run in progress is no failure
    pub ok: bool,
    /// seconds since the last success (ETag-volatile)
    pub age_s: Option<i64>,
    pub cursor: Value,
}

pub fn public_job(r: &JobStatus, now: f64) -> PublicJob {
    let (success, attempt) = (unix_opt(r.last_success), unix_opt(r.last_attempt));
    PublicJob {
        name: r.name.clone(),
        last_success: iso(success),
        last_attempt: iso(attempt),
        last_error: r.last_error.clone(),
        duration_s: fit(r.duration_s, 2),
        ok: r.last_error.is_none() && (success.is_some() || attempt.is_none()),
        age_s: success.and_then(|s| trunc_int(now - s)),
        cursor: r.cursor.0.clone(),
    }
}

/// A radio of an AP.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Radio {
    pub radio: String,
    pub band: Option<&'static str>,
    pub channel: Option<i64>,
    pub clients: Option<i64>,
    pub channel_util: Option<f64>,
}

/// AP_DAY: an `ap_day` row (a house day).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PublicApDay {
    pub ap_mac: String,
    pub day: String,
    pub ap_name: Option<String>,
    pub clients_avg: Option<f64>,
    pub clients_max: Option<i32>,
    pub channel_util_avg: Value,
    pub weak_client_share: Option<f64>,
    pub restarts: Option<i32>,
    pub down_s: Option<i32>,
    pub computed: Option<String>,
}

fn public_ap_day(d: &ApDay) -> PublicApDay {
    PublicApDay {
        ap_mac: normalise_mac(&d.ap_mac).unwrap_or_else(|| d.ap_mac.clone()),
        day: netportal_core::conventions::date_iso(d.day),
        ap_name: d.ap_name.clone(),
        clients_avg: d.clients_avg,
        clients_max: d.clients_max,
        channel_util_avg: d.channel_util_avg.0.clone(),
        weak_client_share: d.weak_client_share,
        restarts: d.restarts,
        down_s: d.down_s,
        computed: d.computed_at.map(iso_dt),
    }
}

/// AP (OVERVIEW.aps, APS.aps; INVENTORY 9.12).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Ap {
    pub name: String,
    pub house: Option<String>,
    pub floor: Option<i64>,
    pub spot: Option<String>,
    pub mac: Option<String>,
    pub ip: Option<String>,
    pub model: Option<String>,
    /// `ok` (listed by unpoller) / `down` (an open ap_down incident) / `unknown`
    pub state: String,
    pub clients: Option<i64>,
    /// 0 when listed and none; null for APs only in the rollups
    pub clients_house: Option<i64>,
    pub weak_clients: Option<i64>,
    pub signal_avg_dbm: Option<f64>,
    pub uptime_s: Option<i64>,
    pub uplink_mbps: Option<i64>,
    pub radios: Vec<Radio>,
    pub open_incidents: Vec<PublicIncident>,
    pub warnings: Vec<&'static str>,
    pub warning_details: Vec<Finding>,
    /// APS only: 7 days of ap_day
    #[serde(skip_serializing_if = "Option::is_none")]
    pub days: Option<Vec<PublicApDay>>,
}

impl Ap {
    fn named(name: &str, listed: bool) -> Ap {
        let info = ap_info(Some(name));
        Ap {
            name: name.to_string(),
            house: info.as_ref().and_then(|i| i.house.clone()),
            floor: info.as_ref().and_then(|i| i.floor),
            spot: info.as_ref().and_then(|i| i.spot.clone()),
            mac: None,
            ip: None,
            model: None,
            state: "unknown".into(),
            clients: None,
            clients_house: listed.then_some(0),
            weak_clients: listed.then_some(0),
            signal_avg_dbm: None,
            uptime_s: None,
            uplink_mbps: None,
            radios: Vec::new(),
            open_incidents: Vec::new(),
            warnings: Vec::new(),
            warning_details: Vec::new(),
            days: None,
        }
    }

    fn facts(&self) -> ApFacts {
        ApFacts {
            state: self.state.clone(),
            clients: self.clients,
            weak_clients: self.weak_clients,
            uptime_s: self.uptime_s,
            uplink_mbps: self.uplink_mbps,
            utils: self.radios.iter().filter_map(|r| r.channel_util).collect(),
            open_incidents: self.open_incidents.iter().map(|i| i.id).collect(),
        }
    }
}

/// The AP's warnings (`diagnostics::ap_warnings`) set on it.
pub fn with_warnings(a: &mut Ap) {
    let details = diagnostics::ap_warnings(&a.facts());
    a.warnings = details.iter().map(|w| w.code).collect();
    a.warning_details = details;
}

/// `[AP]` now from unpoller (no incidents yet): one query per A-query, plus the house SSID's
/// clients per AP; sorted by (house, floor, name).
pub async fn ap_status(client: &Budget) -> std::result::Result<Vec<Ap>, Unavailable> {
    let info = client.vector(AP_INFO, None, CACHE_SECONDS).await?;
    let clients = client.vector(AP_CLIENTS, None, CACHE_SECONDS).await?;
    let radio_clients = client.vector(AP_RADIO_CLIENTS, None, CACHE_SECONDS).await?;
    let radio_util = client.vector(AP_RADIO_UTIL, None, CACHE_SECONDS).await?;
    let radio_channel = client.vector(AP_RADIO_CHANNEL, None, CACHE_SECONDS).await?;
    let uptime = client.vector(AP_UPTIME, None, CACHE_SECONDS).await?;
    let uplink = client.vector(AP_UPLINK, None, CACHE_SECONDS).await?;
    let signal = client.vector(AP_SIGNAL, None, CACHE_SECONDS).await?;
    let weak = client.vector(AP_WEAK, None, CACHE_SECONDS).await?;
    let house =
        client.vector(&AP_HOUSE_CLIENTS.replace("$SSID", &promql_string(client.ssid())?), None, CACHE_SECONDS).await?;
    let mut aps: IndexMap<String, Ap> = IndexMap::new();
    let mut radios: IndexMap<String, IndexMap<String, Radio>> = IndexMap::new();
    fn ap<'a>(aps: &'a mut IndexMap<String, Ap>, name: &str) -> &'a mut Ap {
        aps.entry(name.to_string()).or_insert_with(|| Ap::named(name, true))
    }
    for (labels, _) in &info {
        if let Some(name) = label(labels, "name").filter(|n| !n.is_empty()) {
            let a = ap(&mut aps, name);
            a.mac = label(labels, "mac").and_then(normalise_mac);
            a.ip = labels.get("ip").cloned();
            a.model = labels.get("model").cloned();
            a.state = "ok".into();
        }
    }
    for (rows, field) in [(&clients, 0), (&uptime, 1), (&uplink, 2)] {
        for (labels, value) in rows {
            if let (Some(name), Some(v)) = (label(labels, "name").filter(|n| !n.is_empty()), value) {
                let a = ap(&mut aps, name);
                let v = trunc_int(*v);
                match field {
                    0 => a.clients = v,
                    1 => a.uptime_s = v,
                    _ => a.uplink_mbps = v,
                }
            }
        }
    }
    for (labels, value) in &signal {
        if let (Some(name), Some(v)) = (label(labels, "ap_name").filter(|n| !n.is_empty()), value) {
            ap(&mut aps, name).signal_avg_dbm = fit(Some(*v), 1);
        }
    }
    for (labels, value) in &weak {
        if let (Some(name), Some(v)) = (label(labels, "ap_name").filter(|n| !n.is_empty()), value) {
            ap(&mut aps, name).weak_clients = trunc_int(*v);
        }
    }
    for (labels, value) in &house {
        if let (Some(name), Some(v)) = (label(labels, "ap_name").filter(|n| !n.is_empty()), value) {
            ap(&mut aps, name).clients_house = trunc_int(*v);
        }
    }
    for (rows, field) in [(&radio_clients, 0), (&radio_util, 1), (&radio_channel, 2)] {
        for (labels, value) in rows {
            let (Some(name), Some(radio)) =
                (label(labels, "name").filter(|n| !n.is_empty()), label(labels, "radio").filter(|r| !r.is_empty()))
            else {
                continue;
            };
            ap(&mut aps, name);
            let r = radios.entry(name.to_string()).or_default().entry(radio.to_string()).or_insert_with(|| Radio {
                radio: radio.to_string(),
                band: band(Some(radio)),
                channel: None,
                clients: None,
                channel_util: None,
            });
            match field {
                0 => r.clients = value.and_then(trunc_int),
                1 => r.channel_util = fit(*value, 3),
                _ => r.channel = value.and_then(trunc_int),
            }
        }
    }
    let mut out: Vec<Ap> = aps
        .into_values()
        .map(|mut a| {
            let mut rs: Vec<Radio> = radios.swap_remove(&a.name).map(|m| m.into_values().collect()).unwrap_or_default();
            rs.sort_by(|x, y| x.radio.cmp(&y.radio));
            a.radios = rs;
            a
        })
        .collect();
    out.sort_by(|a, b| {
        let key = |a: &Ap| (a.house.clone().unwrap_or_else(|| "~".into()), a.floor.unwrap_or(99), a.name.clone());
        key(a).cmp(&key(b))
    });
    Ok(out)
}

/// The APs with their open incidents (an open ap_down: state `down`) and warnings.
fn with_incidents(aps: &mut [Ap], open: &[&Incident], now: f64) {
    let mut by_subject: HashMap<String, Vec<&Incident>> = HashMap::new();
    for r in open.iter().filter(|r| r.kind.starts_with("ap_")) {
        by_subject.entry(r.subject.to_lowercase()).or_default().push(r);
        let name = r.subject_name.as_deref().unwrap_or_default().to_lowercase();
        by_subject.entry(format!("name:{name}")).or_default().push(r);
    }
    for a in aps.iter_mut() {
        let by_mac = by_subject.get(&a.mac.clone().unwrap_or_default().to_lowercase()).filter(|r| !r.is_empty());
        let rows =
            by_mac.or_else(|| by_subject.get(&format!("name:{}", a.name.to_lowercase()))).cloned().unwrap_or_default();
        a.open_incidents = rows.iter().map(|r| public_incident(r, now)).collect();
        if rows.iter().any(|r| r.kind == "ap_down") {
            a.state = "down".into();
        }
        with_warnings(a);
    }
}

/// AUTH_FAILURE (INVENTORY 9.12).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PublicFailure {
    pub at: Option<String>,
    pub reason: String,
    pub serial: Option<String>,
    pub device_id: Option<String>,
    pub device_name: Option<String>,
    pub owner: Option<Owner>,
    pub mac: Option<String>,
    pub bssid: Option<String>,
    pub ssid: Option<String>,
    pub nas_ip: Option<String>,
    /// only `/api/admin/auth` places the reject at its AP
    pub ap: Option<ApRef>,
    /// the tries this row stands for (repeats within 60 s are one row)
    pub count: i64,
    pub last_at: Option<String>,
}

/// The rejects these rows stand for: a row of repeated tries counts its tries.
pub fn tries(rows: &[AuthFailure]) -> i64 {
    rows.iter().map(|r| i64::from(r.tries.max(1))).sum()
}

/// `{reason: tries}`.
pub fn by_reason(rows: &[AuthFailure]) -> IndexMap<String, i64> {
    let mut counts = IndexMap::new();
    for r in rows {
        let reason = if r.reason.is_empty() { "other".to_string() } else { r.reason.clone() };
        *counts.entry(reason).or_default() += i64::from(r.tries.max(1));
    }
    counts
}

/// AUTH_FAILURE rows, newest first. `names`: device names for rows without one.
pub fn public_failures(
    rows: &[AuthFailure],
    people: &IndexMap<String, Person>,
    names: &HashMap<Uuid, String>,
    aps: Option<&ApMap>,
) -> Vec<PublicFailure> {
    let mut sorted: Vec<&AuthFailure> = rows.iter().collect();
    sorted.sort_by_key(|r| std::cmp::Reverse(r.at));
    sorted
        .into_iter()
        .map(|r| {
            let owner = r.owner.as_ref().and_then(|o| people.get(o)).map(|p| Owner::of(Some(p)));
            let bssid = mac_of(r.bssid.as_deref());
            let ap = aps.and_then(|aps| {
                let (name, ap_mac, _) = aps.by_bssid(bssid.as_deref(), r.nas_ip.as_deref());
                ap_ref(name.as_deref(), ap_mac.as_deref())
            });
            PublicFailure {
                at: Some(iso_dt(r.at)),
                reason: r.reason.clone(),
                serial: r.serial.clone(),
                device_id: r.device_id.map(|d| d.to_string()),
                device_name: r.device_id.and_then(|d| r.device_name.clone().or_else(|| names.get(&d).cloned())),
                owner,
                mac: mac_of(r.mac.as_deref()),
                bssid,
                ssid: r.ssid.clone(),
                nas_ip: r.nas_ip.clone(),
                ap,
                count: i64::from(r.tries.max(1)),
                last_at: r.last_at.map(iso_dt),
            }
        })
        .collect()
}

/// A section of the overview failed (a table a migration has not made yet, a query error): logged
/// without rows, the transaction rolled back so the next section works.
async fn section_failed<S: Store>(store: &mut S, name: &str, e: &RegistryError) {
    let kind = match e {
        RegistryError::Db(_) => "database",
        RegistryError::Migrate(_) => "migration",
        RegistryError::Invalid(_) => "invalid",
        RegistryError::Conflict(_) => "conflict",
    };
    tracing::warn!(target: LOG, "admin overview: {name} failed ({kind})");
    let _ = store.rollback().await;
}

// --- overview -----------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct IncidentsSummary {
    pub available: bool,
    /// newest start first
    pub open: Vec<PublicIncident>,
    /// ended in 7 days, newest start first, at most 50
    pub recent: Vec<PublicIncident>,
    /// over all rows overlapping 7 days
    pub counts_7d: IndexMap<String, i64>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AuthSummary {
    pub available: bool,
    pub since: Option<String>,
    /// tries (repeats included)
    pub count: i64,
    /// rows at the limit
    pub truncated: bool,
    pub by_reason: IndexMap<String, i64>,
    /// distinct devices
    pub devices: usize,
    /// distinct MACs
    pub macs: usize,
    /// the newest 20
    pub recent: Vec<PublicFailure>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Freshness {
    pub wifi_data_age_s: Option<i64>,
    pub prometheus: &'static str,
    /// all jobs ok (`null` without jobs)
    pub jobs_ok: Option<bool>,
    pub oldest_job_success_age_s: Option<i64>,
}

/// OVERVIEW (`/api/admin/overview`, the admin page's `overview`).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Overview {
    pub generated_at: Option<String>,
    pub telemetry: &'static str,
    pub stale: bool,
    /// empty when Prometheus does not answer
    pub house: House,
    pub incidents: IncidentsSummary,
    /// `[]` unless telemetry ok
    pub aps: Vec<Ap>,
    pub auth: AuthSummary,
    /// a list (not a map: a template would read `.items` as the method)
    pub jobs: Vec<PublicJob>,
    pub jobs_available: bool,
    pub freshness: Freshness,
}

/// The overview. Each registry section that fails is unavailable alone (logged, rolled back).
pub async fn overview<S: Store>(page: &Page, store: &mut S, now: f64) -> Overview {
    let mut telemetry = page.telemetry();
    let (mut house, mut aps) = (empty_house(), Vec::new());
    if let Some(client) = page.budget.as_ref() {
        let asked = async { Ok::<_, Unavailable>((house_status(client).await?, ap_status(client).await?)) };
        match asked.await {
            Ok((h, a)) => (house, aps) = (h, a),
            Err(_) => telemetry = UNAVAILABLE,
        }
    }
    let (mut incidents, open_rows, shown_rows) = match incidents_summary(store, now).await {
        Ok(found) => found,
        Err(e) => {
            section_failed(store, "incidents", &e).await;
            let fallback =
                IncidentsSummary { available: false, open: Vec::new(), recent: Vec::new(), counts_7d: IndexMap::new() };
            (fallback, Vec::new(), Vec::new())
        }
    };
    let open: Vec<&Incident> = open_rows.iter().collect();
    with_incidents(&mut aps, &open, now);
    if !shown_rows.is_empty() {
        let map = if page.budget.is_some() { Some(ap_map(page).await) } else { None };
        let mut public: Vec<PublicIncident> =
            incidents.open.iter().cloned().chain(incidents.recent.iter().cloned()).collect();
        let shown: Vec<&Incident> = shown_rows.iter().collect();
        match attach_devices(&mut public, &shown, store, now, map.as_ref()).await {
            Ok(()) => {
                let n = incidents.open.len();
                incidents.recent = public.split_off(n);
                incidents.open = public;
            }
            Err(e) => {
                section_failed(store, "incident devices", &e).await;
                let unknown =
                    || Some(IncidentDevices { devices: None, devices_truncated: false, devices_basis: "inferred" });
                for p in incidents.open.iter_mut().chain(incidents.recent.iter_mut()) {
                    p.attached = unknown();
                }
            }
        }
    }
    let auth = match auth_summary(store, now).await {
        Ok(auth) => auth,
        Err(e) => {
            section_failed(store, "auth", &e).await;
            AuthSummary {
                available: false,
                since: iso(Some(now - 86400.0)),
                count: 0,
                truncated: false,
                by_reason: IndexMap::new(),
                devices: 0,
                macs: 0,
                recent: Vec::new(),
            }
        }
    };
    let jobs = match store.job_status().await {
        Ok(rows) => Some(rows.iter().map(|r| public_job(r, now)).collect::<Vec<_>>()),
        Err(e) => {
            section_failed(store, "jobs", &e).await;
            None
        }
    };
    let jobs_available = jobs.is_some();
    let jobs = jobs.unwrap_or_default();
    let oldest = jobs.iter().filter_map(|j| j.age_s).max();
    let stale = telemetry == OK && diagnostics::is_stale(house.wifi_data_age_s);
    Overview {
        generated_at: iso(Some(now)),
        telemetry,
        stale,
        freshness: Freshness {
            wifi_data_age_s: house.wifi_data_age_s,
            prometheus: telemetry,
            jobs_ok: (!jobs.is_empty()).then(|| jobs.iter().all(|j| j.ok)),
            oldest_job_success_age_s: oldest,
        },
        house,
        incidents,
        aps,
        auth,
        jobs,
        jobs_available,
    }
}

fn newest_first(rows: &mut [&Incident]) {
    rows.sort_by_key(|r| std::cmp::Reverse(r.started));
}

/// The overview's incidents, the open rows (for the APs) and the rows shown (open + recent).
async fn incidents_summary<S: Store>(
    store: &mut S,
    now: f64,
) -> Result<(IncidentsSummary, Vec<Incident>, Vec<Incident>)> {
    let rows = store.incidents(moment(now - RECENT_INCIDENTS_S), Some(moment(now)), None).await?;
    let mut counts: IndexMap<String, i64> = IndexMap::new();
    for r in &rows {
        *counts.entry(r.kind.clone()).or_default() += 1;
    }
    let open_rows: Vec<Incident> = rows.iter().filter(|r| r.ended.is_none()).cloned().collect();
    let mut open: Vec<&Incident> = open_rows.iter().collect();
    newest_first(&mut open);
    let mut recent: Vec<&Incident> = rows.iter().filter(|r| r.ended.is_some()).collect();
    newest_first(&mut recent);
    recent.truncate(RECENT_INCIDENTS_MAX);
    let shown: Vec<Incident> = open.iter().chain(recent.iter()).map(|r| (*r).clone()).collect();
    let summary = IncidentsSummary {
        available: true,
        open: open.iter().map(|r| public_incident(r, now)).collect(),
        recent: recent.iter().map(|r| public_incident(r, now)).collect(),
        counts_7d: counts,
    };
    Ok((summary, open_rows, shown))
}

async fn auth_summary<S: Store>(store: &mut S, now: f64) -> Result<AuthSummary> {
    let rows = store.auth_failures(moment(now - 86400.0), Some(moment(now)), AUTH_LIMIT).await?;
    let people = store.people().await?;
    let mut events = public_failures(&rows, &people, &HashMap::new(), None);
    events.truncate(AUTH_RECENT);
    Ok(AuthSummary {
        available: true,
        since: iso(Some(now - 86400.0)),
        count: tries(&rows),
        truncated: rows.len() as i64 >= AUTH_LIMIT,
        by_reason: by_reason(&rows),
        devices: rows.iter().filter_map(|r| r.device_id).collect::<BTreeSet<_>>().len(),
        macs: rows.iter().filter_map(|r| r.mac.clone()).collect::<BTreeSet<_>>().len(),
        recent: events,
    })
}

// --- the other admin endpoints ---------------------------------------------------------------------------

/// APS (`/api/admin/aps`).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Aps {
    pub generated_at: Option<String>,
    pub telemetry: &'static str,
    pub aps: Vec<Ap>,
}

/// APS: the APs now (Prometheus, the page's budget) and those only in the rollups, with their
/// open incidents and the last [`AP_DAYS`] house days of `ap_day` (days in the house's zone `tz`,
/// as the rollup writes them).
pub async fn aps<S: Store>(page: &Page, store: &mut S, now: f64, tz: &TimeZone) -> Result<Aps> {
    let mut telemetry = page.telemetry();
    let mut items = Vec::new();
    if let Some(client) = page.budget.as_ref() {
        match ap_status(client).await {
            Ok(found) => items = found,
            Err(_) => telemetry = UNAVAILABLE,
        }
    }
    let rows = store.incidents(moment(now - RECENT_INCIDENTS_S), Some(moment(now)), None).await?;
    let open: Vec<&Incident> = rows.iter().filter(|r| r.ended.is_none()).collect();
    let today = local_day(now.floor() as i64, tz);
    let first = today.checked_sub(jiff::Span::new().days(AP_DAYS - 1)).unwrap_or(today);
    let days = store.ap_days(to_civil_time(first), to_civil_time(today)).await?;
    let mut by_ap: IndexMap<String, Vec<PublicApDay>> = IndexMap::new();
    for d in &days {
        let day = public_ap_day(d);
        by_ap.entry(day.ap_mac.clone()).or_default().push(day);
    }
    let known: BTreeSet<String> = items.iter().filter_map(|a| a.mac.clone()).collect();
    // APs that unpoller does not list now (a down one among them)
    for (mac, rows) in &by_ap {
        if !known.contains(mac) {
            let name =
                rows.last().and_then(|d| d.ap_name.clone()).filter(|n| !n.is_empty()).unwrap_or_else(|| mac.clone());
            let mut a = Ap::named(&name, false);
            a.mac = Some(mac.clone());
            items.push(a);
        }
    }
    with_incidents(&mut items, &open, now);
    for a in items.iter_mut() {
        let mut days = a.mac.as_ref().and_then(|m| by_ap.get(m)).cloned().unwrap_or_default();
        days.sort_by(|x, y| x.day.cmp(&y.day));
        a.days = Some(days);
    }
    Ok(Aps { generated_at: iso(Some(now)), telemetry, aps: items })
}

/// INCIDENTS (`/api/admin/incidents`).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Incidents {
    pub from: Option<String>,
    pub to: Option<String>,
    pub kind: Option<String>,
    /// newest start first, at most [`INCIDENT_LIMIT`]
    pub incidents: Vec<PublicIncident>,
    pub truncated: bool,
    /// `{kind: n}` over every row of the span
    pub counts: IndexMap<String, i64>,
}

/// INCIDENTS between `since` and `until` (Unix), newest first, with the devices that dropped out
/// (the page's AP map places accounting rows at their AP; without Prometheus AP incidents match
/// UniFi events only).
pub async fn incidents<S: Store>(
    page: &Page,
    store: &mut S,
    since: f64,
    until: f64,
    kind: Option<&str>,
    now: f64,
) -> Result<Incidents> {
    incidents_bounded(page, store, since, until, kind, now, INCIDENT_DEVICES_MAX, DEVICES_SPAN_S).await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn incidents_bounded<S: Store>(
    page: &Page,
    store: &mut S,
    since: f64,
    until: f64,
    kind: Option<&str>,
    now: f64,
    devices_max: usize,
    devices_span_s: f64,
) -> Result<Incidents> {
    let kinds: Option<Vec<&str>> = kind.map(|k| vec![k]);
    let rows = store.incidents(moment(since), Some(moment(until)), kinds.as_deref()).await?;
    let mut counts: IndexMap<String, i64> = IndexMap::new();
    for r in &rows {
        *counts.entry(r.kind.clone()).or_default() += 1;
    }
    let mut sorted: Vec<&Incident> = rows.iter().collect();
    newest_first(&mut sorted);
    let truncated = sorted.len() > INCIDENT_LIMIT;
    sorted.truncate(INCIDENT_LIMIT);
    let mut public: Vec<PublicIncident> = sorted.iter().map(|r| public_incident(r, now)).collect();
    let map = if page.budget.is_some() { Some(ap_map(page).await) } else { None };
    attach_bounded(&mut public, &sorted, store, now, map.as_ref(), devices_max, devices_span_s).await?;
    Ok(Incidents {
        from: iso(Some(since)),
        to: iso(Some(until)),
        kind: kind.map(str::to_string),
        incidents: public,
        truncated,
        counts,
    })
}

/// `(from, to)` Unix in which a device's drop-out counts for the incident.
pub fn incident_window(r: &Incident, now: f64) -> (f64, f64) {
    let started = unix(r.started);
    let end = unix_opt(r.ended).unwrap_or(now).min(started + INCIDENT_SPAN_MAX_S);
    (started - INCIDENT_MARGIN_S, end + INCIDENT_MARGIN_S)
}

/// A device's drop-out (UniFi disconnect, accounting Stop, reconnect).
#[derive(Debug, Clone)]
pub struct Dropout {
    pub at: f64,
    pub device: DeviceRow,
    pub ap_mac: Option<String>,
    pub ap: Option<String>,
}

/// Every active device's drop-outs in `[since, until]`, two registry queries per device.
pub async fn dropouts<S: Store>(store: &mut S, since: f64, until: f64, aps: Option<&ApMap>) -> Result<Vec<Dropout>> {
    let (s, u) = (moment(since), moment(until));
    let empty = ApMap::default();
    let aps = aps.unwrap_or(&empty);
    let mut out = Vec::new();
    for d in store.devices(false).await? {
        let unifi = store.connection_events(d.id, s, u, DROPOUT_LIMIT_UNIFI).await?;
        let acct = store.acct_sessions(d.id, s, u, DROPOUT_LIMIT_ACCT).await?;
        let mut events = tl::from_unifi(&unifi, aps);
        events.extend(tl::from_acct(&acct, aps));
        for e in events {
            if tl::DISCONNECT_KINDS.contains(&e.kind) && since <= e.at && e.at <= until {
                out.push(Dropout { at: e.at, device: d.clone(), ap_mac: e.ap_mac, ap: e.ap });
            }
        }
    }
    Ok(out)
}

/// A drop-out concerns the incident: house-wide kinds all, an AP's its own clients, a switch's
/// the clients of the APs its detail lists.
fn concerns(r: &Incident, drop: &Dropout) -> bool {
    let subject = r.subject.to_lowercase();
    let name = r.subject_name.as_deref().unwrap_or_default().to_lowercase();
    if r.kind.starts_with("ap_") {
        return drop.ap_mac.as_ref().is_some_and(|m| *m == subject)
            || (!name.is_empty() && drop.ap.as_ref().is_some_and(|a| a.to_lowercase() == name));
    }
    if r.kind.starts_with("switch") {
        let listed: BTreeSet<String> = r
            .detail
            .0
            .get("ap_macs")
            .and_then(Value::as_array)
            .map(|l| l.iter().filter_map(|m| m.as_str().and_then(normalise_mac)).collect())
            .unwrap_or_default();
        return drop.ap_mac.as_ref().is_some_and(|m| listed.contains(m));
    }
    subject.is_empty()
}

/// INCIDENT.devices (in place) for the incidents of the newest [`DEVICES_SPAN_S`] (at most
/// [`DEVICES_INCIDENTS`] of them); the older ones get `null` (not computed).
pub async fn attach_devices<S: Store>(
    public: &mut [PublicIncident],
    rows: &[&Incident],
    store: &mut S,
    now: f64,
    aps: Option<&ApMap>,
) -> Result<()> {
    attach_bounded(public, rows, store, now, aps, INCIDENT_DEVICES_MAX, DEVICES_SPAN_S).await
}

async fn attach_bounded<S: Store>(
    public: &mut [PublicIncident],
    rows: &[&Incident],
    store: &mut S,
    now: f64,
    aps: Option<&ApMap>,
    devices_max: usize,
    devices_span_s: f64,
) -> Result<()> {
    if rows.is_empty() {
        return Ok(());
    }
    let windows: Vec<(f64, f64)> = rows.iter().map(|r| incident_window(r, now)).collect();
    let newest = windows.iter().map(|w| w.1).fold(f64::NEG_INFINITY, f64::max);
    let chosen: Vec<usize> =
        (0..windows.len()).filter(|&i| windows[i].1 >= newest - devices_span_s).take(DEVICES_INCIDENTS).collect();
    for p in public.iter_mut() {
        p.attached = Some(IncidentDevices { devices: None, devices_truncated: false, devices_basis: "inferred" });
    }
    if chosen.is_empty() {
        return Ok(());
    }
    let lo = chosen.iter().map(|&i| windows[i].0).fold(f64::INFINITY, f64::min);
    let hi = chosen.iter().map(|&i| windows[i].1).fold(f64::NEG_INFINITY, f64::max);
    let drops = dropouts(store, lo, hi, aps).await?;
    let people = store.people().await?;
    for &i in &chosen {
        let (a, b) = windows[i];
        let mut found: IndexMap<Uuid, &DeviceRow> = IndexMap::new();
        for x in drops.iter().filter(|x| a <= x.at && x.at <= b && concerns(rows[i], x)) {
            found.entry(x.device.id).or_insert(&x.device);
        }
        let mut devices: Vec<(&Uuid, &&DeviceRow)> = found.iter().collect();
        devices.sort_by(|x, y| x.1.name.cmp(&y.1.name).then_with(|| x.0.to_string().cmp(&y.0.to_string())));
        let truncated = devices.len() > devices_max;
        let list: Vec<IncidentDevice> = devices
            .into_iter()
            .take(devices_max)
            .map(|(id, d)| IncidentDevice {
                id: id.to_string(),
                name: Some(d.name.clone()),
                owner: Owner::of(people.get(&d.owner)),
            })
            .collect();
        if let Some(p) = public.get_mut(i) {
            p.attached =
                Some(IncidentDevices { devices: Some(list), devices_truncated: truncated, devices_basis: "inferred" });
        }
    }
    Ok(())
}

/// AUTH (`/api/admin/auth`).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Auth {
    pub from: Option<String>,
    pub to: Option<String>,
    pub result: &'static str,
    pub events: Vec<PublicFailure>,
    pub truncated: bool,
    pub by_reason: IndexMap<String, i64>,
}

/// AUTH: the RADIUS rejects between `since` and `until` (Unix), newest first, placed at their AP.
pub async fn auth<S: Store>(page: &Page, store: &mut S, since: f64, until: f64, limit: i64) -> Result<Auth> {
    let rows = store.auth_failures(moment(since), Some(moment(until)), limit).await?;
    // the registry names the device; rows without a name: the registry's list
    let names: HashMap<Uuid, String> = if rows.iter().any(|r| r.device_id.is_some() && r.device_name.is_none()) {
        store.devices(true).await?.into_iter().map(|d| (d.id, d.name)).collect()
    } else {
        HashMap::new()
    };
    let map = if page.budget.is_some() { Some(ap_map(page).await) } else { None };
    let people = store.people().await?;
    Ok(Auth {
        from: iso(Some(since)),
        to: iso(Some(until)),
        result: "reject",
        events: public_failures(&rows, &people, &names, map.as_ref()),
        truncated: rows.len() as i64 >= limit,
        by_reason: by_reason(&rows),
    })
}

// --- RAW --------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RawDevice {
    pub id: String,
    pub name: String,
    pub revoked: bool,
    pub owner: Owner,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RawWindow {
    pub mac: String,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub randomized: bool,
    pub auth_count: Option<i64>,
    pub current: bool,
    pub start: Option<String>,
    /// `null`: open
    pub end: Option<String>,
}

/// A RADIUS decision row (`registry::auth_events`).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RawAuth {
    pub at: Option<String>,
    pub result: String,
    pub reason: String,
    pub mac: Option<String>,
    pub bssid: Option<String>,
    pub ssid: Option<String>,
    pub nas_ip: Option<String>,
    /// how the row is the device's: `device` (its certificate) or `mac`
    #[serde(rename = "match")]
    pub matched: String,
    /// the tries of the row
    pub count: i64,
    pub last_at: Option<String>,
}

/// An accounting session row (`registry::acct_sessions`).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RawAcct {
    pub nas_ip: String,
    pub acct_session_id: String,
    pub link: String,
    pub mac: Option<String>,
    pub bssid: Option<String>,
    pub ssid: Option<String>,
    pub framed_ip: Option<String>,
    pub started: Option<String>,
    pub updated: Option<String>,
    pub stopped: Option<String>,
    pub session_time_s: Option<i64>,
    pub input_octets: Option<i64>,
    pub output_octets: Option<i64>,
    pub terminate_cause: Option<String>,
    pub interim_s: Option<i32>,
}

/// A connection event row (`registry::connection_events`).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RawEvent {
    pub at: Option<String>,
    pub kind: String,
    pub source: String,
    pub mac: String,
    pub ap_mac: Option<String>,
    pub ap_name: Option<String>,
    pub from_ap_mac: Option<String>,
    pub from_ap_name: Option<String>,
    pub ssid: Option<String>,
    pub radio: Option<String>,
    pub channel: Option<i32>,
    pub rssi: Option<i32>,
    pub duration_s: Option<i64>,
    pub rx_bytes: Option<i64>,
    pub tx_bytes: Option<i64>,
    pub detail: Value,
}

/// A device_day row.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RawDay {
    pub device_id: String,
    pub day: String,
    pub online_s: Option<i32>,
    pub stale_s: Option<i32>,
    pub signal_avg_dbm: Option<f64>,
    pub signal_p10_dbm: Option<f64>,
    pub snr_avg_db: Option<f64>,
    pub health_avg: Option<f64>,
    pub health_min: Option<f64>,
    pub retry_ratio_avg: Option<f64>,
    pub rx_bytes: Option<i64>,
    pub tx_bytes: Option<i64>,
    pub link_rx_avg_bps: Option<f64>,
    pub roams: Option<i32>,
    pub reconnects: Option<i32>,
    pub disconnects: Option<i32>,
    pub aps: Value,
    pub bands: Value,
    pub macs: Option<i32>,
    pub auth_ok: Option<i32>,
    pub auth_failed: Option<i32>,
    pub computed: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RawLimits {
    pub auth: i64,
    pub acct: i64,
    pub events: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RawTruncated {
    pub auth: bool,
    pub acct: bool,
    pub events: bool,
}

/// RAW (`/api/admin/devices/<id>/raw`): every source row of one device in `[since, until]`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Raw {
    pub device: RawDevice,
    pub from: Option<String>,
    pub to: Option<String>,
    pub windows: Vec<RawWindow>,
    pub conflicts: Vec<PublicConflict>,
    pub auth: Vec<RawAuth>,
    pub acct: Vec<RawAcct>,
    pub events: Vec<RawEvent>,
    pub days: Vec<RawDay>,
    /// every incident of the span (the house's context, not only the device's)
    pub incidents: Vec<PublicIncident>,
    pub limits: RawLimits,
    pub truncated: RawTruncated,
}

fn raw_auth(r: &AuthEvent) -> RawAuth {
    RawAuth {
        at: Some(iso_dt(r.at)),
        result: r.result.clone(),
        reason: r.reason.clone(),
        mac: r.mac.clone(),
        bssid: r.bssid.clone(),
        ssid: r.ssid.clone(),
        nas_ip: r.nas_ip.clone(),
        matched: r.matched.clone(),
        count: i64::from(r.tries),
        last_at: r.last_at.map(iso_dt),
    }
}

fn raw_acct(r: &AcctSession) -> RawAcct {
    RawAcct {
        nas_ip: r.nas_ip.clone(),
        acct_session_id: r.acct_session_id.clone(),
        link: r.link.clone(),
        mac: r.mac.clone(),
        bssid: r.bssid.clone(),
        ssid: r.ssid.clone(),
        framed_ip: r.framed_ip.clone(),
        started: r.started.map(iso_dt),
        updated: Some(iso_dt(r.updated)),
        stopped: r.stopped.map(iso_dt),
        session_time_s: r.session_time_s,
        input_octets: r.input_octets,
        output_octets: r.output_octets,
        terminate_cause: r.terminate_cause.clone(),
        interim_s: r.interim_s,
    }
}

fn raw_event(r: &ConnectionEvent) -> RawEvent {
    RawEvent {
        at: Some(iso_dt(r.at)),
        kind: r.kind.clone(),
        source: r.source.clone(),
        mac: r.mac.clone(),
        ap_mac: r.ap_mac.clone(),
        ap_name: r.ap_name.clone(),
        from_ap_mac: r.from_ap_mac.clone(),
        from_ap_name: r.from_ap_name.clone(),
        ssid: r.ssid.clone(),
        radio: r.radio.clone(),
        channel: r.channel,
        rssi: r.rssi,
        duration_s: r.duration_s,
        rx_bytes: r.rx_bytes,
        tx_bytes: r.tx_bytes,
        detail: r.detail.0.clone(),
    }
}

fn raw_day(r: &DeviceDay) -> RawDay {
    RawDay {
        device_id: r.device_id.to_string(),
        day: netportal_core::conventions::date_iso(r.day),
        online_s: r.online_s,
        stale_s: r.stale_s,
        signal_avg_dbm: r.signal_avg_dbm,
        signal_p10_dbm: r.signal_p10_dbm,
        snr_avg_db: r.snr_avg_db,
        health_avg: r.health_avg,
        health_min: r.health_min,
        retry_ratio_avg: r.retry_ratio_avg,
        rx_bytes: r.rx_bytes,
        tx_bytes: r.tx_bytes,
        link_rx_avg_bps: r.link_rx_avg_bps,
        roams: r.roams,
        reconnects: r.reconnects,
        disconnects: r.disconnects,
        aps: r.aps.0.clone(),
        bands: r.bands.0.clone(),
        macs: r.macs,
        auth_ok: r.auth_ok,
        auth_failed: r.auth_failed,
        computed: r.computed_at.map(iso_dt),
    }
}

/// RAW: every source row of one device in `[since, until]` (Unix), bounded per source; its
/// `device_day` rows of the house days (in `tz`) the span touches.
#[allow(clippy::too_many_arguments)]
pub async fn raw<S: Store>(
    store: &mut S,
    row: &DeviceRow,
    identity: &Identity,
    since: f64,
    until: f64,
    people: &IndexMap<String, Person>,
    tz: &TimeZone,
    now: f64,
) -> Result<Raw> {
    let (s, u) = (moment(since), moment(until));
    let auth_rows = store.auth_events(row.id, s, u, RAW_LIMIT_AUTH).await?;
    let acct_rows = store.acct_sessions(row.id, s, u, RAW_LIMIT_ACCT).await?;
    let event_rows = store.connection_events(row.id, s, u, RAW_LIMIT_EVENTS).await?;
    let first_day = to_civil_time(local_day(since.floor() as i64, tz));
    let last_day = to_civil_time(local_day(until.floor() as i64, tz));
    let days = store.device_days(row.id, first_day, last_day).await?;
    let incidents = store.incidents(s, Some(u), None).await?;
    let windows = identity
        .windows
        .iter()
        .map(|w| RawWindow {
            mac: w.mac.clone(),
            first_seen: iso(Some(w.first_seen)),
            last_seen: iso(Some(w.last_seen)),
            randomized: w.randomized,
            auth_count: w.auth_count,
            current: w.current,
            start: iso(Some(w.start).filter(|s| s.is_finite())),
            end: iso(w.end),
        })
        .collect();
    Ok(Raw {
        device: RawDevice {
            id: row.id.to_string(),
            name: row.name.clone(),
            revoked: row.revoked_at.is_some(),
            owner: Owner::of(people.get(&row.owner)),
        },
        from: iso(Some(since)),
        to: iso(Some(until)),
        windows,
        conflicts: identity.public_conflicts(),
        auth: auth_rows.iter().map(raw_auth).collect(),
        acct: acct_rows.iter().map(raw_acct).collect(),
        events: event_rows.iter().map(raw_event).collect(),
        days: days.iter().map(raw_day).collect(),
        incidents: incidents.iter().map(|r| public_incident(r, now)).collect(),
        limits: RawLimits { auth: RAW_LIMIT_AUTH, acct: RAW_LIMIT_ACCT, events: RAW_LIMIT_EVENTS },
        truncated: RawTruncated {
            auth: auth_rows.len() as i64 >= RAW_LIMIT_AUTH,
            acct: acct_rows.len() as i64 >= RAW_LIMIT_ACCT,
            events: event_rows.len() as i64 >= RAW_LIMIT_EVENTS,
        },
    })
}
