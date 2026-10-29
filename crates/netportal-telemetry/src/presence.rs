//! Device presence (Python `netportal/presence.py`, INVENTORY 9.7): ONE state per device from
//! every source. Every place that says online/offline (DEVICE.state, last_seen and since, the
//! offline and stale_data findings, the admin list and its counts) reads [`decide`]; nothing else
//! derives a state. It is not a stored state machine: each request decides from the evidence;
//! "transitions" are which rule fires first.
//!
//! Sources (each item is evidence with a time; the newest authoritative one wins):
//! - association (Prometheus/unpoller): present or absent at the snapshot time Ts (scrape time -
//!   unpoller's cache age), with the association start. Fresh only while the snapshot is not
//!   older than `diagnostics::STALE_AFTER_S`; a frozen snapshot is no evidence at all.
//! - sessions (radius_acct, linked to the device by the login's Class or the MAC window, never by
//!   the MAC alone): started, updated (Start/Interim), stopped, cause. A Stop ends only its own
//!   session. An open session is alive while `now - updated <= stale_after = 2 x interval +`
//!   [`STALE_GRACE_S`], interval = the session's measured one, else its NAS's, else the
//!   configured `NETPORTAL_ACCT_INTERIM_S`, clamped ([`interval`]). An open ap_down incident of
//!   its AP (no update since the incident began) makes it not count either.
//! - the latest login (the latest Access-Accept).
//! - UniFi's system log (connection_event): connected / disconnected / roamed, 2-10 min late.
//!
//! Decision ([`decide`]), in order:
//! 1. Evidence newer than Ts decides (all of it when Ts is not fresh); a Start or a Stop counts as
//!    newer when it is within [`CONTROLLER_LAG_S`] before Ts, an Interim must be newer than Ts.
//!    a. an alive session whose Start or Interim is newer -> online (acct_start / acct_interim;
//!    sources_disagree when a fresh snapshot keeps not listing an old session);
//!    b. a login less than [`CONNECTING_S`] old, newer than every session's start and stop, no
//!    alive session and no fresh association -> connecting (accept_pending);
//!    c. no alive session and the newest session stopped after Ts (or a fresh snapshot still
//!    lists an association from before that Stop) -> offline (acct_stop; ap_down when the AP
//!    itself ended it);
//!    d. a UniFi disconnect newer than Ts and than every session's and login's time, no alive
//!    session -> offline (unifi_disconnect).
//! 2. Otherwise a fresh snapshot: present -> online (association); absent -> offline
//!    (association_gone).
//! 3. No fresh snapshot: the newest session open on an AP with an open ap_down incident ->
//!    offline (inferred, ap_down); else unknown (session_stale when the newest session went
//!    silent, telemetry_unavailable otherwise). Missing evidence is never "offline".
//! 4. A resident's device whose current MAC is in a conflict now -> unknown (mac_conflict), no
//!    evidence shown. No MAC, no session and no login: never_connected.
//!
//! Duplicates and reordered packets: only event times are compared, never arrival order.

use std::cmp::Ordering;
use std::collections::HashMap;

use indexmap::IndexMap;
use netportal_core::registry::{Incident, LatestEvent, LatestSession, RegistryError};
use netportal_core::registry::{PRESENCE_EVENTS, PRESENCE_SESSIONS};
use serde::Serialize;
use uuid::Uuid;

use crate::telemetry::common::{ApRef, ap_ref, iso, mac_of, normalise_mac, unix, unix_opt};
use crate::telemetry::identity::Identity;
use crate::telemetry::store::Store;
use crate::telemetry::timeline::{ApMap, Basis};

pub const ONLINE: &str = "online";
pub const CONNECTING: &str = "connecting";
pub const OFFLINE: &str = "offline";
pub const UNKNOWN: &str = "unknown";
pub const NEVER: &str = "never_connected";
pub const STATES: [&str; 5] = [ONLINE, CONNECTING, OFFLINE, UNKNOWN, NEVER];

/// A login without an accounting Start yet is "connecting" this long.
pub const CONNECTING_S: f64 = 60.0;
/// The UniFi controller's delay in listing a new association or dropping a gone one, beyond
/// the snapshot time; RADIUS Starts and Stops this much before Ts still count as newer.
pub const CONTROLLER_LAG_S: f64 = 60.0;
/// An open session is abandoned after 2 intervals without an update plus this.
pub const STALE_GRACE_S: i64 = 60;
/// The configured accounting interval when nothing was measured (`NETPORTAL_ACCT_INTERIM_S`).
pub const DEFAULT_INTERIM_S: i64 = 300;
pub const MIN_INTERIM_S: i64 = 30;
pub const MAX_INTERIM_S: i64 = 86400;
/// A Start this much before the login still is the login's (the AP's clock vs the database's),
/// unless its session ended before the login.
pub const CLOCK_SKEW_S: f64 = 5.0;
/// A measured interval counts up to this many configured ones (an outage's gap is no interval).
pub const MAX_INTERVAL_FACTOR: i64 = 4;
/// A listed association that began this much before a Stop is the gone one, still listed.
pub const ASSOCIATION_SKEW_S: f64 = 60.0;
/// Sessions that overlap or follow each other within this are one stay (roams) for "since".
pub const ROAM_S: f64 = 120.0;
/// The page's poll hint: fast while connecting or within [`RECENT_CHANGE_S`] of a change.
pub const POLL_FAST_S: i64 = 5;
pub const POLL_S: i64 = 30;
pub const RECENT_CHANGE_S: f64 = 120.0;
/// Terminate causes that mean the access point ended the session itself (Accounting-On/Off).
pub const AP_CAUSES: [&str; 3] = ["NAS-Reboot", "NAS-Request", "NAS-Error"];
pub const EVIDENCE_MAX: usize = 12;
pub const SOURCES: [&str; 4] = ["prometheus", "radius_acct", "radius_auth", "unifi_syslog"];

/// Seconds an open session stays alive without an update.
pub fn stale_after(interim_s: i64) -> i64 {
    2 * interim_s + STALE_GRACE_S
}

// --- the inputs -----------------------------------------------------------------------------------

/// What Prometheus says of the device's MAC (`live::device_status`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Sighting {
    pub present: bool,
    pub start: Option<f64>,
    pub last_seen: Option<f64>,
}

/// The Prometheus evidence of one device.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Assoc {
    pub present: bool,
    /// Ts, the snapshot's time
    pub at: Option<f64>,
    pub fresh: bool,
    pub start: Option<f64>,
    pub last_seen: Option<f64>,
}

/// The Prometheus evidence: `None` unless Prometheus answered (telemetry `ok`). `status`: the
/// sighting of the device's MAC (`None`: no MAC asked: absent); `snapshot_at`: Ts.
pub fn association(status: Option<&Sighting>, telemetry: &str, snapshot_at: Option<f64>, stale: bool) -> Option<Assoc> {
    if telemetry != "ok" {
        return None;
    }
    let status = status.cloned().unwrap_or_default();
    Some(Assoc {
        present: status.present,
        at: snapshot_at,
        fresh: !stale && snapshot_at.is_some(),
        start: status.start,
        last_seen: status.last_seen,
    })
}

/// An accounting session as plain data (Unix times).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Session {
    pub nas_ip: Option<String>,
    pub acct_session_id: Option<String>,
    pub link: Option<String>,
    pub mac: Option<String>,
    pub ap_name: Option<String>,
    pub ap_mac: Option<String>,
    /// a session whose Start never came: its first update
    pub started: Option<f64>,
    pub updated: Option<f64>,
    pub stopped: Option<f64>,
    pub cause: Option<String>,
    pub interim_s: Option<i64>,
    pub nas_interim_s: Option<i64>,
}

/// A `registry::latest_sessions` row as plain data; the AP from the ApMap (by BSSID, else NAS).
pub fn session(row: &LatestSession, aps: Option<&ApMap>) -> Session {
    let (ap_name, ap_mac, _) = aps.map(|a| a.by_bssid(row.bssid.as_deref(), Some(&row.nas_ip))).unwrap_or_default();
    let updated = unix(row.updated);
    Session {
        nas_ip: Some(row.nas_ip.clone()),
        acct_session_id: Some(row.acct_session_id.clone()),
        link: Some(row.link.clone()),
        mac: mac_of(row.mac.as_deref()),
        ap_name,
        ap_mac,
        started: Some(unix_opt(row.started).unwrap_or(updated)),
        updated: Some(updated),
        stopped: unix_opt(row.stopped),
        cause: row.terminate_cause.clone(),
        interim_s: row.interim_s.map(i64::from),
        nas_interim_s: row.nas_interim_s.map(i64::from),
    }
}

/// A UniFi connection event as plain data.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ConnEvent {
    pub at: Option<f64>,
    pub kind: String,
    pub mac: Option<String>,
    pub ap_mac: Option<String>,
    pub ap_name: Option<String>,
}

/// A `registry::latest_connection_events` row as plain data.
pub fn event(row: &LatestEvent) -> ConnEvent {
    ConnEvent {
        at: Some(unix(row.at)),
        kind: row.kind.clone(),
        mac: normalise_mac(&row.mac),
        ap_mac: mac_of(row.ap_mac.as_deref()),
        ap_name: row.ap_name.clone(),
    }
}

/// `{AP MAC or "name:<lower name>": start}` of the open ap_down incidents.
pub fn ap_down(incidents: &[Incident]) -> HashMap<String, f64> {
    let mut out = HashMap::new();
    for r in incidents.iter().filter(|r| r.kind == "ap_down" && r.ended.is_none()) {
        let started = unix(r.started);
        if let Some(mac) = normalise_mac(&r.subject) {
            out.insert(mac, started);
        }
        if let Some(name) = r.subject_name.as_ref().filter(|n| !n.is_empty()) {
            out.insert(format!("name:{}", name.to_lowercase()), started);
        }
    }
    out
}

fn withheld_at(identity: &Identity, mac: Option<&str>, at: Option<f64>) -> bool {
    let (Some(mac), Some(at)) = (mac, at) else {
        return false;
    };
    identity.conflicts.iter().any(|c| c.mac == mac && c.from.is_none_or(|f| f <= at) && c.to.is_none_or(|t| at <= t))
}

/// What of a device's sessions a resident may see (the timeline's rule, `timeline::restrict`):
/// nothing of a MAC inside a withheld span except a session that is the device's by its
/// certificate (link `class`). Admins and no identity: everything.
pub fn own_sessions(rows: Vec<Session>, identity: Option<&Identity>) -> Vec<Session> {
    match identity {
        Some(identity) if !identity.admin && !identity.conflicts.is_empty() => rows
            .into_iter()
            .filter(|r| r.link.as_deref() == Some("class") || !withheld_at(identity, r.mac.as_deref(), r.updated))
            .collect(),
        _ => rows,
    }
}

/// [`own_sessions`] for UniFi events (they have no Class link).
pub fn own_events(rows: Vec<ConnEvent>, identity: Option<&Identity>) -> Vec<ConnEvent> {
    match identity {
        Some(identity) if !identity.admin && !identity.conflicts.is_empty() => {
            rows.into_iter().filter(|r| !withheld_at(identity, r.mac.as_deref(), r.at)).collect()
        }
        _ => rows,
    }
}

/// A device's newest sessions and UniFi events (raw rows).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Found {
    pub sessions: Vec<LatestSession>,
    pub events: Vec<LatestEvent>,
}

/// `{device id: Found}` for all devices of a page: two queries (`latest_sessions`,
/// `latest_connection_events` of the house's SSID or without one).
pub async fn load<S: Store>(
    store: &mut S,
    ids: &[Uuid],
    ssid: Option<&str>,
) -> Result<IndexMap<Uuid, Found>, RegistryError> {
    if ids.is_empty() {
        return Ok(IndexMap::new());
    }
    let mut sessions = store.latest_sessions(ids, PRESENCE_SESSIONS).await?;
    let mut events = store.latest_connection_events(ids, PRESENCE_EVENTS, ssid).await?;
    Ok(ids
        .iter()
        .map(|id| {
            let found = Found {
                sessions: sessions.swap_remove(id).unwrap_or_default(),
                events: events.swap_remove(id).unwrap_or_default(),
            };
            (*id, found)
        })
        .collect())
}

// --- the decision ---------------------------------------------------------------------------------

/// A session with what the rules need.
#[derive(Debug, Clone, PartialEq)]
pub struct View {
    /// the session (`stopped` cleared when the session was updated well after its Stop: the id
    /// was used again)
    pub session: Session,
    /// the effective end: the Stop, or the last contact of one the AP closed long after it went
    /// silent (`abandoned`)
    pub end: Option<f64>,
    pub abandoned: bool,
    pub stale_after_s: i64,
    pub interim_basis: Basis,
    pub down_since: Option<f64>,
    pub superseded: bool,
    pub alive: bool,
}

impl View {
    fn started(&self) -> Option<f64> {
        self.session.started
    }

    fn updated(&self) -> f64 {
        self.session.updated.unwrap_or(f64::NEG_INFINITY)
    }

    fn stopped(&self) -> Option<f64> {
        self.session.stopped
    }

    /// The session's last sign: its end, else its latest update.
    fn activity(&self) -> f64 {
        self.end.unwrap_or_else(|| self.updated())
    }

    fn by_start(&self) -> (f64, f64) {
        (self.started().unwrap_or_else(|| self.updated()), self.updated())
    }

    fn ap_cause(&self) -> bool {
        self.session.cause.as_deref().is_some_and(|c| AP_CAUSES.contains(&c))
    }
}

/// The interval a session's staleness counts with: the measured one, clamped to
/// `[configured, MAX_INTERVAL_FACTOR x configured]` (a short extra Interim, an outage's gap or a
/// lost packet cannot move it far); the configured one when nothing was measured.
pub fn interval(measured: Option<i64>, configured: Option<i64>) -> i64 {
    let configured = configured.filter(|c| *c != 0).unwrap_or(DEFAULT_INTERIM_S);
    match measured.filter(|m| *m != 0) {
        None => configured,
        Some(m) => m.max(configured).min(MAX_INTERVAL_FACTOR * configured),
    }
}

/// The open ap_down incident's start when it ends this open session (no update since).
fn down_since(s: &Session, stopped: Option<f64>, down: &HashMap<String, f64>) -> Option<f64> {
    if stopped.is_some() || down.is_empty() {
        return None;
    }
    let start = s
        .ap_mac
        .as_ref()
        .and_then(|m| down.get(m))
        .or_else(|| s.ap_name.as_ref().and_then(|n| down.get(&format!("name:{}", n.to_lowercase()))))
        .copied()?;
    s.updated.is_some_and(|u| u <= start + CONTROLLER_LAG_S).then_some(start)
}

fn cmp_f64(a: f64, b: f64) -> Ordering {
    a.total_cmp(&b)
}

/// The sessions with what the rules need, newest activity first; a duplicate row counts once.
fn view(now: f64, sessions: &[Session], down: &HashMap<String, f64>, interim_s: i64) -> Vec<View> {
    let mut out: Vec<View> = Vec::new();
    type Key<'a> = (&'a Option<String>, &'a Option<String>, Option<f64>, Option<f64>, Option<f64>);
    let mut keys: Vec<Key<'_>> = Vec::new();
    for s in sessions {
        let key = (&s.nas_ip, &s.acct_session_id, s.started, s.stopped, s.updated);
        let Some(updated) = s.updated else {
            continue;
        };
        if keys.contains(&key) {
            continue;
        }
        keys.push(key);
        let measured = s.interim_s.filter(|m| *m != 0).or(s.nas_interim_s.filter(|m| *m != 0));
        let every = interval(measured, Some(interim_s));
        let limit = stale_after(every);
        let stopped = s.stopped.filter(|stopped| updated <= stopped + every as f64);
        let (mut end, mut abandoned) = (stopped, false);
        let ap_cause = s.cause.as_deref().is_some_and(|c| AP_CAUSES.contains(&c));
        if let Some(st) = stopped
            && ap_cause
            && st > updated + limit as f64
        {
            end = Some(updated);
            abandoned = true;
        }
        out.push(View {
            session: Session { stopped, ..s.clone() },
            end,
            abandoned,
            stale_after_s: limit,
            interim_basis: if measured.is_some() { Basis::Measured } else { Basis::Inferred },
            down_since: down_since(s, stopped, down),
            superseded: false,
            alive: false,
        });
    }
    for i in 0..out.len() {
        let v = &out[i];
        // an open session last updated before another session of the device started: the device
        // moved on (a roam whose Stop got lost); not alive, however recent its last Interim
        let superseded = v.stopped().is_none()
            && out.iter().enumerate().any(|(j, o)| j != i && o.started().is_some_and(|s| v.updated() < s));
        let alive = v.stopped().is_none()
            && !superseded
            && now - v.updated() <= v.stale_after_s as f64
            && v.down_since.is_none();
        out[i].superseded = superseded;
        out[i].alive = alive;
    }
    out.sort_by(|a, b| {
        cmp_f64(b.activity(), a.activity())
            .then_with(|| cmp_f64(b.started().unwrap_or(0.0), a.started().unwrap_or(0.0)))
    });
    out
}

/// The first of the greatest (Python's `max` with a key).
fn first_max<'a, T, K: PartialOrd>(items: impl IntoIterator<Item = &'a T>, key: impl Fn(&T) -> K) -> Option<&'a T> {
    let mut best: Option<(&T, K)> = None;
    for item in items {
        let k = key(item);
        if best.as_ref().is_none_or(|(_, b)| k > *b) {
            best = Some((item, k));
        }
    }
    best.map(|(item, _)| item)
}

/// Since when the device is there: the association start of a fresh snapshot that already saw
/// this session; else the start of the session, joined with the sessions before it that overlap
/// it or end within [`ROAM_S`] of it (roams).
fn online_since(s: Option<&View>, view: &[View], assoc: Option<&Assoc>, ts: Option<f64>) -> Option<f64> {
    if let Some(a) = assoc
        && a.fresh
        && a.present
        && let Some(start) = a.start
        && s.is_none_or(|s| s.started().is_none_or(|st| ts.is_some_and(|ts| st <= ts)))
    {
        return Some(start);
    }
    let mut since = s?.started()?;
    for _ in 0..view.len() {
        let earlier = view
            .iter()
            .filter_map(|v| v.started().filter(|st| *st < since && v.activity() >= since - ROAM_S))
            .reduce(f64::min);
        match earlier {
            Some(e) => since = e,
            None => break,
        }
    }
    Some(since)
}

/// The latest time any source saw the device there (`None`: never).
fn last_present(assoc: Option<&Assoc>, view: &[View], accept: Option<f64>, events: &[ConnEvent]) -> Option<f64> {
    let mut times: Vec<Option<f64>> = view.iter().map(|v| Some(v.activity())).collect();
    times.extend(events.iter().map(|e| e.at));
    times.push(accept);
    if let Some(a) = assoc {
        times.push(a.last_seen);
        times.push(if a.present { a.at } else { None });
    }
    times.into_iter().flatten().reduce(f64::max)
}

/// One piece of evidence (Unix time).
#[derive(Debug, Clone, PartialEq)]
pub struct Evidence {
    pub source: &'static str,
    pub at: f64,
    pub kind: String,
}

fn evidence(assoc: Option<&Assoc>, view: &[View], accept: Option<f64>, events: &[ConnEvent]) -> Vec<Evidence> {
    let mut items: Vec<Evidence> = Vec::new();
    let mut add =
        |source: &'static str, at: f64, kind: &str| items.push(Evidence { source, at, kind: kind.to_string() });
    if let Some(a) = assoc
        && let Some(at) = a.at
    {
        let kind = if a.present { "association" } else { "association_gone" };
        if a.fresh {
            add("prometheus", at, kind);
        } else {
            add("prometheus", at, &format!("{kind}_stale"));
        }
    }
    for v in view {
        if let Some(st) = v.started() {
            add("radius_acct", st, "acct_start");
        }
        if v.session.updated != v.started() && v.stopped().is_none_or(|stopped| v.updated() < stopped) {
            add("radius_acct", v.updated(), "acct_interim");
        }
        if let Some(stopped) = v.stopped() {
            add("radius_acct", stopped, "acct_stop");
        }
        if let Some(d) = v.down_since {
            add("incident", d, "ap_down");
        }
    }
    if let Some(a) = accept {
        add("radius_auth", a, "accept");
    }
    for e in events {
        if let Some(at) = e.at {
            add("unifi_syslog", at, &e.kind);
        }
    }
    items.sort_by(|a, b| cmp_f64(b.at, a.at).then_with(|| b.source.cmp(a.source)).then_with(|| b.kind.cmp(&a.kind)));
    items.dedup();
    items.truncate(EVIDENCE_MAX);
    items
}

/// The inputs of one device's decision (Unix times).
#[derive(Debug, Clone, Default)]
pub struct Inputs {
    /// [`association`]
    pub assoc: Option<Assoc>,
    pub sessions: Vec<Session>,
    /// the latest login (the latest Access-Accept)
    pub accept: Option<f64>,
    pub events: Vec<ConnEvent>,
    /// [`ap_down`]
    pub down: HashMap<String, f64>,
    /// the configured accounting interval (`None` or 0: [`DEFAULT_INTERIM_S`])
    pub interim_s: Option<i64>,
    /// a resident's device in a MAC conflict now
    pub withheld: bool,
    /// the device has no MAC identity yet
    pub never: bool,
}

/// The presence of one device (Unix times; [`public`] makes the API's shape).
#[derive(Debug, Clone, PartialEq)]
pub struct Decision {
    pub state: &'static str,
    pub since: Option<f64>,
    pub confirmed_at: Option<f64>,
    pub confirmed_by: Option<&'static str>,
    pub basis: Basis,
    pub reason: &'static str,
    pub session: Option<View>,
    pub stale_after_s: i64,
    pub poll_s: i64,
    pub evidence: Vec<Evidence>,
    pub last_seen: Option<f64>,
}

#[allow(clippy::too_many_arguments)]
fn result(
    now: f64,
    state: &'static str,
    since: Option<f64>,
    confirmed_at: Option<f64>,
    confirmed_by: Option<&'static str>,
    basis: Basis,
    reason: &'static str,
    session: Option<View>,
    limit: i64,
    evidence: Vec<Evidence>,
    last_seen: Option<f64>,
) -> Decision {
    let fast = state == CONNECTING || since.is_some_and(|s| now - s < RECENT_CHANGE_S);
    Decision {
        state,
        since,
        confirmed_at,
        confirmed_by,
        basis,
        reason,
        session,
        stale_after_s: limit,
        poll_s: if fast { POLL_FAST_S } else { POLL_S },
        evidence,
        last_seen,
    }
}

/// The presence of one device: the rules of the module's documentation, in order.
pub fn decide(now: f64, inputs: &Inputs) -> Decision {
    let interim_s = inputs.interim_s.filter(|i| *i != 0).unwrap_or(DEFAULT_INTERIM_S);
    let accept = inputs.accept;
    if inputs.withheld {
        return result(
            now,
            UNKNOWN,
            None,
            None,
            None,
            Basis::Inferred,
            "mac_conflict",
            None,
            stale_after(interim_s),
            Vec::new(),
            accept,
        );
    }
    let view = view(now, &inputs.sessions, &inputs.down, interim_s);
    let mut events: Vec<ConnEvent> = inputs.events.iter().filter(|e| e.at.is_some()).cloned().collect();
    events.sort_by(|a, b| cmp_f64(b.at.unwrap_or(0.0), a.at.unwrap_or(0.0)));
    let assoc = inputs.assoc.as_ref();
    let evidence = evidence(assoc, &view, accept, &events);
    if inputs.never && view.is_empty() && accept.is_none() {
        return result(
            now,
            NEVER,
            None,
            None,
            None,
            Basis::Measured,
            "no_data",
            None,
            stale_after(interim_s),
            evidence,
            None,
        );
    }
    let fresh = assoc.is_some_and(|a| a.fresh);
    let ts = if fresh { assoc.and_then(|a| a.at) } else { None };
    let present = assoc.is_some_and(|a| a.present);
    let absent = fresh && !present;
    let newer = |t: Option<f64>, lag: f64| t.is_some_and(|t| ts.is_none_or(|ts| t > ts - lag));

    let alive: Vec<&View> = view.iter().filter(|v| v.alive).collect();
    let newest = view.first();
    let current = first_max(alive.iter().copied(), View::by_start);

    let done = |state, since, at, by, basis, reason, s: Option<&View>, last_seen| {
        let limit = s.map_or_else(|| stale_after(interim_s), |s| s.stale_after_s);
        result(now, state, since, at, by, basis, reason, s.cloned(), limit, evidence.clone(), last_seen)
    };

    // 1a. an alive session newer than the snapshot (the newest started one). A fresh snapshot
    // that does not list a session it should long have seen while its Interims go on: the
    // sources disagree; online stays, inferred, the session's since: no flapping.
    let recent: Vec<&View> = alive
        .iter()
        .copied()
        .filter(|v| newer(v.started(), CONTROLLER_LAG_S) || newer(v.session.updated, 0.0))
        .collect();
    if !recent.is_empty() || (absent && current.is_some()) {
        let s = first_max(recent.iter().copied(), View::by_start).or(current);
        if let Some(s) = s {
            let since = online_since(Some(s), &view, assoc, ts);
            if absent
                && let (Some(st), Some(ts)) = (s.started(), ts)
                && st <= ts - CONTROLLER_LAG_S
            {
                return done(
                    ONLINE,
                    since,
                    s.session.updated,
                    Some("radius_acct"),
                    Basis::Inferred,
                    "sources_disagree",
                    Some(s),
                    s.session.updated,
                );
            }
            let reason = if s.started().is_some_and(|st| s.updated() > st) { "acct_interim" } else { "acct_start" };
            return done(
                ONLINE,
                since,
                s.session.updated,
                Some("radius_acct"),
                Basis::Measured,
                reason,
                Some(s),
                s.session.updated,
            );
        }
    }
    // 1b. a fresh login without a Start yet
    if let Some(acc) = accept
        && (0.0..CONNECTING_S).contains(&(now - acc))
        && alive.is_empty()
        && !(fresh && present)
        // the login's own session (started at most CLOCK_SKEW_S before it) began, so the login
        // is answered, also when that session already ended; but one the AP itself closed before
        // the login (Accounting-On: it restarted) is no answer
        && !view.iter().any(|v| {
            v.started().is_some_and(|st| st >= acc - CLOCK_SKEW_S)
                && !(v.ap_cause() && v.end.is_some_and(|e| e < acc))
        })
        // an older session that ended clearly after the login: a re-authentication inside it
        && !view.iter().any(|v| v.end.is_some_and(|e| e >= acc + CLOCK_SKEW_S))
    {
        return done(CONNECTING, accept, accept, Some("radius_auth"), Basis::Measured, "accept_pending", None, accept);
    }
    // 1c. none alive and the newest session ended after the snapshot, or a present snapshot lists
    // an association from before that Stop (the controller still shows the gone client)
    if alive.is_empty()
        && let Some(n) = newest
        && let Some(end) = n.end
    {
        let listed_gone = fresh
            && present
            && !n.abandoned
            && assoc.and_then(|a| a.start).is_some_and(|start| start < end - ASSOCIATION_SKEW_S);
        if newer(Some(end), CONTROLLER_LAG_S) || listed_gone {
            let reason = if n.ap_cause() { "ap_down" } else { "acct_stop" };
            return done(
                OFFLINE,
                Some(end),
                Some(end),
                Some("radius_acct"),
                Basis::Measured,
                reason,
                Some(n),
                Some(end),
            );
        }
    }
    // 1d. a UniFi disconnect newer than everything else
    if alive.is_empty()
        && let Some(e) = events.first()
    {
        let mut others: Vec<f64> = view.iter().map(View::activity).collect();
        others.extend(accept);
        if e.kind == "disconnected" && newer(e.at, 0.0) && e.at.is_some_and(|at| others.iter().all(|t| at > *t)) {
            return done(OFFLINE, e.at, e.at, Some("unifi_syslog"), Basis::Measured, "unifi_disconnect", newest, e.at);
        }
    }
    // 2. a fresh snapshot
    if fresh {
        if present {
            let since = online_since(current, &view, assoc, ts);
            return done(ONLINE, since, ts, Some("prometheus"), Basis::Measured, "association", current, ts);
        }
        let seen = last_present(assoc, &view, accept, &events);
        if let (Some(seen), Some(ts)) = (seen, ts)
            && seen > ts
        {
            // seen after the snapshot (a login that got no Start within CONNECTING_S): what
            // confirms it is the time since that sighting, not the older snapshot
            return done(
                OFFLINE,
                Some(seen),
                Some(seen),
                Some("prometheus"),
                Basis::Inferred,
                "association_gone",
                newest,
                Some(seen),
            );
        }
        return done(OFFLINE, seen, ts, Some("prometheus"), Basis::Measured, "association_gone", newest, seen);
    }
    // 3. no fresh snapshot
    let seen = last_present(assoc, &view, accept, &events);
    if let Some(n) = newest
        && n.end.is_none()
    {
        if let Some(d) = n.down_since {
            return done(
                OFFLINE,
                Some(d),
                Some(d),
                Some("prometheus"),
                Basis::Inferred,
                "ap_down",
                Some(n),
                n.session.updated,
            );
        }
        return done(UNKNOWN, None, None, None, Basis::Inferred, "session_stale", Some(n), seen);
    }
    done(UNKNOWN, None, None, None, Basis::Inferred, "telemetry_unavailable", newest, seen)
}

// --- the API's shape -------------------------------------------------------------------------------

/// DEVICE.presence (INVENTORY 9.12).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Presence {
    pub state: &'static str,
    pub since: Option<String>,
    pub confirmed_at: Option<String>,
    pub confirmed_by: Option<&'static str>,
    pub basis: Basis,
    pub reason: &'static str,
    pub session: Option<PublicSession>,
    pub stale_after_s: i64,
    pub poll_s: i64,
    pub evidence: Vec<PublicEvidence>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PublicSession {
    pub nas_ip: Option<String>,
    pub acct_session_id: Option<String>,
    pub ap: Option<ApRef>,
    pub started: Option<String>,
    pub updated: Option<String>,
    pub stopped: Option<String>,
    pub cause: Option<String>,
    /// the measured session or NAS interval (raw, not clamped)
    pub interim_s: Option<i64>,
    pub interim_basis: Basis,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PublicEvidence {
    pub source: &'static str,
    pub at: Option<String>,
    pub kind: String,
}

/// DEVICE.presence with ISO times.
pub fn public(p: &Decision) -> Presence {
    let session = p.session.as_ref().map(|v| {
        let s = &v.session;
        PublicSession {
            nas_ip: s.nas_ip.clone(),
            acct_session_id: s.acct_session_id.clone(),
            ap: ap_ref(s.ap_name.as_deref(), s.ap_mac.as_deref()),
            started: iso(s.started),
            updated: iso(s.updated),
            stopped: iso(s.stopped),
            cause: s.cause.clone(),
            interim_s: s.interim_s.filter(|i| *i != 0).or(s.nas_interim_s),
            interim_basis: v.interim_basis,
        }
    });
    Presence {
        state: p.state,
        since: iso(p.since),
        confirmed_at: iso(p.confirmed_at),
        confirmed_by: p.confirmed_by,
        basis: p.basis,
        reason: p.reason,
        session,
        stale_after_s: p.stale_after_s,
        poll_s: p.poll_s,
        evidence: p
            .evidence
            .iter()
            .map(|e| PublicEvidence { source: e.source, at: iso(Some(e.at)), kind: e.kind.clone() })
            .collect(),
    }
}

/// `{state: n}` over the devices' states (every state a key, then any other seen).
pub fn counts<'a>(states: impl IntoIterator<Item = &'a str>) -> IndexMap<String, i64> {
    let mut out: IndexMap<String, i64> = STATES.iter().map(|s| (s.to_string(), 0)).collect();
    for s in states {
        *out.entry(s.to_string()).or_default() += 1;
    }
    out
}

/// The page's poll interval: the shortest of its devices' hints ([`POLL_S`] without any).
pub fn poll_s(hints: impl IntoIterator<Item = Option<i64>>) -> i64 {
    hints.into_iter().flatten().filter(|h| *h > 0).min().unwrap_or(POLL_S)
}
