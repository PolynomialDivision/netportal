//! Telemetry: a device's connection timeline (`telemetry/timeline.py`, INVENTORY 9.9.1-9.9.2):
//! events from every source, normalised and merged.
//!
//! Sources and what they say (source name, basis):
//! - `radius_auth` (measured): authenticated / auth_rejected, with the BSSID and the NAS (the AP).
//! - `radius_acct` (measured): connected (Start), session_ended (Stop, with Acct-Terminate-Cause,
//!   octets, session time). A Stop followed within [`ROAM_S`] by a Start of the same device is a
//!   roam (another AP) or a reconnect (the same AP): one event, the Stop's cause in its detail.
//! - `unifi_syslog` (measured, connection_event): connected / disconnected / roamed (a roam
//!   between the radios of one AP is band_changed).
//! - `prometheus` (inferred, [`derive_timeline`]): connections from the association start
//!   (snapshot time - uptime), roams and band changes from the AP and radio labels, disconnects
//!   from new association starts and from the device's absence.
//! - `device_mac` (inferred): mac_changed, when a window with another MAC starts.
//! - `incident` (measured or inferred, as the incident row).
//!
//! Merge ([`merge`]): events of different sources within [`MERGE_S`] describing the same thing
//! collapse into one with every source in `sources`; the measured one wins (then the better
//! source, [`source_rank`]), the other only fills what it lacks. An inferred event a measured one
//! covers is dropped. A disconnect followed within [`RECONNECT_S`] by a connection is one
//! `reconnected`. At most [`MAX_EVENTS`] (the latest) are returned, with a truncation flag.
//!
//! Times inside are Unix seconds; [`public`] makes the API's shape.

use std::collections::HashMap;

use netportal_core::registry::{AcctSession, AuthEvent, ConnectionEvent, Incident};
use serde::Serialize;
use serde_json::{Map, Value, json};

use super::common::{ApRef, ap_ref, band, iso, mac_of, normalise_mac, trunc_int, unix, unix_opt};
use super::identity::Identity;
use crate::diagnostics::Disconnect;

pub const MERGE_S: f64 = 120.0;
pub const RECONNECT_S: f64 = 120.0;
pub const ROAM_S: f64 = 120.0;
/// Association starts within this of each other are one connection: the snapshot time is exact,
/// the uptime UniFi reports moves by up to a minute between snapshots.
pub const SAME_ASSOCIATION_S: f64 = 120.0;
pub const MAX_EVENTS: usize = 1000;
/// The kinds a disconnect counts as (diagnostics: frequent_disconnects, incident_correlated).
pub const DISCONNECT_KINDS: [&str; 3] = ["disconnected", "session_ended", "reconnected"];

/// `measured` (samples, RADIUS packets, UniFi events, registry rows) or `inferred` (derived).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Basis {
    Measured,
    Inferred,
}

impl Basis {
    pub fn of(text: &str) -> Basis {
        if text == "measured" { Basis::Measured } else { Basis::Inferred }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Basis::Measured => "measured",
            Basis::Inferred => "inferred",
        }
    }
}

/// The sources' rank when events collapse (lower wins; unknown sources last).
pub fn source_rank(source: &str) -> u8 {
    match source {
        "unifi_syslog" => 0,
        "radius_acct" => 1,
        "radius_auth" => 2,
        "incident" => 3,
        "device_mac" => 4,
        "prometheus" => 5,
        _ => 9,
    }
}

/// What may collapse with what (the canonical kind).
pub fn merge_kind(kind: &str) -> Option<&'static str> {
    Some(match kind {
        "connected" => "connected",
        "disconnected" | "session_ended" => "disconnected",
        "roamed" => "roamed",
        "band_changed" => "band_changed",
        "reconnected" => "reconnected",
        _ => return None,
    })
}

/// An inferred event of this kind is dropped when a measured one of these kinds is that close.
pub fn covers(kind: &str) -> Option<&'static [&'static str]> {
    Some(match kind {
        "connected" => &["connected", "reconnected", "roamed"],
        "disconnected" => &["disconnected", "session_ended", "reconnected"],
        "roamed" => &["roamed"],
        "band_changed" => &["band_changed", "roamed"],
        "reconnected" => &["reconnected"],
        _ => return None,
    })
}

// --- the inferred timeline (Prometheus presence) ----------------------------------------------------

/// One minute of a device's association: `(t, association start, ap_name, radio, mac)`.
#[derive(Debug, Clone, PartialEq)]
pub struct Point {
    pub t: f64,
    pub start: f64,
    pub ap_name: Option<String>,
    pub radio: Option<String>,
    pub mac: Option<String>,
}

/// An event [`derive_timeline`] infers.
#[derive(Debug, Clone, PartialEq)]
pub struct Inferred {
    pub kind: &'static str,
    pub at: f64,
    pub ap: Option<String>,
    pub band: Option<&'static str>,
    pub from_ap: Option<String>,
    pub from_band: Option<&'static str>,
    pub duration_s: Option<i64>,
    pub mac: Option<String>,
}

fn inferred(
    kind: &'static str,
    at: f64,
    ap: Option<String>,
    band: Option<&'static str>,
    mac: Option<String>,
) -> Inferred {
    Inferred { kind, at, ap, band, from_ap: None, from_band: None, duration_s: None, mac }
}

/// `(events, spans)` from points sorted by t, fresh data only. A connection is one association
/// start: a later start (with or without a gap) is a disconnect plus a new connection; a gap with
/// the same start is missing data, not a disconnect (the device stayed associated). AP changes
/// are roams, band changes on the same AP band changes. A device not seen for 3 resolutions
/// before the last fresh data is disconnected now. Nothing before `since` (the data bound).
/// Spans are `(connected at, last seen)`.
pub fn derive_timeline(
    points: &[Point],
    res: f64,
    last_fresh: Option<f64>,
    since: Option<f64>,
) -> (Vec<Inferred>, Vec<(f64, f64)>) {
    struct Current {
        start: f64,
        at: f64,
        last: f64,
        ap: Option<String>,
        band: Option<&'static str>,
        changed: f64,
        event: usize,
        mac: Option<String>,
    }
    let mut events: Vec<Inferred> = Vec::new();
    let mut spans = Vec::new();
    let mut cur: Option<Current> = None;
    let close = |c: &Current, events: &mut Vec<Inferred>, spans: &mut Vec<(f64, f64)>| {
        events[c.event].duration_s = trunc_int(c.last - c.at);
        spans.push((c.at, c.last));
    };
    for p in points {
        if since.is_some_and(|s| p.t < s) {
            continue;
        }
        let mut start = p.start.min(p.t);
        let b = band(p.radio.as_deref());
        if let Some(s) = since {
            start = start.max(s);
        }
        if let Some(c) = cur.as_mut()
            && start - c.start <= SAME_ASSOCIATION_S
            && p.mac == c.mac
        {
            if (p.ap_name.as_deref(), b) != (c.ap.as_deref(), c.band) {
                let kind = if p.ap_name != c.ap { "roamed" } else { "band_changed" };
                events.push(Inferred {
                    kind,
                    at: p.t,
                    ap: p.ap_name.clone(),
                    band: b,
                    from_ap: c.ap.clone(),
                    from_band: c.band,
                    duration_s: trunc_int(p.t - c.changed),
                    mac: p.mac.clone(),
                });
                c.ap = p.ap_name.clone();
                c.band = b;
                c.changed = p.t;
            }
            c.start = start;
            c.last = p.t;
            continue;
        }
        let at = cur.as_ref().map_or(start, |c| start.max(c.last));
        if let Some(c) = cur.take() {
            close(&c, &mut events, &mut spans);
            let mut gone = inferred("disconnected", c.last, c.ap.clone(), c.band, c.mac.clone());
            gone.duration_s = trunc_int(at - c.last);
            events.push(gone);
        }
        let mut new = inferred("connected", at, p.ap_name.clone(), b, p.mac.clone());
        new.duration_s = Some(0);
        events.push(new);
        cur = Some(Current {
            start,
            at,
            last: p.t,
            ap: p.ap_name.clone(),
            band: b,
            changed: at,
            event: events.len() - 1,
            mac: p.mac.clone(),
        });
    }
    if let Some(c) = cur {
        close(&c, &mut events, &mut spans);
        if let Some(fresh) = last_fresh
            && fresh - c.last >= 3.0 * res
        {
            let mut gone = inferred("disconnected", c.last, c.ap.clone(), c.band, c.mac.clone());
            gone.duration_s = trunc_int(fresh - c.last);
            events.push(gone);
        }
    }
    (events, spans)
}

// --- normalised events --------------------------------------------------------------------------------

/// A normalised event (Unix times; [`public`] makes the API's EVENT).
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    pub kind: &'static str,
    pub at: f64,
    pub source: String,
    /// in [`source_rank`] order
    pub sources: Vec<String>,
    pub basis: Basis,
    pub ap: Option<String>,
    pub ap_mac: Option<String>,
    pub band: Option<&'static str>,
    pub from_ap: Option<String>,
    pub from_ap_mac: Option<String>,
    pub from_band: Option<&'static str>,
    pub mac: Option<String>,
    pub duration_s: Option<i64>,
    pub detail: Map<String, Value>,
}

impl Event {
    pub fn new(kind: &'static str, at: f64, source: &str, basis: Basis) -> Event {
        Event {
            kind,
            at,
            source: source.to_string(),
            sources: vec![source.to_string()],
            basis,
            ap: None,
            ap_mac: None,
            band: None,
            from_ap: None,
            from_ap_mac: None,
            from_band: None,
            mac: None,
            duration_s: None,
            detail: Map::new(),
        }
    }
}

/// `(ap name, ap mac, band)`.
pub type ApHit = (Option<String>, Option<String>, Option<&'static str>);

/// Which AP a BSSID, a NAS address or an AP MAC is (from unpoller: the VAPs' bssid and the
/// devices' ip and mac labels). Empty when Prometheus did not answer: the events keep what their
/// row says.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ApMap {
    /// bssid -> (ap name, ap mac, band)
    pub bssids: HashMap<String, ApHit>,
    /// NAS address -> (ap name, ap mac)
    pub nas: HashMap<String, (String, String)>,
    /// ap mac -> ap name
    pub names: HashMap<String, String>,
}

impl ApMap {
    pub fn is_empty(&self) -> bool {
        self.bssids.is_empty() && self.nas.is_empty()
    }

    /// `(ap name, ap mac, band)` of a BSSID, else of the NAS, else nothing.
    pub fn by_bssid(&self, bssid: Option<&str>, nas_ip: Option<&str>) -> ApHit {
        if let Some(hit) = bssid.and_then(normalise_mac).and_then(|b| self.bssids.get(&b)) {
            return hit.clone();
        }
        match nas_ip.and_then(|ip| self.nas.get(ip)) {
            Some((name, mac)) => (Some(name.clone()), Some(mac.clone()), None),
            None => (None, None, None),
        }
    }

    /// The AP's name by its MAC, else the fallback.
    pub fn name(&self, ap_mac: Option<&str>, fallback: Option<&str>) -> Option<String> {
        ap_mac.and_then(|m| self.names.get(m)).cloned().or_else(|| fallback.map(str::to_string))
    }
}

/// [`derive_timeline`]'s events (inferred, source prometheus).
pub fn from_presence(events: &[Inferred]) -> Vec<Event> {
    events
        .iter()
        .map(|e| Event {
            ap: e.ap.clone(),
            band: e.band,
            from_ap: e.from_ap.clone(),
            from_band: e.from_band,
            mac: e.mac.clone(),
            duration_s: e.duration_s,
            ..Event::new(e.kind, e.at, "prometheus", Basis::Inferred)
        })
        .collect()
}

/// RADIUS decisions (`registry::auth_events`): authenticated / auth_rejected at the row's first
/// time. detail: reason, bssid, ssid, match (how the row is the device's: `device` by its
/// certificate, `mac` by one of its MACs only; [`restrict`] needs it), count (repeated rejects
/// are one row) and last_at (the latest repeat, when there were repeats).
pub fn from_auth(rows: &[AuthEvent], aps: &ApMap) -> Vec<Event> {
    rows.iter()
        .map(|r| {
            let (name, ap_mac, b) = aps.by_bssid(r.bssid.as_deref(), r.nas_ip.as_deref());
            let kind = if r.result == "accept" { "authenticated" } else { "auth_rejected" };
            let mut detail = Map::new();
            detail.insert("reason".into(), json!(r.reason));
            detail.insert("bssid".into(), json!(mac_of(r.bssid.as_deref())));
            detail.insert("ssid".into(), json!(r.ssid));
            detail.insert("match".into(), json!(r.matched));
            detail.insert("count".into(), json!(r.tries.max(1)));
            if let Some(last) = r.last_at {
                detail.insert("last_at".into(), json!(iso(Some(unix(last)))));
            }
            Event {
                ap: name,
                ap_mac,
                band: b,
                mac: mac_of(r.mac.as_deref()),
                detail,
                ..Event::new(kind, unix(r.at), "radius_auth", Basis::Measured)
            }
        })
        .collect()
}

/// Accounting sessions (`registry::acct_sessions`): connected at Start, session_ended at Stop;
/// a Stop and the next session's Start within [`ROAM_S`] are one roamed (another AP) or
/// reconnected (the same AP); `gap_s` is negative when the sessions overlapped.
pub fn from_acct(rows: &[AcctSession], aps: &ApMap) -> Vec<Event> {
    struct Prev {
        stopped: Option<f64>,
        ended: Option<usize>,
        ap: Option<String>,
        ap_mac: Option<String>,
        band: Option<&'static str>,
        cause: Option<String>,
        session_s: Option<i64>,
    }
    let mut sessions: Vec<&AcctSession> = rows.iter().filter(|r| r.started.is_some() || r.stopped.is_some()).collect();
    sessions.sort_by(|a, b| {
        let key = |r: &AcctSession| unix_opt(r.started.or(r.stopped)).unwrap_or(0.0);
        key(a).total_cmp(&key(b))
    });
    let mut out: Vec<Option<Event>> = Vec::new();
    let mut prev: Option<Prev> = None;
    for r in sessions {
        let (name, ap_mac, b) = aps.by_bssid(r.bssid.as_deref(), Some(&r.nas_ip));
        let (started, stopped) = (unix_opt(r.started), unix_opt(r.stopped));
        let mac = mac_of(r.mac.as_deref());
        let mut detail = Map::new();
        detail.insert("acct_session_id".into(), json!(r.acct_session_id));
        detail.insert("framed_ip".into(), json!(r.framed_ip));
        detail.insert("link".into(), json!(r.link));
        if let Some(started) = started {
            let joined =
                prev.as_ref().and_then(|p| p.stopped.map(|s| (p, s))).filter(|(_, s)| (started - s).abs() <= ROAM_S);
            match joined {
                Some((p, prev_stopped)) => {
                    if let Some(i) = p.ended {
                        out[i] = None;
                    }
                    let here = ap_mac.clone().or_else(|| name.clone());
                    let same = here.is_some() && p.ap_mac.clone().or_else(|| p.ap.clone()) == here;
                    let kind = if same { "reconnected" } else { "roamed" };
                    let mut d = detail.clone();
                    d.insert("from_cause".into(), json!(p.cause));
                    d.insert("from_session_s".into(), json!(p.session_s));
                    d.insert("gap_s".into(), json!(trunc_int(started - prev_stopped)));
                    out.push(Some(Event {
                        ap: name.clone(),
                        ap_mac: ap_mac.clone(),
                        band: b,
                        from_ap: p.ap.clone(),
                        from_ap_mac: p.ap_mac.clone(),
                        from_band: p.band,
                        mac: mac.clone(),
                        detail: d,
                        ..Event::new(kind, started, "radius_acct", Basis::Measured)
                    }));
                }
                None => out.push(Some(Event {
                    ap: name.clone(),
                    ap_mac: ap_mac.clone(),
                    band: b,
                    mac: mac.clone(),
                    detail: detail.clone(),
                    ..Event::new("connected", started, "radius_acct", Basis::Measured)
                })),
            }
        }
        let mut ended = None;
        if let Some(stopped) = stopped {
            let mut d = detail;
            d.insert("cause".into(), json!(r.terminate_cause));
            d.insert("session_time_s".into(), json!(r.session_time_s));
            d.insert("rx_bytes".into(), json!(r.output_octets));
            d.insert("tx_bytes".into(), json!(r.input_octets));
            out.push(Some(Event {
                ap: name.clone(),
                ap_mac: ap_mac.clone(),
                band: b,
                mac,
                duration_s: r.session_time_s,
                detail: d,
                ..Event::new("session_ended", stopped, "radius_acct", Basis::Measured)
            }));
            ended = Some(out.len() - 1);
        }
        prev = Some(Prev {
            stopped,
            ended,
            ap: name,
            ap_mac,
            band: b,
            cause: r.terminate_cause.clone(),
            session_s: r.session_time_s,
        });
    }
    out.into_iter().flatten().collect()
}

/// UniFi's system log (`registry::connection_events`): connected / disconnected / roamed (a roam
/// between the radios of one AP: band_changed).
pub fn from_unifi(rows: &[ConnectionEvent], aps: &ApMap) -> Vec<Event> {
    let mut out = Vec::new();
    for r in rows {
        let kind: &'static str = match r.kind.as_str() {
            "connected" => "connected",
            "disconnected" => "disconnected",
            "roamed" => "roamed",
            _ => continue,
        };
        let (ap_mac, from_ap_mac) = (mac_of(r.ap_mac.as_deref()), mac_of(r.from_ap_mac.as_deref()));
        let name = aps.name(ap_mac.as_deref(), r.ap_name.as_deref());
        let from_name = aps.name(from_ap_mac.as_deref(), r.from_ap_name.as_deref());
        let same_ap = match &ap_mac {
            Some(m) => from_ap_mac.as_ref() == Some(m),
            None => name.is_some() && name == from_name,
        };
        let kind = if kind == "roamed" && same_ap { "band_changed" } else { kind };
        let mut detail = Map::new();
        let mut put = |k: &str, v: Value| {
            if !v.is_null() {
                detail.insert(k.into(), v);
            }
        };
        put("rssi", json!(r.rssi));
        put("channel", json!(r.channel));
        put("ssid", json!(r.ssid));
        put("radio", json!(r.radio));
        put("rx_bytes", json!(r.rx_bytes));
        put("tx_bytes", json!(r.tx_bytes));
        let source = if r.source.is_empty() { "unifi_syslog" } else { r.source.as_str() };
        out.push(Event {
            ap: name,
            ap_mac,
            band: band(r.radio.as_deref()),
            from_ap: if kind != "connected" { from_name } else { None },
            from_ap_mac,
            mac: mac_of(Some(&r.mac)),
            duration_s: r.duration_s,
            detail,
            ..Event::new(kind, unix(r.at), source, Basis::Measured)
        });
    }
    out
}

/// mac_changed (inferred, device_mac): a window with another MAC starts in `[start, end]`.
pub fn from_windows(identity: &Identity, start: f64, end: f64) -> Vec<Event> {
    let mut windows: Vec<_> = identity.windows.iter().collect();
    windows.sort_by(|a, b| a.first_seen.total_cmp(&b.first_seen).then_with(|| a.mac.cmp(&b.mac)));
    let mut out = Vec::new();
    let mut previous: Option<&super::identity::Window> = None;
    for w in windows {
        let first = w.first_seen;
        if let Some(p) = previous
            && p.mac != w.mac
            && start <= first
            && first <= end
        {
            let mut detail = Map::new();
            detail.insert("from_mac".into(), json!(p.mac));
            detail.insert("randomized".into(), json!(w.randomized));
            out.push(Event {
                mac: Some(w.mac.clone()),
                detail,
                ..Event::new("mac_changed", first, "device_mac", Basis::Inferred)
            });
        }
        previous = Some(w);
    }
    out
}

/// Incident rows (`registry::incidents`): one `incident` event at the start.
pub fn from_incidents(rows: &[&Incident]) -> Vec<Event> {
    rows.iter()
        .map(|r| {
            let (started, ended) = (unix(r.started), unix_opt(r.ended));
            let is_ap = r.kind.starts_with("ap_");
            let mut detail = Map::new();
            detail.insert("id".into(), json!(r.id));
            detail.insert("incident".into(), json!(r.kind));
            detail.insert("subject".into(), json!(r.subject));
            detail.insert("subject_name".into(), json!(r.subject_name));
            detail.insert("ended".into(), json!(iso(ended)));
            detail.insert("open".into(), json!(ended.is_none()));
            Event {
                ap: if is_ap { r.subject_name.clone() } else { None },
                ap_mac: if is_ap { normalise_mac(&r.subject) } else { None },
                duration_s: ended.and_then(|e| trunc_int(e - started)),
                detail,
                ..Event::new("incident", started, "incident", Basis::of(&r.basis))
            }
        })
        .collect()
}

// --- merge ------------------------------------------------------------------------------------------

fn same_ap(a: &Event, b: &Event) -> bool {
    if let (Some(x), Some(y)) = (&a.ap_mac, &b.ap_mac) {
        return x == y;
    }
    if let (Some(x), Some(y)) = (&a.ap, &b.ap)
        && !x.is_empty()
        && !y.is_empty()
    {
        return x.to_lowercase() == y.to_lowercase();
    }
    true
}

fn rank(e: &Event) -> (u8, u8) {
    (if e.basis == Basis::Measured { 0 } else { 1 }, source_rank(&e.source))
}

fn union(a: &[String], b: &[String]) -> Vec<String> {
    let mut all: Vec<String> = a.iter().chain(b).cloned().collect();
    all.sort_by(|x, y| source_rank(x).cmp(&source_rank(y)).then_with(|| x.cmp(y)));
    all.dedup();
    all
}

/// `e` collapsed into `twin`: the better one's fields, the other's where it has none.
fn absorb(twin: &mut Event, e: Event) {
    let sources = union(&twin.sources, &e.sources);
    let basis =
        if twin.basis == Basis::Measured || e.basis == Basis::Measured { Basis::Measured } else { Basis::Inferred };
    let (primary, other) = if rank(&e) < rank(twin) { (e, twin.clone()) } else { (twin.clone(), e) };
    let mut detail = other.detail;
    detail.extend(primary.detail.clone());
    *twin = Event {
        ap: primary.ap.or(other.ap),
        ap_mac: primary.ap_mac.or(other.ap_mac),
        band: primary.band.or(other.band),
        from_ap: primary.from_ap.or(other.from_ap),
        from_ap_mac: primary.from_ap_mac.or(other.from_ap_mac),
        from_band: primary.from_band.or(other.from_band),
        mac: primary.mac.or(other.mac),
        duration_s: primary.duration_s.or(other.duration_s),
        detail,
        sources,
        basis,
        ..primary
    };
}

fn twin(merged: &[Event], e: &Event) -> Option<usize> {
    let kind = merge_kind(e.kind);
    for (i, m) in merged.iter().enumerate().rev() {
        if m.at < e.at - MERGE_S {
            return None;
        }
        if merge_kind(m.kind) == kind && !m.sources.iter().any(|s| e.sources.contains(s)) && same_ap(m, e) {
            return Some(i);
        }
    }
    None
}

/// disconnected + connected within [`RECONNECT_S`]: one reconnected (at the connection; the
/// connection's duration, the gap in detail). Events of other kinds (logins, MAC changes,
/// incidents) between them do not interrupt it.
fn reconnects(events: Vec<Event>) -> Vec<Event> {
    let mut out = Vec::new();
    let mut pending: Option<Event> = None;
    for e in events {
        if e.kind == "disconnected" {
            if let Some(p) = pending.take() {
                out.push(p);
            }
            pending = Some(e);
            continue;
        }
        if let Some(p) = pending.as_ref()
            && e.kind == "connected"
            && e.at - p.at <= RECONNECT_S
        {
            let mut detail = p.detail.clone();
            detail.extend(e.detail.clone());
            detail.insert("gap_s".into(), json!(trunc_int(e.at - p.at)));
            if let (Some(a), Some(b)) = (&p.mac, &e.mac)
                && a != b
            {
                detail.insert("from_mac".into(), json!(a));
            }
            let basis = if e.basis == Basis::Measured && p.basis == Basis::Measured {
                Basis::Measured
            } else {
                Basis::Inferred
            };
            let sources = union(&e.sources, &p.sources);
            let (from_ap, from_ap_mac, from_band) = (p.ap.clone(), p.ap_mac.clone(), p.band);
            out.push(Event { kind: "reconnected", from_ap, from_ap_mac, from_band, sources, basis, detail, ..e });
            pending = None;
            continue;
        }
        if merge_kind(e.kind).is_some()
            && let Some(p) = pending.take()
        {
            out.push(p);
        }
        out.push(e);
    }
    out.extend(pending);
    out
}

/// `(events sorted by time, truncated)`: collapsed, covered ones dropped, reconnects joined, the
/// latest `limit` (`None`: all).
pub fn merge(mut events: Vec<Event>, limit: Option<usize>) -> (Vec<Event>, bool) {
    events.sort_by(|a, b| a.at.total_cmp(&b.at).then_with(|| rank(a).cmp(&rank(b))));
    let mut merged: Vec<Event> = Vec::new();
    for e in events {
        match (merge_kind(e.kind).is_some()).then(|| twin(&merged, &e)).flatten() {
            Some(i) => absorb(&mut merged[i], e),
            None => merged.push(e),
        }
    }
    let measured: Vec<usize> = (0..merged.len()).filter(|&i| merged[i].basis == Basis::Measured).collect();
    let mut dropped = vec![false; merged.len()];
    for i in 0..merged.len() {
        let e = &merged[i];
        if e.basis != Basis::Inferred {
            continue;
        }
        let Some(kinds) = covers(e.kind) else {
            continue;
        };
        let cover = measured.iter().copied().find(|&j| {
            kinds.contains(&merged[j].kind) && (merged[j].at - e.at).abs() <= MERGE_S && same_ap(&merged[j], e)
        });
        if let Some(j) = cover {
            let sources = union(&merged[j].sources, &merged[i].sources);
            merged[j].sources = sources;
            dropped[i] = true;
        }
    }
    let kept: Vec<Event> = merged.into_iter().zip(dropped).filter(|(_, d)| !d).map(|(e, _)| e).collect();
    let mut kept = reconnects(kept);
    kept.sort_by(|a, b| a.at.total_cmp(&b.at));
    match limit {
        Some(limit) if limit > 0 => {
            let truncated = kept.len() > limit;
            let cut = kept.len().saturating_sub(limit);
            (kept.split_off(cut), truncated)
        }
        _ => (kept, false),
    }
}

/// An event that is the device's by its certificate, not only by the MAC: a RADIUS decision
/// logged with the device (`match` `device`) or an accounting session linked by the login's
/// Class. A reject found by the MAC alone (no certificate, so whoever sent it) is not.
fn own(e: &Event) -> bool {
    match e.source.as_str() {
        "radius_auth" => e.detail.get("match").and_then(Value::as_str) == Some("device"),
        "radius_acct" => e.detail.get("link").and_then(Value::as_str) == Some("class"),
        _ => false,
    }
}

/// Residents: nothing of a MAC in its withheld spans except what is the device's by its
/// certificate; admins: such events marked (`detail.conflict` = other owners).
pub fn restrict(events: Vec<Event>, identity: Option<&Identity>) -> Vec<Event> {
    let Some(identity) = identity else {
        return events;
    };
    let mut out = Vec::new();
    for mut e in events {
        if let Some(mac) = &e.mac {
            let most = identity
                .conflicts
                .iter()
                .filter(|c| c.mac == *mac && c.from.is_none_or(|f| f <= e.at) && c.to.is_none_or(|t| e.at <= t))
                .map(|c| c.other_owners)
                .max();
            if let Some(most) = most {
                if !identity.admin && !own(&e) {
                    continue;
                }
                if identity.admin {
                    e.detail.insert("conflict".into(), json!(most));
                }
            }
        }
        out.push(e);
    }
    out
}

/// The disconnect events (the diagnostics' input), from `since` on.
pub fn disconnects(events: &[Event], since: Option<f64>) -> Vec<Disconnect> {
    let text =
        |e: &Event, k: &str| e.detail.get(k).and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string);
    events
        .iter()
        .filter(|e| DISCONNECT_KINDS.contains(&e.kind) && since.is_none_or(|s| e.at >= s))
        .map(|e| Disconnect {
            at: e.at,
            basis: e.basis,
            source: Some(e.source.clone()),
            cause: text(e, "cause").or_else(|| text(e, "from_cause")),
        })
        .collect()
}

/// The API's EVENT (INVENTORY 9.12).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PublicEvent {
    pub kind: &'static str,
    pub at: Option<String>,
    pub source: String,
    pub sources: Vec<String>,
    pub basis: Basis,
    pub ap: Option<ApRef>,
    pub band: Option<&'static str>,
    pub from_ap: Option<ApRef>,
    pub from_band: Option<&'static str>,
    pub mac: Option<String>,
    pub duration_s: Option<i64>,
    pub detail: Map<String, Value>,
}

/// The API's EVENTs; `ap` and `from_ap` as AP references (with the AP's MAC when known).
pub fn public(events: &[Event]) -> Vec<PublicEvent> {
    events
        .iter()
        .map(|e| PublicEvent {
            kind: e.kind,
            at: iso(Some(e.at)),
            source: e.source.clone(),
            sources: e.sources.clone(),
            basis: e.basis,
            ap: ap_ref(e.ap.as_deref(), e.ap_mac.as_deref()),
            band: e.band,
            from_ap: ap_ref(e.from_ap.as_deref(), e.from_ap_mac.as_deref()),
            from_band: e.from_band,
            mac: e.mac.clone(),
            duration_s: e.duration_s,
            detail: e.detail.clone(),
        })
        .collect()
}
