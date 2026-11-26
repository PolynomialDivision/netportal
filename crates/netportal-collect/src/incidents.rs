//! The job `incidents` (Python `collect/incidents.py`, INVENTORY 9.9.5): infrastructure problems
//! from the house's monitoring -> `incident` rows.
//!
//! Every run reads the signals below as per-minute range queries over the time since the last
//! evaluation (cursor `evaluated_until`) plus [`OVERLAP_S`] (at least the last 15 minutes, at most
//! [`MAX_LOOKBACK_S`] after a long pause), turns them into a state per minute and subject
//! (failing / ok / unknown) and reconciles that with the stored incidents:
//!
//! - a failing run of at least its minimum length with no stored incident overlapping it opens
//!   one (started = the run's first failing minute) and, when the run is over, closes it at the
//!   first confirmed ok minute after it;
//! - a stored open incident is closed at the first confirmed ok minute after its start; while one
//!   stays open, no other incident of the same kind and subject is opened;
//! - unknown minutes (no data, or a broader problem hides this one) neither open nor close.
//!
//! Re-evaluating the same minutes finds the stored incident and changes nothing (idempotent).
//!
//! Signals: `router_down`, `internet_down`, `internet_degraded` (loss > 5 % or RTT > 100 ms),
//! `dns_down`, `unifi_data_stale`, `ap_down` (per AP MAC, only while the UniFi data is fresh:
//! house-infra's record `unifi_ap:up` == 0, its `unpoller_device_info` series missing, or the site
//! counting disconnected APs while this AP's uptime is frozen for 3 minutes), `ap_restarted`
//! (uptime reset), `switch_down` (ICMP 3 min, web switches 10 min for unreachable reasons), and
//! `radius_down` (the FreeRADIUS container gone from cAdvisor while cAdvisor answers).
//! `switch_port_down` is not evaluated: there is no mapping of switch ports to APs. All of them
//! are direct signals: basis `measured`.

use std::collections::{BTreeMap, BTreeSet};

use netportal_core::conventions::round_to;
use netportal_core::registry;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::OffsetDateTime;

use crate::scheduler::{Context, JobError, JobResult, to_cursor};
use crate::sources::{Labels, Points, Prometheus, SourceError, normalise_mac};

pub const NAME: &str = "incidents";
const LOG: &str = "netportal.collect.incidents";

pub const STEP: i64 = 60;
pub const OVERLAP_S: i64 = 15 * 60;
pub const MAX_LOOKBACK_S: i64 = 6 * 3600;
/// An AP's uptime unchanged this long (with disconnected APs): down.
pub const FROZEN_S: i64 = 180;
/// unpoller's snapshot older than this: stale.
pub const STALE_AFTER_S: f64 = 600.0;
pub const DEGRADED_LOSS_RATIO: f64 = 0.05;
pub const DEGRADED_RTT_MS: f64 = 100.0;
/// Two restarts of an AP whose boot times are this close are the same.
pub const SAME_RESTART_S: i64 = 120;
/// An ok minute ends a problem only if nothing fails in the next 2 minutes.
pub const CLOSE_AFTER_S: i64 = 120;

/// The minimum length (s) of a failing run per kind.
pub fn min_for(kind: &str) -> i64 {
    match kind {
        "router_down" | "radius_down" => 120,
        "internet_down" | "ap_down" | "switch_down" => 180,
        "internet_degraded" | "dns_down" => 300,
        _ => 0, // unifi_data_stale
    }
}

pub const KINDS: [&str; 9] = [
    "router_down",
    "internet_down",
    "internet_degraded",
    "dns_down",
    "unifi_data_stale",
    "ap_down",
    "switch_down",
    "radius_down",
    "ap_restarted",
];

/// The small web switches are read over their slow web UIs: short timeouts are common (runs of
/// 1-4 minutes every hour), so like the house's WebSwitchDown alert only 10 minutes count, and only
/// for reasons that mean unreachable (`web_switch_down_reason`), not "someone is logged in".
pub const WEB_SWITCH_MIN_FOR: i64 = 600;
pub const WEB_SWITCH_DOWN_REASONS: [&str; 3] = ["timeout", "connection", "loader"];

pub const Q_GATEWAY: &str = r#"max(probe_success{job="blackbox_icmp",role="gateway"})"#;
pub const Q_INTERNET: &str = r#"max(probe_success{job="blackbox_icmp",role="internet"})"#;
pub const Q_LOSS: &str = "max(network_internet_packet_loss_ratio_5m)";
pub const Q_RTT: &str = "max(network_internet_rtt_ms)";
pub const Q_DNS: &str = r#"max(probe_success{job="blackbox_dns",role="gateway"})"#;
pub const Q_UNIFI_UP: &str = r#"max(up{job="unifi"})"#;
pub const Q_AGE: &str = r#"max(unpoller_prometheus_cache_age_seconds{job="unifi"})"#;
pub const Q_SITE_DISCONNECTED: &str = r#"max(unpoller_site_disconnected{job="unifi",subsystem="wlan"})"#;
pub const Q_AP_INFO: &str = r#"max by (mac, name) (unpoller_device_info{job="unifi",type="uap"})"#;
pub const Q_AP_UPTIME: &str = r#"max by (name) (unpoller_device_uptime_seconds{job="unifi",type="uap"})"#;
pub const Q_SWITCH_ICMP: &str = r#"max by (switch) (probe_success{job="switches_icmp"})"#;
pub const Q_WEB_SWITCH: &str = r#"max by (switch) (web_switch_up{job="web_switches"})"#;
pub const Q_WEB_SWITCH_BLOCKED: &str = r#"max by (switch) (web_switch_login_blocked{job="web_switches"})"#;
pub const Q_WEB_SWITCH_REASON: &str = r#"max by (switch, reason) (web_switch_down_reason{job="web_switches"})"#;
pub const Q_WEB_EXPORTER: &str = r#"max(up{job="web_switches"})"#;
pub const Q_CADVISOR: &str = r#"max(up{job="cadvisor"})"#;
pub const AP_KNOWN: &str = r#"max by (mac, name) (last_over_time(unpoller_device_info{job="unifi",type="uap"}[1d]))"#;
/// house-infra's records (wifi-aps rules; absent before 2026-10-25 and while the UniFi data is
/// stale): used where they exist, the raw series otherwise
pub const AP_UP_RECORD: &str = "max by (ap_mac, ap_name) (unifi_ap:up)";
pub const AP_UPTIME_RECORD: &str = "max by (ap_mac, ap_name) (unifi_ap:uptime:seconds)";

/// The FreeRADIUS container's `container_last_seen` (the name is validated at start).
pub fn radius_query(container: &str) -> String {
    format!(r#"max(container_last_seen{{job="cadvisor",name="{container}"}})"#)
}

/// `{ap mac: its name}` (`None`: not known).
pub type ApNames = BTreeMap<String, Option<String>>;

/// One range result.
pub type Rows = Vec<(Labels, Points)>;

/// Every signal over `[start - FROZEN_S, end]` at [`STEP`].
#[derive(Debug, Clone, Default)]
pub struct Signals {
    pub gateway: Points,
    pub internet: Points,
    pub loss: Points,
    pub rtt: Points,
    pub dns: Points,
    pub unifi_up: Points,
    pub age: Points,
    pub site_disconnected: Points,
    pub web_exporter: Points,
    pub cadvisor: Points,
    pub radius: Points,
    pub ap_uptime_rows: Rows,
    pub switch_icmp_rows: Rows,
    pub web_switch_rows: Rows,
    pub web_switch_blocked_rows: Rows,
    pub web_switch_reason_rows: Rows,
    pub ap_info_rows: Rows,
    pub ap_up_rec_rows: Rows,
    pub ap_uptime_rec_rows: Rows,
    pub ap_known_rows: Vec<(Labels, Option<f64>)>,
}

/// `{t: failing}` per minute: `Some(true)` failing, `Some(false)` ok, `None` unknown.
pub type States = BTreeMap<i64, Option<bool>>;
/// `(kind, subject)`; subject `""` for house-wide kinds.
pub type Key = (&'static str, String);

fn single(rows: Rows) -> Points {
    rows.into_iter().next().map(|(_, p)| p).unwrap_or_default()
}

fn by_label(rows: &Rows, label: &str) -> BTreeMap<String, Points> {
    let mut out: BTreeMap<String, Points> = BTreeMap::new();
    for (labels, points) in rows {
        if let Some(key) = labels.get(label).filter(|k| !k.is_empty()) {
            out.entry(key.clone()).or_default().extend(points.iter().map(|(t, v)| (*t, *v)));
        }
    }
    out
}

fn equals(value: Option<f64>, target: f64) -> Option<bool> {
    value.map(|v| v == target)
}

fn at(points: &Points, t: i64) -> Option<f64> {
    points.get(&t).copied()
}

/// The detail of an incident, from the failing minutes of its run.
#[derive(Debug, Clone, PartialEq)]
pub enum Detail {
    Fixed(Value),
    /// `{t: (loss ratio, rtt ms)}` of degraded minutes: the maxima over the run
    Degraded(BTreeMap<i64, (f64, f64)>),
    /// `{t: signal}` of failing minutes: the signals seen during the run, sorted
    Signals(BTreeMap<i64, &'static str>),
}

impl Detail {
    /// The detail of a run `[start, last_fail]`.
    pub fn for_run(&self, start: i64, last_fail: i64) -> Option<Value> {
        match self {
            Detail::Fixed(v) => Some(v.clone()),
            Detail::Degraded(minutes) => {
                let (mut loss, mut rtt) = (0.0f64, 0.0f64);
                for (l, r) in minutes.range(start..=last_fail).map(|(_, v)| v) {
                    loss = loss.max(round_to(*l, 4));
                    rtt = rtt.max(round_to(*r, 1));
                }
                Some(json!({"loss_ratio_max": loss, "rtt_ms_max": rtt}))
            }
            Detail::Signals(minutes) => {
                let seen: BTreeSet<&str> = minutes.range(start..=last_fail).map(|(_, s)| *s).collect();
                (!seen.is_empty()).then(|| json!({"signal": seen.into_iter().collect::<Vec<_>>()}))
            }
        }
    }
}

// --- states per minute ----------------------------------------------------------------------------

/// The house-wide signals.
pub fn house_states(grid: &[i64], s: &Signals) -> (BTreeMap<Key, States>, BTreeMap<Key, Detail>) {
    let mut router = States::new();
    let mut internet = States::new();
    let mut degraded = States::new();
    let mut dns = States::new();
    let mut stale = States::new();
    let mut bad = BTreeMap::new();
    for &t in grid {
        let (gw, net, dn) = (at(&s.gateway, t), at(&s.internet, t), at(&s.dns, t));
        let (loss, rtt) = (at(&s.loss, t), at(&s.rtt, t));
        router.insert(t, equals(gw, 0.0));
        internet.insert(t, if gw == Some(1.0) { net.map(|n| n == 0.0) } else { None });
        let state = if gw == Some(1.0) && net == Some(1.0) {
            let is_bad = loss.is_some_and(|l| l > DEGRADED_LOSS_RATIO) || rtt.is_some_and(|r| r > DEGRADED_RTT_MS);
            if is_bad {
                bad.insert(t, (loss.unwrap_or(0.0), rtt.unwrap_or(0.0)));
            }
            (loss.is_some() || rtt.is_some()).then_some(is_bad)
        } else if gw == Some(0.0) || net == Some(0.0) {
            Some(false) // a broader incident covers it
        } else {
            None
        };
        degraded.insert(t, state);
        dns.insert(t, if gw == Some(1.0) && net == Some(1.0) { equals(dn, 0.0) } else { None });
        let (up, age) = (at(&s.unifi_up, t), at(&s.age, t));
        // no up sample: Prometheus itself has nothing then
        stale.insert(t, up.map(|up| up == 0.0 || age.is_none_or(|a| a > STALE_AFTER_S)));
    }
    let key = |k: &'static str| (k, String::new());
    let states = BTreeMap::from([
        (key("router_down"), router),
        (key("internet_down"), internet),
        (key("internet_degraded"), degraded),
        (key("dns_down"), dns),
        (key("unifi_data_stale"), stale),
    ]);
    (states, BTreeMap::from([(key("internet_degraded"), Detail::Degraded(bad))]))
}

/// The minutes with fresh UniFi data (unpoller scraped, snapshot at most 10 minutes old).
pub fn fresh_minutes(grid: &[i64], s: &Signals) -> BTreeSet<i64> {
    grid.iter()
        .copied()
        .filter(|&t| at(&s.unifi_up, t) == Some(1.0) && at(&s.age, t).is_some_and(|a| a <= STALE_AFTER_S))
        .collect()
}

/// `{ap mac: {t: uptime}}`: the raw `unpoller_device_uptime_seconds` (by name, mapped to the MAC
/// the name had at that minute, else the only MAC the name had) and, where it exists, the record
/// `unifi_ap:uptime:seconds` (by `ap_mac`).
pub fn ap_uptimes(s: &Signals) -> BTreeMap<String, Points> {
    let mut at_minute: BTreeMap<(String, i64), String> = BTreeMap::new();
    let mut macs_of: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (labels, points) in &s.ap_info_rows {
        let (Some(mac), Some(name)) = (labels.get("mac").and_then(|m| normalise_mac(m)), labels.get("name")) else {
            continue;
        };
        macs_of.entry(name.clone()).or_default().insert(mac.clone());
        for t in points.keys() {
            at_minute.insert((name.clone(), *t), mac.clone());
        }
    }
    let only: BTreeMap<&String, &String> = macs_of
        .iter()
        .filter(|(_, m)| m.len() == 1)
        .filter_map(|(name, m)| m.iter().next().map(|mac| (name, mac)))
        .collect();
    let mut out: BTreeMap<String, Points> = BTreeMap::new();
    for (labels, points) in &s.ap_uptime_rows {
        let Some(name) = labels.get("name") else { continue };
        for (t, v) in points {
            let mac = at_minute.get(&(name.clone(), *t)).or_else(|| only.get(name).copied());
            if let Some(mac) = mac {
                out.entry(mac.clone()).or_default().insert(*t, *v);
            }
        }
    }
    for (labels, points) in &s.ap_uptime_rec_rows {
        if let Some(mac) = labels.get("ap_mac").and_then(|m| normalise_mac(m)) {
            out.entry(mac).or_default().extend(points.iter().map(|(t, v)| (*t, *v)));
        }
    }
    out
}

/// The AP's uptime did not change over the last [`FROZEN_S`] (or is 0) at `t`; `None`: unknown.
fn frozen(points: &Points, t: i64) -> Option<bool> {
    let now = at(points, t)?;
    if now == 0.0 {
        return Some(true);
    }
    let mut all_equal = true;
    for k in 1..=FROZEN_S / STEP {
        let before = at(points, t - k * STEP)?;
        all_equal &= before == now;
    }
    Some(all_equal)
}

/// The `ap_down` states of the known APs (C17 of the last day, C9, the record), their names (the
/// name at the latest minute of `unpoller_device_info`, else the known or the record's name) and
/// details (which signals said down).
pub fn ap_states(grid: &[i64], s: &Signals) -> (BTreeMap<Key, States>, ApNames, BTreeMap<Key, Detail>) {
    let mut names: BTreeMap<String, Option<String>> = BTreeMap::new();
    let mut present: BTreeMap<String, BTreeSet<i64>> = BTreeMap::new();
    let mut latest: BTreeMap<String, (i64, String)> = BTreeMap::new();
    for (labels, _) in &s.ap_known_rows {
        if let Some(mac) = labels.get("mac").and_then(|m| normalise_mac(m)) {
            let name = labels.get("name").filter(|n| !n.is_empty()).cloned();
            let entry = names.entry(mac).or_default();
            if name.is_some() {
                *entry = name;
            }
        }
    }
    for (labels, points) in &s.ap_info_rows {
        let Some(mac) = labels.get("mac").and_then(|m| normalise_mac(m)) else { continue };
        names.entry(mac.clone()).or_default();
        present.entry(mac.clone()).or_default().extend(points.keys().copied());
        if let (Some(name), Some(last)) = (labels.get("name").filter(|n| !n.is_empty()), points.keys().next_back())
            && latest.get(&mac).is_none_or(|(t, _)| *last >= *t)
        {
            latest.insert(mac, (*last, name.clone()));
        }
    }
    for (mac, (_, name)) in latest {
        names.insert(mac, Some(name));
    }
    let mut record: BTreeMap<String, Points> = BTreeMap::new();
    for (labels, points) in &s.ap_up_rec_rows {
        if let Some(mac) = labels.get("ap_mac").and_then(|m| normalise_mac(m)) {
            let entry = names.entry(mac.clone()).or_default();
            if entry.is_none() {
                *entry = labels.get("ap_name").filter(|n| !n.is_empty()).cloned();
            }
            record.entry(mac).or_default().extend(points.iter().map(|(t, v)| (*t, *v)));
        }
    }
    let uptimes = ap_uptimes(s);
    let fresh = fresh_minutes(grid, s);
    let none = Points::new();
    let mut states = BTreeMap::new();
    let mut details = BTreeMap::new();
    for mac in names.keys() {
        let mut mine = States::new();
        let mut signals = BTreeMap::new();
        for &t in grid {
            let state = if !fresh.contains(&t) {
                None
            } else if record.get(mac).and_then(|r| at(r, t)) == Some(0.0) {
                signals.insert(t, "unifi_ap_up");
                Some(true)
            } else if !present.get(mac).is_some_and(|p| p.contains(&t)) {
                signals.insert(t, "device_missing");
                Some(true)
            } else if at(&s.site_disconnected, t).unwrap_or(0.0) > 0.0 {
                // a disconnected but adopted AP keeps being exported with its last values
                let state = frozen(uptimes.get(mac).unwrap_or(&none), t);
                if state == Some(true) {
                    signals.insert(t, "site_disconnected");
                }
                state
            } else {
                Some(false)
            };
            mine.insert(t, state);
        }
        let key = ("ap_down", mac.clone());
        states.insert(key.clone(), mine);
        details.insert(key, Detail::Signals(signals));
    }
    (states, names, details)
}

/// An uptime reset of an AP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Restart {
    pub mac: String,
    pub name: Option<String>,
    /// boot time (snapshot time - uptime)
    pub boot: i64,
    /// when it was seen running again (the snapshot's time)
    pub back: i64,
    /// the minute the reset was seen
    pub seen: i64,
}

/// The uptime resets over `grid` (each against the AP's previous value in the grid).
pub fn ap_restarts(grid: &[i64], s: &Signals, names: &BTreeMap<String, Option<String>>) -> Vec<Restart> {
    let mut out = Vec::new();
    for (mac, points) in ap_uptimes(s) {
        let mut prev: Option<f64> = None;
        for &t in grid {
            let Some(v) = at(&points, t) else { continue };
            if prev.is_some_and(|p| v + (STEP as f64) < p) {
                let snapshot = t - at(&s.age, t).unwrap_or(0.0).trunc() as i64;
                out.push(Restart {
                    mac: mac.clone(),
                    name: names.get(&mac).cloned().flatten(),
                    boot: (snapshot as f64 - v).trunc() as i64,
                    back: snapshot,
                    seen: t,
                });
            }
            prev = Some(v);
        }
    }
    out
}

fn either(a: Option<bool>, b: Option<bool>) -> Option<bool> {
    a.or(b)
}

/// The `switch_down` states per switch, their details and minimum lengths. A switch probed by
/// ICMP is judged by ICMP where it is known (its web UI being slow is no outage), else by its web
/// exporter; a switch with web data only needs [`WEB_SWITCH_MIN_FOR`].
pub fn switch_states(grid: &[i64], s: &Signals) -> (BTreeMap<Key, States>, BTreeMap<Key, Detail>, BTreeMap<Key, i64>) {
    let icmp = by_label(&s.switch_icmp_rows, "switch");
    let web = by_label(&s.web_switch_rows, "switch");
    let blocked = by_label(&s.web_switch_blocked_rows, "switch");
    let mut reasons: BTreeMap<(String, i64), String> = BTreeMap::new();
    for (labels, points) in &s.web_switch_reason_rows {
        let (Some(switch), Some(reason)) = (labels.get("switch"), labels.get("reason")) else { continue };
        for (t, v) in points {
            if *v > 0.0 {
                reasons.insert((switch.clone(), *t), reason.clone());
            }
        }
    }
    let (mut states, mut details, mut min) = (BTreeMap::new(), BTreeMap::new(), BTreeMap::new());
    for (name, points) in &icmp {
        let key = ("switch_down", name.clone());
        let mine: States = grid
            .iter()
            .map(|&t| (t, if at(&s.gateway, t) == Some(1.0) { equals(at(points, t), 0.0) } else { None }))
            .collect();
        states.insert(key.clone(), mine);
        details.insert(key.clone(), Detail::Fixed(json!({"source": "switches_icmp"})));
        min.insert(key, min_for("switch_down"));
    }
    let no_points = Points::new();
    for (name, points) in &web {
        let key = ("switch_down", name.clone());
        let is_blocked = blocked.get(name).unwrap_or(&no_points);
        let mine: States = grid
            .iter()
            .map(|&t| {
                let up = at(points, t);
                let reason = reasons.get(&(name.clone(), t));
                let readable = at(&s.web_exporter, t) == Some(1.0)
                    && at(is_blocked, t) != Some(1.0)
                    && !(up == Some(0.0) && reason.is_some_and(|r| !WEB_SWITCH_DOWN_REASONS.contains(&r.as_str())));
                // cannot be read (someone logged in ...): not down, unknown
                (t, if readable { equals(up, 0.0) } else { None })
            })
            .collect();
        match states.get_mut(&key) {
            Some(by_icmp) => {
                for (t, state) in by_icmp.iter_mut() {
                    *state = either(*state, mine.get(t).copied().flatten());
                }
            }
            None => {
                states.insert(key.clone(), mine);
                details.insert(key.clone(), Detail::Fixed(json!({"source": "web_switches"})));
                min.insert(key, WEB_SWITCH_MIN_FOR);
            }
        }
    }
    (states, details, min)
}

/// `radius_down`: the container's series is missing while cAdvisor answers.
pub fn radius_states(grid: &[i64], s: &Signals) -> BTreeMap<Key, States> {
    let states =
        grid.iter().map(|&t| (t, (at(&s.cadvisor, t) == Some(1.0)).then(|| !s.radius.contains_key(&t)))).collect();
    BTreeMap::from([(("radius_down", String::new()), states)])
}

// --- reconciliation ----------------------------------------------------------------------------------

/// `t` is ok and stays so: no failing minute in `(t, t + CLOSE_AFTER_S]`, and the window reaches
/// that far (else the next run decides).
fn confirmed_ok(points: &States, grid: &[i64], t: i64) -> bool {
    let Some(&last) = grid.last() else { return false };
    if points.get(&t).copied().flatten() != Some(false) || t + CLOSE_AFTER_S > last {
        return false;
    }
    !points.range(t + 1..=t + CLOSE_AFTER_S).any(|(_, s)| *s == Some(true))
}

/// A failing run: its first failing minute, the confirmed ok minute after it (`None`: still
/// failing or not confirmed yet), its last failing minute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Run {
    pub start: i64,
    pub end: Option<i64>,
    pub last_fail: i64,
}

/// The failing runs; unknown minutes neither end nor extend a run, a single ok minute does not
/// split one.
pub fn runs(points: &States, grid: &[i64]) -> Vec<Run> {
    let mut out = Vec::new();
    let mut current: Option<(i64, i64)> = None;
    for &t in grid {
        match points.get(&t).copied().flatten() {
            Some(true) => current = Some((current.map_or(t, |c| c.0), t)),
            _ => {
                if let Some((start, last_fail)) = current
                    && confirmed_ok(points, grid, t)
                {
                    out.push(Run { start, end: Some(t), last_fail });
                    current = None;
                }
            }
        }
    }
    if let Some((start, last_fail)) = current {
        out.push(Run { start, end: None, last_fail });
    }
    out
}

/// A stored incident of one kind and subject (Unix seconds).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stored {
    pub started: i64,
    pub ended: Option<i64>,
}

/// What [`reconcile`] decided, in order.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    /// close the open incident at this minute
    Close(i64),
    /// open one (closed at `end` if the run is over)
    Open { start: i64, end: Option<i64>, detail: Option<Value> },
}

/// The opens and closes of one kind and subject from its per-minute states. `stored`: its
/// incidents overlapping the window (updated in place).
pub fn reconcile(
    points: &States,
    grid: &[i64],
    stored: &mut Vec<Stored>,
    min_for: i64,
    detail: Option<&Detail>,
) -> Vec<Action> {
    let mut actions = Vec::new();
    for inc in stored.iter_mut().filter(|i| i.ended.is_none()) {
        if let Some(end) = grid.iter().copied().find(|&t| t > inc.started && confirmed_ok(points, grid, t)) {
            actions.push(Action::Close(end));
            inc.ended = Some(end);
        }
    }
    if stored.iter().any(|i| i.ended.is_none()) {
        // still open: one open incident per kind and subject; nothing else is opened meanwhile
        return actions;
    }
    for run in runs(points, grid) {
        let length = run.end.unwrap_or(run.last_fail + STEP) - run.start;
        if length < min_for.max(if run.end.is_none() { STEP } else { 0 }) {
            continue;
        }
        if stored.iter().any(|i| i.started <= run.last_fail && i.ended.is_none_or(|e| e >= run.start)) {
            continue;
        }
        actions.push(Action::Open {
            start: run.start,
            end: run.end,
            detail: detail.and_then(|d| d.for_run(run.start, run.last_fail)),
        });
        stored.push(Stored { started: run.start, ended: run.end });
    }
    actions
}

// --- the job -----------------------------------------------------------------------------------------

/// `{"evaluated_until": unix, "last_run": {"opened", "closed"}}`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cursor {
    #[serde(default)]
    pub evaluated_until: Option<i64>,
    #[serde(default)]
    pub last_run: Done,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Done {
    pub opened: u64,
    pub closed: u64,
}

/// `[start, end]` (minutes) to evaluate now.
pub fn window(now: i64, evaluated_until: Option<i64>) -> (i64, i64) {
    let now = now.div_euclid(STEP) * STEP;
    let mut start = now - OVERLAP_S;
    if let Some(last) = evaluated_until.filter(|l| *l > 0) {
        start = start.min(last.div_euclid(STEP) * STEP - OVERLAP_S);
    }
    (start.max(now - MAX_LOOKBACK_S), now)
}

/// Every signal over `[start - FROZEN_S, end]`.
pub async fn gather(prom: &Prometheus, start: i64, end: i64, radius_container: &str) -> Result<Signals, SourceError> {
    let first = start - FROZEN_S;
    let range = |q: String| async move { prom.range(&q, first, end, STEP).await };
    Ok(Signals {
        gateway: single(range(Q_GATEWAY.into()).await?),
        internet: single(range(Q_INTERNET.into()).await?),
        loss: single(range(Q_LOSS.into()).await?),
        rtt: single(range(Q_RTT.into()).await?),
        dns: single(range(Q_DNS.into()).await?),
        unifi_up: single(range(Q_UNIFI_UP.into()).await?),
        age: single(range(Q_AGE.into()).await?),
        site_disconnected: single(range(Q_SITE_DISCONNECTED.into()).await?),
        web_exporter: single(range(Q_WEB_EXPORTER.into()).await?),
        cadvisor: single(range(Q_CADVISOR.into()).await?),
        ap_uptime_rows: range(Q_AP_UPTIME.into()).await?,
        switch_icmp_rows: range(Q_SWITCH_ICMP.into()).await?,
        web_switch_rows: range(Q_WEB_SWITCH.into()).await?,
        web_switch_blocked_rows: range(Q_WEB_SWITCH_BLOCKED.into()).await?,
        web_switch_reason_rows: range(Q_WEB_SWITCH_REASON.into()).await?,
        ap_info_rows: range(Q_AP_INFO.into()).await?,
        ap_up_rec_rows: range(AP_UP_RECORD.into()).await?,
        ap_uptime_rec_rows: range(AP_UPTIME_RECORD.into()).await?,
        ap_known_rows: prom.vector(AP_KNOWN, Some(end)).await?,
        radius: single(range(radius_query(radius_container)).await?),
    })
}

/// The evaluation of a window.
#[derive(Debug, Clone, Default)]
pub struct Evaluation {
    pub grid: Vec<i64>,
    pub states: BTreeMap<Key, States>,
    pub names: BTreeMap<Key, String>,
    pub details: BTreeMap<Key, Detail>,
    pub min_for: BTreeMap<Key, i64>,
    pub restarts: Vec<Restart>,
}

pub fn evaluate(s: &Signals, start: i64, end: i64) -> Evaluation {
    let grid: Vec<i64> = (start..=end).step_by(STEP as usize).collect();
    let (mut states, mut details) = house_states(&grid, s);
    let (ap, ap_names, ap_details) = ap_states(&grid, s);
    states.extend(ap);
    details.extend(ap_details);
    let (sw, sw_details, mut min) = switch_states(&grid, s);
    let mut names: BTreeMap<Key, String> = BTreeMap::new();
    for key in sw.keys() {
        names.insert(key.clone(), key.1.clone());
    }
    states.extend(sw);
    details.extend(sw_details);
    states.extend(radius_states(&grid, s));
    for (mac, name) in &ap_names {
        if let Some(name) = name {
            names.insert(("ap_down", mac.clone()), name.clone());
        }
    }
    for key in states.keys() {
        min.entry(key.clone()).or_insert_with(|| min_for(key.0));
    }
    let restart_grid: Vec<i64> = (start - FROZEN_S..=end).step_by(STEP as usize).collect();
    let restarts = ap_restarts(&restart_grid, s, &ap_names);
    Evaluation { grid, states, names, details, min_for: min, restarts }
}

fn dt(unix: i64) -> Result<OffsetDateTime, JobError> {
    OffsetDateTime::from_unix_timestamp(unix).map_err(|_| JobError::Other("time out of range".into()))
}

pub async fn run(ctx: &mut Context) -> JobResult {
    let cursor: Cursor = ctx.cursor_as();
    let (start, end) = window(ctx.now.unix_timestamp(), cursor.evaluated_until);
    let prom = ctx.prometheus()?;
    let signals = gather(&prom, start, end, &ctx.settings.radius_container).await?;
    let ev = evaluate(&signals, start, end);
    let mut stored: BTreeMap<(String, String), Vec<Stored>> = BTreeMap::new();
    for inc in registry::incidents(&mut ctx.db, dt(start - MAX_LOOKBACK_S)?, None, Some(&KINDS), None).await? {
        stored
            .entry((inc.kind, inc.subject))
            .or_default()
            .push(Stored { started: inc.started.unix_timestamp(), ended: inc.ended.map(|e| e.unix_timestamp()) });
    }
    let mut done = Done::default();
    for (key, points) in &ev.states {
        let (kind, subject) = (key.0, key.1.as_str());
        let mine = stored.entry((kind.to_string(), subject.to_string())).or_default();
        let min = ev.min_for.get(key).copied().unwrap_or_else(|| min_for(kind));
        let name = ev.names.get(key).map(String::as_str);
        for action in reconcile(points, &ev.grid, mine, min, ev.details.get(key)) {
            match action {
                Action::Close(at) => {
                    done.closed += registry::close_incident(&mut ctx.db, kind, subject, dt(at)?).await?
                }
                Action::Open { start, end, detail } => {
                    registry::open_incident(&mut ctx.db, kind, subject, name, dt(start)?, "measured", detail.as_ref())
                        .await?;
                    done.opened += 1;
                    if let Some(end) = end {
                        done.closed += registry::close_incident(&mut ctx.db, kind, subject, dt(end)?).await?;
                    }
                }
            }
        }
    }
    for r in &ev.restarts {
        let known = stored.entry(("ap_restarted".to_string(), r.mac.clone())).or_default();
        if known.iter().any(|i| (i.started - r.boot).abs() <= SAME_RESTART_S) {
            continue;
        }
        let detail = json!({"seen_back": r.back});
        registry::open_incident(
            &mut ctx.db,
            "ap_restarted",
            &r.mac,
            r.name.as_deref(),
            dt(r.boot)?,
            "measured",
            Some(&detail),
        )
        .await?;
        registry::close_incident(&mut ctx.db, "ap_restarted", &r.mac, dt(r.back.max(r.boot))?).await?;
        known.push(Stored { started: r.boot, ended: Some(r.back) });
        done.opened += 1;
    }
    ctx.db.commit().await?;
    if done.opened > 0 || done.closed > 0 {
        tracing::info!(target: LOG, "incidents: {} opened, {} closed", done.opened, done.closed);
    }
    to_cursor(&Cursor { evaluated_until: Some(end), last_run: done })
}

#[cfg(test)]
mod tests {
    //! Python test_collect_incidents.py ReconcileTests (reconcile alone, on hand-made states) and
    //! the pure rules; the job's tests are in tests/collect_incidents.rs.
    use super::*;

    const T0: i64 = 1_792_929_600;

    /// '.' ok, 'x' failing, '?' unknown, one per minute from T0.
    fn states(text: &str) -> (Vec<i64>, States) {
        let grid: Vec<i64> = (0..text.len() as i64).map(|i| T0 + 60 * i).collect();
        let points = grid
            .iter()
            .zip(text.chars())
            .map(|(t, c)| {
                (
                    *t,
                    match c {
                        '.' => Some(false),
                        'x' => Some(true),
                        _ => None,
                    },
                )
            })
            .collect();
        (grid, points)
    }

    #[test]
    fn test_unknown_neither_opens_nor_closes() {
        let (grid, points) = states("xxxx????????");
        let mut stored = Vec::new();
        let actions = reconcile(&points, &grid, &mut stored, min_for("router_down"), None);
        assert_eq!(actions, [Action::Open { start: T0, end: None, detail: None }]);
        let (grid, points) = states("????????????");
        assert_eq!(reconcile(&points, &grid, &mut stored, min_for("router_down"), None), []);
        assert_eq!(stored, [Stored { started: T0, ended: None }]);
    }

    #[test]
    fn test_two_separate_outages() {
        let (grid, points) = states("xxxx.....xxxx.....");
        let actions = reconcile(&points, &grid, &mut Vec::new(), min_for("router_down"), None);
        assert_eq!(
            actions,
            [
                Action::Open { start: T0, end: Some(T0 + 240), detail: None },
                Action::Open { start: T0 + 540, end: Some(T0 + 780), detail: None },
            ]
        );
    }

    #[test]
    fn test_a_later_open_incident_is_not_closed_by_an_earlier_run() {
        // a stored incident still open: an earlier run found in the window opens nothing
        let (grid, points) = states("xxxx.....xxxx");
        let mut stored = vec![Stored { started: T0 + 540, ended: None }];
        assert_eq!(reconcile(&points, &grid, &mut stored, 120, None), []);
        assert_eq!(stored, [Stored { started: T0 + 540, ended: None }]);
    }

    #[test]
    fn test_runs_and_confirmation() {
        let (grid, points) = states("xx.x...");
        assert_eq!(runs(&points, &grid), [Run { start: T0, end: Some(T0 + 240), last_fail: T0 + 180 }]);
        let (grid, points) = states("xx..");
        assert_eq!(runs(&points, &grid), [Run { start: T0, end: None, last_fail: T0 + 60 }]); // not confirmed yet
    }

    #[test]
    fn test_window() {
        let now = T0 + 5;
        assert_eq!(window(now, None), (T0 - 900, T0));
        assert_eq!(window(now, Some(T0 - 2400)), (T0 - 3300, T0));
        assert_eq!(window(now, Some(T0 - 86400)), (T0 - 6 * 3600, T0));
        assert_eq!(window(now, Some(T0)), (T0 - 900, T0));
    }

    #[test]
    fn test_degraded_detail_is_the_runs() {
        let detail =
            Detail::Degraded(BTreeMap::from([(T0, (0.2, 30.0)), (T0 + 60, (0.1, 250.04)), (T0 + 600, (0.9, 900.0))]));
        assert_eq!(detail.for_run(T0, T0 + 60), Some(json!({"loss_ratio_max": 0.2, "rtt_ms_max": 250.0})));
    }

    #[test]
    fn test_frozen() {
        let points: Points = [(0, 5.0), (60, 5.0), (120, 5.0), (180, 5.0), (240, 7.0)].into();
        assert_eq!(frozen(&points, 180), Some(true));
        assert_eq!(frozen(&points, 240), Some(false));
        assert_eq!(frozen(&points, 120), None); // too little history
        assert_eq!(frozen(&[(0, 0.0)].into(), 0), Some(true));
        assert_eq!(frozen(&points, 300), None);
    }
}
