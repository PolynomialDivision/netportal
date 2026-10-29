//! Telemetry: the detail page's history (`telemetry/history.py`, INVENTORY 9.9.3): charts and the
//! connection timeline of one device.
//!
//! Ranges: 24h, 7d, 30d, 90d from Prometheus (step 300, 1800, 7200, 21600 s), stitched over the
//! device's MAC windows; 1y and all from the nightly rollups (`device_day`, step "day"). Every
//! chart is one `by (mac)` query for all the device's MACs of the range; a sample counts only
//! inside the window of its MAC ([`Identity::segments`]: minus what is withheld from a resident).
//! A chart point `(t - step, t]` counts when it holds fresh Wi-Fi data and lies, at least in
//! part, in one of the MAC's windows (a point that straddles a window's start averages up to one
//! step of before; windows of different owners that overlap are conflicts and withheld whole).
//!
//! HISTORY: `{range, step_s, step, start, end, telemetry, data_from, withheld, withheld_spans |
//! conflicts, series, timeline, timeline_truncated, timeline_days, sources}`; `start`, `end`,
//! `data_from` and the series' times are Unix seconds (a time series), the timeline's ISO.

use std::collections::{BTreeMap, BTreeSet};

use indexmap::IndexMap;
use jiff::Timestamp;
use jiff::civil::Date as CivilDate;
use jiff::tz::TimeZone;
use netportal_core::registry::{DeviceDay, DeviceRow, Incident};
use serde::Serialize;

use super::Page;
use super::client::{Budget, LONG_CACHE_SECONDS, SUMMARY_CACHE_SECONDS, Unavailable};
use super::common::{fit, fit_int, moment, normalise_mac, selectors, trunc_int, unix};
use super::identity::{self, Identity, PublicConflict, data_bound};
use super::live::{Digits, OFF, UNAVAILABLE, ap_map, fill};
use super::store::{Result, Store};
use super::timeline::{self as tl, ApMap, Event, MAX_EVENTS, Point, PublicEvent};
use crate::diagnostics::STALE_AFTER_S;

/// A history range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Range {
    H24,
    D7,
    D30,
    D90,
    Y1,
    All,
}

/// The ranges' names (the API's `?range=`).
pub const HISTORY_RANGES: [&str; 6] = ["24h", "7d", "30d", "90d", "1y", "all"];
/// `all`: at most this many days.
pub const ALL_MAX_DAYS: i64 = 3660;
/// The registry keeps RADIUS, accounting and UniFi events this long (the prune).
pub const EVENT_RETENTION_DAYS: f64 = 400.0;
/// Registry limits per source and range (the timeline is bounded, then cut to [`MAX_EVENTS`]).
pub const EVENT_LIMIT_AUTH: i64 = 1000;
pub const EVENT_LIMIT_ACCT: i64 = 1000;
pub const EVENT_LIMIT_UNIFI: i64 = 2000;
/// The house's zone when none is given (`NETPORTAL_TIMEZONE`'s default).
pub const TIMEZONE: &str = "Europe/Berlin";

impl Range {
    pub fn parse(key: &str) -> Option<Range> {
        Some(match key {
            "24h" => Range::H24,
            "7d" => Range::D7,
            "30d" => Range::D30,
            "90d" => Range::D90,
            "1y" => Range::Y1,
            "all" => Range::All,
            _ => return None,
        })
    }

    pub fn key(self) -> &'static str {
        match self {
            Range::H24 => "24h",
            Range::D7 => "7d",
            Range::D30 => "30d",
            Range::D90 => "90d",
            Range::Y1 => "1y",
            Range::All => "all",
        }
    }

    /// Prometheus ranges: `(seconds, chart step, timeline resolution)`. The timeline reads the
    /// association start at the resolution; the charts average per step.
    pub fn prometheus(self) -> Option<(i64, i64, i64)> {
        Some(match self {
            Range::H24 => (86400, 300, 60),
            Range::D7 => (7 * 86400, 1800, 60),
            Range::D30 => (30 * 86400, 7200, 120),
            Range::D90 => (90 * 86400, 21600, 300),
            _ => return None,
        })
    }

    /// Day ranges from the rollups: `Some(days)` (`None` inside: since the first window).
    pub fn days(self) -> Option<Option<i64>> {
        match self {
            Range::Y1 => Some(Some(365)),
            Range::All => Some(None),
            _ => None,
        }
    }

    /// The Prometheus cache's TTL for this range's queries.
    pub fn ttl(self) -> f64 {
        match self {
            Range::H24 => 15.0,
            Range::D7 => SUMMARY_CACHE_SECONDS,
            _ => LONG_CACHE_SECONDS,
        }
    }
}

/// H3-H10: chart -> (PromQL with `$STEP` seconds, rounding).
pub const CHARTS: [(&str, &str, Digits); 8] = [
    (
        "signal_dbm",
        r#"avg by (mac) (avg_over_time(unpoller_client_radio_signal_db{job="unifi",$SEL}[$STEPs]))"#,
        Digits::Dp(1),
    ),
    ("health", "avg by (mac) (avg_over_time(wifi_client_health_score{$SEL}[$STEPs]))", Digits::Dp(1)),
    (
        "rx_bps",
        r#"sum by (mac) (rate(unpoller_client_transmit_bytes_total{job="unifi",$MAC}[$STEPs]) and on (mac) max_over_time($U[$STEPs])) * 8"#,
        Digits::Int,
    ),
    (
        "tx_bps",
        r#"sum by (mac) (rate(unpoller_client_receive_bytes_total{job="unifi",$MAC}[$STEPs]) and on (mac) max_over_time($U[$STEPs])) * 8"#,
        Digits::Int,
    ),
    (
        "link_rx_bps",
        r#"avg by (mac) (avg_over_time(unpoller_client_radio_transmit_rate_bps{job="unifi",$SEL}[$STEPs]))"#,
        Digits::Int,
    ),
    (
        "link_tx_bps",
        r#"avg by (mac) (avg_over_time(unpoller_client_radio_receive_rate_bps{job="unifi",$SEL}[$STEPs]))"#,
        Digits::Int,
    ),
    ("snr_db", "avg by (mac) (avg_over_time(wifi_client_snr_db{$SEL}[$STEPs]))", Digits::Dp(1)),
    // the rule has no essid: only while the house network's uptime series is there
    (
        "retry_ratio",
        "avg by (mac) (avg_over_time(wifi_client_retry_ratio{$MAC}[$STEPs])) and on (mac) max by (mac) (max_over_time($U[$STEPs]))",
        Digits::Dp(4),
    ),
];
/// Rates add up over MACs at one time (there is one at a time, rarely two during a change).
pub const SUMMED: [&str; 2] = ["rx_bps", "tx_bps"];
/// The series of every range (day ranges add `signal_p10_dbm`).
pub const SERIES: [&str; 9] =
    ["signal_dbm", "health", "rx_bps", "tx_bps", "link_rx_bps", "link_tx_bps", "snr_db", "retry_ratio", "online"];
/// H1: the snapshot age per resolution step (`$SPAN` = `seconds+step s : res s`).
pub const AGES: &str = r#"max(unpoller_prometheus_cache_age_seconds{job="unifi"})$SPAN"#;
/// H2: the association start per (mac, ap, radio).
pub const ASSOCIATIONS: &str =
    "(max by (mac, ap_name, radio) (timestamp($U) - $U) - on() group_left() ($AGE or vector(0)))$SPAN";

/// A series value: an integer for counted and rate series, else a number.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Num {
    Int(i64),
    Float(f64),
}

impl Num {
    pub fn as_f64(self) -> f64 {
        match self {
            Num::Int(i) => i as f64,
            Num::Float(f) => f,
        }
    }
}

/// `[[t, value or null], ...]` (Unix seconds).
pub type Series = Vec<(i64, Option<Num>)>;

/// HISTORY (INVENTORY 9.12).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct History {
    pub range: &'static str,
    pub step_s: i64,
    /// `null` / `"day"`
    pub step: Option<&'static str>,
    pub start: i64,
    pub end: i64,
    pub telemetry: &'static str,
    pub data_from: Option<i64>,
    /// `"mac_conflict"`: a resident, everything withheld
    pub withheld: Option<&'static str>,
    /// residents: the spans withheld (`[]` for admins)
    pub withheld_spans: Vec<PublicConflict>,
    /// admins: the conflicts (`[]` for residents)
    pub conflicts: Vec<PublicConflict>,
    pub series: IndexMap<&'static str, Series>,
    pub timeline: Vec<PublicEvent>,
    pub timeline_truncated: bool,
    pub timeline_days: Option<i64>,
    pub sources: Vec<String>,
}

/// The house's time zone for day boundaries (`Europe/Berlin` when none is given; UTC if unknown).
pub fn zone(name: Option<&str>) -> TimeZone {
    netportal_core::conventions::zone(name.unwrap_or(TIMEZONE)).unwrap_or(TimeZone::UTC)
}

/// The HISTORY skeleton: the grid's bounds (the end minute-aligned for cache hits), empty series.
pub fn empty_history(range: Range, telemetry: &'static str, now: f64, since: Option<f64>) -> History {
    let end = (now / 60.0).floor() as i64 * 60;
    let (start, step_s, step) = match range.prometheus() {
        Some((seconds, step, _)) => (end - seconds, step, None),
        None => (end - range.days().flatten().unwrap_or(1) * 86400, 86400, Some("day")),
    };
    History {
        range: range.key(),
        step_s,
        step,
        start,
        end,
        telemetry,
        data_from: since.and_then(trunc_int),
        withheld: None,
        withheld_spans: Vec::new(),
        conflicts: Vec::new(),
        series: SERIES.iter().map(|n| (*n, Vec::new())).collect(),
        timeline: Vec::new(),
        timeline_truncated: false,
        timeline_days: None,
        sources: Vec::new(),
    }
}

fn grid(start: i64, end: i64, step: i64) -> Vec<i64> {
    (start..=end).step_by(step.max(1) as usize).collect()
}

/// What the history is asked for.
#[derive(Debug, Clone, Default)]
pub struct HistoryOptions {
    pub admin: bool,
    /// the request's time (default: now)
    pub now: Option<f64>,
    /// the device's identity when the caller has it (else read: all windows)
    pub identity: Option<Identity>,
    /// the AP map when the caller has it (else asked when Prometheus answers)
    pub ap_map: Option<ApMap>,
    /// the house's zone (`NETPORTAL_TIMEZONE`; default [`zone`])
    pub tz: Option<TimeZone>,
}

/// The detail page's charts and connection timeline for one device: its windows and conflicts,
/// the registry's RADIUS, accounting and UniFi events, the incidents and (1y, all) the rollups.
/// Without a Prometheus client telemetry is `off` (the registry's events still come); when it
/// does not answer, `unavailable` with empty series.
pub async fn history<S: Store>(
    page: &Page,
    store: &mut S,
    row: &DeviceRow,
    range: Range,
    opts: HistoryOptions,
) -> Result<History> {
    let now = opts.now.unwrap_or_else(super::live::now);
    let identity = match opts.identity {
        Some(identity) => identity,
        None => identity::from_registry(store, std::slice::from_ref(row), now, opts.admin, None)
            .await?
            .swap_remove(&row.id)
            .unwrap_or_else(|| Identity::new(&row.id.to_string(), Vec::new(), Vec::new(), opts.admin, now)),
    };
    let data_from = identity
        .data_from()
        .or_else(|| row.calling_station.as_deref().and_then(normalise_mac).is_none().then(|| data_bound(row)));
    let mut payload = empty_history(range, page.telemetry(), now, data_from);
    if !identity.admin && !identity.windows.is_empty() && identity.segments(None, None).is_empty() {
        payload.withheld = Some("mac_conflict"); // all of it is in a conflict: nothing at all
        return Ok(payload);
    }
    if identity.admin {
        payload.conflicts = identity.public_conflicts();
    } else {
        payload.withheld_spans = identity.public_conflicts();
    }
    let mut events: Vec<Event> = Vec::new();
    if range.prometheus().is_some() {
        match page.budget.as_ref() {
            Some(client) => match prometheus(client, &identity, range, &mut payload).await {
                Ok(found) => events.extend(found),
                Err(_) => {
                    payload.telemetry = UNAVAILABLE;
                    payload.series = SERIES.iter().map(|n| (*n, Vec::new())).collect();
                    payload.sources.retain(|s| s != "prometheus");
                }
            },
            None => payload.telemetry = OFF,
        }
    } else {
        let tz = opts.tz.clone().unwrap_or_else(|| zone(None));
        days(store, row, &identity, range, &mut payload, &tz).await?;
    }
    let seen: BTreeSet<String> = events.iter().filter_map(|e| e.ap.as_ref().map(|a| a.to_lowercase())).collect();
    let aps = match opts.ap_map {
        Some(map) => map,
        None if page.budget.is_some() && payload.telemetry == super::live::OK => ap_map(page).await,
        None => ApMap::default(),
    };
    events.extend(registry_events(store, row, payload.start as f64, now, &aps, &mut payload, &seen).await?);
    events.extend(tl::from_windows(&identity, payload.start as f64, now));
    let (merged, truncated) = tl::merge(tl::restrict(events, Some(&identity)), Some(MAX_EVENTS));
    payload.timeline = tl::public(&merged);
    payload.timeline_truncated |= truncated;
    if range.days().is_some() {
        payload.timeline_days = timeline_days(&payload, &merged, now);
    }
    let sources: BTreeSet<String> =
        payload.sources.iter().cloned().chain(merged.iter().map(|e| e.source.clone())).collect();
    payload.sources = sources.into_iter().collect();
    Ok(payload)
}

/// `ceil(a / b)` for `b > 0` (Python `-(-a // b)`).
fn ceil_div(a: i64, b: i64) -> i64 {
    -((-a).div_euclid(b))
}

fn combine(name: &str, values: Option<&Vec<f64>>, digits: Digits) -> Option<Num> {
    let values = values.filter(|v| !v.is_empty())?;
    let sum: f64 = values.iter().sum();
    let v = if SUMMED.contains(&name) { sum } else { sum / values.len() as f64 };
    match digits {
        Digits::Int => fit_int(Some(v)).map(Num::Int),
        Digits::Dp(d) => fit(Some(v), d).map(Num::Float),
    }
}

/// Charts and presence events from Prometheus for the MACs whose windows meet the range.
async fn prometheus(
    client: &Budget,
    identity: &Identity,
    range: Range,
    payload: &mut History,
) -> std::result::Result<Vec<Event>, Unavailable> {
    let Some((seconds, step, res)) = range.prometheus() else {
        return Ok(Vec::new());
    };
    let (start, end) = (payload.start, payload.end);
    let segments = identity.segments(Some((start - step) as f64), Some(end as f64));
    let macs: Vec<String> = segments.iter().map(|s| s.mac.clone()).collect::<BTreeSet<_>>().into_iter().collect();
    let grid = grid(start, end, step);
    if macs.is_empty() {
        payload.series = SERIES.iter().map(|n| (*n, grid.iter().map(|t| (*t, None)).collect())).collect();
        return Ok(Vec::new());
    }
    let parts = selectors(client.ssid(), &macs)?;
    let ttl = range.ttl();
    let span = format!("[{}s:{}s]", seconds + step, res);
    let ages = client.matrix(&AGES.replace("$SPAN", &span), Some(end), ttl).await?;
    let assoc = client.matrix(&fill(ASSOCIATIONS, &parts).replace("$SPAN", &span), Some(end), ttl).await?;
    let mut charts = Vec::with_capacity(CHARTS.len());
    for (_, promql, _) in CHARTS {
        let query = fill(promql, &parts).replace("$STEP", &step.to_string());
        charts.push(client.range(&query, start, end, step, ttl).await?);
    }
    let fresh: BTreeSet<i64> = ages
        .first()
        .map(|(_, points)| {
            points.iter().filter(|(_, age)| age.is_some_and(|a| a <= STALE_AFTER_S as f64)).map(|(t, _)| *t).collect()
        })
        .unwrap_or_default();
    let mut by_mac: BTreeMap<&str, Vec<(f64, f64)>> = BTreeMap::new();
    for s in &segments {
        by_mac.entry(s.mac.as_str()).or_default().push((s.start, s.end));
    }
    let mine = |m: Option<&str>, t: f64| {
        m.and_then(|m| by_mac.get(m)).is_some_and(|w| w.iter().any(|(a, b)| *a <= t && t <= *b))
    };
    let overlaps = |m: Option<&str>, t: f64| {
        m.and_then(|m| by_mac.get(m)).is_some_and(|w| w.iter().any(|(a, b)| *a <= t && *b > t - step as f64))
    };
    let fresh_own: BTreeSet<i64> =
        fresh.iter().copied().filter(|t| macs.iter().any(|m| mine(Some(m), *t as f64))).collect();
    type Sample = (f64, Option<String>, Option<String>, Option<String>);
    let mut by_t: BTreeMap<i64, Vec<Sample>> = BTreeMap::new();
    for (labels, values) in &assoc {
        let m = labels.get("mac");
        for (t, s) in values {
            if let Some(s) = s
                && fresh.contains(t)
                && mine(m.map(String::as_str), *t as f64)
            {
                by_t.entry(*t).or_default().push((
                    *s,
                    labels.get("ap_name").cloned(),
                    labels.get("radio").cloned(),
                    m.cloned(),
                ));
            }
        }
    }
    // per minute the newest association (the greatest start; the first of equals)
    let points: Vec<Point> = by_t
        .into_iter()
        .filter_map(|(t, v)| {
            let mut best: Option<&Sample> = None;
            for x in &v {
                if best.is_none_or(|b| x.0 > b.0) {
                    best = Some(x);
                }
            }
            best.map(|(s, ap, radio, mac)| Point {
                t: t as f64,
                start: *s,
                ap_name: ap.clone(),
                radio: radio.clone(),
                mac: mac.clone(),
            })
        })
        .collect();
    let first = segments.iter().map(|s| s.start).reduce(f64::min);
    let last_fresh = fresh_own.iter().next_back().map(|t| *t as f64);
    let (events, spans) = tl::derive_timeline(&points, res as f64, last_fresh, first);
    // a chart point (t - step, t] counts when it holds fresh data and meets one of the windows
    let fresh_k: BTreeSet<i64> = fresh.iter().map(|f| ceil_div(f - start, step)).collect();
    let counts: Vec<bool> = grid
        .iter()
        .map(|t| fresh_k.contains(&(t - start).div_euclid(step)) && macs.iter().any(|m| overlaps(Some(m), *t as f64)))
        .collect();
    for ((name, _, digits), answer) in CHARTS.iter().zip(&charts) {
        let mut values: BTreeMap<i64, Vec<f64>> = BTreeMap::new();
        for (labels, points) in answer {
            let m = labels.get("mac").map(String::as_str);
            for (t, v) in points {
                if let Some(v) = v
                    && overlaps(m, *t as f64)
                {
                    values.entry(*t).or_default().push(*v);
                }
            }
        }
        let series: Series = grid
            .iter()
            .zip(&counts)
            .map(|(t, ok)| (*t, if *ok { combine(name, values.get(t), *digits) } else { None }))
            .collect();
        payload.series.insert(name, series);
    }
    let online: Series = grid
        .iter()
        .zip(&counts)
        .map(|(t, ok)| {
            let t_f = *t as f64;
            let on = spans.iter().any(|(a, last)| *a <= t_f && *last > t_f - step as f64);
            (*t, ok.then_some(Num::Int(i64::from(on))))
        })
        .collect();
    payload.series.insert("online", online);
    if !fresh_own.is_empty() {
        payload.sources.push("prometheus".into());
    }
    Ok(tl::from_presence(&events))
}

// --- the rollups (1y, all) --------------------------------------------------------------------------

fn civil(day: time::Date) -> CivilDate {
    CivilDate::new(day.year() as i16, u8::from(day.month()) as i8, day.day() as i8).unwrap_or(CivilDate::ZERO)
}

/// A `time::Date` of a civil date (the registry's day columns).
pub fn to_civil_time(day: CivilDate) -> time::Date {
    time::Month::try_from(day.month() as u8)
        .ok()
        .and_then(|m| time::Date::from_calendar_date(i32::from(day.year()), m, day.day() as u8).ok())
        .unwrap_or(time::Date::MIN)
}

/// The local date of a Unix time in the zone.
pub fn local_day(t: i64, tz: &TimeZone) -> CivilDate {
    Timestamp::from_second(t).map(|ts| tz.to_datetime(ts).date()).unwrap_or(CivilDate::ZERO)
}

/// The local midnight starting the day, as Unix seconds (23, 24 or 25 h days).
pub fn local_midnight(day: CivilDate, tz: &TimeZone) -> i64 {
    day.to_zoned(tz.clone()).map(|z| z.timestamp().as_second()).unwrap_or(0)
}

fn add_days(day: CivilDate, n: i64) -> CivilDate {
    day.checked_add(jiff::Span::new().days(n)).unwrap_or(day)
}

/// A device_day column by its series name.
fn day_value(r: &DeviceDay, series: &str) -> Option<f64> {
    match series {
        "signal_dbm" => r.signal_avg_dbm,
        "health" => r.health_avg,
        "rx_bps" => r.rx_bytes.map(|v| v as f64),
        "tx_bps" => r.tx_bytes.map(|v| v as f64),
        "link_rx_bps" => r.link_rx_avg_bps,
        "snr_db" => r.snr_avg_db,
        "retry_ratio" => r.retry_ratio_avg,
        _ => None, // link_tx_bps: not in device_day
    }
}

/// Series from `device_day`, one point per day (the day's start in the house's zone).
async fn days<S: Store>(
    store: &mut S,
    row: &DeviceRow,
    identity: &Identity,
    range: Range,
    payload: &mut History,
    tz: &TimeZone,
) -> Result<()> {
    let today = local_day(payload.end, tz);
    let days = match range.days().flatten() {
        Some(days) => days,
        None => {
            let first = identity.data_from().unwrap_or_else(|| unix(row.created_at));
            let first_day = local_day(first.floor() as i64, tz);
            let span = today.since(first_day).map(|s| i64::from(s.get_days())).unwrap_or(0);
            (span + 1).clamp(1, ALL_MAX_DAYS)
        }
    };
    let first_day = add_days(today, -(days - 1));
    let rows: BTreeMap<CivilDate, DeviceDay> = store
        .device_days(row.id, to_civil_time(first_day), to_civil_time(today))
        .await?
        .into_iter()
        .map(|r| (civil(r.day), r))
        .collect();
    let withheld = identity.withheld_spans();
    let mut series: IndexMap<&'static str, Series> = SERIES.iter().map(|n| (*n, Vec::new())).collect();
    let mut p10: Series = Vec::new();
    for i in 0..days {
        let day = add_days(first_day, i);
        let t0 = local_midnight(day, tz);
        let t1 = local_midnight(add_days(day, 1), tz);
        // a resident sees no day with a conflict in it
        let r = rows
            .get(&day)
            .filter(|_| !withheld.iter().any(|(_, f, t)| f.is_none_or(|f| f < t1 as f64) && *t >= t0 as f64));
        p10.push((t0, r.and_then(|r| fit(r.signal_p10_dbm, 1)).map(Num::Float)));
        for (name, _, digits) in CHARTS {
            let mut value = r.and_then(|r| day_value(r, name));
            if SUMMED.contains(&name) {
                value = value.map(|v| v * 8.0 / (t1 - t0) as f64); // the day's average rate
            }
            let value = match digits {
                Digits::Int => fit_int(value).map(Num::Int),
                Digits::Dp(d) => fit(value, d).map(Num::Float),
            };
            if let Some(s) = series.get_mut(name) {
                s.push((t0, value));
            }
        }
        let online = r.and_then(|r| {
            let online_s = f64::from(r.online_s?);
            let known = (t1 - t0) as f64 - f64::from(r.stale_s.unwrap_or(0));
            (known > 0.0).then(|| netportal_core::conventions::round_to((online_s / known).min(1.0), 3))
        });
        if let Some(s) = series.get_mut("online") {
            s.push((t0, online.map(Num::Float)));
        }
    }
    series.insert("signal_p10_dbm", p10);
    if let Some(first) = series.get("online").and_then(|s| s.first()) {
        payload.start = first.0;
    }
    payload.series = series;
    if !rows.is_empty() {
        payload.sources.push("device_day".into());
    }
    Ok(())
}

/// How many days the timeline covers, when less than the charts: from the events' retention or,
/// when it was cut, from its oldest event on; `None` when it covers all of the range.
pub fn timeline_days(payload: &History, merged: &[Event], now: f64) -> Option<i64> {
    let mut start = (payload.start as f64).max(now - EVENT_RETENTION_DAYS * 86400.0);
    if payload.timeline_truncated
        && let Some(first) = merged.first()
    {
        start = start.max(first.at);
    }
    if start <= payload.start as f64 {
        return None;
    }
    let elapsed = trunc_int(now - start).unwrap_or(0);
    Some(ceil_div(elapsed, 86400).max(1))
}

// --- the registry's events ---------------------------------------------------------------------------

/// RADIUS logins and rejects, accounting sessions, UniFi events and the incidents of the device's
/// APs and of the house, each bounded.
async fn registry_events<S: Store>(
    store: &mut S,
    row: &DeviceRow,
    start: f64,
    end: f64,
    aps: &ApMap,
    payload: &mut History,
    ap_names: &BTreeSet<String>,
) -> Result<Vec<Event>> {
    let (since, until) = (moment(start), moment(end));
    let auth = store.auth_events(row.id, since, until, EVENT_LIMIT_AUTH).await?;
    let acct = store.acct_sessions(row.id, since, until, EVENT_LIMIT_ACCT).await?;
    let unifi = store.connection_events(row.id, since, until, EVENT_LIMIT_UNIFI).await?;
    let truncated = auth.len() as i64 >= EVENT_LIMIT_AUTH
        || acct.len() as i64 >= EVENT_LIMIT_ACCT
        || unifi.len() as i64 >= EVENT_LIMIT_UNIFI;
    let mut events = tl::from_auth(&auth, aps);
    events.extend(tl::from_acct(&acct, aps));
    events.extend(tl::from_unifi(&unifi, aps));
    for (name, any) in
        [("radius_auth", !auth.is_empty()), ("radius_acct", !acct.is_empty()), ("unifi_syslog", !unifi.is_empty())]
    {
        if any {
            payload.sources.push(name.into());
        }
    }
    let macs: BTreeSet<String> = events.iter().filter_map(|e| e.ap_mac.clone()).collect();
    let mut names: BTreeSet<String> = events.iter().filter_map(|e| e.ap.as_ref().map(|a| a.to_lowercase())).collect();
    names.extend(ap_names.iter().cloned());
    let rows = store.incidents(since, Some(until), None).await?;
    events.extend(tl::from_incidents(&relevant_incidents(&rows, &macs, &names)));
    if truncated {
        payload.timeline_truncated = true;
    }
    Ok(events)
}

/// The house-wide incident kinds (an empty subject).
pub const HOUSE_INCIDENTS: [&str; 6] =
    ["internet_down", "internet_degraded", "router_down", "dns_down", "unifi_data_stale", "radius_down"];

/// The incidents that concern a device: the house-wide ones and those of the APs it used (by MAC,
/// or by name), a switch's when its detail lists one of those APs.
pub fn relevant_incidents<'a>(
    rows: &'a [Incident],
    ap_macs: &BTreeSet<String>,
    ap_names: &BTreeSet<String>,
) -> Vec<&'a Incident> {
    rows.iter()
        .filter(|r| {
            let subject = r.subject.to_lowercase();
            let name = r.subject_name.as_deref().unwrap_or_default().to_lowercase();
            if HOUSE_INCIDENTS.contains(&r.kind.as_str()) && subject.is_empty() {
                return true;
            }
            if r.kind.starts_with("ap_") {
                return ap_macs.contains(&subject) || (!name.is_empty() && ap_names.contains(&name));
            }
            if r.kind.starts_with("switch") {
                let listed = r.detail.0.get("ap_macs").and_then(|v| v.as_array());
                return listed.is_some_and(|l| l.iter().filter_map(|m| m.as_str()).any(|m| ap_macs.contains(m)));
            }
            false
        })
        .collect()
}
