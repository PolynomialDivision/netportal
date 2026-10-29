//! The job `rollup` (Python `collect/rollup.py`, INVENTORY 9.9.6): Prometheus -> `device_day` and
//! `ap_day` on house days (`NETPORTAL_TIMEZONE`).
//!
//! Every run (re)computes today (so far) and yesterday, then fills up to
//! [`BACKFILL_DAYS_PER_RUN`] missing older days, newest first, back to the Prometheus horizon
//! (its lowest timestamp, at most [`MAX_HISTORY_DAYS`]). Rows are upserted whole per (device,
//! day) and (AP MAC, day): rerunning a day replaces it.
//!
//! Per device and day, from per-minute range queries over `[local midnight, next local
//! midnight)`, only minutes that are
//! - fresh: unpoller's snapshot at most 10 minutes old (stale minutes count as `stale_s`, never
//!   as online or in an average: a frozen snapshot shows clients that may have left);
//! - the house network's: every client selector has `essid = NETPORTAL_SSID` (byte counters and
//!   the retry ratio carry no essid and count only `and on (mac)` the house network's uptime);
//! - the device's: the minute is inside exactly one device's window for that MAC
//!   (`registry::device_windows`, the view `device_mac_window`, the rule the pages use); minutes
//!   in the windows of two devices belong to neither.
//!
//! Values: `online_s`, `stale_s`; averages over the online minutes (signal also its 10th
//! percentile); rx/tx bytes in the device's view (rx = what the AP transmits) as `rate()*60` per
//! online minute; roams = AP changes within one association, reconnects = new associations
//! (association start = snapshot time - uptime); `aps` `{ap_mac: s}` (the AP's MAC at that minute:
//! APs were renamed); `bands` `{"2.4"|"5"|"6": s}`; `macs`; `auth_ok` / `auth_failed` from
//! `radius_auth` (a row of repeated rejects counts its tries); `disconnects` from
//! `connection_event` (`None` when the device has no event that day: unknown, not 0). A device
//! gets a row for every day one of its windows (or a RADIUS decision) touches.
//!
//! Per AP and day (APs with data that day): the latest name, clients avg/max (all networks),
//! `channel_util_avg {radio: ratio}`, the share of client-minutes at or below [`WEAK_DBM`] (one rule with telemetry's `WEAK_SIGNAL_WARN_DBM`), restarts
//! (uptime resets seen that day) and `down_s` (the incidents job's `ap_down` rule per minute).

use std::collections::{BTreeMap, BTreeSet};

use indexmap::IndexMap;
use jiff::tz::TimeZone;
use netportal_core::conventions::{date_iso, round_int, round_to, unix};
use netportal_core::registry::{self, ApDay, AuthEvent, ConnectionEvent, DeviceDay, DeviceRow, MacWindow};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sqlx::types::Json;
use time::{Date, OffsetDateTime};
use uuid::Uuid;

use crate::days::{bounds, local_day};
use crate::incidents::{self, Signals};
use crate::scheduler::{Context, JobError, JobResult};
use crate::sources::{Labels, Points, Prometheus, SourceError, mac_matcher, normalise_mac, promql_string};

pub const NAME: &str = "rollup";
const LOG: &str = "netportal.collect.rollup";

pub const STEP: i64 = 60;
/// MACs per query.
pub const CHUNK: usize = 40;
pub const BACKFILL_DAYS_PER_RUN: usize = 2;
pub const MAX_HISTORY_DAYS: i64 = 400;
/// Two association starts closer than this are the same association.
pub const SAME_ASSOCIATION_S: f64 = 120.0;
pub const WEAK_DBM: i32 = -75;
/// Registry rows read per device and day (the registry's cap).
pub const ROWS_PER_DAY: i64 = 10_000;

pub const HORIZON: &str = "min(prometheus_tsdb_lowest_timestamp_seconds)";
pub const AGE: &str = r#"max(unpoller_prometheus_cache_age_seconds{job="unifi"})"#;

pub const AP_STATIONS: &str = r#"sum by (mac) (unpoller_device_radio_stations{job="unifi"})"#;
pub const AP_UTIL: &str = r#"max by (mac, radio) (unpoller_device_radio_channel_utilization_total_ratio{job="unifi"})"#;
pub fn ap_weak() -> String {
    format!(r#"count by (ap_name) (unpoller_client_radio_signal_db{{job="unifi"}} <= {WEAK_DBM})"#)
}
pub const AP_SIGNALS: &str = r#"count by (ap_name) (unpoller_client_radio_signal_db{job="unifi"})"#;

/// The names of the per-device queries, in the order they are asked.
pub const DEVICE_QUERIES: [&str; 8] = ["presence", "signal", "snr", "health", "retry", "rx", "tx", "link_rx"];

fn band(radio: Option<&str>) -> Option<&'static str> {
    match radio? {
        "ng" => Some("2.4"),
        "na" => Some("5"),
        "6e" => Some("6"),
        _ => None,
    }
}

fn avg(values: &[f64], digits: u32) -> Option<f64> {
    (!values.is_empty()).then(|| round_to(values.iter().sum::<f64>() / values.len() as f64, digits))
}

/// Nearest-rank 10th percentile.
fn p10(values: &[f64]) -> Option<f64> {
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let index = ((0.1 * sorted.len() as f64).ceil() as usize).saturating_sub(1);
    sorted.get(index).copied()
}

fn by_mac(rows: Vec<(Labels, Points)>) -> BTreeMap<String, Points> {
    let mut out: BTreeMap<String, Points> = BTreeMap::new();
    for (labels, points) in rows {
        if let Some(mac) = labels.get("mac").and_then(|m| normalise_mac(m)) {
            out.entry(mac).or_default().extend(points);
        }
    }
    out
}

fn single(rows: Vec<(Labels, Points)>) -> Points {
    rows.into_iter().next().map(|(_, p)| p).unwrap_or_default()
}

fn i32_of(n: usize) -> Option<i32> {
    i32::try_from(n).ok()
}

// --- windows ----------------------------------------------------------------------------------------

/// `{mac: [(device, from, to)]}` from `device_windows` (Unix seconds).
pub type Intervals = BTreeMap<String, Vec<(Uuid, f64, f64)>>;

pub fn mac_intervals(windows: &IndexMap<Uuid, Vec<MacWindow>>) -> Intervals {
    let mut out: Intervals = BTreeMap::new();
    for (device, rows) in windows {
        for w in rows {
            if let Some(mac) = normalise_mac(&w.mac) {
                out.entry(mac).or_default().push((*device, unix(w.first_seen), unix(w.window_end)));
            }
        }
    }
    out
}

/// The one device whose window holds `t`, else `None` (none or several).
pub fn owner_at(intervals: &[(Uuid, f64, f64)], t: i64) -> Option<Uuid> {
    let t = t as f64;
    let owners: BTreeSet<Uuid> = intervals.iter().filter(|(_, a, b)| *a <= t && t <= *b).map(|(d, _, _)| *d).collect();
    (owners.len() == 1).then(|| owners.into_iter().next()).flatten()
}

// --- AP names -> MACs -----------------------------------------------------------------------------------

/// The AP MAC for an `ap_name` at a minute (`unpoller_device_info`'s name then), else the only
/// MAC that name had that day; and each MAC's latest name.
#[derive(Debug, Default)]
pub struct ApNames {
    at: BTreeMap<(String, i64), String>,
    only: BTreeMap<String, String>,
    latest: BTreeMap<String, (i64, String)>,
}

impl ApNames {
    pub fn new(info_rows: &[(Labels, Points)]) -> ApNames {
        let mut names = ApNames::default();
        let mut by_name: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for (labels, points) in info_rows {
            let (Some(mac), Some(name)) = (labels.get("mac").and_then(|m| normalise_mac(m)), labels.get("name")) else {
                continue;
            };
            for t in points.keys() {
                names.at.insert((name.clone(), *t), mac.clone());
                if names.latest.get(&mac).is_none_or(|(l, _)| *t >= *l) {
                    names.latest.insert(mac.clone(), (*t, name.clone()));
                }
            }
            by_name.entry(name.clone()).or_default().insert(mac);
        }
        names.only = by_name
            .into_iter()
            .filter(|(_, macs)| macs.len() == 1)
            .filter_map(|(name, macs)| macs.into_iter().next().map(|m| (name, m)))
            .collect();
        names
    }

    pub fn mac(&self, name: Option<&str>, t: i64) -> Option<&str> {
        let name = name?;
        self.at.get(&(name.to_string(), t)).or_else(|| self.only.get(name)).map(String::as_str)
    }

    pub fn name(&self, mac: &str) -> Option<String> {
        self.latest.get(mac).map(|(_, n)| n.clone())
    }
}

// --- one day ---------------------------------------------------------------------------------------------

/// `(start, end, grid)` of a day: its minutes up to a minute ago for today, else all of them.
pub fn day_grid(day: Date, tz: &TimeZone, now: f64) -> Option<(i64, i64, Vec<i64>)> {
    let (start, end) = bounds(day, tz)?;
    let last = if now < end as f64 { (now as i64).div_euclid(STEP) * STEP - STEP } else { end - STEP };
    let grid = if last < start { Vec::new() } else { (start..=last).step_by(STEP as usize).collect() };
    Some((start, end, grid))
}

/// `{name: PromQL}` of the device queries for one chunk of normalised MACs on the house network.
pub fn device_queries<S: AsRef<str>>(ssid: &str, macs: &[S]) -> Result<Vec<(&'static str, String)>, SourceError> {
    let mac = mac_matcher(macs)?;
    let sel = format!("essid={},{mac}", promql_string(ssid)?);
    let u = format!(r#"unpoller_client_uptime_seconds{{job="unifi",{sel}}}"#);
    Ok(vec![
        ("presence", format!("min by (mac, ap_name, radio) ({u})")),
        ("signal", format!(r#"avg by (mac) (unpoller_client_radio_signal_db{{job="unifi",{sel}}})"#)),
        ("snr", format!("avg by (mac) (wifi_client_snr_db{{{sel}}})")),
        ("health", format!("min by (mac) (wifi_client_health_score{{{sel}}})")),
        ("retry", format!("max by (mac) (wifi_client_retry_ratio{{{mac}}} and on (mac) {u})")),
        (
            "rx",
            format!(
                r#"sum by (mac) (rate(unpoller_client_transmit_bytes_total{{job="unifi",{mac}}}[3m]) and on (mac) {u}) * 60"#
            ),
        ),
        (
            "tx",
            format!(
                r#"sum by (mac) (rate(unpoller_client_receive_bytes_total{{job="unifi",{mac}}}[3m]) and on (mac) {u}) * 60"#
            ),
        ),
        ("link_rx", format!(r#"avg by (mac) (unpoller_client_radio_transmit_rate_bps{{job="unifi",{sel}}})"#)),
    ])
}

/// One minute of a MAC on the house network: uptime, AP name, radio.
#[derive(Debug, Clone, PartialEq)]
pub struct Presence {
    pub uptime: f64,
    pub ap_name: Option<String>,
    pub radio: Option<String>,
}

/// The device series of a day.
#[derive(Debug, Default)]
pub struct DeviceSeries {
    pub presence: BTreeMap<String, BTreeMap<i64, Presence>>,
    /// `{query name: {mac: points}}` (all but presence)
    pub values: BTreeMap<&'static str, BTreeMap<String, Points>>,
}

impl DeviceSeries {
    fn value(&self, name: &str, mac: &str, t: i64) -> Option<f64> {
        self.values.get(name)?.get(mac)?.get(&t).copied()
    }
}

/// The device queries for these MACs over `[start, last]`, in chunks of [`CHUNK`].
pub async fn device_series(
    prom: &Prometheus,
    ssid: &str,
    macs: &BTreeSet<String>,
    start: i64,
    last: i64,
) -> Result<DeviceSeries, SourceError> {
    let mut out = DeviceSeries::default();
    let macs: Vec<&String> = macs.iter().collect();
    for chunk in macs.chunks(CHUNK) {
        for (name, promql) in device_queries(ssid, chunk)? {
            let rows = prom.range(&promql, start, last, STEP).await?;
            if name == "presence" {
                for (labels, points) in rows {
                    let Some(mac) = labels.get("mac").and_then(|m| normalise_mac(m)) else { continue };
                    let minutes = out.presence.entry(mac).or_default();
                    for (t, uptime) in points {
                        // several series at a minute: the newest association (the smallest uptime)
                        if minutes.get(&t).is_none_or(|p| uptime < p.uptime) {
                            let p = Presence {
                                uptime,
                                ap_name: labels.get("ap_name").cloned(),
                                radio: labels.get("radio").cloned(),
                            };
                            minutes.insert(t, p);
                        }
                    }
                }
            } else {
                let target = out.values.entry(name).or_default();
                for (mac, points) in by_mac(rows) {
                    target.entry(mac).or_default().extend(points);
                }
            }
        }
    }
    Ok(out)
}

/// What a device's day is computed from (besides its own MACs, decisions and events).
pub struct DayInput<'a> {
    pub day: Date,
    pub grid: &'a [i64],
    pub fresh: &'a BTreeSet<i64>,
    pub ages: &'a Points,
    pub intervals: &'a Intervals,
    pub series: &'a DeviceSeries,
    pub ap_names: &'a ApNames,
}

/// The `device_day` row of one device (minutes in two devices' windows count for neither).
pub fn device_row(
    input: &DayInput<'_>,
    device: Uuid,
    macs: &BTreeSet<String>,
    auth: &[AuthEvent],
    events: &[ConnectionEvent],
) -> DeviceDay {
    let none = Vec::new();
    let mut online: Vec<(i64, &str, &Presence)> = Vec::new();
    let mut stale = 0usize;
    for &t in input.grid {
        let mine: Vec<&String> =
            macs.iter().filter(|m| owner_at(input.intervals.get(*m).unwrap_or(&none), t) == Some(device)).collect();
        if mine.is_empty() {
            continue;
        }
        if !input.fresh.contains(&t) {
            stale += 1;
            continue;
        }
        let here = mine
            .iter()
            .filter_map(|m| input.series.presence.get(*m).and_then(|p| p.get(&t)).map(|p| (p, m.as_str())))
            .min_by(|(a, am), (b, bm)| {
                a.uptime
                    .total_cmp(&b.uptime)
                    .then_with(|| a.ap_name.cmp(&b.ap_name))
                    .then_with(|| a.radio.cmp(&b.radio))
                    .then_with(|| am.cmp(bm))
            });
        if let Some((p, mac)) = here {
            online.push((t, mac, p));
        }
    }
    let mut aps: BTreeMap<String, i64> = BTreeMap::new();
    let mut bands: BTreeMap<&str, i64> = BTreeMap::new();
    let (mut roams, mut reconnects) = (0, 0);
    let mut prev: Option<(f64, Option<&str>)> = None;
    for (t, _mac, p) in &online {
        if let Some(ap) = input.ap_names.mac(p.ap_name.as_deref(), *t) {
            *aps.entry(ap.to_string()).or_default() += STEP;
        }
        if let Some(b) = band(p.radio.as_deref()) {
            *bands.entry(b).or_default() += STEP;
        }
        let start = *t as f64 - input.ages.get(t).copied().unwrap_or(0.0) - p.uptime;
        if let Some((prev_start, prev_ap)) = prev {
            if start - prev_start > SAME_ASSOCIATION_S {
                reconnects += 1;
            } else if p.ap_name.as_deref() != prev_ap {
                roams += 1;
            }
        }
        prev = Some((start, p.ap_name.as_deref()));
    }
    let values = |name: &str| -> Vec<f64> {
        online.iter().filter_map(|(t, mac, _)| input.series.value(name, mac, *t)).collect()
    };
    let (rx, tx, health, signal) = (values("rx"), values("tx"), values("health"), values("signal"));
    let sum = |v: &[f64]| (!v.is_empty()).then(|| round_int(v.iter().sum())).flatten();
    let tries = |result: &str| -> i32 { auth.iter().filter(|a| a.result == result).map(|a| a.tries.max(1)).sum() };
    let object = |m: Map<String, Value>| Json(Value::Object(m));
    let has_online = !online.is_empty();
    DeviceDay {
        device_id: device,
        day: input.day,
        online_s: i32_of(online.len() * STEP as usize),
        stale_s: i32_of(stale * STEP as usize),
        signal_avg_dbm: avg(&signal, 1),
        signal_p10_dbm: p10(&signal).map(|v| round_to(v, 1)),
        snr_avg_db: avg(&values("snr"), 1),
        health_avg: avg(&health, 1),
        health_min: health.iter().copied().reduce(f64::min).map(|v| round_to(v, 1)),
        retry_ratio_avg: avg(&values("retry"), 4),
        rx_bytes: sum(&rx),
        tx_bytes: sum(&tx),
        link_rx_avg_bps: avg(&values("link_rx"), 0),
        roams: has_online.then_some(roams),
        reconnects: has_online.then_some(reconnects),
        disconnects: (!events.is_empty()).then(|| events.iter().filter(|e| e.kind == "disconnected").count() as i32),
        aps: object(aps.into_iter().map(|(k, v)| (k, Value::from(v))).collect()),
        bands: object(bands.into_iter().map(|(k, v)| (k.to_string(), Value::from(v))).collect()),
        macs: i32_of(macs.len()),
        auth_ok: Some(tries("accept")),
        auth_failed: Some(tries("reject")),
        computed_at: None,
    }
}

/// The AP series of a day.
#[derive(Debug, Default)]
pub struct ApSeries {
    pub stations: Vec<(Labels, Points)>,
    pub util: Vec<(Labels, Points)>,
    pub weak: Vec<(Labels, Points)>,
    pub signals: Vec<(Labels, Points)>,
}

/// The `ap_day` rows of the APs with data that day. `s` holds the AP signals over
/// `[start - FROZEN_S, last]`; a restart counts for the day it is seen in.
pub fn ap_rows(
    day: Date,
    grid: &[i64],
    fresh: &BTreeSet<i64>,
    s: &Signals,
    ap_names: &ApNames,
    aps: ApSeries,
) -> Vec<ApDay> {
    let Some(&first_minute) = grid.first() else { return Vec::new() };
    let stations = by_mac(aps.stations);
    let mut util: BTreeMap<String, BTreeMap<String, Points>> = BTreeMap::new();
    for (labels, points) in aps.util {
        if let (Some(mac), Some(radio)) = (labels.get("mac").and_then(|m| normalise_mac(m)), labels.get("radio")) {
            util.entry(mac).or_default().entry(radio.clone()).or_default().extend(points);
        }
    }
    let count_by_ap = |rows: Vec<(Labels, Points)>| {
        let mut out: BTreeMap<String, f64> = BTreeMap::new();
        for (labels, points) in rows {
            for (t, v) in points {
                if let Some(mac) =
                    ap_names.mac(labels.get("ap_name").map(String::as_str), t).filter(|_| fresh.contains(&t))
                {
                    *out.entry(mac.to_string()).or_default() += v;
                }
            }
        }
        out
    };
    let (weak, total) = (count_by_ap(aps.weak), count_by_ap(aps.signals));
    let (states, _names, _details) = incidents::ap_states(grid, s);
    let mut present: BTreeMap<String, BTreeSet<i64>> = BTreeMap::new();
    for (labels, points) in &s.ap_info_rows {
        if let Some(mac) = labels.get("mac").and_then(|m| normalise_mac(m)) {
            present.entry(mac).or_default().extend(points.keys().copied());
        }
    }
    let names: BTreeMap<String, Option<String>> = present.keys().map(|m| (m.clone(), ap_names.name(m))).collect();
    let extended: Vec<i64> =
        (first_minute - incidents::FROZEN_S..=grid[grid.len() - 1]).step_by(STEP as usize).collect();
    let mut restarts: BTreeMap<String, i32> = BTreeMap::new();
    for r in incidents::ap_restarts(&extended, s, &names) {
        if r.seen >= first_minute {
            *restarts.entry(r.mac).or_default() += 1;
        }
    }
    let mut rows = Vec::new();
    for (mac, minutes) in &present {
        let Some(&first) = minutes.iter().next() else { continue };
        let counts: Vec<f64> = stations
            .get(mac)
            .map(|p| p.iter().filter(|(t, _)| fresh.contains(t)).map(|(_, v)| *v).collect())
            .unwrap_or_default();
        let down = states
            .get(&("ap_down", mac.clone()))
            .map(|st| st.iter().filter(|(t, s)| **s == Some(true) && **t >= first).count())
            .unwrap_or(0);
        let mut channel = Map::new();
        for (radio, points) in util.get(mac).into_iter().flatten() {
            let values: Vec<f64> = points.iter().filter(|(t, _)| fresh.contains(t)).map(|(_, v)| *v).collect();
            if let Some(a) = avg(&values, 4) {
                channel.insert(radio.clone(), Value::from(a));
            }
        }
        rows.push(ApDay {
            ap_mac: mac.clone(),
            day,
            ap_name: ap_names.name(mac),
            clients_avg: avg(&counts, 2),
            clients_max: counts
                .iter()
                .copied()
                .reduce(f64::max)
                .and_then(round_int)
                .and_then(|v| i32::try_from(v).ok()),
            channel_util_avg: Json(Value::Object(channel)),
            weak_client_share: total
                .get(mac)
                .filter(|t| **t > 0.0)
                .map(|t| round_to(weak.get(mac).copied().unwrap_or(0.0) / t, 4)),
            restarts: Some(restarts.get(mac).copied().unwrap_or(0)),
            down_s: i32_of(down * STEP as usize),
            computed_at: None,
        });
    }
    rows
}

fn dt(unix: i64) -> Result<OffsetDateTime, JobError> {
    OffsetDateTime::from_unix_timestamp(unix).map_err(|_| JobError::Other("time out of range".into()))
}

/// The registry's view of the devices, read once per run.
pub struct Registry<'a> {
    pub devices: &'a [DeviceRow],
    pub windows: &'a IndexMap<Uuid, Vec<MacWindow>>,
    pub intervals: &'a Intervals,
}

/// Upserts the day's `device_day` and `ap_day` rows and commits. Returns (devices, APs) written.
pub async fn compute_day(
    ctx: &mut Context,
    prom: &Prometheus,
    tz: &TimeZone,
    day: Date,
    reg: &Registry<'_>,
) -> Result<(u64, u64), JobError> {
    let Some((start, end, grid)) = day_grid(day, tz, unix(ctx.now)) else {
        return Ok((0, 0));
    };
    let Some(&last) = grid.last() else {
        return Ok((0, 0));
    };
    let first = start - incidents::FROZEN_S;
    let ages = single(prom.range(AGE, first, last, STEP).await?);
    let fresh: BTreeSet<i64> =
        grid.iter().copied().filter(|t| ages.get(t).is_some_and(|a| *a <= incidents::STALE_AFTER_S)).collect();
    let info_rows = prom.range(incidents::Q_AP_INFO, first, last, STEP).await?;
    let ap_names = ApNames::new(&info_rows);
    let mut day_macs: BTreeMap<Uuid, BTreeSet<String>> = BTreeMap::new();
    for (device, rows) in reg.windows {
        for w in rows {
            if let Some(mac) = normalise_mac(&w.mac)
                && unix(w.first_seen) < end as f64
                && unix(w.window_end) >= start as f64
            {
                day_macs.entry(*device).or_default().insert(mac);
            }
        }
    }
    let wanted: BTreeSet<String> = day_macs.values().flatten().cloned().collect();
    let series = if wanted.is_empty() {
        DeviceSeries::default()
    } else {
        device_series(prom, &ctx.settings.ssid, &wanted, start, last).await?
    };
    // [midnight, next midnight): an event at the next midnight is the next day's
    let (since, until) = (dt(start)?, dt(end)? - time::Duration::microseconds(1));
    let input = DayInput {
        day,
        grid: &grid,
        fresh: &fresh,
        ages: &ages,
        intervals: reg.intervals,
        series: &series,
        ap_names: &ap_names,
    };
    let empty = BTreeSet::new();
    let mut written = 0;
    for device in reg.devices {
        let auth = registry::auth_events(&mut ctx.db, device.id, since, until, ROWS_PER_DAY).await?;
        let macs = day_macs.get(&device.id).unwrap_or(&empty);
        if macs.is_empty() && auth.is_empty() {
            continue;
        }
        let events = registry::connection_events(&mut ctx.db, device.id, since, until, ROWS_PER_DAY).await?;
        let row = device_row(&input, device.id, macs, &auth, &events);
        registry::upsert_device_day(&mut ctx.db, &row).await?;
        written += 1;
    }
    let s = Signals {
        unifi_up: ages.keys().map(|t| (*t, 1.0)).collect(), // an age sample means unpoller was scraped
        age: ages.clone(),
        site_disconnected: single(prom.range(incidents::Q_SITE_DISCONNECTED, first, last, STEP).await?),
        ap_uptime_rows: prom.range(incidents::Q_AP_UPTIME, first, last, STEP).await?,
        ap_up_rec_rows: prom.range(incidents::AP_UP_RECORD, first, last, STEP).await?,
        ap_uptime_rec_rows: prom.range(incidents::AP_UPTIME_RECORD, first, last, STEP).await?,
        ap_known_rows: info_rows.iter().map(|(labels, _)| (labels.clone(), Some(1.0))).collect(),
        ap_info_rows: info_rows,
        ..Signals::default()
    };
    let aps = ApSeries {
        stations: prom.range(AP_STATIONS, start, last, STEP).await?,
        util: prom.range(AP_UTIL, start, last, STEP).await?,
        weak: prom.range(&ap_weak(), start, last, STEP).await?,
        signals: prom.range(AP_SIGNALS, start, last, STEP).await?,
    };
    let mut ap_written = 0;
    for row in ap_rows(day, &grid, &fresh, &s, &ap_names, aps) {
        registry::upsert_ap_day(&mut ctx.db, &row).await?;
        ap_written += 1;
    }
    ctx.db.commit().await?;
    Ok((written, ap_written))
}

// --- which days ---------------------------------------------------------------------------------------------

/// The oldest day Prometheus has data for (at most [`MAX_HISTORY_DAYS`] back); yesterday when it
/// does not say.
pub async fn horizon_day(prom: &Prometheus, today: Date, tz: &TimeZone) -> Result<Date, SourceError> {
    let rows = prom.vector(HORIZON, None).await?;
    let oldest = today - time::Duration::days(MAX_HISTORY_DAYS);
    let lowest = rows.first().and_then(|r| r.1).filter(|v| *v > 0.0).and_then(|v| local_day(v.trunc() as i64, tz));
    Ok(match lowest {
        Some(day) => day.max(oldest),
        None => today - time::Duration::days(1),
    })
}

fn days_between(first: Date, last: Date) -> impl Iterator<Item = Date> {
    std::iter::successors(Some(first), |d| d.next_day()).take_while(move |d| *d <= last)
}

/// Days in `[horizon, before]` that lack a device's row (one its windows touch) or any AP row
/// (unless known to have no AP data: `empty`), newest first.
pub async fn missing_days(
    ctx: &mut Context,
    reg: &Registry<'_>,
    horizon: Date,
    before: Date,
    tz: &TimeZone,
    empty: &BTreeSet<Date>,
) -> Result<Vec<Date>, JobError> {
    if before < horizon {
        return Ok(Vec::new());
    }
    let mut need = BTreeSet::new();
    for device in reg.devices {
        let mut days = BTreeSet::new();
        for w in reg.windows.get(&device.id).into_iter().flatten() {
            let (Some(a), Some(b)) =
                (local_day(w.first_seen.unix_timestamp(), tz), local_day(w.window_end.unix_timestamp(), tz))
            else {
                continue;
            };
            days.extend(days_between(a.max(horizon), b.min(before)));
        }
        if !days.is_empty() {
            let have: BTreeSet<Date> = registry::device_days(&mut ctx.db, device.id, horizon, before)
                .await?
                .into_iter()
                .map(|r| r.day)
                .collect();
            need.extend(days.difference(&have).copied());
        }
    }
    let have_ap: BTreeSet<Date> =
        registry::ap_days(&mut ctx.db, horizon, before, None).await?.into_iter().map(|r| r.day).collect();
    need.extend(days_between(horizon, before).filter(|d| !have_ap.contains(d) && !empty.contains(d)));
    Ok(need.into_iter().rev().collect())
}

/// A day the run computed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DayDone {
    pub day: String,
    pub devices: u64,
    pub aps: u64,
}

/// `{"horizon": "YYYY-MM-DD", "empty_days": ["YYYY-MM-DD"], "last_run": [{"day", "devices", "aps"}]}`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cursor {
    #[serde(default)]
    pub horizon: Option<String>,
    #[serde(default)]
    pub empty_days: Vec<String>,
    #[serde(default)]
    pub last_run: Vec<DayDone>,
}

pub fn parse_date(text: &str) -> Option<Date> {
    Date::parse(text, time::macros::format_description!("[year]-[month]-[day]")).ok()
}

fn cursor_value(horizon: Date, empty: &BTreeSet<Date>, done: &[DayDone]) -> Value {
    let cursor = Cursor {
        horizon: Some(date_iso(horizon)),
        empty_days: empty.iter().filter(|d| **d >= horizon).map(|d| date_iso(*d)).collect(),
        last_run: done.to_vec(),
    };
    serde_json::to_value(cursor).unwrap_or_else(|_| Value::Object(Map::new()))
}

pub async fn run(ctx: &mut Context) -> JobResult {
    let prom = ctx.prometheus()?;
    let tz = netportal_core::conventions::zone(&ctx.settings.timezone)
        .ok_or_else(|| JobError::Other(format!("unknown time zone {:?}", ctx.settings.timezone)))?;
    let today = local_day(ctx.now.unix_timestamp(), &tz).ok_or_else(|| JobError::Other("time out of range".into()))?;
    let devices = registry::devices(&mut ctx.db, None, true).await?;
    let ids: Vec<Uuid> = devices.iter().map(|d| d.id).collect();
    let windows = registry::device_windows(&mut ctx.db, &ids, None, None).await?;
    let intervals = mac_intervals(&windows);
    let reg = Registry { devices: &devices, windows: &windows, intervals: &intervals };
    let horizon = horizon_day(&prom, today, &tz).await?;
    let previous: Cursor = ctx.cursor_as();
    let mut empty: BTreeSet<Date> = previous.empty_days.iter().filter_map(|d| parse_date(d)).collect();
    let yesterday = today - time::Duration::days(1);
    let mut days = vec![today];
    if yesterday >= horizon {
        days.push(yesterday);
    }
    let missing = missing_days(ctx, &reg, horizon, today - time::Duration::days(2), &tz, &empty).await?;
    days.extend(missing.into_iter().take(BACKFILL_DAYS_PER_RUN));
    let mut done = Vec::new();
    for day in days {
        if ctx.stopping() {
            break;
        }
        let (written, ap_written) = compute_day(ctx, &prom, &tz, day, &reg).await?;
        if ap_written == 0 && day < yesterday {
            empty.insert(day);
        }
        done.push(DayDone { day: date_iso(day), devices: written, aps: ap_written });
        ctx.save(cursor_value(horizon, &empty, &done)); // the day is committed
    }
    if !done.is_empty() {
        tracing::debug!(target: LOG, "rollup: {} days", done.len());
    }
    Ok(Some(cursor_value(horizon, &empty, &done)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p10_and_avg() {
        assert_eq!(p10(&[]), None);
        assert_eq!(p10(&[-60.0]), Some(-60.0));
        let values: Vec<f64> = (1..=20).map(f64::from).collect();
        assert_eq!(p10(&values), Some(2.0));
        assert_eq!(avg(&[1.0, 2.0], 1), Some(1.5));
        assert_eq!(avg(&[], 1), None);
    }

    #[test]
    fn test_owner_at() {
        let (a, b) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let intervals = [(a, 0.0, 100.0), (b, 50.0, 200.0), (a, 300.0, 400.0)];
        assert_eq!(owner_at(&intervals, 10), Some(a));
        assert_eq!(owner_at(&intervals, 60), None); // two devices: nobody's
        assert_eq!(owner_at(&intervals, 150), Some(b));
        assert_eq!(owner_at(&intervals, 250), None);
    }

    #[test]
    fn test_device_queries() {
        let q = device_queries("Scharni", &["02:11:22:33:44:55"]).expect("queries");
        assert_eq!(q.iter().map(|(n, _)| *n).collect::<Vec<_>>(), DEVICE_QUERIES);
        assert_eq!(
            q[0].1,
            r#"min by (mac, ap_name, radio) (unpoller_client_uptime_seconds{job="unifi",essid="Scharni",mac="02:11:22:33:44:55"})"#
        );
        assert!(device_queries("Scharni", &["not a mac"]).is_err());
        assert!(device_queries("a\nb", &["02:11:22:33:44:55"]).is_err());
    }

    #[test]
    fn test_ap_names() {
        let info = vec![
            (
                Labels::from([("mac".into(), "aa:aa:aa:aa:aa:01".into()), ("name".into(), "old".into())]),
                Points::from([(0, 1.0)]),
            ),
            (
                Labels::from([("mac".into(), "aa:aa:aa:aa:aa:01".into()), ("name".into(), "new".into())]),
                Points::from([(60, 1.0)]),
            ),
            (
                Labels::from([("mac".into(), "aa:aa:aa:aa:aa:02".into()), ("name".into(), "old".into())]),
                Points::from([(120, 1.0)]),
            ),
        ];
        let names = ApNames::new(&info);
        assert_eq!(names.mac(Some("old"), 0), Some("aa:aa:aa:aa:aa:01"));
        assert_eq!(names.mac(Some("old"), 120), Some("aa:aa:aa:aa:aa:02"));
        assert_eq!(names.mac(Some("old"), 180), None); // two MACs had that name
        assert_eq!(names.mac(Some("new"), 999), Some("aa:aa:aa:aa:aa:01"));
        assert_eq!(names.name("aa:aa:aa:aa:aa:01").as_deref(), Some("new"));
    }

    #[test]
    fn test_parse_date() {
        assert_eq!(parse_date("2026-10-25"), Some(time::macros::date!(2026 - 10 - 25)));
        assert_eq!(parse_date("25.10.2026"), None);
    }
}
