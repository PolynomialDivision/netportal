//! The job `unifi_events` (Python `collect/unifi_events.py`, INVENTORY 9.4, 9.5): UniFi's client
//! connect/disconnect/roam entries -> `connection_event`.
//!
//! The source: UniFi Network 10.x has no event API any more; client events are in its system log.
//! unpoller (`save_syslog = true`) polls it and pushes every entry to Loki as one JSON line
//! (unpoller `SystemLogEntry.MarshalJSON`, pkg/lokiunifi `SystemLogEvent`):
//!
//! - stream labels `application="unifi_system_log"`, `job="unpoller"`, `site_name`, `source`,
//!   `category`, `severity` (not used here);
//! - the line: `category, event, id, key, message` (rendered), `parameters, severity,
//!   show_on_dashboard, status, subcategory, target, timestamp` (ms), `title_raw, type,
//!   site_name, source_name`;
//! - `parameters`: `{NAME: {id, name, hostname, ip, model, ...}}`; `CLIENT.id` is the client's MAC
//!   (unpoller's `hash_pii` must stay off), `DEVICE` / `DEVICE_TO` the AP (id = its MAC),
//!   `DEVICE_FROM` the AP roamed from, `WLAN` the SSID (name).
//!
//! Not verified on the house controller yet, so everything is parsed defensively: the kind comes
//! from key/event/title (ROAM, DISCONNECT, CONNECT ...), RSSI/channel/band from parameters or the
//! rendered message, everything not mapped is kept in `detail` (without the client's names). An
//! entry without a client MAC is skipped. Only entries of the house SSID are kept, and entries
//! without an SSID only when their MAC is in a device's window (`registry::device_for_mac`).
//! `dedup_key` `unifi_syslog:id:<entry id>` (else the line's SHA-256) makes ingest idempotent.
//!
//! Late lines: Loki stores an entry under the controller's time, which may be well before it
//! arrives (unpoller resumes up to 8 minutes back after an outage, plus a push interval and this
//! job's own 2 minutes). Every run therefore reads again from its cursor minus [`OVERLAP_NS`]
//! (15 minutes; repeats are deduplicated, so the overlap only costs a re-read). A run that
//! stopped inside its range (the page limit, a stop, a failure) goes on exactly where it stopped
//! (`paging`), so paging always moves forward.
//!
//! Rows are inserted and committed in batches of [`BATCH`]: resolving a device extends its window
//! (`device_mac.last_seen`), and FreeRADIUS's logging functions update the same rows on every
//! login; a small batch holds those row locks only briefly.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use indexmap::IndexMap;
use netportal_core::registry::{self, NewConnectionEvent, RegistryError};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::scheduler::{Context, JobError, JobResult, to_cursor};
use crate::sources::{Direction, Entry, normalise_mac};

pub const NAME: &str = "unifi_events";
const LOG: &str = "netportal.collect.unifi_events";

pub const SOURCE: &str = "unifi_syslog";
const NS: i64 = 1_000_000_000;
/// Read again what may have arrived late (see the top).
pub const OVERLAP_NS: i64 = 15 * 60 * NS;
/// No cursor: from Loki's retention (30 days).
pub const FIRST_RUN_NS: i64 = 30 * 86400 * NS;
/// Per run at most a week of log (catching up takes runs).
pub const MAX_WINDOW_NS: i64 = 7 * 86400 * NS;
pub const PAGE_LIMIT: usize = 1000;
/// Loki's default `max_entries_limit_per_query`: the most one nanosecond can hold for us.
pub const SAME_TS_LIMIT: usize = 5000;
pub const MAX_PAGES: usize = 50;
/// Rows per insert and commit (row locks held briefly).
pub const BATCH: usize = 100;

/// The limits of one run (the constants above; tests make them small).
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub overlap_ns: i64,
    pub first_run_ns: i64,
    pub max_window_ns: i64,
    pub page_limit: usize,
    pub same_ts_limit: usize,
    pub max_pages: usize,
    pub batch: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            overlap_ns: OVERLAP_NS,
            first_run_ns: FIRST_RUN_NS,
            max_window_ns: MAX_WINDOW_NS,
            page_limit: PAGE_LIMIT,
            same_ts_limit: SAME_TS_LIMIT,
            max_pages: MAX_PAGES,
            batch: BATCH,
        }
    }
}

// --- one line -------------------------------------------------------------------------------------

/// The radio as Prometheus/unpoller name it (`ng`/`na`/`6e`) from a band in GHz.
fn band_code(ghz: &str) -> Option<&'static str> {
    match ghz {
        "2.4" => Some("ng"),
        "5" => Some("na"),
        "6" => Some("6e"),
        _ => None,
    }
}

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).expect("a valid regular expression")
}

static RSSI_RE: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)(-[0-9]{2,3})\s*dBm"));
static CHANNEL_RE: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)\bCh(?:annel)?\.?\s*([0-9]{1,3})\b"));
static BAND_RE: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)\b(2\.4|5|6)\s*GHz\b"));
static RADIO_RE: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)\b(2\.4|5|6)\s*(?:ghz|g)?\b"));
static DURATION_RE: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)(?:duration|connected for|for)\s*:?\s*((?:[0-9]+\s*(?:d|h|hr|m|min|s|sec)\b\s*)+)"));
static DURATION_PART: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)([0-9]+)\s*(d|h|hr|m|min|s|sec)\b"));
static LEFT_RE: LazyLock<Regex> = LazyLock::new(|| re(r"(^|_)LEFT($|_)"));
static JOIN_RE: LazyLock<Regex> = LazyLock::new(|| re(r"(^|_)JOIN(ED)?($|_)"));
static ENTRY_ID: LazyLock<Regex> = LazyLock::new(|| re(r"^[A-Za-z0-9_.:-]{1,100}$"));

/// Parameter names (exact, in this order) of the AP, the AP roamed from and the SSID.
const AP_KEYS: [&str; 4] = ["DEVICE_TO", "DEVICE", "AP_TO", "AP"];
const FROM_AP_KEYS: [&str; 4] = ["DEVICE_FROM", "AP_FROM", "FROM_DEVICE", "PREVIOUS_DEVICE"];
const SSID_KEYS: [&str; 3] = ["WLAN", "SSID", "WLAN_NAME"];
/// Mapped fields left out of `detail` (besides `parameters`, kept without the client's names).
const MAPPED: [&str; 2] = ["timestamp", "id"];
/// The client's fields that never reach `detail` (personal, not needed).
const CLIENT_PERSONAL: [&str; 3] = ["id", "name", "hostname"];

/// A system-log line as read: its fields in their order, `parameters` apart (an object, in its
/// order: the first matching parameter wins).
#[derive(Deserialize)]
struct RawLine {
    #[serde(default)]
    parameters: Option<RawParameters>,
    #[serde(flatten)]
    fields: IndexMap<String, Value>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawParameters {
    Map(IndexMap<String, Value>),
    Other(serde::de::IgnoredAny),
}

/// A parsed line.
pub struct LogEntry {
    pub fields: IndexMap<String, Value>,
    pub parameters: IndexMap<String, Value>,
}

impl LogEntry {
    pub fn parse(line: &str) -> Option<LogEntry> {
        let raw: RawLine = serde_json::from_str(line).ok()?;
        let parameters = match raw.parameters {
            Some(RawParameters::Map(map)) => map,
            _ => IndexMap::new(),
        };
        Some(LogEntry { fields: raw.fields, parameters })
    }

    fn text(&self, field: &str) -> Option<&str> {
        self.fields.get(field).and_then(Value::as_str)
    }

    fn parameter(&self, keys: &[&str]) -> Option<&Map<String, Value>> {
        keys.iter().find_map(|k| self.parameters.get(*k).and_then(Value::as_object))
    }

    /// The `id` (else `name`) of the first parameter, in the line's order, whose NAME contains
    /// one of the needles (upper case).
    fn parameter_value(&self, needles: &[&str]) -> Option<&Value> {
        self.parameters.iter().find_map(|(name, value)| {
            let value = value.as_object()?;
            let upper = name.to_uppercase();
            if !needles.iter().any(|n| upper.contains(n)) {
                return None;
            }
            ["id", "name"].iter().find_map(|f| value.get(*f).filter(|v| !v.is_null() && v.as_str() != Some("")))
        })
    }
}

/// Why a line is not stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skip {
    Malformed,
    NoClientMac,
    OtherNetwork,
}

impl Skip {
    pub fn as_str(self) -> &'static str {
        match self {
            Skip::Malformed => "malformed",
            Skip::NoClientMac => "no_client_mac",
            Skip::OtherNetwork => "other_network",
        }
    }
}

/// `connected | disconnected | roamed | other`, from the entry's key, then event, then title.
pub fn classify(texts: &[Option<&str>]) -> &'static str {
    for text in texts.iter().flatten().filter(|t| !t.is_empty()) {
        let words = text.to_uppercase();
        if words.contains("ROAM") {
            return "roamed";
        }
        // DISCONNECT contains CONNECT, DISASSOC contains ASSOC: the order matters
        if words.contains("DISCONNECT") || words.contains("DISASSOC") || LEFT_RE.is_match(&words) {
            return "disconnected";
        }
        if words.contains("CONNECT") || words.contains("ASSOC") || JOIN_RE.is_match(&words) {
            return "connected";
        }
    }
    "other"
}

fn classify_entry(entry: &LogEntry) -> &'static str {
    classify(&[entry.text("key"), entry.text("event"), entry.text("title_raw")])
}

fn text_of(value: Option<&Value>) -> Option<String> {
    value.and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string)
}

/// A whole number in `lo..=hi` from a JSON number or a numeric string (truncated towards zero);
/// anything else, also NaN and infinities, `None`.
fn integer(value: Option<&Value>, lo: i64, hi: i64) -> Option<i64> {
    let x = match value? {
        Value::Number(n) => n.as_f64()?,
        Value::String(s) => s.trim().parse::<f64>().ok()?,
        _ => return None,
    };
    if !x.is_finite() {
        return None;
    }
    let n = x.trunc();
    (n >= lo as f64 && n <= hi as f64).then_some(n as i64)
}

fn i32_of(n: Option<i64>) -> Option<i32> {
    n.and_then(|n| i32::try_from(n).ok())
}

/// The radio code of a parameter value: `ng`/`na`/`6e` as they are, the 802.11 letters `g`/`a`
/// as their band, a band in GHz (`5`, `2.4 GHz`, `6g`) as its code; anything else `None`.
fn radio(value: Option<&Value>) -> Option<String> {
    let text = match value? {
        Value::String(s) => s.trim().to_lowercase(),
        Value::Number(n) => n.to_string(),
        _ => return None,
    };
    match text.as_str() {
        "" => None,
        "ng" | "na" | "6e" => Some(text),
        "g" => Some("ng".into()),
        "a" => Some("na".into()),
        _ => RADIO_RE.captures(&text).and_then(|m| band_code(&m[1])).map(str::to_string),
    }
}

/// A duration in a rendered message (`Connected for 1h 2m 3s.` -> 3723), at most 10^9 s.
fn duration_in(message: &str) -> Option<i64> {
    let m = DURATION_RE.captures(message)?;
    let mut total: i64 = 0;
    for part in DURATION_PART.captures_iter(&m[1]) {
        let n: i64 = part[1].parse().ok()?;
        let unit = match part[2].to_lowercase().as_str() {
            "d" => 86400,
            "h" | "hr" => 3600,
            "m" | "min" => 60,
            _ => 1,
        };
        total = total.checked_add(n.checked_mul(unit)?)?;
    }
    (total <= 1_000_000_000).then_some(total)
}

/// The entry's time: its own timestamp (ms) when plausible, else Loki's.
fn entry_time(entry: &LogEntry, ts_ns: i64) -> Option<OffsetDateTime> {
    let own = entry.fields.get("timestamp").and_then(Value::as_f64).filter(|ms| (1e12..=1e13).contains(ms));
    match own {
        Some(ms) => OffsetDateTime::from_unix_timestamp_nanos((ms * 1e6) as i128).ok(),
        None => OffsetDateTime::from_unix_timestamp_nanos(i128::from(ts_ns)).ok(),
    }
}

/// `unifi_syslog:id:<id>` for a plausible entry id, else `unifi_syslog:sha256:<hex of the line>`.
pub fn dedup_key(entry: &LogEntry, line: &str) -> String {
    match entry.text("id").filter(|id| ENTRY_ID.is_match(id)) {
        Some(id) => format!("{SOURCE}:id:{id}"),
        None => format!("{SOURCE}:sha256:{}", hex::encode(Sha256::digest(line.as_bytes()))),
    }
}

/// The entry without what was mapped and without the client's names: `CLIENT` loses its `id`,
/// `name` and `hostname`, and the client's name and host name are replaced by `<client>` in the
/// rendered texts (the message names the client).
fn detail_of(entry: &LogEntry) -> Value {
    let client = entry.parameters.get("CLIENT").and_then(Value::as_object);
    let names: Vec<String> = client
        .map(|c| {
            ["name", "hostname"].iter().filter_map(|f| text_of(c.get(*f))).filter(|n| n.chars().count() >= 3).collect()
        })
        .unwrap_or_default();
    let mut detail = Map::new();
    for (key, value) in &entry.fields {
        if MAPPED.contains(&key.as_str()) {
            continue;
        }
        let value = match value {
            Value::String(text) if !names.is_empty() => {
                Value::String(names.iter().fold(text.clone(), |t, name| t.replace(name.as_str(), "<client>")))
            }
            other => other.clone(),
        };
        detail.insert(key.clone(), value);
    }
    if !entry.parameters.is_empty() {
        let mut kept = Map::new();
        for (name, value) in &entry.parameters {
            let value = match value {
                Value::Object(c) if name == "CLIENT" => Value::Object(
                    c.iter()
                        .filter(|(k, _)| !CLIENT_PERSONAL.contains(&k.as_str()))
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect(),
                ),
                other => other.clone(),
            };
            kept.insert(name.clone(), value);
        }
        detail.insert("parameters".into(), Value::Object(kept));
    }
    Value::Object(detail)
}

/// The `connection_event` row of a client entry, or why the line is skipped. The device is
/// resolved later (by [`keep`] or at insert).
pub fn map_entry(line: &str, ts_ns: i64) -> Result<NewConnectionEvent, Skip> {
    let entry = LogEntry::parse(line).ok_or(Skip::Malformed)?;
    let mac = entry
        .parameters
        .get("CLIENT")
        .and_then(Value::as_object)
        .and_then(|c| c.get("id"))
        .and_then(Value::as_str)
        .and_then(normalise_mac)
        .ok_or(Skip::NoClientMac)?;
    let ap = entry.parameter(&AP_KEYS);
    let from_ap = entry.parameter(&FROM_AP_KEYS);
    let wlan = entry.parameter(&SSID_KEYS);
    let message = entry.text("message").unwrap_or("");
    let kind = classify_entry(&entry);
    let from_message = |re: &Regex| re.captures(message).map(|m| Value::String(m[1].to_string()));
    let rssi = integer(entry.parameter_value(&["RSSI", "SIGNAL"]), -120, 0)
        .or_else(|| integer(from_message(&RSSI_RE).as_ref(), -120, 0));
    let channel = integer(entry.parameter_value(&["CHANNEL"]), 1, 233)
        .or_else(|| integer(from_message(&CHANNEL_RE).as_ref(), 1, 233));
    let radio = radio(entry.parameter_value(&["RADIO", "BAND"]))
        .or_else(|| BAND_RE.captures(message).and_then(|m| band_code(&m[1])).map(str::to_string));
    let mut duration = integer(entry.parameter_value(&["DURATION", "UPTIME"]), 0, 1_000_000_000);
    if duration.is_none() && kind == "disconnected" {
        duration = duration_in(message);
    }
    let mac_in =
        |p: Option<&Map<String, Value>>| p.and_then(|p| p.get("id")).and_then(Value::as_str).and_then(normalise_mac);
    let name_in = |p: Option<&Map<String, Value>>| text_of(p.and_then(|p| p.get("name")));
    Ok(NewConnectionEvent {
        at: entry_time(&entry, ts_ns),
        kind: kind.to_string(),
        source: SOURCE.to_string(),
        mac,
        ap_mac: mac_in(ap),
        ap_name: name_in(ap),
        from_ap_mac: mac_in(from_ap),
        from_ap_name: name_in(from_ap),
        ssid: name_in(wlan).or_else(|| text_of(wlan.and_then(|w| w.get("id")))),
        radio,
        channel: i32_of(channel),
        rssi: i32_of(rssi),
        duration_s: duration,
        rx_bytes: integer(entry.parameter_value(&["RX_BYTES", "DOWNLOAD"]), 0, 1_000_000_000_000_000),
        tx_bytes: integer(entry.parameter_value(&["TX_BYTES", "UPLOAD"]), 0, 1_000_000_000_000_000),
        detail: Some(detail_of(&entry)),
        dedup_key: dedup_key(&entry, line),
        device_id: None,
    })
}

// --- the job ----------------------------------------------------------------------------------------

/// Whether the row is the house network's: its SSID is the house SSID, or (none known) its MAC is
/// in a device's window then (the device is set on the row).
pub async fn keep(
    db: &mut netportal_core::Db,
    row: &mut NewConnectionEvent,
    ssid: &str,
) -> Result<bool, RegistryError> {
    if let Some(own) = &row.ssid {
        return Ok(own == ssid);
    }
    let Some(at) = row.at else {
        return Ok(false);
    };
    row.device_id = registry::device_for_mac(db, &row.mac, at).await?;
    Ok(row.device_id.is_some())
}

/// What a run did (in the cursor's `last_run`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counts {
    pub read: u64,
    pub inserted: u64,
    pub skipped: BTreeMap<String, u64>,
}

/// The cursor: `{"until_ns": ns, "paging": true (only while paging), "last_run": counts}`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cursor {
    #[serde(default)]
    pub until_ns: Option<i64>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub paging: bool,
    #[serde(default)]
    pub last_run: Counts,
}

fn to_value(cursor: &Cursor) -> Value {
    serde_json::to_value(cursor).unwrap_or_else(|_| Value::Object(Map::new()))
}

/// Maps, filters and inserts one page; commits after every batch of rows (and at the end).
async fn ingest(ctx: &mut Context, entries: &[Entry], counts: &mut Counts, batch: usize) -> Result<(), JobError> {
    let ssid = ctx.settings.ssid.clone();
    let mut rows = Vec::new();
    for entry in entries {
        counts.read += 1;
        let skip = match map_entry(&entry.line, entry.ts_ns) {
            Ok(mut row) => {
                if keep(&mut ctx.db, &mut row, &ssid).await? {
                    rows.push(row);
                    continue;
                }
                Skip::OtherNetwork
            }
            Err(why) => why,
        };
        *counts.skipped.entry(skip.as_str().to_string()).or_default() += 1;
    }
    for chunk in rows.chunks(batch.max(1)) {
        counts.inserted += registry::insert_connection_events(&mut ctx.db, chunk).await?;
        ctx.db.commit().await?;
    }
    ctx.db.commit().await?; // also the reads of a page without rows
    Ok(())
}

pub async fn run(ctx: &mut Context) -> JobResult {
    run_with(ctx, Limits::default()).await
}

/// The job with these limits.
pub async fn run_with(ctx: &mut Context, limits: Limits) -> JobResult {
    let loki = ctx.loki()?;
    let selector = ctx.settings.loki_selector.clone();
    let now_ns =
        i64::try_from(ctx.now.unix_timestamp_nanos()).map_err(|_| JobError::Other("time out of range".into()))?;
    let previous: Cursor = ctx.cursor_as();
    let mut start = match previous.until_ns {
        // stopped inside its range: on exactly there; read to the end: the overlap again
        Some(until) if until > 0 => {
            (if previous.paging { until } else { until - limits.overlap_ns }).max(now_ns - limits.first_run_ns)
        }
        _ => now_ns - limits.first_run_ns,
    };
    if start >= now_ns {
        start = now_ns - limits.overlap_ns; // a cursor ahead of the clock
    }
    let end = now_ns.min(start.saturating_add(limits.max_window_ns));
    let mut counts = Counts::default();
    let (mut page_start, mut pages, mut done) = (start, 0, false);
    while pages < limits.max_pages && !ctx.stopping() {
        if page_start >= end {
            done = true;
            break;
        }
        let entries = loki.entries(&selector, page_start, end, limits.page_limit, Direction::Forward).await?;
        pages += 1;
        if entries.len() >= limits.page_limit && entries.last().is_some_and(|e| e.ts_ns == page_start) {
            // a full page of one timestamp: forward paging cannot get past it; that one
            // nanosecond with Loki's largest limit
            let entries =
                loki.entries(&selector, page_start, page_start + 1, limits.same_ts_limit, Direction::Forward).await?;
            ingest(ctx, &entries, &mut counts, limits.batch).await?;
            page_start += 1;
            ctx.save(to_value(&Cursor { until_ns: Some(page_start), paging: true, last_run: counts.clone() }));
            continue;
        }
        ingest(ctx, &entries, &mut counts, limits.batch).await?;
        match entries.last() {
            Some(last) if entries.len() >= limits.page_limit => {
                // a full page: on from its last timestamp (inclusive: the repeats are deduplicated)
                page_start = last.ts_ns;
                ctx.save(to_value(&Cursor { until_ns: Some(page_start), paging: true, last_run: counts.clone() }));
            }
            _ => {
                done = true;
                break;
            }
        }
    }
    if counts.read > 0 {
        tracing::info!(target: LOG, "unifi_events: {} read, {} new, skipped {:?}", counts.read, counts.inserted, counts.skipped);
    }
    let cursor = if done {
        Cursor { until_ns: Some(end), paging: false, last_run: counts }
    } else {
        Cursor { until_ns: Some(page_start), paging: true, last_run: counts }
    };
    to_cursor(&cursor)
}

#[cfg(test)]
mod tests {
    //! Python test_collect_events.py MappingTests (the job's tests are in tests/collect_events.rs).
    use super::*;
    use serde_json::json;

    pub const PHONE: &str = "02:11:22:33:44:55";
    pub const LAPTOP: &str = "a4:83:e7:00:00:01";
    const AP_A: (&str, &str) = ("60:22:32:37:48:00", "ap-scharni-2-corner");
    const AP_B: (&str, &str) = ("68:d7:9a:1c:61:46", "ap-scharni-4-corner");
    /// 2026-10-25 12:00 UTC in ms
    const NOW_MS: i64 = 1_792_929_600_000;

    fn ms(minutes_ago: i64) -> i64 {
        NOW_MS - minutes_ago * 60_000
    }

    struct E {
        key: &'static str,
        mac: &'static str,
        minutes_ago: i64,
        id: &'static str,
        ap: Option<(&'static str, &'static str)>,
        from_ap: Option<(&'static str, &'static str)>,
        wlan: Option<&'static str>,
        message: &'static str,
    }

    impl E {
        fn new(key: &'static str, mac: &'static str, minutes_ago: i64, id: &'static str) -> E {
            E { key, mac, minutes_ago, id, ap: Some(AP_A), from_ap: None, wlan: Some("Scharni"), message: "" }
        }

        fn line(&self, extra: Value) -> String {
            let client_id =
                if self.mac == LAPTOP { self.mac.to_uppercase().replace(':', "-") } else { self.mac.into() };
            let mut params = serde_json::Map::new();
            params.insert(
                "CLIENT".into(),
                json!({"id": client_id, "name": "Nicks Phone", "hostname": "nicks-phone", "ip": "10.0.30.140"}),
            );
            if let Some(ap) = self.ap {
                let key = if self.from_ap.is_some() { "DEVICE_TO" } else { "DEVICE" };
                params.insert(key.into(), json!({"id": ap.0, "name": ap.1, "model": "UAL6"}));
            }
            if let Some(from) = self.from_ap {
                params.insert("DEVICE_FROM".into(), json!({"id": from.0, "name": from.1}));
            }
            if let Some(wlan) = self.wlan {
                params.insert("WLAN".into(), json!({"id": "65f0aa", "name": wlan}));
            }
            let mut body = json!({
                "category": "CLIENT_DEVICES", "event": self.key.replace("WIRELESS_", ""), "id": self.id,
                "key": self.key, "message": self.message, "parameters": params, "severity": "LOW",
                "show_on_dashboard": false, "status": "", "subcategory": "WIFI", "target": "",
                "timestamp": ms(self.minutes_ago), "title_raw": self.key.replace('_', " "), "type": "CLIENT",
                "site_name": "Default (default)", "source_name": "https://unifi.scharni.org",
            });
            if let (Some(b), Some(x)) = (body.as_object_mut(), extra.as_object()) {
                b.extend(x.clone());
            }
            body.to_string()
        }
    }

    fn connect() -> String {
        E {
            message: "Nicks Phone connected to Scharni on ap-scharni-2-corner. Connection Info: Ch. 36 (5 GHz, 80 MHz), -61 dBm",
            ..E::new("WIRELESS_CLIENT_CONNECTED", PHONE, 30, "6720aa01")
        }
        .line(json!({}))
    }

    fn row(line: &str) -> NewConnectionEvent {
        map_entry(line, NOW_MS * 1_000_000).expect("a row")
    }

    fn at_ms(ms: i64) -> Option<OffsetDateTime> {
        OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000).ok()
    }

    #[test]
    fn test_connect() {
        let r = row(&connect());
        assert_eq!(
            (r.kind.as_str(), r.mac.as_str(), r.ap_mac.as_deref(), r.ap_name.as_deref(), r.ssid.as_deref()),
            ("connected", PHONE, Some(AP_A.0), Some(AP_A.1), Some("Scharni"))
        );
        assert_eq!((r.channel, r.radio.as_deref(), r.rssi), (Some(36), Some("na"), Some(-61)));
        assert_eq!(r.at, at_ms(ms(30))); // the entry's own time
        assert_eq!(r.source, "unifi_syslog");
        assert_eq!(r.dedup_key, "unifi_syslog:id:6720aa01");
        let detail = r.detail.expect("detail");
        // unmapped fields stay, the client's names do not
        assert_eq!(detail["subcategory"], "WIFI");
        assert_eq!(detail["parameters"]["CLIENT"], json!({"ip": "10.0.30.140"}));
        assert_eq!(detail["parameters"]["DEVICE"]["model"], "UAL6");
        assert!(detail.get("timestamp").is_none());
        assert!(detail.get("id").is_none());
        assert_eq!(
            detail["message"],
            "<client> connected to Scharni on ap-scharni-2-corner. Connection Info: Ch. 36 (5 GHz, 80 MHz), -61 dBm"
        );
    }

    #[test]
    fn test_roam() {
        let line = E {
            ap: Some(AP_B),
            from_ap: Some(AP_A),
            message: "Nicks Phone roamed from ap-scharni-2-corner to ap-scharni-4-corner. Ch. 6 (2.4 GHz), -70 dBm",
            ..E::new("WIRELESS_CLIENT_ROAMED", PHONE, 20, "6720aa02")
        }
        .line(json!({}));
        let r = row(&line);
        assert_eq!(
            (
                r.kind.as_str(),
                r.ap_mac.as_deref(),
                r.ap_name.as_deref(),
                r.from_ap_mac.as_deref(),
                r.from_ap_name.as_deref()
            ),
            ("roamed", Some(AP_B.0), Some(AP_B.1), Some(AP_A.0), Some(AP_A.1))
        );
        assert_eq!((r.channel, r.radio.as_deref(), r.rssi), (Some(6), Some("ng"), Some(-70)));
    }

    #[test]
    fn test_disconnect_without_wlan() {
        let line = E {
            ap: Some(AP_B),
            wlan: None,
            message: "Nicks Phone disconnected from Scharni. Connected for 1h 2m 3s.",
            ..E::new("WIRELESS_CLIENT_DISCONNECTED", PHONE, 10, "6720aa03")
        }
        .line(json!({}));
        let r = row(&line);
        assert_eq!((r.kind.as_str(), r.ssid.as_deref(), r.duration_s), ("disconnected", None, Some(3723)));
    }

    #[test]
    fn test_unknown_shape_is_kept_as_other() {
        let line =
            E { message: "something new", ..E::new("CLIENT_BLOCKED_BY_POLICY", PHONE, 9, "6720aa04") }.line(json!({}));
        let r = row(&line);
        assert_eq!(r.kind, "other");
        assert_eq!(r.detail.expect("detail")["key"], "CLIENT_BLOCKED_BY_POLICY");
    }

    #[test]
    fn test_dash_separated_mac() {
        let line = E { ap: Some(AP_B), ..E::new("WIRELESS_CLIENT_CONNECTED", LAPTOP, 8, "6720aa05") }.line(json!({}));
        assert_eq!(row(&line).mac, LAPTOP);
    }

    #[test]
    fn test_malformed() {
        let no_client =
            json!({"key": "WIRELESS_CLIENT_CONNECTED", "id": "6720aa08", "parameters": {"WLAN": {"name": "Scharni"}}, "timestamp": ms(5)})
                .to_string();
        for (line, why) in [
            ("not json".to_string(), Skip::Malformed),
            ("[1, 2]".to_string(), Skip::Malformed),
            ("\"text\"".to_string(), Skip::Malformed),
            ("".to_string(), Skip::Malformed),
            (no_client, Skip::NoClientMac),
            (json!({"parameters": {"CLIENT": {"id": "zz"}}}).to_string(), Skip::NoClientMac),
            (json!({"parameters": {"CLIENT": {"id": 5}}}).to_string(), Skip::NoClientMac),
            (json!({"parameters": {"CLIENT": "02:11:22:33:44:55"}}).to_string(), Skip::NoClientMac),
            (json!({"parameters": "x"}).to_string(), Skip::NoClientMac),
        ] {
            assert_eq!(map_entry(&line, 1).err(), Some(why), "{line}");
        }
    }

    #[test]
    fn test_missing_fields_do_not_break_it() {
        let r = map_entry(&json!({"parameters": {"CLIENT": {"id": PHONE}}}).to_string(), 1_792_931_000 * 1_000_000_000)
            .expect("row");
        assert_eq!((r.kind.as_str(), r.ap_mac.as_deref(), r.ssid.as_deref(), r.rssi), ("other", None, None, None));
        assert_eq!(r.at, OffsetDateTime::from_unix_timestamp(1_792_931_000).ok()); // Loki's time
        assert!(r.dedup_key.starts_with("unifi_syslog:sha256:"));
        assert_eq!(r.dedup_key.len(), "unifi_syslog:sha256:".len() + 64);
    }

    #[test]
    fn test_weird_values() {
        let line = E { message: "Ch. 999, +5 dBm", ..E::new("WIRELESS_CLIENT_CONNECTED", PHONE, 1, "../../x") }
            .line(json!({"timestamp": "yesterday"}));
        let r = row(&line);
        assert_eq!((r.channel, r.rssi), (None, None));
        assert!(r.dedup_key.starts_with("unifi_syslog:sha256:")); // an id that is no id
        assert_eq!(r.at, at_ms(NOW_MS)); // Loki's time: the entry's is no time
        // values that are not numbers, or too big, or not finite
        let params = json!({"CLIENT": {"id": PHONE}, "RSSI": {"id": "inf"}, "CHANNEL": {"id": true},
                            "UPTIME": {"id": 1e30}, "RX_BYTES": {"name": "-5"}, "RADIO": {"id": {"x": 1}}});
        let r = map_entry(&json!({"parameters": params, "message": "for 99999999999999999999d"}).to_string(), 1)
            .expect("row");
        assert_eq!((r.rssi, r.channel, r.duration_s, r.rx_bytes, r.radio), (None, None, None, None, None));
    }

    #[test]
    fn test_parameter_values_in_line_order() {
        // the first parameter (in the line's order) whose name contains a needle; id before name
        let line = r#"{"key":"X","parameters":{"CLIENT":{"id":"02:11:22:33:44:55"},"SIGNAL_OLD":{"name":"-80"},
                       "RSSI":{"id":"-55"},"CHANNEL_INFO":{"id":"","name":"11"},"RADIO_BAND":{"id":"5 GHz"},
                       "DURATION_S":{"id":"600"},"TX_BYTES":{"id":42}}}"#;
        let r = map_entry(line, 1).expect("row");
        assert_eq!((r.rssi, r.channel, r.radio.as_deref()), (Some(-80), Some(11), Some("na")));
        assert_eq!((r.duration_s, r.tx_bytes), (Some(600), Some(42)));
    }

    #[test]
    fn test_radio() {
        for (value, want) in [
            (json!("ng"), Some("ng")),
            (json!("NA"), Some("na")),
            (json!("6e"), Some("6e")),
            (json!("g"), Some("ng")),
            (json!("a"), Some("na")),
            (json!("be"), None),
            (json!("2.4 GHz"), Some("ng")),
            (json!("5g"), Some("na")),
            (json!(6), Some("6e")),
            (json!(2.4), Some("ng")),
            (json!("160 MHz"), None),
            (json!("15"), None),
            (json!(""), None),
        ] {
            assert_eq!(radio(Some(&value)).as_deref(), want, "{value}");
        }
    }

    #[test]
    fn test_classify() {
        for (key, kind) in [
            ("CLIENT_ROAMED_RADIO", "roamed"),
            ("EVT_WU_Disconnected", "disconnected"),
            ("CLIENT_DISASSOCIATED", "disconnected"),
            ("WIFI_CLIENT_JOINED", "connected"),
            ("CLIENT_RECONNECTED", "connected"),
            ("CLIENT_LEFT", "disconnected"),
            ("CLIENT_BLOCKED", "other"),
        ] {
            assert_eq!(classify(&[Some(key)]), kind, "{key}");
        }
        // key first, then event, then title; empty fields are passed over
        assert_eq!(classify(&[Some(""), Some("CLIENT_BLOCKED"), Some("Client Roamed")]), "roamed");
        assert_eq!(classify(&[None, None, None]), "other");
    }

    #[test]
    fn test_durations() {
        assert_eq!(duration_in("Connected for 1h 2m 3s."), Some(3723));
        assert_eq!(duration_in("duration: 2min 5sec"), Some(125));
        assert_eq!(duration_in("for 1d"), Some(86400));
        assert_eq!(duration_in("no time here"), None);
    }
}
