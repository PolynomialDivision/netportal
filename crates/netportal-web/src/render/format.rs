//! The dashboard's formatting per language (Python `i18n.Format`, INVENTORY 11.5-11.6): numbers,
//! sizes, rates, durations, moments in the house's time zone, rooms, Wi-Fi bands, the telemetry
//! codes (causes, reasons, incidents, evidence) and the presence line. Plain functions on JSON
//! values (the payloads' shapes, INVENTORY 9.12), registered for the templates as `fmt` by
//! [`super`]; `static/format.js` and `static/presence.js` answer alike in the browser.
//!
//! Every function returns [`NONE`] (`–`) for an unknown value. Where this port differs from
//! Python, the core conventions decide (`netportal_core::conventions`, `netportal_core::i18n`;
//! `docs/PARITY.md`): rounding half away from zero, RFC 3339 `Z` times, `fill` keeping an
//! unknown `{name}`. Beyond them: numeric strings are read as numbers, a value of another shape
//! than a function expects gives `–` (Python raised: HTTP 500), and a moment is an RFC 3339 /
//! ISO 8601 string (Python also took `datetime` objects).

use std::sync::LazyLock;

use jiff::tz::TimeZone;
use jiff::{Timestamp, civil};
use netportal_core::conventions;
use netportal_core::i18n::{self, fill};
use regex::Regex;
use serde_json::{Map, Value, json};

/// What every method shows for an unknown value (Python `Format.NONE`).
pub const NONE: &str = "\u{2013}";

// The access points' limits (Python diagnostics.py AP_*, BUSY_CHANNEL_WARN; i18n.AP_WEAK_SHARE_WARN).
const AP_CLIENTS_WARN: f64 = 25.0;
const AP_UTIL_WARN: f64 = 0.8;
const AP_LOAD_MIN_CLIENTS: f64 = 10.0;
const BUSY_CHANNEL_WARN: f64 = 0.6;
const AP_WEAK_MIN_CLIENTS: f64 = 4.0;
const AP_RESTARTED_S: f64 = 86400.0;
const AP_UPLINK_MIN_MBPS: f64 = 1000.0;
/// The limits above by the names of the backend's constants (a test compares them with
/// `netportal-telemetry`'s `diagnostics.rs`).
pub const AP_LIMITS: [(&str, f64); 7] = [
    ("AP_CLIENTS_WARN", AP_CLIENTS_WARN),
    ("AP_UTIL_WARN", AP_UTIL_WARN),
    ("AP_LOAD_MIN_CLIENTS", AP_LOAD_MIN_CLIENTS),
    ("BUSY_CHANNEL_WARN", BUSY_CHANNEL_WARN),
    ("AP_WEAK_MIN_CLIENTS", AP_WEAK_MIN_CLIENTS),
    ("AP_RESTARTED_S", AP_RESTARTED_S),
    ("AP_UPLINK_MIN_MBPS", AP_UPLINK_MIN_MBPS),
];

// --- texts and tables ---------------------------------------------------------------------------

/// A text of `lang`, or the key itself when there is none (the browser's `t()` does the same).
pub fn t<'a>(lang: &str, key: &'a str) -> &'a str {
    i18n::text(lang, key).unwrap_or(key)
}

/// A text of `lang` if it exists (Python `t.get(key)`).
fn t_get(lang: &str, key: &str) -> Option<&'static str> {
    i18n::text(lang, key)
}

/// A text of `lang` if it exists and is not empty (Python `t.get(key) or …`).
fn t_nonempty(lang: &str, key: &str) -> Option<&'static str> {
    t_get(lang, key).filter(|s| !s.is_empty())
}

/// A code table of `i18n.py` as a list of strings (DIAGNOSES, TERMINATE_CAUSES, ...).
pub fn codes(name: &str) -> Vec<&'static str> {
    i18n::tables()
        .get(name)
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

fn is_code(table: &str, code: &str) -> bool {
    i18n::tables().get(table).and_then(Value::as_array).is_some_and(|a| a.iter().any(|c| c.as_str() == Some(code)))
}

fn table(name: &str) -> &'static Value {
    static NULL: Value = Value::Null;
    i18n::tables().get(name).unwrap_or(&NULL)
}

// --- values -------------------------------------------------------------------------------------

/// Python truthiness of a JSON value.
pub fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|x| x != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// A number from a JSON number or a numeric string (Python `float(value)`); `None` otherwise.
pub fn num(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse::<f64>().ok(),
        _ => None,
    }
    .filter(|x| x.is_finite())
}

/// Python `str(value)` for the scalars of a payload (`None`, `True`, `2.0`; lists and maps as JSON).
pub fn py_str(v: &Value) -> String {
    match v {
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::String(s) => s.clone(),
        Value::Number(n) if n.is_f64() => {
            let x = n.as_f64().unwrap_or(0.0);
            if x.fract() == 0.0 && x.abs() < 1e16 { format!("{x:.1}") } else { format!("{x}") }
        }
        Value::Number(n) => n.to_string(),
        other => other.to_string(),
    }
}

fn get<'a>(v: &'a Value, key: &str) -> &'a Value {
    static NULL: Value = Value::Null;
    v.get(key).unwrap_or(&NULL)
}

fn empty_value(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
        _ => false,
    }
}

// --- numbers ------------------------------------------------------------------------------------

/// A number with `digits` decimals in the language's style (core `format_number`).
pub fn number(value: Option<f64>, lang: &str, digits: u32) -> String {
    i18n::format_number(value, lang, digits)
}

/// 1-2 significant decimals: 4.2 MB, 42 MB, 420 MB.
fn scaled(value: Option<f64>, lang: &str, units: &[&str]) -> String {
    let Some(mut v) = value else {
        return NONE.into();
    };
    let mut unit = 0;
    while v.abs() >= 1000.0 && unit < units.len() - 1 {
        v /= 1000.0;
        unit += 1;
    }
    let digits = if unit > 0 && v.abs() < 10.0 { 1 } else { 0 };
    format!("{} {}", number(Some(v), lang, digits), t(lang, units[unit]))
}

/// Bytes in SI units (1000): "1,8 GB".
pub fn bytes(value: Option<f64>, lang: &str) -> String {
    scaled(value, lang, &["u_b", "u_kb", "u_mb", "u_gb", "u_tb"])
}

/// Bits per second: "2,4 Mbit/s".
pub fn bitrate(value: Option<f64>, lang: &str) -> String {
    scaled(value, lang, &["u_bit", "u_kbit", "u_mbit", "u_gbit"])
}

/// A ratio as a percentage: "24%" (en), "24\u{a0}%" (de, uk: a no-break space).
pub fn percent(ratio: Option<f64>, lang: &str, digits: u32) -> String {
    let Some(ratio) = ratio else {
        return NONE.into();
    };
    let sign = if lang == "de" || lang == "uk" { "\u{a0}%" } else { "%" };
    number(Some(ratio * 100.0), lang, digits) + sign
}

fn unit_text(key: &str, value: Option<f64>, lang: &str, digits: u32) -> String {
    match value {
        None => NONE.into(),
        Some(v) => fill(t(lang, key), &[("n", &number(Some(v), lang, digits))]),
    }
}

/// "−58 dBm".
pub fn dbm(value: Option<f64>, lang: &str) -> String {
    unit_text("dbm_fmt", value, lang, 0)
}

/// "37 dB".
pub fn db(value: Option<f64>, lang: &str) -> String {
    unit_text("db_fmt", value, lang, 0)
}

/// "11 ms", one decimal below 10.
pub fn ms(value: Option<f64>, lang: &str) -> String {
    let digits = if value.is_some_and(|v| v < 10.0) { 1 } else { 0 };
    unit_text("ms_fmt", value, lang, digits)
}

/// The largest units: "2 h 15 min", "3 d 4 h", "40 s" (at most `parts` of them; seconds only
/// below a minute; "2 h", not "2 h 0 min 5 s").
pub fn duration(seconds: Option<f64>, lang: &str, parts: usize) -> String {
    let Some(seconds) = seconds else {
        return NONE.into();
    };
    let mut rest = seconds.trunc().max(0.0) as u64;
    let mut out: Vec<String> = Vec::new();
    for (key, size) in [("dur_d", 86400), ("dur_h", 3600), ("dur_min", 60), ("dur_s", 1)] {
        let n = rest / size;
        rest %= size;
        if n > 0 && out.len() < parts {
            out.push(fill(t(lang, key), &[("n", &n.to_string())]));
        } else if !out.is_empty() {
            break;
        }
        if key == "dur_min" && !out.is_empty() {
            break;
        }
    }
    if out.is_empty() { fill(t(lang, "dur_s"), &[("n", "0")]) } else { out.join(" ") }
}

// --- moments ------------------------------------------------------------------------------------

/// The house's time zone (`HOUSE_TZ`, Europe/Berlin), UTC if the zone database lacks it.
pub fn house_zone() -> &'static TimeZone {
    static ZONE: LazyLock<TimeZone> = LazyLock::new(|| {
        let name = table("HOUSE_TZ").as_str().unwrap_or("Europe/Berlin");
        conventions::zone(name).unwrap_or(TimeZone::UTC)
    });
    &ZONE
}

/// An ISO 8601 / RFC 3339 moment (`Z` or an offset; without one: UTC; a date alone: its
/// midnight UTC), as the payloads send them; `None` for anything else (Python `parse_time`).
pub fn parse_time(value: &Value) -> Option<Timestamp> {
    let s = value.as_str()?;
    if s.is_empty() {
        return None;
    }
    if let Ok(ts) = s.parse::<Timestamp>() {
        return Some(ts);
    }
    if let Ok(dt) = s.parse::<civil::DateTime>() {
        return dt.to_zoned(TimeZone::UTC).ok().map(|z| z.timestamp());
    }
    s.parse::<civil::Date>().ok().and_then(|d| d.to_zoned(TimeZone::UTC).ok()).map(|z| z.timestamp())
}

fn seconds_between(later: Timestamp, earlier: Timestamp) -> f64 {
    (later.as_nanosecond() - earlier.as_nanosecond()) as f64 / 1e9
}

fn local(moment: Timestamp) -> civil::DateTime {
    moment.to_zoned(house_zone().clone()).datetime()
}

/// `%Y %m %d %e` (day without a leading zero) `%H %M %S %b` (the language's short month); no
/// locale needed.
pub fn strftime(when: civil::DateTime, pattern: &str, lang: &str) -> String {
    let month = when.month();
    let month_name = i18n::list(lang, "months")
        .and_then(|m| m.get(usize::try_from(month - 1).unwrap_or(0)))
        .map(String::as_str)
        .unwrap_or("");
    pattern
        .replace("%Y", &format!("{:04}", when.year()))
        .replace("%m", &format!("{month:02}"))
        .replace("%d", &format!("{:02}", when.day()))
        .replace("%e", &when.day().to_string())
        .replace("%H", &format!("{:02}", when.hour()))
        .replace("%M", &format!("{:02}", when.minute()))
        .replace("%S", &format!("{:02}", when.second()))
        .replace("%b", month_name)
}

/// "5 min ago", "just now" (under a minute).
pub fn ago(value: &Value, lang: &str, now: Option<Timestamp>) -> String {
    let Some(when) = parse_time(value) else {
        return NONE.into();
    };
    let seconds = seconds_between(now.unwrap_or_else(Timestamp::now), when);
    if seconds < 60.0 {
        return t(lang, "ago_now").into();
    }
    fill(t(lang, "ago_fmt"), &[("when", &duration(Some(seconds), lang, 1))])
}

/// A moment to the second, for what was just confirmed: "just now" (under 5 s), "12 s ago",
/// beyond a minute as [`ago`].
pub fn recent(value: &Value, lang: &str, now: Option<Timestamp>) -> String {
    let Some(when) = parse_time(value) else {
        return NONE.into();
    };
    let now = now.unwrap_or_else(Timestamp::now);
    let seconds = seconds_between(now, when);
    if seconds < 5.0 {
        return t(lang, "ago_now").into();
    }
    if seconds < 60.0 {
        let n = (seconds.trunc() as i64).to_string();
        return fill(t(lang, "ago_fmt"), &[("when", &fill(t(lang, "dur_s"), &[("n", &n)]))]);
    }
    ago(value, lang, Some(now))
}

/// The full moment with seconds in the house's time (a tooltip): "2026-10-25 16:52:13".
pub fn stamp(value: &Value, lang: &str) -> String {
    match parse_time(value) {
        None => NONE.into(),
        Some(m) => strftime(local(m), &format!("{} %H:%M:%S", t(lang, "date_format")), lang),
    }
}

/// How long since `start`, as a duration ("2 h 15 min").
pub fn elapsed(start: &Value, lang: &str, now: Option<Timestamp>) -> String {
    match parse_time(start) {
        None => NONE.into(),
        Some(begin) => duration(Some(seconds_between(now.unwrap_or_else(Timestamp::now), begin)), lang, 2),
    }
}

/// A moment in the house's time: "14:05" today, "yesterday 14:05", else "24 Oct 14:05" (with
/// the year when it is not this year).
pub fn when(value: &Value, lang: &str, now: Option<Timestamp>) -> String {
    let Some(moment) = parse_time(value) else {
        return NONE.into();
    };
    let moment = local(moment);
    let today = local(now.unwrap_or_else(Timestamp::now)).date();
    let clock = strftime(moment, t(lang, "time_format"), lang);
    if moment.date() == today {
        return clock;
    }
    if today.yesterday().is_ok_and(|y| y == moment.date()) {
        return fill(t(lang, "yesterday_at"), &[("time", &clock)]);
    }
    let pattern = if moment.year() == today.year() { t(lang, "day_format") } else { t(lang, "date_format") };
    format!("{} {}", strftime(moment, pattern, lang), clock)
}

/// The day of a moment in the house's time (`date_format`).
pub fn date(value: &Value, lang: &str) -> String {
    match parse_time(value) {
        None => NONE.into(),
        Some(m) => strftime(local(m), t(lang, "date_format"), lang),
    }
}

/// For `<time datetime>`: RFC 3339 in UTC with whole seconds (`2026-10-25T12:00:00Z`), or "".
pub fn iso(value: &Value) -> String {
    parse_time(value).and_then(|m| conventions::rfc3339_from_unix(m.as_second() as f64)).unwrap_or_default()
}

/// A day of the day bars (`"2026-10-24"` as it is, a moment in the house's time): "24 Oct".
pub fn day(value: &Value, lang: &str) -> String {
    let Some(moment) = parse_time(value) else {
        return NONE.into();
    };
    let civil = match value.as_str() {
        Some(s) if s.chars().count() == 10 => moment.to_zoned(TimeZone::UTC).datetime(),
        _ => local(moment),
    };
    strftime(civil, t(lang, "day_format"), lang).trim().to_string()
}

/// Which of `keys` ("7d", "30d", "90d", "1y") a span [start, end] is (the nearest).
pub fn span_key(start: &Value, end: &Value, keys: &[&str]) -> Option<String> {
    let (a, b) = (parse_time(start)?, parse_time(end)?);
    let days = seconds_between(b, a) / 86400.0;
    let size = |k: &str| match k {
        "7d" => 7.0,
        "30d" => 30.0,
        "90d" => 90.0,
        "1y" => 365.0,
        _ => 0.0,
    };
    let mut best: Option<(&str, f64)> = None;
    for key in keys {
        let distance = (size(key) - days).abs();
        if best.is_none_or(|(_, d)| distance < d) {
            best = Some((key, distance));
        }
    }
    best.map(|(k, _)| k.to_string())
}

// --- places and radio ---------------------------------------------------------------------------

fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(first) => first.to_uppercase().chain(chars.flat_map(char::to_lowercase)).collect(),
    }
}

/// An AP as a room: `{"house": "scharni", "floor": 2, "spot": "corner"}` -> "Scharni · 2nd
/// floor · corner"; a name outside the scheme (no house) as it is.
pub fn room(ap: &Value, lang: &str) -> String {
    if !truthy(ap) {
        return NONE.into();
    }
    if let Value::String(name) = ap {
        return name.clone();
    }
    let house = get(ap, "house");
    if !truthy(house) {
        let name = get(ap, "name");
        return if truthy(name) { py_str(name) } else { NONE.into() };
    }
    let house = py_str(house);
    let mut parts =
        vec![t_get(lang, &format!("room_{house}")).map(str::to_string).unwrap_or_else(|| capitalize(&house))];
    let floor = get(ap, "floor");
    if !floor.is_null() && !py_str(floor).is_empty() {
        let floor = py_str(floor);
        parts.push(
            t_nonempty(lang, &format!("room_floor_{floor}"))
                .map(str::to_string)
                .unwrap_or_else(|| fill(t(lang, "room_floor_n"), &[("n", &floor)])),
        );
    }
    let spot = get(ap, "spot");
    if truthy(spot) {
        let spot = py_str(spot);
        parts.push(t_get(lang, &format!("room_spot_{spot}")).map(str::to_string).unwrap_or(spot));
    }
    parts.join(" · ")
}

/// The Wi-Fi generation: "Wi-Fi 6", `ax` on 6 GHz "Wi-Fi 6E", unknown ones `proto_old`.
pub fn proto(proto: &Value, band: &Value, lang: &str) -> Option<String> {
    if !truthy(proto) {
        return None;
    }
    let proto = py_str(proto);
    let key = if proto == "ax" && py_str(band) == "6" { "proto_ax6".to_string() } else { format!("proto_{proto}") };
    Some(t_nonempty(lang, &key).unwrap_or_else(|| t(lang, "proto_old")).to_string())
}

/// `None` where Python's `float(band)` raised.
fn try_band(band: &Value, lang: &str) -> Option<String> {
    if !truthy(band) {
        return Some(NONE.into());
    }
    let value = num(band)?;
    let digits = if py_str(band) == "2.4" { 1 } else { 0 };
    Some(fill(t(lang, "band_fmt"), &[("band", &number(Some(value), lang, digits))]))
}

/// "2.4" -> "2,4 GHz" (de).
pub fn band(band: &Value, lang: &str) -> String {
    try_band(band, lang).unwrap_or_else(|| NONE.into())
}

/// "5 GHz · channel 36 · Wi-Fi 6" from what is known.
pub fn wifi(device: &Value, lang: &str) -> String {
    let mut parts = Vec::new();
    if truthy(get(device, "band")) {
        parts.push(band(get(device, "band"), lang));
    }
    if truthy(get(device, "channel")) {
        parts.push(fill(t(lang, "channel_fmt"), &[("channel", &py_str(get(device, "channel")))]));
    }
    if let Some(p) = proto(get(device, "proto"), get(device, "band"), lang) {
        parts.push(p);
    }
    if parts.is_empty() { NONE.into() } else { parts.join(" · ") }
}

/// (bars 0-4, text key, tone ok|warn|bad), or `None` when unknown.
pub fn signal(dbm: Option<f64>) -> Option<(i64, &'static str, &'static str)> {
    let dbm = dbm?;
    for level in table("SIGNAL_LEVELS").as_array().into_iter().flatten() {
        if let (Some(threshold), Some(bars), Some(key)) = (level[0].as_f64(), level[1].as_i64(), level[2].as_str())
            && dbm >= threshold
        {
            return Some((bars, key, if bars >= 3 { "ok" } else { "warn" }));
        }
    }
    Some((0, "sig_very_weak", "bad"))
}

/// (text key, tone ok|warn|bad), or `None` when unknown.
pub fn health(score: Option<f64>) -> Option<(&'static str, &'static str)> {
    let score = score?;
    for level in table("HEALTH_LEVELS").as_array().into_iter().flatten() {
        if let (Some(threshold), Some(key), Some(tone)) = (level[0].as_f64(), level[1].as_str(), level[2].as_str())
            && score >= threshold
        {
            return Some((key, tone));
        }
    }
    Some(("q_poor", "bad"))
}

// --- telemetry v2 codes -------------------------------------------------------------------------

/// An Acct-Terminate-Cause as its text key's suffix: "Lost-Carrier", "lost_carrier" or "2" ->
/// "lost_carrier"; anything else (or nothing) -> "unknown".
pub fn cause_key(cause: &Value) -> String {
    if cause.is_null() || cause.as_str() == Some("") {
        return "unknown".into();
    }
    let text = py_str(cause);
    let text = text.trim();
    let causes = codes("TERMINATE_CAUSES");
    if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) {
        return text
            .parse::<usize>()
            .ok()
            .and_then(|n| n.checked_sub(1))
            .and_then(|i| causes.get(i))
            .map_or_else(|| "unknown".into(), |c| c.to_string());
    }
    let key = text.to_lowercase().replace(['-', ' '], "_");
    if causes.contains(&key.as_str()) { key } else { "unknown".into() }
}

/// A RADIUS reject reason as its text key's suffix (unknown ones: "other").
pub fn reason_key(reason: &Value) -> String {
    match reason.as_str() {
        Some(r) if is_code("REJECT_REASONS", r) => r.to_string(),
        _ => "other".into(),
    }
}

/// "Access point offline (Scharni · 2nd floor · corner)" from an incident or its kind.
pub fn incident_text(incident: &Value, lang: &str) -> String {
    if !truthy(incident) {
        return NONE.into();
    }
    let incident = if incident.is_object() { incident.clone() } else { json!({"kind": incident}) };
    let what = match get(&incident, "kind").as_str() {
        Some(kind) if is_code("INCIDENT_KINDS", kind) => t(lang, &format!("inc_{kind}")).to_string(),
        _ => t(lang, "inc_other").to_string(),
    };
    let scope = scope(&incident, lang);
    if scope.is_empty() { what } else { format!("{what} ({scope})") }
}

/// Where an incident is: the AP as a room, the switch or port by name, else the house.
pub fn scope(incident: &Value, lang: &str) -> String {
    let subject = get(incident, "subject");
    let subject = if truthy(subject) { py_str(subject) } else { String::new() };
    let name = get(incident, "subject_name");
    let name = if truthy(name) { py_str(name) } else { subject.clone() };
    if subject.is_empty() && name.is_empty() {
        return t(lang, "inc_house_wide").into();
    }
    if get(incident, "ap").is_object() {
        return room(get(incident, "ap"), lang);
    }
    let kind = get(incident, "kind");
    if !kind.is_null() && py_str(kind).starts_with("ap_") {
        return room(&ap_from_name(&Value::String(name)), lang);
    }
    name
}

/// An AP name as the backend splits it: `ap-<house>-<floor>-<spot>` (else house, floor, spot
/// are none).
pub fn ap_from_name(name: &Value) -> Value {
    static SCHEME: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^ap-([a-z0-9]+)-([0-9]{1,2})-([a-z0-9][a-z0-9-]*)$").expect("a constant, valid pattern")
    });
    let text = if truthy(name) { py_str(name) } else { String::new() };
    match SCHEME.captures(&text) {
        Some(c) => {
            json!({"name": name, "house": &c[1], "floor": c[2].parse::<i64>().unwrap_or(0), "spot": &c[3]})
        }
        None => json!({"name": name, "house": null, "floor": null, "spot": null}),
    }
}

// --- evidence -----------------------------------------------------------------------------------

/// A finding's evidence (`{key: value}`) as (label, value text) in the order of EVIDENCE_SPEC
/// for its code, and the time span it covers as a text. Keys outside the spec show only to
/// admins, as they are: a resident never sees a raw field name.
pub fn evidence_items(finding: &Value, lang: &str, admin: bool) -> (Vec<(String, String)>, Option<String>) {
    static EMPTY: LazyLock<Map<String, Value>> = LazyLock::new(Map::new);
    let evidence = get(finding, "evidence").as_object().unwrap_or(&EMPTY);
    let code = get(finding, "code").as_str().unwrap_or("");
    let spec: Vec<(String, String)> = match table("EVIDENCE_SPEC").get(code).and_then(Value::as_array) {
        Some(spec) => spec
            .iter()
            .filter_map(|pair| Some((pair[0].as_str()?.to_string(), pair[1].as_str()?.to_string())))
            .collect(),
        None => evidence
            .keys()
            .filter_map(|k| Some((k.clone(), table("EVIDENCE_FORMAT").get(k)?.as_str()?.to_string())))
            .collect(),
    };
    let mut items = Vec::new();
    for (key, kind) in &spec {
        let value = evidence.get(key).unwrap_or(&Value::Null);
        if empty_value(value) {
            continue;
        }
        let label = if kind.starts_with("limit_") {
            t(lang, "evk_limit").to_string()
        } else {
            t_get(lang, &format!("evk_{key}")).unwrap_or(key).to_string()
        };
        items.push((label, evidence_value(kind, value, lang, admin)));
    }
    if admin {
        for (key, value) in evidence {
            if !spec.iter().any(|(k, _)| k == key) && !empty_value(value) {
                items.push((key.clone(), plain(value)));
            }
        }
    }
    let window = table("EVIDENCE_WINDOW")
        .get(code)
        .and_then(Value::as_str)
        .map(|w| t(lang, &format!("ev_last_{w}")).to_string());
    (items, window)
}

/// The one value a card shows beside a finding's title (EVIDENCE_SHORT, else the first evidence
/// item's value), or `None`.
pub fn evidence_short(finding: &Value, lang: &str) -> Option<String> {
    let code = get(finding, "code").as_str().unwrap_or("");
    if let Some(short) = table("EVIDENCE_SHORT").get(code).and_then(Value::as_array) {
        let (key, kind) = (short[0].as_str().unwrap_or(""), short[1].as_str().unwrap_or(""));
        let mut value = get(get(finding, "evidence"), key);
        if value.is_null() {
            value = get(get(finding, "params"), key);
        }
        if value.is_null() || value.as_str() == Some("") {
            return None;
        }
        if let Some(text_key) = table("SHORT_TEXTS").get(kind).and_then(Value::as_str) {
            return Some(fill(t(lang, text_key), &[("n", &number(num(value), lang, 0))]));
        }
        return Some(evidence_value(kind, value, lang, false));
    }
    evidence_items(finding, lang, false).0.into_iter().next().map(|(_, v)| v)
}

fn pairs(value: &Value) -> Vec<(Value, Value)> {
    match value {
        Value::Object(map) => map.iter().map(|(k, v)| (Value::String(k.clone()), v.clone())).collect(),
        Value::Array(list) => list.iter().map(|v| (v.clone(), Value::Null)).collect(),
        _ => Vec::new(),
    }
}

fn times_suffix(n: &Value) -> String {
    if truthy(n) { format!(" ×{}", py_str(n)) } else { String::new() }
}

/// One evidence value as text (`kind`: EVIDENCE_SPEC's); values of another shape than the kind
/// expects are shown as they are ([`plain`]).
pub fn evidence_value(kind: &str, value: &Value, lang: &str, admin: bool) -> String {
    let kind = kind.strip_prefix("limit_").unwrap_or(kind);
    let numeric = num(value);
    let text = match kind {
        "dbm" => numeric.map(|v| dbm(Some(v), lang)),
        "db" => numeric.map(|v| db(Some(v), lang)),
        "percent" => numeric.map(|v| percent(Some(v), lang, 0)),
        "bitrate" => numeric.map(|v| bitrate(Some(v), lang)),
        "duration" => numeric.map(|v| duration(Some(v), lang, 2)),
        "bytes" => numeric.map(|v| bytes(Some(v), lang)),
        "per_hour" => numeric.map(|v| fill(t(lang, "per_hour"), &[("n", &number(Some(v), lang, 0))])),
        "count" => numeric.map(|v| number(Some(v), lang, 0)),
        "rate" => numeric.map(|v| format!("{}/s", number(Some(v), lang, 1))),
        "days" => Some(fill(t(lang, "days_n"), &[("n", &py_str(value))])),
        "when" if value.is_string() => Some(when(value, lang, None)),
        "ago" if value.is_string() => Some(ago(value, lang, None)),
        "recent" if value.is_string() => Some(recent(value, lang, None)),
        "date" if value.is_string() => Some(date(value, lang)),
        "source" => {
            let code = py_str(value);
            Some(if admin {
                t_get(lang, &format!("src_admin_{code}")).map_or(code, str::to_string)
            } else {
                t_nonempty(lang, &format!("pr_src_{code}"))
                    .or_else(|| t_get(lang, &format!("src_{code}")))
                    .map_or(code, str::to_string)
            })
        }
        "times" => value.as_array().map(|list| {
            let shown: Vec<String> = list.iter().take(3).map(|v| when(v, lang, None)).collect();
            shown.join(", ") + if list.len() > 3 { " …" } else { "" }
        }),
        "band" => try_band(value, lang),
        "bands" => value
            .as_array()
            .and_then(|list| list.iter().map(|b| try_band(b, lang)).collect::<Option<Vec<_>>>().map(|b| b.join(", "))),
        "reason" => {
            let key = reason_key(value);
            Some(t(lang, &if admin { format!("rr_{key}_admin") } else { format!("rr_{key}") }).to_string())
        }
        "reasons" if value.is_object() || value.is_array() => Some(
            pairs(value)
                .iter()
                .map(|(r, n)| {
                    let label = if admin { py_str(r) } else { t(lang, &format!("rr_{}", reason_key(r))).to_string() };
                    label + &times_suffix(n)
                })
                .collect::<Vec<_>>()
                .join(", "),
        ),
        "causes" if value.is_object() || value.is_array() => Some(
            pairs(value)
                .iter()
                .map(|(c, n)| {
                    let mut text = t(lang, &format!("cause_{}", cause_key(c))).to_string();
                    if admin {
                        text += &format!(" ({})", py_str(c));
                    }
                    text + &times_suffix(n)
                })
                .collect::<Vec<_>>()
                .join(", "),
        ),
        "room" => Some(if value.is_object() { room(value, lang) } else { room(&ap_from_name(value), lang) }),
        "ap_signals" => value.as_object().map(|aps| {
            aps.iter()
                .map(|(ap, v)| {
                    format!("{} {}", room(&ap_from_name(&Value::String(ap.clone())), lang), dbm(num(v), lang))
                })
                .collect::<Vec<_>>()
                .join(", ")
        }),
        "incident" => Some(match value {
            Value::Object(_) => {
                let text = incident_text(value, lang);
                if truthy(get(value, "started")) {
                    format!("{text}, {}", when(get(value, "started"), lang, None))
                } else {
                    text
                }
            }
            _ => incident_text(value, lang),
        }),
        _ => None,
    };
    text.unwrap_or_else(|| plain(value))
}

/// A value as it is (`static/format.js` `plain()`): JSON's words for booleans and nothing,
/// floats to three decimals without trailing zeros.
pub fn plain(value: &Value) -> String {
    match value {
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".into(),
        Value::Object(map) => map.iter().map(|(k, v)| format!("{k} {}", plain(v))).collect::<Vec<_>>().join(", "),
        Value::Array(list) => list.iter().map(plain).collect::<Vec<_>>().join(", "),
        Value::Number(n) if n.is_f64() => {
            let text = format!("{:.3}", n.as_f64().unwrap_or(0.0));
            text.trim_end_matches('0').trim_end_matches('.').to_string()
        }
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
    }
}

// --- access points ------------------------------------------------------------------------------

/// up | down | unknown from an AP's state (the API's ok | down | unknown).
pub fn ap_state(ap: &Value) -> &'static str {
    match get(ap, "state").as_str() {
        Some("ok" | "up") => "up",
        Some("down") => "down",
        _ => "unknown",
    }
}

/// The share of an AP's devices with a weak signal (weak_clients / clients), or `None`.
pub fn ap_weak_share(ap: &Value) -> Option<f64> {
    if !get(ap, "weak_share").is_null() {
        return num(get(ap, "weak_share"));
    }
    let (weak, clients) = (num(get(ap, "weak_clients")), num(get(ap, "clients")));
    match (weak, clients) {
        (Some(w), Some(c)) if c != 0.0 => Some(w / c),
        _ => None,
    }
}

/// The busiest radio's channel utilisation (0-1), or `None`.
pub fn ap_load(ap: &Value) -> Option<f64> {
    get(ap, "radios").as_array().into_iter().flatten().filter_map(util_of).reduce(f64::max)
}

/// A radio's channel utilisation (`channel_util`, else `utilization`), or `None`.
pub fn util_of(radio: &Value) -> Option<f64> {
    let util = get(radio, "channel_util");
    num(if util.is_null() { get(radio, "utilization") } else { util })
}

/// What the admin pages point out about an AP (`ap_warn_<code>`), from its live values with the
/// diagnostics' limits, unless the API sent its own list.
pub fn ap_warnings(ap: &Value) -> Vec<String> {
    let given = get(ap, "warnings");
    if !given.is_null() {
        return given.as_array().into_iter().flatten().map(py_str).collect();
    }
    if ap_state(ap) == "down" {
        return vec!["down".into()];
    }
    let mut out = Vec::new();
    let (clients, load) = (num(get(ap, "clients")), ap_load(ap));
    let overloaded = clients
        .is_some_and(|c| c >= AP_CLIENTS_WARN || load.is_some_and(|l| l >= AP_UTIL_WARN) && c >= AP_LOAD_MIN_CLIENTS);
    if overloaded {
        out.push("overloaded".into());
    } else if load.is_some_and(|l| l >= BUSY_CHANNEL_WARN) {
        out.push("busy_channel".into());
    }
    let weak_limit = table("AP_WEAK_SHARE_WARN").as_f64().unwrap_or(0.25);
    if ap_weak_share(ap).is_some_and(|w| w >= weak_limit) && clients.unwrap_or(0.0) >= AP_WEAK_MIN_CLIENTS {
        out.push("poor_coverage".into());
    }
    if num(get(ap, "uptime_s")).is_some_and(|u| u < AP_RESTARTED_S) {
        out.push("restarted".into());
    }
    if num(get(ap, "uplink_mbps")).is_some_and(|u| u < AP_UPLINK_MIN_MBPS) {
        out.push("uplink".into());
    }
    out
}

// --- presence (DEVICE.presence; static/presence.js answers alike) -------------------------------

/// The device's presence with its state checked. A payload without one gets one from v1's
/// `state` alone, marked derived: nothing is claimed about when or by what it was confirmed.
pub fn presence(device: &Value) -> Value {
    let p = get(device, "presence").as_object();
    let states = codes("PRESENCE_STATES");
    let given = p.and_then(|p| p.get("state")).and_then(Value::as_str).filter(|s| states.contains(s));
    let state = given.or_else(|| get(device, "state").as_str().filter(|s| states.contains(s))).unwrap_or("unknown");
    let mut out = json!({"state": state, "since": null, "confirmed_at": null, "confirmed_by": null, "basis": null,
                         "reason": null, "session": null, "stale_after_s": null, "poll_s": null, "evidence": [],
                         "derived": p.is_none()});
    if let (Some(p), Some(map)) = (p, out.as_object_mut()) {
        for key in [
            "since",
            "confirmed_at",
            "confirmed_by",
            "basis",
            "reason",
            "session",
            "stale_after_s",
            "poll_s",
            "evidence",
        ] {
            if let Some(v) = p.get(key).filter(|v| !v.is_null()) {
                map.insert(key.into(), v.clone());
            }
        }
        if !map.get("evidence").is_some_and(Value::is_array) {
            map.insert("evidence".into(), json!([]));
        }
        if !map.get("session").is_some_and(Value::is_object) {
            map.insert("session".into(), Value::Null);
        }
    }
    out
}

/// A presence's evidence for an admin: the newest first (by its time), at most `limit`.
pub fn presence_evidence(presence: &Value, limit: usize) -> Vec<Value> {
    let mut items: Vec<&Value> =
        get(presence, "evidence").as_array().into_iter().flatten().filter(|e| e.is_object()).collect();
    let at = |e: &Value| parse_time(get(e, "at")).map_or(i128::MIN, Timestamp::as_nanosecond);
    items.sort_by_key(|e| std::cmp::Reverse(at(e)));
    items.into_iter().take(limit).cloned().collect()
}

/// The one state every part of a page shows for a device (presence first).
pub fn state_of(device: &Value) -> String {
    get(&presence(device), "state").as_str().unwrap_or("unknown").to_string()
}

/// A moment as the page shows it and the script keeps current (`<time data-rel>`).
pub fn rel(kind: &str, value: &Value, lang: &str, now: Option<Timestamp>) -> String {
    match kind {
        "recent" => recent(value, lang, now),
        "ago" => ago(value, lang, now),
        "elapsed" => elapsed(value, lang, now),
        _ => when(value, lang, now),
    }
}

/// A moment for a segment: `{time, kind, text, title}` (the title to the second).
pub fn moment(value: &Value, kind: &str, lang: &str, now: Option<Timestamp>) -> Value {
    json!({"time": iso(value), "kind": kind, "text": rel(kind, value, lang, now), "title": stamp(value, lang)})
}

fn segment(lang: &str, key: &str, values: Value) -> Value {
    json!({"text": t(lang, key), "values": values})
}

/// What the state line says: `{state, icon, label, more: [segment], confirmed: segment|null}`,
/// a segment being `{text: a text with {placeholders}, values: {name: str | moment}}`. One state
/// only: nothing next to "offline" says connected, "connecting" is not an error, an unknown
/// state says why, and only a measured presence says when and by which source it was confirmed.
pub fn presence_view(device: &Value, lang: &str, now: Option<Timestamp>, ssid: &str) -> Value {
    let p = presence(device);
    let state = get(&p, "state").as_str().unwrap_or("unknown").to_string();
    let derived = get(&p, "derived").as_bool().unwrap_or(true);
    let at = |value: &Value, kind: &str| moment(value, kind, lang, now);
    let mut more = Vec::new();
    match state.as_str() {
        "online" => {
            let since = if truthy(get(&p, "since")) { get(&p, "since") } else { get(device, "since") };
            if parse_time(since).is_some() {
                more.push(segment(
                    lang,
                    "since_line",
                    json!({"time": at(since, "when"), "duration": at(since, "elapsed")}),
                ));
            }
        }
        "connecting" => more.push(segment(lang, "pr_connecting_line", json!({}))),
        "never_connected" => more.push(segment(lang, "never_line", json!({"ssid": ssid}))),
        "offline" => {
            if !derived && parse_time(get(&p, "since")).is_some() {
                more.push(segment(lang, "pr_offline_since", json!({"when": at(get(&p, "since"), "recent")})));
            } else if parse_time(get(device, "last_seen")).is_some() {
                more.push(segment(lang, "seen_line", json!({"when": at(get(device, "last_seen"), "ago")})));
            }
        }
        _ => {
            let diagnostics = get(device, "diagnostics");
            let has_conflict = diagnostics
                .as_array()
                .into_iter()
                .flatten()
                .any(|f| f.is_object() && get(f, "code").as_str() == Some("mac_conflict"));
            let reason = get(&p, "reason");
            if !derived && truthy(reason) && !(reason.as_str() == Some("mac_conflict") && has_conflict) {
                let code = reason.as_str().filter(|r| is_code("PRESENCE_REASONS", r)).unwrap_or("other");
                more.push(segment(lang, &format!("pr_reason_{code}"), json!({})));
            }
            if parse_time(get(device, "last_seen")).is_some() {
                more.push(segment(lang, "seen_line", json!({"when": at(get(device, "last_seen"), "ago")})));
            } else if more.is_empty() && !truthy(diagnostics) {
                more.push(segment(lang, "unknown_line", json!({})));
            }
        }
    }
    let mut confirmed = Value::Null;
    if !derived
        && matches!(state.as_str(), "online" | "connecting" | "offline")
        && parse_time(get(&p, "confirmed_at")).is_some()
    {
        let source = get(&p, "confirmed_by");
        let code = py_str(source);
        let words = t_nonempty(lang, &format!("pr_src_{code}"))
            .or_else(|| t_nonempty(lang, &format!("src_{code}")))
            .map(str::to_string)
            .or_else(|| truthy(source).then(|| code.clone()));
        let when = at(get(&p, "confirmed_at"), "recent");
        confirmed = match words {
            Some(words) => segment(lang, "pr_confirmed", json!({"when": when, "source": words})),
            None => segment(lang, "pr_confirmed_plain", json!({"when": when})),
        };
    }
    let icon = get(table("PRESENCE_ICON"), &state).as_str().unwrap_or("help");
    json!({"state": state, "icon": icon, "label": t(lang, &format!("state_{state}")), "more": more,
           "confirmed": confirmed})
}

/// A segment as `[(kind, value)]` for the template: `("text", str)` and `("time", moment)`;
/// an unknown `{name}` stays as it is, a value of none is empty.
pub fn parts(segment: &Value) -> Vec<(&'static str, Value)> {
    static PLACEHOLDER: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\{(\w+)\}").expect("a constant, valid pattern"));
    let text = get(segment, "text").as_str().unwrap_or("");
    let values = get(segment, "values");
    let mut out = Vec::new();
    let mut last = 0;
    for m in PLACEHOLDER.captures_iter(text) {
        let (Some(whole), Some(name)) = (m.get(0), m.get(1)) else {
            continue;
        };
        if whole.start() > last {
            out.push(("text", Value::String(text[last..whole.start()].to_string())));
        }
        match values.get(name.as_str()) {
            None => out.push(("text", Value::String(whole.as_str().to_string()))),
            Some(v) if v.is_object() => out.push(("time", v.clone())),
            Some(Value::Null) => out.push(("text", Value::String(String::new()))),
            Some(v) => out.push(("text", Value::String(py_str(v)))),
        }
        last = whole.end();
    }
    if last < text.len() {
        out.push(("text", Value::String(text[last..].to_string())));
    }
    out
}

/// The findings a page shows: "Not connected" (offline) only while the state is offline.
pub fn findings_shown(device: &Value) -> Vec<Value> {
    let state = state_of(device);
    get(device, "diagnostics")
        .as_array()
        .into_iter()
        .flatten()
        .filter(|f| !(f.is_object() && get(f, "code").as_str() == Some("offline") && state != "offline"))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_and_units() {
        assert_eq!(bytes(Some(1_830_000_000.0), "de"), "1,8 GB");
        assert_eq!(bytes(Some(0.0), "en"), "0 B");
        assert_eq!(bitrate(Some(950.0), "en"), "950 bit/s");
        assert_eq!(bitrate(Some(2_400_000.0), "de"), "2,4 Mbit/s");
        assert_eq!(percent(Some(0.24), "en", 0), "24%");
        assert_eq!(percent(Some(0.24), "de", 0), "24\u{a0}%");
        assert_eq!(dbm(Some(-58.0), "en"), "\u{2212}58 dBm");
        assert_eq!(ms(Some(9.8), "en"), "9.8 ms");
        assert_eq!(ms(Some(11.4), "en"), "11 ms");
        assert_eq!(duration(Some(8130.0), "en", 2), "2 h 15 min");
        assert_eq!(duration(Some(90061.0), "en", 2), "1 d 1 h");
        assert_eq!(duration(Some(7205.0), "en", 2), "2 h");
        assert_eq!(duration(Some(40.0), "en", 2), "40 s");
        assert_eq!(duration(Some(-5.0), "en", 2), "0 s");
        assert_eq!(duration(None, "en", 2), NONE);
    }

    #[test]
    fn moments() {
        let now = parse_time(&json!("2026-10-25T12:00:00Z"));
        assert_eq!(when(&json!("2026-10-25T11:00:00+00:00"), "en", now), "12:00");
        assert_eq!(when(&json!("2026-10-24T11:00:00Z"), "en", now), "yesterday 13:00");
        assert_eq!(when(&json!("2026-10-20T11:00:00Z"), "de", now), "20. Okt. 13:00");
        assert_eq!(when(&json!("2025-10-20T11:00:00Z"), "de", now), "20.10.2025 13:00");
        assert_eq!(iso(&json!("2026-10-25T13:00:00.5+01:00")), "2026-10-25T12:00:00Z");
        assert_eq!(iso(&json!("nonsense")), "");
        assert_eq!(day(&json!("2026-10-24"), "en"), "24 Oct");
        assert_eq!(day(&json!("2026-10-24T23:30:00Z"), "en"), "25 Oct");
        assert_eq!(recent(&json!("2026-10-25T11:59:58Z"), "en", now), "just now");
        assert_eq!(elapsed(&json!("2026-10-25T09:45:00Z"), "en", now), "2 h 15 min");
        assert_eq!(
            span_key(&json!("2026-09-25T12:00:00Z"), &json!("2026-10-25T12:00:00Z"), &["7d", "30d"]).as_deref(),
            Some("30d")
        );
    }

    #[test]
    fn codes_and_plain() {
        assert_eq!(cause_key(&json!(2)), "lost_carrier");
        assert_eq!(cause_key(&json!("Admin Reset")), "admin_reset");
        assert_eq!(cause_key(&json!("0")), "unknown");
        assert_eq!(plain(&json!(2e6)), "2000000");
        assert_eq!(plain(&json!(0.12345)), "0.123");
        assert_eq!(plain(&json!({"a": [true, null]})), "a true, null");
        assert_eq!(ap_from_name(&json!("ap-colbe-0-far"))["floor"], 0);
        assert_eq!(ap_from_name(&json!("AP-colbe-0-far"))["house"], Value::Null);
        assert_eq!(room(&json!("Werkstatt"), "en"), "Werkstatt");
        assert_eq!(room(&json!({}), "en"), NONE);
    }

    #[test]
    fn segments() {
        let seg = json!({"text": "{a}-{b}-{c}-{d}", "values": {"a": null, "b": 2.0, "c": {"time": "t"}}});
        let p = parts(&seg);
        let kinds: Vec<&str> = p.iter().map(|(k, _)| *k).collect();
        assert_eq!(kinds, ["text", "text", "text", "text", "time", "text", "text"]);
        assert_eq!(p[2].1, "2.0");
        assert_eq!(p[6].1, "{d}");
    }
}
