//! Telemetry: shared helpers (`telemetry/common.py`, INVENTORY 9.1.1): MACs and PromQL
//! selectors, times, AP names, rounding.
//!
//! Only validated MACs ([`is_normalised_mac`]) ever go into a query: [`mac_selector`] refuses
//! anything else, and the SSID goes in as a PromQL string literal ([`promql_string`]).

use std::collections::BTreeMap;
use std::sync::LazyLock;

use indexmap::IndexMap;
use netportal_core::conventions;
use regex::Regex;
use serde::Serialize;
use time::OffsetDateTime;

/// A series' labels.
pub type Labels = BTreeMap<String, String>;

/// unpoller's `radio` label -> the band.
pub const BANDS: [(&str, &str); 3] = [("ng", "2.4"), ("na", "5"), ("6e", "6")];

/// The band of an unpoller `radio` code (`ng` -> `2.4`).
pub fn band(radio: Option<&str>) -> Option<&'static str> {
    let radio = radio?;
    BANDS.iter().find(|(r, _)| *r == radio).map(|(_, b)| *b)
}

/// The unpoller `radio` code of a band (`5` -> `na`).
pub fn radio_of(band: Option<&str>) -> Option<&'static str> {
    let band = band?;
    BANDS.iter().find(|(_, b)| *b == band).map(|(r, _)| *r)
}

static AP_NAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    // ap-<house>-<floor>-<spot>, e.g. ap-scharni-2-corner, ap-scharni-0-schlaglicht
    Regex::new(r"^ap-([a-z0-9]+)-([0-9]{1,2})-([a-z0-9][a-z0-9-]*)$").unwrap_or_else(|_| unreachable!())
});

/// The one MAC normaliser (the twin of SQL `np_mac`): `aa:bb:cc:dd:ee:ff` or `None`.
pub fn normalise_mac(raw: &str) -> Option<String> {
    netportal_core::registry::normalise_mac(raw)
}

/// [`normalise_mac`] of an optional value.
pub fn mac_of(raw: Option<&str>) -> Option<String> {
    raw.and_then(normalise_mac)
}

/// The locally administered bit (a private address).
pub fn randomized(mac: &str) -> bool {
    netportal_core::registry::is_randomized(mac)
}

/// `[0-9a-f]{2}(:[0-9a-f]{2}){5}` exactly: the only MAC form that may enter PromQL.
pub fn is_normalised_mac(mac: &str) -> bool {
    let b = mac.as_bytes();
    b.len() == 17
        && b.iter()
            .enumerate()
            .all(|(i, c)| if i % 3 == 2 { *c == b':' } else { matches!(c, b'0'..=b'9' | b'a'..=b'f') })
}

/// A query text refused before it reaches Prometheus (a bug in a caller: never user input).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BadQuery {
    #[error("only normalised MACs go into a query")]
    Mac,
    #[error("not a plain string")]
    NotPlain,
}

/// The label matcher for these MACs (sorted, deduplicated): `mac="m"` for one, `mac=~"m1|m2"`
/// for several. Each must already be normalised: nothing else (no quote, no regex character)
/// can reach PromQL.
pub fn mac_selector<S: AsRef<str>>(macs: &[S]) -> Result<String, BadQuery> {
    let mut sorted: Vec<&str> = macs.iter().map(AsRef::as_ref).collect();
    sorted.sort_unstable();
    sorted.dedup();
    if sorted.is_empty() || !sorted.iter().all(|m| is_normalised_mac(m)) {
        return Err(BadQuery::Mac);
    }
    Ok(if sorted.len() == 1 { format!("mac=\"{}\"", sorted[0]) } else { format!("mac=~\"{}\"", sorted.join("|")) })
}

/// A PromQL string literal (double quotes, Go escapes) of plain text; control characters are
/// refused rather than escaped (no SSID has them).
pub fn promql_string(text: &str) -> Result<String, BadQuery> {
    if text.chars().any(|c| (c as u32) < 32 || c as u32 == 127) {
        return Err(BadQuery::NotPlain);
    }
    Ok(format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\"")))
}

/// The query fragments of a set of MACs on the house network (INVENTORY 9.3): `sel` (essid and
/// mac matchers), `mac` (the mac matcher alone), `u` (the uptime series of the house network).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selectors {
    pub sel: String,
    pub mac: String,
    pub u: String,
}

pub fn selectors<S: AsRef<str>>(ssid: &str, macs: &[S]) -> Result<Selectors, BadQuery> {
    let mac = mac_selector(macs)?;
    let sel = format!("essid={},{mac}", promql_string(ssid)?);
    let u = format!("unpoller_client_uptime_seconds{{job=\"unifi\",{sel}}}");
    Ok(Selectors { sel, mac, u })
}

// --- times --------------------------------------------------------------------------------------

/// RFC 3339 (UTC, `Z`, whole seconds) of a Unix time; `None` stays `None` (the convention of every
/// JSON time, `netportal_core::conventions`).
pub fn iso(t: Option<f64>) -> Option<String> {
    t.and_then(conventions::rfc3339_from_unix)
}

/// RFC 3339 of a moment.
pub fn iso_dt(t: OffsetDateTime) -> String {
    conventions::rfc3339(t)
}

/// Unix seconds of a moment.
pub fn unix(t: OffsetDateTime) -> f64 {
    conventions::unix(t)
}

/// Unix seconds of an optional moment.
pub fn unix_opt(t: Option<OffsetDateTime>) -> Option<f64> {
    t.map(unix)
}

/// The moment of Unix seconds (clamped into the supported years: never fails).
pub fn moment(t: f64) -> OffsetDateTime {
    conventions::from_unix(t).unwrap_or(if t > 0.0 {
        time::macros::datetime!(9999-12-31 23:59:59 UTC)
    } else {
        OffsetDateTime::UNIX_EPOCH
    })
}

/// The newest of these times.
pub fn latest(times: &[Option<f64>]) -> Option<f64> {
    times.iter().flatten().copied().reduce(f64::max)
}

// --- APs ----------------------------------------------------------------------------------------

/// An AP as the pages name it (`ap_info` / `ap_ref` of the Python version): the house scheme's
/// parts of its name, and its MAC when known (its identity in long-term data: APs get renamed).
/// The `mac` key is left out when unknown; all name parts are null when only the MAC is known.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApRef {
    pub name: Option<String>,
    pub house: Option<String>,
    pub floor: Option<i64>,
    pub spot: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
}

/// `{"name", "house", "floor", "spot"}` of an AP; names not in the house scheme keep only their
/// name (the frontend shows them as they are). `None` for no name.
pub fn ap_info(name: Option<&str>) -> Option<ApRef> {
    let name = name.filter(|n| !n.is_empty())?;
    let Some(m) = AP_NAME_RE.captures(name) else {
        return Some(ApRef { name: Some(name.to_string()), house: None, floor: None, spot: None, mac: None });
    };
    Some(ApRef {
        name: Some(name.to_string()),
        house: m.get(1).map(|g| g.as_str().to_string()),
        floor: m.get(2).and_then(|g| g.as_str().parse().ok()),
        spot: m.get(3).map(|g| g.as_str().to_string()),
        mac: None,
    })
}

/// [`ap_info`] plus the AP's MAC when known; `None` when neither is known.
pub fn ap_ref(name: Option<&str>, mac: Option<&str>) -> Option<ApRef> {
    let info = ap_info(name);
    let Some(mac) = mac else {
        return info;
    };
    let mut info = info.unwrap_or(ApRef { name: None, house: None, floor: None, spot: None, mac: None });
    info.mac = Some(mac.to_string());
    Some(info)
}

// --- numbers ------------------------------------------------------------------------------------

/// A sample value; NaN, infinities and text that is no number (no data) are `None`.
pub fn number(text: &str) -> Option<f64> {
    text.trim().parse::<f64>().ok().and_then(conventions::finite)
}

/// A value rounded to `digits` decimals (half away from zero, `conventions::round_to`).
pub fn fit(value: Option<f64>, digits: u32) -> Option<f64> {
    value.filter(|v| v.is_finite()).map(|v| conventions::round_to(v, digits))
}

/// A value rounded to an integer (half away from zero).
pub fn fit_int(value: Option<f64>) -> Option<i64> {
    value.and_then(conventions::round_int)
}

/// The integer part of a value (Python `int()`: towards zero).
pub fn trunc_int(value: f64) -> Option<i64> {
    let t = value.trunc();
    (t.is_finite() && t >= i64::MIN as f64 && t < i64::MAX as f64).then_some(t as i64)
}

/// A channel label: 1 to 4 ASCII digits, else `None`.
pub fn small_int(text: Option<&str>) -> Option<i64> {
    let text = text?;
    (!text.is_empty() && text.len() <= 4 && text.bytes().all(|b| b.is_ascii_digit())).then(|| text.parse().ok())?
}

/// `{mac: value}` of rows with a non-empty `mac` label (later rows win).
pub fn by_mac(rows: &[(Labels, Option<f64>)]) -> IndexMap<String, Option<f64>> {
    let mut out = IndexMap::new();
    for (labels, value) in rows {
        if let Some(mac) = labels.get("mac").filter(|m| !m.is_empty()) {
            out.insert(mac.clone(), *value);
        }
    }
    out
}

/// A label's value (`None` when missing).
pub fn label<'a>(labels: &'a Labels, name: &str) -> Option<&'a str> {
    labels.get(name).map(String::as_str)
}
