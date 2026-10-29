//! The number and time conventions of every page, JSON payload and log line (replacing the
//! Python version's implicit ones, INVENTORY 9.13; the changes are in `docs/PARITY.md`,
//! "Deliberate deviations"):
//!
//! - **Times** in JSON and in `<time datetime>`: RFC 3339 in UTC with `Z` and whole seconds,
//!   `2026-10-28T11:34:56Z` ([`rfc3339`]); sub-second parts are truncated (a time is never shown
//!   later than it happened). Dates: `YYYY-MM-DD` ([`date_iso`]). Unix seconds where a payload
//!   is a time series (as before).
//! - **Rounding**: half away from zero at the requested decimal place, applied to the binary
//!   value ([`round_to`]), the same rule as `Intl.NumberFormat`'s default, so the server and the
//!   browser agree on everything except exact binary ties that the browser sees differently
//!   (none in practice: values come from measurements).
//! - **Display numbers**: rounded by [`round_to`], then formatted with fixed decimals and the
//!   language's separators ([`format_fixed`]).
//! - **Non-finite values** (NaN, infinities) never reach JSON: [`finite`] turns them into `None`.
//! - **Days** of the house are in `NETPORTAL_TIMEZONE` ([`zone`]); SQL sessions run in UTC (sqlx
//!   sets `TimeZone=UTC`), so calendar arithmetic in SQL is UTC and house days are computed in Rust.

use time::{Date, OffsetDateTime, UtcOffset};

// --- numbers ------------------------------------------------------------------------------------

/// `x` rounded to `digits` decimal places, ties away from zero (`round_to(2.5, 0) == 3.0`,
/// `round_to(-2.5, 0) == -3.0`, `round_to(0.125, 2) == 0.13`). Computed on the binary value
/// (`x * 10^digits`), so a decimal tie that is not exactly representable rounds by its binary
/// value (`1.005` is `1.00499...`: `1.0`). NaN and infinities are returned unchanged.
pub fn round_to(x: f64, digits: u32) -> f64 {
    if !x.is_finite() {
        return x;
    }
    let scale = 10f64.powi(digits.min(300) as i32);
    let scaled = x * scale;
    if !scaled.is_finite() {
        return x;
    }
    // -0.0 stays -0.0 only if x was negative zero; a negative value rounded to zero is 0.0
    let r = scaled.round() / scale;
    if r == 0.0 { 0.0 } else { r }
}

/// `x` rounded to an integer, ties away from zero; `None` for NaN, infinities and values outside
/// `i64`.
pub fn round_int(x: f64) -> Option<i64> {
    let r = x.round();
    if r.is_finite() && r >= i64::MIN as f64 && r < i64::MAX as f64 { Some(r as i64) } else { None }
}

/// `Some(x)` for a finite value, `None` for NaN and infinities (no data).
pub fn finite(x: f64) -> Option<f64> {
    x.is_finite().then_some(x)
}

/// `x` with exactly `digits` decimals after [`round_to`], the integer part grouped in threes
/// with `thousands` (empty: no grouping), `decimal` as the decimal mark and U+2212 as the minus
/// sign (as `Intl.NumberFormat` writes it). `None` for NaN and infinities.
///
/// `format_fixed(-1234.5, 1, ",", ".") == "−1,234.5"`
pub fn format_fixed(x: f64, digits: u32, thousands: &str, decimal: &str) -> Option<String> {
    if !x.is_finite() {
        return None;
    }
    let rounded = round_to(x, digits);
    let text = format!("{:.*}", digits as usize, rounded.abs());
    let (int, frac) = match text.split_once('.') {
        Some((int, frac)) => (int, Some(frac)),
        None => (text.as_str(), None),
    };
    let mut out = String::with_capacity(text.len() + 8);
    if rounded < 0.0 {
        out.push('\u{2212}');
    }
    for (i, c) in int.chars().enumerate() {
        if i > 0 && (int.len() - i) % 3 == 0 {
            out.push_str(thousands);
        }
        out.push(c);
    }
    if let Some(frac) = frac {
        out.push_str(decimal);
        out.push_str(frac);
    }
    Some(out)
}

// --- times --------------------------------------------------------------------------------------

/// RFC 3339 in UTC with whole seconds: `2026-10-28T11:34:56Z` (sub-second parts truncated).
pub fn rfc3339(value: OffsetDateTime) -> String {
    let utc = value.to_offset(UtcOffset::UTC);
    format!("{}T{:02}:{:02}:{:02}Z", date_iso(utc.date()), utc.hour(), utc.minute(), utc.second())
}

/// [`rfc3339`] of a Unix time in seconds (`None` for non-finite values and values outside years
/// 1..9999).
pub fn rfc3339_from_unix(t: f64) -> Option<String> {
    from_unix(t).map(rfc3339)
}

/// The moment of a Unix time in seconds, to the microsecond (truncated towards the past).
pub fn from_unix(t: f64) -> Option<OffsetDateTime> {
    if !t.is_finite() || !(-62_135_596_800.0..253_402_300_800.0).contains(&t) {
        return None;
    }
    let us = (t * 1e6).floor() as i128;
    OffsetDateTime::from_unix_timestamp_nanos(us * 1000).ok()
}

/// Unix seconds of a moment, to the microsecond.
pub fn unix(value: OffsetDateTime) -> f64 {
    let us = value.unix_timestamp_nanos().div_euclid(1000);
    us as f64 / 1e6
}

/// `YYYY-MM-DD` (four-digit year).
pub fn date_iso(value: Date) -> String {
    format!("{:04}-{:02}-{:02}", value.year(), u8::from(value.month()), value.day())
}

/// An IANA time zone (`Europe/Berlin`): the system database (`/usr/share/zoneinfo`), else the
/// copy bundled into the binary. `None` when unknown.
pub fn zone(name: &str) -> Option<jiff::tz::TimeZone> {
    jiff::tz::TimeZone::get(name).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::{date, datetime};

    #[test]
    fn rounding_is_half_away_from_zero() {
        assert_eq!(round_to(2.5, 0), 3.0);
        assert_eq!(round_to(-2.5, 0), -3.0);
        assert_eq!(round_to(0.125, 2), 0.13);
        assert_eq!(round_to(-60.25, 1), -60.3);
        assert_eq!(round_to(123.456, 0), 123.0);
        assert_eq!(round_to(1.005, 2), 1.0); // the binary value is below the tie
        assert_eq!(round_to(-0.4, 0), 0.0);
        assert!(round_to(-0.4, 0).is_sign_positive());
        assert!(round_to(f64::NAN, 1).is_nan());
        assert_eq!(round_int(0.5), Some(1));
        assert_eq!(round_int(-0.5), Some(-1));
        assert_eq!(round_int(f64::INFINITY), None);
        assert_eq!(finite(f64::NAN), None);
        assert_eq!(finite(1.5), Some(1.5));
    }

    #[test]
    fn fixed_format() {
        let f = |x, d, t, s| format_fixed(x, d, t, s).unwrap_or_default();
        assert_eq!(f(1234567.891, 0, ",", "."), "1,234,568");
        assert_eq!(f(1234567.891, 2, ".", ","), "1.234.567,89");
        assert_eq!(f(-1234.5, 1, ",", "."), "\u{2212}1,234.5");
        assert_eq!(f(-1234.5, 0, ",", "."), "\u{2212}1,235");
        assert_eq!(f(999.5, 0, "\u{a0}", ","), "1\u{a0}000");
        assert_eq!(f(2.5, 0, "", "."), "3");
        assert_eq!(f(0.125, 2, "", "."), "0.13");
        assert_eq!(f(-0.4, 0, ",", "."), "0");
        assert_eq!(f(100.0, 0, ",", "."), "100");
        assert_eq!(format_fixed(f64::NAN, 0, ",", "."), None);
    }

    #[test]
    fn times() {
        let t = datetime!(2026-10-28 12:34:56.789 +01:00);
        assert_eq!(rfc3339(t), "2026-10-28T11:34:56Z");
        assert_eq!(rfc3339_from_unix(1.9999999).as_deref(), Some("1970-01-01T00:00:01Z"));
        assert_eq!(rfc3339_from_unix(-0.5).as_deref(), Some("1969-12-31T23:59:59Z"));
        assert_eq!(rfc3339_from_unix(1_800_000_000.0).as_deref(), Some("2027-01-15T08:00:00Z"));
        assert_eq!(rfc3339_from_unix(f64::NAN), None);
        assert_eq!(date_iso(date!(0999 - 01 - 02)), "0999-01-02");
        assert_eq!(unix(datetime!(1970-01-01 00:00:01.5 UTC)), 1.5);
        assert_eq!(from_unix(1.5).map(unix), Some(1.5));
    }

    #[test]
    fn zones() {
        assert!(zone("Europe/Berlin").is_some());
        assert!(zone("UTC").is_some());
        assert!(zone("Mars/Olympus").is_none());
    }
}
