//! House days (Python `collect/days.py`, INVENTORY 9.10.3): a local date of the house's time
//! zone (`NETPORTAL_TIMEZONE`) as an interval of Unix seconds `[local midnight, next local
//! midnight)`; with summer time a day is 23, 24 or 25 hours long.

use jiff::tz::TimeZone;
use time::Date;

fn civil(day: Date) -> Option<jiff::civil::Date> {
    jiff::civil::Date::new(day.year().try_into().ok()?, u8::from(day.month()) as i8, day.day() as i8).ok()
}

fn date_of(day: jiff::civil::Date) -> Option<Date> {
    let month = time::Month::try_from(day.month() as u8).ok()?;
    Date::from_calendar_date(day.year().into(), month, day.day() as u8).ok()
}

/// The first moment of a local date as Unix seconds (a midnight that does not exist, in a zone
/// that skips it, is the first moment after the gap).
fn midnight(day: jiff::civil::Date, tz: &TimeZone) -> Option<i64> {
    Some(day.to_zoned(tz.clone()).ok()?.timestamp().as_second())
}

/// `(start, end)` of a local date: `[local midnight, next local midnight)` as Unix seconds;
/// `None` outside the supported years.
pub fn bounds(day: Date, tz: &TimeZone) -> Option<(i64, i64)> {
    let d = civil(day)?;
    let next = d.tomorrow().ok()?;
    Some((midnight(d, tz)?, midnight(next, tz)?))
}

/// The local date of a Unix time; `None` outside the supported years.
pub fn local_day(unix: i64, tz: &TimeZone) -> Option<Date> {
    let ts = jiff::Timestamp::from_second(unix).ok()?;
    date_of(ts.to_zoned(tz.clone()).date())
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::{date, datetime};

    fn berlin() -> TimeZone {
        netportal_core::conventions::zone("Europe/Berlin").expect("zone")
    }

    /// Python test_collect_rollup.py DayTests.test_dst_days
    #[test]
    fn test_dst_days() {
        let tz = berlin();
        let (start, end) = bounds(date!(2026 - 10 - 25), &tz).expect("bounds");
        assert_eq!(end - start, 25 * 3600);
        assert_eq!(start, datetime!(2026-10-24 22:00 UTC).unix_timestamp());
        let spring = bounds(date!(2026 - 03 - 29), &tz).expect("bounds");
        assert_eq!(spring.1 - spring.0, 23 * 3600);
        let normal = bounds(date!(2026 - 10 - 24), &tz).expect("bounds");
        assert_eq!((normal.1 - normal.0, normal.1), (24 * 3600, start));
        assert_eq!(local_day(start, &tz), Some(date!(2026 - 10 - 25)));
        assert_eq!(local_day(start - 1, &tz), Some(date!(2026 - 10 - 24)));
        assert_eq!(local_day(end - 1, &tz), Some(date!(2026 - 10 - 25)));
        assert_eq!(local_day(end, &tz), Some(date!(2026 - 10 - 26)));
    }

    #[test]
    fn test_utc_and_a_zone_without_midnight() {
        let utc = TimeZone::UTC;
        assert_eq!(bounds(date!(1970 - 01 - 02), &utc), Some((86400, 2 * 86400)));
        // Havana skips 00:00-01:00 on its spring change (2026-03-08): the day starts at 01:00
        if let Some(havana) = netportal_core::conventions::zone("America/Havana") {
            let (start, end) = bounds(date!(2026 - 03 - 08), &havana).expect("bounds");
            assert_eq!(end - start, 23 * 3600);
            assert_eq!(local_day(start, &havana), Some(date!(2026 - 03 - 08)));
        }
    }
}
