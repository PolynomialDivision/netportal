//! Log lines (Python: `logging.basicConfig(level=INFO, format="%(asctime)s %(name)s
//! %(levelname)s %(message)s")`), on stderr:
//!
//! `2026-10-28T11:34:56.123Z netportal.registry INFO applying migration 0001_registry`
//!
//! The time is RFC 3339 UTC with milliseconds (Python wrote local time with a comma); the logger
//! name is the event's tracing target (the crates log with `target: "netportal.<module>"`); the
//! levels are `ERROR`, `WARNING`, `INFO`, `DEBUG`, `TRACE`. INFO and above are written, the
//! libraries' own logs (sqlx, hyper, reqwest, rustls) only from WARNING, and sqlx's statement
//! logs never: queries contain MACs (INVENTORY 4.9). `NETPORTAL_LOG=debug` lowers the level.

use std::fmt;

use time::OffsetDateTime;
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::registry::LookupSpan;

/// The line format above.
pub struct LineFormat;

impl<S, N> FormatEvent<S, N> for LineFormat
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(&self, ctx: &FmtContext<'_, S, N>, mut writer: Writer<'_>, event: &Event<'_>) -> fmt::Result {
        let now = OffsetDateTime::now_utc();
        let meta = event.metadata();
        let level = match *meta.level() {
            Level::ERROR => "ERROR",
            Level::WARN => "WARNING",
            Level::INFO => "INFO",
            Level::DEBUG => "DEBUG",
            Level::TRACE => "TRACE",
        };
        write!(
            writer,
            "{}.{:03}Z {} {} ",
            crate::conventions::rfc3339(now).trim_end_matches('Z'),
            now.millisecond(),
            meta.target(),
            level
        )?;
        ctx.field_format().format_fields(writer.by_ref(), event)?;
        writeln!(writer)
    }
}

fn wanted(target: &str, level: &Level, base: Level) -> bool {
    if target.starts_with("sqlx::query") {
        return false;
    }
    let ours = target.starts_with("netportal");
    let limit = if ours { base } else { Level::WARN.min(base) };
    *level <= limit
}

/// Install the subscriber (once per process; later calls do nothing).
pub fn init() {
    use tracing_subscriber::prelude::*;
    let base = match std::env::var("NETPORTAL_LOG").unwrap_or_default().to_ascii_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "warning" | "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };
    let filter = tracing_subscriber::filter::filter_fn(move |meta| wanted(meta.target(), meta.level(), base));
    let layer =
        tracing_subscriber::fmt::layer().event_format(LineFormat).with_writer(std::io::stderr).with_filter(filter);
    let _ = tracing_subscriber::registry().with(layer).try_init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters() {
        assert!(wanted("netportal.registry", &Level::INFO, Level::INFO));
        assert!(!wanted("netportal.registry", &Level::DEBUG, Level::INFO));
        assert!(wanted("netportal.registry", &Level::DEBUG, Level::DEBUG));
        assert!(!wanted("hyper::proto", &Level::INFO, Level::INFO));
        assert!(wanted("sqlx::postgres::notice", &Level::WARN, Level::INFO));
        assert!(!wanted("sqlx::query", &Level::WARN, Level::INFO));
    }
}
