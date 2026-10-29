//! The server's side of the JS tests' cross-checks that concern the telemetry (Python:
//! `python3 -c "from netportal import diagnostics, i18n ..."` in `tests/js/ages.test.mjs`):
//! prints `{"texts": <the English texts>, "stale_after_s": <diagnostics::STALE_AFTER_S>,
//! "tables": {"PRESENCE_STATES", "PRESENCE_SOURCES", "MAC_MODES", "HISTORY_RANGES"}}` as the
//! Rust version has them. Used by `rust/tests/js/ages.test.mjs`:
//!
//! ```sh
//! cargo run -q -p netportal-telemetry --example js_oracle
//! ```

use netportal_core::i18n::{self, Text};
use netportal_telemetry::diagnostics::STALE_AFTER_S;
use netportal_telemetry::presence;
use netportal_telemetry::telemetry::history::HISTORY_RANGES;
use serde_json::{Map, Value, json};

fn main() {
    let texts: Map<String, Value> = i18n::texts("en")
        .iter()
        .map(|(k, v)| {
            let v = match v {
                Text::One(s) => json!(s),
                Text::List(items) => json!(items),
            };
            (k.clone(), v)
        })
        .collect();
    let out = json!({
        "texts": texts,
        "stale_after_s": STALE_AFTER_S,
        "tables": {
            "PRESENCE_STATES": presence::STATES,
            "PRESENCE_SOURCES": presence::SOURCES,
            "MAC_MODES": ["hardware", "random_fixed", "rotating"],
            "HISTORY_RANGES": HISTORY_RANGES,
        },
    });
    println!("{out}");
}
