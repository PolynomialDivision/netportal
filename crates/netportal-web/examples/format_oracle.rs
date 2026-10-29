//! The server's side of the JS tests' cross-checks of the formatting (`tests/js/format.test.mjs`,
//! `presence.test.mjs`, `v2.test.mjs`; the Python version ran `python3 -c "from netportal import
//! i18n ..."`): reads the cases as JSON on stdin, answers them with
//! [`netportal_web::render::format`] and prints the answers as JSON, in the shape the Python
//! scripts printed. Every mode prints `"texts": {lang: {key: text}}` for `en`, `de`, `uk`.
//!
//! - `format`: stdin `[[name, args], ...]` (`bytes`, `bitrate`, `percent`, `dbm`, `db`, `ms`,
//!   `duration`, `ago`, `when`, `date`, `number`, `room`, `wifi`, `band`); prints
//!   `{"texts", "answers": {lang: [text, ...]}}`.
//! - `presence`: stdin `{"devices", "now", "times"}`; prints `{"texts", "tables": {PRESENCE_*},
//!   "views": {lang: [presence_view]}, "recent": {lang: [..]}, "stamp": {lang: [..]}, "shown":
//!   [[code, ...]]}` (the SSID is "Example").
//! - `v2`: stdin `{"findings", "aps", "incidents", "days", "causes"}`; prints `{"texts",
//!   "tables", "ap_warnings", "causes", "lang": {lang: {"items", "admin", "short", "incidents",
//!   "days"}}}`.
//!
//! ```sh
//! echo '[["bytes", [999]]]' | cargo run -q -p netportal-web --example format_oracle -- format
//! ```

use std::io::Read;
use std::process::ExitCode;

use netportal_core::i18n::{self, Text};
use netportal_web::render::format as f;
use serde_json::{Map, Value, json};

const LANGS: [&str; 3] = ["en", "de", "uk"];

fn texts() -> Value {
    let mut out = Map::new();
    for lang in LANGS {
        let texts: Map<String, Value> = i18n::texts(lang)
            .iter()
            .map(|(k, v)| {
                let v = match v {
                    Text::One(s) => json!(s),
                    Text::List(items) => json!(items),
                };
                (k.clone(), v)
            })
            .collect();
        out.insert(lang.into(), Value::Object(texts));
    }
    Value::Object(out)
}

fn tables(names: &[&str]) -> Value {
    let all = i18n::tables();
    Value::Object(names.iter().map(|n| (n.to_string(), all.get(*n).cloned().unwrap_or(Value::Null))).collect())
}

fn list(input: &Value, key: &str) -> Vec<Value> {
    input.get(key).and_then(Value::as_array).cloned().unwrap_or_default()
}

fn digits(arg: Option<&Value>) -> u32 {
    arg.and_then(Value::as_u64).and_then(|d| u32::try_from(d).ok()).unwrap_or(0)
}

/// One case of `format.test.mjs` as Python's `getattr(i18n.Format, name)(args[0], lang, ...)`.
fn format_case(name: &str, args: &[Value], lang: &str) -> Result<String, String> {
    let null = Value::Null;
    let a = args.first().unwrap_or(&null);
    Ok(match name {
        "bytes" => f::bytes(f::num(a), lang),
        "bitrate" => f::bitrate(f::num(a), lang),
        "percent" => f::percent(f::num(a), lang, digits(args.get(1))),
        "number" => f::number(f::num(a), lang, digits(args.get(1))),
        "dbm" => f::dbm(f::num(a), lang),
        "db" => f::db(f::num(a), lang),
        "ms" => f::ms(f::num(a), lang),
        "duration" => f::duration(f::num(a), lang, 2),
        "ago" => f::ago(a, lang, args.get(1).and_then(f::parse_time)),
        "when" => f::when(a, lang, args.get(1).and_then(f::parse_time)),
        "date" => f::date(a, lang),
        "room" => f::room(a, lang),
        "wifi" => f::wifi(a, lang),
        "band" => f::band(a, lang),
        other => return Err(format!("unknown format case {other:?}")),
    })
}

fn format(input: &Value) -> Result<Value, String> {
    let cases = input.as_array().ok_or("format: stdin must be [[name, args], ...]")?;
    let mut answers = Map::new();
    for lang in LANGS {
        let mut out = Vec::new();
        for case in cases {
            let name = case.get(0).and_then(Value::as_str).ok_or("format: a case without a name")?;
            let args = case.get(1).and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]);
            out.push(Value::String(format_case(name, args, lang)?));
        }
        answers.insert(lang.into(), Value::Array(out));
    }
    Ok(json!({"texts": texts(), "answers": answers}))
}

fn presence(input: &Value) -> Value {
    let devices = list(input, "devices");
    let times = list(input, "times");
    let now = input.get("now").and_then(f::parse_time);
    let (mut views, mut recent, mut stamp) = (Map::new(), Map::new(), Map::new());
    for lang in LANGS {
        views.insert(lang.into(), devices.iter().map(|d| f::presence_view(d, lang, now, "Example")).collect());
        recent.insert(lang.into(), times.iter().map(|t| Value::String(f::recent(t, lang, now))).collect());
        stamp.insert(lang.into(), times.iter().map(|t| Value::String(f::stamp(t, lang))).collect());
    }
    let shown: Vec<Value> = devices
        .iter()
        .map(|d| f::findings_shown(d).iter().map(|x| x.get("code").cloned().unwrap_or(Value::Null)).collect())
        .collect();
    json!({
        "texts": texts(),
        "tables": tables(&["PRESENCE_STATES", "PRESENCE_SOURCES", "PRESENCE_REASONS", "PRESENCE_ICON"]),
        "views": views, "recent": recent, "stamp": stamp, "shown": shown,
    })
}

fn pairs(items: Vec<(String, String)>) -> Value {
    items.into_iter().map(|(label, value)| json!([label, value])).collect()
}

fn v2(input: &Value) -> Value {
    let findings = list(input, "findings");
    let incidents = list(input, "incidents");
    let days = list(input, "days");
    let mut by_lang = Map::new();
    for lang in LANGS {
        let (mut items, mut admin, mut short) = (Vec::new(), Vec::new(), Vec::new());
        for finding in &findings {
            let (shown, window) = f::evidence_items(finding, lang, false);
            items.push(json!([pairs(shown), window]));
            admin.push(pairs(f::evidence_items(finding, lang, true).0));
            short.push(json!(f::evidence_short(finding, lang)));
        }
        by_lang.insert(
            lang.into(),
            json!({
                "items": items, "admin": admin, "short": short,
                "incidents": incidents.iter().map(|i| f::incident_text(i, lang)).collect::<Vec<_>>(),
                "days": days.iter().map(|d| f::day(d, lang)).collect::<Vec<_>>(),
            }),
        );
    }
    json!({
        "texts": texts(),
        "tables": tables(&["EVIDENCE_SPEC", "EVIDENCE_FORMAT", "EVIDENCE_WINDOW", "EVIDENCE_SHORT", "EVENT_KINDS",
                           "REJECT_REASONS", "TERMINATE_CAUSES", "INCIDENT_KINDS", "MAC_MODES", "DIAGNOSES"]),
        "ap_warnings": list(input, "aps").iter().map(f::ap_warnings).collect::<Vec<_>>(),
        "causes": list(input, "causes").iter().map(f::cause_key).collect::<Vec<_>>(),
        "lang": by_lang,
    })
}

fn run() -> Result<Value, String> {
    let mode = std::env::args().nth(1).ok_or("usage: format_oracle format|presence|v2 < cases.json")?;
    let mut stdin = String::new();
    std::io::stdin().read_to_string(&mut stdin).map_err(|e| format!("stdin: {e}"))?;
    let input: Value = serde_json::from_str(&stdin).map_err(|e| format!("stdin is not JSON: {e}"))?;
    match mode.as_str() {
        "format" => format(&input),
        "presence" => Ok(presence(&input)),
        "v2" => Ok(v2(&input)),
        other => Err(format!("unknown mode {other:?} (format|presence|v2)")),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(out) => {
            println!("{out}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("format_oracle: {e}");
            ExitCode::FAILURE
        }
    }
}
