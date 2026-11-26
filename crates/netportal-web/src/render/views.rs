//! What the Python templates computed in Jinja with mutation (`dict.update`, `list.append`,
//! `namespace` counters) or with macros used as functions (`state_of(d)|string`,
//! `ap_clients(a)|trim`, `job_state(j)|trim`): the admin list's and the AP page's search,
//! filter and sort, the registry-only device cards, lookups by id. Plain functions on the page
//! values, registered on `fmt` like the Format port (`super::format`).
//!
//! Sorting follows the browser (`static/dashboard.js` applyFilters, applyApFilters), which
//! re-sorts the same lists in place: ties go by name (devices) or room (APs), the "seen" sort is
//! reversed as a whole (Python broke its ties by ascending name).

use std::cmp::Ordering;

use indexmap::IndexMap;
use jiff::Timestamp;
use serde_json::{Map, Value, json};

use super::format::{self, NONE, num, py_str, truthy};

/// The `x(kind, value)` macro of `_dash.html`: one value of a kind (`number`, `bytes`,
/// `bitrate`, `percent`, `dbm`, `db`, `ms`, `duration`, `ago`, `when`, `elapsed`, `date`, `room`,
/// `band`, `wifi`) in the language, `–` for none or "".
pub fn x(kind: &str, v: &Value, lang: &str, now: Option<Timestamp>) -> String {
    if v.is_null() || v.as_str() == Some("") {
        return NONE.into();
    }
    match kind {
        "number" => format::number(num(v), lang, 0),
        "bytes" => format::bytes(num(v), lang),
        "bitrate" => format::bitrate(num(v), lang),
        "percent" => format::percent(num(v), lang, 0),
        "dbm" => format::dbm(num(v), lang),
        "db" => format::db(num(v), lang),
        "ms" => format::ms(num(v), lang),
        "duration" => format::duration(num(v), lang, 2),
        "ago" => format::ago(v, lang, now),
        "when" => format::when(v, lang, now),
        "elapsed" => format::elapsed(v, lang, now),
        "date" => format::date(v, lang),
        "room" => format::room(v, lang),
        "band" => format::band(v, lang),
        "wifi" => format::wifi(v, lang),
        _ => py_str(v),
    }
}

/// `{str(item[key]): item}` (Python: `{% set _ = rows.update({r.id|string: r}) %}`).
pub fn by_key(items: &Value, key: &str) -> Map<String, Value> {
    items
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|item| {
            let k = item.get(key).filter(|k| !k.is_null())?;
            Some((py_str(k), item.clone()))
        })
        .collect()
}

/// The device cards from the registry alone, while the dashboard data is missing (state from
/// the last RADIUS login only); with `people` (the admin list) each with its owner.
pub fn registry_cards(rows: &Value, people: Option<&Value>) -> Vec<Value> {
    rows.as_array()
        .into_iter()
        .flatten()
        .map(|r| {
            let mut card = json!({
                "id": py_str(&r["id"]), "name": r["name"], "platform": r["platform"], "created": r["created"],
                "last_seen": r["last_seen"],
                "state": if truthy(&r["last_seen"]) { "unknown" } else { "never_connected" },
                "diagnostics": [],
            });
            if let (Some(people), Some(map)) = (people, card.as_object_mut()) {
                let person = people.get(py_str(&r["owner"])).unwrap_or(&Value::Null);
                let field = |name: &str| person.get(name).cloned().unwrap_or_else(|| r["owner"].clone());
                map.insert("owner".into(), json!({"username": field("username"), "display": field("display")}));
            }
            card
        })
        .collect()
}

/// A job's state on the overview: never, failed, late (older than three intervals of the
/// collector's schedule) or ok.
pub fn job_state(job: &Value) -> &'static str {
    let every = |name: &str| match name {
        "unifi_events" | "incidents" => Some(120.0),
        "rollup" => Some(1800.0),
        "prune" | "offboarding" => Some(86400.0),
        _ => None,
    };
    if !truthy(&job["last_attempt"]) && !truthy(&job["last_success"]) {
        return "never";
    }
    let failed = match job.get("ok") {
        Some(ok) => *ok == Value::Bool(false),
        None => truthy(&job["last_error"]),
    };
    if failed {
        return "failed";
    }
    let late = num(&job["age_s"])
        .zip(job["name"].as_str().and_then(every))
        .is_some_and(|(age, interval)| age > 3.0 * interval);
    if late { "late" } else { "ok" }
}

/// The devices on an AP now (`clients`, else `num_clients`), as the API sent it.
pub fn ap_clients(ap: &Value) -> Value {
    [&ap["clients"], &ap["num_clients"]].into_iter().find(|v| !v.is_null()).cloned().unwrap_or(Value::Null)
}

/// An AP as a room: the API's AP carries name, house, floor and spot itself (or under `ap`);
/// else the name is split.
pub fn ap_room(ap: &Value, lang: &str) -> String {
    let info = if ap["ap"].is_object() {
        ap["ap"].clone()
    } else if ap.get("house").is_some() {
        ap.clone()
    } else {
        let name = if truthy(&ap["name"]) { &ap["name"] } else { &ap["ap_name"] };
        format::ap_from_name(name)
    };
    x("room", &info, lang, None)
}

fn arg<'a>(args: &'a IndexMap<String, String>, name: &str) -> &'a str {
    args.get(name).map_or("", String::as_str)
}

/// A key the lists sort by: numbers before text, as the browser compares its `data-*` values.
#[derive(Debug, Clone, PartialEq)]
enum Key {
    Number(f64),
    Text(String),
}

fn compare(a: &Key, b: &Key) -> Ordering {
    match (a, b) {
        (Key::Number(x), Key::Number(y)) => x.total_cmp(y),
        (Key::Text(x), Key::Text(y)) => x.cmp(y),
        (Key::Number(_), Key::Text(_)) => Ordering::Less,
        (Key::Text(_), Key::Number(_)) => Ordering::Greater,
    }
}

/// The admin page's device list (Python `admin.html` top level): every device of the house
/// (the dashboard's, or the registry's alone with their owners), each with its registry row,
/// whether it matches the search and filters of the address (`q`: name, owner, MAC also as
/// `aa-bb-…`; `state`; `problem`: with, without or a finding code), its problems (warn and bad
/// findings) and finding codes, in the order of `sort` (name, owner, state, signal, health,
/// seen). Non-matching rows stay in the list (rendered `hidden`, the script filters in place).
pub fn admin_devices(dashboard: &Value, devices: &Value, people: &Value, args: &IndexMap<String, String>) -> Value {
    let all: Vec<Value> = if truthy(dashboard) {
        dashboard["devices"].as_array().cloned().unwrap_or_default()
    } else {
        registry_cards(devices, Some(people))
    };
    let rows = by_key(devices, "id");
    let q = arg(args, "q").trim().to_lowercase();
    let q_mac = q.replace('-', ":");
    let want_state = arg(args, "state");
    let want_problem = arg(args, "problem");
    let sort = match arg(args, "sort") {
        s @ ("name" | "owner" | "state" | "signal" | "health" | "seen") => s,
        _ => "name",
    };
    let mut shown = 0;
    let mut entries: Vec<(Key, String, Value)> = Vec::new();
    for d in &all {
        let owner = if truthy(&d["owner"]) { d["owner"].clone() } else { json!({}) };
        let state = format::state_of(d);
        let findings: Vec<&Value> = d["diagnostics"].as_array().into_iter().flatten().collect();
        let problems: Vec<Value> = findings
            .iter()
            .filter(|f| matches!(f["severity"].as_str(), Some("warn" | "bad")))
            .map(|f| (*f).clone())
            .collect();
        let codes: Vec<Value> = findings.iter().map(|f| f["code"].clone()).collect();
        let hay = [&d["name"], &owner["username"], &owner["display"], &d["mac"]]
            .into_iter()
            .filter(|v| truthy(v))
            .map(py_str)
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase();
        let matches = (q.is_empty() || hay.contains(&q) || hay.contains(&q_mac))
            && (want_state.is_empty() || state == want_state)
            && (want_problem.is_empty()
                || (want_problem == "with" && !problems.is_empty())
                || (want_problem == "without" && problems.is_empty())
                || codes.iter().any(|c| c.as_str() == Some(want_problem)));
        if matches {
            shown += 1;
        }
        let number_or =
            |v: &Value, default: f64| Key::Number(if v.is_null() { default } else { num(v).unwrap_or(default) });
        let key = match sort {
            "owner" => {
                let who = [&owner["display"], &owner["username"]].into_iter().find(|v| truthy(v)).map(py_str);
                Key::Text(who.unwrap_or_default().to_lowercase())
            }
            "state" => Key::Number(match state.as_str() {
                "offline" => 0.0,
                "never_connected" => 1.0,
                "connecting" => 3.0,
                "online" => 4.0,
                _ => 2.0,
            }),
            "signal" => number_or(&d["signal_dbm"], 999.0),
            "health" => number_or(&d["health"], 999.0),
            "seen" => Key::Text(seen(d, &state)),
            _ => Key::Text(py_str(&d["name"]).to_lowercase()),
        };
        let row = rows.get(&py_str(&d["id"])).cloned().unwrap_or(Value::Null);
        let entry = json!({"d": d, "row": row, "shown": matches, "problems": problems, "codes": codes, "state": state});
        entries.push((key, py_str(&d["name"]).to_lowercase(), entry));
    }
    entries.sort_by(|a, b| {
        let order = compare(&a.0, &b.0).then_with(|| a.1.cmp(&b.1));
        if sort == "seen" { order.reverse() } else { order }
    });
    json!({
        "rows": entries.into_iter().map(|(_, _, e)| e).collect::<Vec<_>>(),
        "total": all.len(), "shown": shown, "state": want_state, "problem": want_problem, "sort": sort,
    })
}

/// The admin row's `data-seen`: "~" while connected, else the last moment seen (RFC 3339), "".
fn seen(device: &Value, state: &str) -> String {
    if matches!(state, "online" | "connecting") {
        "~".into()
    } else if truthy(&device["last_seen"]) {
        format::iso(&device["last_seen"])
    } else {
        String::new()
    }
}

/// The AP page's cards (Python `admin_aps.html` top level): each AP with whether it matches
/// the search of the address (`q`: name, MAC, room), its devices now (as text, "" unknown), its
/// busiest radio's load and weak-signal share (-1 unknown) and its room, in the order of `sort`
/// (name = room, clients, load, weak: the most first).
pub fn ap_list(aps: &Value, args: &IndexMap<String, String>, lang: &str) -> Value {
    let q = arg(args, "q").trim().to_lowercase();
    let q_mac = q.replace('-', ":");
    let sort = match arg(args, "sort") {
        s @ ("name" | "clients" | "load" | "weak") => s,
        _ => "name",
    };
    let mut shown = 0;
    let mut entries: Vec<(Key, String, Value)> = Vec::new();
    for a in aps.as_array().into_iter().flatten() {
        let clients = ap_clients(a);
        let clients = if clients.is_null() { String::new() } else { py_str(&clients) };
        let load = format::ap_load(a).map_or(json!(-1), |l| json!(l));
        let weak = format::ap_weak_share(a).map_or(json!(-1), |w| json!(w));
        let room = ap_room(a, lang);
        let hay = [&a["name"], &a["mac"], &Value::String(room.clone())]
            .into_iter()
            .filter(|v| truthy(v))
            .map(py_str)
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase();
        let matches = q.is_empty() || hay.contains(&q) || hay.contains(&q_mac);
        if matches {
            shown += 1;
        }
        let most_first = |v: &Value| Key::Number(-num(v).unwrap_or(-1.0));
        let key = match sort {
            "clients" => Key::Number(-num(&Value::String(clients.clone())).unwrap_or(-1.0)),
            "load" => most_first(&load),
            "weak" => most_first(&weak),
            _ => Key::Text(room.to_lowercase()),
        };
        let entry = json!({"a": a, "shown": matches, "clients": clients, "load": load, "weak": weak, "room": room});
        entries.push((key, room.to_lowercase(), entry));
    }
    entries.sort_by(|a, b| compare(&a.0, &b.0).then_with(|| a.1.cmp(&b.1)));
    json!({"rows": entries.into_iter().map(|(_, _, e)| e).collect::<Vec<_>>(), "shown": shown, "sort": sort})
}

/// The renewal hint (`netportal_pki::enroll::expires_soon`, 30 days): an RFC 3339 expiry within
/// 30 days of now (or past); false for none or an unreadable value.
pub fn expires_soon(expires: &Value) -> bool {
    let expires = format::parse_time(expires)
        .and_then(|ts| time::OffsetDateTime::from_unix_timestamp_nanos(ts.as_nanosecond()).ok());
    expires.is_some() && netportal_pki::enroll::expires_soon(expires, time::OffsetDateTime::now_utc(), 30)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jobs() {
        assert_eq!(job_state(&json!({"last_attempt": null, "last_success": null})), "never");
        assert_eq!(job_state(&json!({"last_attempt": "x", "ok": false})), "failed");
        assert_eq!(job_state(&json!({"last_attempt": "x", "last_error": "boom"})), "failed");
        assert_eq!(job_state(&json!({"last_attempt": "x", "ok": null, "last_error": "boom"})), "ok");
        assert_eq!(job_state(&json!({"last_success": "x", "name": "incidents", "age_s": 361})), "late");
        assert_eq!(job_state(&json!({"last_success": "x", "name": "rollup", "age_s": 361})), "ok");
    }

    #[test]
    fn renewal_hint() {
        assert!(expires_soon(&json!("2000-01-01T00:00:00Z")));
        assert!(!expires_soon(&json!("2999-01-01T00:00:00Z")));
        assert!(!expires_soon(&Value::Null));
        assert!(!expires_soon(&json!("soon")));
    }

    #[test]
    fn registry_cards_take_the_owner() {
        let rows = json!([{"id": "1", "owner": "s1", "name": "A", "last_seen": null},
                          {"id": "2", "owner": "s2", "name": "B", "last_seen": "2026-10-25T12:00:00Z"}]);
        let people = json!({"s1": {"username": "resi", "display": "Resi"}});
        let cards = registry_cards(&rows, Some(&people));
        assert_eq!(cards[0]["owner"], json!({"username": "resi", "display": "Resi"}));
        assert_eq!(cards[0]["state"], "never_connected");
        assert_eq!(cards[1]["owner"], json!({"username": "s2", "display": "s2"}));
        assert_eq!(cards[1]["state"], "unknown");
        assert!(registry_cards(&rows, None)[0].get("owner").is_none());
    }
}
