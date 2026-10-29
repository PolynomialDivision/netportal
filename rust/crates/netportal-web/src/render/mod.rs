//! Server-side rendering of the portal's pages (Python: Flask's `render_template` with Jinja2,
//! `netportal/templates/*.html`, the context processor and `i18n.template_globals()`; INVENTORY
//! 11.7-11.10, 12.1). The 12 templates are embedded (`templates/*.html` of this crate), ported to
//! minijinja with the same markup (`static/*.js` redraws parts of it with the same elements,
//! classes and `data-*` attributes).
//!
//! # Contract with the handlers
//!
//! A handler renders a page with [`Templates::render`]`(name, &base, page)`: [`Base`] is the
//! request's part (Python's context processor plus `request` and the session's user), `page`
//! the page's own values as a map (`minijinja::Value::from(minijinja::value::Serde(json))`);
//! a page value wins over a base value of the same name. Times are RFC 3339 strings (`Z`);
//! registry rows are JSON objects with Python's key names (`id, owner, name, platform, policy,
//! created, revoked, expires, certificates, last_seen, calling_station, first_seen`).
//!
//! | Template | Page values |
//! |---|---|
//! | `message.html` | `message` (str) |
//! | `landing.html` | – |
//! | `install.html` | `profile` (apple, apple-mac, android, eap-config; Python's `fmt`, renamed: it shadowed the formatting global), `token`, `name` |
//! | `consent.html` | `args` (map of the request's values), `consent_args` (the 7 field names, in order), `name` |
//! | `devices.html` | `devices` (the resident's registry rows), `dashboard` (`/api/devices` payload, devices with `expires_soon`), `options` (enrolment options, best first) |
//! | `device.html` | `dashboard` (one device), `device` (its DEVICE), `row` (its registry row), `history` (HISTORY of the range asked for), `ranges` (the range keys), `admin_view` (bool: `/admin/devices/<id>`), `raw` (RAW or none; admins) |
//! | `admin.html` | `devices` (every active registry row), `people` (`{sub: {username, display}}`), `dashboard` (admin DASHBOARD, devices with `owner {username, display}`), `overview` (OVERVIEW) |
//! | `admin_aps.html` | `aps` (APS payload, or a list of APs) |
//! | `admin_incidents.html` | `incidents` (INCIDENTS payload), `span` (`{from, to, kind}`; Python's `range`, renamed: it shadowed `range()`; unused by the template), `incident_kinds` |
//!
//! The render module provides the rest itself: `t` (the texts of `base.lang`), the JSON of the
//! texts for `np-texts`, `fmt` (the Format port, [`format`](mod@format) and [`views`]), `platform_label`,
//! `diagnoses`, `incident_kinds`, `history_ranges`, `event_kinds`, `presence_states` and
//! `expires_soon(value)` (30 days, `netportal_pki::enroll::expires_soon`). What Python computed
//! in the templates from the query string (the admin list's `q`, `state`, `problem`, `sort`; the
//! AP page's `q`, `sort`; the device page's `range` and `from`; the incidents page's `range`,
//! `kind`, `state`) is computed here from `base.request.args`, so the handlers pass only the
//! values above. `url_for` became literal paths.
//!
//! # Escaping
//!
//! markupsafe's, as Python: `& < > " '` become `&amp; &lt; &gt; &#34; &#39;` and nothing else
//! (minijinja's own HTML escaper also escapes `/`). `(t.key|e).format(...)` escapes the text,
//! inserts macro output raw and escapes plain values (`Markup.format`); `t.key.format(...)`
//! fills in plain text that is escaped as a whole on output. A `{name}` without a value stays
//! (core `fill`). `|tojson` writes JSON with `< > & '` as `\u003c` etc. (Jinja's
//! `htmlsafe_json_dumps`), safe inside `<script type="application/json">`; the JSON is UTF-8
//! (Python escaped every non-ASCII character), so the texts in `np-texts` read as they are.
//!
//! # From Jinja2 to minijinja
//!
//! - `str.format(**values)` and `dict.get(key[, default])` are answered by the unknown-method
//!   callback (`python_methods`); every other Python method is gone from the templates.
//! - `fmt` is an object with methods (`Fmt`): the Format port and the helpers that replace
//!   template code built on mutation or on macros used as functions (`rows.update`,
//!   `cards.append`, `keyed.append` + `sort(attribute="0")`, `state_of(d)|string`,
//!   `ap_clients(a)|trim`, `job_state(j)|trim`, `signal_level(...).split("|")`).
//! - Python's fallbacks for a missing `fmt` global are gone (it is always registered).
//! - `|truncate` follows `static/admin.js` (no leeway); the admin list's and the AP page's sort
//!   follow `static/dashboard.js` (ties by name or room; "seen" reversed as a whole); the day
//!   bars note follows `dashboard.js` `isDays` (`step == "day"`, or day steps on 1y/all).
//!
//! Moments relative to now (`5 min ago`, today's `14:05`) count from `dashboard.generated_at`
//! when the page has a dashboard payload, else from the real clock, as in Python; so does
//! `expires_soon`.

pub mod format;
pub mod views;

use std::collections::{BTreeMap, HashMap};

use indexmap::IndexMap;
use jiff::Timestamp;
use minijinja::value::{Kwargs, Object, Serde, Value, ValueKind, from_args};
use minijinja::{AutoEscape, Environment, Error, ErrorKind, State};
use netportal_core::i18n::{self, Text};
use serde::Serialize;

/// The embedded templates, by the names handlers render.
const TEMPLATES: [(&str, &str); 12] = [
    ("base.html", include_str!("../../templates/base.html")),
    ("message.html", include_str!("../../templates/message.html")),
    ("landing.html", include_str!("../../templates/landing.html")),
    ("install.html", include_str!("../../templates/install.html")),
    ("consent.html", include_str!("../../templates/consent.html")),
    ("devices.html", include_str!("../../templates/devices.html")),
    ("device.html", include_str!("../../templates/device.html")),
    ("admin.html", include_str!("../../templates/admin.html")),
    ("admin_aps.html", include_str!("../../templates/admin_aps.html")),
    ("admin_incidents.html", include_str!("../../templates/admin_incidents.html")),
    ("_dash.html", include_str!("../../templates/_dash.html")),
    ("_admin.html", include_str!("../../templates/_admin.html")),
];

/// The templates with everything they need, built once at start.
pub struct Templates {
    env: Environment<'static>,
    /// Per language: `t` (the texts) and the texts as JSON for `np-texts`.
    texts: HashMap<String, (Value, Value)>,
}

/// The per-request values every template sees (Python's context processor, `request`, the
/// session's user).
#[derive(Debug, Clone, Default, Serialize)]
pub struct Base {
    /// `en`, `de` or `uk` (another code renders English).
    pub lang: String,
    /// The logged-in person, `None` on pages without a login.
    pub user: Option<User>,
    /// The session's CSRF token (the meta tag and every form).
    pub csrf: String,
    pub settings: SettingsView,
    /// The netloc of `NETPORTAL_BASE_URL` (install steps).
    pub host: String,
    /// The browser saves a Passpoint file instead of installing it (Firefox/Gecko on Android).
    pub no_passpoint_browser: bool,
    pub request: RequestView,
}

/// The logged-in person; `admin` from the registry on this request.
#[derive(Debug, Clone, Default, Serialize)]
pub struct User {
    pub sub: String,
    pub username: String,
    pub name: String,
    pub admin: bool,
}

/// The settings the templates show.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SettingsView {
    pub display_name: String,
    /// The house's start page (the house bar's link).
    pub home: String,
    pub ssid: String,
    pub passpoint: bool,
}

/// The request as the templates read it.
#[derive(Debug, Clone, Default, Serialize)]
pub struct RequestView {
    pub path: String,
    /// The first value of every query key.
    pub args: IndexMap<String, String>,
}

impl Templates {
    /// Every template embedded, globals, functions and filters registered, markupsafe
    /// auto-escaping for `.html`; a template that does not parse is an error here.
    pub fn new() -> Result<Templates, Error> {
        let mut env = Environment::new();
        env.set_auto_escape_callback(|name| if name.ends_with(".html") { AutoEscape::Html } else { AutoEscape::None });
        env.set_formatter(|out, state, value| {
            if value.is_undefined() {
                return Ok(());
            }
            if value.is_safe() || matches!(state.auto_escape(), AutoEscape::None) {
                return write!(out, "{value}").map_err(Error::from);
            }
            out.write_str(&escape(&value.to_string())).map_err(Error::from)
        });
        env.add_filter("e", escape_filter);
        env.add_filter("escape", escape_filter);
        env.add_filter("tojson", tojson);
        env.add_filter("truncate", truncate);
        env.set_unknown_method_callback(python_methods);
        env.add_global("fmt", Value::from_object(Fmt));
        for (global, table) in [
            ("diagnoses", "DIAGNOSES"),
            ("event_kinds", "EVENT_KINDS"),
            ("incident_kinds", "INCIDENT_KINDS"),
            ("history_ranges", "RANGES"),
            ("presence_states", "PRESENCE_STATES"),
            ("platform_label", "PLATFORM_LABEL"),
        ] {
            let value = i18n::tables().get(table).cloned().unwrap_or(serde_json::Value::Null);
            env.add_global(global, Value::from(Serde(value)));
        }
        env.add_function("expires_soon", |value: Value| views::expires_soon(&json(&value)));
        for (name, source) in TEMPLATES {
            env.add_template(name, source)?;
        }
        let mut texts = HashMap::new();
        for lang in i18n::languages() {
            let mut t = BTreeMap::new();
            let mut j = serde_json::Map::new();
            for (key, text) in i18n::texts(lang) {
                let (value, json) = match text {
                    Text::One(s) => (Value::from(s.as_str()), serde_json::Value::from(s.as_str())),
                    Text::List(items) => (Value::from(items.clone()), serde_json::Value::from(items.clone())),
                };
                t.insert(key.clone(), value);
                j.insert(key.clone(), json);
            }
            let blob = html_safe_json(&serde_json::to_string(&j).map_err(json_error)?);
            texts.insert(lang.clone(), (Value::from(t), Value::from_safe_string(blob)));
        }
        Ok(Templates { env, texts })
    }

    /// Render one template with the request's [`Base`] merged with the page's own values (a
    /// map; a page value wins).
    pub fn render(&self, name: &str, base: &Base, page: Value) -> Result<String, Error> {
        let template = self.env.get_template(name)?;
        let lang = if self.texts.contains_key(&base.lang) { base.lang.as_str() } else { i18n::DEFAULT };
        let (t, texts_json) = self
            .texts
            .get(lang)
            .cloned()
            .ok_or_else(|| Error::new(ErrorKind::InvalidOperation, "no texts for the default language"))?;
        let mut context: BTreeMap<String, Value> = BTreeMap::new();
        context.insert("lang".into(), Value::from(lang));
        context.insert("user".into(), Value::from(Serde(&base.user)));
        context.insert("csrf".into(), Value::from(base.csrf.as_str()));
        context.insert("settings".into(), Value::from(Serde(&base.settings)));
        context.insert("host".into(), Value::from(base.host.as_str()));
        context.insert("no_passpoint_browser".into(), Value::from(base.no_passpoint_browser));
        context.insert("request".into(), Value::from(Serde(&base.request)));
        context.insert("t".into(), t);
        context.insert("texts_json".into(), texts_json);
        if page.kind() == ValueKind::Map {
            for key in page.try_iter()? {
                let value = page.get_item(&key)?;
                context.insert(key.to_string(), value);
            }
        }
        template.render(Value::from(context))
    }
}

// --- escaping -------------------------------------------------------------------------------------

/// markupsafe's escaping: `& < > " '` and nothing else.
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 8);
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&#34;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// `|e`: a safe string as it is, anything else escaped and marked safe (markupsafe `escape`).
fn escape_filter(value: Value) -> Value {
    if value.is_safe() { value } else { Value::from_safe_string(escape(&value.to_string())) }
}

/// JSON safe inside HTML (Jinja `htmlsafe_json_dumps`): `< > & '` as `\u003c` etc.
fn html_safe_json(json: &str) -> String {
    json.replace('<', "\\u003c").replace('>', "\\u003e").replace('&', "\\u0026").replace('\'', "\\u0027")
}

fn json_error(e: serde_json::Error) -> Error {
    Error::new(ErrorKind::InvalidOperation, "value cannot be written as JSON").with_source(e)
}

/// `|tojson`: the value as JSON for a `<script type="application/json">` block, marked safe.
fn tojson(value: Value) -> Result<Value, Error> {
    let text = serde_json::to_string(&value).map_err(json_error)?;
    Ok(Value::from_safe_string(html_safe_json(&text)))
}

/// `|truncate(length, end="…")`: at most `length` characters, the last one `end` when cut (as
/// `static/admin.js` cuts serials and errors; Jinja's leeway of 5 is gone).
fn truncate(value: Value, length: usize, end: Option<String>) -> Value {
    let text = value.to_string();
    let end = end.unwrap_or_else(|| "\u{2026}".into());
    if text.chars().count() <= length {
        return Value::from(text);
    }
    let keep = length.saturating_sub(end.chars().count());
    Value::from(text.chars().take(keep).collect::<String>() + &end)
}

/// The Python methods the templates call: `str.format(**values)` (with markupsafe's
/// `Markup.format` on a safe string) and `dict.get(key[, default])`.
fn python_methods(_state: &mut State, value: &Value, method: &str, args: &[Value]) -> Result<Value, Error> {
    match (value.kind(), method) {
        (ValueKind::String, "format") => {
            let (kwargs,): (Kwargs,) = from_args(args)?;
            let markup = value.is_safe();
            let mut values: Vec<(String, String)> = Vec::new();
            for name in kwargs.args() {
                let arg: Value = kwargs.get(name)?;
                let text = if markup && !arg.is_safe() { escape(&arg.to_string()) } else { arg.to_string() };
                values.push((name.to_string(), text));
            }
            let pairs: Vec<(&str, &str)> = values.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
            let filled = i18n::fill(value.as_str().unwrap_or(""), &pairs);
            Ok(if markup { Value::from_safe_string(filled) } else { Value::from(filled) })
        }
        (ValueKind::Map, "get") => {
            let (key, default): (Value, Option<Value>) = from_args(args)?;
            let found = value.get_item(&key)?;
            Ok(if found.is_undefined() { default.unwrap_or(Value::from(())) } else { found })
        }
        _ => Err(Error::from(ErrorKind::UnknownMethod)),
    }
}

// --- fmt ------------------------------------------------------------------------------------------

/// A template value as JSON (undefined: null).
fn json(value: &Value) -> serde_json::Value {
    serde_json::to_value(value).unwrap_or(serde_json::Value::Null)
}

fn moment_arg(value: Option<&Value>) -> Option<Timestamp> {
    value.and_then(|v| format::parse_time(&json(v)))
}

fn out<T: Serialize>(value: T) -> Value {
    Value::from(Serde(value))
}

/// The template global `fmt`: the Format port ([`format`]) and the page helpers ([`views`]),
/// called as `fmt.<name>(...)`; `lang` and `now` are passed by the templates as in Python.
#[derive(Debug)]
struct Fmt;

impl Object for Fmt {
    fn call_method(
        self: &std::sync::Arc<Self>,
        _state: &mut State,
        name: &str,
        args: &[Value],
    ) -> Result<Value, Error> {
        let rv = match name {
            "x" => {
                let (kind, v, lang, now): (&str, Value, &str, Option<Value>) = from_args(args)?;
                out(views::x(kind, &json(&v), lang, moment_arg(now.as_ref())))
            }
            "iso" => out(format::iso(&json(&one(args)?))),
            "state_of" => out(format::state_of(&json(&one(args)?))),
            "presence" => out(format::presence(&json(&one(args)?))),
            "presence_view" => {
                let (d, lang, now, ssid): (Value, &str, Option<Value>, Option<&str>) = from_args(args)?;
                out(format::presence_view(&json(&d), lang, moment_arg(now.as_ref()), ssid.unwrap_or("")))
            }
            "parts" => out(format::parts(&json(&one(args)?))),
            "presence_evidence" => {
                let (p, limit): (Value, Option<usize>) = from_args(args)?;
                out(format::presence_evidence(&json(&p), limit.unwrap_or(20)))
            }
            "moment" => {
                let (v, kind, lang, now): (Value, &str, &str, Option<Value>) = from_args(args)?;
                out(format::moment(&json(&v), kind, lang, moment_arg(now.as_ref())))
            }
            "signal" => out(format::signal(format::num(&json(&one(args)?)))),
            "health" => out(format::health(format::num(&json(&one(args)?)))),
            "evidence_short" => {
                let (f, lang): (Value, &str) = from_args(args)?;
                out(format::evidence_short(&json(&f), lang))
            }
            "evidence_items" => {
                let (f, lang, admin): (Value, &str, Option<bool>) = from_args(args)?;
                out(format::evidence_items(&json(&f), lang, admin.unwrap_or(false)))
            }
            "findings_shown" => out(format::findings_shown(&json(&one(args)?))),
            "reason_key" => out(format::reason_key(&json(&one(args)?))),
            "cause_key" => out(format::cause_key(&json(&one(args)?))),
            "ap_from_name" => out(format::ap_from_name(&json(&one(args)?))),
            "incident_text" | "scope" => {
                let (inc, lang): (Value, &str) = from_args(args)?;
                let inc = json(&inc);
                out(if name == "scope" { format::scope(&inc, lang) } else { format::incident_text(&inc, lang) })
            }
            "elapsed" => {
                let (start, lang, now): (Value, &str, Option<Value>) = from_args(args)?;
                out(format::elapsed(&json(&start), lang, moment_arg(now.as_ref())))
            }
            "plain" => out(format::plain(&json(&one(args)?))),
            "ap_state" => out(format::ap_state(&json(&one(args)?))),
            "ap_weak_share" => out(format::ap_weak_share(&json(&one(args)?))),
            "ap_load" => out(format::ap_load(&json(&one(args)?))),
            "ap_warnings" => out(format::ap_warnings(&json(&one(args)?))),
            "util_of" => out(format::util_of(&json(&one(args)?))),
            "ap_clients" => out(views::ap_clients(&json(&one(args)?))),
            "ap_room" => {
                let (ap, lang): (Value, &str) = from_args(args)?;
                out(views::ap_room(&json(&ap), lang))
            }
            "day" => {
                let (v, lang): (Value, &str) = from_args(args)?;
                out(format::day(&json(&v), lang))
            }
            "span_key" => {
                let (start, end, keys): (Value, Value, Vec<String>) = from_args(args)?;
                let keys: Vec<&str> = keys.iter().map(String::as_str).collect();
                out(format::span_key(&json(&start), &json(&end), &keys))
            }
            "job_state" => out(views::job_state(&json(&one(args)?))),
            "by_key" => {
                let (items, key): (Value, &str) = from_args(args)?;
                out(views::by_key(&json(&items), key))
            }
            "registry_cards" => {
                let (rows, people): (Value, Option<Value>) = from_args(args)?;
                out(views::registry_cards(&json(&rows), people.map(|p| json(&p)).as_ref()))
            }
            "admin_devices" => {
                let (dashboard, devices, people, query): (Value, Value, Value, Value) = from_args(args)?;
                out(views::admin_devices(&json(&dashboard), &json(&devices), &json(&people), &query_args(&query)))
            }
            "ap_list" => {
                let (aps, query, lang): (Value, Value, &str) = from_args(args)?;
                out(views::ap_list(&json(&aps), &query_args(&query), lang))
            }
            _ => return Err(Error::from(ErrorKind::UnknownMethod)),
        };
        Ok(rv)
    }
}

fn one(args: &[Value]) -> Result<Value, Error> {
    let (value,): (Value,) = from_args(args)?;
    Ok(value)
}

/// `request.args` back as a map of strings.
fn query_args(value: &Value) -> IndexMap<String, String> {
    match json(value) {
        serde_json::Value::Object(map) => {
            map.into_iter().map(|(k, v)| (k, v.as_str().map_or_else(|| format::py_str(&v), str::to_string))).collect()
        }
        _ => IndexMap::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaping_is_markupsafes() {
        assert_eq!(escape(r#"<a href="/x">'&'</a>"#), "&lt;a href=&#34;/x&#34;&gt;&#39;&amp;&#39;&lt;/a&gt;");
        assert_eq!(html_safe_json(r#"{"a":"</script>&'"}"#), r#"{"a":"\u003c/script\u003e\u0026\u0027"}"#);
        assert_eq!(truncate(Value::from("4f1c2a9b77e0aa"), 14, None).to_string(), "4f1c2a9b77e0aa");
        assert_eq!(truncate(Value::from("4f1c2a9b77e0aab"), 14, None).to_string(), "4f1c2a9b77e0a\u{2026}");
        assert_eq!(truncate(Value::from("abcdef"), 3, Some(String::new())).to_string(), "abc");
    }

    #[test]
    fn every_template_parses() {
        assert!(Templates::new().is_ok());
    }
}
