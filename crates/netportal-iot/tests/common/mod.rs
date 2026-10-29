//! Shared test pieces: an in-process fake UniFi controller (legacy API: login cookie, CSRF
//! token, `rest/wlanconf`, `rest/networkconf`, `stat/sta`, `rest/user`, `cmd/stamgr`), an
//! in-process fake OPNsense (HTTP Basic; aliases, alias_util, filter rules, interfaces, states,
//! leases), both recording every request, and a fresh registry database per test.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use netportal_core::Db;
use netportal_core::config::Policy;
use netportal_core::iot::{self, NewDevice};
use netportal_core::registry;
use serde_json::{Value, json};
use sqlx::{Connection, Executor, PgConnection};
use uuid::Uuid;

/// A recorded request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Req {
    pub method: String,
    pub path: String,
    pub body: Value,
    /// the `Cookie`, `X-Csrf-Token` and `Authorization` headers, when sent
    pub headers: BTreeMap<String, String>,
}

impl Req {
    pub fn is(&self, method: &str, path: &str) -> bool {
        self.method == method && self.path == path
    }
}

async fn read_body(req: Request) -> (Method, String, HeaderMap, Value) {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let headers = req.headers().clone();
    let bytes: Bytes = axum::body::to_bytes(req.into_body(), 1 << 20).await.unwrap_or_default();
    let body = if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).unwrap_or(Value::Null) };
    (method, path, headers, body)
}

fn record(method: &Method, path: &str, headers: &HeaderMap, body: &Value) -> Req {
    let kept = ["cookie", "x-csrf-token", "authorization"]
        .iter()
        .filter_map(|h| headers.get(*h).and_then(|v| v.to_str().ok()).map(|v| (h.to_string(), v.to_string())))
        .collect();
    Req { method: method.to_string(), path: path.to_string(), body: body.clone(), headers: kept }
}

fn s(v: &Value, key: &str) -> String {
    match v.get(key) {
        Some(Value::String(t)) => t.clone(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => if *b { "1" } else { "0" }.to_string(),
        _ => String::new(),
    }
}

async fn serve(app: axum::Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("address");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

// --- UniFi ------------------------------------------------------------------------------------------

pub const UNIFI_USER: &str = "iot-admin";
pub const UNIFI_PASSWORD: &str = "unifi-admin-password";
const UNIFI_COOKIE: &str = "unifises=sess-0001";
const UNIFI_CSRF: &str = "csrf-0001";

#[derive(Default)]
pub struct UnifiState {
    pub networks: Vec<Value>,
    pub wlans: Vec<Value>,
    pub clients: Vec<Value>,
    pub users: Vec<Value>,
    pub requests: Vec<Req>,
    /// paths containing one of these answer 500
    pub fail_paths: Vec<String>,
}

pub struct FakeUnifi {
    pub url: String,
    pub state: Arc<Mutex<UnifiState>>,
}

impl FakeUnifi {
    pub async fn start(state: UnifiState) -> FakeUnifi {
        let state = Arc::new(Mutex::new(state));
        let app = axum::Router::new().fallback(unifi_handler).with_state(state.clone());
        FakeUnifi { url: serve(app).await, state }
    }

    /// The standard set-up: the IoT network and SSID (no keys yet), a residents' SSID.
    pub fn standard() -> UnifiState {
        UnifiState {
            networks: vec![
                json!({"_id": "n-res", "name": "Residents", "vlan": 30, "purpose": "corporate"}),
                json!({"_id": "n-iot", "name": "IoT", "vlan": 40, "purpose": "corporate"}),
            ],
            wlans: vec![
                json!({"_id": "w-res", "name": "Scharni", "security": "wpaeap"}),
                json!({"_id": "w-iot", "name": "Scharni-IoT", "security": "wpapsk",
                       "private_preshared_keys": [], "private_preshared_keys_enabled": false}),
            ],
            ..UnifiState::default()
        }
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut UnifiState) -> R) -> R {
        f(&mut self.state.lock().expect("state"))
    }

    pub fn requests(&self) -> Vec<Req> {
        self.with(|s| s.requests.clone())
    }

    /// The requests that change something (everything but logins, logouts and reads).
    pub fn writes(&self) -> Vec<Req> {
        self.requests()
            .into_iter()
            .filter(|r| r.method != "GET" && r.path != "/api/login" && r.path != "/api/logout")
            .collect()
    }

    pub fn clear(&self) {
        self.with(|s| s.requests.clear());
    }

    /// The IoT SSID's keys as `(password, networkconf_id)`.
    pub fn keys(&self) -> BTreeSet<(String, String)> {
        self.with(|st| {
            st.wlans
                .iter()
                .find(|w| s(w, "_id") == "w-iot")
                .and_then(|w| w.get("private_preshared_keys"))
                .and_then(Value::as_array)
                .map(|keys| keys.iter().map(|k| (s(k, "password"), s(k, "networkconf_id"))).collect())
                .unwrap_or_default()
        })
    }

    pub fn ppsk_enabled(&self) -> bool {
        self.with(|st| {
            st.wlans
                .iter()
                .find(|w| s(w, "_id") == "w-iot")
                .and_then(|w| w.get("private_preshared_keys_enabled"))
                .and_then(Value::as_bool)
                .unwrap_or(false)
        })
    }

    pub fn blocked(&self) -> BTreeSet<String> {
        self.with(|st| {
            st.users.iter().filter(|u| u.get("blocked") == Some(&json!(true))).map(|u| s(u, "mac")).collect()
        })
    }
}

fn unifi_ok(data: Value) -> Response {
    axum::Json(json!({"meta": {"rc": "ok"}, "data": data})).into_response()
}

fn unifi_err(status: StatusCode, msg: &str) -> Response {
    (status, axum::Json(json!({"meta": {"rc": "error", "msg": msg}, "data": []}))).into_response()
}

async fn unifi_handler(State(state): State<Arc<Mutex<UnifiState>>>, req: Request) -> Response {
    let (method, path, headers, body) = read_body(req).await;
    let mut st = state.lock().expect("state");
    st.requests.push(record(&method, &path, &headers, &body));
    if st.fail_paths.iter().any(|f| path.contains(f.as_str())) {
        return unifi_err(StatusCode::INTERNAL_SERVER_ERROR, "api.err.ServerError");
    }
    if method == Method::POST && path == "/api/login" {
        if s(&body, "username") == UNIFI_USER && s(&body, "password") == UNIFI_PASSWORD {
            // two Set-Cookie headers (append: an array of pairs would replace the first)
            let mut out = HeaderMap::new();
            let cookie = |text: String| HeaderValue::from_str(&text).expect("header value");
            out.append(header::SET_COOKIE, cookie(format!("{UNIFI_COOKIE}; Path=/; HttpOnly")));
            out.append(header::SET_COOKIE, cookie(format!("csrf_token={UNIFI_CSRF}; Path=/")));
            out.insert("x-csrf-token", HeaderValue::from_static(UNIFI_CSRF));
            return (out, axum::Json(json!({"meta": {"rc": "ok"}, "data": []}))).into_response();
        }
        return unifi_err(StatusCode::BAD_REQUEST, "api.err.Invalid");
    }
    if method == Method::POST && path == "/api/logout" {
        return unifi_ok(json!([]));
    }
    let cookie = headers.get(header::COOKIE).and_then(|v| v.to_str().ok()).unwrap_or("");
    if !cookie.split(';').any(|c| c.trim() == UNIFI_COOKIE) {
        return unifi_err(StatusCode::UNAUTHORIZED, "api.err.LoginRequired");
    }
    if method != Method::GET && headers.get("x-csrf-token").and_then(|v| v.to_str().ok()) != Some(UNIFI_CSRF) {
        return unifi_err(StatusCode::UNAUTHORIZED, "api.err.CsrfTokenInvalid");
    }
    let Some(rest) = path.strip_prefix("/api/s/default/") else {
        return unifi_err(StatusCode::BAD_REQUEST, "api.err.NoSiteContext");
    };
    match (method.as_str(), rest) {
        ("GET", "rest/networkconf") => unifi_ok(Value::Array(st.networks.clone())),
        ("GET", "rest/wlanconf") => unifi_ok(Value::Array(st.wlans.clone())),
        ("GET", "stat/sta") => unifi_ok(Value::Array(st.clients.clone())),
        ("GET", "rest/user") => unifi_ok(Value::Array(st.users.clone())),
        ("PUT", p) if p.starts_with("rest/wlanconf/") => {
            let id = p.trim_start_matches("rest/wlanconf/").to_string();
            let Some(wlan) = st.wlans.iter_mut().find(|w| s(w, "_id") == id) else {
                return unifi_err(StatusCode::BAD_REQUEST, "api.err.IdInvalid");
            };
            // the real controller refuses PPSK switched on without a key (2026-10-29)
            let merged = {
                let mut m = wlan.clone();
                if let (Some(target), Some(fields)) = (m.as_object_mut(), body.as_object()) {
                    for (k, v) in fields {
                        target.insert(k.clone(), v.clone());
                    }
                }
                m
            };
            let enabled = merged.get("private_preshared_keys_enabled").and_then(Value::as_bool).unwrap_or(false);
            let empty = merged.get("private_preshared_keys").and_then(Value::as_array).is_none_or(Vec::is_empty);
            if enabled && empty {
                return unifi_err(StatusCode::BAD_REQUEST, "api.err.EmptyPrivatePreSharedKeys");
            }
            *wlan = merged.clone();
            unifi_ok(json!([merged]))
        }
        ("POST", "cmd/stamgr") => {
            let (cmd, mac) = (s(&body, "cmd"), s(&body, "mac"));
            if mac.is_empty() {
                return unifi_err(StatusCode::BAD_REQUEST, "api.err.InvalidPayload");
            }
            match cmd.as_str() {
                "block-sta" | "unblock-sta" => {
                    let blocked = cmd == "block-sta";
                    match st.users.iter_mut().find(|u| s(u, "mac").eq_ignore_ascii_case(&mac)) {
                        Some(user) => {
                            user["blocked"] = json!(blocked);
                        }
                        None => st.users.push(json!({"mac": mac, "blocked": blocked, "name": "unknown"})),
                    }
                    unifi_ok(json!([]))
                }
                "kick-sta" => {
                    st.clients.retain(|c| !s(c, "mac").eq_ignore_ascii_case(&mac));
                    unifi_ok(json!([]))
                }
                _ => unifi_err(StatusCode::BAD_REQUEST, "api.err.InvalidCommand"),
            }
        }
        _ => unifi_err(StatusCode::NOT_FOUND, "api.err.NotFound"),
    }
}

// --- OPNsense -----------------------------------------------------------------------------------------

pub const OPN_KEY: &str = "iot-api-key";
pub const OPN_SECRET: &str = "iot-api-secret";

#[derive(Default)]
pub struct OpnState {
    /// uuid -> the alias object (name, description, enabled, type, content)
    pub aliases: BTreeMap<String, Value>,
    /// alias name -> live content
    pub contents: BTreeMap<String, BTreeSet<String>>,
    /// uuid -> the rule fields
    pub rules: BTreeMap<String, Value>,
    pub interfaces: Vec<Value>,
    pub leases: Vec<Value>,
    /// `{id, creatorid, src_addr, dst_addr}`
    pub states: Vec<Value>,
    pub requests: Vec<Req>,
    pub reconfigures: usize,
    pub applies: usize,
    /// which state-removal route exists: `del_state` or `delState`
    pub del_state_route: String,
    pub kill_states_available: bool,
    pub fail_paths: Vec<String>,
    next_id: usize,
}

pub struct FakeOpnsense {
    pub url: String,
    pub state: Arc<Mutex<OpnState>>,
}

impl FakeOpnsense {
    pub async fn start(state: OpnState) -> FakeOpnsense {
        let state = Arc::new(Mutex::new(state));
        let app = axum::Router::new().fallback(opn_handler).with_state(state.clone());
        FakeOpnsense { url: serve(app).await, state }
    }

    /// The standard set-up: the residents' and IoT interfaces, a hand-made alias and rule
    /// (never touched), `del_state` and `kill_states` available.
    pub fn standard() -> OpnState {
        let mut st = OpnState {
            interfaces: vec![
                json!({"identifier": "lan", "description": "LAN", "addr4": ["10.0.10.1/24"]}),
                json!({"identifier": "opt2", "description": "Residents", "addr4": ["10.0.30.1/24"]}),
                json!({"identifier": "opt3", "description": "IoT", "ipv4": [{"ipaddr": "10.0.40.1/24"}]}),
            ],
            del_state_route: "del_state".into(),
            kill_states_available: true,
            ..OpnState::default()
        };
        st.add_alias("house_servers", "house-infra: the servers", &["10.0.10.5"]);
        st.rules.insert(
            "r-hand".into(),
            json!({"enabled": "1", "sequence": "100", "action": "block", "quick": "1", "interface": "opt2",
                   "direction": "in", "ipprotocol": "inet", "protocol": "any", "source_net": "any", "source_not": "0",
                   "destination_net": "10.0.40.0/24", "destination_not": "0", "destination_port": "", "log": "0",
                   "description": "house-infra: residents to iot blocked"}),
        );
        st
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut OpnState) -> R) -> R {
        f(&mut self.state.lock().expect("state"))
    }

    pub fn requests(&self) -> Vec<Req> {
        self.with(|s| s.requests.clone())
    }

    /// The requests that change something (every POST but the searches).
    pub fn writes(&self) -> Vec<Req> {
        self.requests()
            .into_iter()
            .filter(|r| {
                r.method == "POST"
                    && !r.path.contains("searchItem")
                    && !r.path.contains("searchRule")
                    && !r.path.contains("query_states")
            })
            .collect()
    }

    pub fn clear(&self) {
        self.with(|s| s.requests.clear());
    }

    pub fn alias_names(&self) -> BTreeSet<String> {
        self.with(|st| st.aliases.values().map(|a| s(a, "name")).collect())
    }

    pub fn content(&self, name: &str) -> BTreeSet<String> {
        self.with(|st| st.contents.get(name).cloned().unwrap_or_default())
    }

    pub fn rule_descriptions(&self) -> BTreeSet<String> {
        self.with(|st| st.rules.values().map(|r| s(r, "description")).collect())
    }

    pub fn rule(&self, description: &str) -> Option<Value> {
        self.with(|st| st.rules.values().find(|r| s(r, "description") == description).cloned())
    }

    pub fn states(&self) -> Vec<(String, String)> {
        self.with(|st| st.states.iter().map(|x| (s(x, "src_addr"), s(x, "dst_addr"))).collect())
    }
}

impl OpnState {
    fn id(&mut self, kind: &str) -> String {
        self.next_id += 1;
        format!("{kind}-{:04}", self.next_id)
    }

    pub fn add_alias(&mut self, name: &str, description: &str, content: &[&str]) -> String {
        let uuid = self.id("alias");
        self.aliases.insert(
            uuid.clone(),
            json!({"enabled": "1", "name": name, "type": "host", "content": content.join("\n"), "description": description}),
        );
        self.contents.insert(name.to_string(), content.iter().map(|c| c.to_string()).collect());
        uuid
    }

    pub fn lease(&mut self, mac: &str, address: &str, expire: Value) {
        self.leases.push(json!({"hwaddr": mac, "address": address, "expire": expire, "hostname": "", "if": "opt2"}));
    }

    pub fn state(&mut self, src: &str, dst: &str) {
        let id = self.id("state");
        self.states.push(json!({"id": id, "creatorid": "c0", "src_addr": src, "dst_addr": dst, "proto": "tcp"}));
    }
}

fn opn_json(v: Value) -> Response {
    axum::Json(v).into_response()
}

fn opn_rows(rows: Vec<Value>) -> Response {
    let n = rows.len();
    opn_json(json!({"rows": rows, "rowCount": n, "total": n, "current": 1}))
}

fn opn_not_found() -> Response {
    (StatusCode::NOT_FOUND, axum::Json(json!({"status": 404, "message": "Endpoint not found"}))).into_response()
}

async fn opn_handler(State(state): State<Arc<Mutex<OpnState>>>, req: Request) -> Response {
    let (method, path, headers, body) = read_body(req).await;
    let mut st = state.lock().expect("state");
    st.requests.push(record(&method, &path, &headers, &body));
    let expected =
        format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{OPN_KEY}:{OPN_SECRET}")));
    if headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) != Some(expected.as_str()) {
        return (StatusCode::UNAUTHORIZED, axum::Json(json!({"status": 401, "message": "Authentication Failed"})))
            .into_response();
    }
    if st.fail_paths.iter().any(|f| path.contains(f.as_str())) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"status": 500, "message": "failing on purpose"})),
        )
            .into_response();
    }
    let Some(rest) = path.strip_prefix("/api/") else {
        return opn_not_found();
    };
    let parts: Vec<&str> = rest.split('/').collect();
    let m = method.as_str();
    match (m, parts.as_slice()) {
        ("POST", ["firewall", "alias", "searchItem"]) => {
            let rows = st
                .aliases
                .iter()
                .map(|(uuid, a)| {
                    let mut row = a.clone();
                    row["uuid"] = json!(uuid);
                    row
                })
                .collect();
            opn_rows(rows)
        }
        ("POST", ["firewall", "alias", "addItem"]) => {
            let alias = body.get("alias").cloned().unwrap_or(Value::Null);
            let name = s(&alias, "name");
            let valid = !name.is_empty()
                && name.len() <= 31
                && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                && !name.as_bytes()[0].is_ascii_digit();
            if !valid {
                return opn_json(json!({"result": "failed", "validations": {"alias.name": "Invalid alias name"}}));
            }
            if st.aliases.values().any(|a| s(a, "name") == name) {
                return opn_json(
                    json!({"result": "failed", "validations": {"alias.name": "An alias with this name already exists"}}),
                );
            }
            let uuid = st.id("alias");
            let content: BTreeSet<String> =
                s(&alias, "content").split('\n').filter(|c| !c.is_empty()).map(str::to_string).collect();
            st.aliases.insert(uuid.clone(), alias);
            st.contents.insert(name, content);
            opn_json(json!({"result": "saved", "uuid": uuid}))
        }
        ("POST", ["firewall", "alias", "setItem", uuid]) => {
            let uuid = uuid.to_string();
            if !st.aliases.contains_key(&uuid) {
                return opn_json(json!({"result": "failed"}));
            }
            st.aliases.insert(uuid, body.get("alias").cloned().unwrap_or(Value::Null));
            opn_json(json!({"result": "saved"}))
        }
        ("POST", ["firewall", "alias", "delItem", uuid]) => {
            let uuid = uuid.to_string();
            let Some(alias) = st.aliases.get(&uuid).cloned() else {
                return opn_json(json!({"result": "not found"}));
            };
            let name = s(&alias, "name");
            if st.rules.values().any(|r| s(r, "source_net") == name || s(r, "destination_net") == name) {
                return opn_json(json!({"result": "failed", "validations": {"alias": "Alias in use by a rule"}}));
            }
            st.aliases.remove(&uuid);
            st.contents.remove(&name);
            opn_json(json!({"result": "deleted"}))
        }
        ("POST", ["firewall", "alias", "reconfigure"]) => {
            st.reconfigures += 1;
            opn_json(json!({"status": "ok"}))
        }
        ("GET", ["firewall", "alias_util", "list", name]) => {
            let rows =
                st.contents.get(*name).map(|c| c.iter().map(|ip| json!({"ip": ip})).collect()).unwrap_or_default();
            opn_rows(rows)
        }
        ("POST", ["firewall", "alias_util", verb @ ("add" | "delete"), name]) => {
            let address = s(&body, "address");
            let Some(content) = st.contents.get_mut(*name) else {
                return opn_json(json!({"status": "failed"}));
            };
            if address.is_empty() {
                return opn_json(json!({"status": "failed"}));
            }
            if *verb == "add" {
                content.insert(address);
            } else {
                content.remove(&address);
            }
            opn_json(json!({"status": "done"}))
        }
        ("POST", ["firewall", "filter", "searchRule"]) => {
            let rows = st
                .rules
                .iter()
                .map(|(uuid, r)| {
                    let mut row = r.clone();
                    row["uuid"] = json!(uuid);
                    row["%interface"] = json!(s(r, "interface").to_uppercase());
                    row
                })
                .collect();
            opn_rows(rows)
        }
        ("POST", ["firewall", "filter", "addRule"]) | ("POST", ["firewall", "filter", "setRule", _]) => {
            let rule = body.get("rule").cloned().unwrap_or(Value::Null);
            let interfaces: BTreeSet<String> = st.interfaces.iter().map(|i| s(i, "identifier")).collect();
            let aliases: BTreeSet<String> = st.aliases.values().map(|a| s(a, "name")).collect();
            let net_ok = |v: String| {
                v == "any" || v.contains('/') || v.parse::<std::net::Ipv4Addr>().is_ok() || aliases.contains(&v)
            };
            if !interfaces.contains(&s(&rule, "interface")) {
                return opn_json(json!({"result": "failed", "validations": {"rule.interface": "option not in list"}}));
            }
            if !net_ok(s(&rule, "source_net")) || !net_ok(s(&rule, "destination_net")) {
                return opn_json(json!({"result": "failed", "validations": {"rule.source_net": "unknown alias"}}));
            }
            if s(&rule, "description").is_empty() || s(&rule, "sequence").parse::<u32>().is_err() {
                return opn_json(json!({"result": "failed", "validations": {"rule.sequence": "a number"}}));
            }
            if parts.len() == 4 {
                let uuid = parts[3].to_string();
                if !st.rules.contains_key(&uuid) {
                    return opn_json(json!({"result": "failed"}));
                }
                st.rules.insert(uuid, rule);
                return opn_json(json!({"result": "saved"}));
            }
            let uuid = st.id("rule");
            st.rules.insert(uuid.clone(), rule);
            opn_json(json!({"result": "saved", "uuid": uuid}))
        }
        ("POST", ["firewall", "filter", "delRule", uuid]) => {
            if st.rules.remove(*uuid).is_none() {
                return opn_json(json!({"result": "not found"}));
            }
            opn_json(json!({"result": "deleted"}))
        }
        ("POST", ["firewall", "filter", "apply"]) => {
            st.applies += 1;
            opn_json(json!({"status": "OK\n\n"}))
        }
        ("GET", ["interfaces", "overview", "interfacesInfo"]) => opn_rows(st.interfaces.clone()),
        ("POST", ["diagnostics", "firewall", "query_states"]) => {
            let phrase = s(&body, "searchPhrase");
            let rows = st
                .states
                .iter()
                .filter(|x| {
                    phrase.is_empty() || s(x, "src_addr").contains(&phrase) || s(x, "dst_addr").contains(&phrase)
                })
                .cloned()
                .collect();
            opn_rows(rows)
        }
        ("POST", ["diagnostics", "firewall", route @ ("del_state" | "delState"), id, creatorid]) => {
            if *route != st.del_state_route {
                return opn_not_found();
            }
            let before = st.states.len();
            st.states.retain(|x| !(s(x, "id") == *id && s(x, "creatorid") == *creatorid));
            if st.states.len() == before {
                return opn_json(json!({"result": "failed"}));
            }
            opn_json(json!({"result": "ok"}))
        }
        ("POST", ["diagnostics", "firewall", "kill_states"]) => {
            if !st.kill_states_available {
                return opn_not_found();
            }
            let filter = s(&body, "filter");
            let before = st.states.len();
            st.states.retain(|x| {
                let strip = |a: String| a.rsplit_once(':').map(|(h, _)| h.to_string()).unwrap_or(a);
                strip(s(x, "src_addr")) != filter && strip(s(x, "dst_addr")) != filter
            });
            opn_json(json!({"result": "ok", "dropped_states": before - st.states.len()}))
        }
        ("GET", ["dnsmasq", "leases", "search"]) => opn_rows(st.leases.clone()),
        _ => opn_not_found(),
    }
}

// --- the registry ----------------------------------------------------------------------------------------

/// The registry tests' database URL, `None` (test skipped) without `NETPORTAL_TEST_DATABASE_URL`.
pub fn admin_url() -> Option<url::Url> {
    let url = std::env::var("NETPORTAL_TEST_DATABASE_URL").ok().filter(|u| !u.is_empty())?;
    url::Url::parse(&url).ok()
}

#[macro_export]
macro_rules! need_db {
    () => {
        match common::admin_url() {
            Some(url) => url,
            None => {
                eprintln!("skipped: NETPORTAL_TEST_DATABASE_URL is not set (eval \"$(tools/test-db.sh)\")");
                return;
            }
        }
    };
}

/// Schema set-up statements of concurrent tests (the grants) would collide.
static INIT: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub fn policies() -> Vec<Policy> {
    vec![
        Policy { name: "residents".into(), vlan: 30, groups: ["residents".to_string()].into() },
        Policy { name: "guests".into(), vlan: 50, groups: ["former-residents".to_string()].into() },
    ]
}

/// A fresh, initialised database `t_<random>` (never dropped: the container is throwaway).
pub struct Case {
    pub url: String,
    pub db: Db,
}

impl Case {
    pub async fn new(admin: &url::Url) -> Case {
        let name = format!("t_{}", &Uuid::new_v4().simple().to_string()[..12]);
        let mut conn = PgConnection::connect(admin.as_str()).await.expect("connect as admin");
        conn.execute(sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))).await.expect("database");
        let mut url = admin.clone();
        url.set_path(&format!("/{name}"));
        let url = url.to_string();
        let mut db = Db::connect(&url).await.expect("connect");
        {
            let _init = INIT.lock().await;
            registry::init(&mut db, &policies()).await.expect("init");
        }
        Case { url, db }
    }

    pub async fn person(&mut self, sub: &str) {
        registry::upsert_person(&mut self.db, sub, sub, sub, false).await.expect("person");
        registry::set_policy(&mut self.db, sub, "residents").await.expect("policy");
        self.db.commit().await.expect("commit");
    }

    /// A certificate device of the person whose MAC window is current (seen just now).
    pub async fn resident_device(&mut self, owner: &str, mac: &str) -> Uuid {
        let id = registry::create_device(&mut self.db, owner, "phone", "apple", "residents").await.expect("device");
        sqlx::query(
            "INSERT INTO device_mac (device_id, mac, first_seen, last_seen, auth_count, randomized)
             VALUES ($1, $2::macaddr, now() - interval '1 hour', now(), 3, false)",
        )
        .bind(id)
        .bind(mac)
        .execute(self.db.tx().await.expect("tx"))
        .await
        .expect("window");
        self.db.commit().await.expect("commit");
        id
    }

    /// A home device (`iot::register`): its id and key.
    pub async fn iot_device(&mut self, owner: &str, name: &str, mac: Option<&str>, visibility: &str) -> (Uuid, String) {
        let (id, psk) = iot::register(&mut self.db, NewDevice { owner, name, class: "cast", mac, policy: "residents" })
            .await
            .expect("iot device");
        if visibility != "private" {
            iot::set_visibility(&mut self.db, id, visibility, owner).await.expect("visibility");
        }
        self.db.commit().await.expect("commit");
        (id, psk)
    }

    pub async fn share(&mut self, device: Uuid, grantee: &str, actor: &str) {
        iot::share(&mut self.db, device, grantee, actor).await.expect("share");
        self.db.commit().await.expect("commit");
    }

    pub async fn unshare(&mut self, device: Uuid, grantee: &str, actor: &str) {
        iot::unshare(&mut self.db, device, grantee, actor).await.expect("unshare");
        self.db.commit().await.expect("commit");
    }

    pub async fn revoke(&mut self, device: Uuid, actor: &str) {
        registry::revoke(&mut self.db, device, actor, "revoke").await.expect("revoke");
        self.db.commit().await.expect("commit");
    }

    pub async fn offboard(&mut self, sub: &str) {
        registry::offboard_person(&mut self.db, sub).await.expect("offboard");
        self.db.commit().await.expect("commit");
    }

    /// `(actor, action)` of the device's audit rows, oldest first.
    pub async fn audit(&mut self, device: Option<Uuid>) -> Vec<(String, String)> {
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT actor, action FROM audit WHERE ($1::uuid IS NULL AND device_id IS NULL) OR device_id = $1 ORDER BY id",
        )
        .bind(device)
        .fetch_all(self.db.tx().await.expect("tx"))
        .await
        .expect("audit");
        self.db.commit().await.expect("commit");
        rows
    }

    /// Every audit action by the actor `iot`, oldest first.
    pub async fn iot_audit(&mut self) -> Vec<String> {
        let rows: Vec<String> = sqlx::query_scalar("SELECT action FROM audit WHERE actor = 'iot' ORDER BY id")
            .fetch_all(self.db.tx().await.expect("tx"))
            .await
            .expect("audit");
        self.db.commit().await.expect("commit");
        rows
    }

    /// `{(target, key): (status, detail)}`.
    pub async fn sync(&mut self) -> BTreeMap<(String, String), (String, String)> {
        let rows = iot::sync_states(&mut self.db).await.expect("sync");
        self.db.commit().await.expect("commit");
        rows.into_iter().map(|r| ((r.target, r.key), (r.status, r.detail))).collect()
    }

    pub async fn sync_updated_max(&mut self) -> Option<time::OffsetDateTime> {
        let at: Option<time::OffsetDateTime> = sqlx::query_scalar("SELECT max(updated_at) FROM iot_sync")
            .fetch_one(self.db.tx().await.expect("tx"))
            .await
            .expect("max");
        self.db.commit().await.expect("commit");
        at
    }

    pub async fn job(&mut self) -> Option<registry::JobStatus> {
        let jobs = registry::job_status(&mut self.db).await.expect("jobs");
        self.db.commit().await.expect("commit");
        jobs.into_iter().find(|j| j.name == "iot")
    }

    pub async fn count(&mut self, sql: &str) -> i64 {
        let n: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_string()))
            .fetch_one(self.db.tx().await.expect("tx"))
            .await
            .expect(sql);
        self.db.commit().await.expect("commit");
        n
    }
}
