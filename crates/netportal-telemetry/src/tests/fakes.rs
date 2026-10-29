//! The fakes of the ported tests (Python `tests/fakes/`, `tests/test_telemetry.py` FakeSession,
//! `tests/test_telemetry_registry.py` FakeRegistry): a Prometheus HTTP API on 127.0.0.1 (a real
//! socket) answering canned JSON by query text, and an in-memory registry behind [`Store`].

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{RawQuery, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use indexmap::IndexMap;
use netportal_core::registry::{
    AcctSession, ApDay, AuthEvent, AuthFailure, ConnectionEvent, DeviceDay, DeviceRow, Incident, JobStatus,
    LatestEvent, LatestSession, MacWindow, Person, RegistryError, WindowConflict,
};
use serde_json::{Value, json};
use sqlx::types::Json;
use time::{Date, OffsetDateTime};
use tokio::sync::Semaphore;
use uuid::Uuid;

use crate::telemetry::Telemetry;
use crate::telemetry::client::{Clock, Prometheus};
use crate::telemetry::common::{moment, randomized, unix};
use crate::telemetry::identity::{CURRENT_WINDOW_S, WINDOW_GRACE_S};
use crate::telemetry::store::{Result, Store};

pub const NOW: f64 = 1_800_000_000.0;
pub const SSID: &str = "Example";
pub const MAC_A: &str = "02:00:00:00:00:0a";
pub const MAC_B: &str = "02:00:00:00:00:0b";

pub fn dt(t: f64) -> OffsetDateTime {
    moment(t)
}

/// A device id from a short name (`"a"` -> ...0a).
pub fn id(name: &str) -> Uuid {
    let n = name.bytes().fold(0u128, |acc, b| acc * 256 + u128::from(b));
    Uuid::from_u128(0x0000_0000_0000_4000_8000_0000_0000_0000 | n)
}

// --- the fake clock ------------------------------------------------------------------------------

/// A monotonic clock the tests move (seconds, from 1000).
#[derive(Clone)]
pub struct FakeClock(Arc<AtomicU64>);

impl FakeClock {
    pub fn new() -> Self {
        FakeClock(Arc::new(AtomicU64::new(1000f64.to_bits())))
    }

    pub fn now(&self) -> f64 {
        f64::from_bits(self.0.load(Ordering::SeqCst))
    }

    pub fn advance(&self, s: f64) {
        let t = self.now() + s;
        self.0.store(t.to_bits(), Ordering::SeqCst);
    }

    pub fn clock(&self) -> Clock {
        let me = self.clone();
        Arc::new(move || me.now())
    }
}

// --- the fake Prometheus -----------------------------------------------------------------------------

/// A canned answer (the `data` object of a success).
pub fn vector(rows: &[(Value, Value)]) -> Value {
    let result: Vec<Value> = rows.iter().map(|(m, v)| json!({"metric": m, "value": [NOW, text(v)]})).collect();
    json!({"resultType": "vector", "result": result})
}

pub fn matrix(rows: &[(Value, Vec<(f64, Value)>)]) -> Value {
    let result: Vec<Value> = rows
        .iter()
        .map(|(m, vals)| json!({"metric": m, "values": vals.iter().map(|(t, v)| json!([t, text(v)])).collect::<Vec<_>>()}))
        .collect();
    json!({"resultType": "matrix", "result": result})
}

/// A sample's text as Prometheus sends it (strings as they are, numbers as numbers print).
fn text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "NaN".into(),
        other => other.to_string(),
    }
}

#[derive(Default)]
pub struct PromState {
    pub handlers: Vec<(String, Value)>,
    /// `(path, params)` of every request
    pub calls: Vec<(String, BTreeMap<String, String>)>,
    /// answer every request with this status and body
    pub raw: Option<(u16, String)>,
    /// each answer takes this long on the client's clock
    pub delay_s: f64,
}

/// Prometheus's HTTP API over canned answers: each query gets the first handler whose text
/// occurs in it (`^text`: that it starts with; a vector handler is skipped for `query_range`),
/// an empty result if none.
#[derive(Clone)]
pub struct FakePrometheus {
    pub url: String,
    pub state: Arc<Mutex<PromState>>,
    pub clock: FakeClock,
    /// when set, every request waits for a permit (single-flight tests)
    pub gate: Arc<Mutex<Option<Arc<Semaphore>>>>,
}

#[derive(Clone)]
struct App {
    state: Arc<Mutex<PromState>>,
    clock: FakeClock,
    gate: Arc<Mutex<Option<Arc<Semaphore>>>>,
}

fn params(raw: &str) -> BTreeMap<String, String> {
    raw.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            let decode = |s: &str| percent(&s.replace('+', " "));
            (decode(k), decode(v))
        })
        .collect()
}

fn percent(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 3 <= bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok());
            if let Some(b) = hex {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

async fn answer(app: App, path: &str, query: Option<String>, body: Bytes) -> Response {
    let gate = app.gate.lock().map(|g| g.clone()).unwrap_or(None);
    if let Some(gate) = gate {
        let _permit = gate.acquire().await;
    }
    let mut p = params(query.as_deref().unwrap_or_default());
    p.extend(params(&String::from_utf8_lossy(&body)));
    let delay = app.state.lock().map(|s| s.delay_s).unwrap_or(0.0);
    app.clock.advance(delay);
    let mut st = app.state.lock().unwrap_or_else(|e| e.into_inner());
    st.calls.push((path.to_string(), p.clone()));
    if let Some((status, body)) = &st.raw {
        return (StatusCode::from_u16(*status).unwrap_or(StatusCode::OK), body.clone()).into_response();
    }
    let promql = p.get("query").cloned().unwrap_or_default();
    let is_range = path.ends_with("query_range");
    for (needle, data) in &st.handlers {
        if is_range && data.get("resultType").and_then(Value::as_str) != Some("matrix") {
            continue; // a live value's handler, not a chart's
        }
        let hit = match needle.strip_prefix('^') {
            Some(prefix) => promql.starts_with(prefix),
            None => promql.contains(needle.as_str()),
        };
        if hit {
            return axum::Json(json!({"status": "success", "data": data})).into_response();
        }
    }
    let subquery = regex::Regex::new(r":\d+[smhd]\]$").map(|r| r.is_match(&promql)).unwrap_or(false);
    let kind = if is_range || subquery { "matrix" } else { "vector" };
    axum::Json(json!({"status": "success", "data": {"resultType": kind, "result": []}})).into_response()
}

impl FakePrometheus {
    pub async fn start(handlers: Vec<(String, Value)>) -> Self {
        let state = Arc::new(Mutex::new(PromState { handlers, ..PromState::default() }));
        let clock = FakeClock::new();
        let gate = Arc::new(Mutex::new(None));
        let app = App { state: state.clone(), clock: clock.clone(), gate: gate.clone() };
        let router = Router::new()
            .route(
                "/api/v1/query",
                axum::routing::any(|State(app): State<App>, RawQuery(q): RawQuery, body: Bytes| async move {
                    answer(app, "/api/v1/query", q, body).await
                }),
            )
            .route(
                "/api/v1/query_range",
                axum::routing::any(|State(app): State<App>, RawQuery(q): RawQuery, body: Bytes| async move {
                    answer(app, "/api/v1/query_range", q, body).await
                }),
            )
            .with_state(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let url = format!("http://{}", listener.local_addr().expect("addr"));
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        FakePrometheus { url, state, clock, gate }
    }

    pub fn client(&self) -> Prometheus {
        Prometheus::with_clock(&self.url, Duration::from_secs(4), SSID, self.clock.clock()).expect("client")
    }

    pub fn telemetry(&self) -> Telemetry {
        Telemetry::with_clock(Some(self.client()), SSID, self.clock.clock())
    }

    pub fn calls(&self) -> Vec<(String, BTreeMap<String, String>)> {
        self.state.lock().map(|s| s.calls.clone()).unwrap_or_default()
    }

    /// The query texts asked that contain `needle`.
    pub fn queries(&self, needle: &str) -> Vec<String> {
        self.calls().into_iter().filter_map(|(_, p)| p.get("query").cloned()).filter(|q| q.contains(needle)).collect()
    }

    pub fn ranges(&self) -> Vec<BTreeMap<String, String>> {
        self.calls().into_iter().filter(|(path, _)| path.ends_with("query_range")).map(|(_, p)| p).collect()
    }

    pub fn set_handlers(&self, handlers: Vec<(String, Value)>) {
        if let Ok(mut s) = self.state.lock() {
            s.handlers = handlers;
        }
    }

    pub fn edit(&self, f: impl FnOnce(&mut PromState)) {
        if let Ok(mut s) = self.state.lock() {
            f(&mut s);
        }
    }
}

/// A Prometheus URL where nothing listens (connection refused).
pub async fn refused_url() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("addr"));
    drop(listener);
    url
}

/// A client of a Prometheus that refuses connections, and its clock.
pub async fn down_client() -> (Prometheus, FakeClock) {
    let clock = FakeClock::new();
    let client =
        Prometheus::with_clock(&refused_url().await, Duration::from_secs(4), SSID, clock.clock()).expect("client");
    (client, clock)
}

pub fn h(needle: &str, data: Value) -> (String, Value) {
    (needle.to_string(), data)
}

/// Python's HOUSE_OK.
pub fn house_ok() -> Vec<(String, Value)> {
    vec![
        h(
            "max by (job, role) (probe_success",
            vector(&[
                (json!({"job": "blackbox_icmp", "role": "gateway"}), json!(1)),
                (json!({"job": "blackbox_icmp", "role": "internet"}), json!(1)),
                (json!({"job": "blackbox_dns", "role": "gateway"}), json!(1)),
            ]),
        ),
        h(
            "network_internet_packet_loss_ratio_5m|",
            vector(&[
                (json!({"__name__": "network_internet_packet_loss_ratio_5m"}), json!(0)),
                (json!({"__name__": "network_internet_rtt_ms"}), json!(5.04)),
            ]),
        ),
        h(
            "{job=\"speedtest\",__name__",
            vector(&[
                (
                    json!({"__name__": "speedtest_tracker_download_bits", "server_id": "1", "status": "completed"}),
                    json!(236752744),
                ),
                (
                    json!({"__name__": "speedtest_tracker_upload_bits", "server_id": "1", "status": "completed"}),
                    json!(86375664),
                ),
                (json!({"__name__": "speedtest_tracker_ping_ms", "server_id": "1", "status": "completed"}), json!(4.2)),
                (
                    json!({"__name__": "speedtest_tracker_result_id", "server_id": "1", "status": "completed"}),
                    json!(126),
                ),
            ]),
        ),
        h(
            "max(speedtest_tracker_result_id",
            matrix(&[(
                json!({}),
                vec![(NOW - 180.0, json!(125)), (NOW - 120.0, json!(126)), (NOW - 60.0, json!(126))],
            )]),
        ),
        h("time() - timestamp(unpoller_prometheus_cache_age_seconds", vector(&[(json!({}), json!(42.5))])),
    ]
}

/// Python's `live(macs_present)`: MAC_A online on ap-scharni-2-corner (5 GHz), MAC_B seen 2 hours
/// ago, nothing about others.
pub fn live(a_present: bool) -> Vec<(String, Value)> {
    let start_a = NOW - 3600.0;
    let mut out = house_ok();
    let assoc = if a_present {
        vector(&[(
            json!({"mac": MAC_A, "ap_name": "ap-scharni-2-corner", "essid": "Scharni", "radio": "na", "channel": "56",
                   "radio_proto": "ax", "ip": "10.0.30.5"}),
            json!(start_a),
        )])
    } else {
        vector(&[])
    };
    let a = |v: Value| vector(&[(json!({"mac": MAC_A}), v)]);
    out.extend([
        h("^(timestamp(unpoller_client_uptime_seconds", assoc),
        h("max by (mac) (unpoller_client_radio_signal_db", a(json!(-58))),
        h("max by (mac) (unpoller_client_noise_db", a(json!(-96))),
        h("max by (mac) (wifi_client_snr_db", a(json!(38))),
        h("min by (mac) (wifi_client_health_score", a(json!(91.24))),
        h("max by (mac) (wifi_client_retry_ratio", a(json!(0.0312))),
        h("max by (mac) (wifi_client_channel_utilization_ratio", a(json!(0.2))),
        h("max by (mac) (unpoller_client_radio_transmit_rate_bps", a(json!(864000000))),
        h("max by (mac) (unpoller_client_radio_receive_rate_bps", a(json!(576000000))),
        h("rate(unpoller_client_transmit_bytes_total", a(json!(125000.4))),
        h("rate(unpoller_client_receive_bytes_total", a(json!(2500))),
        h(
            "increase(unpoller_client_transmit_bytes_total",
            vector(&[(json!({"mac": MAC_A}), json!(9e9)), (json!({"mac": MAC_B}), json!(1e6))]),
        ),
        h(
            "increase(unpoller_client_receive_bytes_total",
            vector(&[(json!({"mac": MAC_A}), json!(3e8)), (json!({"mac": MAC_B}), json!(2e5))]),
        ),
        h(
            "max by (mac, ap_name, radio)",
            matrix(&[
                (
                    json!({"mac": MAC_A, "ap_name": "ap-scharni-1-corner", "radio": "na"}),
                    vec![(NOW - 600.0, json!(3000))],
                ),
                (
                    json!({"mac": MAC_A, "ap_name": "ap-scharni-2-corner", "radio": "na"}),
                    vec![(NOW - 540.0, json!(3060)), (NOW - 60.0, json!(3540))],
                ),
            ]),
        ),
        h(
            "[24h:5m]",
            matrix(&[(
                json!({"mac": MAC_A}),
                vec![
                    (NOW - 7200.0, json!(NOW - 9000.0)),
                    (NOW - 6900.0, json!(NOW - 9010.0)),
                    (NOW - 3300.0, json!(start_a)),
                ],
            )]),
        ),
        h(
            "^max by (mac, radio)",
            vector(&[
                (json!({"mac": MAC_A, "radio": "na"}), json!(NOW - 60.0)),
                (json!({"mac": MAC_A, "radio": "ng"}), json!(NOW - 86400.0)),
                (json!({"mac": MAC_B, "radio": "ng"}), json!(NOW - 7200.0)),
            ]),
        ),
        h("wifi_attempts_transmit_total", a(json!(50))),
        h("max_over_time(timestamp(", vector(&[(json!({"mac": MAC_B}), json!(NOW - 7200.0))])),
    ]);
    out
}

/// A snapshot age handler (first, so it wins).
pub fn age(seconds: f64) -> (String, Value) {
    h("time() - timestamp(unpoller_prometheus_cache_age_seconds", vector(&[(json!({}), json!(seconds))]))
}

// --- the fake registry ----------------------------------------------------------------------------------

/// A `device_mac` row of the fake (window_end and current by the view's rule unless given).
#[derive(Debug, Clone)]
pub struct Win {
    pub mac: String,
    pub first_seen: f64,
    pub last_seen: f64,
    pub randomized: bool,
    pub auth_count: i32,
    pub current: Option<bool>,
    pub window_end: Option<f64>,
}

pub fn window(mac: &str, first: f64, last: f64) -> Win {
    Win {
        mac: mac.into(),
        first_seen: first,
        last_seen: last,
        randomized: randomized(mac),
        auth_count: 1,
        current: None,
        window_end: None,
    }
}

/// A conflict of the fake; `to` `None`: open (the registry caps it at its now).
#[derive(Debug, Clone)]
pub struct Clash {
    pub mac: String,
    pub other_owners: i64,
    pub from: f64,
    pub to: Option<f64>,
}

pub fn clash(mac: &str, owners: i64, from: f64, to: Option<f64>) -> Clash {
    Clash { mac: mac.into(), other_owners: owners, from, to }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Call {
    pub name: &'static str,
    pub since: Option<OffsetDateTime>,
    pub until: Option<OffsetDateTime>,
    pub limit: Option<i64>,
    pub days: Option<(Date, Date)>,
}

fn call(name: &'static str) -> Call {
    Call { name, since: None, until: None, limit: None, days: None }
}

/// The registry's telemetry reads over in-memory rows (keyed by device id); every call is
/// remembered.
#[derive(Default)]
pub struct FakeRegistry {
    pub now: f64,
    pub windows: HashMap<Uuid, Vec<Win>>,
    pub conflicts: HashMap<Uuid, Vec<Clash>>,
    pub auth: HashMap<Uuid, Vec<AuthEvent>>,
    /// sessions with their NAS's measured interval
    pub acct: HashMap<Uuid, Vec<(AcctSession, Option<i32>)>>,
    pub events: HashMap<Uuid, Vec<ConnectionEvent>>,
    pub days: HashMap<Uuid, Vec<DeviceDay>>,
    pub failures: Vec<AuthFailure>,
    pub incidents: Vec<Incident>,
    pub jobs: Vec<JobStatus>,
    pub ap_days: Vec<ApDay>,
    pub devices: Vec<DeviceRow>,
    pub people: IndexMap<String, Person>,
    /// functions that fail (a missing table)
    pub failing: Vec<&'static str>,
    pub calls: Vec<Call>,
}

impl FakeRegistry {
    pub fn new() -> Self {
        FakeRegistry { now: NOW, ..FakeRegistry::default() }
    }

    pub fn called(&self, name: &str) -> Vec<&Call> {
        self.calls.iter().filter(|c| c.name == name).collect()
    }

    fn check(&mut self, c: Call) -> Result<()> {
        let name = c.name;
        self.calls.push(c);
        if self.failing.contains(&name) {
            return Err(RegistryError::Invalid(format!("{name}: no table")));
        }
        Ok(())
    }

    /// The SQL view's rule: the MAC with the newest last_seen is current; its window ends at
    /// last_seen + CURRENT_WINDOW, capped at now (not before last_seen + WINDOW_GRACE); every
    /// other one at last_seen + WINDOW_GRACE.
    fn mac_windows(&self, rows: &[Win]) -> Vec<MacWindow> {
        let newest = rows.iter().map(|w| w.last_seen).fold(f64::NEG_INFINITY, f64::max);
        rows.iter()
            .map(|w| {
                let current = w.current.unwrap_or(w.last_seen == newest);
                let end = w.window_end.unwrap_or(if current {
                    (w.last_seen + CURRENT_WINDOW_S).min(self.now.max(w.last_seen + WINDOW_GRACE_S))
                } else {
                    w.last_seen + WINDOW_GRACE_S
                });
                MacWindow {
                    mac: w.mac.clone(),
                    first_seen: dt(w.first_seen),
                    last_seen: dt(w.last_seen),
                    window_end: dt(end),
                    current,
                    randomized: w.randomized,
                    auth_count: w.auth_count,
                }
            })
            .collect()
    }
}

fn within(t: OffsetDateTime, since: OffsetDateTime, until: OffsetDateTime) -> bool {
    since <= t && t <= until
}

fn take<T: Clone>(rows: impl Iterator<Item = T>, limit: i64) -> Vec<T> {
    rows.take(limit.max(0) as usize).collect()
}

impl Store for FakeRegistry {
    async fn device_windows(
        &mut self,
        ids: &[Uuid],
        since: Option<OffsetDateTime>,
        until: Option<OffsetDateTime>,
    ) -> Result<IndexMap<Uuid, Vec<MacWindow>>> {
        self.check(Call { since, until, ..call("device_windows") })?;
        Ok(ids
            .iter()
            .map(|i| {
                let rows = self.mac_windows(self.windows.get(i).map(Vec::as_slice).unwrap_or_default());
                let rows = rows
                    .into_iter()
                    .filter(|w| since.is_none_or(|s| w.window_end >= s) && until.is_none_or(|u| w.first_seen <= u))
                    .collect();
                (*i, rows)
            })
            .collect())
    }

    async fn window_conflicts(
        &mut self,
        ids: &[Uuid],
        since: Option<OffsetDateTime>,
        until: Option<OffsetDateTime>,
    ) -> Result<IndexMap<Uuid, Vec<WindowConflict>>> {
        self.check(Call { since, until, ..call("window_conflicts") })?;
        let now = self.now;
        Ok(ids
            .iter()
            .filter_map(|i| {
                let rows: Vec<WindowConflict> = self
                    .conflicts
                    .get(i)?
                    .iter()
                    .map(|c| WindowConflict {
                        mac: c.mac.clone(),
                        other_owners: c.other_owners,
                        from: dt(c.from),
                        to: dt(c.to.unwrap_or(now)),
                    })
                    .collect();
                Some((*i, rows))
            })
            .collect())
    }

    async fn auth_events(
        &mut self,
        device_id: Uuid,
        since: OffsetDateTime,
        until: OffsetDateTime,
        limit: i64,
    ) -> Result<Vec<AuthEvent>> {
        self.check(Call { since: Some(since), until: Some(until), limit: Some(limit), ..call("auth_events") })?;
        let rows = self.auth.get(&device_id).cloned().unwrap_or_default();
        Ok(take(rows.into_iter().filter(|r| within(r.at, since, until)), limit))
    }

    async fn auth_failures(
        &mut self,
        since: OffsetDateTime,
        until: Option<OffsetDateTime>,
        limit: i64,
    ) -> Result<Vec<AuthFailure>> {
        self.check(Call { since: Some(since), until, limit: Some(limit), ..call("auth_failures") })?;
        let until = until.unwrap_or(time::macros::datetime!(9999-01-01 00:00 UTC));
        Ok(take(self.failures.clone().into_iter().filter(|r| within(r.at, since, until)), limit))
    }

    async fn acct_sessions(
        &mut self,
        device_id: Uuid,
        since: OffsetDateTime,
        until: OffsetDateTime,
        limit: i64,
    ) -> Result<Vec<AcctSession>> {
        self.check(Call { since: Some(since), until: Some(until), limit: Some(limit), ..call("acct_sessions") })?;
        let rows = self.acct.get(&device_id).cloned().unwrap_or_default();
        Ok(take(rows.into_iter().map(|(r, _)| r).filter(|r| within(r.updated, since, until)), limit))
    }

    async fn latest_sessions(&mut self, ids: &[Uuid], per_device: i64) -> Result<IndexMap<Uuid, Vec<LatestSession>>> {
        self.check(call("latest_sessions"))?;
        Ok(ids
            .iter()
            .map(|i| {
                let mut rows = self.acct.get(i).cloned().unwrap_or_default();
                rows.sort_by_key(|(r, _)| std::cmp::Reverse(r.updated));
                let rows = take(rows.into_iter(), per_device)
                    .into_iter()
                    .map(|(r, nas)| LatestSession {
                        nas_ip: r.nas_ip,
                        acct_session_id: r.acct_session_id,
                        link: r.link,
                        mac: r.mac,
                        bssid: r.bssid,
                        ssid: r.ssid,
                        started: r.started,
                        updated: r.updated,
                        stopped: r.stopped,
                        terminate_cause: r.terminate_cause,
                        session_time_s: r.session_time_s,
                        interim_s: r.interim_s,
                        nas_interim_s: nas,
                    })
                    .collect();
                (*i, rows)
            })
            .collect())
    }

    async fn latest_connection_events(
        &mut self,
        ids: &[Uuid],
        per_device: i64,
        ssid: Option<&str>,
    ) -> Result<IndexMap<Uuid, Vec<LatestEvent>>> {
        self.check(call("latest_connection_events"))?;
        Ok(ids
            .iter()
            .map(|i| {
                let mut rows: Vec<ConnectionEvent> = self
                    .events
                    .get(i)
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|e| ["connected", "disconnected", "roamed"].contains(&e.kind.as_str()))
                    .filter(|e| ssid.is_none() || e.ssid.is_none() || e.ssid.as_deref() == ssid)
                    .collect();
                rows.sort_by_key(|e| std::cmp::Reverse(e.at));
                let rows = take(rows.into_iter(), per_device)
                    .into_iter()
                    .map(|e| LatestEvent { at: e.at, kind: e.kind, mac: e.mac, ap_mac: e.ap_mac, ap_name: e.ap_name })
                    .collect();
                (*i, rows)
            })
            .collect())
    }

    async fn connection_events(
        &mut self,
        device_id: Uuid,
        since: OffsetDateTime,
        until: OffsetDateTime,
        limit: i64,
    ) -> Result<Vec<ConnectionEvent>> {
        self.check(Call { since: Some(since), until: Some(until), limit: Some(limit), ..call("connection_events") })?;
        let rows = self.events.get(&device_id).cloned().unwrap_or_default();
        Ok(take(rows.into_iter().filter(|r| within(r.at, since, until)), limit))
    }

    async fn device_days(&mut self, device_id: Uuid, since_day: Date, until_day: Date) -> Result<Vec<DeviceDay>> {
        self.check(Call { days: Some((since_day, until_day)), ..call("device_days") })?;
        let rows = self.days.get(&device_id).cloned().unwrap_or_default();
        Ok(rows.into_iter().filter(|r| since_day <= r.day && r.day <= until_day).collect())
    }

    async fn ap_days(&mut self, since_day: Date, until_day: Date) -> Result<Vec<ApDay>> {
        self.check(Call { days: Some((since_day, until_day)), ..call("ap_days") })?;
        Ok(self.ap_days.iter().filter(|r| since_day <= r.day && r.day <= until_day).cloned().collect())
    }

    async fn incidents(
        &mut self,
        since: OffsetDateTime,
        until: Option<OffsetDateTime>,
        kinds: Option<&[&str]>,
    ) -> Result<Vec<Incident>> {
        self.check(Call { since: Some(since), until, ..call("incidents") })?;
        Ok(self
            .incidents
            .iter()
            .filter(|r| until.is_none_or(|u| r.started <= u) && r.ended.is_none_or(|e| e >= since))
            .filter(|r| kinds.is_none_or(|k| k.contains(&r.kind.as_str())))
            .cloned()
            .collect())
    }

    async fn job_status(&mut self) -> Result<Vec<JobStatus>> {
        self.check(call("job_status"))?;
        Ok(self.jobs.clone())
    }

    async fn devices(&mut self, include_revoked: bool) -> Result<Vec<DeviceRow>> {
        self.check(call("devices"))?;
        Ok(self.devices.iter().filter(|d| include_revoked || d.revoked_at.is_none()).cloned().collect())
    }

    async fn people(&mut self) -> Result<IndexMap<String, Person>> {
        self.check(call("people"))?;
        Ok(self.people.clone())
    }

    async fn rollback(&mut self) -> Result<()> {
        self.calls.push(call("rollback"));
        Ok(())
    }
}

// --- rows --------------------------------------------------------------------------------------------

/// Python's `row()` of test_telemetry_registry: enrolled 400 days ago, a certificate for 200 more.
pub fn row(name: &str) -> DeviceRow {
    DeviceRow {
        id: id(name),
        owner: "sub-resident".into(),
        name: format!("Phone {name}"),
        platform: "android".into(),
        policy: "residents".into(),
        created_at: dt(NOW - 400.0 * 86400.0),
        revoked_at: None,
        expires: Some(dt(NOW + 200.0 * 86400.0)),
        certificates: 1,
        last_seen: None,
        calling_station: None,
        first_seen: None,
    }
}

pub fn person(sub: &str, username: &str, display: &str) -> Person {
    Person { sub: sub.into(), username: username.into(), display_name: display.into() }
}

/// An accounting session (Python test_telemetry_v2 `acct`).
pub fn acct(
    started: Option<f64>,
    stopped: Option<f64>,
    bssid: &str,
    cause: Option<&str>,
    sid: &str,
    link: &str,
    mac: &str,
) -> AcctSession {
    let updated = stopped.or(started).unwrap_or(NOW);
    AcctSession {
        nas_ip: "10.0.10.27".into(),
        acct_session_id: sid.into(),
        link: link.into(),
        mac: Some(mac.into()),
        bssid: Some(bssid.into()),
        ssid: Some(SSID.into()),
        framed_ip: Some("10.30.0.5".into()),
        started: started.map(dt),
        updated: dt(updated),
        stopped: stopped.map(dt),
        session_time_s: match (started, stopped) {
            (Some(a), Some(b)) => Some((b - a) as i64),
            _ => None,
        },
        input_octets: Some(1000),
        output_octets: Some(9000),
        terminate_cause: cause.map(str::to_string),
        interim_s: None,
    }
}

/// A UniFi event (Python test_telemetry_v2 `unifi`).
#[allow(clippy::too_many_arguments)]
pub fn unifi(
    at: f64,
    kind: &str,
    ap: Option<&str>,
    ap_mac: Option<&str>,
    from_ap: Option<&str>,
    from_ap_mac: Option<&str>,
    mac: &str,
    radio: &str,
) -> ConnectionEvent {
    ConnectionEvent {
        at: dt(at),
        kind: kind.into(),
        source: "unifi_syslog".into(),
        mac: mac.into(),
        ap_mac: ap_mac.map(str::to_string),
        ap_name: ap.map(str::to_string),
        from_ap_mac: from_ap_mac.map(str::to_string),
        from_ap_name: from_ap.map(str::to_string),
        ssid: Some(SSID.into()),
        radio: Some(radio.into()),
        channel: Some(36),
        rssi: Some(-60),
        duration_s: None,
        rx_bytes: None,
        tx_bytes: None,
        detail: Json(json!({})),
    }
}

pub fn auth_event(at: f64, result: &str, reason: &str, mac: &str, matched: &str) -> AuthEvent {
    AuthEvent {
        at: dt(at),
        result: result.into(),
        reason: reason.into(),
        mac: Some(mac.into()),
        bssid: None,
        ssid: Some(SSID.into()),
        nas_ip: Some("10.0.10.27".into()),
        matched: matched.into(),
        tries: 1,
        last_at: None,
    }
}

pub fn failure(at: f64, reason: &str, device: Option<Uuid>, mac: Option<&str>) -> AuthFailure {
    AuthFailure {
        at: dt(at),
        reason: reason.into(),
        serial: device.map(|_| "ab".to_string()),
        device_id: device,
        owner: device.map(|_| "sub-resident".to_string()),
        owner_name: None,
        device_name: None,
        mac: mac.map(str::to_string),
        bssid: None,
        ssid: Some(SSID.into()),
        nas_ip: None,
        tries: 1,
        last_at: None,
    }
}

pub fn incident(id: i64, kind: &str, subject: &str, name: Option<&str>, started: f64, ended: Option<f64>) -> Incident {
    Incident {
        id,
        kind: kind.into(),
        subject: subject.into(),
        subject_name: name.map(str::to_string),
        started: dt(started),
        ended: ended.map(dt),
        basis: "measured".into(),
        detail: Json(json!({})),
    }
}

pub fn job(name: &str, success: Option<f64>, attempt: Option<f64>, error: Option<&str>, duration: f64) -> JobStatus {
    JobStatus {
        name: name.into(),
        last_success: success.map(dt),
        last_attempt: attempt.map(dt),
        last_error: error.map(str::to_string),
        duration_s: Some(duration),
        cursor: Json(json!({})),
    }
}

/// The Unix seconds of a registry time (tests).
pub fn t(at: OffsetDateTime) -> f64 {
    unix(at)
}
