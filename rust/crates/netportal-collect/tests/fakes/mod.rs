//! In-process fakes of the Prometheus and Loki HTTP APIs (Python tests/fakes/: real sockets on
//! 127.0.0.1, no Docker).
//!
//! - [`FakePrometheus`]: `/api/v1/query` and `/api/v1/query_range` from canned series per exact
//!   PromQL text; range answers only the points in `[start, end]` on the request's step grid, as
//!   Prometheus does; unknown queries answer an empty success; `fail` makes one query (or all)
//!   answer an error status.
//! - [`FakeLoki`]: `/loki/api/v1/query_range` over pushed lines: the stream selector
//!   (`{k="v", k=~"a|b", k!="v", k!~"re"}`; anything after it is ignored) picks the streams;
//!   entries in `[start, end)` sorted by direction, at most `limit`, grouped back into streams.
#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{RawQuery, State};
use axum::http::{StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

pub type Labels = BTreeMap<String, String>;
/// Range series as a test gives them (`None`: a NaN sample).
pub type Series = Vec<(Labels, BTreeMap<i64, Option<f64>>)>;

pub fn labels(pairs: &[(&str, &str)]) -> Labels {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

/// The requests a fake got: `(path, {param: value})`, in order.
pub type Requests = Arc<Mutex<Vec<(String, HashMap<String, String>)>>>;

fn params_of(query: Option<String>) -> HashMap<String, String> {
    url::form_urlencoded::parse(query.unwrap_or_default().as_bytes()).into_owned().collect()
}

async fn serve(router: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    format!("http://{address}")
}

fn text(v: Option<f64>) -> String {
    match v {
        None => "NaN".into(),
        Some(v) => format!("{v:?}"),
    }
}

fn reply(status: u16, body: Value) -> Response {
    (StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR), axum::Json(body)).into_response()
}

// --- Prometheus -----------------------------------------------------------------------------------

#[derive(Default)]
struct PromState {
    ranges: HashMap<String, Series>,
    vectors: HashMap<String, Vec<(Labels, Option<f64>)>>,
    /// `None`: every query
    failures: HashMap<Option<String>, u16>,
}

#[derive(Clone)]
pub struct FakePrometheus {
    pub url: String,
    state: Arc<Mutex<PromState>>,
    pub requests: Requests,
}

impl FakePrometheus {
    pub async fn start() -> FakePrometheus {
        let state = Arc::new(Mutex::new(PromState::default()));
        let requests: Requests = Arc::default();
        let shared = (state.clone(), requests.clone());
        let router = Router::new().fallback(prom_answer).with_state(shared);
        FakePrometheus { url: serve(router).await, state, requests }
    }

    pub fn range_series(&self, promql: &str, series: Series) {
        self.state.lock().expect("lock").ranges.insert(promql.to_string(), series);
    }

    pub fn vector(&self, promql: &str, series: Vec<(Labels, Option<f64>)>) {
        self.state.lock().expect("lock").vectors.insert(promql.to_string(), series);
    }

    pub fn fail(&self, promql: Option<&str>, status: u16) {
        self.state.lock().expect("lock").failures.insert(promql.map(str::to_string), status);
    }

    /// The PromQL texts asked (optionally of one path only).
    pub fn queries(&self, path: Option<&str>) -> Vec<String> {
        let requests = self.requests.lock().expect("lock");
        requests
            .iter()
            .filter(|(p, _)| path.is_none_or(|w| w == p))
            .filter_map(|(_, q)| q.get("query").cloned())
            .collect()
    }
}

/// `{t: Some(v)}` for every t of `points`.
pub fn pts(points: impl IntoIterator<Item = (i64, f64)>) -> BTreeMap<i64, Option<f64>> {
    points.into_iter().map(|(t, v)| (t, Some(v))).collect()
}

async fn prom_answer(
    State((state, requests)): State<(Arc<Mutex<PromState>>, Requests)>,
    uri: Uri,
    RawQuery(query): RawQuery,
) -> Response {
    let params = params_of(query);
    let path = uri.path().to_string();
    requests.lock().expect("lock").push((path.clone(), params.clone()));
    let state = state.lock().expect("lock");
    let promql = params.get("query").cloned().unwrap_or_default();
    if let Some(status) = state.failures.get(&Some(promql.clone())).or_else(|| state.failures.get(&None)) {
        return reply(*status, json!({"status": "error", "errorType": "fake", "error": "failing on purpose"}));
    }
    let num = |name: &str| params.get(name).and_then(|v| v.parse::<f64>().ok()).map(|v| v as i64);
    match path.as_str() {
        "/api/v1/query_range" => {
            let (Some(start), Some(end), Some(step)) = (num("start"), num("end"), num("step")) else {
                return reply(400, json!({"status": "error", "error": "bad range"}));
            };
            let mut result = Vec::new();
            for (labels, points) in state.ranges.get(&promql).into_iter().flatten() {
                let values: Vec<Value> = points
                    .iter()
                    .filter(|(t, _)| start <= **t && **t <= end && (**t - start) % step.max(1) == 0)
                    .map(|(t, v)| json!([t, text(*v)]))
                    .collect();
                if !values.is_empty() {
                    result.push(json!({"metric": labels, "values": values}));
                }
            }
            reply(200, json!({"status": "success", "data": {"resultType": "matrix", "result": result}}))
        }
        "/api/v1/query" => {
            let at = params.get("time").and_then(|v| v.parse::<f64>().ok()).unwrap_or(0.0);
            let result: Vec<Value> = state
                .vectors
                .get(&promql)
                .into_iter()
                .flatten()
                .map(|(labels, v)| json!({"metric": labels, "value": [at, text(*v)]}))
                .collect();
            reply(200, json!({"status": "success", "data": {"resultType": "vector", "result": result}}))
        }
        _ => reply(404, json!({"status": "error", "error": "unknown path"})),
    }
}

// --- Loki -------------------------------------------------------------------------------------------

#[derive(Default)]
struct LokiState {
    entries: Vec<(Labels, i64, String)>,
    status: Option<u16>,
}

#[derive(Clone)]
pub struct FakeLoki {
    pub url: String,
    state: Arc<Mutex<LokiState>>,
    pub requests: Requests,
}

impl FakeLoki {
    pub async fn start() -> FakeLoki {
        let state = Arc::new(Mutex::new(LokiState::default()));
        let requests: Requests = Arc::default();
        let router = Router::new().fallback(loki_answer).with_state((state.clone(), requests.clone()));
        FakeLoki { url: serve(router).await, state, requests }
    }

    pub fn push(&self, labels: &Labels, ts_ns: i64, line: &str) {
        self.state.lock().expect("lock").entries.push((labels.clone(), ts_ns, line.to_string()));
    }

    pub fn fail(&self, status: u16) {
        self.state.lock().expect("lock").status = Some(status);
    }

    pub fn request_count(&self) -> usize {
        self.requests.lock().expect("lock").len()
    }

    pub fn request(&self, index: usize) -> HashMap<String, String> {
        self.requests.lock().expect("lock")[index].1.clone()
    }

    pub fn last_request(&self) -> HashMap<String, String> {
        self.requests.lock().expect("lock").last().map(|r| r.1.clone()).unwrap_or_default()
    }
}

type Matcher = (String, String, String);

fn parse_selector(logql: &str) -> Option<Vec<Matcher>> {
    let inner = logql.trim().strip_prefix('{')?.split('}').next()?;
    let re = regex::Regex::new(r#"\s*([A-Za-z_][A-Za-z0-9_]*)\s*(=~|!=|!~|=)\s*"((?:[^"\\]|\\.)*)"\s*,?"#).ok()?;
    Some(re.captures_iter(inner).map(|c| (c[1].to_string(), c[2].to_string(), c[3].replace("\\\"", "\""))).collect())
}

fn matches(matchers: &[Matcher], labels: &Labels) -> bool {
    matchers.iter().all(|(key, op, value)| {
        let have = labels.get(key).map(String::as_str).unwrap_or("");
        let full = |v: &str| regex::Regex::new(&format!("^(?:{value})$")).is_ok_and(|r| r.is_match(v));
        match op.as_str() {
            "=" => have == value,
            "!=" => have != value,
            "=~" => full(have),
            _ => !full(have),
        }
    })
}

async fn loki_answer(
    State((state, requests)): State<(Arc<Mutex<LokiState>>, Requests)>,
    uri: Uri,
    RawQuery(query): RawQuery,
) -> Response {
    let params = params_of(query);
    requests.lock().expect("lock").push((uri.path().to_string(), params.clone()));
    let state = state.lock().expect("lock");
    if let Some(status) = state.status {
        return reply(status, json!({"status": "error", "error": "failing on purpose"}));
    }
    if uri.path() != "/loki/api/v1/query_range" {
        return reply(404, json!({"status": "error", "error": "unknown path"}));
    }
    let Some(matchers) = params.get("query").and_then(|q| parse_selector(q)) else {
        return reply(400, json!({"status": "error", "error": "no stream selector"}));
    };
    let num = |name: &str| params.get(name).and_then(|v| v.parse::<i64>().ok());
    let (Some(start), Some(end)) = (num("start"), num("end")) else {
        return reply(400, json!({"status": "error", "error": "bad range"}));
    };
    if end < start {
        return reply(400, json!({"status": "error", "error": "end before start"}));
    }
    let limit = num("limit").unwrap_or(100).max(0) as usize;
    let backward = params.get("direction").is_none_or(|d| d == "backward");
    let mut picked: Vec<&(Labels, i64, String)> =
        state.entries.iter().filter(|e| matches(&matchers, &e.0) && start <= e.1 && e.1 < end).collect();
    picked.sort_by_key(|e| if backward { -e.1 } else { e.1 });
    picked.truncate(limit);
    let mut streams: Vec<(Labels, Vec<Value>)> = Vec::new();
    for (labels, ts, line) in picked {
        match streams.iter_mut().find(|(l, _)| l == labels) {
            Some((_, values)) => values.push(json!([ts.to_string(), line])),
            None => streams.push((labels.clone(), vec![json!([ts.to_string(), line])])),
        }
    }
    let result: Vec<Value> = streams.into_iter().map(|(l, v)| json!({"stream": l, "values": v})).collect();
    reply(200, json!({"status": "success", "data": {"resultType": "streams", "result": result}}))
}
