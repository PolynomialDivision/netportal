//! The collector's Prometheus and Loki clients (Python `collect/sources.py`, INVENTORY 9.2.2,
//! 9.4).
//!
//! Not the web's Prometheus client (`netportal-telemetry`): that one is built for page views (a
//! cache, a down latch, the dashboard's query counter). The collector runs on a schedule and
//! wants the opposite: no cache, every failure returned (the job records it), and one time
//! budget per job run so a slow source cannot hold the scheduler. Queries never carry anything
//! but validated MACs and quoted strings, and no error text carries a query or a URL with one
//! (they hold MACs, INVENTORY 4.9).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;
use tokio::time::Instant;

/// Prometheus or Loki did not answer usefully (not configured, down, slow, an error, an
/// unexpected reply). The text never holds the query.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct SourceError(pub String);

fn fail<T>(text: impl Into<String>) -> Result<T, SourceError> {
    Err(SourceError(text.into()))
}

/// A series' labels.
pub type Labels = BTreeMap<String, String>;

/// One series of a range query: its labels and `{unix second: value}` (NaN and infinities, "no
/// data", are left out).
pub type Points = BTreeMap<i64, f64>;

/// `aa:bb:cc:dd:ee:ff` or `None` (the registry's one normaliser).
pub fn normalise_mac(raw: &str) -> Option<String> {
    netportal_core::registry::normalise_mac(raw)
}

/// The normalised MAC of a JSON value (a string), else `None`.
pub fn mac_of(value: Option<&Value>) -> Option<String> {
    value.and_then(Value::as_str).and_then(normalise_mac)
}

fn is_normalised_mac(mac: &str) -> bool {
    normalise_mac(mac).as_deref() == Some(mac)
}

/// `mac="…"` or `mac=~"a|b"` for normalised MACs (sorted, without repeats); anything else is
/// refused, so nothing but MACs reaches the query.
pub fn mac_matcher<S: AsRef<str>>(macs: &[S]) -> Result<String, SourceError> {
    let mut list: Vec<&str> = macs.iter().map(AsRef::as_ref).collect();
    list.sort_unstable();
    list.dedup();
    if list.is_empty() || !list.iter().all(|m| is_normalised_mac(m)) {
        return fail("only normalised MACs go into a query");
    }
    Ok(match list.as_slice() {
        [one] => format!("mac=\"{one}\""),
        many => format!("mac=~\"{}\"", many.join("|")),
    })
}

/// A PromQL string literal of plain text (control characters refused).
pub fn promql_string(text: &str) -> Result<String, SourceError> {
    if text.chars().any(|c| (c as u32) < 32 || c as u32 == 127) {
        return fail("not a plain string");
    }
    Ok(format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\"")))
}

/// A sample value; NaN and infinities (no data) and anything unparsable are `None`.
pub fn number(text: &str) -> Option<f64> {
    text.trim().parse::<f64>().ok().filter(|v| v.is_finite())
}

/// One deadline for all the requests of a job run.
#[derive(Debug)]
pub struct Budget {
    deadline: Instant,
}

/// Below this much time left no request is started.
const BUDGET_FLOOR: Duration = Duration::from_millis(50);

impl Budget {
    pub fn new(total: Duration) -> Budget {
        Budget { deadline: Instant::now() + total }
    }

    /// The time a request may take now: `cap`, or what is left of the budget when that is less;
    /// an error when (almost) nothing is left.
    pub fn left(&self, cap: Duration) -> Result<Duration, SourceError> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left <= BUDGET_FLOOR {
            return fail("time budget used up");
        }
        Ok(cap.min(left))
    }
}

/// Why a request failed, without the URL (it holds the query).
fn request_error(path: &str, error: &reqwest::Error) -> SourceError {
    let why = if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connection failed"
    } else if error.is_decode() || error.is_body() {
        "reply not readable"
    } else {
        "request failed"
    };
    SourceError(format!("{path} {why}"))
}

#[derive(Deserialize)]
struct Reply {
    status: Option<String>,
    data: Option<Value>,
}

/// An answer larger than this fails the request (a Loki page or a day of Prometheus samples
/// is a few MiB at most; a misbehaving source must not fill the collector's memory).
pub const MAX_ANSWER: usize = 64 * 1024 * 1024;

/// The shared HTTP part: one GET, status and envelope checked, `data` returned.
#[derive(Clone)]
struct Http {
    client: reqwest::Client,
    url: String,
    timeout: Duration,
    budget: Arc<Budget>,
}

impl Http {
    async fn get(&self, path: &str, params: &[(&str, String)], timeout: Duration) -> Result<Value, SourceError> {
        let mut response = self
            .client
            .get(format!("{}{path}", self.url))
            .query(params)
            .timeout(timeout)
            .send()
            .await
            .map_err(|e| request_error(path, &e))?;
        let status = response.status();
        if status != reqwest::StatusCode::OK {
            return fail(format!("{path} HTTP {}", status.as_u16()));
        }
        if response.content_length().is_some_and(|n| n > MAX_ANSWER as u64) {
            return fail(format!("{path} reply too large"));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|e| request_error(path, &e))? {
            if body.len() + chunk.len() > MAX_ANSWER {
                return fail(format!("{path} reply too large"));
            }
            body.extend_from_slice(&chunk);
        }
        let Ok(reply) = serde_json::from_slice::<Reply>(&body) else {
            return fail(format!("{path} reply is not JSON"));
        };
        if reply.status.as_deref() != Some("success") {
            return fail(format!("{path} HTTP {} without success", status.as_u16()));
        }
        match reply.data {
            Some(data @ Value::Object(_)) => Ok(data),
            _ => fail(format!("{path} unexpected reply")),
        }
    }
}

/// Instant and range queries of the collector.
#[derive(Clone)]
pub struct Prometheus {
    http: Http,
}

#[derive(Deserialize)]
struct VectorData {
    #[serde(rename = "resultType")]
    result_type: String,
    result: Vec<VectorSample>,
}

#[derive(Deserialize)]
struct VectorSample {
    #[serde(default)]
    metric: Labels,
    value: (Value, String),
}

#[derive(Deserialize)]
struct MatrixData {
    #[serde(rename = "resultType")]
    result_type: String,
    result: Vec<MatrixSeries>,
}

#[derive(Deserialize)]
struct MatrixSeries {
    #[serde(default)]
    metric: Labels,
    values: Vec<(Value, String)>,
}

/// A Prometheus timestamp (a JSON number of seconds, possibly fractional) as whole seconds.
fn seconds_of(value: &Value) -> Option<i64> {
    let t = value.as_f64().or_else(|| value.as_str().and_then(|s| s.parse().ok()))?;
    netportal_core::conventions::round_int(t)
}

impl Prometheus {
    /// A client for `url` (`http(s)://host:port`); every request at most `timeout` and within
    /// `budget`.
    pub fn new(client: reqwest::Client, url: &str, timeout: Duration, budget: Arc<Budget>) -> Prometheus {
        Prometheus { http: Http { client, url: url.trim_end_matches('/').to_string(), timeout, budget } }
    }

    async fn query(&self, path: &str, mut params: Vec<(&str, String)>) -> Result<Value, SourceError> {
        let timeout = self.http.budget.left(self.http.timeout)?;
        // Prometheus stops evaluating too (whole seconds, at least 1)
        params.push(("timeout", format!("{}s", timeout.as_secs_f64().ceil().max(1.0) as u64)));
        self.http.get(path, &params, timeout).await
    }

    /// `[(labels, value)]` of an instant query at Unix time `at` (`None`: now); NaN and
    /// infinities are `None`.
    pub async fn vector(&self, promql: &str, at: Option<i64>) -> Result<Vec<(Labels, Option<f64>)>, SourceError> {
        let mut params = vec![("query", promql.to_string())];
        if let Some(at) = at {
            params.push(("time", at.to_string()));
        }
        let data = self.query("/api/v1/query", params).await?;
        let Ok(data) = serde_json::from_value::<VectorData>(data) else {
            return fail("/api/v1/query unexpected reply");
        };
        if data.result_type != "vector" {
            return fail("/api/v1/query unexpected reply");
        }
        Ok(data.result.into_iter().map(|s| (s.metric, number(&s.value.1))).collect())
    }

    /// `[(labels, {t: value})]` of a range query over `[start, end]` at `step` seconds (t whole
    /// Unix seconds; NaN and infinities left out).
    pub async fn range(
        &self,
        promql: &str,
        start: i64,
        end: i64,
        step: i64,
    ) -> Result<Vec<(Labels, Points)>, SourceError> {
        let params = vec![
            ("query", promql.to_string()),
            ("start", start.to_string()),
            ("end", end.to_string()),
            ("step", step.to_string()),
        ];
        let data = self.query("/api/v1/query_range", params).await?;
        let Ok(data) = serde_json::from_value::<MatrixData>(data) else {
            return fail("/api/v1/query_range unexpected reply");
        };
        if data.result_type != "matrix" {
            return fail("/api/v1/query_range unexpected reply");
        }
        let mut out = Vec::with_capacity(data.result.len());
        for series in data.result {
            let mut points = Points::new();
            for (t, v) in &series.values {
                let Some(t) = seconds_of(t) else {
                    return fail("/api/v1/query_range unexpected reply");
                };
                if let Some(v) = number(v) {
                    points.insert(t, v);
                }
            }
            out.push((series.metric, points));
        }
        Ok(out)
    }
}

/// Which end of a time range Loki reads from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Forward,
    Backward,
}

/// One log line: its time (ns), the line, its stream's labels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub ts_ns: i64,
    pub line: String,
    pub labels: Labels,
}

/// `query_range` over log streams.
#[derive(Clone)]
pub struct Loki {
    http: Http,
}

#[derive(Deserialize)]
struct StreamsData {
    #[serde(rename = "resultType")]
    result_type: String,
    result: Vec<Stream>,
}

#[derive(Deserialize)]
struct Stream {
    #[serde(default)]
    stream: Option<Labels>,
    values: Vec<(Value, String)>,
}

fn nanos_of(value: &Value) -> Option<i64> {
    match value {
        Value::String(s) => s.parse().ok(),
        Value::Number(n) => n.as_i64(),
        _ => None,
    }
}

impl Loki {
    pub fn new(client: reqwest::Client, url: &str, timeout: Duration, budget: Arc<Budget>) -> Loki {
        Loki { http: Http { client, url: url.trim_end_matches('/').to_string(), timeout, budget } }
    }

    /// The entries in `[start_ns, end_ns)` (Loki's end is exclusive), at most `limit`, all
    /// streams merged and sorted by time (stable; newest first for [`Direction::Backward`]).
    pub async fn entries(
        &self,
        logql: &str,
        start_ns: i64,
        end_ns: i64,
        limit: usize,
        direction: Direction,
    ) -> Result<Vec<Entry>, SourceError> {
        let path = "/loki/api/v1/query_range";
        let params = vec![
            ("query", logql.to_string()),
            ("start", start_ns.to_string()),
            ("end", end_ns.to_string()),
            ("limit", limit.to_string()),
            ("direction", if direction == Direction::Forward { "forward" } else { "backward" }.to_string()),
        ];
        let timeout = self.http.budget.left(self.http.timeout)?;
        let data = self.http.get(path, &params, timeout).await?;
        let Ok(data) = serde_json::from_value::<StreamsData>(data) else {
            return fail(format!("{path} unexpected reply"));
        };
        if data.result_type != "streams" {
            return fail(format!("{path} unexpected reply"));
        }
        let mut out = Vec::new();
        for stream in data.result {
            let labels = stream.stream.unwrap_or_default();
            for (ts, line) in stream.values {
                let Some(ts_ns) = nanos_of(&ts) else {
                    return fail(format!("{path} unexpected reply"));
                };
                out.push(Entry { ts_ns, line, labels: labels.clone() });
            }
        }
        match direction {
            Direction::Forward => out.sort_by_key(|e| e.ts_ns),
            Direction::Backward => out.sort_by_key(|e| std::cmp::Reverse(e.ts_ns)),
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_matcher() {
        assert_eq!(mac_matcher(&["aa:bb:cc:dd:ee:ff"]).ok().as_deref(), Some("mac=\"aa:bb:cc:dd:ee:ff\""));
        assert_eq!(
            mac_matcher(&["aa:bb:cc:dd:ee:ff", "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"]).ok().as_deref(),
            Some("mac=~\"00:11:22:33:44:55|aa:bb:cc:dd:ee:ff\"")
        );
        let empty: [&str; 0] = [];
        assert!(mac_matcher(&empty).is_err());
        assert!(mac_matcher(&["AA:BB:CC:DD:EE:FF"]).is_err());
        assert!(mac_matcher(&["aa:bb:cc:dd:ee:ff\"} or vector(1) #"]).is_err());
    }

    #[test]
    fn test_promql_string() {
        assert_eq!(promql_string("Scharni").ok().as_deref(), Some("\"Scharni\""));
        assert_eq!(promql_string(r#"a"b\c"#).ok().as_deref(), Some(r#""a\"b\\c""#));
        assert!(promql_string("a\nb").is_err());
        assert!(promql_string("a\u{7f}").is_err());
    }

    #[test]
    fn test_number() {
        assert_eq!(number("1.5"), Some(1.5));
        assert_eq!(number("NaN"), None);
        assert_eq!(number("+Inf"), None);
        assert_eq!(number("-Inf"), None);
        assert_eq!(number("x"), None);
        assert_eq!(seconds_of(&serde_json::json!(1792929600.4)), Some(1792929600));
        assert_eq!(seconds_of(&serde_json::json!("x")), None);
    }

    #[tokio::test]
    async fn test_budget() {
        let budget = Budget::new(Duration::from_secs(10));
        assert_eq!(budget.left(Duration::from_secs(2)), Ok(Duration::from_secs(2)));
        assert!(budget.left(Duration::from_secs(20)).is_ok_and(|d| d <= Duration::from_secs(10)));
        let spent = Budget::new(Duration::from_millis(10));
        assert_eq!(spent.left(Duration::from_secs(2)), Err(SourceError("time budget used up".into())));
    }
}
