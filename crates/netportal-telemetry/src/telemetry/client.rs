//! Telemetry: the Prometheus client of the web (`telemetry/client.py`, INVENTORY 9.2.1).
//!
//! Instant and range queries over one HTTP client, cached, one fetch per query at a time (single
//! flight), a cool-down after Prometheus failed, and page budgets ([`Budget`]): every query of
//! one page shares one deadline ([`BUDGET_S`]); each gets what is left, at most the configured
//! timeout, and Prometheus is told to stop evaluating then too. The query text is never logged:
//! it holds MACs.
//!
//! Differences to the Python client (`docs/PARITY.md`, "Deliberate deviations"):
//!
//! - **The cool-down** ([`DOWN_LATCH_S`]) follows only evidence that Prometheus itself fails: a
//!   connection error, a 5xx, an unreadable answer, or a timeout of a request that had the full
//!   configured timeout. A page whose own budget is used up (or whose last request was cut short
//!   by it) fails alone; Python set the process-wide 15 s latch then too, so one heavy admin page
//!   made every resident's page "unavailable".
//! - **The cache** honours each caller's TTL: an answer counts for a caller while it is younger
//!   than that caller's TTL (Python: the first caller's TTL decided for everyone, e.g. the AP
//!   list's 15 s query got the AP map's 60 s answer). A full cache drops its oldest answers
//!   (Python: everything).
//! - **POST** (`application/x-www-form-urlencoded`, which Prometheus accepts for both endpoints)
//!   instead of GET: the house's admin list puts every live MAC into one `mac=~` regex, and a
//!   query string has a length limit (INVENTORY 9.14 #26). The answers are the same.
//! - A non-200 status is judged before the body (Python parsed the body first, so a proxy's
//!   HTML 404 counted as "Prometheus down").

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use serde_json::Value;
use tokio::sync::Notify;

use super::common::{BadQuery, Labels, number};

const LOG: &str = "netportal.telemetry";

/// Live values are cached this long (seconds).
pub const CACHE_SECONDS: f64 = 15.0;
/// The 24 h and 7 day summaries change slowly.
pub const SUMMARY_CACHE_SECONDS: f64 = 60.0;
/// 30 and 90 day charts: a new point every 2 or 6 hours.
pub const LONG_CACHE_SECONDS: f64 = 300.0;
pub const CACHE_MAX_ENTRIES: usize = 512;
/// All of a page's queries together (seconds).
pub const BUDGET_S: f64 = 5.0;
/// After Prometheus failed, uncached queries are not sent for this long (seconds).
pub const DOWN_LATCH_S: f64 = 15.0;
/// An answer larger than this is refused (a page holds at most a few thousand series; a
/// misbehaving or impersonated Prometheus must not fill the web's memory).
pub const MAX_ANSWER: usize = 16 * 1024 * 1024;
/// The shortest timeout a request gets.
const MIN_TIMEOUT_S: f64 = 0.05;

/// Prometheus did not answer usefully: down, slow, an error, an unexpected reply, or the page's
/// budget is used up. The text never holds the query.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("Prometheus unavailable: {0}")]
pub struct Unavailable(pub String);

impl From<BadQuery> for Unavailable {
    fn from(e: BadQuery) -> Self {
        Unavailable(format!("refused to ask: {e}"))
    }
}

/// `[(labels, value)]` of an instant query.
pub type Vector = Vec<(Labels, Option<f64>)>;
/// `[(labels, value, evaluation time)]` of an instant query.
pub type Samples = Vec<(Labels, Option<f64>, f64)>;
/// `[(labels, [(t, value)])]` of a range query or a subquery.
pub type Matrix = Vec<(Labels, Vec<(i64, Option<f64>)>)>;

/// A monotonic clock in seconds (tests use their own).
pub type Clock = Arc<dyn Fn() -> f64 + Send + Sync>;

/// Seconds since the first call, monotonic.
pub fn monotonic() -> Clock {
    let start = Instant::now();
    Arc::new(move || start.elapsed().as_secs_f64())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Kind {
    Vector,
    Samples,
    Matrix,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Key {
    path: &'static str,
    params: Vec<(&'static str, String)>,
    kind: Kind,
}

#[derive(Debug, Clone)]
enum Answer {
    Vector(Vector),
    Samples(Samples),
    Matrix(Matrix),
}

struct Cached {
    at: f64,
    answer: Answer,
}

#[derive(Default)]
struct State {
    cache: HashMap<Key, Cached>,
    inflight: HashMap<Key, Arc<Notify>>,
    down_until: f64,
}

struct Inner {
    url: String,
    timeout: f64,
    ssid: String,
    http: reqwest::Client,
    clock: Clock,
    state: Mutex<State>,
    ok: AtomicU64,
    errors: AtomicU64,
}

/// The web's Prometheus client: one per process (cheap to clone, shared state).
#[derive(Clone)]
pub struct Prometheus {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Prometheus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Prometheus").field("url", &self.inner.url).field("timeout", &self.inner.timeout).finish()
    }
}

impl Prometheus {
    /// A client of `url` (`NETPORTAL_PROMETHEUS_URL`; a trailing `/` is dropped) with a per-query
    /// `timeout` (`NETPORTAL_PROMETHEUS_TIMEOUT`); `ssid` is the house's EAP-TLS network (only its
    /// clients count).
    pub fn new(url: &str, timeout: Duration, ssid: &str) -> Result<Self, reqwest::Error> {
        Self::with_clock(url, timeout, ssid, monotonic())
    }

    /// [`Prometheus::new`] with a given monotonic clock (tests).
    pub fn with_clock(url: &str, timeout: Duration, ssid: &str, clock: Clock) -> Result<Self, reqwest::Error> {
        // no redirects: a query (it holds MACs) goes to NETPORTAL_PROMETHEUS_URL and nowhere else
        let http = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build()?;
        Ok(Prometheus {
            inner: Arc::new(Inner {
                url: url.trim_end_matches('/').to_string(),
                timeout: timeout.as_secs_f64(),
                ssid: ssid.to_string(),
                http,
                clock,
                state: Mutex::new(State::default()),
                ok: AtomicU64::new(0),
                errors: AtomicU64::new(0),
            }),
        })
    }

    /// One page's budget: every query made through it shares the deadline now + [`BUDGET_S`].
    pub fn within(&self) -> Budget {
        self.within_s(BUDGET_S)
    }

    pub fn within_s(&self, seconds: f64) -> Budget {
        Budget { client: self.clone(), deadline: self.now() + seconds }
    }

    pub fn ssid(&self) -> &str {
        &self.inner.ssid
    }

    pub fn url(&self) -> &str {
        &self.inner.url
    }

    /// `(ok, error)`: queries sent (not cache hits) since the start, for
    /// `netportal_telemetry_queries_total{result}` on `/metrics`.
    pub fn queries_total(&self) -> (u64, u64) {
        (self.inner.ok.load(Ordering::Relaxed), self.inner.errors.load(Ordering::Relaxed))
    }

    /// Forget every cached answer and the cool-down (tests, admin tools).
    pub fn reset(&self) {
        let mut st = self.state();
        st.cache.clear();
        st.down_until = 0.0;
    }

    /// The number of cached answers (tests).
    pub fn cached(&self) -> usize {
        self.state().cache.len()
    }

    fn now(&self) -> f64 {
        (self.inner.clock)()
    }

    fn state(&self) -> MutexGuard<'_, State> {
        // a panic while holding the lock leaves plain data: use it
        self.inner.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn time_left(&self, deadline: f64) -> f64 {
        self.inner.timeout.min(deadline - self.now()).max(MIN_TIMEOUT_S)
    }

    async fn get(
        &self,
        path: &'static str,
        params: Vec<(&'static str, String)>,
        kind: Kind,
        ttl: f64,
        deadline: f64,
    ) -> Result<Answer, Unavailable> {
        let key = Key { path, params, kind };
        let follow = {
            let mut st = self.state();
            let now = self.now();
            if let Some(hit) = lookup(&st, &key, now, ttl) {
                return Ok(hit);
            }
            if st.down_until > now {
                return Err(Unavailable(format!("failed less than {DOWN_LATCH_S} s ago")));
            }
            if now >= deadline {
                drop(st);
                // the page's own budget: no evidence about Prometheus, no cool-down
                return Err(self.failed("time budget used up", false));
            }
            match st.inflight.get(&key) {
                Some(flight) => Some(Arc::clone(flight)),
                None => {
                    st.inflight.insert(key.clone(), Arc::new(Notify::new()));
                    None
                }
            }
        };
        if let Some(flight) = follow {
            // the same query is on its way (another request): wait for its answer, not a second fetch
            let notified = flight.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let pending = self.state().inflight.get(&key).is_some_and(|f| Arc::ptr_eq(f, &flight));
            if pending {
                let left = Duration::from_secs_f64(self.time_left(deadline));
                let _ = tokio::time::timeout(left, notified).await;
            }
            let st = self.state();
            return lookup(&st, &key, self.now(), ttl)
                .ok_or_else(|| Unavailable("the same query failed or did not finish".into()));
        }
        let leader = Leader { client: self, key: &key };
        let result = self.fetch(&key, deadline).await;
        if let Ok(answer) = &result {
            let mut st = self.state();
            let now = self.now();
            if st.cache.len() >= CACHE_MAX_ENTRIES {
                evict(&mut st.cache, now);
            }
            st.cache.insert(key.clone(), Cached { at: now, answer: answer.clone() });
        }
        drop(leader);
        result
    }

    async fn fetch(&self, key: &Key, deadline: f64) -> Result<Answer, Unavailable> {
        let left = self.time_left(deadline);
        // cut short by the page's budget: a timeout then says nothing about Prometheus
        let cut = left < self.inner.timeout;
        let mut form: Vec<(&str, String)> = key.params.iter().map(|(k, v)| (*k, v.clone())).collect();
        form.push(("timeout", format!("{}s", left.ceil().max(1.0) as i64)));
        let url = format!("{}/api/v1/{}", self.inner.url, key.path);
        let sent = self.inner.http.post(&url).form(&form).timeout(Duration::from_secs_f64(left)).send().await;
        let mut resp = match sent {
            Ok(resp) => resp,
            Err(e) => return Err(self.request_failed(&e, cut)),
        };
        let status = resp.status().as_u16();
        if resp.content_length().is_some_and(|n| n > MAX_ANSWER as u64) {
            return Err(self.failed("answer too large", false));
        }
        let mut body = Vec::new();
        loop {
            match resp.chunk().await {
                Ok(Some(chunk)) if body.len() + chunk.len() > MAX_ANSWER => {
                    return Err(self.failed("answer too large", false));
                }
                Ok(Some(chunk)) => body.extend_from_slice(&chunk),
                Ok(None) => break,
                Err(e) => return Err(self.request_failed(&e, cut)),
            }
        }
        if status != 200 {
            // 4xx: this query is wrong (a bug here), Prometheus itself works; 5xx: it does not
            return Err(self.failed(&format!("HTTP {status}"), status >= 500));
        }
        let Ok(body) = serde_json::from_slice::<Value>(&body) else {
            return Err(self.failed("not JSON", true));
        };
        if body.get("status").and_then(Value::as_str) != Some("success") {
            return Err(self.failed("HTTP 200 without success", false));
        }
        let Some(answer) = body.get("data").and_then(|data| parse(key.kind, data)) else {
            return Err(self.failed("unexpected reply", false));
        };
        self.inner.ok.fetch_add(1, Ordering::Relaxed);
        Ok(answer)
    }

    fn request_failed(&self, e: &reqwest::Error, cut: bool) -> Unavailable {
        if e.is_timeout() && cut {
            return self.failed("timeout (the page's time budget)", false);
        }
        let why = if e.is_timeout() {
            "timeout"
        } else if e.is_connect() {
            "connection failed"
        } else {
            "request failed"
        };
        self.failed(why, true)
    }

    fn failed(&self, why: &str, down: bool) -> Unavailable {
        self.inner.errors.fetch_add(1, Ordering::Relaxed);
        // never the query: it holds MACs
        tracing::warn!(target: LOG, "Prometheus query failed: {why}");
        if down {
            let until = self.now() + DOWN_LATCH_S;
            self.state().down_until = until;
        }
        Unavailable(why.to_string())
    }
}

/// The single-flight leader's registration: removed (and the followers woken) however the fetch
/// ends, also when the request's future is dropped.
struct Leader<'a> {
    client: &'a Prometheus,
    key: &'a Key,
}

impl Drop for Leader<'_> {
    fn drop(&mut self) {
        let flight = self.client.state().inflight.remove(self.key);
        if let Some(flight) = flight {
            flight.notify_waiters();
        }
    }
}

fn lookup(st: &State, key: &Key, now: f64, ttl: f64) -> Option<Answer> {
    st.cache.get(key).filter(|c| now - c.at < ttl).map(|c| c.answer.clone())
}

/// Make room: answers older than the longest TTL go, then the oldest until a quarter is free.
fn evict(cache: &mut HashMap<Key, Cached>, now: f64) {
    cache.retain(|_, c| now - c.at < LONG_CACHE_SECONDS);
    if cache.len() >= CACHE_MAX_ENTRIES {
        let mut ages: Vec<f64> = cache.values().map(|c| c.at).collect();
        ages.sort_by(f64::total_cmp);
        let cut = ages[ages.len() / 4];
        cache.retain(|_, c| c.at > cut);
    }
}

fn labels(metric: &Value) -> Option<Labels> {
    metric.as_object()?.iter().map(|(k, v)| Some((k.clone(), v.as_str()?.to_string()))).collect()
}

fn sample_value(v: &Value) -> Option<Option<f64>> {
    match v {
        Value::String(s) => Some(number(s)),
        Value::Number(n) => Some(n.as_f64().and_then(netportal_core::conventions::finite)),
        _ => None,
    }
}

fn time_value(v: &Value) -> Option<f64> {
    let t = match v {
        Value::String(s) => s.trim().parse::<f64>().ok()?,
        Value::Number(n) => n.as_f64()?,
        _ => return None,
    };
    t.is_finite().then_some(t)
}

/// The answer of a `data` object, `None` for anything unexpected (labels that are not strings,
/// a value that is not a pair, the wrong result type).
fn parse(kind: Kind, data: &Value) -> Option<Answer> {
    let result_type = data.get("resultType")?.as_str()?;
    let result = data.get("result")?.as_array()?;
    match kind {
        Kind::Vector | Kind::Samples => {
            if result_type != "vector" {
                return None;
            }
            let mut rows = Vec::with_capacity(result.len());
            for r in result {
                let metric = labels(r.get("metric")?)?;
                let pair = r.get("value")?.as_array().filter(|p| p.len() == 2)?;
                rows.push((metric, sample_value(&pair[1])?, time_value(&pair[0])?));
            }
            Some(if kind == Kind::Vector {
                Answer::Vector(rows.into_iter().map(|(l, v, _)| (l, v)).collect())
            } else {
                Answer::Samples(rows)
            })
        }
        Kind::Matrix => {
            if result_type != "matrix" {
                return None;
            }
            let mut rows = Vec::with_capacity(result.len());
            for r in result {
                let metric = labels(r.get("metric")?)?;
                let mut points = Vec::new();
                for p in r.get("values")?.as_array()? {
                    let pair = p.as_array().filter(|p| p.len() == 2)?;
                    let t = time_value(&pair[0])?.round();
                    points.push((t as i64, sample_value(&pair[1])?));
                }
                rows.push((metric, points));
            }
            Some(Answer::Matrix(rows))
        }
    }
}

fn int_param(v: i64) -> String {
    v.to_string()
}

/// A Prometheus client whose queries share one deadline (one page's worth). The web makes one
/// per page view and hands it to every telemetry function of that page (the device page: the
/// live status and the history together).
#[derive(Clone, Debug)]
pub struct Budget {
    client: Prometheus,
    deadline: f64,
}

impl Budget {
    pub fn ssid(&self) -> &str {
        self.client.ssid()
    }

    pub fn client(&self) -> &Prometheus {
        &self.client
    }

    /// The seconds left of the budget (negative: used up).
    pub fn left(&self) -> f64 {
        self.deadline - self.client.now()
    }

    /// `[(labels, value)]` of an instant query (at `at`, else now).
    pub async fn vector(&self, promql: &str, at: Option<i64>, ttl: f64) -> Result<Vector, Unavailable> {
        match self.instant(promql, at, Kind::Vector, ttl).await? {
            Answer::Vector(v) => Ok(v),
            _ => Err(Unavailable("unexpected reply".into())),
        }
    }

    /// `[(labels, value, evaluation time)]` of an instant query.
    pub async fn samples(&self, promql: &str, at: Option<i64>, ttl: f64) -> Result<Samples, Unavailable> {
        match self.instant(promql, at, Kind::Samples, ttl).await? {
            Answer::Samples(v) => Ok(v),
            _ => Err(Unavailable("unexpected reply".into())),
        }
    }

    /// `[(labels, [(t, value)])]` of an instant query of a range (a subquery).
    pub async fn matrix(&self, promql: &str, at: Option<i64>, ttl: f64) -> Result<Matrix, Unavailable> {
        match self.instant(promql, at, Kind::Matrix, ttl).await? {
            Answer::Matrix(v) => Ok(v),
            _ => Err(Unavailable("unexpected reply".into())),
        }
    }

    /// `[(labels, [(t, value)])]` of a range query.
    pub async fn range(&self, promql: &str, start: i64, end: i64, step: i64, ttl: f64) -> Result<Matrix, Unavailable> {
        let params = vec![
            ("query", promql.to_string()),
            ("start", int_param(start)),
            ("end", int_param(end)),
            ("step", int_param(step)),
        ];
        match self.client.get("query_range", params, Kind::Matrix, ttl, self.deadline).await? {
            Answer::Matrix(v) => Ok(v),
            _ => Err(Unavailable("unexpected reply".into())),
        }
    }

    async fn instant(&self, promql: &str, at: Option<i64>, kind: Kind, ttl: f64) -> Result<Answer, Unavailable> {
        let mut params = vec![("query", promql.to_string())];
        if let Some(at) = at {
            params.push(("time", int_param(at)));
        }
        self.client.get("query", params, kind, ttl, self.deadline).await
    }
}
