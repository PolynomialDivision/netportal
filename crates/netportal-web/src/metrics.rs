//! `/metrics` (Python `netportal/metrics.py`, INVENTORY 10): counts only, no names, no devices.
//!
//! The families, types and labels are Python's (house-infra's alert rules and dashboards use
//! them). In-process counters: `netportal_enrolments_total{format}`,
//! `netportal_disconnects_total{result}` (the portal's own Disconnects), the always-0
//! `netportal_offboarded_devices_total` (kept: the offboarding sidecar has no endpoint, the
//! registry holds its facts) and `netportal_telemetry_queries_total{result}` (from the telemetry
//! client). Read from the registry at every scrape over a connection of the web's pool (a failure
//! shows as `netportal_registry_up 0`, the other gauges keep their last values): devices, certificates
//! (DEVICES per certificate state: a device in its renewal overlap counts once), the
//! Disconnects of the last hour of every process, the offboarding's last success and the jobs'
//! gauges (rebuilt each scrape; a job without an attempt has no `_up` and `_last_attempt`), the
//! Disconnect reconciliation's running totals (`netportal_disconnect_rechecks_total{result}`, a
//! counter kept in the job's cursor by the offboarding sidecar) and the live sessions of locked
//! devices (`netportal_locked_sessions_live{reason}`: still connected after the
//! reconciliation's tries, for the alert "a revoked device is still connected").
//!
//! Encoding: prometheus-client's OpenMetrics text when the scraper asks for it (`Accept:
//! application/openmetrics-text`, as Prometheus does), else the classic text format 0.0.4
//! (`text/plain`), derived from the same output (counter families named with `_total`, no
//! `# EOF`). Every label value of the fixed label sets exists from the start (0), so `rate()`
//! sees the first increase.

use std::sync::atomic::AtomicU64;
use std::time::Duration;

use std::sync::Mutex;

use netportal_core::Pool;
use netportal_core::registry::{self, DISCONNECT_RESULTS, LOCK_REASONS};
use netportal_offboard::recheck;
use netportal_telemetry::telemetry::Telemetry;
use prometheus_client::collector::Collector;
use prometheus_client::encoding::{DescriptorEncoder, EncodeMetric};
use prometheus_client::metrics::MetricType;
use prometheus_client::metrics::counter::{ConstCounter, Counter};
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;

const LOG: &str = "netportal.metrics";

type Labels = Vec<(&'static str, String)>;
type FloatGauge = Gauge<f64, AtomicU64>;

/// The enrolment formats (the downloads and the Let's Wi-Fi API).
pub const FORMATS: [&str; 5] = ["apple", "apple-mac", "android", "eap-config", "letswifi"];
const COUNTERS: [&str; 5] = [
    "netportal_enrolments",
    "netportal_disconnects",
    "netportal_offboarded_devices",
    "netportal_telemetry_queries",
    "netportal_disconnect_rechecks",
];
/// A scrape waits at most this long for the registry.
const DB_TIMEOUT: Duration = Duration::from_secs(5);

fn label(name: &'static str, value: &str) -> Labels {
    vec![(name, value.to_string())]
}

/// `netportal_telemetry_queries_total{result}` from the telemetry client at scrape time.
#[derive(Debug)]
struct TelemetryQueries(Option<netportal_telemetry::telemetry::client::Prometheus>);

impl Collector for TelemetryQueries {
    fn encode(&self, mut encoder: DescriptorEncoder) -> Result<(), std::fmt::Error> {
        let (ok, error) = self.0.as_ref().map(|p| p.queries_total()).unwrap_or((0, 0));
        let mut family = encoder.encode_descriptor(
            "netportal_telemetry_queries",
            "Prometheus queries of the device dashboard (not the cached answers), by result",
            None,
            MetricType::Counter,
        )?;
        for (result, n) in [("ok", ok), ("error", error)] {
            let labels = label("result", result);
            ConstCounter::new(n).encode(family.encode_family(&labels)?)?;
        }
        Ok(())
    }
}

/// `netportal_disconnect_rechecks_total{result}`: the reconciliation's totals as the registry
/// held them at the latest scrape (the job's cursor; every label from the start).
#[derive(Debug, Default)]
struct Rechecks(std::sync::Arc<Mutex<Vec<(&'static str, u64)>>>);

impl Collector for Rechecks {
    fn encode(&self, mut encoder: DescriptorEncoder) -> Result<(), std::fmt::Error> {
        let totals = self.0.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let mut family = encoder.encode_descriptor(
            "netportal_disconnect_rechecks",
            "Disconnect-Requests of the reconciliation (sessions still live after a lock) and sessions it settled, by result",
            None,
            MetricType::Counter,
        )?;
        for result in recheck::RESULTS {
            let n = totals.iter().find(|(r, _)| *r == result).map(|(_, n)| *n).unwrap_or(0);
            ConstCounter::new(n).encode(family.encode_family(&label("result", result))?)?;
        }
        Ok(())
    }
}

/// The portal's metrics (one per process).
pub struct Metrics {
    registry: Registry,
    enrolments: Family<Labels, Counter>,
    disconnects: Family<Labels, Counter>,
    offboarding_last: FloatGauge,
    disconnects_1h: Family<Labels, FloatGauge>,
    devices: Family<Labels, FloatGauge>,
    certificates: Family<Labels, FloatGauge>,
    up: FloatGauge,
    job_last_success: Family<Labels, FloatGauge>,
    job_last_attempt: Family<Labels, FloatGauge>,
    job_up: Family<Labels, FloatGauge>,
    job_duration: Family<Labels, FloatGauge>,
    rechecks: std::sync::Arc<Mutex<Vec<(&'static str, u64)>>>,
    locked_live: Family<Labels, FloatGauge>,
    /// `NETPORTAL_ACCT_INTERIM_S` (which sessions are live)
    interim_s: u32,
    /// one scrape at a time (the gauges are shared)
    scrape: tokio::sync::Mutex<()>,
}

impl Metrics {
    pub fn new(telemetry: &Telemetry, interim_s: u32) -> Metrics {
        let mut registry = Registry::default();
        let enrolments = Family::<Labels, Counter>::default();
        let disconnects = Family::<Labels, Counter>::default();
        let offboarded = Counter::<u64>::default();
        let offboarding_last = FloatGauge::default();
        let disconnects_1h = Family::<Labels, FloatGauge>::default();
        let devices = Family::<Labels, FloatGauge>::default();
        let certificates = Family::<Labels, FloatGauge>::default();
        let up = FloatGauge::default();
        let job_last_success = Family::<Labels, FloatGauge>::default();
        let job_last_attempt = Family::<Labels, FloatGauge>::default();
        let job_up = Family::<Labels, FloatGauge>::default();
        let job_duration = Family::<Labels, FloatGauge>::default();
        let rechecks = Rechecks::default();
        let recheck_totals = rechecks.0.clone();
        let locked_live = Family::<Labels, FloatGauge>::default();
        registry.register("netportal_enrolments", "Profiles and app enrolments handed out", enrolments.clone());
        registry.register(
            "netportal_disconnects",
            "Disconnect-Requests after a revocation, by result",
            disconnects.clone(),
        );
        registry.register(
            "netportal_offboarded_devices",
            "Devices revoked because the owner lost access (offboarding process)",
            offboarded,
        );
        registry.register(
            "netportal_offboarding_last_success_timestamp_seconds",
            "When the Authentik reconciliation last succeeded",
            offboarding_last.clone(),
        );
        registry.register(
            "netportal_disconnects_last_hour",
            "Disconnect-Requests of the last hour by result (portal and offboarding)",
            disconnects_1h.clone(),
        );
        registry.register("netportal_devices", "Devices by state", devices.clone());
        registry.register("netportal_certificates", "Devices by certificate state", certificates.clone());
        registry.register_collector(Box::new(TelemetryQueries(telemetry.prometheus().cloned())));
        registry.register("netportal_registry_up", "Registry reachable", up.clone());
        registry.register(
            "netportal_job_last_success_timestamp_seconds",
            "When the job last succeeded",
            job_last_success.clone(),
        );
        registry.register(
            "netportal_job_last_attempt_timestamp_seconds",
            "When the job last started",
            job_last_attempt.clone(),
        );
        registry.register("netportal_job_up", "Whether the job's last run succeeded", job_up.clone());
        registry.register("netportal_job_duration_seconds", "How long the job's last run took", job_duration.clone());
        registry.register_collector(Box::new(rechecks));
        registry.register(
            "netportal_locked_sessions_live",
            "Live accounting sessions of revoked or moved devices still connected after the reconciliation's tries, by reason",
            locked_live.clone(),
        );
        for reason in LOCK_REASONS {
            locked_live.get_or_create(&label("reason", reason)).set(0.0);
        }
        for format in FORMATS {
            let _ = enrolments.get_or_create(&label("format", format));
        }
        for result in DISCONNECT_RESULTS {
            let _ = disconnects.get_or_create(&label("result", result));
        }
        Metrics {
            registry,
            enrolments,
            disconnects,
            offboarding_last,
            disconnects_1h,
            devices,
            certificates,
            up,
            job_last_success,
            job_last_attempt,
            job_up,
            job_duration,
            rechecks: recheck_totals,
            locked_live,
            interim_s,
            scrape: tokio::sync::Mutex::new(()),
        }
    }

    /// One more enrolment of this format (`/enroll`, the first eap-config of a grant).
    pub fn enrolled(&self, format: &str) {
        self.enrolments.get_or_create(&label("format", format)).inc();
    }

    /// One more Disconnect-Request attempt of the portal with this result.
    pub fn disconnected(&self, result: &str) {
        self.disconnects.get_or_create(&label("result", result)).inc();
    }

    async fn read_registry(&self, pool: &Pool) -> bool {
        let read = async {
            let mut db = pool.acquire().await?;
            let stats = registry::stats(&mut db).await?;
            self.devices.get_or_create(&label("state", "active")).set(stats.active as f64);
            self.devices.get_or_create(&label("state", "revoked")).set(stats.revoked as f64);
            self.certificates.get_or_create(&label("state", "valid")).set(stats.valid_certificates as f64);
            self.certificates.get_or_create(&label("state", "expiring_30d")).set(stats.expiring_30d as f64);
            self.certificates.get_or_create(&label("state", "expired")).set(stats.expired as f64);
            if let Some(at) = stats.offboarding_last_success {
                self.offboarding_last.set(netportal_core::conventions::unix(at));
            }
            for (result, n) in &stats.disconnects_1h {
                self.disconnects_1h.get_or_create(&label("result", result)).set(*n as f64);
            }
            for (reason, n) in registry::locked_live_counts(&mut db, self.interim_s).await? {
                self.locked_live.get_or_create(&label("reason", reason)).set(n as f64);
            }
            let jobs = registry::job_status(&mut db).await;
            let _ = db.close().await;
            Ok::<_, registry::RegistryError>(jobs)
        };
        match tokio::time::timeout(DB_TIMEOUT, read).await {
            Ok(Ok(jobs)) => {
                for family in [&self.job_last_success, &self.job_last_attempt, &self.job_up, &self.job_duration] {
                    family.clear();
                }
                match jobs {
                    Ok(rows) => {
                        if let Some(row) = rows.iter().find(|r| r.name == recheck::JOB) {
                            let totals = recheck::RESULTS
                                .iter()
                                .map(|r| {
                                    let n = row.cursor.0.get("totals").and_then(|t| t.get(*r)).and_then(|v| v.as_u64());
                                    (*r, n.unwrap_or(0))
                                })
                                .collect();
                            *self.rechecks.lock().unwrap_or_else(|e| e.into_inner()) = totals;
                        }
                        for row in rows.iter().filter(|r| !r.name.is_empty()) {
                            let labels = label("job", &row.name);
                            if let Some(at) = row.last_success {
                                self.job_last_success.get_or_create(&labels).set(netportal_core::conventions::unix(at));
                            }
                            if let Some(at) = row.last_attempt {
                                self.job_last_attempt.get_or_create(&labels).set(netportal_core::conventions::unix(at));
                                let ok = row.last_error.is_none() && row.last_success.is_some();
                                self.job_up.get_or_create(&labels).set(if ok { 1.0 } else { 0.0 });
                            }
                            if let Some(d) = row.duration_s {
                                self.job_duration.get_or_create(&labels).set(d);
                            }
                        }
                    }
                    Err(e) => tracing::warn!(target: LOG, "job status unreadable: {}", kind(&e)),
                }
                true
            }
            Ok(Err(e)) => {
                tracing::warn!(target: LOG, "registry unreadable: {}", kind(&e));
                false
            }
            Err(_) => {
                tracing::warn!(target: LOG, "registry unreadable: timeout");
                false
            }
        }
    }

    /// The exposition: `(Content-Type, body)` for the request's `Accept`.
    pub async fn scrape(&self, pool: &Pool, accept: &str) -> (&'static str, String) {
        let _one = self.scrape.lock().await;
        let up = self.read_registry(pool).await;
        self.up.set(if up { 1.0 } else { 0.0 });
        let mut text = String::new();
        if prometheus_client::encoding::text::encode_registry(&mut text, &self.registry).is_err() {
            tracing::error!(target: LOG, "metrics not encodable");
        }
        if accept.to_ascii_lowercase().contains("application/openmetrics-text") {
            text.push_str("# EOF\n");
            ("application/openmetrics-text; version=1.0.0; charset=utf-8", text)
        } else {
            ("text/plain; version=0.0.4; charset=utf-8", classic(&text))
        }
    }
}

fn kind(e: &registry::RegistryError) -> String {
    match e {
        registry::RegistryError::Db(e) => crate::errors::db_kind(e),
        registry::RegistryError::Migrate(_) => "migration".into(),
        _ => "registry".into(),
    }
}

/// The classic text format from prometheus-client's OpenMetrics text: a counter family's
/// `# HELP` and `# TYPE` name it with `_total` (as its samples), no `# EOF`.
fn classic(openmetrics: &str) -> String {
    let mut out = String::with_capacity(openmetrics.len() + 128);
    for line in openmetrics.lines() {
        if line == "# EOF" {
            continue;
        }
        let renamed = ["# HELP ", "# TYPE "].iter().find_map(|prefix| {
            let rest = line.strip_prefix(prefix)?;
            let (name, tail) = rest.split_once(' ')?;
            COUNTERS.contains(&name).then(|| format!("{prefix}{name}_total {tail}"))
        });
        out.push_str(renamed.as_deref().unwrap_or(line));
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_families_without_a_registry() {
        let telemetry = Telemetry::new(None, "Example");
        let metrics = Metrics::new(&telemetry, 300);
        metrics.enrolled("apple");
        metrics.disconnected("no-session");
        let pool = Pool::new(
            "postgresql://nobody:x@127.0.0.1:1/none",
            &netportal_core::PoolSettings {
                size: 1,
                acquire_timeout: Duration::from_millis(300),
                statement_timeout: Duration::from_secs(1),
                lock_timeout: Duration::from_secs(1),
                idle_in_transaction_timeout: Duration::from_secs(1),
                application_name: "test".into(),
            },
        )
        .expect("pool");
        let (ctype, text) = metrics.scrape(&pool, "").await;
        assert_eq!(ctype, "text/plain; version=0.0.4; charset=utf-8");
        for line in [
            "# TYPE netportal_enrolments_total counter",
            "netportal_enrolments_total{format=\"apple\"} 1",
            "netportal_enrolments_total{format=\"letswifi\"} 0",
            "netportal_disconnects_total{result=\"no-session\"} 1",
            "netportal_disconnects_total{result=\"ack\"} 0",
            "# TYPE netportal_offboarded_devices_total counter",
            "netportal_offboarded_devices_total 0",
            "# TYPE netportal_telemetry_queries_total counter",
            "netportal_telemetry_queries_total{result=\"ok\"} 0",
            "netportal_telemetry_queries_total{result=\"error\"} 0",
            "# TYPE netportal_registry_up gauge",
            "netportal_registry_up 0.0",
            "# TYPE netportal_disconnect_rechecks_total counter",
            "netportal_disconnect_rechecks_total{result=\"ack\"} 0",
            "netportal_disconnect_rechecks_total{result=\"not_found\"} 0",
            "netportal_disconnect_rechecks_total{result=\"settled_stale\"} 0",
            "netportal_disconnect_rechecks_total{result=\"given_up\"} 0",
            "# TYPE netportal_locked_sessions_live gauge",
            "netportal_locked_sessions_live{reason=\"revoked\"} 0.0",
            "netportal_locked_sessions_live{reason=\"credential\"} 0.0",
            "netportal_locked_sessions_live{reason=\"vlan\"} 0.0",
        ] {
            assert!(text.lines().any(|l| l == line), "{line} missing in\n{text}");
        }
        assert!(!text.contains("# EOF"));
        let (ctype, text) = metrics.scrape(&pool, "application/openmetrics-text;version=1.0.0").await;
        assert!(ctype.starts_with("application/openmetrics-text"));
        assert!(text.ends_with("# EOF\n"));
        assert!(text.contains("# TYPE netportal_enrolments counter"));
    }
}
