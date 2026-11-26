//! Telemetry: the house status (`telemetry/house.py`, INVENTORY 9.1.4): the internet line, the
//! router, the house's DNS, the latest speed test, and how old the Wi-Fi data is (blackbox
//! probes, the house's recording rules, speedtest-tracker, unpoller's snapshot age):
//! `wifi_data_age_s` (seconds, at the query) and `wifi_data_at` (the snapshot's time, unpoller's
//! poll of the controller; stable until the next snapshot).

use std::collections::BTreeMap;

use indexmap::IndexMap;
use serde::Serialize;

use super::client::{Budget, CACHE_SECONDS, SUMMARY_CACHE_SECONDS, Unavailable};
use super::common::{Labels, fit, iso, label, trunc_int};

/// The internet counts as degraded above these: the house's InternetPacketLossHigh alert fires
/// at 5 % loss; the public resolvers normally answer in 5-20 ms, above 100 ms calls lag.
pub const DEGRADED_LOSS_RATIO: f64 = 0.05;
pub const DEGRADED_RTT_MS: f64 = 100.0;

/// T1: router (ICMP gateway), DNS (blackbox_dns gateway), internet (ICMP internet) up.
pub const PROBES: &str =
    r#"max by (job, role) (probe_success{job=~"blackbox_icmp|blackbox_dns",role=~"gateway|internet"})"#;
/// T2: the internet line's loss and round trip (house recording rules).
pub const LINE: &str = r#"{__name__=~"network_internet_packet_loss_ratio_5m|network_internet_rtt_ms"}"#;
/// T3: the Wi-Fi snapshot's age at the evaluation (scrape time - snapshot age = the snapshot).
pub const SNAPSHOT_AGE: &str = r#"max(unpoller_prometheus_cache_age_seconds{job="unifi"} + (time() - timestamp(unpoller_prometheus_cache_age_seconds{job="unifi"})))"#;
/// T4: the latest speed test (speedtest-tracker's gauges, the server as labels).
pub const SPEEDTEST: &str =
    r#"{job="speedtest",__name__=~"speedtest_tracker_(download_bits|upload_bits|ping_ms|result_id)"}"#;
/// T5: when the result id last changed (2 days at 1 min).
pub const SPEEDTEST_HISTORY: &str = r#"max(speedtest_tracker_result_id{job="speedtest"})[2d:1m]"#;

/// HOUSE (INVENTORY 9.12).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct House {
    /// `ok` / `degraded` / `down` / `unknown`
    pub internet: String,
    pub internet_loss_ratio: Option<f64>,
    pub internet_rtt_ms: Option<f64>,
    /// `ok` / `down` / `unknown`
    pub dns: String,
    pub router: String,
    pub speedtest: Option<Speedtest>,
    pub wifi_data_age_s: Option<i64>,
    pub wifi_data_at: Option<String>,
    /// `wifi_data_at` as Unix seconds (presence's Ts; not in the JSON)
    #[serde(skip)]
    pub snapshot_at: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Speedtest {
    pub download_bps: i64,
    pub upload_bps: Option<i64>,
    pub ping_ms: Option<f64>,
    pub at: Option<String>,
}

/// HOUSE with nothing known.
pub fn empty_house() -> House {
    House {
        internet: "unknown".into(),
        internet_loss_ratio: None,
        internet_rtt_ms: None,
        dns: "unknown".into(),
        router: "unknown".into(),
        speedtest: None,
        wifi_data_age_s: None,
        wifi_data_at: None,
        snapshot_at: None,
    }
}

fn up_state(value: Option<f64>) -> String {
    match value {
        None => "unknown",
        Some(v) if v >= 1.0 => "ok",
        Some(_) => "down",
    }
    .into()
}

/// HOUSE from Prometheus (T1-T5); [`Unavailable`] when it does not answer.
pub async fn house_status(client: &Budget) -> Result<House, Unavailable> {
    let mut house = empty_house();
    let probes: BTreeMap<(Option<String>, Option<String>), Option<f64>> = client
        .vector(PROBES, None, CACHE_SECONDS)
        .await?
        .into_iter()
        .map(|(m, v)| ((m.get("job").cloned(), m.get("role").cloned()), v))
        .collect();
    let probe = |job: &str, role: &str| probes.get(&(Some(job.to_string()), Some(role.to_string()))).copied().flatten();
    house.router = up_state(probe("blackbox_icmp", "gateway"));
    house.dns = up_state(probe("blackbox_dns", "gateway")); // OPNsense Unbound
    let mut line: BTreeMap<String, Option<f64>> = BTreeMap::new();
    for (m, v) in client.vector(LINE, None, CACHE_SECONDS).await? {
        if let Some(name) = label(&m, "__name__") {
            line.insert(name.to_string(), v); // several series per name: the last wins
        }
    }
    let loss = line.get("network_internet_packet_loss_ratio_5m").copied().flatten();
    let rtt = line.get("network_internet_rtt_ms").copied().flatten();
    house.internet_loss_ratio = fit(loss, 4);
    house.internet_rtt_ms = fit(rtt, 1);
    // max: any public host answers
    house.internet = match probe("blackbox_icmp", "internet") {
        None => "unknown",
        Some(v) if v < 1.0 => "down",
        Some(_) if loss.is_some_and(|l| l > DEGRADED_LOSS_RATIO) || rtt.is_some_and(|r| r > DEGRADED_RTT_MS) => {
            "degraded"
        }
        Some(_) => "ok",
    }
    .into();
    house.speedtest = speedtest(client).await?;
    // the age at the query's evaluation; the snapshot time (evaluation - age: unpoller's poll of
    // the controller) stays the same for every request until the next snapshot (presence's Ts)
    let age = client.samples(SNAPSHOT_AGE, None, CACHE_SECONDS).await?;
    if let Some((_, Some(value), at)) = age.first() {
        let snapshot = (at - value).round();
        house.wifi_data_age_s = trunc_int(*value);
        house.wifi_data_at = iso(Some(snapshot));
        house.snapshot_at = Some(snapshot);
    }
    Ok(house)
}

/// The latest speed test of the internet line, or `None` (no result, not completed, no
/// download). speedtest-tracker shows only its latest result; `at` is when its result id last
/// changed (within a minute; `None` if not in the last 2 days).
pub async fn speedtest(client: &Budget) -> Result<Option<Speedtest>, Unavailable> {
    let rows = client.vector(SPEEDTEST, None, CACHE_SECONDS).await?;
    // grouped by every label but the name: one group per result (server)
    let mut results: IndexMap<Labels, BTreeMap<String, Option<f64>>> = IndexMap::new();
    for (labels, value) in rows {
        let name = labels.get("__name__").cloned().unwrap_or_default();
        let mut key = labels;
        key.remove("__name__");
        results.entry(key).or_default().insert(name, value);
    }
    let id_of =
        |r: &BTreeMap<String, Option<f64>>| r.get("speedtest_tracker_result_id").copied().flatten().unwrap_or(-1.0);
    // the first group with the highest result id (Python's max keeps the first of equals)
    let mut best: Option<(&Labels, &BTreeMap<String, Option<f64>>)> = None;
    for (key, values) in &results {
        if best.is_none_or(|(_, b)| id_of(values) > id_of(b)) {
            best = Some((key, values));
        }
    }
    let Some((key, latest)) = best else {
        return Ok(None);
    };
    let get = |name: &str| latest.get(name).copied().flatten();
    let Some(download) = get("speedtest_tracker_download_bits") else {
        return Ok(None);
    };
    if key.get("status").map_or("completed", String::as_str) != "completed" {
        return Ok(None);
    }
    let result_id = get("speedtest_tracker_result_id");
    let mut at = None;
    let history = client.matrix(SPEEDTEST_HISTORY, None, SUMMARY_CACHE_SECONDS).await?;
    let points = history.first().map(|(_, p)| p.as_slice()).unwrap_or_default();
    if let (Some(id), Some(last)) = (result_id, points.last())
        && last.1 == Some(id)
    {
        let mut i = points.len() - 1;
        while i > 0 && points[i - 1].1 == Some(id) {
            i -= 1;
        }
        // the same id for 2 days: when is not known
        at = if i > 0 { iso(Some(points[i].0 as f64)) } else { None };
    }
    Ok(Some(Speedtest {
        download_bps: trunc_int(download).unwrap_or(0),
        upload_bps: get("speedtest_tracker_upload_bits").and_then(trunc_int),
        ping_ms: fit(get("speedtest_tracker_ping_ms"), 2),
        at,
    }))
}

/// HOUSE alone (`/api/house`): unknown values when telemetry is off or Prometheus unavailable.
pub async fn house(client: Option<&Budget>) -> House {
    match client {
        None => empty_house(),
        Some(client) => house_status(client).await.unwrap_or_else(|_| empty_house()),
    }
}
