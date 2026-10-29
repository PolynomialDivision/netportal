//! The codes the telemetry sends are those the translations know (`i18n.json`, made from
//! `netportal/i18n.py`): every state, source, reason, finding, AP warning, event kind, MAC mode
//! and range has its texts in the frontend (INVENTORY 9.8, 11.9). Python checked these in the JS
//! tests through `python3`.

use std::collections::BTreeSet;

use netportal_core::i18n;
use serde_json::Value;

use crate::diagnostics::AP_WEAK_SHARE_WARN;
use crate::presence;
use crate::telemetry::history::HISTORY_RANGES;

fn table(name: &str) -> Vec<String> {
    i18n::tables()
        .get(name)
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_else(|| panic!("table {name}"))
}

fn codes(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

#[test]
fn test_presence_tables_are_the_translations() {
    assert_eq!(table("PRESENCE_STATES"), presence::STATES);
    assert_eq!(table("PRESENCE_SOURCES"), presence::SOURCES);
    let reasons = [
        "association",
        "association_gone",
        "acct_start",
        "acct_interim",
        "sources_disagree",
        "accept_pending",
        "acct_stop",
        "ap_down",
        "unifi_disconnect",
        "session_stale",
        "telemetry_unavailable",
        "mac_conflict",
        "no_data",
    ];
    let known: BTreeSet<String> = table("PRESENCE_REASONS").into_iter().collect();
    assert!(codes(&reasons).is_subset(&known));
}

#[test]
fn test_every_code_has_its_texts() {
    let diagnoses: BTreeSet<String> = table("DIAGNOSES").into_iter().collect();
    let findings = [
        "never_connected",
        "stale_data",
        "offline",
        "weak_signal",
        "low_snr",
        "high_retries",
        "busy_channel",
        "slow_link",
        "unstable_roaming",
        "frequent_disconnects",
        "stuck_on_2ghz",
        "auth_failures",
        "cert_expired",
        "cert_expiring",
        "rotating_mac",
        "ap_overloaded",
        "poor_coverage",
        "incident_correlated",
        "mac_conflict",
    ];
    assert_eq!(codes(&findings), diagnoses);
    let warnings: BTreeSet<String> = table("AP_WARNINGS").into_iter().collect();
    assert_eq!(codes(&["down", "overloaded", "busy_channel", "poor_coverage", "restarted", "uplink"]), warnings);
    let kinds: BTreeSet<String> = table("EVENT_KINDS").into_iter().collect();
    let ours = [
        "authenticated",
        "auth_rejected",
        "connected",
        "disconnected",
        "reconnected",
        "roamed",
        "band_changed",
        "mac_changed",
        "session_ended",
        "incident",
    ];
    assert_eq!(codes(&ours), kinds);
    assert_eq!(table("MAC_MODES"), ["hardware", "random_fixed", "rotating"]);
    assert_eq!(table("RANGES"), HISTORY_RANGES);
    let sources: BTreeSet<String> = table("SOURCES").into_iter().collect();
    let ours = [
        "radius_auth",
        "radius_acct",
        "unifi_syslog",
        "prometheus",
        "device_day",
        "device_mac",
        "incident",
        "registry",
    ];
    assert!(codes(&ours).is_subset(&sources));
    assert_eq!(i18n::tables().get("AP_WEAK_SHARE_WARN").and_then(Value::as_f64), Some(AP_WEAK_SHARE_WARN));
    for lang in i18n::languages() {
        for code in &findings {
            for suffix in ["", "_why", "_do"] {
                assert!(i18n::text(lang, &format!("diag_{code}{suffix}")).is_some(), "{lang}: diag_{code}{suffix}");
            }
        }
    }
}
