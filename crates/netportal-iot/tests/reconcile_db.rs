//! The rounds against a real registry and the fake UniFi and OPNsense (house-infra
//! docs/IOT-ACCESS.md 6.4): the first round applies keys, aliases and rules, the second makes
//! no writes; a share taken away kills the states and removes the address; a revoked device
//! loses its key, is blocked and kicked, its aliases go; the IoT offboarding; the job row.
//!
//! Needs `NETPORTAL_TEST_DATABASE_URL` (`eval "$(tools/test-db.sh)"`); skipped without it.

mod common;

use std::collections::{BTreeMap, BTreeSet};

use common::{Case, FakeOpnsense, FakeUnifi, OPN_KEY, OPN_SECRET, UNIFI_PASSWORD, UNIFI_USER};
use netportal_core::config::IotSettings;
use netportal_iot::desired::{Names, device_hash, person_hash};
use netportal_iot::opnsense::OpnsenseClient;
use netportal_iot::reconcile::{self, Backends, IotError, Memory};
use netportal_iot::unifi::UnifiClient;
use serde_json::json;
use sqlx::{Connection, PgConnection};
use uuid::Uuid;

const ALICE_PHONE: &str = "bb:00:00:00:00:01";
const BOB_LAPTOP: &str = "bb:00:00:00:00:02";
const CHROMECAST: &str = "aa:00:00:00:00:a1";
const PRINTER: &str = "aa:00:00:00:00:a2";
const SPEAKER: &str = "aa:00:00:00:00:b1";

fn settings(db_url: &str, unifi: Option<&str>, opnsense: Option<&str>) -> IotSettings {
    let mut env: BTreeMap<&str, &str> = [
        ("NETPORTAL_DATABASE_URL", db_url),
        ("NETPORTAL_UNIFI_SITE", "default"),
        ("NETPORTAL_UNIFI_USER", UNIFI_USER),
        ("NETPORTAL_UNIFI_PASSWORD", UNIFI_PASSWORD),
        ("NETPORTAL_UNIFI_IOT_SSID", "Scharni-IoT"),
        ("NETPORTAL_UNIFI_IOT_NETWORK", "IoT"),
        ("NETPORTAL_OPNSENSE_API_KEY", OPN_KEY),
        ("NETPORTAL_OPNSENSE_API_SECRET", OPN_SECRET),
        ("NETPORTAL_IOT_API_TIMEOUT", "5"),
        ("NETPORTAL_HEARTBEAT", "/tmp/netportal-iot-test.heartbeat"),
    ]
    .into();
    if let Some(u) = unifi {
        env.insert("NETPORTAL_UNIFI_URL", u);
    }
    if let Some(o) = opnsense {
        env.insert("NETPORTAL_OPNSENSE_URL", o);
    }
    IotSettings::from_env(&env).expect("settings")
}

struct World {
    case: Case,
    unifi: FakeUnifi,
    opnsense: FakeOpnsense,
    settings: IotSettings,
    alice_cc: Uuid,
    alice_printer: Uuid,
    bob_speaker: Uuid,
    cc_psk: String,
    printer_psk: String,
    speaker_psk: String,
}

/// alice (phone .21) owns a private Chromecast (.11, shared with bob) and a house printer
/// (.12); bob (laptop .22) owns a private speaker (.13, shared with alice); carol has no
/// devices. Streams run between bob and the Chromecast, alice and the Chromecast, bob and the
/// printer.
async fn world(admin: &url::Url) -> World {
    let mut case = Case::new(admin).await;
    for sub in ["sub-alice", "sub-bob", "sub-carol"] {
        case.person(sub).await;
    }
    case.resident_device("sub-alice", ALICE_PHONE).await;
    case.resident_device("sub-bob", BOB_LAPTOP).await;
    let (alice_cc, cc_psk) = case.iot_device("sub-alice", "Chromecast", Some(CHROMECAST), "private").await;
    let (alice_printer, printer_psk) = case.iot_device("sub-alice", "Printer", Some(PRINTER), "house").await;
    let (bob_speaker, speaker_psk) = case.iot_device("sub-bob", "Speaker", Some(SPEAKER), "private").await;
    case.share(alice_cc, "sub-bob", "sub-alice").await;
    case.share(bob_speaker, "sub-alice", "sub-bob").await;
    let mut opn = FakeOpnsense::standard();
    opn.lease(ALICE_PHONE, "10.0.30.21", json!(4000000000u64));
    opn.lease(BOB_LAPTOP, "10.0.30.22", json!(4000000000u64));
    opn.lease(CHROMECAST, "10.0.40.11", json!(4000000000u64));
    opn.lease(PRINTER, "10.0.40.12", json!(4000000000u64));
    opn.lease(SPEAKER, "10.0.40.13", json!(4000000000u64));
    opn.state("10.0.30.22:50001", "10.0.40.11:8009");
    opn.state("10.0.30.21:50002", "10.0.40.11:8009");
    opn.state("10.0.30.22:50003", "10.0.40.12:631");
    let opnsense = FakeOpnsense::start(opn).await;
    let unifi = FakeUnifi::start(FakeUnifi::standard()).await;
    let settings = settings(&case.url, Some(&unifi.url), Some(&opnsense.url));
    World { case, unifi, opnsense, settings, alice_cc, alice_printer, bob_speaker, cc_psk, printer_psk, speaker_psk }
}

impl World {
    async fn round(&mut self, memory: &mut Memory) -> reconcile::RoundReport {
        let unifi = UnifiClient::new(&self.settings).expect("unifi");
        let opnsense = OpnsenseClient::new(&self.settings).expect("opnsense");
        let backends = Backends { unifi: unifi.as_ref(), opnsense: opnsense.as_ref() };
        self.unifi.clear();
        self.opnsense.clear();
        reconcile::round(&self.settings, &backends, memory).await.expect("round")
    }
}

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

#[tokio::test]
async fn test_two_rounds_apply_then_change_nothing() {
    let admin = need_db!();
    let mut w = world(&admin).await;
    let names = Names::new("np_iot");
    let (alice, bob) = (person_hash("sub-alice"), person_hash("sub-bob"));
    let mut memory = Memory::default();

    // --- the first round applies keys, aliases and rules
    let report = w.round(&mut memory).await;
    assert!(report.unifi_ok && report.opnsense_ok, "{report:?}");
    assert!(report.keys_written);
    assert_eq!((report.devices, report.shares, report.address_conflicts), (3, 2, 0));
    assert_eq!((report.sync_pending, report.sync_failed), (0, 0));
    assert_eq!(report.rules_changed, 3, "alice, bob, the house");
    assert_eq!((report.blocked, report.kicked, report.states_killed), (0, 0, 0));
    // UniFi: exactly the three keys, mapped to the IoT network, PPSK on
    let keys: BTreeSet<(String, String)> =
        [&w.cc_psk, &w.printer_psk, &w.speaker_psk].iter().map(|k| (k.to_string(), "n-iot".to_string())).collect();
    assert_eq!(w.unifi.keys(), keys);
    assert!(w.unifi.ppsk_enabled());
    assert!(w.unifi.blocked().is_empty());
    let puts = w.unifi.writes();
    assert_eq!(puts.len(), 1, "{puts:?}");
    assert!(puts[0].is("PUT", "/api/s/default/rest/wlanconf/w-iot"));
    assert!(w.unifi.requests().iter().any(|r| r.is("POST", "/api/logout")));
    // OPNsense: the aliases with their live contents, the hand-made alias untouched
    let expected: BTreeSet<String> = [
        names.dev(w.alice_cc),
        names.dev(w.alice_printer),
        names.dev(w.bob_speaker),
        names.src(&alice),
        names.to(&alice),
        names.src(&bob),
        names.to(&bob),
        names.house(),
        names.house_src(),
        "house_servers".to_string(),
    ]
    .into();
    assert_eq!(w.opnsense.alias_names(), expected);
    assert_eq!(w.opnsense.content(&names.dev(w.alice_cc)), set(&["10.0.40.11"]));
    assert_eq!(w.opnsense.content(&names.src(&alice)), set(&["10.0.30.21"]));
    assert_eq!(w.opnsense.content(&names.to(&alice)), set(&["10.0.40.11", "10.0.40.12", "10.0.40.13"]));
    assert_eq!(w.opnsense.content(&names.src(&bob)), set(&["10.0.30.22"]));
    assert_eq!(w.opnsense.content(&names.to(&bob)), set(&["10.0.40.11", "10.0.40.13"]));
    assert_eq!(w.opnsense.content(&names.house()), set(&["10.0.40.12"]));
    assert_eq!(w.opnsense.content(&names.house_src()), set(&["10.0.30.21", "10.0.30.22"]));
    assert_eq!(w.opnsense.content("house_servers"), set(&["10.0.10.5"]));
    // the rules: one per person and the house, pass quick on the residents' interface
    assert_eq!(
        w.opnsense.rule_descriptions(),
        set(&[
            &names.person_rule(&alice),
            &names.person_rule(&bob),
            &names.house_rule(),
            "house-infra: residents to iot blocked"
        ])
    );
    let rule = w.opnsense.rule(&names.person_rule(&bob)).expect("bob's rule");
    assert_eq!(rule["interface"], json!("opt2"));
    assert_eq!(
        (rule["source_net"].clone(), rule["destination_net"].clone()),
        (json!(names.src(&bob)), json!(names.to(&bob)))
    );
    assert_eq!(
        (rule["action"].clone(), rule["quick"].clone(), rule["protocol"].clone()),
        (json!("pass"), json!("1"), json!("any"))
    );
    assert_eq!(w.opnsense.with(|s| (s.applies, s.reconfigures)), (1, 1));
    // the streams are untouched: nothing lost access
    assert_eq!(w.opnsense.states().len(), 3);
    // the sync rows: all applied; the job row with the cursor /metrics reads
    let sync = w.case.sync().await;
    assert!(sync.values().all(|(status, _)| status == "applied"), "{sync:?}");
    assert_eq!(sync[&("unifi_key".to_string(), w.alice_cc.to_string())].0, "applied");
    assert_eq!(sync[&("opnsense_alias".to_string(), names.to(&bob))].1, "2 address(es)");
    assert_eq!(sync[&("opnsense_rule".to_string(), "house".to_string())].0, "applied");
    assert_eq!(sync[&("opnsense_rule".to_string(), alice.clone())].0, "applied");
    assert_eq!(sync.len(), 3 + 9 + 3);
    let job = w.case.job().await.expect("job iot");
    assert!(job.last_success.is_some() && job.last_error.is_none());
    assert_eq!(
        job.cursor.0,
        json!({"devices": 3, "shares": 2, "sync_pending": 0, "sync_failed": 0, "address_conflicts": 0,
               "unifi_ok": 1, "opnsense_ok": 1})
    );
    // the audit
    let cc_audit = w.case.audit(Some(w.alice_cc)).await;
    assert!(cc_audit.contains(&("iot".into(), "iot:unifi-key".into())), "{cc_audit:?}");
    assert!(cc_audit.contains(&("iot".into(), format!("iot:alias:{}", names.dev(w.alice_cc)))), "{cc_audit:?}");
    let actions = w.case.iot_audit().await;
    assert!(
        actions.contains(&format!("iot:rule:{bob}")) && actions.contains(&"iot:rule:house".to_string()),
        "{actions:?}"
    );
    let updated = w.case.sync_updated_max().await;

    // --- the second round calls no writing endpoint
    let report = w.round(&mut memory).await;
    assert!(report.unifi_ok && report.opnsense_ok);
    assert!(!report.wrote(), "{report:?}");
    assert_eq!(w.unifi.writes(), []);
    assert_eq!(w.opnsense.writes(), []);
    assert_eq!(w.case.sync_updated_max().await, updated, "no sync row rewritten");
    assert_eq!(w.case.iot_audit().await, actions, "no new audit rows");
    // the second round was a cheap one (the contents came from memory, no alias_util/list)
    assert!(!w.opnsense.requests().iter().any(|r| r.path.contains("alias_util/list")));

    // --- a share taken away: the address leaves the alias, the stream's states die
    w.case.unshare(w.alice_cc, "sub-bob", "sub-alice").await;
    let report = w.round(&mut memory).await;
    assert!(report.opnsense_ok);
    assert_eq!(report.states_killed, 1, "{report:?}");
    assert_eq!(w.opnsense.content(&names.to(&bob)), set(&["10.0.40.13"]));
    let writes = w.opnsense.writes();
    assert!(
        writes.iter().any(|r| r.is("POST", &format!("/api/firewall/alias_util/delete/{}", names.to(&bob)))
            && r.body == json!({"address": "10.0.40.11"})),
        "{writes:?}"
    );
    assert!(writes.iter().any(|r| r.path.contains("/del_state/")), "{writes:?}");
    assert!(!writes.iter().any(|r| r.path.contains("kill_states")), "a pair, not the whole device");
    // only bob's stream to the Chromecast is gone; alice's and bob's to the printer stay
    assert_eq!(
        w.opnsense.states(),
        [
            ("10.0.30.21:50002".to_string(), "10.0.40.11:8009".to_string()),
            ("10.0.30.22:50003".into(), "10.0.40.12:631".into())
        ]
    );
    assert!(w.unifi.writes().is_empty(), "UniFi untouched by a share");
    let cc_audit = w.case.audit(Some(w.alice_cc)).await;
    assert_eq!(cc_audit.iter().filter(|(_, a)| a == "iot:states-killed").count(), 1, "{cc_audit:?}");
    let sync = w.case.sync().await;
    assert_eq!(
        sync[&("opnsense_states".to_string(), w.alice_cc.to_string())],
        ("applied".to_string(), "1 state(s) killed".to_string())
    );
    assert!(!w.round(&mut memory).await.wrote());

    // --- a revoked device loses its key, is blocked and kicked, its aliases go
    w.case.revoke(w.alice_cc, "sub-alice").await;
    let report = w.round(&mut memory).await;
    assert!(report.unifi_ok && report.opnsense_ok, "{report:?}");
    assert!(report.keys_written);
    assert_eq!((report.blocked, report.kicked), (1, 1));
    assert_eq!(report.states_killed, 1, "alice's own stream to it");
    assert_eq!(report.devices, 2);
    let keys: BTreeSet<(String, String)> =
        [&w.printer_psk, &w.speaker_psk].iter().map(|k| (k.to_string(), "n-iot".to_string())).collect();
    assert_eq!(w.unifi.keys(), keys);
    assert_eq!(w.unifi.blocked(), set(&[CHROMECAST]));
    let cmds: Vec<serde_json::Value> =
        w.unifi.writes().into_iter().filter(|r| r.path.ends_with("cmd/stamgr")).map(|r| r.body).collect();
    assert_eq!(cmds, [json!({"cmd": "block-sta", "mac": CHROMECAST}), json!({"cmd": "kick-sta", "mac": CHROMECAST})]);
    assert!(!w.opnsense.alias_names().contains(&names.dev(w.alice_cc)));
    assert_eq!(w.opnsense.content(&names.to(&alice)), set(&["10.0.40.12", "10.0.40.13"]));
    assert!(
        w.opnsense.writes().iter().any(|r| r.path.contains("kill_states") && r.body == json!({"filter": "10.0.40.11"}))
    );
    assert_eq!(w.opnsense.states(), [("10.0.30.22:50003".to_string(), "10.0.40.12:631".to_string())]);
    let cc_audit = w.case.audit(Some(w.alice_cc)).await;
    for action in ["iot:unifi-key-removed", "iot:block", "iot:kick", "iot:states-killed"] {
        assert!(cc_audit.contains(&("iot".into(), action.into())), "{action}: {cc_audit:?}");
    }
    let sync = w.case.sync().await;
    assert_eq!(
        sync[&("unifi_block".to_string(), w.alice_cc.to_string())],
        ("applied".to_string(), format!("blocked {CHROMECAST}, kicked"))
    );
    assert!(!sync.contains_key(&("unifi_key".to_string(), w.alice_cc.to_string())), "the key row is gone");
    assert!(!sync.contains_key(&("opnsense_alias".to_string(), names.dev(w.alice_cc))));
    let updated = w.case.sync_updated_max().await;
    assert!(!w.round(&mut memory).await.wrote());
    assert_eq!(w.case.sync_updated_max().await, updated, "no sync row rewritten after the block");

    // --- the device row deleted: its MAC is unblocked, the rows go
    w.case.count(&format!("DELETE FROM device WHERE id = '{}' RETURNING 1::bigint", w.alice_cc)).await;
    let report = w.round(&mut memory).await;
    assert_eq!(report.unblocked, 1);
    assert!(w.unifi.blocked().is_empty());
    assert!(!w.case.sync().await.contains_key(&("unifi_block".to_string(), w.alice_cc.to_string())));
    assert!(!w.round(&mut memory).await.wrote());
}

#[tokio::test]
async fn test_offboarding_and_full_readback() {
    let admin = need_db!();
    let mut w = world(&admin).await;
    let names = Names::new("np_iot");
    let (alice, bob) = (person_hash("sub-alice"), person_hash("sub-bob"));
    let mut memory = Memory::default();
    w.round(&mut memory).await;
    assert!(!w.round(&mut memory).await.wrote());

    // bob leaves: the shares he holds and gave go, his speaker is revoked, his aliases and rule go
    w.case.offboard("sub-bob").await;
    let report = w.round(&mut memory).await;
    assert!(report.unifi_ok && report.opnsense_ok, "{report:?}");
    assert_eq!((report.shares_dropped, report.devices_revoked), (2, 1));
    assert_eq!((report.devices, report.shares), (2, 0));
    assert_eq!(w.case.count("SELECT count(*) FROM iot_share").await, 0);
    assert_eq!(w.unifi.keys().len(), 2);
    assert!(!w.unifi.keys().contains(&(w.speaker_psk.clone(), "n-iot".to_string())));
    assert_eq!(w.unifi.blocked(), set(&[SPEAKER]));
    assert!(!w.opnsense.alias_names().contains(&names.src(&bob)));
    assert!(!w.opnsense.alias_names().contains(&names.to(&bob)));
    assert!(!w.opnsense.alias_names().contains(&names.dev(w.bob_speaker)));
    assert!(!w.opnsense.rule_descriptions().contains(&names.person_rule(&bob)));
    // alice keeps her own devices; bob's speaker is gone from what she may reach
    assert_eq!(w.opnsense.content(&names.to(&alice)), set(&["10.0.40.11", "10.0.40.12"]));
    // bob's laptop is still a current resident MAC: the house sources keep it (the house
    // rule reaches house devices; the person's rule is gone)
    assert_eq!(w.opnsense.content(&names.house_src()), set(&["10.0.30.21", "10.0.30.22"]));
    assert_eq!(w.opnsense.rule_descriptions().len(), 3);
    // bob's streams to the Chromecast died with his pair; the printer stream stays (house)
    assert_eq!(
        w.opnsense.states(),
        [
            ("10.0.30.21:50002".to_string(), "10.0.40.11:8009".to_string()),
            ("10.0.30.22:50003".into(), "10.0.40.12:631".into())
        ]
    );
    let speaker_audit = w.case.audit(Some(w.bob_speaker)).await;
    assert!(speaker_audit.contains(&("iot".into(), "revoke".into())), "{speaker_audit:?}");
    assert!(speaker_audit.contains(&("iot".into(), "iot:block".into())), "{speaker_audit:?}");
    assert!(w.case.iot_audit().await.contains(&"iot:shares-dropped:sub-bob".to_string()));
    let sync = w.case.sync().await;
    assert!(!sync.keys().any(|(_, k)| k == &bob), "{sync:?}");
    assert!(!w.round(&mut memory).await.wrote());

    // --- a change made by hand is reverted on the full read-back
    w.opnsense.with(|s| {
        s.contents.get_mut(&names.house()).expect("house").insert("10.0.40.99".into());
    });
    assert!(!w.round(&mut memory).await.wrote(), "a cheap round trusts its memory");
    memory.last_full = None;
    let report = w.round(&mut memory).await;
    assert_eq!(report.aliases_changed, 1, "{report:?}");
    assert_eq!(w.opnsense.content(&names.house()), set(&["10.0.40.12"]));
    assert!(w.opnsense.requests().iter().any(|r| r.path.contains("alias_util/list")));

    // --- a conflict: the Chromecast's MAC with two leases is left out and counted
    w.opnsense.with(|s| s.lease(CHROMECAST, "10.0.40.77", json!(4000000000u64)));
    let report = w.round(&mut memory).await;
    assert_eq!(report.address_conflicts, 1);
    assert!(w.opnsense.content(&names.dev(w.alice_cc)).is_empty());
    assert_eq!(w.case.job().await.expect("job").cursor.0["address_conflicts"], json!(1));
}

#[tokio::test]
async fn test_backend_failures_fail_rows_not_the_round() {
    let admin = need_db!();
    let mut w = world(&admin).await;
    let names = Names::new("np_iot");
    let mut memory = Memory::default();
    // UniFi refuses the login, OPNsense is fine
    w.unifi.with(|s| s.fail_paths.push("/api/login".into()));
    let report = w.round(&mut memory).await;
    assert!(!report.unifi_ok && report.opnsense_ok, "{report:?}");
    assert_eq!(report.sync_failed, 3, "the three keys");
    let sync = w.case.sync().await;
    let (status, detail) = &sync[&("unifi_key".to_string(), w.alice_cc.to_string())];
    assert_eq!(status, "failed");
    assert!(detail.contains("api.err.ServerError"), "{detail}");
    assert!(!detail.contains(UNIFI_PASSWORD));
    let job = w.case.job().await.expect("job");
    assert!(job.last_success.is_some(), "a failed backend does not fail the round");
    assert_eq!(job.cursor.0["unifi_ok"], json!(0));
    assert_eq!(job.cursor.0["sync_failed"], json!(3));
    // UniFi back, OPNsense's filter apply broken: the rules' rows fail, aliases are applied
    w.unifi.with(|s| s.fail_paths.clear());
    w.opnsense.with(|s| s.fail_paths.push("filter/apply".into()));
    w.opnsense.with(|s| s.rules.clear());
    let report = w.round(&mut memory).await;
    assert!(report.unifi_ok && !report.opnsense_ok, "{report:?}");
    let sync = w.case.sync().await;
    assert_eq!(sync[&("unifi_key".to_string(), w.alice_cc.to_string())].0, "applied");
    assert_eq!(sync[&("opnsense_rule".to_string(), "house".to_string())].0, "failed");
    assert!(sync[&("opnsense_rule".to_string(), "house".to_string())].1.starts_with("apply: "));
    assert_eq!(sync[&("opnsense_alias".to_string(), names.house())].0, "applied");
    // and healed
    w.opnsense.with(|s| s.fail_paths.clear());
    let report = w.round(&mut memory).await;
    assert!(report.opnsense_ok);
    assert_eq!(report.sync_failed, 0);
    assert!(!w.round(&mut memory).await.wrote());
}

#[tokio::test]
async fn test_without_backends_rows_stay_pending() {
    let admin = need_db!();
    let mut case = Case::new(&admin).await;
    case.person("sub-alice").await;
    let (dev, _) = case.iot_device("sub-alice", "Chromecast", Some(CHROMECAST), "house").await;
    let settings = settings(&case.url, None, None);
    assert!(!settings.unifi_enabled() && !settings.opnsense_enabled());
    let mut memory = Memory::default();
    let report = reconcile::round(&settings, &Backends::default(), &mut memory).await.expect("round");
    assert!(!report.unifi_ok && !report.opnsense_ok);
    assert_eq!(
        (report.devices, report.sync_pending, report.sync_failed),
        (1, 1 + 5 + 2, 0),
        "key; dev, src, to, house, house_src; alice, house"
    );
    let sync = case.sync().await;
    assert_eq!(
        sync[&("unifi_key".to_string(), dev.to_string())],
        ("pending".to_string(), "UniFi is not configured".to_string())
    );
    assert_eq!(sync[&("opnsense_rule".to_string(), "house".to_string())].1, "OPNsense is not configured");
    assert_eq!(sync[&("opnsense_alias".to_string(), Names::new("np_iot").dev(dev))].0, "pending");
    assert_eq!(case.job().await.expect("job").cursor.0["sync_pending"], json!(8));
    // join attempts older than a day are pruned by the round
    case.count("INSERT INTO iot_join_attempt (mac, first_seen, last_seen) VALUES ('aa:00:00:00:00:77', now() - interval '2 days', now() - interval '2 days') RETURNING 1::bigint").await;
    case.count("INSERT INTO iot_join_attempt (mac) VALUES ('aa:00:00:00:00:78') RETURNING 1::bigint").await;
    let report = reconcile::round(&settings, &Backends::default(), &mut memory).await.expect("round");
    assert_eq!(report.join_attempts_pruned, 1);
    assert_eq!(case.count("SELECT count(*) FROM iot_join_attempt").await, 1);
    // another process holding the lock: the round is skipped
    let mut other = PgConnection::connect(&case.url).await.expect("connect");
    let held: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock(hashtext($1))")
        .bind(reconcile::LOCK_KEY)
        .fetch_one(&mut other)
        .await
        .expect("lock");
    assert!(held);
    let result = reconcile::round(&settings, &Backends::default(), &mut memory).await;
    assert!(matches!(result, Err(IotError::Locked)), "{result:?}");
    let _ = device_hash(dev);
}

#[tokio::test]
async fn test_the_last_key_switches_ppsk_off() {
    let admin = need_db!();
    let mut w = world(&admin).await;
    let mut memory = Memory::default();
    let report = w.round(&mut memory).await;
    assert!(report.unifi_ok && w.unifi.ppsk_enabled() && w.unifi.keys().len() == 3, "{report:?}");

    // every device removed: the keys go and PPSK with them (UniFi refuses "on" with no key; the
    // fake does too), the SSID stays as house-infra made it
    for id in [w.alice_cc, w.alice_printer, w.bob_speaker] {
        w.case.revoke(id, "sub-admin").await;
    }
    let report = w.round(&mut memory).await;
    assert!(report.unifi_ok, "{report:?}");
    assert!(report.keys_written);
    assert!(w.unifi.keys().is_empty() && !w.unifi.ppsk_enabled());
    let put = w.unifi.writes().into_iter().find(|r| r.method == "PUT").expect("the PUT");
    assert_eq!(put.body, json!({"private_preshared_keys": [], "private_preshared_keys_enabled": false}));

    // and nothing to write the round after
    let report = w.round(&mut memory).await;
    assert!(report.unifi_ok && !report.keys_written, "{report:?}");
    assert!(!w.unifi.writes().iter().any(|r| r.method == "PUT"), "{:?}", w.unifi.writes());
}
