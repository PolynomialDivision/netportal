//! The two API clients against fake servers: the requests they shape (paths, bodies, the
//! session cookie and CSRF token, HTTP Basic), what they parse, how they fail. No database.

mod common;

use std::time::Duration;

use common::{FakeOpnsense, FakeUnifi, OPN_KEY, OPN_SECRET, UNIFI_PASSWORD, UNIFI_USER};
use netportal_core::config::Secret;
use netportal_iot::opnsense::{OpnsenseClient, OpnsenseError, RULE_FIELDS};
use netportal_iot::unifi::{Ppsk, UnifiClient, UnifiError};
use serde_json::json;

const TIMEOUT: Duration = Duration::from_secs(5);

fn unifi(fake: &FakeUnifi, password: &str) -> UnifiClient {
    UnifiClient::from_parts(&fake.url, "default", UNIFI_USER, Secret::new(password.to_string()), true, TIMEOUT)
        .expect("client")
}

fn opnsense(fake: &FakeOpnsense, secret: &str) -> OpnsenseClient {
    OpnsenseClient::from_parts(&fake.url, OPN_KEY, Secret::new(secret.to_string()), None, TIMEOUT).expect("client")
}

#[tokio::test]
async fn test_unifi_session_and_requests() {
    let mut state = FakeUnifi::standard();
    state.clients.push(json!({"mac": "AA:BB:CC:00:00:10", "ip": "10.0.40.10", "essid": "Scharni-IoT", "vlan": 40,
        "ap_mac": "f0:9f:c2:00:00:01", "hostname": "chromecast", "last_seen": 1700000000, "signal": -55,
        "ppsk_id": "ppsk-3"}));
    state.users.push(json!({"mac": "aa:bb:cc:00:00:99", "blocked": true, "name": "old"}));
    state.users.push(json!({"mac": "aa:bb:cc:00:00:98", "blocked": false, "name": "fine"}));
    let fake = FakeUnifi::start(state).await;
    let client = unifi(&fake, UNIFI_PASSWORD);
    // before the login every site call is refused by the controller
    let refused = client.networks().await;
    assert!(matches!(&refused, Err(UnifiError::Refused { rc, .. }) if rc == "error"), "{refused:?}");
    client.login().await.expect("login");
    assert!(client.logged_in());
    let login = &fake.requests()[1];
    assert!(login.is("POST", "/api/login"));
    assert_eq!(login.body, json!({"username": UNIFI_USER, "password": UNIFI_PASSWORD, "remember": false}));
    // reads (the fake refuses them without the cookie)
    assert_eq!(client.network_id("IoT").await.expect("network"), "n-iot");
    let wlan = client.wlan("Scharni-IoT").await.expect("wlan");
    assert_eq!(
        (wlan.id.as_str(), wlan.private_preshared_keys.len(), wlan.private_preshared_keys_enabled),
        ("w-iot", 0, false)
    );
    let clients = client.clients().await.expect("clients");
    assert_eq!(clients.len(), 1);
    assert_eq!(
        (clients[0].mac.as_str(), clients[0].ip.as_deref(), clients[0].vlan),
        ("aa:bb:cc:00:00:10", Some("10.0.40.10"), Some(40))
    );
    assert_eq!(clients[0].ppsk_id.as_deref(), Some("ppsk-3"));
    assert_eq!(client.blocked().await.expect("blocked"), ["aa:bb:cc:00:00:99"]);
    // writes carry the CSRF token (the fake refuses them without it) and the partial object
    let keys = [
        Ppsk { password: "KEYAAAAAAAAAAAAAAAA1".into(), networkconf_id: "n-iot".into() },
        Ppsk { password: "KEYBBBBBBBBBBBBBBBB2".into(), networkconf_id: "n-iot".into() },
    ];
    client.set_ppsk("w-iot", &keys).await.expect("set keys");
    let put = fake.requests().into_iter().find(|r| r.method == "PUT").expect("a PUT");
    assert_eq!(put.path, "/api/s/default/rest/wlanconf/w-iot");
    assert_eq!(
        put.body,
        json!({"private_preshared_keys": [
            {"password": "KEYAAAAAAAAAAAAAAAA1", "networkconf_id": "n-iot"},
            {"password": "KEYBBBBBBBBBBBBBBBB2", "networkconf_id": "n-iot"}],
            "private_preshared_keys_enabled": true})
    );
    assert_eq!(fake.keys().len(), 2);
    assert!(fake.ppsk_enabled());
    let wlan = client.wlan("Scharni-IoT").await.expect("wlan");
    assert_eq!(wlan.private_preshared_keys, keys);
    // the last key gone: PPSK off with it (the fake refuses "on" with none, as the controller does)
    client.set_ppsk("w-iot", &[]).await.expect("no keys");
    let put = fake.requests().into_iter().rev().find(|r| r.method == "PUT").expect("a PUT");
    assert_eq!(put.body, json!({"private_preshared_keys": [], "private_preshared_keys_enabled": false}));
    assert!(!fake.ppsk_enabled() && fake.keys().is_empty());
    client.block("AA:BB:CC:00:00:10").await.expect("block");
    client.kick("AA:BB:CC:00:00:10").await.expect("kick");
    client.unblock("aa:bb:cc:00:00:99").await.expect("unblock");
    let cmds: Vec<serde_json::Value> =
        fake.requests().into_iter().filter(|r| r.path.ends_with("/cmd/stamgr")).map(|r| r.body).collect();
    assert_eq!(
        cmds,
        [
            json!({"cmd": "block-sta", "mac": "aa:bb:cc:00:00:10"}),
            json!({"cmd": "kick-sta", "mac": "aa:bb:cc:00:00:10"}),
            json!({"cmd": "unblock-sta", "mac": "aa:bb:cc:00:00:99"})
        ]
    );
    assert_eq!(fake.blocked(), ["aa:bb:cc:00:00:10".to_string()].into());
    assert!(client.clients().await.expect("clients").is_empty(), "kicked");
    // the key never shows in Debug output
    assert!(!format!("{:?}", keys[0]).contains("KEYAAAA"));
    client.logout().await;
    assert!(!client.logged_in());
    assert!(fake.requests().last().expect("logout").is("POST", "/api/logout"));
    assert!(matches!(client.networks().await, Err(UnifiError::Refused { .. })));
}

#[tokio::test]
async fn test_unifi_failures() {
    let fake = FakeUnifi::start(FakeUnifi::standard()).await;
    let wrong = unifi(&fake, "not-the-password");
    let err = wrong.login().await.expect_err("refused");
    assert!(
        matches!(&err, UnifiError::Refused { rc, msg, .. } if rc == "error" && msg.contains("api.err.Invalid")),
        "{err}"
    );
    assert!(!err.to_string().contains("not-the-password"));
    let client = unifi(&fake, UNIFI_PASSWORD);
    client.login().await.expect("login");
    assert!(matches!(client.network_id("Guests").await, Err(UnifiError::NoNetwork(n)) if n == "Guests"));
    assert!(matches!(client.wlan("Nope").await, Err(UnifiError::NoSsid(n)) if n == "Nope"));
    fake.with(|s| s.fail_paths.push("stat/sta".into()));
    let err = client.clients().await.expect_err("500");
    assert!(matches!(&err, UnifiError::Refused { msg, .. } if msg.contains("api.err.ServerError")), "{err}");
    // a server that is not there
    let gone = UnifiClient::from_parts("http://127.0.0.1:9", "default", "u", Secret::new("p".into()), true, TIMEOUT)
        .expect("client");
    let err = gone.login().await.expect_err("no server");
    assert!(matches!(err, UnifiError::Request { reason: "connection failed", .. }), "{err}");
}

#[tokio::test]
async fn test_opnsense_aliases_rules_and_interfaces() {
    let fake = FakeOpnsense::start(FakeOpnsense::standard()).await;
    let wrong = opnsense(&fake, "wrong-secret");
    assert!(matches!(wrong.aliases().await, Err(OpnsenseError::Status { status: 401, .. })));
    let client = opnsense(&fake, OPN_SECRET);
    // the hand-made alias is listed and recognised as not ours
    let aliases = client.aliases().await.expect("aliases");
    assert_eq!(aliases.len(), 1);
    assert_eq!(
        (aliases[0].name.as_str(), aliases[0].is_ours(), aliases[0].enabled, aliases[0].kind.as_str()),
        ("house_servers", false, true, "host")
    );
    let search = fake.requests().last().expect("search").clone();
    assert!(search.is("POST", "/api/firewall/alias/searchItem"));
    assert_eq!(search.body["rowCount"], json!(-1));
    // an alias object, then its content live
    let uuid = client.add_alias("np_iot_house", "netportal: house devices").await.expect("add");
    assert!(!uuid.is_empty());
    let add = fake.requests().last().expect("add").clone();
    assert!(add.is("POST", "/api/firewall/alias/addItem"));
    assert_eq!(
        add.body,
        json!({"alias": {"enabled": "1", "name": "np_iot_house", "type": "host", "content": "", "description": "netportal: house devices"}})
    );
    let twice = client.add_alias("np_iot_house", "netportal: house devices").await.expect_err("taken");
    assert!(matches!(&twice, OpnsenseError::Refused { message, .. } if message.contains("alias.name")), "{twice}");
    client.reconfigure_aliases().await.expect("reconfigure");
    assert_eq!(fake.with(|s| s.reconfigures), 1);
    client.alias_add("np_iot_house", "10.0.40.12").await.expect("alias add");
    client.alias_add("np_iot_house", "10.0.40.13").await.expect("alias add");
    let add = fake.requests().last().expect("alias_util add").clone();
    assert!(add.is("POST", "/api/firewall/alias_util/add/np_iot_house"));
    assert_eq!(add.body, json!({"address": "10.0.40.13"}));
    client.alias_delete("np_iot_house", "10.0.40.12").await.expect("alias delete");
    assert!(fake.requests().last().expect("delete").is("POST", "/api/firewall/alias_util/delete/np_iot_house"));
    assert_eq!(client.alias_content("np_iot_house").await.expect("list"), ["10.0.40.13"]);
    assert!(fake.requests().last().expect("list").is("GET", "/api/firewall/alias_util/list/np_iot_house"));
    assert!(matches!(client.alias_add("np_iot_missing", "10.0.40.1").await, Err(OpnsenseError::Refused { .. })));
    // a rule with every field as a string
    let ours = client.aliases().await.expect("aliases").into_iter().find(|a| a.is_ours()).expect("ours");
    assert_eq!((ours.name.as_str(), ours.uuid.as_str()), ("np_iot_house", uuid.as_str()));
    let fields: std::collections::BTreeMap<&'static str, String> = [
        ("enabled", "1"),
        ("sequence", "50"),
        ("action", "pass"),
        ("quick", "1"),
        ("interface", "opt2"),
        ("direction", "in"),
        ("ipprotocol", "inet"),
        ("protocol", "any"),
        ("source_net", "any"),
        ("source_not", "0"),
        ("destination_net", "np_iot_house"),
        ("destination_not", "0"),
        ("destination_port", ""),
        ("log", "0"),
        ("description", "netportal: np_iot house"),
    ]
    .into_iter()
    .map(|(k, v)| (k, v.to_string()))
    .collect();
    let rule_uuid = client.add_rule(&fields).await.expect("add rule");
    let add = fake.requests().last().expect("addRule").clone();
    assert!(add.is("POST", "/api/firewall/filter/addRule"));
    assert_eq!(add.body["rule"].as_object().expect("rule").len(), RULE_FIELDS.len());
    assert_eq!(add.body["rule"]["destination_net"], json!("np_iot_house"));
    assert_eq!(add.body["rule"]["sequence"], json!("50"));
    let rules = client.rules().await.expect("rules");
    assert_eq!(rules.len(), 2);
    let mine = rules.iter().find(|r| r.is_ours()).expect("ours");
    assert_eq!((mine.uuid.as_str(), mine.description()), (rule_uuid.as_str(), "netportal: np_iot house"));
    assert_eq!(mine.fields.get("interface").map(String::as_str), Some("opt2"));
    assert!(!rules.iter().find(|r| r.description().starts_with("house-infra:")).expect("hand-made").is_ours());
    let mut changed = fields.clone();
    changed.insert("log", "1".into());
    client.set_rule(&rule_uuid, &changed).await.expect("set rule");
    assert!(fake.requests().last().expect("setRule").path.ends_with(&format!("/setRule/{rule_uuid}")));
    assert_eq!(fake.rule("netportal: np_iot house").expect("rule")["log"], json!("1"));
    client.apply_rules().await.expect("apply");
    assert_eq!(fake.with(|s| s.applies), 1);
    // an alias in use cannot go; after the rule it can
    assert!(matches!(client.del_alias(&uuid).await, Err(OpnsenseError::Refused { .. })));
    client.del_rule(&rule_uuid).await.expect("del rule");
    client.del_alias(&uuid).await.expect("del alias");
    assert_eq!(fake.alias_names(), ["house_servers".to_string()].into());
    // the interface by its gateway address, from addr4 or ipv4[].ipaddr
    assert_eq!(client.interface_by_gateway("10.0.30.1").await.expect("iface").as_deref(), Some("opt2"));
    assert_eq!(client.interface_by_gateway("10.0.40.1").await.expect("iface").as_deref(), Some("opt3"));
    assert_eq!(client.interface_by_gateway("10.0.50.1").await.expect("iface"), None);
    fake.with(|s| s.interfaces.push(json!({"identifier": "opt9", "addr4": ["10.0.30.1/24"]})));
    assert_eq!(client.interface_by_gateway("10.0.30.1").await.expect("iface"), None, "two interfaces: none");
    // every request carried the key and secret as HTTP Basic (the fake refuses otherwise)
    assert!(fake.requests().len() > 10);
}

#[tokio::test]
async fn test_opnsense_states_and_leases() {
    let mut state = FakeOpnsense::standard();
    state.state("10.0.30.21:51000", "10.0.40.11:8009");
    state.state("10.0.30.22:51001", "10.0.40.11:8009");
    state.state("10.0.40.11:40000", "10.0.30.22:7000");
    state.state("10.0.30.22:51002", "10.0.40.12:631");
    state.lease("AA:BB:CC:00:00:11", "10.0.40.11", json!(4000000000u64));
    state.lease("aa-bb-cc-00-00-12", "10.0.40.12", json!("4000000000"));
    state.lease("aabbcc000013", "10.0.30.13", json!(0));
    state.lease("junk", "10.0.30.14", json!(0));
    let fake = FakeOpnsense::start(state).await;
    let client = opnsense(&fake, OPN_SECRET);
    let states = client.states("10.0.40.11").await.expect("states");
    assert_eq!(states.len(), 3);
    assert_eq!(
        (states[0].src.as_str(), states[0].dst.as_str(), states[0].creatorid.as_str()),
        ("10.0.30.21", "10.0.40.11", "c0")
    );
    let query = fake.requests().last().expect("query").clone();
    assert!(query.is("POST", "/api/diagnostics/firewall/query_states"));
    assert_eq!(query.body["searchPhrase"], json!("10.0.40.11"));
    client.del_state(&states[0].id, &states[0].creatorid).await.expect("del_state");
    assert!(fake.requests().last().expect("del").path.ends_with(&format!("/del_state/{}/c0", states[0].id)));
    assert_eq!(fake.states().len(), 3);
    // a version that routes delState only: the first form is 404, the second works
    fake.with(|s| s.del_state_route = "delState".into());
    client.del_state(&states[1].id, "c0").await.expect("delState");
    let last_two: Vec<String> = fake.requests().iter().rev().take(2).map(|r| r.path.clone()).collect();
    assert!(last_two[1].contains("/del_state/") && last_two[0].contains("/delState/"), "{last_two:?}");
    assert_eq!(fake.states().len(), 2);
    assert!(matches!(client.del_state("nope", "c0").await, Err(OpnsenseError::Refused { .. })));
    // kill_states by address, and its absence
    assert_eq!(client.kill_states("10.0.40.11").await.expect("kill"), Some(1));
    assert_eq!(fake.requests().last().expect("kill").body, json!({"filter": "10.0.40.11"}));
    assert_eq!(fake.states(), [("10.0.30.22:51002".to_string(), "10.0.40.12:631".to_string())]);
    fake.with(|s| s.kill_states_available = false);
    let err = client.kill_states("10.0.40.12").await.expect_err("404");
    assert!(err.is_not_found(), "{err}");
    // leases: any MAC form normalised, expiry as number or string, junk left out
    let leases = client.leases().await.expect("leases");
    assert!(fake.requests().last().expect("leases").is("GET", "/api/dnsmasq/leases/search"));
    assert_eq!(leases.len(), 3);
    assert_eq!(
        (leases[0].mac.as_str(), leases[0].address.as_str(), leases[0].expire),
        ("aa:bb:cc:00:00:11", "10.0.40.11", Some(4000000000))
    );
    assert_eq!((leases[1].mac.as_str(), leases[1].expire), ("aa:bb:cc:00:00:12", Some(4000000000)));
    assert_eq!((leases[2].mac.as_str(), leases[2].expire), ("aa:bb:cc:00:00:13", Some(0)));
    // a CA file that is not PEM is refused at start
    let bad = OpnsenseClient::from_parts(&fake.url, OPN_KEY, Secret::new(OPN_SECRET.into()), Some(b"not pem"), TIMEOUT);
    assert!(matches!(bad, Err(OpnsenseError::Client(m)) if m.contains("NETPORTAL_OPNSENSE_CA")));
}

#[tokio::test]
async fn test_unifi_client_from_settings() {
    let fake = FakeUnifi::start(FakeUnifi::standard()).await;
    let vars: std::collections::BTreeMap<&str, &str> = [
        ("NETPORTAL_DATABASE_URL", "postgresql://u:p@127.0.0.1:9/n"),
        ("NETPORTAL_UNIFI_URL", fake.url.as_str()),
        ("NETPORTAL_UNIFI_USER", UNIFI_USER),
        ("NETPORTAL_UNIFI_PASSWORD", UNIFI_PASSWORD),
    ]
    .into();
    let settings = netportal_core::config::IotSettings::from_env(&vars).expect("settings");
    let client = UnifiClient::new(&settings).expect("client").expect("configured");
    client.login().await.expect("login");
    let network = client.network_id("IoT").await;
    assert_eq!(network.map_err(|e| e.to_string()), Ok("n-iot".to_string()), "{:#?}", fake.requests());
    client.logout().await;
}
