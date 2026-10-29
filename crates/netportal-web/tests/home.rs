//! The home devices (house-infra docs/IOT-ACCESS.md 6.6) through the router: the overview, the
//! pages and actions of `/home`, the rights of the owner, a sharee, a stranger and an admin, the
//! key and its QR code (never for a sharee), the JSON API, the admin page, the old device path's
//! redirect, and that the Wi-Fi pages and the Let's Wi-Fi endpoints are as before.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::{Browser, Portal, admin, fresh_mac, newest_device, register_home, resident};
use netportal_core::registry;
use uuid::Uuid;

async fn psk_of(portal: &Portal, id: Uuid) -> String {
    portal.scalar(&format!("SELECT psk FROM iot_device WHERE device_id = '{id}'")).await
}

async fn mac_of(portal: &Portal, id: Uuid) -> Option<String> {
    portal.scalar(&format!("SELECT mac::text FROM iot_device WHERE device_id = '{id}'")).await
}

async fn actions(portal: &Portal, id: Uuid) -> Vec<String> {
    let mut db = portal.db().await;
    sqlx::query_scalar("SELECT action FROM audit WHERE device_id = $1 ORDER BY at, id")
        .bind(id)
        .fetch_all(db.tx().await.expect("tx"))
        .await
        .expect("audit")
}

/// A home device of this browser's person, registered with a fresh MAC.
async fn mine(b: &mut Browser<'_>, name: &str) -> Uuid {
    let (r, id) = register_home(b, name, "cast", &fresh_mac()).await;
    assert_eq!(r.status, StatusCode::FOUND, "{}", r.text());
    id.expect("the device's id")
}

async fn share(b: &mut Browser<'_>, id: Uuid, grantee: &str) -> common::Resp {
    let csrf = b.csrf().await;
    b.post(&format!("/home/devices/{id}/share"), &[("csrf", &csrf), ("grantee", grantee)]).await
}

#[tokio::test]
async fn test_overview_and_the_areas() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    // logged out: the landing page at /welcome, / to the login (no target), the areas to the
    // login with their target
    assert!(portal.get("/").await.to_login());
    assert_eq!(portal.get("/welcome").await.status, StatusCode::OK);
    let mut anon = portal.browser();
    assert!(anon.get("/home").await.to_login());
    let person = resident("ov");
    let callback = anon.login(&person).await;
    assert_eq!(callback.location().as_deref(), Some("/home"), "the login returns to the area asked for");
    let mut b = anon;
    // the overview: empty
    let r = b.get("/").await;
    assert_eq!(r.status, StatusCode::OK);
    let page = r.text();
    assert!(page.contains("<title>Scharni · Network</title>"), "{page}");
    assert!(page.contains(r#"<nav class="main-nav""#) && page.contains(r#"href="/" aria-current="page""#));
    assert!(page.contains(r#"href="/wifi""#) && page.contains(r#"href="/home""#) && !page.contains(r#"href="/admin""#));
    assert!(page.contains("No device in the house Wi-Fi yet.") && page.contains("No home devices yet."), "{page}");
    assert!(page.contains(r#"href="/wifi#add""#) && page.contains(r#"href="/home#add""#));
    // a Wi-Fi device (expiring soon), a home device of their own, one shared with them
    let (_, token) = b.enrol("apple", "old phone").await;
    b.get(&format!("/download/{}", token.expect("token"))).await;
    let wifi = newest_device(&portal, &person.sub).await;
    portal
        .exec(&format!("UPDATE credential SET not_after = now() + interval '3 days' WHERE device_id = '{wifi}'"))
        .await;
    let own = mine(&mut b, "my cast").await;
    let other = resident("ov2");
    let mut ob = portal.browser().logged_in(&other).await;
    let theirs = mine(&mut ob, "their printer").await;
    assert_eq!(share(&mut ob, theirs, &person.sub).await.status, StatusCode::FOUND);
    let page = b.get("/").await.text();
    assert!(page.contains("<strong>1</strong> <span>1 devices in the house Wi-Fi</span>"), "{page}");
    assert!(page.contains("Expiring soon: old phone"), "{page}");
    assert!(page.contains("<strong>1</strong> <span>1 of your own</span>"), "{page}");
    assert!(page.contains("<strong>1</strong> <span>1 shared with you</span>"), "{page}");
    // the Wi-Fi area shows certificate devices only, the home area home devices only
    let wifi_page = b.get("/wifi").await.text();
    assert!(wifi_page.contains("old phone") && !wifi_page.contains("my cast"), "{wifi_page}");
    assert!(
        wifi_page.contains(r#"action="/wifi/enroll""#)
            && wifi_page.contains(&format!(r#"href="/wifi/devices/{wifi}""#))
    );
    assert!(wifi_page.contains(r#"href="/wifi" aria-current="page""#));
    let api = b.get("/api/devices").await.json();
    let ids: Vec<&str> = api["devices"].as_array().expect("devices").iter().filter_map(|d| d["id"].as_str()).collect();
    assert_eq!(ids, [wifi.to_string()]);
    assert_eq!(b.get(&format!("/wifi/devices/{own}")).await.status, StatusCode::NOT_FOUND);
    assert_eq!(b.get(&format!("/api/devices/{own}")).await.error().as_deref(), Some("not_found"));
    let home_page = b.get("/home").await.text();
    assert!(home_page.contains("my cast") && home_page.contains("their printer") && !home_page.contains("old phone"));
    assert_eq!(b.get(&format!("/home/devices/{wifi}")).await.status, StatusCode::NOT_FOUND);
    // in German and Ukrainian too
    for (lang, word) in [("de", "Heimgeräte"), ("uk", "Домашні пристрої")] {
        b.lang = lang.into();
        let page = b.get("/home").await.text();
        assert!(page.contains(word), "{lang}: {page}");
        assert!(page.contains("Chrome") && page.contains("Netflix"), "{lang}: the sender matrix");
    }
    // the mails' and bookmarks' device links: a permanent redirect, without a session
    let r = portal.get(&format!("/devices/{wifi}")).await;
    assert_eq!(r.status, StatusCode::PERMANENT_REDIRECT);
    assert_eq!(r.location(), Some(format!("/wifi/devices/{wifi}")));
    assert!(r.set_cookies().is_empty());
    assert_eq!(portal.get("/devices/not-a-uuid").await.status, StatusCode::NOT_FOUND);
    assert_eq!(portal.get("/devices/").await.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_register_claim_and_the_key() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let person = resident("reg");
    let mut b = portal.browser().logged_in(&person).await;
    // without a MAC: the page with the key open, a QR code of the IoT network's Wi-Fi string
    let (r, id) = register_home(&mut b, "  Living room TV  ", "tv", "").await;
    assert_eq!(r.status, StatusCode::FOUND, "{}", r.text());
    let id = id.expect("id");
    assert_eq!(r.location(), Some(format!("/home/devices/{id}?key=1")));
    let psk = psk_of(&portal, id).await;
    assert_eq!(psk.len(), 20);
    let page = b.get(&format!("/home/devices/{id}?key=1")).await;
    assert_eq!(page.status, StatusCode::OK);
    let page = page.text();
    assert!(page.contains("<h1 class=\"dev-name-text\">Living room TV</h1>"), "{page}");
    assert!(page.contains(r#"<details class="key-box" open>"#), "{page}");
    assert!(page.contains(&format!(r#"<code class="psk">{psk}</code>"#)), "{page}");
    assert!(page.contains(r#"<svg class="qr" aria-hidden="true""#) && page.contains("Scharni-IoT"), "{page}");
    assert!(page.contains("not known yet") && page.contains("A device tried to join"), "{page}");
    assert!(page.contains("No unknown device tried to join in the last 15 minutes"), "{page}");
    let plain = b.get(&format!("/home/devices/{id}")).await.text();
    assert!(plain.contains(r#"<details class="key-box">"#), "closed without ?key=1");
    assert_eq!(actions(&portal, id).await, ["iot:register"]);
    let row = {
        let mut db = portal.db().await;
        registry::device(&mut db, id, None).await.expect("device").expect("row")
    };
    assert_eq!((row.platform.as_str(), row.name.as_str(), row.owner.as_str()), ("iot", "Living room TV", &*person.sub));
    assert_eq!(row.policy, "residents");
    // a join attempt (what FreeRADIUS records for an unknown MAC): offered on the list and the
    // device page with a claim button per device without an address
    let mac = fresh_mac();
    portal.exec(&format!("INSERT INTO iot_join_attempt (mac, tries, ssid) VALUES ('{mac}', 3, 'Scharni-IoT')")).await;
    let page = b.get("/home").await.text();
    assert!(page.contains(&format!(r#"<span class="mono">{mac}</span>"#)) && page.contains("3 tries"), "{page}");
    assert!(page.contains(&format!(r#"action="/home/devices/{id}/claim""#)) && page.contains("That is Living room TV"));
    let csrf = b.csrf().await;
    let r = b.post(&format!("/home/devices/{id}/claim"), &[("csrf", &csrf), ("mac", &mac), ("back", "/home")]).await;
    assert_eq!((r.status, r.location().as_deref()), (StatusCode::FOUND, Some("/home")));
    assert_eq!(mac_of(&portal, id).await.as_deref(), Some(mac.as_str()));
    let attempts: i64 = portal.scalar("SELECT count(*) FROM iot_join_attempt").await;
    assert_eq!(attempts, 0, "the attempt is consumed");
    let windows: i64 = portal.scalar(&format!("SELECT count(*) FROM device_mac WHERE device_id = '{id}'")).await;
    assert_eq!(windows, 1, "the MAC window the presence pipeline reads");
    let page = b.get(&format!("/home/devices/{id}")).await.text();
    assert!(page.contains(&format!(r#"<span class="mono">{mac}</span>"#)) && !page.contains("A device tried to join"));
    // with a MAC at registration; a bad one; one taken already; an unknown class
    let (r, second) = register_home(&mut b, "printer", "printer", "3C-22-FB-AA-BB-01").await;
    assert_eq!(r.status, StatusCode::FOUND, "{}", r.text());
    assert_eq!(mac_of(&portal, second.expect("id")).await.as_deref(), Some("3c:22:fb:aa:bb:01"));
    let (r, _) = register_home(&mut b, "bad", "printer", "not-a-mac").await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(r.text().contains("That is not a hardware address"), "{}", r.text());
    let (r, _) = register_home(&mut b, "taken", "printer", "3c:22:fb:aa:bb:01").await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert!(r.text().contains("registered for another device already"), "{}", r.text());
    let (r, _) = register_home(&mut b, "x", "toaster", "").await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let (r, named) = register_home(&mut b, "", "speaker", "").await;
    assert_eq!(r.status, StatusCode::FOUND);
    let mut db = portal.db().await;
    let row = registry::device(&mut db, named.expect("id"), None).await.expect("device").expect("row");
    assert_eq!(row.name, format!("Speaker ({})", person.username));
    // the device limit counts home devices too
    let limited = Portal::with(&admin_url, &[("NETPORTAL_MAX_DEVICES", "1")]).await;
    let mut lb = limited.browser().logged_in(&resident("lim")).await;
    mine(&mut lb, "one").await;
    let (r, _) = register_home(&mut lb, "two", "cast", "").await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert!(r.text().contains("limit of 1 devices"), "{}", r.text());
    // a new key: shown at once, audited
    let csrf = b.csrf().await;
    let r = b.post(&format!("/home/devices/{id}/rotate-key"), &[("csrf", &csrf)]).await;
    assert_eq!(r.location(), Some(format!("/home/devices/{id}?key=1")));
    let rotated = psk_of(&portal, id).await;
    assert_ne!(rotated, psk);
    assert!(b.get(&format!("/home/devices/{id}?key=1")).await.text().contains(&rotated));
    assert_eq!(actions(&portal, id).await, ["iot:register", "iot:claim", "iot:rotate-key"]);
    // every POST needs the CSRF token
    assert_eq!(b.post(&format!("/home/devices/{id}/rotate-key"), &[]).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(b.post("/home/register", &[("class", "cast")]).await.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_sharing_visibility_rename_and_remove() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let owner = resident("own");
    let mut b = portal.browser().logged_in(&owner).await;
    let friend = resident("frd");
    let mut fb = portal.browser().logged_in(&friend).await;
    let id = mine(&mut b, "kitchen speaker").await;
    // the share picker offers the friend (not the owner); the share takes effect in the view
    let page = b.get(&format!("/home/devices/{id}")).await.text();
    assert!(
        page.contains(&format!(r#"<option value="{}">"#, friend.sub))
            && !page.contains(&format!(r#"<option value="{}">"#, owner.sub))
    );
    assert!(page.contains("Shared with nobody yet."));
    assert_eq!(share(&mut b, id, &friend.sub).await.location(), Some(format!("/home/devices/{id}")));
    let page = b.get(&format!("/home/devices/{id}")).await.text();
    assert!(page.contains(&friend.name) && page.contains("shared with 1 people"), "{page}");
    assert!(page.contains(&format!(r#"<input type="hidden" name="grantee" value="{}">"#, friend.sub)));
    assert!(page.contains("Nobody else to share with yet."), "the only candidate is shared with already");
    assert!(share(&mut b, id, &owner.sub).await.status == StatusCode::BAD_REQUEST, "the owner is no grantee");
    assert!(share(&mut b, id, "sub-nobody").await.status == StatusCode::BAD_REQUEST);
    // the friend's list and page: the device, its owner, no key, no forms
    let list = fb.get("/home").await.text();
    assert!(list.contains("kitchen speaker") && list.contains(&format!("shared by {}", owner.name)), "{list}");
    let page = fb.get(&format!("/home/devices/{id}")).await;
    assert_eq!(page.status, StatusCode::OK);
    let page = page.text();
    let psk = psk_of(&portal, id).await;
    assert!(!page.contains(&psk) && !page.contains("class=\"psk\"") && !page.contains("<svg class=\"qr\""), "{page}");
    assert!(!page.contains(&format!("/home/devices/{id}/")), "no action forms for a sharee: {page}");
    assert!(page.contains(&format!("{} shared this device with you", owner.name)), "{page}");
    // visibility: house-visible devices reach everyone with a policy
    let stranger = resident("str");
    let mut sb = portal.browser().logged_in(&stranger).await;
    assert_eq!(sb.get(&format!("/home/devices/{id}")).await.status, StatusCode::NOT_FOUND);
    let csrf = b.csrf().await;
    let r = b.post(&format!("/home/devices/{id}/visibility"), &[("csrf", &csrf), ("visibility", "house")]).await;
    assert_eq!(r.status, StatusCode::FOUND);
    assert_eq!(sb.get(&format!("/home/devices/{id}")).await.status, StatusCode::OK);
    assert!(sb.get("/home").await.text().contains("kitchen speaker"));
    let csrf = b.csrf().await;
    assert_eq!(
        b.post(&format!("/home/devices/{id}/visibility"), &[("csrf", &csrf), ("visibility", "everyone")]).await.status,
        StatusCode::BAD_REQUEST
    );
    let csrf = b.csrf().await;
    b.post(&format!("/home/devices/{id}/visibility"), &[("csrf", &csrf), ("visibility", "private")]).await;
    assert_eq!(sb.get(&format!("/home/devices/{id}")).await.status, StatusCode::NOT_FOUND);
    // unshare
    let csrf = b.csrf().await;
    b.post(&format!("/home/devices/{id}/unshare"), &[("csrf", &csrf), ("grantee", &friend.sub)]).await;
    assert_eq!(fb.get(&format!("/home/devices/{id}")).await.status, StatusCode::NOT_FOUND);
    assert!(!fb.get("/home").await.text().contains("kitchen speaker"));
    // rename: the form, the JSON variant, nothing for an empty name
    let csrf = b.csrf().await;
    let r = b.post(&format!("/home/devices/{id}/rename"), &[("csrf", &csrf), ("name", "  hall speaker  ")]).await;
    assert_eq!(r.location(), Some(format!("/home/devices/{id}")));
    let r = b
        .post_with(
            &format!("/home/devices/{id}/rename"),
            &[("csrf", &csrf), ("name", "")],
            &[("accept", "application/json")],
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(r.json()["name"], "hall speaker");
    let r = b
        .post_with(
            &format!("/home/devices/{id}/rename"),
            &[("csrf", &csrf), ("name", "hall")],
            &[("accept", "application/json")],
        )
        .await;
    assert_eq!((r.status, r.json()["ok"].as_bool()), (StatusCode::OK, Some(true)));
    // remove: revoked with the audit, no Disconnect; gone from every page and API
    let csrf = b.csrf().await;
    let r = b.post(&format!("/home/devices/{id}/remove"), &[("csrf", &csrf), ("back", "/home")]).await;
    assert_eq!((r.status, r.location().as_deref()), (StatusCode::FOUND, Some("/home")));
    let mut db = portal.db().await;
    let row = registry::device(&mut db, id, None).await.expect("device").expect("row");
    assert!(row.revoked_at.is_some());
    let acts = actions(&portal, id).await;
    assert_eq!(acts.last().map(String::as_str), Some("iot:remove"));
    assert!(acts.iter().any(|a| a == &format!("iot:share:{}", friend.sub)));
    assert!(acts.iter().any(|a| a == &format!("iot:unshare:{}", friend.sub)));
    assert!(acts.iter().any(|a| a == "iot:visibility:house"));
    assert!(!acts.iter().any(|a| a.starts_with("disconnect:")));
    assert_eq!(b.get(&format!("/home/devices/{id}")).await.status, StatusCode::NOT_FOUND);
    assert_eq!(b.get(&format!("/api/home/devices/{id}")).await.error().as_deref(), Some("not_found"));
    assert!(!b.get("/home").await.text().contains("hall"));
}

#[tokio::test]
async fn test_rights_of_a_sharee_a_stranger_and_an_admin() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let owner = resident("own");
    let mut b = portal.browser().logged_in(&owner).await;
    let friend = resident("frd");
    let mut fb = portal.browser().logged_in(&friend).await;
    let mut sb = portal.browser().logged_in(&resident("str")).await;
    let id = mine(&mut b, "tv").await;
    share(&mut b, id, &friend.sub).await;
    let posts = ["claim", "rotate-key", "share", "unshare", "visibility", "rename", "remove"];
    // a sharee may look, not change (403); a stranger gets 404 everywhere
    for action in posts {
        let csrf = fb.csrf().await;
        let fields = [
            ("csrf", csrf.as_str()),
            ("name", "x"),
            ("mac", "3c:22:fb:00:00:01"),
            ("visibility", "house"),
            ("grantee", "x"),
        ];
        let r = fb.post(&format!("/home/devices/{id}/{action}"), &fields).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{action} by a sharee: {}", r.text());
        let csrf = sb.csrf().await;
        let fields = [
            ("csrf", csrf.as_str()),
            ("name", "x"),
            ("mac", "3c:22:fb:00:00:01"),
            ("visibility", "house"),
            ("grantee", "x"),
        ];
        let r = sb.post(&format!("/home/devices/{id}/{action}"), &fields).await;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{action} by a stranger");
    }
    assert_eq!(sb.get(&format!("/home/devices/{id}")).await.status, StatusCode::NOT_FOUND);
    assert_eq!(sb.get(&format!("/api/home/devices/{id}")).await.error().as_deref(), Some("not_found"));
    let mut db = portal.db().await;
    let row = registry::device(&mut db, id, None).await.expect("device").expect("row");
    assert!(row.revoked_at.is_none() && row.name == "tv", "nothing changed");
    assert_eq!(actions(&portal, id).await, ["iot:register", &format!("iot:share:{}", friend.sub)]);
    // an admin: everything an owner can, on anyone's device, the audit naming the admin
    let adm = admin("adm");
    let mut ab = portal.browser().logged_in(&adm).await;
    let page = ab.get(&format!("/home/devices/{id}?from=admin")).await;
    assert_eq!(page.status, StatusCode::OK);
    let page = page.text();
    let psk = psk_of(&portal, id).await;
    assert!(
        page.contains(&psk) && page.contains("<svg class=\"qr\"") && page.contains(r#"href="/admin/home""#),
        "{page}"
    );
    let csrf = ab.csrf().await;
    let r = ab.post(&format!("/home/devices/{id}/rename"), &[("csrf", &csrf), ("name", "the tv")]).await;
    assert_eq!(r.status, StatusCode::FOUND);
    let mac = fresh_mac();
    let r =
        ab.post(&format!("/home/devices/{id}/claim"), &[("csrf", &csrf), ("mac", &mac), ("back", "/admin/home")]).await;
    assert_eq!((r.status, r.location().as_deref()), (StatusCode::FOUND, Some("/admin/home")));
    assert_eq!(mac_of(&portal, id).await.as_deref(), Some(mac.as_str()));
    let actor: String =
        portal.scalar(&format!("SELECT actor FROM audit WHERE device_id = '{id}' AND action = 'iot:claim'")).await;
    assert_eq!(actor, adm.sub);
    // the admin page and its API: every device with owner, MAC, class, visibility, shares, sync
    portal
        .exec(&format!(
            "INSERT INTO iot_sync (target, key, status, detail) VALUES ('unifi_key', '{id}', 'applied', ''),
             ('opnsense_alias', '{id}', 'failed', 'alias_util: 502')"
        ))
        .await;
    portal.exec("INSERT INTO iot_join_attempt (mac, tries) VALUES ('3c:22:fb:ee:ee:01', 1)").await;
    let page = ab.get("/admin/home").await;
    assert_eq!(page.status, StatusCode::OK);
    let page = page.text();
    assert!(page.contains("the tv") && page.contains(&owner.name) && page.contains(&mac), "{page}");
    assert!(page.contains("failed: alias_util: 502") && page.contains("opnsense_alias"), "{page}");
    assert!(page.contains("3c:22:fb:ee:ee:01") && page.contains(&friend.name), "{page}");
    assert!(page.contains(r#"href="/admin/home" aria-current="page""#), "{page}");
    assert!(ab.get("/admin").await.text().contains(r#"href="/admin/home""#), "linked from the admin page");
    let api = ab.get("/api/admin/home/devices").await;
    assert_eq!(api.status, StatusCode::OK);
    let api = api.json();
    let devices = api["devices"].as_array().expect("devices");
    let d = devices.iter().find(|d| d["id"] == id.to_string()).expect("the device");
    assert_eq!(d["owner"]["sub"], owner.sub);
    assert_eq!(d["mac"], mac);
    assert_eq!(d["class"], "cast");
    assert_eq!(d["visibility"], "private");
    assert_eq!(d["shares"][0]["sub"], friend.sub);
    assert_eq!(d["sync"]["status"], "failed");
    assert_eq!(d["sync_targets"].as_array().map(Vec::len), Some(2));
    assert!(d.get("psk").is_none(), "the list API carries no keys");
    assert_eq!(api["attempts"][0]["mac"], "3c:22:fb:ee:ee:01");
    // the sync line on the owner's pages
    let page = b.get("/home").await.text();
    assert!(page.contains("Firewall and Wi-Fi: failed: alias_util: 502"), "{page}");
    // residents: no admin page, no admin API
    assert_eq!(b.get("/admin/home").await.status, StatusCode::FORBIDDEN);
    assert_eq!(b.get("/api/admin/home/devices").await.error().as_deref(), Some("forbidden"));
    // the key of a removed device is nobody's business any more: 404 for the admin too
    let csrf = ab.csrf().await;
    ab.post(&format!("/home/devices/{id}/remove"), &[("csrf", &csrf)]).await;
    assert_eq!(ab.get(&format!("/home/devices/{id}")).await.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_the_json_api() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let owner = resident("own");
    let mut b = portal.browser().logged_in(&owner).await;
    let friend = resident("frd");
    let mut fb = portal.browser().logged_in(&friend).await;
    let id = mine(&mut b, "cast").await;
    let theirs = mine(&mut fb, "printer").await;
    share(&mut fb, theirs, &owner.sub).await;
    assert_eq!(portal.get("/api/home/devices").await.error().as_deref(), Some("login_required"));
    let r = b.get("/api/home/devices").await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.header("cache-control").as_deref(), Some("private, no-store"));
    let tag = r.header("etag").expect("etag");
    let body = r.json();
    assert_eq!(body["telemetry"], "off");
    let devices = body["devices"].as_array().expect("devices");
    assert_eq!(devices.len(), 2);
    let own = &devices[0];
    assert_eq!(
        (own["id"].as_str(), own["role"].as_str(), own["name"].as_str()),
        (Some(&*id.to_string()), Some("owner"), Some("cast"))
    );
    // registered with a MAC: its window exists, so the pipeline says unknown rather than never
    assert!(["unknown", "never_connected"].contains(&own["state"].as_str().unwrap_or("")), "{own}");
    assert!(own["mac"].is_string() && own["sync"]["status"] == "pending" && own["claimed"] == true);
    assert_eq!(own["shares"].as_array().map(Vec::len), Some(0));
    let shared = &devices[1];
    assert_eq!((shared["id"].as_str(), shared["role"].as_str()), (Some(&*theirs.to_string()), Some("shared")));
    assert_eq!(shared["owner"]["sub"], friend.sub);
    assert!(shared.get("mac").is_none() && shared.get("sync").is_none());
    let text = r.text();
    assert!(
        !text.contains(&psk_of(&portal, id).await) && !text.contains(&psk_of(&portal, theirs).await),
        "no key in the list"
    );
    assert_eq!(b.get_with("/api/home/devices", &[("if-none-match", &tag)]).await.status, StatusCode::NOT_MODIFIED);
    // one device: the key for the owner, not for a sharee; 404 for a stranger
    let one = b.get(&format!("/api/home/devices/{id}")).await.json();
    assert_eq!(one["device"]["psk"], psk_of(&portal, id).await);
    assert_eq!(one["device"]["shares"].as_array().map(Vec::len), Some(0));
    let one = b.get(&format!("/api/home/devices/{theirs}")).await;
    assert_eq!(one.status, StatusCode::OK);
    assert!(!one.text().contains(&psk_of(&portal, theirs).await));
    assert_eq!(one.json()["device"]["role"], "shared");
    assert!(one.json()["device"].get("psk").is_none());
    let mut sb = portal.browser().logged_in(&resident("str")).await;
    assert_eq!(sb.get(&format!("/api/home/devices/{id}")).await.error().as_deref(), Some("not_found"));
    assert_eq!(sb.get("/api/home/devices").await.json()["devices"].as_array().map(Vec::len), Some(0));
}

#[tokio::test]
async fn test_metrics_count_the_home_devices() {
    let admin_url = need_db!();
    let portal = Portal::with(&admin_url, &[("NETPORTAL_METRICS_LISTEN", "127.0.0.1:0")]).await;
    let mut b = portal.browser().logged_in(&resident("met")).await;
    let id = mine(&mut b, "cast").await;
    portal.exec(&format!("INSERT INTO iot_sync (target, key, status) VALUES ('unifi_key', '{id}', 'pending'), ('opnsense_alias', 'x', 'failed')")).await;
    portal
        .exec("INSERT INTO iot_join_attempt (mac, tries) VALUES ('3c:22:fb:ee:ee:02', 1), ('3c:22:fb:ee:ee:03', 2)")
        .await;
    portal
        .exec(
            "INSERT INTO job (name, last_attempt, last_success, cursor) VALUES ('iot', now(), now(),
             '{\"devices\": 1, \"shares\": 0, \"sync_pending\": 1, \"sync_failed\": 1, \"address_conflicts\": 2, \"unifi_ok\": 1, \"opnsense_ok\": 0}')",
        )
        .await;
    let r = portal.call_metrics(Request::get("/metrics").body(Body::empty()).expect("request")).await;
    assert_eq!(r.status, StatusCode::OK);
    let text = r.text();
    for line in [
        "netportal_iot_devices 1",
        "netportal_iot_shares 0",
        "netportal_iot_sync{status=\"pending\"} 1",
        "netportal_iot_sync{status=\"failed\"} 1",
        "netportal_iot_address_conflicts 2",
        "netportal_iot_backend_ok{backend=\"unifi\"} 1",
        "netportal_iot_backend_ok{backend=\"opnsense\"} 0",
        "netportal_iot_join_attempts 2",
        "netportal_job_up{job=\"iot\"} 1",
        "netportal_devices{state=\"active\"} 1",
    ] {
        assert!(text.lines().any(|l| l.starts_with(line)), "{line} missing in\n{text}");
    }
}

#[tokio::test]
async fn test_the_letswifi_endpoints_are_where_they_were() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let r = portal.get("/.well-known/letswifi.json").await;
    assert_eq!(r.status, StatusCode::OK);
    let doc = r.json();
    assert_eq!(
        doc["http://letswifi.app/api#v2"]["authorization_endpoint"],
        format!("{}/oauth/authorize", common::BASE_URL)
    );
    assert_eq!(doc["http://letswifi.app/api#v2"]["token_endpoint"], format!("{}/oauth/token", common::BASE_URL));
    assert_eq!(
        doc["http://letswifi.app/api#v2"]["eapconfig_endpoint"],
        format!("{}/api/eap-config/", common::BASE_URL)
    );
    let probe = Request::get("/").header(header::ACCEPT, "application/json").body(Body::empty()).expect("request");
    assert_eq!(portal.call(probe).await.json(), doc);
    assert_eq!(portal.post_form("/oauth/token", &[], &[]).await.error().as_deref(), Some("invalid_client"));
    assert_eq!(portal.post_form("/api/eap-config/", &[], &[]).await.error().as_deref(), Some("invalid_token"));
    assert_eq!(portal.post_form("/api/eap-config", &[], &[]).await.error().as_deref(), Some("invalid_token"));
    assert!(portal.browser().get("/oauth/authorize?client_id=app.eduroam.geteduroam").await.to_login());
}
