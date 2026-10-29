//! Sessions, login, logout, CSRF and rights (Python tests/test_web.py, INVENTORY 4.1-4.4, 3.1),
//! through the router with a fake OIDC provider and a throwaway registry, with a test clock for
//! the 8 h idle and 12 h absolute limits (Rust-only: the black-box suite cannot age a cookie).

mod common;

use axum::http::{Method, StatusCode};
use common::{Portal, admin, newest_device, resident};
use netportal_core::registry;

const HOUR: i64 = 3600;

#[tokio::test]
async fn test_admin_from_the_registry() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let mut b = portal.browser().logged_in(&admin("adm")).await;
    assert_eq!(b.get("/admin").await.status, StatusCode::OK);
}

#[tokio::test]
async fn test_removed_from_the_admin_group_loses_admin_at_once() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let person = admin("adm");
    let mut b = portal.browser().logged_in(&person).await;
    assert_eq!(b.get("/admin").await.status, StatusCode::OK);
    let mut db = portal.db().await;
    // the offboarding round takes the right away: the portal sessions end at once (security
    // review L2), the next login gets the groups from Authentik
    registry::set_admin(&mut db, &person.sub, false).await.expect("admin");
    db.commit().await.expect("commit");
    assert!(b.get("/admin").await.to_login());
    assert_eq!(b.get("/api/admin/devices").await.error().as_deref(), Some("login_required"));
    let mut person = person;
    person.groups = vec!["residents".into()];
    b.login(&person).await;
    let r = b.get("/admin").await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert!(r.is_page());
    let page = b.get("/").await.text();
    assert!(!page.contains("href=\"/admin\""), "{page}");
    assert_eq!(b.get("/api/admin/devices").await.error().as_deref(), Some("forbidden"));
}

#[tokio::test]
async fn test_the_cookie_cannot_claim_admin() {
    // the cookie carries no right at all: a resident is no admin, whatever the cookie held
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let mut b = portal.browser().logged_in(&resident("res")).await;
    assert_eq!(b.get("/admin").await.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_admin_can_revoke_others_only_while_admin() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let owner = resident("own");
    let mut ob = portal.browser().logged_in(&owner).await;
    ob.enrol("apple", "theirs").await;
    let device = newest_device(&portal, &owner.sub).await;
    let person = admin("adm");
    let mut ab = portal.browser().logged_in(&person).await;
    let mut db = portal.db().await;
    registry::set_admin(&mut db, &person.sub, false).await.expect("admin");
    db.commit().await.expect("commit");
    let csrf = ab.csrf().await;
    let r = ab.post(&format!("/wifi/devices/{device}/revoke"), &[("csrf", &csrf)]).await;
    assert!(r.to_login(), "{:?}", r.status); // the session ended with the right (L2)
    let mut person = person;
    person.groups = vec!["residents".into()];
    ab.login(&person).await;
    let csrf = ab.csrf().await;
    let r = ab.post(&format!("/wifi/devices/{device}/revoke"), &[("csrf", &csrf)]).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND); // only their own devices now
    let row = registry::device(&mut db, device, None).await.expect("device").expect("row");
    assert!(row.revoked_at.is_none());
}

#[tokio::test]
async fn test_offboarded_goes_to_the_login() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let person = admin("adm");
    let mut b = portal.browser().logged_in(&person).await;
    let token = b.csrf().await;
    let mut db = portal.db().await;
    registry::offboard_person(&mut db, &person.sub).await.expect("offboard");
    db.commit().await.expect("commit");
    assert!(b.get("/admin").await.to_login());
    assert_eq!(b.get("/api/devices").await.error().as_deref(), Some("login_required"));
    // the CSRF token stays: a form sent now goes through the login, not into a CSRF error
    assert_eq!(b.csrf().await, token);
    assert!(b.post("/wifi/enroll", &[("csrf", &token), ("format", "apple")]).await.to_login());
}

#[tokio::test]
async fn test_an_old_login_ends_however_busy() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let mut b = portal.browser().logged_in(&admin("adm")).await;
    // used every hour: the idle limit never ends it, the 12 h limit after the login does
    for _ in 0..11 {
        portal.clock.advance(HOUR);
        assert_eq!(b.get("/admin").await.status, StatusCode::OK);
    }
    portal.clock.advance(HOUR - 60);
    assert_eq!(b.get("/admin").await.status, StatusCode::OK);
    portal.clock.advance(60);
    let r = b.get("/admin").await;
    assert!(r.to_login(), "{:?}", r.status);
    assert_eq!(b.get("/api/devices").await.error().as_deref(), Some("login_required"));
}

#[tokio::test]
async fn test_an_idle_session_ends_after_eight_hours() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let mut b = portal.browser().logged_in(&resident("idle")).await;
    portal.clock.advance(8 * HOUR - 60);
    assert_eq!(b.get("/").await.status, StatusCode::OK); // used: the idle time starts again
    portal.clock.advance(3 * HOUR);
    assert_eq!(b.get("/api/devices").await.status, StatusCode::OK);
    // 8 h without a request (and still within 12 h of the login): ended on the server
    let mut idle = portal.browser().logged_in(&resident("idle2")).await;
    portal.clock.advance(2 * HOUR);
    assert_eq!(idle.get("/").await.status, StatusCode::OK);
    portal.clock.advance(8 * HOUR);
    assert!(idle.get("/").await.to_login());
    assert_eq!(idle.get("/api/devices").await.error().as_deref(), Some("login_required"));
}

#[tokio::test]
async fn test_the_cookie_expires_eight_hours_after_the_last_request() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let mut b = portal.browser();
    let anonymous = b.get("/welcome").await.set_cookies();
    assert_eq!(anonymous.len(), 1);
    assert!(!anonymous[0].attrs.contains_key("max-age") && !anonymous[0].attrs.contains_key("expires"));
    let callback = b.login(&resident("ck")).await;
    let cookies = callback.set_cookies();
    assert_eq!(cookies.len(), 1);
    let c = &cookies[0];
    assert_eq!(c.name, "netportal");
    assert_eq!(c.attrs.get("max-age").map(String::as_str), Some("28800"));
    assert!(c.attrs.contains_key("httponly") && !c.attrs.contains_key("secure") && !c.attrs.contains_key("domain"));
    assert_eq!(c.attrs.get("samesite").map(String::as_str), Some("Lax"));
    assert_eq!(c.attrs.get("path").map(String::as_str), Some("/"));
    for path in ["/", "/api/devices"] {
        let again = b.get(path).await.set_cookies();
        assert_eq!(again.len(), 1, "{path}: the idle expiry moves with the request");
        assert_eq!(again[0].attrs.get("max-age").map(String::as_str), Some("28800"));
    }
}

#[tokio::test]
async fn test_https_gives_a_host_cookie() {
    let admin_url = need_db!();
    let portal = Portal::with(&admin_url, &[("NETPORTAL_BASE_URL", "https://wifi.test")]).await;
    let mut b = portal.browser();
    let cookies = b.get("/welcome").await.set_cookies();
    assert_eq!(cookies[0].name, "__Host-netportal");
    assert!(cookies[0].attrs.contains_key("secure"));
    b.login(&resident("https")).await;
    assert_eq!(b.get("/").await.status, StatusCode::OK);
}

#[tokio::test]
async fn test_a_form_sent_after_the_limit_goes_to_the_login() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let mut b = portal.browser().logged_in(&resident("res")).await;
    let csrf = b.csrf().await;
    portal.clock.advance(12 * HOUR);
    assert!(b.post("/wifi/enroll", &[("csrf", &csrf), ("format", "apple")]).await.to_login());
}

#[tokio::test]
async fn test_a_page_asked_for_after_the_limit_is_where_the_login_goes_back_to() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let person = admin("adm");
    let mut b = portal.browser().logged_in(&person).await;
    portal.clock.advance(12 * HOUR);
    assert!(b.get("/admin?q=x").await.to_login());
    let callback = b.login(&person).await;
    assert_eq!(callback.location().as_deref(), Some("/admin?q=x"));
}

#[tokio::test]
async fn test_a_form_sent_after_the_limit_goes_back_to_a_page_not_to_its_post_url() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let person = admin("adm");
    let mut b = portal.browser().logged_in(&person).await;
    let id = "00000000-0000-4000-8000-000000000001";
    for (path, back, want) in [
        ("/wifi/enroll", "", "/"),
        (&format!("/wifi/devices/{id}/revoke") as &str, "/admin", "/admin"),
        (&format!("/wifi/devices/{id}/revoke"), "https://evil.example.org/", "/"),
        (&format!("/wifi/devices/{id}/revoke"), "//evil.example.org/", "/"),
    ] {
        let csrf = b.csrf().await;
        portal.clock.advance(12 * HOUR);
        assert!(b.post(path, &[("csrf", &csrf), ("format", "apple"), ("back", back)]).await.to_login());
        let callback = b.login(&person).await;
        assert_eq!(callback.location().as_deref(), Some(want), "{path} {back}");
        assert_eq!(b.get(want).await.status, StatusCode::OK); // not 405
    }
}

#[tokio::test]
async fn test_a_consent_sent_after_the_limit_shows_the_consent_page_again() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let person = resident("res");
    let mut b = portal.browser().logged_in(&person).await;
    let csrf = b.csrf().await;
    portal.clock.advance(12 * HOUR);
    let fields = [
        ("csrf", csrf.as_str()),
        ("name", "Example phone"),
        ("client_id", "app.eduroam.geteduroam"),
        ("redirect_uri", "app.eduroam.geteduroam:/"),
        ("response_type", "code"),
        ("state", "example-state"),
        ("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
        ("code_challenge_method", "S256"),
    ];
    assert!(b.post("/oauth/authorize", &fields).await.to_login());
    let callback = b.login(&person).await;
    let next = callback.location().expect("location");
    let (path, query) = next.split_once('?').expect("query");
    assert_eq!(path, "/oauth/authorize");
    let sent: Vec<(String, String)> = url::form_urlencoded::parse(query.as_bytes()).into_owned().collect();
    let want: Vec<(String, String)> = fields
        .iter()
        .filter(|(k, _)| !["csrf", "name"].contains(k))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let mut sent_sorted = sent.clone();
    sent_sorted.sort();
    let mut want_sorted = want;
    want_sorted.sort();
    assert_eq!(sent_sorted, want_sorted);
    let page = b.get(&next).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.text().contains("name=\"code_challenge\""));
}

#[tokio::test]
async fn test_the_login_records_its_time_and_the_rights_go_to_the_registry() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let person = admin("adm");
    let mut b = portal.browser();
    let callback = b.login(&person).await;
    assert_eq!(callback.status, StatusCode::FOUND);
    assert_eq!(callback.location().as_deref(), Some("/"));
    let mut db = portal.db().await;
    let state = registry::person_state(&mut db, &person.sub).await.expect("state").expect("person");
    assert!(state.is_admin);
    let policy = registry::person_policy(&mut db, &person.sub).await.expect("policy");
    assert_eq!(policy.as_deref(), Some("residents")); // an admin outside every policy: the first
    let recent: bool = portal
        .scalar(&format!("SELECT last_login_at > now() - interval '1 minute' FROM person WHERE sub = '{}'", person.sub))
        .await;
    assert!(recent);
}

#[tokio::test]
async fn test_login_rotates_the_session() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let mut b = portal.browser();
    let before = b.csrf().await;
    let anonymous = b.cookies.clone();
    b.login(&resident("rot")).await;
    let after = b.csrf().await;
    assert_ne!(before, after);
    assert_ne!(anonymous, b.cookies);
    assert_eq!(b.post("/logout", &[("csrf", &before)]).await.status, StatusCode::BAD_REQUEST);
    // the cookie from before the login is not the logged-in session (no fixation)
    let mut other = portal.browser();
    other.cookies = anonymous;
    assert!(other.get("/").await.to_login());
}

#[tokio::test]
async fn test_tampered_or_foreign_cookie_is_no_session() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let mut b = portal.browser().logged_in(&resident("tmp")).await;
    let cookies = b.cookies.clone();
    for value in b.cookies.values_mut() {
        let cut = value.len() - 2;
        value.replace_range(cut.., if value.ends_with("AA") { "BB" } else { "AA" });
    }
    assert!(b.get("/").await.to_login());
    let other =
        Portal::with(&admin_url, &[("NETPORTAL_SESSION_SECRET", "another-session-secret-0123456789abcdef")]).await;
    let mut ob = other.browser();
    ob.cookies = cookies;
    assert!(ob.get("/").await.to_login());
}

#[tokio::test]
async fn test_logout_ends_only_this_session() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let person = resident("out");
    let mut phone = portal.browser().logged_in(&person).await;
    let mut laptop = portal.browser().logged_in(&person).await;
    let copy = phone.cookies.clone();
    let csrf = phone.csrf().await;
    let r = phone.post("/logout", &[("csrf", &csrf)]).await;
    assert_eq!(r.status, StatusCode::FOUND);
    assert_eq!(r.location().as_deref(), Some(common::LOGOUT_URL));
    assert!(phone.cookies.is_empty(), "the cookie is removed");
    assert!(phone.get("/").await.to_login());
    // a copy of the cookie (or a response in flight that sets it again) is no session either:
    // the session ended on the server
    let mut stolen = portal.browser();
    stolen.cookies = copy;
    assert!(stolen.get("/").await.to_login());
    // the person's other sessions stay
    assert_eq!(laptop.get("/").await.status, StatusCode::OK);
    let open: i64 = portal
        .scalar(&format!("SELECT count(*) FROM web_session WHERE sub = '{}' AND ended_at IS NULL", person.sub))
        .await;
    assert_eq!(open, 1);
}

#[tokio::test]
async fn test_logout_everywhere_ends_every_session_of_the_person() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let person = resident("all");
    let other = resident("other");
    let mut phone = portal.browser().logged_in(&person).await;
    let mut laptop = portal.browser().logged_in(&person).await;
    let mut someone = portal.browser().logged_in(&other).await;
    let copy = laptop.cookies.clone();
    let page = phone.get("/").await.text();
    assert!(page.contains(r#"<form method="post" action="/logout/all" class="inline">"#), "{page}");
    // CSRF as every POST
    assert_eq!(phone.post("/logout/all", &[]).await.status, StatusCode::BAD_REQUEST);
    let csrf = phone.csrf().await;
    let r = phone.post("/logout/all", &[("csrf", &csrf)]).await;
    assert_eq!(r.status, StatusCode::FOUND);
    assert_eq!(r.location().as_deref(), Some(common::LOGOUT_URL));
    assert!(phone.cookies.is_empty());
    for b in [&mut phone, &mut laptop] {
        assert!(b.get("/").await.to_login());
    }
    let mut stolen = portal.browser();
    stolen.cookies = copy;
    assert!(stolen.get("/").await.to_login());
    // nobody else's
    assert_eq!(someone.get("/").await.status, StatusCode::OK);
    // the next login is a new session
    laptop.login(&person).await;
    assert_eq!(laptop.get("/").await.status, StatusCode::OK);
}

#[tokio::test]
async fn test_a_stale_cookie_cannot_log_the_person_out_everywhere() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let person = resident("stale-all");
    let mut current = portal.browser().logged_in(&person).await;
    let mut copy = portal.browser().logged_in(&person).await;
    let saved = copy.cookies.clone();
    let token = copy.csrf().await;
    copy.post("/logout", &[("csrf", &token)]).await;
    // a copy of that ended session's cookie (its CSRF token still matches): it ends nothing else
    let mut replay = portal.browser();
    replay.cookies = saved;
    let r = replay.post("/logout/all", &[("csrf", &token)]).await;
    assert_eq!(r.status, StatusCode::FOUND);
    assert_eq!(current.get("/").await.status, StatusCode::OK);
}

#[tokio::test]
async fn test_a_stale_cookie_cannot_log_the_person_out() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let person = resident("stale");
    let mut old = portal.browser().logged_in(&person).await;
    let old_csrf = old.csrf().await;
    let mut fresh = portal.browser().logged_in(&person).await;
    let csrf = fresh.csrf().await;
    fresh.post("/logout", &[("csrf", &csrf)]).await;
    let mut current = portal.browser().logged_in(&person).await;
    // the old cookie is dead; its logout does not end the new session
    old.post("/logout", &[("csrf", &old_csrf)]).await;
    assert_eq!(current.get("/").await.status, StatusCode::OK);
}

#[tokio::test]
async fn test_an_offboarded_cookie_stays_dead_after_a_new_login() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let person = resident("again");
    let b = portal.browser().logged_in(&person).await;
    let copy = b.cookies.clone();
    let mut db = portal.db().await;
    registry::offboard_person(&mut db, &person.sub).await.expect("offboard");
    db.commit().await.expect("commit");
    let mut again = portal.browser().logged_in(&person).await; // the login clears offboarded
    assert_eq!(again.get("/").await.status, StatusCode::OK);
    let mut old = portal.browser();
    old.cookies = copy;
    assert!(old.get("/").await.to_login());
}

#[tokio::test]
async fn test_logout_without_a_login() {
    let admin_url = need_db!();
    let portal = Portal::with(&admin_url, &[("NETPORTAL_LOGOUT_URL", "")]).await;
    let mut b = portal.browser();
    let csrf = b.csrf().await;
    let r = b.post("/logout", &[("csrf", &csrf)]).await;
    assert_eq!(r.location().as_deref(), Some("/"));
    assert_eq!(b.post("/logout", &[]).await.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_csrf_rules() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let person = resident("csrf");
    let mut b = portal.browser().logged_in(&person).await;
    b.enrol("apple", "csrf device").await;
    let device = newest_device(&portal, &person.sub).await;
    let path = format!("/wifi/devices/{device}/rename");
    let csrf = b.csrf().await;
    for sent in ["", "wrong", &format!("{csrf}x")] {
        let r = b.post(&path, &[("csrf", sent), ("name", "changed")]).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{sent:?}");
        assert!(r.is_page());
    }
    // only the form field counts
    let r = b.post_with(&path, &[("name", "x")], &[("x-csrf-token", &csrf)]).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    // a script's POST with a wrong token: JSON
    let r = b.post_with(&path, &[("csrf", "wrong"), ("name", "x")], &[("accept", "application/json")]).await;
    assert_eq!((r.status, r.error().as_deref()), (StatusCode::BAD_REQUEST, Some("bad_request")));
    // a POST to a GET-only route is 405 (with Allow), not a CSRF error
    let r = b.post("/admin", &[]).await;
    assert_eq!(r.status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(r.header("allow").as_deref(), Some("GET,HEAD"));
    let mut db = portal.db().await;
    assert_eq!(registry::device(&mut db, device, None).await.expect("d").expect("row").name, "csrf device");
}

#[tokio::test]
async fn test_a_stale_script_post_is_401_before_the_csrf_check() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let mut anon = portal.browser();
    let csrf = anon.csrf().await;
    let path = "/wifi/devices/00000000-0000-4000-8000-000000000001/rename";
    for fields in [vec![("name", "x")], vec![("name", "x"), ("csrf", "wrong")], vec![("name", "x"), ("csrf", &csrf)]] {
        let r = anon.post_with(path, &fields, &[("accept", "application/json")]).await;
        assert_eq!((r.status, r.error().as_deref()), (StatusCode::UNAUTHORIZED, Some("login_required")));
        assert!(r.location().is_none());
    }
    assert_eq!(anon.post(path, &[("name", "x")]).await.status, StatusCode::BAD_REQUEST);
    let r = anon.post_with(path, &[("name", "x")], &[("accept", "text/html, application/json;q=0.5")]).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(r.is_page());
}

#[tokio::test]
async fn test_house_lang_cookie_wins_over_the_browser() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let mut b = portal.browser();
    b.lang = "de".into();
    b.cookies.insert("house_lang".into(), "uk".into());
    assert!(b.get("/welcome").await.text().contains("<html lang=\"uk\">"));
    b.cookies.insert("house_lang".into(), "xx".into());
    assert!(b.get("/welcome").await.text().contains("<html lang=\"de\">"));
}

#[tokio::test]
async fn test_kit_and_house_bar() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let page = portal.browser().get("/welcome").await.text();
    assert!(page.contains("href=\"/_house/ui.css\""));
    assert!(page.find("/_house/ui.css") < page.find("style.css"));
    assert!(page.contains("<nav class=\"h-bar\""));
    assert!(page.contains("href=\"https://scharni.org/\""), "{page}");
}

#[tokio::test]
async fn test_head_and_options() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let mut b = portal.browser();
    for (path, status) in [("/healthz", 200), ("/welcome", 200), ("/", 302), ("/.well-known/letswifi.json", 200)] {
        let r = b.request(Method::HEAD, path, None, &[]).await;
        assert_eq!(r.status.as_u16(), status, "{path}");
        assert!(r.body.is_empty());
    }
    for (path, methods) in [
        ("/login", "GET,HEAD,OPTIONS"),
        ("/oauth/token", "POST,OPTIONS"),
        ("/oauth/authorize", "GET,HEAD,POST,OPTIONS"),
    ] {
        let r = b.request(Method::OPTIONS, path, None, &[]).await;
        assert_eq!(r.status, StatusCode::NO_CONTENT, "{path}");
        assert_eq!(r.header("allow").as_deref(), Some(methods), "{path}");
    }
    let r = b.request(Method::OPTIONS, "/nope", None, &[]).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_405_and_404_answers() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let mut b = portal.browser();
    let r = b.get("/logout").await;
    assert_eq!((r.status, r.header("allow").as_deref()), (StatusCode::METHOD_NOT_ALLOWED, Some("POST")));
    assert!(r.is_page());
    let r = b.get("/api/eap-config/").await;
    assert_eq!((r.status, r.error().as_deref()), (StatusCode::METHOD_NOT_ALLOWED, Some("method_not_allowed")));
    assert_eq!(r.header("allow").as_deref(), Some("POST"));
    let r = b.request(Method::DELETE, "/api/devices", None, &[]).await;
    assert_eq!(r.header("allow").as_deref(), Some("GET,HEAD"));
    assert_eq!(r.error().as_deref(), Some("method_not_allowed"));
    let r = b.get("/no-such-page").await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    assert!(r.is_page() && r.text().contains("Something went wrong."));
    assert_eq!(b.get("/api/no-such-api").await.error().as_deref(), Some("not_found"));
    // exact paths: no trailing-slash variants (only /api/eap-config, for the apps)
    assert_eq!(b.get("/admin/").await.status, StatusCode::NOT_FOUND);
    assert_eq!(b.get("/welcome/").await.status, StatusCode::NOT_FOUND);
    let r = portal.post_form("/api/eap-config", &[], &[("authorization", "Bearer not-a-token")]).await;
    assert_eq!((r.status, r.error().as_deref()), (StatusCode::UNAUTHORIZED, Some("invalid_token")));
    // device ids only in the canonical form
    assert_eq!(b.get("/wifi/devices/not-a-uuid").await.status, StatusCode::FOUND); // the login first
    let mut ab = portal.browser().logged_in(&admin("adm")).await;
    assert_eq!(ab.get("/wifi/devices/not-a-uuid").await.status, StatusCode::NOT_FOUND);
    assert_eq!(ab.get("/api/devices/1234").await.error().as_deref(), Some("not_found"));
    assert_eq!(ab.get("/devices/0f8e1c2a3b4d4e5f8a9b0c1d2e3f4a5b").await.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_security_headers() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let base = "default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";
    let dashboard = "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";
    let mut b = portal.browser().logged_in(&resident("hdr")).await;
    for (path, csp, cache) in [
        ("/", base, "no-store"),
        ("/wifi", dashboard, "no-store"),
        ("/home", base, "no-store"),
        ("/welcome", base, "no-store"),
        ("/nope", base, "no-store"),
        ("/api/house", base, "no-store"),
        ("/api/devices", base, "private, no-store"),
        ("/healthz", base, "no-store"),
        ("/static/style.css", base, "no-cache"),
        ("/.well-known/letswifi.json", base, "no-store"),
    ] {
        let r = b.get(path).await;
        assert_eq!(r.header("content-security-policy").as_deref(), Some(csp), "{path}");
        assert_eq!(r.header("x-content-type-options").as_deref(), Some("nosniff"), "{path}");
        assert_eq!(r.header("referrer-policy").as_deref(), Some("no-referrer"), "{path}");
        assert_eq!(r.header("cache-control").as_deref(), Some(cache), "{path}");
    }
    let r = b.get("/static/dashboard.js").await;
    assert_eq!(r.header("content-type").as_deref(), Some("text/javascript; charset=utf-8"));
    let tag = r.header("etag").expect("etag");
    assert_eq!(b.get_with("/static/dashboard.js", &[("if-none-match", &tag)]).await.status, StatusCode::NOT_MODIFIED);
    assert_eq!(b.get("/static/nope.js").await.status, StatusCode::NOT_FOUND);
    assert_eq!(b.get("/static/..%2Fweb.py").await.status, StatusCode::NOT_FOUND);
}

/// Waits (a little) until the person has `open` sessions on the server: the row of an expired
/// cookie is ended by a task the request does not wait for.
async fn open_sessions_become(portal: &Portal, sub: &str, open: i64) {
    let sql = format!("SELECT count(*) FROM web_session WHERE sub = '{sub}' AND ended_at IS NULL");
    for _ in 0..100 {
        if portal.scalar::<i64>(&sql).await == open {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(portal.scalar::<i64>(&sql).await, open);
}

#[tokio::test]
async fn test_a_cookie_past_its_idle_limit_ends_its_row_so_copies_stop() {
    // review 2026-10-29: the idle limit lives in each copy of the cookie; a copy kept fresh
    // elsewhere must not outlive the owner's expired one
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let person = resident("idlecopy");
    let mut owner = portal.browser().logged_in(&person).await;
    let mut copy = portal.browser();
    copy.cookies = owner.cookies.clone();
    portal.clock.advance(4 * HOUR);
    assert_eq!(copy.get("/").await.status, StatusCode::OK); // the copy is used, the owner's is not
    portal.clock.advance(4 * HOUR + 60);
    assert!(owner.get("/").await.to_login());
    open_sessions_become(&portal, &person.sub, 0).await;
    assert!(copy.get("/").await.to_login());
}

#[tokio::test]
async fn test_a_login_over_a_login_ends_the_old_row() {
    // review 2026-10-29: on a shared computer the previous person's cookie (and its copies) is no
    // login once someone logs in on top of it
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let (first, second) = (resident("shared1"), resident("shared2"));
    let mut b = portal.browser().logged_in(&first).await;
    let mut copy = portal.browser();
    copy.cookies = b.cookies.clone();
    let mut elsewhere = portal.browser().logged_in(&first).await;
    b.login(&second).await;
    assert_eq!(b.get("/").await.status, StatusCode::OK);
    assert!(copy.get("/").await.to_login());
    // only that browser's row: the first person's other session stays
    assert_eq!(elsewhere.get("/").await.status, StatusCode::OK);
    open_sessions_become(&portal, &first.sub, 1).await;
}

#[tokio::test]
async fn test_a_logout_that_cannot_reach_the_registry_says_so_and_keeps_the_cookie() {
    // review 2026-10-29: "log out everywhere" must not look done when no row was ended
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let person = resident("nodb");
    let mut b = portal.browser().logged_in(&person).await;
    let csrf = b.csrf().await;
    // the person's rows cannot be written for a moment
    portal.exec("ALTER TABLE web_session ADD CONSTRAINT test_no_end CHECK (ended_at IS NULL) NOT VALID").await;
    let r = b.post("/logout/all", &[("csrf", &csrf)]).await;
    portal.exec("ALTER TABLE web_session DROP CONSTRAINT test_no_end").await;
    assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(r.text().contains("still valid") || r.text().contains("gelten noch"), "{}", r.text());
    assert!(!b.cookies.is_empty(), "the cookie stays, so the person can try again");
    open_sessions_become(&portal, &person.sub, 1).await;
    let r = b.post("/logout/all", &[("csrf", &csrf)]).await;
    assert_eq!(r.status, StatusCode::FOUND);
    open_sessions_become(&portal, &person.sub, 0).await;
}
