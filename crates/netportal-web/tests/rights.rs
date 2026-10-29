//! Admin rights checked live with Authentik (owner's review 2026-10-29): every route that uses
//! them (the route table's `Gate::Admin` and `Gate::AdminWidens`, walked here, so a new route
//! cannot be added without being checked) refuses a login whose right the users API no longer
//! confirms, clears the registry's flag and ends the person's sessions; a confirmation counts 30 s;
//! Authentik unreachable refuses admin requests (503) and leaves resident pages alone.

mod common;

use axum::http::StatusCode;
use common::{Browser, Portal, admin, newest_device, resident};
use netportal_core::registry;
use netportal_web::web::{Gate, routes};
use uuid::Uuid;

async fn is_admin(portal: &Portal, sub: &str) -> bool {
    let mut db = portal.db().await;
    registry::person_state(&mut db, sub).await.expect("state").is_some_and(|s| s.is_admin)
}

/// Another resident's new device.
async fn someones_device(portal: &Portal) -> Uuid {
    let owner = resident("own");
    let mut b = portal.browser().logged_in(&owner).await;
    b.enrol("apple", "theirs").await;
    newest_device(portal, &owner.sub).await
}

/// The route called the way a browser or a script would: GET, or (a POST-only route) the form
/// with the session's CSRF token.
async fn call(b: &mut Browser<'_>, path: &str) -> common::Resp {
    let r = b.get(path).await;
    if r.status != StatusCode::METHOD_NOT_ALLOWED {
        return r;
    }
    let csrf = b.csrf().await;
    b.post(path, &[("csrf", &csrf), ("name", "renamed by the walk")]).await
}

#[tokio::test]
async fn test_every_admin_route_checks_the_right_with_authentik() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let gated: Vec<&str> =
        routes().into_iter().filter(|(_, g)| matches!(g, Gate::Admin | Gate::AdminWidens)).map(|(p, _)| p).collect();
    // the table names them all (a new admin route must be added there to be served at all)
    for path in [
        "/admin",
        "/admin/aps",
        "/admin/incidents",
        "/admin/devices/{id}",
        "/api/admin/devices",
        "/api/admin/overview",
        "/api/admin/aps",
        "/api/admin/incidents",
        "/api/admin/auth",
        "/api/admin/devices/{id}/raw",
        "/devices/{id}",
        "/devices/{id}/rename",
        "/devices/{id}/revoke",
        "/api/devices/{id}",
        "/api/devices/{id}/history",
    ] {
        assert!(gated.contains(&path), "{path} is not admin-gated");
    }
    assert_eq!(gated.len(), 15, "{gated:?}");
    for path in gated {
        // Authentik confirms: the route serves the admin (another person's device for {id})
        let device = someones_device(&portal).await;
        let url = path.replace("{id}", &device.to_string());
        let person = admin("ok");
        let mut b = portal.browser().logged_in(&person).await;
        let r = call(&mut b, &url).await;
        assert!(r.status == StatusCode::OK || r.status == StatusCode::FOUND, "{path}: {} {}", r.status, r.text());
        // Authentik says no (out of the admin group since the login): refused, the flag cleared,
        // the sessions ended, nothing changed; also when the script calls the API directly
        let device = someones_device(&portal).await;
        let url = path.replace("{id}", &device.to_string());
        let person = admin("no");
        let mut b = portal.browser().logged_in(&person).await;
        assert!(is_admin(&portal, &person.sub).await, "{path}: the login's groups gave the flag");
        portal.idp.set_groups(&person.sub, &["residents"]);
        let r = call(&mut b, &url).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{path}: {}", r.text());
        if url.starts_with("/api/") {
            assert_eq!(r.error().as_deref(), Some("forbidden"), "{path}");
        } else {
            assert!(r.is_page(), "{path}");
        }
        assert!(!is_admin(&portal, &person.sub).await, "{path}: the registry's flag is cleared");
        assert!(b.get("/").await.to_login(), "{path}: the sessions ended");
        let mut db = portal.db().await;
        let row = registry::device(&mut db, device, None).await.expect("device").expect("row");
        assert!(row.revoked_at.is_none() && row.name == "theirs", "{path}: nothing changed");
    }
}

#[tokio::test]
async fn test_a_right_taken_away_in_authentik_ends_within_30_seconds() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let person = admin("gone");
    let mut b = portal.browser().logged_in(&person).await;
    assert_eq!(b.get("/admin").await.status, StatusCode::OK);
    let calls = portal.idp.api_calls();
    portal.idp.set_groups(&person.sub, &["residents"]);
    // the confirmation counts for 30 s (the documented window; one users API read per person)
    portal.clock.advance(20);
    assert_eq!(b.get("/admin").await.status, StatusCode::OK);
    assert_eq!(b.get("/api/admin/devices").await.status, StatusCode::OK);
    assert_eq!(portal.idp.api_calls(), calls);
    portal.clock.advance(11);
    let r = b.get("/api/admin/overview").await;
    assert_eq!((r.status, r.error().as_deref()), (StatusCode::FORBIDDEN, Some("forbidden")));
    assert_eq!(portal.idp.api_calls(), calls + 1);
    assert!(!is_admin(&portal, &person.sub).await);
    assert!(b.get("/admin").await.to_login());
    // the next login gets Authentik's groups: a resident's session, nothing to ask
    let mut person = person;
    person.groups = vec!["residents".into()];
    b.login(&person).await;
    assert!(!is_admin(&portal, &person.sub).await);
    assert_eq!(b.get("/admin").await.status, StatusCode::FORBIDDEN);
    assert_eq!(b.get("/").await.status, StatusCode::OK);
    assert_eq!(portal.idp.api_calls(), calls + 1);
}

#[tokio::test]
async fn test_a_deactivated_or_deleted_admin_loses_the_right() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    portal.browser().logged_in(&resident("res")).await;
    let person = admin("off");
    let mut b = portal.browser().logged_in(&person).await;
    portal.idp.set_active(&person.sub, false);
    assert_eq!(b.get("/admin").await.status, StatusCode::FORBIDDEN);
    assert!(!is_admin(&portal, &person.sub).await);
    // a directory that names nobody with access is no answer: 503, the flag stays
    let empty = Portal::new(&admin_url).await;
    let person = admin("alone");
    let mut b = empty.browser().logged_in(&person).await;
    empty.idp.set_active(&person.sub, false);
    assert_eq!(b.get("/admin").await.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(is_admin(&empty, &person.sub).await);
}

#[tokio::test]
async fn test_authentik_unreachable_refuses_admin_requests_only() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let device = someones_device(&portal).await;
    let person = admin("down");
    let mut b = portal.browser().logged_in(&person).await;
    b.enrol("apple", "mine").await;
    let mine = newest_device(&portal, &person.sub).await;
    portal.idp.fail_api(Some(500));
    let r = b.get("/admin").await;
    assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(r.is_page() && r.header("retry-after").is_some());
    assert!(r.text().contains("cannot be checked"), "{}", r.text());
    let r = b.get("/api/admin/devices").await;
    assert_eq!((r.status, r.error().as_deref()), (StatusCode::SERVICE_UNAVAILABLE, Some("unavailable")));
    // another person's device needs the right: 503; their own: the resident's view
    assert_eq!(b.get(&format!("/devices/{device}")).await.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(b.get(&format!("/devices/{mine}")).await.status, StatusCode::OK);
    assert_eq!(b.get(&format!("/api/devices/{mine}")).await.status, StatusCode::OK);
    // resident pages: unaffected; the right stays in the registry (nothing was decided)
    assert_eq!(b.get("/").await.status, StatusCode::OK);
    assert_eq!(b.get("/api/devices").await.status, StatusCode::OK);
    assert!(is_admin(&portal, &person.sub).await);
    // back: admin again (after the failure pause)
    portal.idp.fail_api(None);
    portal.clock.advance(6);
    assert_eq!(b.get("/admin").await.status, StatusCode::OK);
}

#[tokio::test]
async fn test_without_the_users_api_every_admin_request_is_refused() {
    let admin_url = need_db!();
    let portal = Portal::with(&admin_url, &[("NETPORTAL_AUTHENTIK_TOKEN", "")]).await;
    let person = admin("noapi");
    let mut b = portal.browser().logged_in(&person).await;
    assert_eq!(b.get("/admin").await.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(b.get("/api/admin/overview").await.error().as_deref(), Some("unavailable"));
    assert_eq!(b.get("/").await.status, StatusCode::OK);
    assert_eq!(portal.idp.api_calls(), 0);
}

#[tokio::test]
async fn test_residents_never_ask_authentik() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let device = someones_device(&portal).await;
    let mut b = portal.browser().logged_in(&resident("res")).await;
    assert_eq!(b.get("/admin").await.status, StatusCode::FORBIDDEN);
    assert_eq!(b.get(&format!("/devices/{device}")).await.status, StatusCode::NOT_FOUND);
    assert_eq!(b.get(&format!("/api/devices/{device}")).await.status, StatusCode::NOT_FOUND);
    assert_eq!(b.get("/").await.status, StatusCode::OK);
    assert_eq!(portal.idp.api_calls(), 0);
}
