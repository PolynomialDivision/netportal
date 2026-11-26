//! The dashboard's pages and JSON API (Python tests/test_dashboard_api.py, the route-level parts;
//! INVENTORY 3.2 rows 4-6, 12-25, 3.3): ownership, the admin rights, JSON errors, the polled
//! APIs' ETag and 304, the admin API's parameter checks, CSP of the dashboard pages, telemetry
//! off and unavailable. The payloads' contents are netportal-telemetry's tests; Prometheus is
//! off here (or unreachable).

mod common;

use axum::http::{Method, StatusCode};
use common::{Portal, admin, newest_device, resident};
use serde_json::Value;

const DASHBOARD_CSP: &str = "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";

fn keys(v: &Value) -> Vec<String> {
    let mut k: Vec<String> = v.as_object().map(|m| m.keys().cloned().collect()).unwrap_or_default();
    k.sort();
    k
}

#[tokio::test]
async fn test_ownership() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let person = resident("own");
    let mut b = portal.browser().logged_in(&person).await;
    b.enrol("apple", "Kitchen tablet").await;
    let mine = newest_device(&portal, &person.sub).await.to_string();
    let other = resident("oth");
    let mut ob = portal.browser().logged_in(&other).await;
    ob.enrol("apple", "Theirs").await;
    let theirs = newest_device(&portal, &other.sub).await.to_string();
    // a resident gets their devices only, without an owner block
    let body = b.get("/api/devices").await.json();
    let ids: Vec<&str> = body["devices"].as_array().expect("devices").iter().filter_map(|d| d["id"].as_str()).collect();
    assert_eq!(ids, [mine.as_str()]);
    assert!(body["devices"][0].get("owner").is_none());
    assert_eq!(body["devices"][0]["expires_soon"], false);
    assert_eq!(body["telemetry"], "off");
    for path in [format!("/api/devices/{theirs}"), format!("/api/devices/{theirs}/history")] {
        assert_eq!(b.get(&path).await.error().as_deref(), Some("not_found"), "{path}");
    }
    let r = b.get(&format!("/wifi/devices/{theirs}")).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    assert!(r.is_page());
    // one device: exactly these keys
    let one = b.get(&format!("/api/devices/{mine}")).await.json();
    assert_eq!(keys(&one), ["device", "generated_at", "house", "poll_s", "stale", "telemetry"]);
    // history
    let history = b.get(&format!("/api/devices/{mine}/history?range=7d")).await;
    assert_eq!(history.header("cache-control").as_deref(), Some("no-store"));
    assert!(history.header("etag").is_none());
    let history = history.json();
    assert_eq!((history["range"].as_str(), history["step_s"].as_i64()), (Some("7d"), Some(1800)));
    for bad in ["2y", "", "24H", "1d"] {
        let r = b.get(&format!("/api/devices/{mine}/history?range={bad}")).await;
        assert_eq!((r.status, r.error().as_deref()), (StatusCode::BAD_REQUEST, Some("bad_range")), "{bad:?}");
    }
    // the page with an unknown range: 24h
    assert_eq!(b.get(&format!("/wifi/devices/{mine}?range=2y")).await.status, StatusCode::OK);
    // an admin reads any device, with its owner
    let mut ab = portal.browser().logged_in(&admin("adm")).await;
    let one = ab.get(&format!("/api/devices/{theirs}")).await.json();
    assert_eq!(one["device"]["owner"]["username"], other.username.as_str());
    assert_eq!(ab.get(&format!("/wifi/devices/{theirs}")).await.status, StatusCode::OK);
    assert_eq!(ab.get(&format!("/admin/devices/{theirs}")).await.status, StatusCode::OK);
    let own_list = ab.get("/api/devices").await.json();
    assert_eq!(own_list["devices"].as_array().map(Vec::len), Some(0));
    // a revoked device is gone from the pages and device APIs, not from raw
    let csrf = ob.csrf().await;
    ob.post(&format!("/wifi/devices/{theirs}/revoke"), &[("csrf", &csrf)]).await;
    assert_eq!(ab.get(&format!("/api/devices/{theirs}")).await.error().as_deref(), Some("not_found"));
    assert_eq!(ab.get(&format!("/admin/devices/{theirs}")).await.status, StatusCode::NOT_FOUND);
    let raw = ab.get(&format!("/api/admin/devices/{theirs}/raw")).await;
    assert_eq!(raw.status, StatusCode::OK, "{}", raw.text());
    assert_eq!(
        keys(&raw.json()),
        [
            "acct",
            "auth",
            "conflicts",
            "days",
            "device",
            "events",
            "from",
            "incidents",
            "limits",
            "to",
            "truncated",
            "windows"
        ]
    );
}

#[tokio::test]
async fn test_admin_api_is_for_admins() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let mut anon = portal.browser();
    let mut res = portal.browser().logged_in(&resident("res")).await;
    for path in
        ["/api/admin/devices", "/api/admin/overview", "/api/admin/aps", "/api/admin/incidents", "/api/admin/auth"]
    {
        let r = anon.get(path).await;
        assert_eq!((r.status, r.error().as_deref()), (StatusCode::UNAUTHORIZED, Some("login_required")), "{path}");
        assert!(r.location().is_none());
        assert_eq!(res.get(path).await.error().as_deref(), Some("forbidden"), "{path}");
    }
    for path in ["/admin", "/admin/aps", "/admin/incidents"] {
        assert!(anon.get(path).await.to_login());
        assert_eq!(res.get(path).await.status, StatusCode::FORBIDDEN);
    }
    assert_eq!(anon.get("/api/no-such-api").await.error().as_deref(), Some("not_found"));
    let r = res.request(Method::POST, "/api/devices", None, &[]).await;
    assert_eq!((r.status, r.error().as_deref()), (StatusCode::METHOD_NOT_ALLOWED, Some("method_not_allowed")));
}

#[tokio::test]
async fn test_admin_api() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let owner = resident("aap");
    let mut ob = portal.browser().logged_in(&owner).await;
    ob.enrol("apple", &format!("Zebra-Tablet-{}", owner.username)).await;
    let device = newest_device(&portal, &owner.sub).await.to_string();
    let mut ab = portal.browser().logged_in(&admin("aap")).await;
    let all = ab.get("/api/admin/devices").await.json();
    let found: Vec<&Value> =
        all["devices"].as_array().expect("devices").iter().filter(|d| d["id"] == device.as_str()).collect();
    assert_eq!(found[0]["owner"]["username"], owner.username.as_str());
    let total: i64 = all["counts"].as_object().expect("counts").values().filter_map(Value::as_i64).sum();
    for q in [format!("zebra-tablet-{}", owner.username), owner.username.to_uppercase()] {
        let r = ab.get(&format!("/api/admin/devices?q={q}")).await.json();
        let ids: Vec<&str> =
            r["devices"].as_array().expect("devices").iter().filter_map(|d| d["id"].as_str()).collect();
        assert_eq!(ids, [device.as_str()]);
        let counted: i64 = r["counts"].as_object().expect("counts").values().filter_map(Value::as_i64).sum();
        assert_eq!(counted, total); // counts: of all devices
    }
    let r = ab.get("/api/admin/devices?state=online").await.json();
    assert_eq!(r["devices"].as_array().map(Vec::len), Some(0));
    let r = ab.get("/api/admin/devices?state=nonsense").await.json();
    assert!(r["devices"].as_array().is_some_and(|d| !d.is_empty())); // ignored
    let overview = ab.get("/api/admin/overview").await.json();
    assert_eq!(
        keys(&overview),
        [
            "aps",
            "auth",
            "freshness",
            "generated_at",
            "house",
            "incidents",
            "jobs",
            "jobs_available",
            "stale",
            "telemetry"
        ]
    );
    for q in [
        "",
        "?range=7d",
        "?range=1y",
        "?kind=ap_down",
        "?from=2026-10-01&to=2026-10-20",
        "?from=2026-10-01T00:00:00Z&to=2026-10-02T00:00:00Z",
    ] {
        let r = ab.get(&format!("/api/admin/incidents{q}")).await;
        assert_eq!(r.status, StatusCode::OK, "{q} {}", r.text());
    }
    for (q, code) in [
        ("?kind=AP_DOWN", "bad_kind"),
        ("?kind=1x", "bad_kind"),
        ("?from=2026-10-20&to=2026-10-01", "bad_range"),
        ("?from=2020-01-01&to=2026-01-01", "bad_range"),
        ("?from=yesterday", "bad_range"),
    ] {
        assert_eq!(ab.get(&format!("/api/admin/incidents{q}")).await.error().as_deref(), Some(code), "{q}");
    }
    assert_eq!(ab.get("/api/admin/auth?limit=10").await.status, StatusCode::OK);
    assert_eq!(ab.get("/api/admin/auth?result=accept").await.error().as_deref(), Some("bad_result"));
    for limit in ["0", "501", "abc", "%C2%B2", "%D9%A3", "-1", "1.5", "%2B5"] {
        assert_eq!(
            ab.get(&format!("/api/admin/auth?limit={limit}")).await.error().as_deref(),
            Some("bad_limit"),
            "{limit}"
        );
    }
    assert_eq!(ab.get("/api/admin/auth?from=2026-01-01&to=2026-03-01").await.error().as_deref(), Some("bad_range"));
    assert_eq!(
        ab.get("/api/admin/devices/00000000-0000-4000-8000-000000000000/raw").await.error().as_deref(),
        Some("not_found")
    );
    assert_eq!(
        ab.get(&format!("/api/admin/devices/{device}/raw?from=2026-01-01&to=2026-03-01")).await.error().as_deref(),
        Some("bad_range")
    );
    // the pages: the incidents page falls back to 7 days on nonsense
    for path in
        ["/admin", "/admin/aps", "/admin/incidents", "/admin/incidents?kind=AP%22", &format!("/admin/devices/{device}")]
    {
        let r = ab.get(path).await;
        assert_eq!(r.status, StatusCode::OK, "{path}");
        assert_eq!(r.header("content-security-policy").as_deref(), Some(DASHBOARD_CSP), "{path}");
    }
}

#[tokio::test]
async fn test_polled_api() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let person = resident("poll");
    let mut b = portal.browser().logged_in(&person).await;
    b.enrol("apple", "poll phone").await;
    let device = newest_device(&portal, &person.sub).await;
    let r = b.get("/api/devices").await;
    let tag = r.header("etag").expect("etag");
    assert!(tag.starts_with("W/\""));
    assert_eq!(r.header("cache-control").as_deref(), Some("private, no-store"));
    assert!(r.json()["poll_s"].is_i64());
    // the same data later: the same tag (generated_at is left out)
    portal.clock.advance(5);
    assert_eq!(b.get("/api/devices").await.header("etag").as_deref(), Some(tag.as_str()));
    for header in [tag.clone(), tag[2..].to_string(), "*".into(), format!("\"nope\", {tag}")] {
        let r = b.get_with("/api/devices", &[("if-none-match", &header)]).await;
        assert_eq!(r.status, StatusCode::NOT_MODIFIED, "{header}");
        assert!(r.body.is_empty());
        assert_eq!(r.header("etag").as_deref(), Some(tag.as_str()));
        assert_eq!(r.header("x-content-type-options").as_deref(), Some("nosniff"));
    }
    // the login is checked before the 304
    let r = portal.browser().get_with("/api/devices", &[("if-none-match", &tag)]).await;
    assert_eq!(r.error().as_deref(), Some("login_required"));
    // another name, another tag
    let csrf = b.csrf().await;
    b.post(&format!("/wifi/devices/{device}/rename"), &[("csrf", &csrf), ("name", "renamed")]).await;
    let r = b.get_with("/api/devices", &[("if-none-match", &tag)]).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_ne!(r.header("etag").as_deref(), Some(tag.as_str()));
    let one = b.get(&format!("/api/devices/{device}")).await;
    let one_tag = one.header("etag").expect("etag");
    assert_eq!(
        b.get_with(&format!("/api/devices/{device}"), &[("if-none-match", &one_tag)]).await.status,
        StatusCode::NOT_MODIFIED
    );
}

#[tokio::test]
async fn test_pages_and_telemetry_states() {
    let admin_url = need_db!();
    let portal = Portal::with(&admin_url, &[("NETPORTAL_PROMETHEUS_URL", "http://127.0.0.1:1")]).await;
    let person = resident("tel");
    let mut b = portal.browser().logged_in(&person).await;
    b.enrol("apple", "phone").await;
    let device = newest_device(&portal, &person.sub).await;
    // Prometheus down: no error page, the API says unavailable
    let r = b.get("/wifi").await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.header("content-security-policy").as_deref(), Some(DASHBOARD_CSP));
    assert_eq!(b.get("/api/devices").await.json()["telemetry"], "unavailable");
    assert_eq!(b.get(&format!("/wifi/devices/{device}")).await.status, StatusCode::OK);
    let house = b.get("/api/house").await.json();
    assert!(house.get("internet").is_some() && house.get("wifi_data_at").is_some());
    // no CSP for scripts outside the dashboard pages
    let welcome = b.get("/welcome").await;
    assert!(!welcome.header("content-security-policy").unwrap_or_default().contains("script-src"));
}
