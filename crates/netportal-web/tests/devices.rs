//! Enrolment, one-time downloads, renewal, rename, revocation and `/metrics` (INVENTORY 3.2 rows
//! 7-11, 31; 4.6, 6.4, 10) through the router; the artefacts' contents are netportal-pki's tests.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::{FIREFOX_ANDROID, Portal, admin, download_token, newest_device, resident};
use netportal_core::registry;

#[tokio::test]
async fn test_enrol_download_once() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let person = resident("enr");
    let mut b = portal.browser().logged_in(&person).await;
    for (format, ctype, disposition) in [
        ("apple", "application/x-apple-aspen-config", Some("attachment; filename=\"Scharni.mobileconfig\"")),
        ("apple-mac", "application/x-apple-aspen-config", Some("attachment; filename=\"Scharni.mobileconfig\"")),
        ("android", "application/x-wifi-config", None),
        ("eap-config", "application/eap-config", Some("attachment; filename=\"Scharni.eap-config\"")),
    ] {
        let (page, token) = b.enrol(format, "").await;
        assert_eq!(page.status, StatusCode::OK, "{format}");
        let token = token.expect("download link");
        assert!(token.len() >= 43 && token.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'));
        let device = newest_device(&portal, &person.sub).await;
        let mut db = portal.db().await;
        let row = registry::device(&mut db, device, None).await.expect("device").expect("row");
        let prefix = match format {
            "apple" => "iPhone/iPad",
            "apple-mac" => "Mac",
            _ => "Android",
        };
        assert_eq!(row.name, format!("{prefix} ({})", person.username));
        let r = b.get(&format!("/download/{token}")).await;
        assert_eq!(r.status, StatusCode::OK, "{format}");
        assert_eq!(r.content_type(), ctype);
        assert_eq!(r.header("content-disposition").as_deref(), disposition);
        assert_eq!(r.header("cache-control").as_deref(), Some("no-store"));
        if format == "android" {
            assert_eq!(r.header("content-transfer-encoding").as_deref(), Some("base64"));
        }
        assert_eq!(b.get(&format!("/download/{token}")).await.status, StatusCode::NOT_FOUND); // once
        let credentials: i64 =
            portal.scalar(&format!("SELECT count(*) FROM credential WHERE device_id = '{device}'")).await;
        assert_eq!(credentials, 1);
        let audit: i64 = portal
            .scalar(&format!("SELECT count(*) FROM audit WHERE device_id = '{device}' AND action = 'enrol:{format}'"))
            .await;
        assert_eq!(audit, 1);
    }
    for bad in ["", "windows", "android-app", "letswifi", "APPLE"] {
        let csrf = b.csrf().await;
        assert_eq!(b.post("/wifi/enroll", &[("csrf", &csrf), ("format", bad)]).await.status, StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn test_someone_elses_or_an_expired_token() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let mut b = portal.browser().logged_in(&resident("dl")).await;
    let (_, token) = b.enrol("apple", "mine").await;
    let token = token.expect("token");
    let mut other = portal.browser().logged_in(&resident("dl2")).await;
    assert_eq!(other.get(&format!("/download/{token}")).await.status, StatusCode::NOT_FOUND);
    assert_eq!(b.get(&format!("/download/{token}")).await.status, StatusCode::OK); // not used up
    let (_, token) = b.enrol("apple", "later").await;
    portal.exec("UPDATE download SET expires_at = now() - interval '1 second'").await;
    assert_eq!(b.get(&format!("/download/{}", token.expect("token"))).await.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_names_and_passpoint() {
    let admin_url = need_db!();
    let portal = Portal::with(&admin_url, &[("NETPORTAL_PASSPOINT", "false")]).await;
    let person = resident("nm");
    let mut b = portal.browser().logged_in(&person).await;
    b.enrol("apple", &format!("  {}  ", "x".repeat(70))).await;
    let mut db = portal.db().await;
    let device = newest_device(&portal, &person.sub).await;
    assert_eq!(registry::device(&mut db, device, None).await.expect("d").expect("row").name, "x".repeat(60));
    let csrf = b.csrf().await;
    assert_eq!(b.post("/wifi/enroll", &[("csrf", &csrf), ("format", "android")]).await.status, StatusCode::BAD_REQUEST);
    assert!(!b.get("/wifi").await.text().contains("value=\"android\""));
}

#[tokio::test]
async fn test_firefox_on_android_is_told_and_gets_the_app_first() {
    // Python BrowserNoticeTests
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let mut chrome = portal.browser().logged_in(&resident("ch")).await;
    // the visible page (the texts are also in the scripts' np-texts block)
    let visible = |page: String| page.split("<script type=\"application/json\"").next().unwrap_or("").to_string();
    let page = visible(chrome.get("/wifi").await.text());
    let other_browser = netportal_core::i18n::text("en", "other_browser").expect("text");
    assert!(!page.contains(other_browser));
    assert!(page.find("value=\"android\"") < page.find("value=\"eap-config\""));
    let mut firefox = portal.browser();
    firefox.ua = FIREFOX_ANDROID.into();
    let mut firefox = firefox.logged_in(&resident("ff")).await;
    let page = visible(firefox.get("/wifi").await.text());
    assert!(page.contains(other_browser));
    assert!(page.find("value=\"eap-config\"") < page.find("value=\"android\""));
}

#[tokio::test]
async fn test_renew_keeps_the_device_and_overlaps() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let person = resident("ren");
    let mut b = portal.browser().logged_in(&person).await;
    let (_, token) = b.enrol("apple", "phone").await;
    b.get(&format!("/download/{}", token.expect("token"))).await;
    let device = newest_device(&portal, &person.sub).await;
    let csrf = b.csrf().await;
    let page = b.post(&format!("/wifi/devices/{device}/renew"), &[("csrf", &csrf)]).await;
    assert_eq!(page.status, StatusCode::OK);
    let token = download_token(&page.text()).expect("token");
    assert_eq!(b.get(&format!("/download/{token}")).await.status, StatusCode::OK);
    let devices: i64 = portal.scalar(&format!("SELECT count(*) FROM device WHERE owner = '{}'", person.sub)).await;
    assert_eq!(devices, 1);
    let valid: i64 =
        portal.scalar(&format!("SELECT count(*) FROM radius.valid_cert WHERE device_id = '{device}'")).await;
    assert_eq!(valid, 2); // the earlier one overlaps
    let retires: f64 = portal
        .scalar(&format!(
            "SELECT extract(epoch FROM min(retired_at) - now())::float8 FROM credential WHERE device_id = '{device}'"
        ))
        .await;
    assert!((retires - 2.0 * 86400.0).abs() < 120.0, "{retires}");
    // someone else's, or an admin renewing someone else's: 404
    let mut ab = portal.browser().logged_in(&admin("adm")).await;
    let csrf = ab.csrf().await;
    assert_eq!(
        ab.post(&format!("/wifi/devices/{device}/renew"), &[("csrf", &csrf)]).await.status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn test_rename_form_and_json() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let person = resident("rn");
    let mut b = portal.browser().logged_in(&person).await;
    b.enrol("apple", "before").await;
    let device = newest_device(&portal, &person.sub).await;
    let path = format!("/wifi/devices/{device}/rename");
    let csrf = b.csrf().await;
    let r = b.post(&path, &[("csrf", &csrf), ("name", "  phone  ")]).await;
    assert_eq!(r.location().as_deref(), Some("/wifi"));
    let json = [("accept", "application/json")];
    let r = b.post_with(&path, &[("csrf", &csrf), ("name", &"y".repeat(65))], &json).await;
    assert_eq!((r.status, r.json()), (StatusCode::OK, serde_json::json!({"ok": true, "name": "y".repeat(60)})));
    let r = b.post_with(&path, &[("csrf", &csrf), ("name", "  ")], &json).await;
    assert_eq!(
        (r.status, r.json()),
        (StatusCode::BAD_REQUEST, serde_json::json!({"ok": false, "name": "y".repeat(60)}))
    );
    // someone else's: 404 (JSON for the script)
    let mut other = portal.browser().logged_in(&resident("rn2")).await;
    let csrf = other.csrf().await;
    let r = other.post_with(&path, &[("csrf", &csrf), ("name", "x")], &json).await;
    assert_eq!(r.error().as_deref(), Some("not_found"));
    assert_eq!(other.post(&path, &[("csrf", &csrf), ("name", "x")]).await.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_revoke_and_its_metrics() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let person = resident("rv");
    let mut b = portal.browser().logged_in(&person).await;
    let (_, token) = b.enrol("apple-mac", "laptop").await;
    b.get(&format!("/download/{}", token.expect("token"))).await;
    let device = newest_device(&portal, &person.sub).await;
    let metrics = metrics_text(&portal).await;
    assert!(metrics.contains("netportal_enrolments_total{format=\"apple-mac\"} 1"), "{metrics}");
    assert!(metrics.contains("netportal_certificates{state=\"valid\"} 1"));
    assert!(metrics.contains("netportal_registry_up 1"));
    let csrf = b.csrf().await;
    let r =
        b.post(&format!("/wifi/devices/{device}/revoke"), &[("csrf", &csrf), ("back", "https://evil.example/")]).await;
    assert_eq!(r.location().as_deref(), Some("/wifi"));
    let actions: Vec<String> = sqlx_actions(&portal, &device.to_string()).await;
    assert_eq!(actions[actions.len() - 2..], ["revoke".to_string(), "disconnect:no-session".to_string()]);
    assert_eq!(
        b.post(&format!("/wifi/devices/{device}/revoke"), &[("csrf", &csrf)]).await.status,
        StatusCode::NOT_FOUND
    );
    let metrics = metrics_text(&portal).await;
    assert!(metrics.contains("netportal_disconnects_total{result=\"no-session\"} 1"), "{metrics}");
    assert!(metrics.contains("netportal_devices{state=\"revoked\"} 1"));
    assert!(metrics.contains("netportal_disconnects_last_hour{result=\"no-session\"} 1"));
    // a revoked device's download link gives nothing
    let (_, token) = b.enrol("apple", "other").await;
    let other = newest_device(&portal, &person.sub).await;
    let csrf = b.csrf().await;
    b.post(&format!("/wifi/devices/{other}/revoke"), &[("csrf", &csrf)]).await;
    assert_eq!(b.get(&format!("/download/{}", token.expect("token"))).await.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_a_revocation_whose_disconnect_is_not_confirmed_says_so() {
    // no DAE secret here: the Disconnect is not sent ("skipped"), as a timeout or NAK would
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let person = resident("unc");
    let mut b = portal.browser().logged_in(&person).await;
    b.enrol("apple", "kitchen tablet").await;
    let device = newest_device(&portal, &person.sub).await;
    portal
        .exec(&format!(
            "INSERT INTO radius_session (device_id, nas_ip, calling_station, user_name)
             VALUES ('{device}', '127.0.0.1', 'AA-BB-CC-DD-EE-01', 'anonymous@scharni.org')"
        ))
        .await;
    let csrf = b.csrf().await;
    let r = b.post(&format!("/wifi/devices/{device}/revoke"), &[("csrf", &csrf)]).await;
    assert_eq!(r.status, StatusCode::OK);
    let page = r.text();
    assert!(page.contains("is removed: it cannot join the Wi-Fi again") && page.contains("kitchen tablet"), "{page}");
    assert!(page.contains(r#"<a href="/wifi">"#), "{page}");
    let actions = sqlx_actions(&portal, &device.to_string()).await;
    assert_eq!(actions[actions.len() - 2..], ["revoke".to_string(), "disconnect:skipped".to_string()]);
    // an admin's revocation from the admin page goes back there
    let other = resident("unc2");
    let mut ob = portal.browser().logged_in(&other).await;
    ob.enrol("apple", "theirs").await;
    let theirs = newest_device(&portal, &other.sub).await;
    portal
        .exec(&format!(
            "INSERT INTO radius_session (device_id, nas_ip, calling_station, user_name)
             VALUES ('{theirs}', '127.0.0.1', 'AA-BB-CC-DD-EE-02', '')"
        ))
        .await;
    let mut ab = portal.browser().logged_in(&admin("unca")).await;
    let csrf = ab.csrf().await;
    let r = ab.post(&format!("/wifi/devices/{theirs}/revoke"), &[("csrf", &csrf), ("back", "/admin")]).await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.text().contains(r#"<a href="/admin">"#), "{}", r.text());
}

#[tokio::test]
async fn test_the_metrics_token() {
    let admin_url = need_db!();
    let token = "prometheus-scrape-token-0123456789abcdef";
    let portal = Portal::with(&admin_url, &[("NETPORTAL_METRICS_TOKEN", token)]).await;
    let get = |auth: Option<String>| {
        let mut req = Request::get("/metrics");
        if let Some(auth) = auth {
            req = req.header("authorization", auth);
        }
        req.body(Body::empty()).expect("request")
    };
    for auth in
        [None, Some("Bearer wrong".to_string()), Some(format!("Basic {token}")), Some(format!("Bearer {token}x"))]
    {
        let r = portal.call_metrics(get(auth.clone())).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{auth:?}");
        assert_eq!(r.header("www-authenticate").as_deref(), Some("Bearer realm=\"metrics\""));
        assert!(!r.text().contains("netportal_"));
    }
    for auth in [format!("Bearer {token}"), format!("bearer {token}")] {
        let r = portal.call_metrics(get(Some(auth))).await;
        assert_eq!(r.status, StatusCode::OK);
        assert!(r.text().contains("netportal_registry_up 1"));
    }
    // through a proxy: 404 whatever the token
    let req = Request::get("/metrics")
        .header("authorization", format!("Bearer {token}"))
        .header("x-forwarded-for", "203.0.113.7")
        .body(Body::empty())
        .expect("request");
    assert_eq!(portal.call_metrics(req).await.status, StatusCode::NOT_FOUND);
}

async fn metrics_text(portal: &Portal) -> String {
    portal.call_metrics(Request::get("/metrics").body(Body::empty()).expect("request")).await.text()
}

async fn sqlx_actions(portal: &Portal, device: &str) -> Vec<String> {
    let mut db = portal.db().await;
    let conn = db.tx().await.expect("tx");
    sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT action FROM audit WHERE device_id = '{device}' ORDER BY id"
    )))
    .fetch_all(conn)
    .await
    .expect("audit")
}

#[tokio::test]
async fn test_metrics_only_without_a_proxy() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    // the public listener has no /metrics at all (security review L6), only its own listener
    let r = portal.get("/metrics").await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    assert!(!r.text().contains("netportal_"));
    for (name, value) in
        [("x-forwarded-for", "203.0.113.7"), ("forwarded", "for=203.0.113.7"), ("x-real-ip", "10.0.0.1")]
    {
        let req = Request::get("/metrics").header(name, value).body(Body::empty()).expect("request");
        let r = portal.call_metrics(req).await;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{name}");
        assert!(!r.text().contains("netportal_"));
    }
    let r = portal.call_metrics(Request::get("/metrics").body(Body::empty()).expect("request")).await;
    assert_eq!(r.header("content-type").as_deref(), Some("text/plain; version=0.0.4; charset=utf-8"));
    let text = r.text();
    for line in [
        "# TYPE netportal_enrolments_total counter",
        "# TYPE netportal_disconnects_total counter",
        "# TYPE netportal_offboarded_devices_total counter",
        "# TYPE netportal_offboarding_last_success_timestamp_seconds gauge",
        "# TYPE netportal_disconnects_last_hour gauge",
        "# TYPE netportal_devices gauge",
        "# TYPE netportal_certificates gauge",
        "# TYPE netportal_telemetry_queries_total counter",
        "# TYPE netportal_registry_up gauge",
        "# TYPE netportal_disconnect_rechecks_total counter",
        "netportal_disconnect_rechecks_total{result=\"not_found\"} 0",
        "# TYPE netportal_locked_sessions_live gauge",
        "netportal_locked_sessions_live{reason=\"revoked\"} 0",
    ] {
        assert!(text.contains(line), "{line}");
    }
    assert!(text.contains("netportal_job_last_success_timestamp_seconds{job=\"offboarding\"}"));
    let req = Request::get("/metrics")
        .header("accept", "application/openmetrics-text;version=1.0.0")
        .body(Body::empty())
        .expect("r");
    let r = portal.call_metrics(req).await;
    assert!(r.header("content-type").is_some_and(|c| c.starts_with("application/openmetrics-text")));
    assert!(r.text().ends_with("# EOF\n"));
    // nothing else on the metrics listener
    let r = portal.call_metrics(Request::get("/healthz").body(Body::empty()).expect("request")).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_healthz_and_an_unreachable_registry() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let r = portal.get("/healthz").await;
    assert_eq!((r.status, r.text().as_str()), (StatusCode::OK, "ok\n"));
    // a logged-in browser's cookie, for the same portal without its registry
    let b = portal.browser().logged_in(&resident("hz")).await;
    let cookie: String = b.cookies.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; ");
    // the same portal with its registry gone: 503 for what needs it (JSON for the API, with
    // Retry-After), metrics still up; what needs no registry still works (security review H1)
    let mut vars = common::env("postgresql://nobody:x@127.0.0.1:1/none", &portal.idp, common::BASE_URL);
    vars.insert("NETPORTAL_DATABASE_URL".into(), "postgresql://nobody:x@127.0.0.1:1/none".into());
    let settings = netportal_core::config::PortalSettings::from_env(&vars).expect("settings");
    let telemetry = netportal_telemetry::telemetry::Telemetry::new(None, "Scharni");
    let app = netportal_web::web::App::new(settings, telemetry, portal.clock.clock()).expect("app");
    let router = netportal_web::web::router(app.clone());
    let metrics = netportal_web::web::metrics_router(app);
    use tower::ServiceExt;
    let call = |path: &'static str, cookie: Option<String>| {
        let router = router.clone();
        async move {
            let mut req = Request::get(path);
            if let Some(cookie) = cookie {
                req = req.header("cookie", cookie);
            }
            router.oneshot(req.body(Body::empty()).expect("request")).await.expect("infallible")
        }
    };
    assert_eq!(call("/healthz", None).await.status(), StatusCode::SERVICE_UNAVAILABLE);
    let r = call("/api/devices", Some(cookie.clone())).await;
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(r.headers()["content-type"], "application/json");
    assert_eq!(r.headers()["retry-after"], "5");
    assert_eq!(call("/welcome", Some(cookie.clone())).await.status(), StatusCode::SERVICE_UNAVAILABLE);
    // anonymous: no registry needed
    assert_eq!(call("/welcome", None).await.status(), StatusCode::OK);
    assert_eq!(call("/api/devices", None).await.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(call("/", None).await.headers()["location"], "/login");
    assert_eq!(call("/static/style.css", None).await.status(), StatusCode::OK);
    let r = metrics.oneshot(Request::get("/metrics").body(Body::empty()).expect("request")).await.expect("infallible");
    assert_eq!(r.status(), StatusCode::OK);
    let body = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("body");
    assert!(String::from_utf8_lossy(&body).contains("netportal_registry_up 0"));
}

// --- security review 2026-10-29: H1 (pool, load shedding), L5 (limits) ---------------------------

#[tokio::test]
async fn test_the_pool_bounds_the_connections_and_recovers() {
    let admin_url = need_db!();
    let portal = Portal::with(&admin_url, &[("NETPORTAL_DB_POOL_SIZE", "1")]).await;
    let mut b = portal.browser().logged_in(&resident("pool")).await;
    assert_eq!(b.get("/").await.status, StatusCode::OK);
    // the sessions' limits
    let mut db = portal.app.pool.acquire().await.expect("pooled");
    let row: (String, String, String) = sqlx::query_as(
        "SELECT current_setting('statement_timeout'), current_setting('lock_timeout'),
                current_setting('idle_in_transaction_session_timeout')",
    )
    .fetch_one(db.tx().await.expect("tx"))
    .await
    .expect("settings");
    assert_eq!(row, ("15s".to_string(), "5s".to_string(), "75s".to_string()));
    // every connection taken: a request that needs one is 503 with Retry-After after the acquire
    // timeout, an anonymous one is served at once
    let started = std::time::Instant::now();
    let r = b.get("/").await;
    assert_eq!((r.status, r.header("retry-after").as_deref()), (StatusCode::SERVICE_UNAVAILABLE, Some("5")));
    assert!(started.elapsed() >= std::time::Duration::from_millis(1900), "{:?}", started.elapsed());
    let started = std::time::Instant::now();
    assert_eq!(portal.get("/welcome").await.status, StatusCode::OK);
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
    // the pool never opened a second connection
    assert_eq!(portal.app.pool.size(), 1);
    // released (with its open transaction rolled back): the next request gets it
    drop(db);
    assert_eq!(b.get("/").await.status, StatusCode::OK);
}

#[tokio::test]
async fn test_load_shedding() {
    let admin_url = need_db!();
    let portal = Portal::with(&admin_url, &[("NETPORTAL_MAX_REQUESTS", "1")]).await;
    let held = portal.app.requests.clone().try_acquire_owned().expect("the only slot");
    for path in ["/welcome", "/static/style.css", "/api/devices", "/login"] {
        let r = portal.get(path).await;
        assert_eq!(
            (r.status, r.header("retry-after").as_deref()),
            (StatusCode::SERVICE_UNAVAILABLE, Some("5")),
            "{path}"
        );
    }
    assert_eq!(portal.get("/api/devices").await.error().as_deref(), Some("unavailable"));
    // the healthcheck is not counted
    assert_eq!(portal.get("/healthz").await.status, StatusCode::OK);
    drop(held);
    assert_eq!(portal.get("/welcome").await.status, StatusCode::OK);
}

#[tokio::test]
async fn test_device_limit_and_enrolment_rate() {
    let admin_url = need_db!();
    let portal = Portal::with(&admin_url, &[("NETPORTAL_MAX_DEVICES", "2")]).await;
    let person = resident("lim");
    let mut b = portal.browser().logged_in(&person).await;
    for name in ["one", "two"] {
        let (r, token) = b.enrol("apple", name).await;
        assert_eq!(r.status, StatusCode::OK, "{name}");
        assert!(token.is_some());
    }
    let (r, token) = b.enrol("apple", "three").await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert!(token.is_none());
    assert!(r.text().contains("limit of 2 devices"), "{}", r.text());
    let n: i64 = portal.scalar(&format!("SELECT count(*) FROM device WHERE owner = '{}'", person.sub)).await;
    assert_eq!(n, 2);
    // a revoked device frees its place
    let device = newest_device(&portal, &person.sub).await;
    let csrf = b.csrf().await;
    b.post(&format!("/wifi/devices/{device}/revoke"), &[("csrf", &csrf)]).await;
    assert_eq!(b.enrol("apple", "three").await.0.status, StatusCode::OK);
    // the rate: at most 10 new devices an hour (revoked ones count)
    let portal = Portal::with(&admin_url, &[("NETPORTAL_MAX_DEVICES", "50")]).await;
    let mut b = portal.browser().logged_in(&person).await;
    for i in 0..10 {
        assert_eq!(b.enrol("apple", &format!("d{i}")).await.0.status, StatusCode::OK, "{i}");
    }
    let (r, _) = b.enrol("apple", "d10").await;
    assert_eq!((r.status, r.header("retry-after").as_deref()), (StatusCode::TOO_MANY_REQUESTS, Some("900")));
    assert!(r.text().contains("Too many new devices"), "{}", r.text());
}

#[tokio::test]
async fn test_certificate_rate() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let person = resident("cr");
    let mut b = portal.browser().logged_in(&person).await;
    let (_, token) = b.enrol("apple", "phone").await;
    let device = newest_device(&portal, &person.sub).await;
    // 29 certificates issued today already (as if renewed again and again)
    portal
        .exec(&format!(
            "INSERT INTO credential (serial, device_id, issued_at, not_after)
             SELECT lpad(to_hex(n), 4, '0'), '{device}', now() - interval '1 hour', now() + interval '1 day'
             FROM generate_series(1, 29) n"
        ))
        .await;
    let token = token.expect("token");
    assert_eq!(b.get(&format!("/download/{token}")).await.status, StatusCode::OK); // the 30th
    let csrf = b.csrf().await;
    let r = b.post(&format!("/wifi/devices/{device}/renew"), &[("csrf", &csrf)]).await;
    let again = common::download_token(&r.text()).expect("a new link");
    let r = b.get(&format!("/download/{again}")).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    // the refused link is not used up
    portal.exec("UPDATE credential SET issued_at = now() - interval '2 days'").await;
    assert_eq!(b.get(&format!("/download/{again}")).await.status, StatusCode::OK);
}
