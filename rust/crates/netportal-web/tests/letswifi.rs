//! The Let's Wi-Fi authorization server (INVENTORY 3.5; Python tests/test_units.py RedirectTests
//! and PkceTests are unit tests in `src/letswifi.rs`): the whole flow of the geteduroam apps
//! through the router, codes and refresh tokens once only, replay revoking the grant, bearer
//! rules, tokens stored as hashes.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use common::{Portal, resident};
use sha2::{Digest, Sha256};

struct Flow<'a> {
    portal: &'a Portal,
    browser: common::Browser<'a>,
    client_id: &'static str,
    redirect_uri: String,
    verifier: String,
    challenge: String,
}

fn pkce() -> (String, String) {
    let verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 48]>());
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

fn query_of(location: &str) -> Vec<(String, String)> {
    let query = location.split_once('?').map(|(_, q)| q).unwrap_or("");
    url::form_urlencoded::parse(query.as_bytes()).into_owned().collect()
}

fn get<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

impl<'a> Flow<'a> {
    async fn new(portal: &'a Portal, client_id: &'static str, redirect_uri: &str) -> Flow<'a> {
        let browser = portal.browser().logged_in(&resident("lw")).await;
        let (verifier, challenge) = pkce();
        Flow { portal, browser, client_id, redirect_uri: redirect_uri.into(), verifier, challenge }
    }

    fn params(&self) -> Vec<(&'static str, String)> {
        vec![
            ("client_id", self.client_id.to_string()),
            ("redirect_uri", self.redirect_uri.clone()),
            ("response_type", "code".into()),
            ("code_challenge", self.challenge.clone()),
            ("code_challenge_method", "S256".into()),
            ("state", "st-1".into()),
            ("scope", "eap-metadata".into()),
        ]
    }

    async fn authorize(&mut self, changes: &[(&str, &str)]) -> common::Resp {
        let mut params: Vec<(String, String)> = self.params().into_iter().map(|(k, v)| (k.to_string(), v)).collect();
        for (k, v) in changes {
            params.retain(|(pk, _)| pk != k);
            if !v.is_empty() {
                params.push((k.to_string(), v.to_string()));
            }
        }
        let pairs: Vec<(&str, &str)> = params.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        self.browser.get(&format!("/oauth/authorize?{}", common::form(&pairs))).await
    }

    async fn code(&mut self) -> String {
        let page = self.authorize(&[]).await;
        assert_eq!(page.status, StatusCode::OK, "{}", page.text());
        let csrf = self.browser.csrf().await;
        let mut fields: Vec<(&str, String)> = self.params();
        fields.push(("csrf", csrf));
        let pairs: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let r = self.browser.post("/oauth/authorize", &pairs).await;
        assert_eq!(r.status, StatusCode::FOUND, "{}", r.text());
        let location = r.location().expect("location");
        get(&query_of(&location), "code").expect("code").to_string()
    }

    async fn token(&self, fields: &[(&str, &str)]) -> common::Resp {
        self.portal.post_form("/oauth/token", fields, &[]).await
    }

    async fn exchange(&self, code: &str) -> common::Resp {
        self.token(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", self.client_id),
            ("redirect_uri", &self.redirect_uri),
            ("code_verifier", &self.verifier),
        ])
        .await
    }

    async fn refresh(&self, token: &str) -> common::Resp {
        self.token(&[("grant_type", "refresh_token"), ("refresh_token", token), ("client_id", self.client_id)]).await
    }

    async fn eap(&self, authorization: &str) -> common::Resp {
        let req = Request::post("/api/eap-config/")
            .header(header::AUTHORIZATION, authorization)
            .body(Body::empty())
            .expect("request");
        self.portal.call(req).await
    }
}

#[tokio::test]
async fn test_the_whole_flow_of_a_desktop_app() {
    let admin = need_db!();
    let portal = Portal::new(&admin).await;
    let mut f = Flow::new(&portal, "app.geteduroam.win", "http://127.0.0.1:4711/callback").await;
    let consent = f.authorize(&[]).await;
    assert_eq!(consent.status, StatusCode::OK);
    // the page names the app and where the browser goes afterwards (security review I4)
    let text = consent.text();
    assert!(text.contains("App: <strong>geteduroam (Windows)</strong>"), "{text}");
    assert!(text.contains("<code>http://127.0.0.1:4711/callback</code>"), "{text}");
    let csp = consent.header("content-security-policy").expect("csp");
    assert!(csp.ends_with("form-action 'self' http://127.0.0.1:4711"), "{csp}");
    assert!(!csp.contains("script-src"));
    let code = f.code().await;
    let r = f.exchange(&code).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(r.header("cache-control").as_deref(), Some("no-store"));
    let body = r.json();
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["expires_in"], 3600);
    let access = body["access_token"].as_str().expect("access").to_string();
    let refresh = body["refresh_token"].as_str().expect("refresh").to_string();
    // stored only as SHA-256
    let plain: i64 = portal.scalar(&format!("SELECT count(*) FROM oauth_token WHERE token_hash = '{access}'")).await;
    assert_eq!(plain, 0);
    let hashed = hex::encode(Sha256::digest(access.as_bytes()));
    let found: i64 = portal.scalar(&format!("SELECT count(*) FROM oauth_token WHERE token_hash = '{hashed}'")).await;
    assert_eq!(found, 1);
    // the first eap-config enrols the device, the scheme in any case
    let r = f.eap(&format!("bearer {access}")).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(r.content_type(), "application/eap-config");
    assert!(r.header("content-disposition").is_none());
    let devices: i64 = portal.scalar("SELECT count(*) FROM device WHERE platform = 'letswifi'").await;
    assert_eq!(devices, 1);
    // one eap-config per access token: a second call is refused, nothing else happens
    let r = f.eap(&format!("Bearer {access}")).await;
    assert_eq!((r.status, r.error().as_deref()), (StatusCode::UNAUTHORIZED, Some("invalid_token")));
    let certificates: i64 = portal.scalar("SELECT count(*) FROM credential").await;
    assert_eq!(certificates, 1);
    // refresh rotation: the new access token renews the same device; the certificate of an
    // hour ago is retired at once (a re-issue within REISSUE_WINDOW), not after the overlap
    let second = f.refresh(&refresh).await.json();
    let new_access = second["access_token"].as_str().expect("access").to_string();
    assert_ne!(second["refresh_token"].as_str(), Some(refresh.as_str()));
    assert_eq!(f.eap(&format!("Bearer {new_access}")).await.status, StatusCode::OK);
    let certificates: i64 = portal.scalar("SELECT count(*) FROM credential").await;
    assert_eq!(certificates, 2);
    let valid: i64 = portal.scalar("SELECT count(*) FROM radius.valid_cert").await;
    assert_eq!(valid, 1);
    // a replayed refresh token revokes the grant and the device it made (with its Disconnect)
    assert_eq!(f.refresh(&refresh).await.error().as_deref(), Some("invalid_grant"));
    let revoked: i64 =
        portal.scalar("SELECT count(*) FROM device WHERE platform = 'letswifi' AND revoked_at IS NOT NULL").await;
    assert_eq!(revoked, 1);
    let valid: i64 = portal.scalar("SELECT count(*) FROM radius.valid_cert").await;
    assert_eq!(valid, 0);
    let audit: i64 = portal
        .scalar("SELECT count(*) FROM audit WHERE actor = 'letswifi' AND action IN ('letswifi-replay:app.geteduroam.win', 'revoke', 'disconnect:no-session')")
        .await;
    assert_eq!(audit, 3);
    let third = second["refresh_token"].as_str().expect("refresh").to_string();
    assert_eq!(f.refresh(&third).await.error().as_deref(), Some("invalid_grant"));
    let r = f.eap(&format!("Bearer {new_access}")).await;
    assert_eq!((r.status, r.error().as_deref()), (StatusCode::UNAUTHORIZED, Some("invalid_token")));
    assert_eq!(r.header("www-authenticate").as_deref(), Some(r#"Bearer realm="netportal", error="invalid_token""#));
}

#[tokio::test]
async fn test_a_reused_code_revokes_the_grant_and_a_failed_exchange_burns_it() {
    let admin = need_db!();
    let portal = Portal::new(&admin).await;
    let mut f = Flow::new(&portal, "app.eduroam.geteduroam", "app.eduroam.geteduroam:/").await;
    let code = f.code().await;
    let first = f.exchange(&code).await.json();
    assert!(first.get("refresh_token").is_none()); // the mobile app has none
    let access = first["access_token"].as_str().expect("access").to_string();
    assert_eq!(f.eap(&format!("Bearer {access}")).await.status, StatusCode::OK);
    let valid: i64 = portal.scalar("SELECT count(*) FROM radius.valid_cert").await;
    assert_eq!(valid, 1);
    // the replay revokes the grant and the certificate it produced (security review M2)
    assert_eq!(f.exchange(&code).await.error().as_deref(), Some("invalid_grant"));
    let valid: i64 = portal.scalar("SELECT count(*) FROM radius.valid_cert").await;
    assert_eq!(valid, 0);
    assert_eq!(f.eap(&format!("Bearer {access}")).await.status, StatusCode::UNAUTHORIZED);
    // a wrong verifier uses the code up
    let code = f.code().await;
    let r = f
        .token(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("client_id", f.client_id),
            ("redirect_uri", &f.redirect_uri),
            ("code_verifier", &pkce().0),
        ])
        .await;
    assert_eq!(r.error().as_deref(), Some("invalid_grant"));
    assert_eq!(f.exchange(&code).await.error().as_deref(), Some("invalid_grant"));
}

#[tokio::test]
async fn test_authorize_errors() {
    let admin = need_db!();
    let portal = Portal::new(&admin).await;
    let mut f = Flow::new(&portal, "app.geteduroam.win", "http://127.0.0.1:4711/callback").await;
    // not the app's target: 400 page, no redirect
    for (client, redirect) in
        [("app.unknown", "app.eduroam.geteduroam:/"), ("app.geteduroam.win", "http://localhost:4711/")]
    {
        let r = f.authorize(&[("client_id", client), ("redirect_uri", redirect)]).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST);
        assert!(r.location().is_none());
    }
    // back to the app with the error and the state
    for (changes, error) in [
        (vec![("response_type", "token")], "unsupported_response_type"),
        (vec![("response_type", "")], "invalid_request"),
        (vec![("code_challenge_method", "plain")], "invalid_request"),
        (vec![("code_challenge", "")], "invalid_request"),
        (vec![("code_challenge", "short")], "invalid_request"),
    ] {
        let r = f.authorize(&changes).await;
        assert_eq!(r.status, StatusCode::FOUND, "{changes:?}");
        let q = query_of(&r.location().expect("location"));
        assert_eq!(get(&q, "error"), Some(error), "{changes:?}");
        assert_eq!(get(&q, "state"), Some("st-1"));
    }
    // the consent needs the CSRF token
    let params = f.params();
    let pairs: Vec<(&str, &str)> = params.iter().map(|(k, v)| (*k, v.as_str())).collect();
    assert_eq!(f.browser.post("/oauth/authorize", &pairs).await.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_token_errors() {
    let admin = need_db!();
    let portal = Portal::new(&admin).await;
    let f = Flow::new(&portal, "app.eduroam.geteduroam", "app.eduroam.geteduroam:/").await;
    let r = f.token(&[("grant_type", "authorization_code"), ("client_id", "app.unknown")]).await;
    assert_eq!((r.status, r.error().as_deref()), (StatusCode::BAD_REQUEST, Some("invalid_client")));
    assert_eq!(r.header("cache-control").as_deref(), Some("no-store"));
    let r = f.token(&[("client_id", f.client_id)]).await;
    assert_eq!(r.error().as_deref(), Some("invalid_request"));
    let r = f.token(&[("grant_type", "password"), ("client_id", f.client_id)]).await;
    assert_eq!(r.error().as_deref(), Some("unsupported_grant_type"));
    assert_eq!(f.refresh(&"x".repeat(43)).await.error().as_deref(), Some("unauthorized_client"));
    let r = f.token(&[("grant_type", "authorization_code"), ("client_id", f.client_id), ("code", "nope")]).await;
    assert_eq!(r.error().as_deref(), Some("invalid_grant"));
}

#[tokio::test]
async fn test_bearer_rules() {
    let admin = need_db!();
    let portal = Portal::new(&admin).await;
    let mut f = Flow::new(&portal, "app.eduroam.geteduroam", "app.eduroam.geteduroam:/").await;
    let r = portal.call(Request::post("/api/eap-config/").body(Body::empty()).expect("request")).await;
    assert_eq!((r.status, r.error().as_deref()), (StatusCode::UNAUTHORIZED, Some("invalid_token")));
    assert_eq!(r.header("www-authenticate").as_deref(), Some(r#"Bearer realm="netportal""#));
    for auth in ["Bearer", "Basic Zm9vOmJhcg==", "Bearer a b", &format!("Bearer {}", "x".repeat(43))] {
        let r = f.eap(auth).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{auth}");
        assert!(r.header("www-authenticate").is_some_and(|h| h.starts_with("Bearer")));
    }
    let code = f.code().await;
    assert_eq!(f.eap(&format!("Bearer {code}")).await.status, StatusCode::UNAUTHORIZED); // a code is no access token
}

#[tokio::test]
async fn test_discovery() {
    let admin = need_db!();
    let portal = Portal::new(&admin).await;
    let doc = portal.get("/.well-known/letswifi.json").await.json();
    assert_eq!(doc["http://letswifi.app/api#v2"]["token_endpoint"], "http://wifi.test/oauth/token");
    let req = Request::get("/").header(header::ACCEPT, "application/json").body(Body::empty()).expect("request");
    assert_eq!(portal.call(req).await.json(), doc);
    let req =
        Request::get("/").header(header::ACCEPT, "text/html, application/json").body(Body::empty()).expect("request");
    assert!(portal.call(req).await.to_login());
}

#[tokio::test]
async fn test_the_apps_get_the_device_limit() {
    let admin = need_db!();
    let portal = Portal::with(&admin, &[("NETPORTAL_MAX_DEVICES", "1")]).await;
    let mut f = Flow::new(&portal, "app.eduroam.geteduroam", "app.eduroam.geteduroam:/").await;
    let code = f.code().await; // the consent while the person has no device
    let access = f.exchange(&code).await.json()["access_token"].as_str().expect("access").to_string();
    // meanwhile a profile download takes the one place
    let (r, _) = f.browser.enrol("apple", "phone").await;
    assert_eq!(r.status, StatusCode::OK);
    // the app's first eap-config would be a second device: JSON, nothing created
    let r = f.eap(&format!("Bearer {access}")).await;
    assert_eq!((r.status, r.error().as_deref()), (StatusCode::CONFLICT, Some("too_many_devices")));
    let apps: i64 = portal.scalar("SELECT count(*) FROM device WHERE platform = 'letswifi'").await;
    assert_eq!(apps, 0);
    // a new consent is refused with the page
    assert_eq!(f.authorize(&[]).await.status, StatusCode::OK);
    let csrf = f.browser.csrf().await;
    let mut fields: Vec<(&str, String)> = f.params();
    fields.push(("csrf", csrf));
    let pairs: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let r = f.browser.post("/oauth/authorize", &pairs).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert!(r.text().contains("limit of 1 devices"), "{}", r.text());
    // the refusal did not use the access token up: once the phone is gone, the app gets in
    portal.exec("UPDATE device SET revoked_at = now() WHERE platform = 'apple'").await;
    assert_eq!(f.eap(&format!("Bearer {access}")).await.status, StatusCode::OK);
}
