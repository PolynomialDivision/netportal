//! The Let's Wi-Fi authorization server for the geteduroam apps (INVENTORY 3.5, 4.5), by OAuth
//! 2.1 / RFC 6749, RFC 7636 (PKCE), RFC 8252 (native apps), RFC 9700 (security BCP), RFC 6750
//! (bearer tokens):
//!
//! - three registered public clients; redirect URIs by exact match, except loopback redirects of
//!   the desktop apps (`http://127.0.0.1` or `http://[::1]`, any port and path, RFC 8252 7.3;
//!   never `localhost`, no fragment, no user info);
//! - authorization code with PKCE S256 required (the challenge must be the 43 characters of an
//!   S256 challenge; a verifier 43-128 unreserved characters, compared in constant time);
//! - errors before the redirect is trusted are a 400 page (never a redirect); after it, the
//!   error goes back to the app (`invalid_request`, `unsupported_response_type`) with its state;
//! - codes live 300 s and are single-use: a reused code revokes the grant (every token it
//!   issued) and the device it made, whose sessions get Disconnect-Requests (RFC 6749 4.1.2:
//!   "SHOULD revoke ... all tokens previously issued based on that authorization code"; the
//!   certificate is such a credential); a failed exchange burns the code; refresh tokens
//!   (desktop apps only) are rotated at every use, and a replayed one revokes the grant and its
//!   device the same way (RFC 9700 4.14.2); tokens of a revoked grant, a revoked device or an
//!   offboarded person stop at once;
//! - tokens are 256-bit random, stored only as SHA-256 (registry); access tokens 3600 s, refresh
//!   tokens 400 days; token answers `Cache-Control: no-store`;
//! - `/api/eap-config/` takes `Authorization: Bearer <token>` (scheme case-insensitive, RFC 9110
//!   11.1); a 401 names the scheme (`WWW-Authenticate: Bearer`, RFC 6750 3). One eap-config per
//!   access token: a second call with it is a 401 (nothing else happens: an app that lost the
//!   answer gets a new token, the desktop apps by their refresh token); so one token yields one
//!   certificate. A certificate issued within [`REISSUE_WINDOW`] of the device's previous one
//!   retires that one at once instead of after the renewal overlap (at most one older
//!   certificate stays valid), and the person's limits apply ([`crate::limits`]).

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use minijinja::context;
use netportal_core::Db;
use netportal_core::registry::{self, TokenGrant, TokenUse};
use netportal_offboard::actions;
use netportal_pki::enroll::Format;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::ctx::{CONSENT_ARGS, Ctx};
use crate::devices::{artefact_response, issue_artefact, owner_policy};
use crate::errors::{Reject, json_error};
use crate::http::{origin, parse_pairs, with_query};
use crate::limits;
use crate::login::redirect;
use crate::pipeline::Policy;
use crate::platform::{cut_name, default_name};
use crate::web::{App, BODY_LIMIT, Reg, json_no_store};

const LOG: &str = "netportal.letswifi";

pub const CODE_SECONDS: i64 = 300;
pub const ACCESS_SECONDS: i64 = 3600;
pub const REFRESH_SECONDS: i64 = 400 * 86400;
/// A device's certificate issued within this time of the next one is retired at once.
pub const REISSUE_WINDOW: time::Duration = time::Duration::hours(1);
/// The audit actor of what a replayed token causes.
pub const ACTOR: &str = "letswifi";

/// A registered app.
#[derive(Debug, PartialEq, Eq)]
pub struct AppClient {
    pub id: &'static str,
    /// what the consent page calls it
    pub name: &'static str,
    pub redirects: &'static [&'static str],
    /// desktop apps keep a refresh token
    pub refresh: bool,
}

/// The geteduroam apps, as the reference portal registers them.
pub const CLIENTS: [AppClient; 3] = [
    AppClient {
        id: "app.eduroam.geteduroam",
        name: "geteduroam (Android, iPhone, iPad)",
        redirects: &["app.eduroam.geteduroam:/"],
        refresh: false,
    },
    AppClient {
        id: "app.geteduroam.win",
        name: "geteduroam (Windows)",
        redirects: &["http://127.0.0.1/", "http://[::1]/"],
        refresh: true,
    },
    AppClient {
        id: "app.geteduroam.sh",
        name: "geteduroam (Linux)",
        redirects: &["http://127.0.0.1/", "http://[::1]/"],
        refresh: true,
    },
];

pub fn client(id: &str) -> Option<&'static AppClient> {
    CLIENTS.iter().find(|c| c.id == id)
}

/// Exact match, or a loopback redirect of a client registered with the bare loopback URI.
pub fn redirect_allowed(client: &AppClient, uri: &str) -> bool {
    if client.redirects.contains(&uri) {
        return true;
    }
    let Ok(url) = url::Url::parse(uri) else {
        return false;
    };
    if url.scheme() != "http" || url.fragment().is_some() || !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    let bare = match url.host() {
        Some(url::Host::Ipv4(ip)) if ip == std::net::Ipv4Addr::LOCALHOST => "http://127.0.0.1/",
        Some(url::Host::Ipv6(ip)) if ip == std::net::Ipv6Addr::LOCALHOST => "http://[::1]/",
        _ => return false,
    };
    client.redirects.contains(&bare)
}

fn b64url_chars(text: &str) -> bool {
    text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// An S256 challenge: base64url of a SHA-256 digest, 43 characters (RFC 7636 4.2).
pub fn challenge_ok(challenge: &str) -> bool {
    challenge.len() == 43 && b64url_chars(challenge)
}

/// The verifier (43-128 unreserved characters, RFC 7636 4.1) hashes to the challenge.
pub fn pkce_ok(verifier: &str, challenge: &str) -> bool {
    let unreserved = verifier.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'));
    if !(43..=128).contains(&verifier.len()) || !unreserved || challenge.is_empty() {
        return false;
    }
    let digest = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    digest.as_bytes().ct_eq(challenge.as_bytes()).into()
}

/// The discovery document the apps read (`/.well-known/letswifi.json`, and `/` for
/// `Accept: application/json`).
pub fn document(base_url: &str) -> Value {
    json!({"http://letswifi.app/api#v2": {
        "authorization_endpoint": format!("{base_url}/oauth/authorize"),
        "token_endpoint": format!("{base_url}/oauth/token"),
        "eapconfig_endpoint": format!("{base_url}/api/eap-config/"),
    }})
}

/// `GET /.well-known/letswifi.json`.
pub async fn well_known(State(app): State<App>) -> Response {
    axum::Json(document(&app.settings.base_url)).into_response()
}

/// `GET /oauth/authorize` (the consent page: which app asks, and where the browser goes
/// afterwards) and `POST` (the consent: a grant and a code, within the person's device limit).
pub async fn authorize(State(app): State<App>, ctx: Ctx, mut reg: Reg) -> Result<Response, Reject> {
    let user = ctx.need_user(&mut reg).await?;
    let values = ctx.values();
    let get = |k: &str| values.get(k).map(String::as_str).unwrap_or("");
    let redirect_uri = get("redirect_uri");
    let Some(client) = client(get("client_id")).filter(|c| redirect_allowed(c, redirect_uri)) else {
        // never redirect to a target that is not the app's
        return Err(Reject::bad_request());
    };
    let state = get("state");
    let error = match get("response_type") {
        "" => Some("invalid_request"),
        "code" => None,
        _ => Some("unsupported_response_type"),
    }
    .or_else(|| {
        (get("code_challenge_method") != "S256" || !challenge_ok(get("code_challenge"))).then_some("invalid_request")
    });
    if let Some(error) = error {
        return Ok(redirect(&with_query(redirect_uri, &[("error", error), ("state", state)])));
    }
    if ctx.method == axum::http::Method::GET || ctx.method == axum::http::Method::HEAD {
        let args: indexmap::IndexMap<&str, &str> = CONSENT_ARGS.iter().map(|k| (*k, get(k))).collect();
        let page = context! {
            args => minijinja::Value::from(minijinja::value::Serde(&args)),
            consent_args => CONSENT_ARGS,
            name => default_name("letswifi", &user.username),
            app_name => client.name,
            redirect_uri => redirect_uri,
        };
        let mut response = app.page(&ctx, Some(&user), "consent.html", page)?;
        if let Some(origin) = origin(redirect_uri) {
            response.extensions_mut().insert(Policy::FormAction(origin));
        }
        return Ok(response);
    }
    if let Some(over) = limits::new_device(&app, &mut reg, &user.sub).await? {
        return limits::page(&app, &ctx, &user, over);
    }
    let name = cut_name(ctx.field("name")).unwrap_or_else(|| default_name("letswifi", &user.username));
    let grant = registry::create_grant(&mut reg, &user.sub, client.id, &name).await?;
    let code =
        registry::issue_token(&mut reg, grant, "code", CODE_SECONDS, Some(get("code_challenge")), Some(redirect_uri))
            .await?;
    registry::audit(&mut reg, &user.sub, &format!("letswifi-consent:{}", client.id), None).await?;
    reg.commit().await?;
    Ok(redirect(&with_query(redirect_uri, &[("code", &code), ("state", state)])))
}

fn oauth_error(status: StatusCode, code: &str) -> Response {
    let mut response = json_error(status, code);
    response.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// A used-up token answer: commit the token's state (a burnt code, a revoked grant), then the
/// error.
async fn refuse(db: &mut Db, code: &str) -> Response {
    if let Err(e) = db.commit().await {
        tracing::error!(target: LOG, "token state not committed: {}", crate::errors::db_kind(&e));
    }
    oauth_error(StatusCode::BAD_REQUEST, code)
}

fn is_form(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|t| t.trim().eq_ignore_ascii_case("application/x-www-form-urlencoded"))
}

/// `POST /oauth/token` (form-encoded, public clients, no CSRF).
pub async fn token(State(app): State<App>, headers: HeaderMap, body: Bytes) -> Response {
    let form = if is_form(&headers) && body.len() <= BODY_LIMIT { parse_pairs(&body) } else { Default::default() };
    let get = |k: &str| form.get(k).map(String::as_str).unwrap_or("");
    let Some(client) = client(get("client_id")) else {
        // a public client that is not registered (RFC 6749 5.2): 400, no authentication scheme
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_client");
    };
    let grant_type = get("grant_type");
    if grant_type.is_empty() {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    if grant_type != "authorization_code" && grant_type != "refresh_token" {
        return oauth_error(StatusCode::BAD_REQUEST, "unsupported_grant_type");
    }
    if grant_type == "refresh_token" && !client.refresh {
        return oauth_error(StatusCode::BAD_REQUEST, "unauthorized_client");
    }
    let Ok(mut db) = app.registry().await else {
        return oauth_error(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
    };
    match exchange(&mut db, client, grant_type, &form).await {
        Ok(Exchange::Tokens(body)) => json_no_store(StatusCode::OK, &body),
        Ok(Exchange::Refused(code)) => refuse(&mut db, code).await,
        Ok(Exchange::Replayed(row)) => match replayed(&app, &mut db, &row).await {
            Ok(()) => oauth_error(StatusCode::BAD_REQUEST, "invalid_grant"),
            Err(_) => oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
        },
        Err(_) => oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
    }
}

/// What a code or refresh token is worth.
enum Exchange {
    /// the token answer
    Tokens(Value),
    /// refused with this OAuth error (a burnt code stays burnt: committed by [`refuse`])
    Refused(&'static str),
    /// a code or refresh token used before: someone else has (or had) it
    Replayed(TokenGrant),
}

/// The checks of a code or refresh token.
async fn exchange(
    db: &mut Db,
    client: &AppClient,
    grant_type: &str,
    form: &indexmap::IndexMap<String, String>,
) -> Result<Exchange, Reject> {
    let get = |k: &str| form.get(k).map(String::as_str).unwrap_or("");
    let (token, kind) =
        if grant_type == "authorization_code" { (get("code"), "code") } else { (get("refresh_token"), "refresh") };
    let row = match registry::use_token(db, token, kind, true).await? {
        TokenUse::Valid(row) => row,
        TokenUse::Replayed(row) => return Ok(Exchange::Replayed(row)),
        TokenUse::Invalid => return Ok(Exchange::Refused("invalid_grant")),
    };
    let ok = if kind == "code" {
        row.client_id == client.id
            && row.redirect_uri.as_deref() == Some(get("redirect_uri"))
            && pkce_ok(get("code_verifier"), row.pkce_challenge.as_deref().unwrap_or(""))
    } else {
        row.client_id == client.id
    };
    if !ok {
        return Ok(Exchange::Refused("invalid_grant"));
    }
    let access = registry::issue_token(db, row.grant_id, "access", ACCESS_SECONDS, None, None).await?;
    let mut body = json!({"access_token": access, "token_type": "Bearer", "expires_in": ACCESS_SECONDS});
    if client.refresh {
        body["refresh_token"] =
            json!(registry::issue_token(db, row.grant_id, "refresh", REFRESH_SECONDS, None, None).await?);
    }
    db.commit().await?;
    Ok(Exchange::Tokens(body))
}

/// A replayed code or refresh token: the grant is revoked (every token it issued stops) and
/// audited `letswifi-replay:<client>`, committed; then the device it made is revoked with
/// Disconnect-Requests for its sessions (`netportal_offboard::actions::revoke_now`, by
/// [`ACTOR`]). Whoever holds it (the app or someone who copied the token) needs a new consent.
async fn replayed(app: &App, db: &mut Db, row: &TokenGrant) -> Result<(), Reject> {
    db.rollback().await?;
    registry::revoke_grant(db, row.grant_id).await?;
    registry::audit(db, ACTOR, &format!("letswifi-replay:{}", row.client_id), row.device_id).await?;
    db.commit().await?;
    tracing::warn!(
        target: LOG,
        "a used token of a grant of {} ({}) came again: grant revoked{}",
        row.owner,
        row.client_id,
        if row.device_id.is_some() { ", its device too" } else { "" }
    );
    if let Some(device) = row.device_id {
        for result in actions::revoke_now(db, device, ACTOR, &app.disconnector).await? {
            app.metrics.disconnected(result.as_str());
        }
    }
    Ok(())
}

/// The bearer token of an `Authorization` header (`Bearer` in any case, then the b64token).
pub fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, rest) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = rest.trim_start_matches(' ');
    let body = token.trim_end_matches('=');
    let ok = !body.is_empty()
        && body.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'+' | b'/'));
    ok.then_some(token)
}

fn invalid_token(with_error: bool) -> Response {
    let mut response = oauth_error(StatusCode::UNAUTHORIZED, "invalid_token");
    let challenge =
        if with_error { r#"Bearer realm="netportal", error="invalid_token""# } else { r#"Bearer realm="netportal""# };
    response.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static(challenge));
    response
}

/// `POST /api/eap-config/`: the app's eap-config with a new certificate of its device (created
/// at the grant's first call), once per access token.
pub async fn eap_config(State(app): State<App>, headers: HeaderMap) -> Response {
    let Some(token) = bearer(&headers) else {
        return invalid_token(headers.contains_key(header::AUTHORIZATION));
    };
    let Ok(mut db) = app.registry().await else {
        return json_error(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
    };
    match eap_config_for(&app, &mut db, token).await {
        Ok(Some(response)) => response,
        Ok(None) => invalid_token(true),
        Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
    }
}

/// The token is used up only with the certificate's commit (a refused or failed call leaves
/// it usable).
async fn eap_config_for(app: &App, db: &mut Db, token: &str) -> Result<Option<Response>, Reject> {
    let row = match registry::use_token(db, token, "access", true).await? {
        TokenUse::Valid(row) => row,
        TokenUse::Replayed(row) => {
            tracing::info!(target: LOG, "an access token of {} ({}) was used again: refused", row.owner, row.client_id);
            return Ok(None);
        }
        TokenUse::Invalid => return Ok(None),
    };
    let first = row.device_id.is_none();
    let over = if first {
        limits::new_device(app, db, &row.owner).await?
    } else {
        limits::new_certificate(db, &row.owner).await?
    };
    if let Some(over) = over {
        return Ok(Some(limits::app_answer(&row.owner, over)));
    }
    let device_id = match row.device_id {
        None => {
            let policy = owner_policy(app, db, &row.owner).await?;
            let id = registry::create_device(db, &row.owner, &row.device_name, "letswifi", &policy).await?;
            registry::bind_grant(db, row.grant_id, id).await?;
            registry::audit(db, &row.owner, "enrol:letswifi", Some(id)).await?;
            id
        }
        Some(id) => {
            match registry::device(db, id, None).await? {
                Some(dev) if dev.revoked_at.is_none() => {}
                _ => return Ok(None),
            }
            registry::audit(db, &row.owner, "renew:letswifi", Some(id)).await?;
            id
        }
    };
    let artefact = issue_artefact(app, db, device_id, Format::LetsWifi, Some(REISSUE_WINDOW)).await?;
    if first {
        app.metrics.enrolled("letswifi");
    }
    Ok(Some(artefact_response(artefact)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_loopback_any_port() {
        // Python RedirectTests
        let win = client("app.geteduroam.win").expect("client");
        for uri in
            ["http://127.0.0.1/", "http://127.0.0.1:61234/x/y", "http://[::1]:5000/", "http://127.0.0.1:1/cb?x=1"]
        {
            assert!(redirect_allowed(win, uri), "{uri}");
        }
    }

    #[test]
    fn test_refused() {
        let win = client("app.geteduroam.win").expect("client");
        for uri in [
            "http://localhost:4711/",
            "http://127.0.0.2/",
            "https://127.0.0.1/",
            "http://127.0.0.1.evil.example/",
            "http://evil.example/?u=http://127.0.0.1/",
            "http://user@127.0.0.1/",
            "http://127.0.0.1/#frag",
            "",
            "app.eduroam.geteduroam:/",
        ] {
            assert!(!redirect_allowed(win, uri), "{uri}");
        }
        let linux = client("app.geteduroam.sh").expect("client");
        assert!(!redirect_allowed(linux, "http://[::2]/"));
    }

    #[test]
    fn test_custom_scheme_exact() {
        let android = client("app.eduroam.geteduroam").expect("client");
        assert!(redirect_allowed(android, "app.eduroam.geteduroam:/"));
        assert!(!redirect_allowed(android, "app.eduroam.geteduroam:/other"));
        assert!(!redirect_allowed(android, "http://127.0.0.1:4711/"));
        assert!(client("app.unknown").is_none());
    }

    #[test]
    fn test_rfc7636_example() {
        // RFC 7636 appendix B
        assert!(pkce_ok("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"));
        assert!(challenge_ok("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"));
    }

    #[test]
    fn test_pkce_refused() {
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(!pkce_ok("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXX", challenge));
        assert!(!pkce_ok("", challenge));
        assert!(!pkce_ok(&"x".repeat(43), challenge));
        assert!(!pkce_ok(&"a".repeat(42), challenge));
        assert!(!pkce_ok(&"a".repeat(129), challenge));
        assert!(!pkce_ok("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", ""));
        assert!(!pkce_ok(&format!("{}!", "a".repeat(43)), challenge));
        assert!(!challenge_ok("x"));
        assert!(!challenge_ok(&"x".repeat(44)));
        assert!(!challenge_ok(&format!("{}=", "x".repeat(42))));
    }

    #[test]
    fn test_bearer() {
        let with = |v: &str| {
            let mut h = HeaderMap::new();
            h.insert(header::AUTHORIZATION, HeaderValue::from_str(v).expect("header"));
            h
        };
        assert_eq!(bearer(&with("Bearer abc-_.~+/=")), Some("abc-_.~+/="));
        assert_eq!(bearer(&with("bearer abc")), Some("abc"));
        assert_eq!(bearer(&with("BEARER  abc")), Some("abc"));
        assert_eq!(bearer(&with("Bearer")), None);
        assert_eq!(bearer(&with("Bearer ")), None);
        assert_eq!(bearer(&with("Basic Zm9vOmJhcg==")), None);
        assert_eq!(bearer(&with("Bearer a b")), None);
        assert_eq!(bearer(&HeaderMap::new()), None);
    }

    #[test]
    fn test_document() {
        let doc = document("https://wifi.example.org");
        assert_eq!(doc["http://letswifi.app/api#v2"]["eapconfig_endpoint"], "https://wifi.example.org/api/eap-config/");
    }
}
