//! Shared test pieces: a fake Authentik OIDC provider (a real HTTP server on 127.0.0.1: discovery,
//! JWKS, authorize, token with client authentication and PKCE, RS256 ID tokens with nonce and
//! groups, claims that can be left out; and the users API the portal checks admin rights with:
//! everyone who logged in, with the groups of their latest login unless a test changes them), a
//! PKI made by the ceremony, a fresh registry database per
//! test (`NETPORTAL_TEST_DATABASE_URL`, `tools/test-db.sh`), the portal built around them with
//! a test clock, and a browser that sends requests through the router (`tower::ServiceExt::oneshot`)
//! with its own cookie jar.

#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, LazyLock, Mutex};

use axum::Router;
use axum::body::Body;
use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine;
use netportal_core::Db;
use netportal_core::config::PortalSettings;
use netportal_core::registry;
use netportal_telemetry::telemetry::Telemetry;
use netportal_web::clock::TestClock;
use netportal_web::web::{App, router};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::sign::Signer;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{Connection, Executor, PgConnection};
use tower::ServiceExt;
use uuid::Uuid;

pub const CLIENT_ID: &str = "netportal";
pub const CLIENT_SECRET: &str = "idp-client-secret";
pub const BASE_URL: &str = "http://wifi.test";
pub const LOGOUT_URL: &str = "https://login.test/if/flow/house-logout/";
/// The users API's token (NETPORTAL_AUTHENTIK_TOKEN).
pub const API_TOKEN: &str = "idp-api-token";

fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

// --- the fake identity provider ----------------------------------------------------------------------

/// A person at the identity provider; `omit` leaves claims out of the ID token.
#[derive(Clone, Debug)]
pub struct Person {
    pub sub: String,
    pub username: String,
    pub name: String,
    pub groups: Vec<String>,
    pub omit: Vec<&'static str>,
}

impl Person {
    pub fn new(groups: &[&str], prefix: &str) -> Person {
        let tag = &Uuid::new_v4().simple().to_string()[..8];
        Person {
            sub: format!("sub-{prefix}-{tag}"),
            username: format!("{prefix}{tag}"),
            name: format!("{prefix} {tag}"),
            groups: groups.iter().map(|g| g.to_string()).collect(),
            omit: Vec::new(),
        }
    }
}

pub fn resident(prefix: &str) -> Person {
    Person::new(&["residents"], prefix)
}

pub fn admin(prefix: &str) -> Person {
    Person::new(&["it-admins"], prefix)
}

struct Code {
    person: Person,
    nonce: String,
    redirect_uri: String,
    challenge: String,
}

struct IdpState {
    issuer: String,
    base: String,
    key: PKey<Private>,
    jwk: Value,
    user: Option<Person>,
    codes: HashMap<String, Code>,
    /// the users API: sub -> (active, groups)
    directory: BTreeMap<String, (bool, Vec<String>)>,
    /// the users API answers this status instead
    api_fails: Option<u16>,
    /// users API requests so far
    api_calls: usize,
}

pub struct FakeIdp {
    pub base: String,
    pub issuer: String,
    state: Arc<Mutex<IdpState>>,
}

fn id_token(st: &IdpState, person: &Person, nonce: &str) -> String {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let mut claims = json!({"iss": st.issuer, "aud": CLIENT_ID, "sub": person.sub, "iat": now, "exp": now + 300,
        "nonce": nonce, "preferred_username": person.username, "name": person.name, "groups": person.groups,
        "email": format!("{}@example.org", person.username)});
    if let Some(map) = claims.as_object_mut() {
        for key in &person.omit {
            map.remove(*key);
        }
    }
    let head = b64(json!({"alg": "RS256", "typ": "JWT", "kid": "k1"}).to_string().as_bytes());
    let signing = format!("{head}.{}", b64(claims.to_string().as_bytes()));
    let mut signer = Signer::new(MessageDigest::sha256(), &st.key).expect("signer");
    signer.update(signing.as_bytes()).expect("sign");
    format!("{signing}.{}", b64(&signer.sign_to_vec().expect("signature")))
}

async fn discovery(State(st): State<Arc<Mutex<IdpState>>>) -> Response {
    let st = st.lock().expect("idp");
    axum::Json(json!({
        "issuer": st.issuer,
        "authorization_endpoint": format!("{}/application/o/authorize/", st.base),
        "token_endpoint": format!("{}/application/o/token/", st.base),
        "userinfo_endpoint": format!("{}/application/o/userinfo/", st.base),
        "jwks_uri": format!("{}/application/o/netportal/jwks/", st.base),
        "response_types_supported": ["code"], "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"], "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
    }))
    .into_response()
}

async fn jwks(State(st): State<Arc<Mutex<IdpState>>>) -> Response {
    let st = st.lock().expect("idp");
    axum::Json(json!({"keys": [st.jwk]})).into_response()
}

async fn authorize(State(st): State<Arc<Mutex<IdpState>>>, Query(q): Query<HashMap<String, String>>) -> Response {
    let mut st = st.lock().expect("idp");
    let (Some(person), Some(nonce), Some(redirect)) = (st.user.clone(), q.get("nonce"), q.get("redirect_uri")) else {
        return (StatusCode::BAD_REQUEST, "invalid_request").into_response();
    };
    if q.get("client_id").map(String::as_str) != Some(CLIENT_ID) {
        return (StatusCode::BAD_REQUEST, "invalid_client").into_response();
    }
    let code = b64(&rand::random::<[u8; 16]>());
    let entry = Code {
        person,
        nonce: nonce.clone(),
        redirect_uri: redirect.clone(),
        challenge: q.get("code_challenge").cloned().unwrap_or_default(),
    };
    st.codes.insert(code.clone(), entry);
    let state = q.get("state").cloned().unwrap_or_default();
    let target = format!("{redirect}?code={code}&state={state}");
    (StatusCode::FOUND, [(header::LOCATION, target)]).into_response()
}

async fn token(
    State(st): State<Arc<Mutex<IdpState>>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let mut st = st.lock().expect("idp");
    let basic = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "))
        .and_then(|v| base64::engine::general_purpose::STANDARD.decode(v).ok())
        .and_then(|v| String::from_utf8(v).ok());
    if basic.as_deref() != Some(&format!("{CLIENT_ID}:{CLIENT_SECRET}")) {
        return (StatusCode::UNAUTHORIZED, axum::Json(json!({"error": "invalid_client"}))).into_response();
    }
    let Some(entry) = form.get("code").and_then(|c| st.codes.remove(c)) else {
        return (StatusCode::BAD_REQUEST, axum::Json(json!({"error": "invalid_grant"}))).into_response();
    };
    let verifier = form.get("code_verifier").cloned().unwrap_or_default();
    if form.get("redirect_uri") != Some(&entry.redirect_uri)
        || b64(&Sha256::digest(verifier.as_bytes())) != entry.challenge
    {
        return (StatusCode::BAD_REQUEST, axum::Json(json!({"error": "invalid_grant"}))).into_response();
    }
    let token = id_token(&st, &entry.person, &entry.nonce);
    axum::Json(json!({"access_token": "at", "token_type": "Bearer", "expires_in": 300, "id_token": token}))
        .into_response()
}

/// `GET /api/v3/core/users/`: Authentik's paged list (one page) of the directory.
async fn users(State(st): State<Arc<Mutex<IdpState>>>, headers: HeaderMap) -> Response {
    let mut st = st.lock().expect("idp");
    st.api_calls += 1;
    if let Some(status) = st.api_fails {
        return StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR).into_response();
    }
    let auth = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok());
    if auth != Some(&format!("Bearer {API_TOKEN}")) {
        return (StatusCode::FORBIDDEN, axum::Json(json!({"detail": "no"}))).into_response();
    }
    let results: Vec<Value> = st
        .directory
        .iter()
        .map(|(sub, (active, groups))| {
            json!({"uid": sub, "username": sub, "is_active": active,
                   "groups_obj": groups.iter().map(|g| json!({"name": g})).collect::<Vec<_>>()})
        })
        .collect();
    let body = json!({"pagination": {"next": 0, "current": 1, "count": results.len(), "total_pages": 1},
                      "results": results});
    axum::Json(body).into_response()
}

impl FakeIdp {
    pub async fn start() -> FakeIdp {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("address");
        let base = format!("http://{addr}");
        let issuer = format!("{base}/application/o/netportal/");
        let rsa = Rsa::generate(2048).expect("rsa");
        let jwk = json!({"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "k1",
            "n": b64(&rsa.n().to_vec()), "e": b64(&rsa.e().to_vec())});
        let key = PKey::from_rsa(rsa).expect("key");
        let state = Arc::new(Mutex::new(IdpState {
            issuer: issuer.clone(),
            base: base.clone(),
            key,
            jwk,
            user: None,
            codes: HashMap::new(),
            directory: BTreeMap::new(),
            api_fails: None,
            api_calls: 0,
        }));
        let app = Router::new()
            .route("/application/o/netportal/.well-known/openid-configuration", get(discovery))
            .route("/application/o/netportal/jwks/", get(jwks))
            .route("/application/o/authorize/", get(authorize))
            .route("/application/o/token/", post(token))
            .route("/api/v3/core/users/", get(users))
            .with_state(state.clone());
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        FakeIdp { base, issuer, state }
    }

    /// The person who logs in next (and is in the directory with these groups from now on).
    pub fn log_in_as(&self, person: &Person) {
        let mut st = self.state.lock().expect("idp");
        st.user = Some(person.clone());
        st.directory.insert(person.sub.clone(), (true, person.groups.clone()));
    }

    /// The person's groups in the users API only (the next ID token keeps the login's).
    pub fn set_groups(&self, sub: &str, groups: &[&str]) {
        let mut st = self.state.lock().expect("idp");
        let active = st.directory.get(sub).map(|(a, _)| *a).unwrap_or(true);
        st.directory.insert(sub.to_string(), (active, groups.iter().map(|g| g.to_string()).collect()));
    }

    /// The person deactivated (`false`) or active again in the users API.
    pub fn set_active(&self, sub: &str, active: bool) {
        if let Some(entry) = self.state.lock().expect("idp").directory.get_mut(sub) {
            entry.0 = active;
        }
    }

    /// The users API answers this HTTP status (`None`: works again).
    pub fn fail_api(&self, status: Option<u16>) {
        self.state.lock().expect("idp").api_fails = status;
    }

    /// Users API requests so far.
    pub fn api_calls(&self) -> usize {
        self.state.lock().expect("idp").api_calls
    }
}

// --- PKI and database ----------------------------------------------------------------------------------

static PKI: LazyLock<tempfile::TempDir> = LazyLock::new(|| {
    let dir = tempfile::tempdir().expect("tempdir");
    let request =
        netportal_pki::ceremony::Request { name: "Test".into(), server_name: "radius.scharni.org".into(), realm: None };
    netportal_pki::ceremony::run(&dir.path().join("pki"), &request, time::OffsetDateTime::now_utc()).expect("ceremony");
    dir
});

pub fn admin_url() -> Option<url::Url> {
    let url = std::env::var("NETPORTAL_TEST_DATABASE_URL").ok().filter(|u| !u.is_empty())?;
    url::Url::parse(&url).ok()
}

#[macro_export]
macro_rules! need_db {
    () => {
        match common::admin_url() {
            Some(url) => url,
            None => {
                eprintln!("skipped: NETPORTAL_TEST_DATABASE_URL is not set (eval \"$(tools/test-db.sh)\")");
                return;
            }
        }
    };
}

static INIT: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn fresh_database(admin: &url::Url) -> String {
    let name = format!("w_{}", &Uuid::new_v4().simple().to_string()[..12]);
    let mut conn = PgConnection::connect(admin.as_str()).await.expect("connect as admin");
    conn.execute(sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))).await.expect("database");
    let mut url = admin.clone();
    url.set_path(&format!("/{name}"));
    url.to_string()
}

// --- the portal --------------------------------------------------------------------------------------------

pub struct Portal {
    pub app: App,
    pub router: Router,
    /// the metrics listener's routes (`NETPORTAL_METRICS_LISTEN`)
    pub metrics: Router,
    pub clock: TestClock,
    pub db_url: String,
    pub idp: Arc<FakeIdp>,
    pub base_url: String,
}

pub fn env(db_url: &str, idp: &FakeIdp, base_url: &str) -> HashMap<String, String> {
    let pki = PKI.path().join("pki");
    let path = |name: &str| pki.join(name).display().to_string();
    [
        ("NETPORTAL_BASE_URL", base_url.to_string()),
        ("NETPORTAL_REALM", "scharni.org".into()),
        ("NETPORTAL_SSID", "Scharni".into()),
        ("NETPORTAL_RADIUS_SERVER_NAME", "radius.scharni.org".into()),
        ("NETPORTAL_DISPLAY_NAME", "Scharni".into()),
        ("NETPORTAL_DATABASE_URL", db_url.to_string()),
        ("NETPORTAL_SESSION_SECRET", "test-session-secret-0123456789abcdef".into()),
        ("NETPORTAL_OIDC_ISSUER", idp.issuer.clone()),
        ("NETPORTAL_OIDC_CLIENT_ID", CLIENT_ID.into()),
        ("NETPORTAL_OIDC_CLIENT_SECRET", CLIENT_SECRET.into()),
        ("NETPORTAL_POLICIES", "residents=30:residents,house-admins;guests=50:former-residents".into()),
        ("NETPORTAL_ADMIN_GROUPS", "it-admins".into()),
        ("NETPORTAL_ROOT_CERT", path("root.pem")),
        ("NETPORTAL_DEVICE_CA_CERT", path("device-ca.pem")),
        ("NETPORTAL_DEVICE_CA_KEY", path("device-ca.key")),
        ("NETPORTAL_PASSPOINT", "true".into()),
        ("NETPORTAL_LOGOUT_URL", LOGOUT_URL.into()),
        ("NETPORTAL_AUTHENTIK_API", format!("{}/api/v3", idp.base)),
        ("NETPORTAL_AUTHENTIK_TOKEN", API_TOKEN.into()),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect()
}

impl Portal {
    pub async fn new(admin: &url::Url) -> Portal {
        Portal::with(admin, &[]).await
    }

    /// A portal with these settings changed (`""`: removed).
    pub async fn with(admin: &url::Url, changes: &[(&str, &str)]) -> Portal {
        let idp = Arc::new(FakeIdp::start().await);
        let db_url = fresh_database(admin).await;
        let base_url = changes.iter().find(|(k, _)| *k == "NETPORTAL_BASE_URL").map(|(_, v)| v.to_string());
        let base_url = base_url.unwrap_or_else(|| BASE_URL.to_string());
        let mut vars = env(&db_url, &idp, &base_url);
        for (k, v) in changes {
            if v.is_empty() {
                vars.remove(*k);
            } else {
                vars.insert(k.to_string(), v.to_string());
            }
        }
        let settings = PortalSettings::from_env(&vars).expect("settings");
        {
            let _init = INIT.lock().await;
            let mut db = Db::connect(&db_url).await.expect("connect");
            registry::init(&mut db, &settings.policies.list).await.expect("init");
        }
        let clock = TestClock::new();
        let telemetry = Telemetry::from_settings(&settings).expect("telemetry");
        let app = App::new(settings, telemetry, clock.clock()).expect("app");
        Portal {
            router: router(app.clone()),
            metrics: netportal_web::web::metrics_router(app.clone()),
            app,
            clock,
            db_url,
            idp,
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    pub fn browser(&self) -> Browser<'_> {
        Browser { portal: self, cookies: BTreeMap::new(), ua: CHROME_ANDROID.into(), lang: "en".into() }
    }

    pub async fn db(&self) -> Db {
        Db::connect(&self.db_url).await.expect("connect")
    }

    /// One SQL value (tests only look at the schema through this).
    pub async fn scalar<T>(&self, sql: &str) -> T
    where
        T: for<'r> sqlx::Decode<'r, sqlx::Postgres> + sqlx::Type<sqlx::Postgres> + Send + Unpin,
    {
        let mut conn = PgConnection::connect(&self.db_url).await.expect("connect");
        sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_string())).fetch_one(&mut conn).await.expect("query")
    }

    pub async fn exec(&self, sql: &str) {
        let mut conn = PgConnection::connect(&self.db_url).await.expect("connect");
        conn.execute(sqlx::raw_sql(sqlx::AssertSqlSafe(sql.to_string()))).await.expect("statement");
    }

    /// A request without cookies (a script, an app).
    pub async fn call(&self, req: Request<Body>) -> Resp {
        let response = self.router.clone().oneshot(req).await.expect("infallible");
        Resp::read(response).await
    }

    /// A request to the metrics listener.
    pub async fn call_metrics(&self, req: Request<Body>) -> Resp {
        use tower::ServiceExt;
        Resp::read(self.metrics.clone().oneshot(req).await.expect("infallible")).await
    }

    pub async fn get(&self, path: &str) -> Resp {
        self.call(Request::get(path).body(Body::empty()).expect("request")).await
    }

    pub async fn post_form(&self, path: &str, fields: &[(&str, &str)], headers: &[(&str, &str)]) -> Resp {
        let mut req = Request::post(path).header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        self.call(req.body(Body::from(form(fields))).expect("request")).await
    }
}

pub const CHROME_ANDROID: &str = "Mozilla/5.0 (Linux; Android 16; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36";
pub const FIREFOX_ANDROID: &str = "Mozilla/5.0 (Android 15; Mobile; rv:158.0) Gecko/158.0 Firefox/158.0";

pub fn form(fields: &[(&str, &str)]) -> String {
    let mut ser = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in fields {
        ser.append_pair(k, v);
    }
    ser.finish()
}

// --- responses ------------------------------------------------------------------------------------------

pub struct Resp {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

/// A `Set-Cookie`: name, value, lower-case attributes.
#[derive(Debug, Clone)]
pub struct SetCookie {
    pub name: String,
    pub value: String,
    pub attrs: BTreeMap<String, String>,
}

impl SetCookie {
    pub fn removal(&self) -> bool {
        self.attrs.get("max-age").is_some_and(|v| v.parse::<i64>().is_ok_and(|n| n <= 0))
    }
}

impl Resp {
    async fn read(response: Response) -> Resp {
        let (parts, body) = response.into_parts();
        let body = axum::body::to_bytes(body, usize::MAX).await.expect("body").to_vec();
        Resp { status: parts.status, headers: parts.headers, body }
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    pub fn header(&self, name: &str) -> Option<String> {
        self.headers.get(name).and_then(|v| v.to_str().ok()).map(str::to_string)
    }

    pub fn location(&self) -> Option<String> {
        self.header("location")
    }

    pub fn content_type(&self) -> String {
        self.header("content-type").unwrap_or_default().split(';').next().unwrap_or("").trim().to_string()
    }

    pub fn set_cookies(&self) -> Vec<SetCookie> {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .map(|raw| {
                let mut parts = raw.split(';').map(str::trim);
                let (name, value) = parts.next().unwrap_or("").split_once('=').unwrap_or(("", ""));
                let attrs = parts
                    .map(|p| match p.split_once('=') {
                        Some((k, v)) => (k.to_ascii_lowercase(), v.to_string()),
                        None => (p.to_ascii_lowercase(), String::new()),
                    })
                    .collect();
                SetCookie { name: name.to_string(), value: value.to_string(), attrs }
            })
            .collect()
    }

    /// The JSON error code of a JSON answer.
    pub fn error(&self) -> Option<String> {
        if self.content_type() != "application/json" {
            return None;
        }
        self.json().get("error").and_then(Value::as_str).map(str::to_string)
    }

    pub fn is_page(&self) -> bool {
        self.header("content-type").as_deref() == Some("text/html; charset=utf-8")
    }

    pub fn to_login(&self) -> bool {
        self.status == StatusCode::FOUND && self.location().as_deref() == Some("/login")
    }
}

pub fn meta_csrf(html: &str) -> Option<String> {
    let start = html.find("<meta name=\"csrf\" content=\"")? + "<meta name=\"csrf\" content=\"".len();
    let end = html[start..].find('"')?;
    Some(html[start..start + end].to_string())
}

pub fn download_token(html: &str) -> Option<String> {
    let start = html.find("href=\"/download/")? + "href=\"/download/".len();
    let end = html[start..].find('"')?;
    Some(html[start..start + end].to_string())
}

// --- the browser ------------------------------------------------------------------------------------------

pub struct Browser<'a> {
    pub portal: &'a Portal,
    pub cookies: BTreeMap<String, String>,
    pub ua: String,
    pub lang: String,
}

impl Browser<'_> {
    pub async fn request(
        &mut self,
        method: Method,
        path: &str,
        body: Option<String>,
        headers: &[(&str, &str)],
    ) -> Resp {
        let mut req = Request::builder().method(method).uri(path).header(header::USER_AGENT, &self.ua);
        req = req.header(header::ACCEPT_LANGUAGE, &self.lang);
        if !self.cookies.is_empty() {
            let cookie = self.cookies.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; ");
            req = req.header(header::COOKIE, cookie);
        }
        if body.is_some() {
            req = req.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        }
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let resp = self.portal.call(req.body(body.map(Body::from).unwrap_or_else(Body::empty)).expect("request")).await;
        for c in resp.set_cookies() {
            if c.removal() {
                self.cookies.remove(&c.name);
            } else {
                self.cookies.insert(c.name.clone(), c.value.clone());
            }
        }
        resp
    }

    pub async fn get(&mut self, path: &str) -> Resp {
        self.request(Method::GET, path, None, &[]).await
    }

    pub async fn get_with(&mut self, path: &str, headers: &[(&str, &str)]) -> Resp {
        self.request(Method::GET, path, None, headers).await
    }

    pub async fn post(&mut self, path: &str, fields: &[(&str, &str)]) -> Resp {
        self.request(Method::POST, path, Some(form(fields)), &[]).await
    }

    pub async fn post_with(&mut self, path: &str, fields: &[(&str, &str)], headers: &[(&str, &str)]) -> Resp {
        self.request(Method::POST, path, Some(form(fields)), headers).await
    }

    /// The session's CSRF token, as every page carries it.
    pub async fn csrf(&mut self) -> String {
        let page = self.get("/welcome").await;
        meta_csrf(&page.text()).expect("csrf meta")
    }

    /// Through the fake provider as this person: the callback's answer.
    pub async fn login(&mut self, person: &Person) -> Resp {
        self.portal.idp.log_in_as(person);
        let start = self.get("/login").await;
        assert_eq!(start.status, StatusCode::FOUND, "{}", start.text());
        let authorize = start.location().expect("location");
        let http = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().expect("client");
        let answer = http.get(&authorize).send().await.expect("authorize");
        let callback = answer.headers().get("location").and_then(|v| v.to_str().ok()).expect("callback").to_string();
        let local = callback.strip_prefix(&self.portal.base_url).expect("callback to the portal").to_string();
        self.get(&local).await
    }

    pub async fn logged_in(mut self, person: &Person) -> Self {
        let callback = self.login(person).await;
        assert_eq!(callback.status, StatusCode::FOUND, "{}", callback.text());
        self
    }

    /// POST /enroll: (install page, download token).
    pub async fn enrol(&mut self, format: &str, name: &str) -> (Resp, Option<String>) {
        let csrf = self.csrf().await;
        let page = self.post("/enroll", &[("csrf", &csrf), ("format", format), ("name", name)]).await;
        let token = download_token(&page.text());
        (page, token)
    }
}

/// The newest device of an owner.
pub async fn newest_device(portal: &Portal, owner: &str) -> Uuid {
    let mut db = portal.db().await;
    let rows = registry::devices(&mut db, Some(owner), true).await.expect("devices");
    rows.first().expect("a device").id
}
