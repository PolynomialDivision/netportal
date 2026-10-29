//! Shared test pieces: an in-process fake of Authentik's users API (paged like Authentik:
//! `pagination.next` is the next page number, 0 on the last; with failure modes), a recording
//! fake Disconnector, and a fresh registry database per test.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use netportal_core::Db;
use netportal_core::config::{Policies, Policy, Secret};
use netportal_core::registry::{self, RadiusSession};
use netportal_offboard::directory::UsersApi;
use netportal_offboard::disconnect::{DisconnectResult, Disconnector};
use serde_json::{Value, json};
use sqlx::{Connection, Executor, PgConnection};
use uuid::Uuid;

pub const TOKEN: &str = "reader-token-0123456789";

/// Changes a page's JSON before it is sent: (page number, body).
pub type Tweak = Arc<dyn Fn(u32, &mut Value) + Send + Sync>;

#[derive(Default)]
pub struct IdpState {
    pub users: Vec<Value>,
    pub page_size: usize,
    pub fail: Option<u16>,
    pub delay: Option<Duration>,
    pub content_type: Option<&'static str>,
    pub raw: Option<String>,
    pub tweak: Option<Tweak>,
    /// (query parameters, whether the bearer token was right)
    pub requests: Vec<(HashMap<String, String>, bool)>,
}

pub struct FakeIdp {
    /// the API base, as `NETPORTAL_AUTHENTIK_API`
    pub api: String,
    pub state: Arc<Mutex<IdpState>>,
}

pub fn user(uid: &str, active: bool, groups: &[&str]) -> Value {
    json!({"pk": 1, "username": uid, "uid": uid, "is_active": active,
           "groups_obj": groups.iter().map(|g| json!({"pk": g, "name": g})).collect::<Vec<_>>()})
}

impl FakeIdp {
    pub async fn start(users: Vec<Value>) -> FakeIdp {
        let state = Arc::new(Mutex::new(IdpState { users, page_size: 100, ..IdpState::default() }));
        let app = axum::Router::new()
            .route("/api/v3/core/users/", get(users_api))
            .route(
                "/api/v3/redirect/core/users/",
                get(|| async { (StatusCode::FOUND, [(header::LOCATION, "/login")]) }),
            )
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("address");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        FakeIdp { api: format!("http://{addr}/api/v3"), state }
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut IdpState) -> R) -> R {
        f(&mut self.state.lock().expect("state"))
    }

    pub fn client(&self) -> UsersApi {
        self.client_with(TOKEN, Duration::from_secs(5))
    }

    pub fn client_with(&self, token: &str, timeout: Duration) -> UsersApi {
        UsersApi::new(&self.api, Secret::new(token.to_string()), timeout).expect("client")
    }

    pub fn requests(&self) -> Vec<(HashMap<String, String>, bool)> {
        self.with(|s| s.requests.clone())
    }
}

async fn users_api(
    State(state): State<Arc<Mutex<IdpState>>>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let authorized =
        headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) == Some(&format!("Bearer {TOKEN}"));
    let (delay, answer) = {
        let mut st = state.lock().expect("state");
        st.requests.push((query.clone(), authorized));
        (st.delay, answer(&st, &query, authorized))
    };
    if let Some(delay) = delay {
        tokio::time::sleep(delay).await;
    }
    answer
}

fn answer(st: &IdpState, query: &HashMap<String, String>, authorized: bool) -> Response {
    if !authorized {
        return (StatusCode::FORBIDDEN, axum::Json(json!({"detail": "no"}))).into_response();
    }
    if let Some(status) = st.fail {
        let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        return (status, axum::Json(json!({"detail": "failing on purpose"}))).into_response();
    }
    let content_type = st.content_type.unwrap_or("application/json");
    if let Some(raw) = &st.raw {
        return ([(header::CONTENT_TYPE, content_type)], raw.clone()).into_response();
    }
    let page: u32 = query.get("page").and_then(|p| p.parse().ok()).unwrap_or(1);
    let size = st.page_size.max(1);
    let pages = st.users.len().div_ceil(size).max(1) as u32;
    let start = ((page.saturating_sub(1)) as usize * size).min(st.users.len());
    let end = (start + size).min(st.users.len());
    let mut body = json!({
        "pagination": {"next": if page < pages { page + 1 } else { 0 }, "previous": page.saturating_sub(1),
                       "count": st.users.len(), "current": page, "total_pages": pages,
                       "start_index": start + 1, "end_index": end},
        "results": st.users[start..end],
    });
    if let Some(tweak) = &st.tweak {
        tweak(page, &mut body);
    }
    ([(header::CONTENT_TYPE, content_type)], body.to_string()).into_response()
}

// --- Disconnect ------------------------------------------------------------------------------------

/// Records every session it is asked to disconnect and answers `result`.
pub struct FakeDisconnector {
    pub result: DisconnectResult,
    pub sent: Mutex<Vec<RadiusSession>>,
}

impl FakeDisconnector {
    pub fn new(result: DisconnectResult) -> FakeDisconnector {
        FakeDisconnector { result, sent: Mutex::new(Vec::new()) }
    }

    pub fn sent(&self) -> Vec<RadiusSession> {
        self.sent.lock().expect("sent").clone()
    }
}

impl Disconnector for FakeDisconnector {
    async fn disconnect(&self, session: &RadiusSession) -> DisconnectResult {
        self.sent.lock().expect("sent").push(session.clone());
        self.result
    }
}

// --- the registry ------------------------------------------------------------------------------------

pub fn policies() -> Policies {
    Policies {
        list: vec![
            Policy {
                name: "residents".into(),
                vlan: 30,
                groups: ["residents".to_string(), "it-admins".to_string()].into(),
            },
            Policy { name: "guests".into(), vlan: 50, groups: ["former-residents".to_string()].into() },
        ],
        admin_groups: ["it-admins".to_string()].into(),
    }
}

/// The registry tests' database URL, `None` (test skipped) without `NETPORTAL_TEST_DATABASE_URL`.
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
                eprintln!("skipped: NETPORTAL_TEST_DATABASE_URL is not set (eval \"$(rust/tools/test-db.sh)\")");
                return;
            }
        }
    };
}

/// Schema set-up statements of concurrent tests (the grants) would collide.
static INIT: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A fresh, initialised database `t_<random>` (never dropped: the container is throwaway).
pub struct Case {
    pub url: String,
    pub db: Db,
}

impl Case {
    pub async fn new(admin: &url::Url) -> Case {
        let name = format!("t_{}", &Uuid::new_v4().simple().to_string()[..12]);
        let mut conn = PgConnection::connect(admin.as_str()).await.expect("connect as admin");
        conn.execute(sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))).await.expect("database");
        let mut url = admin.clone();
        url.set_path(&format!("/{name}"));
        let url = url.to_string();
        let mut db = Db::connect(&url).await.expect("connect");
        {
            let _init = INIT.lock().await;
            registry::init(&mut db, &policies().list).await.expect("init");
        }
        Case { url, db }
    }

    pub async fn person(&mut self, sub: &str, admin: bool) {
        registry::upsert_person(&mut self.db, sub, sub, sub, admin).await.expect("person");
        registry::set_policy(&mut self.db, sub, "residents").await.expect("policy");
        self.db.commit().await.expect("commit");
    }

    /// A residents device of the person, with a RADIUS session when `nas_ip` is given.
    pub async fn device(&mut self, owner: &str, nas_ip: Option<&str>) -> Uuid {
        let id = registry::create_device(&mut self.db, owner, "phone", "apple", "residents").await.expect("device");
        if let Some(nas_ip) = nas_ip {
            sqlx::query(
                "INSERT INTO radius_session (device_id, nas_ip, calling_station, user_name)
                 VALUES ($1, $2::inet, 'AA-BB-CC-DD-EE-01', 'anonymous@example.org')",
            )
            .bind(id)
            .bind(nas_ip)
            .execute(self.db.tx().await.expect("tx"))
            .await
            .expect("session");
        }
        self.db.commit().await.expect("commit");
        id
    }

    pub async fn offboarded(&mut self, sub: &str) -> bool {
        let state = registry::person_state(&mut self.db, sub).await.expect("state");
        self.db.commit().await.expect("commit");
        state.is_none()
    }

    pub async fn is_admin(&mut self, sub: &str) -> Option<bool> {
        let state = registry::person_state(&mut self.db, sub).await.expect("state");
        self.db.commit().await.expect("commit");
        state.map(|s| s.is_admin)
    }

    pub async fn revoked(&mut self, device: Uuid) -> bool {
        let row = registry::device(&mut self.db, device, None).await.expect("device").expect("found");
        self.db.commit().await.expect("commit");
        row.revoked_at.is_some()
    }

    pub async fn device_policy(&mut self, device: Uuid) -> String {
        let row = registry::device(&mut self.db, device, None).await.expect("device").expect("found");
        self.db.commit().await.expect("commit");
        row.policy
    }

    /// (actor, action) of the device's audit rows, oldest first.
    pub async fn audit(&mut self, device: Uuid) -> Vec<(String, String)> {
        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT actor, action FROM audit WHERE device_id = $1 ORDER BY id")
                .bind(device)
                .fetch_all(self.db.tx().await.expect("tx"))
                .await
                .expect("audit");
        self.db.commit().await.expect("commit");
        rows
    }

    pub async fn count(&mut self, sql: &str) -> i64 {
        let n: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_string()))
            .fetch_one(self.db.tx().await.expect("tx"))
            .await
            .expect(sql);
        self.db.commit().await.expect("commit");
        n
    }

    pub async fn job(&mut self) -> Option<registry::JobStatus> {
        let jobs = registry::job_status(&mut self.db).await.expect("jobs");
        self.db.commit().await.expect("commit");
        jobs.into_iter().find(|j| j.name == "offboarding")
    }
}
