//! The portal application (Python `netportal/web.py` `create_app`, `wsgi.py`): its state, the
//! route table of INVENTORY 3.2 and `netportal serve`.
//!
//! Request handling, outside in (every layer is explicit here, nothing implicit as in Flask):
//!
//! 1. [`pipeline::outer`] (every response): OPTIONS (204 with `Allow`), the answers of routing
//!    itself (404, and 405 with `Allow`: the message page, JSON under `/api/`), `Retry-After` on
//!    every 503, the security headers (CSP per page, nosniff, no-referrer, `Cache-Control:
//!    no-store` unless set);
//! 2. [`pipeline::shed`]: at most `NETPORTAL_MAX_REQUESTS` requests at once; one more is
//!    answered 503 at once (load shedding: a flood cannot queue up work; `/healthz` is not
//!    counted);
//! 3. a timeout (60 s: the request is answered 503) and a body limit (64 KiB: 413);
//! 4. routing: exact paths (no trailing-slash redirects; `/api/eap-config` is served without the
//!    slash too, for apps that drop it), device ids only in the canonical UUID form, the method
//!    decided here (a POST to a GET-only route is 405, never a CSRF error);
//! 5. [`pipeline::browser`] on the browser routes only: language, session cookie and its limits,
//!    the form, the 401 for a script's POST after the session ended, then the CSRF check of every
//!    POST; afterwards the rendering of rejections and the session cookie. The machine endpoints
//!    (`/oauth/token`, `/api/eap-config/`, discovery, `/healthz`, static files) have no session
//!    and no cookie;
//! 6. the handler: a registry connection from the process's pool ([`App::registry`], [`Reg`])
//!    only when it needs one, after the cheap checks (a request without a login never takes one,
//!    except the login's callback); the rights from the registry, the work, explicit commits.
//!
//! The registry pool (H1 of the security review 2026-10-29): `NETPORTAL_DB_POOL_SIZE`
//! connections at most (10), opened lazily (an outage is a 503 and recovers without a restart),
//! waiting at most [`DB_ACQUIRE_TIMEOUT`] for one (then 503 with `Retry-After`); every session
//! runs with `statement_timeout` [`DB_STATEMENT_TIMEOUT`], `lock_timeout` [`DB_LOCK_TIMEOUT`]
//! and `idle_in_transaction_session_timeout` [`DB_IDLE_IN_TRANSACTION_TIMEOUT`]. So a flood of
//! requests holds at most the pool's connections and the database keeps the rest for
//! FreeRADIUS, the offboarding and the collector.
//!
//! `/metrics` is not on this router: it has a listener of its own (`NETPORTAL_METRICS_LISTEN`,
//! unset: none; [`metrics_router`]). Nothing trusts forwarded headers: the portal's own URL is
//! `NETPORTAL_BASE_URL`, no client address is used, and `/metrics` also refuses any request that
//! came through a proxy.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::{DefaultBodyLimit, FromRequestParts};
use axum::http::request::Parts;
use axum::http::{StatusCode, header};
use axum::middleware;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{MethodRouter, get, post};
use minijinja::Value;
use netportal_core::config::{PortalSettings, read_device_ca_key};
use netportal_core::registry;
use netportal_core::{Db, Pool, PoolSettings};
use netportal_offboard::disconnect::RadiusDisconnector;
use netportal_pki::enroll::{Issuer, IssuerConfig};
use netportal_telemetry::telemetry::Telemetry;
use tower_http::timeout::TimeoutLayer;

use crate::clock::{self, Clock};
use crate::ctx::{Ctx, User};
use crate::errors::{Reject, Sparse, left_out};
use crate::metrics::Metrics;
use crate::oidc::Oidc;
use crate::render::{self, Base, RequestView, SettingsView, Templates};
use crate::session::{CookieConfig, cookie_key};
use crate::{dashboard, devices, letswifi, login, ops, pipeline, static_files};

const LOG: &str = "netportal.web";
/// Request bodies (forms) larger than this are refused (413).
pub const BODY_LIMIT: usize = 64 * 1024;
/// A request taking longer is answered 503 (a hung dependency; the Disconnect's 3 x 2 s and the
/// telemetry's budget are far below).
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// Waiting for a registry connection of the pool (or for a new one to open) at most.
pub const DB_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(2);
/// The web's sessions: no statement runs longer (the heaviest page reads take milliseconds).
pub const DB_STATEMENT_TIMEOUT: Duration = Duration::from_secs(15);
/// ... and no statement waits longer for a lock (the logging functions of FreeRADIUS and the
/// offboarding's row locks are short).
pub const DB_LOCK_TIMEOUT: Duration = Duration::from_secs(5);
/// ... and no transaction stays idle longer (a request lasts at most [`REQUEST_TIMEOUT`]).
pub const DB_IDLE_IN_TRANSACTION_TIMEOUT: Duration = Duration::from_secs(75);
/// `/healthz` asks the registry at most this often while it answers; requests in between get
/// the last answer (so a registry outage shows within this time)...
pub const HEALTH_CACHE: Duration = Duration::from_secs(10);
/// ... and this often while it does not (so its recovery shows within this time).
pub const HEALTH_CACHE_FAILED: Duration = Duration::from_secs(2);
/// `/healthz`'s registry check waits at most this long.
pub const HEALTH_TIMEOUT: Duration = Duration::from_secs(2);

static POOL_BUSY: Sparse = Sparse::new();

/// The application state (cheap to clone).
#[derive(Clone)]
pub struct App(Arc<AppInner>);

pub struct AppInner {
    pub settings: PortalSettings,
    pub cookies: CookieConfig,
    pub issuer: Issuer,
    pub templates: Templates,
    pub oidc: Oidc,
    pub telemetry: Telemetry,
    pub metrics: Metrics,
    pub disconnector: RadiusDisconnector,
    pub clock: Clock,
    /// the house's days (`NETPORTAL_TIMEZONE`)
    pub zone: jiff::tz::TimeZone,
    /// the netloc of `NETPORTAL_BASE_URL` (install steps, the app's server name)
    pub host: String,
    /// the registry pool (one per process)
    pub pool: Pool,
    /// the requests handled now ([`pipeline::shed`])
    pub requests: Arc<tokio::sync::Semaphore>,
    /// the last registry check of `/healthz`: when, and whether it answered
    pub health: tokio::sync::Mutex<Option<(Instant, bool)>>,
}

impl std::ops::Deref for App {
    type Target = AppInner;
    fn deref(&self) -> &AppInner {
        &self.0
    }
}

fn read(path: &std::path::Path, what: &str) -> anyhow::Result<Vec<u8>> {
    std::fs::read(path).map_err(|e| anyhow::anyhow!("{what}: cannot read {}: {e}", path.display()))
}

impl App {
    /// Everything the portal needs, checked now (a bad CA, key, template or issuer URL stops the
    /// start, not the first request). The device CA key is read from its file into a buffer
    /// that is wiped as soon as the issuer holds the key (OpenSSL's, freed with the process);
    /// the settings keep only its path. No registry connection is opened here.
    pub fn new(settings: PortalSettings, telemetry: Telemetry, clock: Clock) -> anyhow::Result<App> {
        let root = read(&settings.root_cert, "NETPORTAL_ROOT_CERT")?;
        let device_ca = read(&settings.device_ca_cert, "NETPORTAL_DEVICE_CA_CERT")?;
        let device_ca_key = read_device_ca_key(&settings.device_ca_key).map_err(|e| anyhow::anyhow!(e))?;
        let issuer = Issuer::new(IssuerConfig {
            root_pem: &root,
            device_ca_pem: &device_ca,
            device_ca_key_pem: &device_ca_key,
            realm: &settings.realm,
            ssid: &settings.ssid,
            radius_server_name: &settings.radius_server_name,
            display_name: &settings.display_name,
            cert_days: settings.cert_days,
            profile_signer: None,
        })
        .map_err(|e| anyhow::anyhow!("device CA: {e}"))?;
        drop(device_ca_key);
        let templates = Templates::new().map_err(|e| anyhow::anyhow!("templates: {e}"))?;
        let oidc = Oidc::new(
            &settings.oidc_issuer,
            &settings.oidc_client_id,
            settings.oidc_client_secret.expose(),
            &format!("{}/auth/callback", settings.base_url),
        )
        .map_err(|e| anyhow::anyhow!(e))?;
        let key = cookie_key(settings.session_secret.expose().as_bytes()).map_err(|e| anyhow::anyhow!(e))?;
        let cookies = CookieConfig { key, secure: settings.is_https() };
        let host = url::Url::parse(&settings.base_url)
            .ok()
            .and_then(|u| {
                u.host_str().map(|h| match u.port() {
                    Some(p) => format!("{h}:{p}"),
                    None => h.to_string(),
                })
            })
            .unwrap_or_default();
        let zone = netportal_core::conventions::zone(&settings.timezone)
            .ok_or_else(|| anyhow::anyhow!("NETPORTAL_TIMEZONE: unknown zone"))?;
        let metrics = Metrics::new(&telemetry);
        let disconnector = RadiusDisconnector::new(&settings.dae);
        let pool = Pool::new(
            settings.database_url.expose(),
            &PoolSettings {
                size: settings.db_pool_size,
                acquire_timeout: DB_ACQUIRE_TIMEOUT,
                statement_timeout: DB_STATEMENT_TIMEOUT,
                lock_timeout: DB_LOCK_TIMEOUT,
                idle_in_transaction_timeout: DB_IDLE_IN_TRANSACTION_TIMEOUT,
                application_name: "netportal-web".into(),
            },
        )
        .map_err(|e| anyhow::anyhow!("NETPORTAL_DATABASE_URL: {}", crate::errors::db_kind(&e)))?;
        let requests = Arc::new(tokio::sync::Semaphore::new(settings.max_requests));
        Ok(App(Arc::new(AppInner {
            settings,
            cookies,
            issuer,
            templates,
            oidc,
            telemetry,
            metrics,
            disconnector,
            clock,
            zone,
            host,
            pool,
            requests,
            health: tokio::sync::Mutex::new(None),
        })))
    }

    /// A registry connection of the pool, or 503 (every connection busy for
    /// [`DB_ACQUIRE_TIMEOUT`], or the registry unreachable). Dropping it rolls back what was not
    /// committed and returns it to the pool.
    pub async fn registry(&self) -> Result<Db, Reject> {
        match self.pool.acquire().await {
            Ok(db) => Ok(db),
            Err(sqlx::Error::PoolTimedOut) => {
                if let Some(n) = POOL_BUSY.due() {
                    tracing::warn!(
                        target: LOG,
                        "registry busy or unreachable: no connection within {} s ({} of {} open){}",
                        DB_ACQUIRE_TIMEOUT.as_secs(),
                        self.pool.size(),
                        self.pool.max_size(),
                        left_out(n)
                    );
                }
                Err(Reject::Unavailable)
            }
            Err(e) => {
                if let Some(n) = POOL_BUSY.due() {
                    tracing::error!(target: LOG, "registry unreachable: {}{}", crate::errors::db_kind(&e), left_out(n));
                }
                Err(Reject::Unavailable)
            }
        }
    }

    /// Whether the registry answers, asked at most every [`HEALTH_CACHE`] (after a failure every
    /// [`HEALTH_CACHE_FAILED`]; one check at a time, the requests meanwhile get its answer): a
    /// pooled `SELECT 1` within [`HEALTH_TIMEOUT`].
    pub async fn registry_ok(&self) -> bool {
        let mut last = self.health.lock().await;
        if let Some((at, ok)) = *last
            && at.elapsed() < if ok { HEALTH_CACHE } else { HEALTH_CACHE_FAILED }
        {
            return ok;
        }
        let check = async {
            let mut db = self.pool.acquire().await?;
            sqlx::query("SELECT 1").execute(db.tx().await?).await?;
            db.close().await
        };
        let ok = matches!(tokio::time::timeout(HEALTH_TIMEOUT, check).await, Ok(Ok(())));
        *last = Some((Instant::now(), ok));
        ok
    }

    /// The template globals of this request (the user as the registry knows them, or the
    /// cookie's login without rights on error pages).
    pub fn base(&self, ctx: &Ctx, user: Option<&User>) -> Base {
        let user = user.map(|u| render::User {
            sub: u.sub.clone(),
            username: u.username.clone(),
            name: u.name.clone(),
            admin: u.admin,
        });
        Base {
            lang: ctx.lang.to_string(),
            user,
            csrf: ctx.csrf(),
            settings: self.settings_view(),
            host: self.host.clone(),
            no_passpoint_browser: crate::platform::no_passpoint_browser(&ctx.user_agent),
            request: RequestView { path: ctx.path.clone(), args: ctx.args.clone() },
        }
    }

    pub fn settings_view(&self) -> SettingsView {
        SettingsView {
            display_name: self.settings.display_name.clone(),
            home: self.settings.home_url.clone(),
            ssid: self.settings.ssid.clone(),
            passpoint: self.settings.passpoint,
        }
    }

    /// A rendered page (200).
    pub fn page(&self, ctx: &Ctx, user: Option<&User>, name: &str, page: Value) -> Result<Response, Reject> {
        self.page_with(ctx, user, name, page, StatusCode::OK)
    }

    pub fn page_with(
        &self,
        ctx: &Ctx,
        user: Option<&User>,
        name: &str,
        page: Value,
        status: StatusCode,
    ) -> Result<Response, Reject> {
        let base = self.base(ctx, user);
        match self.templates.render(name, &base, page) {
            Ok(html) => Ok((status, Html(html)).into_response()),
            Err(e) => {
                tracing::error!(target: LOG, "template {name} failed: {e}");
                Err(Reject::Internal)
            }
        }
    }

    /// The request's time.
    pub fn now(&self) -> time::OffsetDateTime {
        (self.clock)()
    }
}

/// The registry connection of a request that needs a login (Python `g.db`): a request whose
/// session has no login is refused before any connection is taken, exactly as the login checks
/// would refuse it (`Ctx::need_user` / `Ctx::api_user`: 401 `login_required` for the JSON
/// routes, else to the login, remembering where to come back); otherwise a connection of the
/// pool ([`App::registry`]; 503 when none is free in time). Dropping it rolls back what was not
/// committed. Handlers that serve anonymous requests too (`/welcome`, `/`, the login's callback,
/// the apps' endpoints) take a connection themselves when they need one.
pub struct Reg(pub Db);

impl std::ops::Deref for Reg {
    type Target = Db;
    fn deref(&self) -> &Db {
        &self.0
    }
}

impl std::ops::DerefMut for Reg {
    fn deref_mut(&mut self) -> &mut Db {
        &mut self.0
    }
}

impl FromRequestParts<App> for Reg {
    type Rejection = Reject;

    async fn from_request_parts(parts: &mut Parts, app: &App) -> Result<Self, Self::Rejection> {
        if let Some(ctx) = parts.extensions.get::<Ctx>()
            && ctx.session().login.is_none()
        {
            if ctx.wants_json() {
                return Err(Reject::Json(StatusCode::UNAUTHORIZED, "login_required"));
            }
            let target = ctx.return_to();
            ctx.session().next = Some(target);
            return Err(Reject::Login);
        }
        Ok(Reg(app.registry().await?))
    }
}

/// The route table (INVENTORY 3.2), with the layers described in the module documentation.
pub fn router(app: App) -> Router {
    let browser =
        |mr: MethodRouter<App>| mr.route_layer(middleware::from_fn_with_state(app.clone(), pipeline::browser));
    let routes = Router::new()
        // login (rows 1-3)
        .route("/login", browser(get(login::login)))
        .route("/auth/callback", browser(get(login::callback)))
        .route("/logout", browser(post(login::logout)))
        // the resident's pages and actions (rows 4-11)
        .route("/welcome", browser(get(dashboard::welcome)))
        .route("/", browser(get(dashboard::index)))
        .route("/devices/{id}", browser(get(dashboard::device_page)))
        .route("/enroll", browser(post(devices::enrol)))
        .route("/devices/{id}/renew", browser(post(devices::renew)))
        .route("/download/{token}", browser(get(devices::download)))
        .route("/devices/{id}/rename", browser(post(devices::rename)))
        .route("/devices/{id}/revoke", browser(post(devices::revoke)))
        // admin pages (rows 12-15)
        .route("/admin", browser(get(dashboard::admin)))
        .route("/admin/aps", browser(get(dashboard::admin_aps)))
        .route("/admin/incidents", browser(get(dashboard::admin_incidents)))
        .route("/admin/devices/{id}", browser(get(dashboard::admin_device)))
        // the dashboard's JSON API (rows 16-25)
        .route("/api/devices", browser(get(dashboard::api_devices)))
        .route("/api/devices/{id}", browser(get(dashboard::api_device)))
        .route("/api/devices/{id}/history", browser(get(dashboard::api_history)))
        .route("/api/house", browser(get(dashboard::api_house)))
        .route("/api/admin/devices", browser(get(dashboard::api_admin_devices)))
        .route("/api/admin/overview", browser(get(dashboard::api_admin_overview)))
        .route("/api/admin/aps", browser(get(dashboard::api_admin_aps)))
        .route("/api/admin/incidents", browser(get(dashboard::api_admin_incidents)))
        .route("/api/admin/auth", browser(get(dashboard::api_admin_auth)))
        .route("/api/admin/devices/{id}/raw", browser(get(dashboard::api_admin_device_raw)))
        // Let's Wi-Fi (rows 26-29)
        .route("/.well-known/letswifi.json", get(letswifi::well_known))
        .route("/oauth/authorize", browser(get(letswifi::authorize).post(letswifi::authorize)))
        .route("/oauth/token", post(letswifi::token))
        .route("/api/eap-config/", post(letswifi::eap_config))
        .route("/api/eap-config", post(letswifi::eap_config))
        // operations (rows 30, 32; /metrics is on its own listener: metrics_router)
        .route("/healthz", get(ops::healthz))
        .route("/static/{name}", get(static_files::serve))
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .with_state(app.clone());
    // the routes as one service, so the outer layer sees routing's complete answers (a 405 with
    // its Allow)
    Router::new()
        .fallback_service(routes)
        .layer(TimeoutLayer::with_status_code(StatusCode::SERVICE_UNAVAILABLE, REQUEST_TIMEOUT))
        .layer(middleware::from_fn_with_state(app.clone(), pipeline::shed))
        .layer(middleware::from_fn_with_state(app, pipeline::outer))
}

/// The metrics listener's routes (`NETPORTAL_METRICS_LISTEN`): `GET /metrics` (INVENTORY 3.2
/// row 31), nothing else (404). Prometheus on the internal network scrapes it directly; the
/// public listener does not serve it at all.
pub fn metrics_router(app: App) -> Router {
    Router::new()
        .route("/metrics", get(ops::metrics))
        .with_state(app)
        .layer(TimeoutLayer::with_status_code(StatusCode::SERVICE_UNAVAILABLE, REQUEST_TIMEOUT))
}

/// The address to listen on: `--bind`, else `NETPORTAL_LISTEN`, else `0.0.0.0:8080`.
pub fn listen_address(bind: Option<&str>) -> String {
    bind.map(str::to_string)
        .or_else(|| std::env::var("NETPORTAL_LISTEN").ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty()))
        .unwrap_or_else(|| "0.0.0.0:8080".to_string())
}

/// `netportal serve`: migrate and seed the registry (the schema is ready before `/healthz`
/// answers), check the CA, templates and OIDC settings, then serve HTTP on `bind` (and
/// `/metrics` on `NETPORTAL_METRICS_LISTEN` when set) until SIGTERM or SIGINT (requests in
/// progress finish). The settings are taken, not copied: the device CA key's path is all they
/// hold of it.
pub async fn serve(settings: PortalSettings, bind: &str) -> anyhow::Result<()> {
    let addr: SocketAddr =
        bind.parse().map_err(|_| anyhow::anyhow!("--bind / NETPORTAL_LISTEN: {bind:?} is not host:port"))?;
    let metrics_addr: Option<SocketAddr> = match settings.metrics_listen.as_deref() {
        Some(text) => {
            Some(text.parse().map_err(|_| anyhow::anyhow!("NETPORTAL_METRICS_LISTEN: {text:?} is not host:port"))?)
        }
        None => None,
    };
    let mut db = Db::connect(settings.database_url.expose())
        .await
        .map_err(|e| anyhow::anyhow!("registry: {}", crate::errors::db_kind(&e)))?;
    let report =
        registry::init(&mut db, &settings.policies.list).await.map_err(|e| anyhow::anyhow!("registry: {e}"))?;
    let _ = db.close().await;
    tracing::info!(target: LOG, "schema ready (version {})", report.version.unwrap_or_default());
    let telemetry = Telemetry::from_settings(&settings).map_err(|e| anyhow::anyhow!("telemetry: {e}"))?;
    let app = App::new(settings, telemetry, clock::system())?;
    let listener =
        tokio::net::TcpListener::bind(addr).await.map_err(|e| anyhow::anyhow!("cannot listen on {addr}: {e}"))?;
    let metrics_listener = match metrics_addr {
        Some(addr) => Some(
            tokio::net::TcpListener::bind(addr)
                .await
                .map_err(|e| anyhow::anyhow!("cannot listen on {addr} (NETPORTAL_METRICS_LISTEN): {e}"))?,
        ),
        None => None,
    };
    tracing::info!(target: LOG, "listening on {addr}");
    // one stop for both listeners: the signal, or either server ending
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let stop_tx = Arc::new(stop_tx);
    let stopped = |mut rx: tokio::sync::watch::Receiver<bool>| async move {
        let _ = rx.wait_for(|stop| *stop).await;
    };
    let signal_tx = stop_tx.clone();
    tokio::spawn(async move {
        stop_signal().await;
        let _ = signal_tx.send(true);
    });
    let web = async {
        let result = axum::serve(listener, router(app.clone())).with_graceful_shutdown(stopped(stop_rx.clone())).await;
        let _ = stop_tx.send(true);
        result
    };
    let metrics = async {
        let result = match metrics_listener {
            Some(listener) => {
                let at = listener.local_addr().map(|a| a.to_string()).unwrap_or_default();
                tracing::info!(target: LOG, "serving /metrics on {at}");
                axum::serve(listener, metrics_router(app.clone()))
                    .with_graceful_shutdown(stopped(stop_rx.clone()))
                    .await
            }
            None => {
                tracing::info!(target: LOG, "no metrics listener (NETPORTAL_METRICS_LISTEN is not set)");
                return Ok(());
            }
        };
        let _ = stop_tx.send(true);
        result
    };
    let (web, metrics) = tokio::join!(web, metrics);
    web?;
    metrics?;
    app.pool.close().await;
    tracing::info!(target: LOG, "stopped");
    Ok(())
}

async fn stop_signal() {
    let interrupt = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut term = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => {
                let _ = interrupt.await;
                return;
            }
        };
        tokio::select! {
            _ = interrupt => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = interrupt.await;
    }
}

/// A JSON response with `Cache-Control: no-store` and `Pragma: no-cache` (token answers, RFC
/// 6749 5.1).
pub fn json_no_store<T: serde::Serialize>(status: StatusCode, body: &T) -> Response {
    let mut response = (status, axum::Json(body)).into_response();
    response.headers_mut().insert(header::CACHE_CONTROL, header::HeaderValue::from_static("no-store"));
    response.headers_mut().insert(header::PRAGMA, header::HeaderValue::from_static("no-cache"));
    response
}
