//! One browser request as the handlers see it (Python: Flask's `g`, `session`, `request`): the
//! language, the session (changed by the handlers, written back by the pipeline), the query and
//! form values, and the login's rights, read from the registry on every request that needs them
//! (INVENTORY 4.3).
//!
//! Admin rights are a value, not a flag: a [`User`] says only whether the registry lists the
//! person as admin (the admin link); admin powers need an [`Admin`], which only the live check
//! with Authentik makes ([`Ctx::need_admin`], [`Ctx::api_admin`], [`Ctx::admin_for`]; the admin
//! routes get theirs from the router's gate, [`crate::pipeline::admin_gate`]). Its field is
//! private, so no handler can make one without the check.

use std::sync::{Arc, Mutex, MutexGuard};

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{Method, StatusCode};
use indexmap::IndexMap;
use netportal_core::Db;
use netportal_core::registry;
use time::OffsetDateTime;

use crate::errors::Reject;
use crate::http::{best_accept, with_query};
use crate::rights::Verdict;
use crate::session::Session;
use crate::web::App;

const LOG: &str = "netportal.web";

/// The consent form's fields, re-sent as the authorize URL when the login interrupts a consent
/// (Python `CONSENT_ARGS`).
pub const CONSENT_ARGS: [&str; 7] =
    ["client_id", "redirect_uri", "response_type", "code_challenge", "code_challenge_method", "state", "scope"];

/// The logged-in person (their session row lives, they are not offboarded).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub sub: String,
    pub username: String,
    pub name: String,
    /// the registry lists the person as admin (from the login's groups and the offboarding
    /// round): shows the admin link and makes the admin checks ask Authentik; it grants nothing
    /// by itself (an [`Admin`] does)
    pub listed_admin: bool,
}

/// The admin right of this request's login, confirmed by Authentik now ([`crate::rights`]).
/// Only the checks of [`Ctx`] make one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admin {
    user: User,
}

impl Admin {
    pub fn user(&self) -> &User {
        &self.user
    }

    pub fn sub(&self) -> &str {
        &self.user.sub
    }
}

/// The admin routes' extractor: the [`Admin`] the router's gate checked for this request
/// ([`crate::pipeline::admin_gate`]); a route without the gate has none (500, never a right).
impl<S: Send + Sync> FromRequestParts<S> for Admin {
    type Rejection = Reject;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        parts.extensions.remove::<Admin>().ok_or(Reject::Internal)
    }
}

/// What becomes of the session cookie after the handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CookieFate {
    /// written when it changed or a login is in it (the sliding idle expiry)
    Keep,
    /// removed (logout, failed login)
    Remove,
}

pub struct Inner {
    pub lang: &'static str,
    pub method: Method,
    /// the raw path (percent-encoded as sent)
    pub path: String,
    /// the raw query, without `?`
    pub query: Option<String>,
    pub args: IndexMap<String, String>,
    pub form: IndexMap<String, String>,
    pub user_agent: String,
    pub accept: String,
    pub now: OffsetDateTime,
    pub session: Mutex<Session>,
    pub fate: Mutex<CookieFate>,
}

/// The request context (cheap to clone).
#[derive(Clone)]
pub struct Ctx(pub Arc<Inner>);

impl std::ops::Deref for Ctx {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.0
    }
}

impl<S: Send + Sync> FromRequestParts<S> for Ctx {
    type Rejection = Reject;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        // only routes behind the browser pipeline have one
        parts.extensions.get::<Ctx>().cloned().ok_or(Reject::Internal)
    }
}

impl Ctx {
    pub fn session(&self) -> MutexGuard<'_, Session> {
        self.session.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn set_fate(&self, fate: CookieFate) {
        *self.fate.lock().unwrap_or_else(|e| e.into_inner()) = fate;
    }

    pub fn fate(&self) -> CookieFate {
        *self.fate.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn now_unix(&self) -> i64 {
        self.now.unix_timestamp()
    }

    pub fn csrf(&self) -> String {
        self.session().csrf.clone()
    }

    /// The form field (or `""`).
    pub fn field(&self, name: &str) -> &str {
        self.form.get(name).map(String::as_str).unwrap_or("")
    }

    /// The query parameter (or `""`).
    pub fn arg(&self, name: &str) -> &str {
        self.args.get(name).map(String::as_str).unwrap_or("")
    }

    /// The request's values: query for a GET, form for a POST (Python `request.values` as the
    /// authorize endpoint reads them).
    pub fn values(&self) -> &IndexMap<String, String> {
        if self.method == Method::POST { &self.form } else { &self.args }
    }

    /// Errors and expired sessions answer JSON: the dashboard's API, and a dashboard script's
    /// POST (`Accept` prefers `application/json`), never a page or a redirect (3.1).
    pub fn wants_json(&self) -> bool {
        wants_json(&self.method, &self.path, &self.accept)
    }

    /// The logged-in person, or `None`; a session whose row ended (logout, logout everywhere,
    /// offboarding, the admin right lost), expired or belongs to a person no longer active ends
    /// the login here and now (one query).
    pub async fn user(&self, db: &mut Db) -> Result<Option<User>, Reject> {
        let Some(login) = self.session().login.clone() else {
            return Ok(None);
        };
        match registry::session_rights(db, &login.sid, &login.sub).await? {
            Some(state) => Ok(Some(User {
                sub: login.sub,
                username: login.username,
                name: login.name,
                listed_admin: state.is_admin,
            })),
            None => {
                self.session().end_login();
                Ok(None)
            }
        }
    }

    /// A page that needs a login: without one, remember where to come back and go to the login.
    pub async fn need_user(&self, db: &mut Db) -> Result<User, Reject> {
        let Some(user) = self.user(db).await? else {
            let target = self.return_to();
            self.session().next = Some(target);
            return Err(Reject::Login);
        };
        Ok(user)
    }

    /// The JSON API's login: 401 `login_required` (the script reloads the page, which goes through
    /// the login).
    pub async fn api_user(&self, db: &mut Db) -> Result<User, Reject> {
        self.user(db).await?.ok_or(Reject::Json(StatusCode::UNAUTHORIZED, "login_required"))
    }

    /// An admin page: the login ([`Ctx::need_user`]), then the admin right checked live: 403 for
    /// a person the registry does not list as admin or whose right Authentik no longer confirms
    /// (the flag is cleared and their sessions end), 503 when Authentik cannot be asked.
    pub async fn need_admin(&self, app: &App, db: &mut Db) -> Result<Admin, Reject> {
        let user = self.need_user(db).await?;
        self.verify_admin(app, Some(db), user).await
    }

    /// An admin API call: [`Ctx::api_user`], then as [`Ctx::need_admin`] (JSON `forbidden`,
    /// `unavailable`).
    pub async fn api_admin(&self, app: &App, db: &mut Db) -> Result<Admin, Reject> {
        let user = self.api_user(db).await?;
        self.verify_admin(app, Some(db), user).await
    }

    /// The admin routes' gate ([`crate::pipeline::admin_gate`]): [`Ctx::need_admin`] for a page,
    /// [`Ctx::api_admin`] for the JSON API, with the registry connection held only for the login
    /// (none at all for a session without one: the login or 401 at once, as [`crate::web::Reg`]
    /// answers), not while Authentik is asked.
    pub async fn gate_admin(&self, app: &App) -> Result<Admin, Reject> {
        let json = self.wants_json();
        if self.session().login.is_none() {
            if json {
                return Err(Reject::Json(StatusCode::UNAUTHORIZED, "login_required"));
            }
            let target = self.return_to();
            self.session().next = Some(target);
            return Err(Reject::Login);
        }
        let user = {
            let mut db = app.registry().await?;
            if json { self.api_user(&mut db).await? } else { self.need_user(&mut db).await? }
        };
        self.verify_admin(app, None, user).await
    }

    /// Where admin rights widen what a route shows or allows (another person's device, the admin
    /// view of one): `None` for a person the registry does not list as admin (no question
    /// asked); else the live check: `Some(Admin)`, or refused when the right is gone (as
    /// [`Ctx::need_admin`]). When Authentik cannot be asked: 503 if the route needs the right
    /// (`required`), else `None` (the resident's view: resident pages work without Authentik).
    pub async fn admin_for(
        &self,
        app: &App,
        db: &mut Db,
        user: &User,
        required: bool,
    ) -> Result<Option<Admin>, Reject> {
        if !user.listed_admin {
            return Ok(None);
        }
        match self.verify_admin(app, Some(db), user.clone()).await {
            Ok(admin) => Ok(Some(admin)),
            Err(Reject::Message(status, _)) if status == StatusCode::SERVICE_UNAVAILABLE && !required => Ok(None),
            Err(reject) => Err(reject),
        }
    }

    /// The one place an [`Admin`] is made: the registry lists the person as admin and Authentik
    /// confirms it now. When it does not, the flag is cleared (over `db`, or a connection of the
    /// pool) and the person's sessions end.
    async fn verify_admin(&self, app: &App, db: Option<&mut Db>, user: User) -> Result<Admin, Reject> {
        if !user.listed_admin {
            return Err(Reject::forbidden());
        }
        match app.admin_check.verify(&user.sub).await {
            Verdict::Admin => Ok(Admin { user }),
            Verdict::NotAdmin => {
                match db {
                    Some(db) => self.right_gone(db, &user).await?,
                    None => self.right_gone(&mut app.registry().await?, &user).await?,
                }
                Err(Reject::forbidden())
            }
            Verdict::Unknown => Err(Reject::Message(StatusCode::SERVICE_UNAVAILABLE, "admin_unavailable")),
        }
    }

    /// Authentik no longer confirms the right: the registry's flag goes (which ends every portal
    /// session of the person), this request's login too.
    async fn right_gone(&self, db: &mut Db, user: &User) -> Result<(), Reject> {
        registry::set_admin(db, &user.sub, false).await?;
        db.commit().await?;
        self.session().end_login();
        tracing::info!(
            target: LOG,
            "{} is no longer an admin in Authentik: admin flag cleared, portal sessions ended",
            user.sub
        );
        Ok(())
    }

    /// Where the login goes back to (Python `return_to`): the page itself for a GET; a consent
    /// sent after the session ended goes back to the consent page (the authorize URL from its
    /// non-empty fields); a form from the admin page back there; any other form to the start page
    /// (its POST URL would answer 405, and the form is not sent again).
    pub fn return_to(&self) -> String {
        if self.method == Method::GET || self.method == Method::HEAD {
            return match &self.query {
                Some(q) if !q.is_empty() => format!("{}?{q}", self.path),
                _ => self.path.clone(),
            };
        }
        if self.path == "/oauth/authorize" {
            let fields: Vec<(&str, &str)> = CONSENT_ARGS
                .iter()
                .filter_map(|k| self.form.get(*k).filter(|v| !v.is_empty()).map(|v| (*k, v.as_str())))
                .collect();
            return with_query("/oauth/authorize", &fields);
        }
        if self.field("back") == "/admin" {
            return "/admin".into();
        }
        "/".into()
    }
}

/// [`Ctx::wants_json`] from the request line and `Accept`.
pub fn wants_json(method: &Method, path: &str, accept: &str) -> bool {
    path.starts_with("/api/") || (method == Method::POST && best_accept(accept).as_deref() == Some("application/json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(method: Method, path: &str, query: Option<&str>, form: &[(&str, &str)]) -> Ctx {
        Ctx(Arc::new(Inner {
            lang: "en",
            method,
            path: path.into(),
            query: query.map(str::to_string),
            args: IndexMap::new(),
            form: form.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            user_agent: String::new(),
            accept: String::new(),
            now: OffsetDateTime::now_utc(),
            session: Mutex::new(Session::new()),
            fate: Mutex::new(CookieFate::Keep),
        }))
    }

    #[test]
    fn test_return_to() {
        assert_eq!(
            ctx(Method::GET, "/admin", Some("q=abc&state=online"), &[]).return_to(),
            "/admin?q=abc&state=online"
        );
        assert_eq!(ctx(Method::GET, "/admin/aps", None, &[]).return_to(), "/admin/aps");
        assert_eq!(ctx(Method::HEAD, "/devices/x", Some(""), &[]).return_to(), "/devices/x");
        let consent = ctx(
            Method::POST,
            "/oauth/authorize",
            None,
            &[
                ("client_id", "app.geteduroam.win"),
                ("state", ""),
                ("csrf", "x"),
                ("name", "laptop"),
                ("scope", "eap-metadata"),
            ],
        );
        assert_eq!(consent.return_to(), "/oauth/authorize?client_id=app.geteduroam.win&scope=eap-metadata");
        assert_eq!(ctx(Method::POST, "/devices/x/revoke", None, &[("back", "/admin")]).return_to(), "/admin");
        for back in ["", "/elsewhere", "//evil.example/", "https://evil.example/"] {
            assert_eq!(ctx(Method::POST, "/enroll", None, &[("back", back)]).return_to(), "/");
        }
    }

    #[test]
    fn test_wants_json() {
        assert!(wants_json(&Method::GET, "/api/devices", ""));
        assert!(wants_json(&Method::POST, "/devices/x/rename", "application/json"));
        assert!(!wants_json(&Method::POST, "/devices/x/rename", "text/html, application/json;q=0.5"));
        assert!(!wants_json(&Method::GET, "/devices/x", "application/json"));
        assert!(!wants_json(&Method::POST, "/enroll", ""));
    }
}
