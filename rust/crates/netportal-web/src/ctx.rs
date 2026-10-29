//! One browser request as the handlers see it (Python: Flask's `g`, `session`, `request`): the
//! language, the session (changed by the handlers, written back by the pipeline), the query and
//! form values, and the login's rights, read from the registry on every request that needs them
//! (INVENTORY 4.3).

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
use crate::session::Session;

/// The consent form's fields, re-sent as the authorize URL when the login interrupts a consent
/// (Python `CONSENT_ARGS`).
pub const CONSENT_ARGS: [&str; 7] =
    ["client_id", "redirect_uri", "response_type", "code_challenge", "code_challenge_method", "state", "scope"];

/// The logged-in person with the rights the registry gives now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub sub: String,
    pub username: String,
    pub name: String,
    pub admin: bool,
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

    /// The logged-in person with the rights the registry gives now, or `None`; a person no longer
    /// active (offboarded, unknown) or a session of an ended epoch (logout elsewhere, offboarded
    /// since) ends the login here and now.
    pub async fn user(&self, db: &mut Db) -> Result<Option<User>, Reject> {
        let Some(login) = self.session().login.clone() else {
            return Ok(None);
        };
        match registry::person_state(db, &login.sub).await? {
            Some(state) if state.session_epoch == login.epoch => {
                Ok(Some(User { sub: login.sub, username: login.username, name: login.name, admin: state.is_admin }))
            }
            _ => {
                self.session().end_login();
                Ok(None)
            }
        }
    }

    /// A page that needs a login: without one, remember where to come back and go to the login.
    pub async fn need_user(&self, db: &mut Db, admin: bool) -> Result<User, Reject> {
        let Some(user) = self.user(db).await? else {
            let target = self.return_to();
            self.session().next = Some(target);
            return Err(Reject::Login);
        };
        if admin && !user.admin {
            return Err(Reject::forbidden());
        }
        Ok(user)
    }

    /// The JSON API's login: 401 `login_required` (the script reloads the page, which goes through
    /// the login), 403 `forbidden` for a non-admin.
    pub async fn api_user(&self, db: &mut Db, admin: bool) -> Result<User, Reject> {
        let Some(user) = self.user(db).await? else {
            return Err(Reject::Json(StatusCode::UNAUTHORIZED, "login_required"));
        };
        if admin && !user.admin {
            return Err(Reject::Json(StatusCode::FORBIDDEN, "forbidden"));
        }
        Ok(user)
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
