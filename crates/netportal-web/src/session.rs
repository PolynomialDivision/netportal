//! The portal session (Python: Flask's signed client-side session, INVENTORY 4.1), done right:
//!
//! - One cookie, encrypted and authenticated (AES-256-GCM, the `cookie` crate's private jar as
//!   axum-extra exposes it; the cookie's name is the associated data). Its key is HKDF-Extract
//!   (HMAC-SHA-512) of `NETPORTAL_SESSION_SECRET` (at least 32 bytes, checked by core) with a
//!   fixed salt, so another secret means no session, and nothing in the cookie is readable.
//! - Name `__Host-netportal` with `Secure` when `NETPORTAL_BASE_URL` is https (the prefix
//!   requires Secure, `Path=/` and no `Domain`), `netportal` over plain http (local tests only);
//!   always `HttpOnly`, `SameSite=Lax` (the login comes back from Authentik as a cross-site
//!   navigation), `Path=/`, no `Domain`.
//! - The limits are enforced on the server from the timestamps inside the cookie: a login ends
//!   [`IDLE_S`] after the last request and [`MAX_S`] after the login however busy (a login time
//!   in the future ends it too). A logged-in cookie also expires in the browser [`IDLE_S`] after
//!   the last request (`Max-Age`, re-sent with every response); before the login it is a
//!   browser-session cookie.
//! - Every login gets a new session (new CSRF token, nothing carried over) and a row of its own
//!   on the server (registry `web_session`, the cookie carries its random id; only the id's
//!   SHA-256 is stored). Every request that resolves the login asks for that row, so ending it
//!   ends the cookie and every copy of it (responses still in flight that would set it again
//!   too): a logout ends its own session (`end_session`), "log out everywhere", an offboarding
//!   and the loss of the admin right end every session of the person (`end_sessions`).
//!
//! The cookie carries who it is (sub, names), the login's times and session id, the CSRF token,
//! where the login goes back to and the pending OIDC logins (state, nonce, PKCE verifier); never
//! a right: admin comes from the registry on every request, and is checked with Authentik
//! wherever it is used ([`crate::rights`]).

use axum::http::HeaderMap;
use axum_extra::extract::cookie::{Cookie, CookieJar, Key, PrivateCookieJar, SameSite};
use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use subtle::ConstantTimeEq;

/// A login ends this long after the last request (seconds).
pub const IDLE_S: i64 = 8 * 3600;
/// ... and this long after the login, however busy (seconds; the registry's session rows end
/// then too).
pub const MAX_S: i64 = netportal_core::registry::SESSION_LIFETIME.whole_seconds();
/// A started login (Authentik's form) must come back within this time (seconds).
pub const PENDING_LOGIN_S: i64 = 20 * 60;
/// Logins started at once (several tabs) that may be pending together.
pub const PENDING_LOGINS: usize = 4;
/// The session format; another version is no session (2: the server-side session id).
const VERSION: u32 = 2;
/// Cookies above this size are not set reliably; pending logins go first.
const MAX_COOKIE_JSON: usize = 2800;

const KEY_SALT: &[u8] = b"netportal session cookie v1";

/// The cookie key from `NETPORTAL_SESSION_SECRET`: HKDF-Extract with SHA-512 (64 bytes: the
/// cookie crate's signing and encryption halves).
pub fn cookie_key(secret: &[u8]) -> Result<Key, String> {
    if secret.len() < 32 {
        return Err("NETPORTAL_SESSION_SECRET: at least 32 bytes".into());
    }
    let mut mac = <Hmac<Sha512> as KeyInit>::new_from_slice(KEY_SALT).map_err(|e| e.to_string())?;
    mac.update(secret);
    let prk = mac.finalize().into_bytes();
    Key::try_from(prk.as_slice()).map_err(|e| e.to_string())
}

/// A random token: 32 bytes from the OS CSPRNG, base64url without padding (43 characters).
pub fn random_token() -> String {
    let bytes: [u8; 32] = rand::random();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Constant-time comparison of two tokens (an empty expected token never matches).
pub fn same_token(sent: &str, expected: &str) -> bool {
    !expected.is_empty() && sent.as_bytes().ct_eq(expected.as_bytes()).into()
}

/// Who is logged in, as the cookie says (the registry decides on the rights).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Login {
    pub sub: String,
    pub username: String,
    pub name: String,
    /// Unix seconds of the login
    pub login_at: i64,
    /// Unix seconds of the latest request (the idle limit)
    pub seen_at: i64,
    /// the id of the login's row on the server (registry `web_session`)
    pub sid: String,
}

impl Login {
    /// Within both limits at `now` (Unix seconds).
    pub fn fresh(&self, now: i64) -> bool {
        let age = now - self.login_at;
        let idle = now - self.seen_at;
        (0..MAX_S).contains(&age) && (0..IDLE_S).contains(&idle) && self.seen_at >= self.login_at
    }
}

/// An OIDC login started at `/login` and not back yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingLogin {
    pub state: String,
    pub nonce: String,
    pub verifier: String,
    /// Unix seconds
    pub at: i64,
}

/// The session's contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    pub v: u32,
    /// the synchronizer token every form (and the scripts' POSTs) send back
    pub csrf: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login: Option<Login>,
    /// where the login goes back to (a local path with its query)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pending: Vec<PendingLogin>,
    /// this request only (never in the cookie): the server row of a login [`Session::end_login`]
    /// dropped (idle or too old), so a logout or a new login still ends it on the server
    #[serde(skip)]
    pub ended_sid: Option<String>,
}

impl Session {
    /// A new anonymous session with a new CSRF token.
    pub fn new() -> Session {
        Session { v: VERSION, csrf: random_token(), login: None, next: None, pending: Vec::new(), ended_sid: None }
    }

    /// The login ends (stale, offboarded, unknown): the CSRF token stays, so a form sent now goes
    /// through the login instead of into a CSRF error.
    pub fn end_login(&mut self) {
        if let Some(login) = self.login.take() {
            self.ended_sid = Some(login.sid);
        }
    }

    /// The server row of this cookie's login, alive or just dropped by [`Session::end_login`].
    pub fn login_sid(&self) -> Option<String> {
        self.login.as_ref().map(|l| l.sid.clone()).or_else(|| self.ended_sid.clone())
    }

    /// Remember a started login (the newest few; older and expired ones go).
    pub fn add_pending(&mut self, login: PendingLogin) {
        let now = login.at;
        self.pending.retain(|p| (0..PENDING_LOGIN_S).contains(&(now - p.at)));
        self.pending.push(login);
        let excess = self.pending.len().saturating_sub(PENDING_LOGINS);
        self.pending.drain(..excess);
    }

    /// Take the pending login of this `state` (once), if it has not expired.
    pub fn take_pending(&mut self, state: &str, now: i64) -> Option<PendingLogin> {
        let index = self.pending.iter().position(|p| same_token(state, &p.state))?;
        let found = self.pending.remove(index);
        (0..PENDING_LOGIN_S).contains(&(now - found.at)).then_some(found)
    }

    fn encode(&mut self) -> Option<String> {
        loop {
            let json = serde_json::to_string(self).ok()?;
            if json.len() <= MAX_COOKIE_JSON || self.pending.is_empty() {
                return Some(json);
            }
            self.pending.remove(0);
        }
    }
}

impl Default for Session {
    fn default() -> Self {
        Session::new()
    }
}

/// The cookie's name and attributes for this portal.
#[derive(Clone)]
pub struct CookieConfig {
    pub key: Key,
    pub secure: bool,
}

impl CookieConfig {
    pub fn name(&self) -> &'static str {
        if self.secure { "__Host-netportal" } else { "netportal" }
    }

    /// The session in the request's cookie, `None` when there is none or it does not verify
    /// (another key, tampered, another format).
    pub fn read(&self, headers: &HeaderMap) -> Option<Session> {
        let jar = PrivateCookieJar::from_headers(headers, self.key.clone());
        let cookie = jar.get(self.name())?;
        let session: Session = serde_json::from_str(cookie.value()).ok()?;
        (session.v == VERSION && !session.csrf.is_empty()).then_some(session)
    }

    fn base(&self, value: String) -> Cookie<'static> {
        Cookie::build((self.name(), value))
            .path("/")
            .http_only(true)
            .secure(self.secure)
            .same_site(SameSite::Lax)
            .build()
    }

    /// The `Set-Cookie` for this session: `Max-Age` [`IDLE_S`] while logged in, a browser-session
    /// cookie before.
    pub fn write(&self, session: &mut Session) -> Option<PrivateCookieJar> {
        let json = session.encode()?;
        let mut cookie = self.base(json);
        if session.login.is_some() {
            cookie.set_max_age(time::Duration::seconds(IDLE_S));
        }
        Some(PrivateCookieJar::new(self.key.clone()).add(cookie))
    }

    /// The `Set-Cookie` that removes the session (logout, failed login): empty, `Max-Age=0`,
    /// with the cookie's attributes (a `__Host-` cookie is only replaced by a Secure one).
    pub fn remove(&self) -> CookieJar {
        let mut cookie = self.base(String::new());
        cookie.make_removal();
        CookieJar::new().add(cookie)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header;
    use axum::response::IntoResponse;

    fn config(secret: &str, secure: bool) -> CookieConfig {
        CookieConfig { key: cookie_key(secret.as_bytes()).expect("key"), secure }
    }

    fn round_trip(from: &CookieConfig, to: &CookieConfig, session: &mut Session) -> Option<Session> {
        let response = from.write(session).expect("cookie").into_response();
        let set = response.headers().get(header::SET_COOKIE).expect("set-cookie").to_str().expect("ascii").to_string();
        let pair = set.split(';').next().expect("pair").to_string();
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, pair.parse().expect("header"));
        to.read(&headers)
    }

    #[test]
    fn test_key_needs_32_bytes() {
        assert!(cookie_key(b"short").is_err());
        assert!(cookie_key(&[7u8; 32]).is_ok());
    }

    #[test]
    fn test_round_trip_and_binding_to_the_secret() {
        let a = config("a-session-secret-of-at-least-32-bytes", false);
        let b = config("b-session-secret-of-at-least-32-bytes", false);
        let mut session = Session::new();
        assert_eq!(round_trip(&a, &a, &mut session.clone()), Some(session.clone()));
        assert_eq!(round_trip(&a, &b, &mut session), None);
    }

    #[test]
    fn test_cookie_attributes() {
        let https = config("a-session-secret-of-at-least-32-bytes", true);
        let mut session = Session::new();
        let response = https.write(&mut session).expect("cookie").into_response();
        let set = response.headers()[header::SET_COOKIE].to_str().expect("ascii").to_string();
        assert!(set.starts_with("__Host-netportal="), "{set}");
        for attr in ["HttpOnly", "Secure", "SameSite=Lax", "Path=/"] {
            assert!(set.contains(attr), "{set}");
        }
        assert!(!set.contains("Domain") && !set.contains("Max-Age"), "{set}");
        session.login = Some(Login {
            sub: "s".into(),
            username: "u".into(),
            name: "n".into(),
            login_at: 1,
            seen_at: 1,
            sid: random_token(),
        });
        let response = https.write(&mut session).expect("cookie").into_response();
        let set = response.headers()[header::SET_COOKIE].to_str().expect("ascii").to_string();
        assert!(set.contains("Max-Age=28800"), "{set}");
        let plain = config("a-session-secret-of-at-least-32-bytes", false);
        let response = plain.remove().into_response();
        let set = response.headers()[header::SET_COOKIE].to_str().expect("ascii").to_string();
        assert!(set.starts_with("netportal=;") && set.contains("Max-Age=0") && !set.contains("Secure"), "{set}");
    }

    #[test]
    fn test_tampered_cookie_is_no_session() {
        let a = config("a-session-secret-of-at-least-32-bytes", false);
        let mut session = Session::new();
        let response = a.write(&mut session).expect("cookie").into_response();
        let set = response.headers()[header::SET_COOKIE].to_str().expect("ascii").to_string();
        let pair = set.split(';').next().expect("pair");
        let tampered = format!("{}AA", &pair[..pair.len() - 2]);
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, tampered.parse().expect("header"));
        assert_eq!(a.read(&headers), None);
    }

    #[test]
    fn test_session_fresh() {
        // Python SessionAgeTests.test_fresh, with the idle limit on the server too
        let now = 1_800_000_000;
        let login = |login_at: i64, seen_at: i64| Login {
            sub: "s".into(),
            username: "u".into(),
            name: "n".into(),
            login_at,
            seen_at,
            sid: "x".into(),
        };
        assert!(login(now - 60, now - 60).fresh(now));
        assert!(login(now - MAX_S + 1, now - 10).fresh(now));
        assert!(!login(now - MAX_S, now - 10).fresh(now));
        assert!(!login(now + 60, now + 60).fresh(now)); // from the future
        assert!(login(now - IDLE_S, now - IDLE_S + 1).fresh(now));
        assert!(!login(now - IDLE_S, now - IDLE_S).fresh(now)); // idle for 8 h
        assert!(!login(now - 60, now + 5).fresh(now)); // last request in the future
    }

    #[test]
    fn test_pending_logins() {
        let mut session = Session::new();
        for i in 0..6 {
            session.add_pending(PendingLogin {
                state: format!("s{i}"),
                nonce: "n".into(),
                verifier: "v".into(),
                at: 100 + i,
            });
        }
        assert_eq!(session.pending.len(), PENDING_LOGINS);
        assert!(session.take_pending("s0", 110).is_none()); // dropped as the oldest
        assert!(session.take_pending("s5", 110).is_some());
        assert!(session.take_pending("s5", 110).is_none()); // once
        assert!(session.take_pending("s4", 100 + PENDING_LOGIN_S + 10).is_none()); // expired
        assert!(session.take_pending("", 110).is_none());
    }

    #[test]
    fn test_same_token() {
        assert!(same_token("abc", "abc"));
        assert!(!same_token("abd", "abc"));
        assert!(!same_token("", ""));
        assert!(!same_token("abc", "abcd"));
    }
}
