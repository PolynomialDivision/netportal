//! `/login`, `/auth/callback`, `/logout`, `/logout/all` (INVENTORY 3.2 rows 1-3, 4.4).

use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use netportal_core::Db;
use netportal_core::registry;
use netportal_offboard::actions;

use crate::ctx::{CookieFate, Ctx};
use crate::errors::Reject;
use crate::http::safe_local_path;
use crate::platform::visible_text;
use crate::session::{Login, PendingLogin, Session};
use crate::web::App;

const LOG: &str = "netportal.web";
/// Names longer than this are cut (they travel in the session cookie).
const NAME_MAX: usize = 128;

/// A `302` to `location` (relative or absolute).
pub fn redirect(location: &str) -> Response {
    let mut response = StatusCode::FOUND.into_response();
    if let Ok(v) = HeaderValue::from_str(location) {
        response.headers_mut().insert(header::LOCATION, v);
    }
    response
}

/// `GET /login`: to Authentik's authorization endpoint (code flow, PKCE S256, state, nonce; the
/// three secrets stay in the encrypted session cookie until the callback).
pub async fn login(State(app): State<App>, ctx: Ctx) -> Result<Response, Reject> {
    let started = app.oidc.start().await.map_err(|e| {
        tracing::warn!(target: LOG, "login not possible: {e}");
        Reject::Unavailable
    })?;
    ctx.session().add_pending(PendingLogin {
        state: started.state,
        nonce: started.nonce,
        verifier: started.verifier,
        at: ctx.now_unix(),
    });
    Ok(redirect(started.url.as_str()))
}

/// A name for the cookie and the pages: no control, bidi or zero-width characters
/// ([`visible_text`]), at most [`NAME_MAX`] characters.
fn cut(text: &str) -> String {
    visible_text(text).chars().take(NAME_MAX).collect()
}

/// A failed login: logged by kind, 400 `t.error`. Only the pending login it belonged to is gone
/// (taken by the callback); a session the browser already had stays: a failed or forged callback
/// must not log anyone out.
fn failed(why: &str) -> Reject {
    tracing::info!(target: LOG, "login failed: {why}");
    Reject::bad_request()
}

/// `GET /auth/callback`: the state must be a pending login of this session (once), the code is
/// exchanged and the ID token validated; then the person is recorded with the policy and admin
/// flag of their groups (a policy change moves their devices, with a Disconnect each), and a
/// NEW session (a new row on the server, its id in the cookie) goes back to where the login was
/// asked for (a local path only). An unknown, used
/// or expired state (e.g. a link another site put there) is a 400 that changes nothing but
/// dropping that one pending login; the registry is asked only after the code exchange.
pub async fn callback(State(app): State<App>, ctx: Ctx) -> Result<Response, Reject> {
    let pending = ctx.session().take_pending(ctx.arg("state"), ctx.now_unix());
    let Some(pending) = pending else {
        return Err(failed("unknown, used or expired state"));
    };
    let error = ctx.arg("error");
    if !error.is_empty() {
        let code: String = error.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_').take(40).collect();
        return Err(failed(&format!("provider: {code}")));
    }
    let code = ctx.arg("code");
    if code.is_empty() {
        return Err(failed("no code"));
    }
    let claims = match app.oidc.finish(code, &pending.verifier, &pending.nonce).await {
        Ok(claims) => claims,
        Err(e) => return Err(failed(&e.0)),
    };
    let groups = claims.groups.clone().unwrap_or_default();
    let Some(policy) = app.settings.policies.policy_for(&groups).map(str::to_string) else {
        tracing::info!(target: LOG, "login refused for {}: no policy for the groups", claims.sub);
        ctx.set_fate(CookieFate::Remove);
        return Err(Reject::Message(StatusCode::FORBIDDEN, "no_access"));
    };
    let sub = claims.sub.clone();
    let username = cut(claims.preferred_username.as_deref().unwrap_or(&sub));
    let name = claims.name.as_deref().map(cut).filter(|n| !n.is_empty()).unwrap_or_else(|| username.clone());
    let admin = groups.iter().any(|g| app.settings.policies.admin_groups.contains(g));
    let mut reg = app.registry().await?;
    registry::upsert_person(&mut reg, &sub, &username, &name, admin).await?;
    let moved = actions::apply_policy(&mut reg, &sub, &policy, &sub, &app.disconnector).await?;
    for result in moved.iter().flat_map(|(_, results)| results) {
        app.metrics.disconnected(result.as_str());
    }
    // the browser's previous login (from its authenticated cookie) ends on the server too: a
    // copy of that cookie is no login once someone else (or the same person) logs in here
    let old = ctx.session().login_sid();
    if let Some(old) = old {
        registry::end_session(&mut reg, &old).await?;
    }
    let sid = registry::start_session(&mut reg, &sub).await?;
    reg.commit().await?;
    let next = ctx.session().next.take();
    let now = ctx.now_unix();
    let mut fresh = Session::new();
    fresh.login = Some(Login { sub, username, name, login_at: now, seen_at: now, sid });
    *ctx.session() = fresh;
    let target = next.as_deref().and_then(safe_local_path).unwrap_or("/");
    Ok(redirect(target))
}

/// End this login's session, or (`everywhere`) every portal session of its person, if this one
/// still lives (a stale copy of a cookie cannot log the person out elsewhere).
async fn end_sessions(db: &mut Db, login: &Login, everywhere: bool) -> Result<(), registry::RegistryError> {
    if !everywhere {
        registry::end_session(db, &login.sid).await?;
    } else if registry::session_rights(db, &login.sid, &login.sub).await?.is_some() {
        let n = registry::end_sessions(db, &login.sub).await?;
        tracing::info!(target: LOG, "{} logged out everywhere: {n} portal session(s) ended", login.sub);
    }
    db.commit().await?;
    Ok(())
}

/// The cookie's session ends (`everywhere`: every session of the person), the cookie is removed,
/// then to the house's logout (`NETPORTAL_LOGOUT_URL`, which ends the Authentik session; the
/// portal's own page would log straight back in) or `/`. A login the cookie no longer counts
/// (idle or too old) still ends its row, so a copy of the cookie that kept it alive stops too.
/// When the registry cannot end it, the cookie stays and the answer is 503 (`logout_failed`):
/// the person must not believe that copies of their cookie stopped working.
async fn log_out(app: &App, ctx: &Ctx, everywhere: bool) -> Result<Response, Reject> {
    let (login, ended_sid) = {
        let session = ctx.session();
        (session.login.clone(), session.ended_sid.clone())
    };
    let sub = login.as_ref().map(|l| l.sub.clone());
    let ended = match (login, ended_sid) {
        (Some(login), _) => match app.registry().await {
            Ok(mut db) => end_sessions(&mut db, &login, everywhere).await.map_err(|e| e.to_string()),
            Err(_) => Err("registry unavailable".to_string()),
        },
        (None, Some(sid)) => match app.registry().await {
            Ok(mut db) => match registry::end_session(&mut db, &sid).await {
                Ok(_) => db.commit().await.map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            },
            Err(_) => Err("registry unavailable".to_string()),
        },
        (None, None) => Ok(()),
    };
    if let Err(e) = ended {
        tracing::warn!(target: LOG, "logout of {}: sessions not ended: {e}", sub.as_deref().unwrap_or("an ended login"));
        return Err(Reject::Message(StatusCode::SERVICE_UNAVAILABLE, "logout_failed"));
    }
    ctx.set_fate(CookieFate::Remove);
    Ok(redirect(app.settings.logout_url.as_deref().unwrap_or("/")))
}

/// `POST /logout` (CSRF checked): this session ends (the person's other devices stay logged in),
/// the cookie is removed, then to `NETPORTAL_LOGOUT_URL` or `/`.
pub async fn logout(State(app): State<App>, ctx: Ctx) -> Result<Response, Reject> {
    log_out(&app, &ctx, false).await
}

/// `POST /logout/all` (CSRF checked): every portal session of the person ends, this one included
/// (every browser and device, copies of a cookie too), then as `/logout`.
pub async fn logout_all(State(app): State<App>, ctx: Ctx) -> Result<Response, Reject> {
    log_out(&app, &ctx, true).await
}
