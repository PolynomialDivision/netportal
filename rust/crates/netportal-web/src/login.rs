//! `/login`, `/auth/callback`, `/logout` (INVENTORY 3.2 rows 1-3, 4.4).

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
/// NEW session goes back to where the login was asked for (a local path only). An unknown, used
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
    let state = registry::person_state(&mut reg, &sub).await?.ok_or(Reject::Internal)?;
    reg.commit().await?;
    let next = ctx.session().next.take();
    let now = ctx.now_unix();
    let mut fresh = Session::new();
    fresh.login = Some(Login { sub, username, name, login_at: now, seen_at: now, epoch: state.session_epoch });
    *ctx.session() = fresh;
    let target = next.as_deref().and_then(safe_local_path).unwrap_or("/");
    Ok(redirect(target))
}

/// End every portal session of this login's person (their session epoch moves on), if the
/// cookie's login is still a valid one (a stale copy cannot log the person out elsewhere).
async fn end_sessions(db: &mut Db, login: &Login) -> Result<(), registry::RegistryError> {
    if let Some(state) = registry::person_state(db, &login.sub).await?
        && state.session_epoch == login.epoch
    {
        registry::end_sessions(db, &login.sub).await?;
    }
    db.commit().await?;
    Ok(())
}

/// `POST /logout` (CSRF checked): every portal session of the person ends, the cookie is
/// removed, then to the house's logout (`NETPORTAL_LOGOUT_URL`, which ends the Authentik
/// session; the portal's own page would log straight back in) or `/`.
pub async fn logout(State(app): State<App>, ctx: Ctx) -> Response {
    let login = ctx.session().login.clone();
    if let Some(login) = login {
        match app.registry().await {
            Ok(mut db) => {
                if let Err(e) = end_sessions(&mut db, &login).await {
                    tracing::warn!(target: LOG, "logout of {}: sessions not ended: {e}", login.sub);
                }
            }
            Err(_) => tracing::warn!(target: LOG, "logout of {}: sessions not ended (registry unavailable)", login.sub),
        }
    }
    ctx.set_fate(CookieFate::Remove);
    redirect(app.settings.logout_url.as_deref().unwrap_or("/"))
}
