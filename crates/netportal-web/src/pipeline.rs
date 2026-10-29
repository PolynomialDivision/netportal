//! The request pipeline (Python `before_request`, `after_request`, the error handlers; INVENTORY
//! 3.1, 3.4, 3.6, 4.2, 4.8), as two middlewares (see [`crate::web`] for where they sit).

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Response};
use axum_extra::extract::cookie::CookieJar;
use indexmap::IndexMap;
use minijinja::context;
use netportal_core::registry;

use crate::ctx::{CookieFate, Ctx, Inner, User, wants_json};
use crate::errors::{Reject, Rejected, Sparse, json_error, left_out, status_code_name};
use crate::http::parse_pairs;
use crate::render::{Base, RequestView};
use crate::session::{Session, same_token};
use crate::web::{App, BODY_LIMIT, BODY_READ_TIMEOUT};

const LOG: &str = "netportal.web";

/// What a page needs in its Content-Security-Policy beyond the default (a response extension
/// the handler sets).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Policy {
    /// the dashboard pages: the portal's own static scripts, which read its JSON API
    Dashboard,
    /// the consent page: the app's redirect target as a form-action source (browsers apply
    /// form-action to the redirect after the POST)
    FormAction(String),
}

/// The CSP of a response (3.4): no script anywhere except the dashboard pages' own static
/// modules, no inline code or style, no framing, forms only to the portal.
pub fn csp(policy: Option<&Policy>) -> String {
    let scripts = if policy == Some(&Policy::Dashboard) { "script-src 'self'; connect-src 'self'; " } else { "" };
    let form_action = match policy {
        Some(Policy::FormAction(origin)) => format!("'self' {origin}"),
        _ => "'self'".to_string(),
    };
    format!(
        "default-src 'none'; {scripts}style-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; \
         form-action {form_action}"
    )
}

fn header_str(headers: &HeaderMap, name: header::HeaderName) -> &str {
    headers.get(name).and_then(|v| v.to_str().ok()).unwrap_or("")
}

/// The request's language: the house's `house_lang` cookie, else `Accept-Language`.
pub fn language(headers: &HeaderMap) -> &'static str {
    let jar = CookieJar::from_headers(headers);
    netportal_core::i18n::pick(
        headers.get(header::ACCEPT_LANGUAGE).and_then(|v| v.to_str().ok()),
        jar.get("house_lang").map(|c| c.value()),
    )
}

fn set_default(headers: &mut HeaderMap, name: header::HeaderName, value: &str) {
    if !headers.contains_key(&name)
        && let Ok(v) = HeaderValue::from_str(value)
    {
        headers.insert(name, v);
    }
}

/// The security headers every response gets unless it set its own (4.8).
pub fn security_headers(response: &mut Response) {
    let policy = response.extensions().get::<Policy>().cloned();
    let headers = response.headers_mut();
    set_default(headers, header::CONTENT_SECURITY_POLICY, &csp(policy.as_ref()));
    set_default(headers, header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    set_default(headers, header::REFERRER_POLICY, "no-referrer");
    set_default(headers, header::CACHE_CONTROL, "no-store");
}

/// The message page (or a plain text if even that fails).
fn message_page(app: &App, base: &Base, status: StatusCode, text_key: &str) -> Response {
    let message = netportal_core::i18n::text(&base.lang, text_key).unwrap_or("error");
    match app.templates.render("message.html", base, context! { message => message }) {
        Ok(html) => (status, Html(html)).into_response(),
        Err(e) => {
            tracing::error!(target: "netportal.web", "template message.html failed: {e}");
            (status, [(header::CONTENT_TYPE, "text/plain; charset=utf-8")], "error\n").into_response()
        }
    }
}

/// A rejection as the request wants it (3.6).
fn render(app: &App, base: &Base, json: bool, reject: &Reject) -> Response {
    match reject {
        Reject::Login => (StatusCode::FOUND, [(header::LOCATION, "/login")]).into_response(),
        Reject::Json(status, code) => json_error(*status, code),
        Reject::Message(status, key) if !json => message_page(app, base, *status, key),
        other if json => {
            let status = other.status();
            json_error(status, status_code_name(status))
        }
        other => message_page(app, base, other.status(), "error"),
    }
}

static SHED: Sparse = Sparse::new();
static ANSWERED_503: Sparse = Sparse::new();

/// A 503 tells the client when to try again (load shedding, a busy or unreachable registry, the
/// request timeout).
pub const RETRY_AFTER_S: &str = "5";

/// Load shedding: at most `NETPORTAL_MAX_REQUESTS` requests at once, one more is answered 503
/// at once (rendered by [`outer`], with `Retry-After`) instead of queueing. `/healthz` is not
/// counted (its registry check is cached: [`App::registry_ok`]), so a flood does not make the
/// container look dead.
pub async fn shed(State(app): State<App>, req: Request, next: Next) -> Response {
    if req.uri().path() == "/healthz" {
        return next.run(req).await;
    }
    match app.requests.clone().try_acquire_owned() {
        Ok(permit) => {
            let response = next.run(req).await;
            drop(permit);
            response
        }
        Err(_) => {
            if let Some(n) = SHED.due() {
                tracing::warn!(
                    target: "netportal.web",
                    "busy: {} requests at once, one more answered 503{}",
                    app.settings.max_requests,
                    left_out(n)
                );
            }
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}

/// Every request body is read whole before routing's handlers see it: within
/// [`BODY_READ_TIMEOUT`] (a client sending its body slowly gets 408 and the connection's slot
/// back) and [`BODY_LIMIT`] (413).
pub async fn read_body(req: Request, next: Next) -> Response {
    read_body_within(BODY_READ_TIMEOUT, req, next).await
}

/// [`read_body`] with another deadline (the server's tests).
pub async fn read_body_within(deadline: std::time::Duration, req: Request, next: Next) -> Response {
    let (parts, body) = req.into_parts();
    match tokio::time::timeout(deadline, axum::body::to_bytes(body, BODY_LIMIT)).await {
        Err(_) => StatusCode::REQUEST_TIMEOUT.into_response(),
        Ok(Err(_)) => StatusCode::PAYLOAD_TOO_LARGE.into_response(),
        Ok(Ok(bytes)) => next.run(Request::from_parts(parts, Body::from(bytes))).await,
    }
}

/// The gate of the admin routes (`web::Gate::Admin`, inside [`browser`]): the login and the admin
/// right checked live with Authentik ([`Ctx::gate_admin`]: as [`Ctx::need_admin`], or
/// [`Ctx::api_admin`] for the JSON routes) before the handler runs; the handler takes the
/// [`crate::ctx::Admin`] it leaves in the request. A refusal is rendered by [`browser`] (403, 503,
/// or the login).
pub async fn admin_gate(State(app): State<App>, mut req: Request, next: Next) -> Response {
    let Some(ctx) = req.extensions().get::<Ctx>().cloned() else {
        return Reject::Internal.into_response();
    };
    match ctx.gate_admin(&app).await {
        Ok(admin) => {
            req.extensions_mut().insert(admin);
            next.run(req).await
        }
        Err(reject) => reject.into_response(),
    }
}

/// Outermost: OPTIONS, routing's own 404/405 (and the timeout's and the load shedding's 503) as
/// pages or JSON with their `Allow`, `Retry-After` on a 503, the security headers.
pub async fn outer(State(app): State<App>, req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let accept = header_str(req.headers(), header::ACCEPT).to_string();
    let lang = language(req.headers());
    let mut response = next.run(req).await;
    let bare = !response.headers().contains_key(header::CONTENT_TYPE)
        && response.extensions().get::<Rejected>().is_none()
        && matches!(response.status().as_u16(), 400 | 404 | 405 | 408 | 413 | 503);
    if method == Method::OPTIONS && response.status() == StatusCode::METHOD_NOT_ALLOWED {
        // OPTIONS changes nothing: the route's methods
        let allow = response.headers().get(header::ALLOW).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        let allow = if allow.is_empty() { "OPTIONS".to_string() } else { format!("{allow},OPTIONS") };
        response = StatusCode::NO_CONTENT.into_response();
        if let Ok(v) = HeaderValue::from_str(&allow) {
            response.headers_mut().insert(header::ALLOW, v);
        }
    } else if bare {
        let allow = response.headers().get(header::ALLOW).cloned();
        let base = Base {
            lang: lang.to_string(),
            user: None,
            csrf: String::new(),
            settings: app.settings_view(),
            host: app.host.clone(),
            no_passpoint_browser: false,
            request: RequestView { path: path.clone(), args: IndexMap::new() },
        };
        let status = response.status();
        response = render(&app, &base, wants_json(&method, &path, &accept), &Reject::Status(status));
        if let Some(allow) = allow {
            response.headers_mut().insert(header::ALLOW, allow);
        }
    }
    if response.status() == StatusCode::SERVICE_UNAVAILABLE && !response.headers().contains_key(header::RETRY_AFTER) {
        response.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from_static(RETRY_AFTER_S));
    }
    security_headers(&mut response);
    response
}

/// The server row of a login whose cookie passed its limit.
async fn end_expired_session(app: &App, sid: &str) {
    let ended = match app.registry().await {
        Ok(mut db) => match registry::end_session(&mut db, sid).await {
            Ok(_) => db.commit().await.map_err(|e| e.to_string()),
            Err(e) => Err(e.to_string()),
        },
        Err(_) => Err("registry unavailable".to_string()),
    };
    if let Err(e) = ended {
        tracing::warn!(target: LOG, "an expired portal session was not ended on the server: {e}");
    }
}

fn is_form(headers: &HeaderMap) -> bool {
    header_str(headers, header::CONTENT_TYPE)
        .split(';')
        .next()
        .is_some_and(|t| t.trim().eq_ignore_ascii_case("application/x-www-form-urlencoded"))
}

/// The browser routes: session, language, form, the stale-script 401, the CSRF check (every
/// POST), then after the handler the rendering of rejections and the session cookie.
pub async fn browser(State(app): State<App>, req: Request, next: Next) -> Response {
    let now = app.now();
    let (mut parts, body) = req.into_parts();
    let original = app.cookies.read(&parts.headers);
    let mut session = original.clone().unwrap_or_else(Session::new);
    let now_s = now.unix_timestamp();
    if let Some(login) = session.login.as_mut() {
        if login.fresh(now_s) {
            login.seen_at = now_s;
        } else {
            session.end_login();
            // the idle (or absolute) limit is the cookie's: its row ends on the server too, so
            // a copy of the cookie kept fresh elsewhere stops with it (once: the cookie written
            // back has no login any more); not waited for, a failure leaves the 12 h limit
            if let Some(sid) = session.ended_sid.clone() {
                let app = app.clone();
                tokio::spawn(async move { end_expired_session(&app, &sid).await });
            }
        }
    }
    let method = parts.method.clone();
    let mut too_large = false;
    let mut form = IndexMap::new();
    if method == Method::POST {
        // read by [`read_body`] already: no wait here
        match axum::body::to_bytes(body, BODY_LIMIT).await {
            Ok(bytes) if is_form(&parts.headers) => form = parse_pairs(&bytes),
            Ok(_) => {}
            Err(_) => too_large = true,
        }
    }
    let query = parts.uri.query().map(str::to_string);
    let ctx = Ctx(Arc::new(Inner {
        lang: language(&parts.headers),
        method: method.clone(),
        path: parts.uri.path().to_string(),
        args: query.as_deref().map(|q| parse_pairs(q.as_bytes())).unwrap_or_default(),
        query,
        form,
        user_agent: header_str(&parts.headers, header::USER_AGENT).to_string(),
        accept: header_str(&parts.headers, header::ACCEPT).to_string(),
        now,
        session: Mutex::new(session),
        fate: Mutex::new(CookieFate::Keep),
    }));
    let logged_in = ctx.session().login.is_some();
    let early = if too_large {
        Some(Reject::Status(StatusCode::PAYLOAD_TOO_LARGE))
    } else if method == Method::POST && !logged_in && ctx.wants_json() {
        // a dashboard script's POST after the session ended: "log in again", not a CSRF error
        // (nothing is changed either way)
        Some(Reject::Json(StatusCode::UNAUTHORIZED, "login_required"))
    } else if method == Method::POST && !same_token(ctx.field("csrf"), &ctx.csrf()) {
        Some(Reject::bad_request())
    } else {
        None
    };
    let response = match early {
        Some(reject) => reject.into_response(),
        None => {
            parts.extensions.insert(ctx.clone());
            next.run(Request::from_parts(parts, Body::empty())).await
        }
    };
    finish(&app, &ctx, original, response)
}

fn finish(app: &App, ctx: &Ctx, original: Option<Session>, mut response: Response) -> Response {
    if let Some(Rejected(reject)) = response.extensions().get::<Rejected>().cloned() {
        // the cause is logged where it happened (by kind); here which request it hit (a 503,
        // which a flood repeats, sparsely)
        let due = match reject {
            Reject::Internal => Some(0),
            Reject::Unavailable => ANSWERED_503.due(),
            _ => None,
        };
        if let Some(n) = due {
            tracing::warn!(
                target: "netportal.web",
                "{} {} answered {}{}",
                ctx.method,
                crate::http::loggable_path(&ctx.path),
                reject.status().as_u16(),
                left_out(n)
            );
        }
        let login = ctx.session().login.clone();
        let user = login.map(|l| User { sub: l.sub, username: l.username, name: l.name, listed_admin: false });
        let base = app.base(ctx, user.as_ref());
        response = render(app, &base, ctx.wants_json(), &reject);
    }
    match ctx.fate() {
        CookieFate::Remove => response = (app.cookies.remove(), response).into_response(),
        CookieFate::Keep => {
            let mut session = ctx.session().clone();
            if (Some(&session) != original.as_ref() || session.login.is_some())
                && let Some(jar) = app.cookies.write(&mut session)
            {
                response = (jar, response).into_response();
            }
        }
    }
    response.headers_mut().append(header::VARY, HeaderValue::from_static("Cookie"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csp() {
        assert_eq!(
            csp(None),
            "default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        );
        assert_eq!(
            csp(Some(&Policy::Dashboard)),
            "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; img-src 'self'; \
             base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        );
        assert!(
            csp(Some(&Policy::FormAction("app.eduroam.geteduroam:".into())))
                .ends_with("form-action 'self' app.eduroam.geteduroam:")
        );
    }
}
