//! The dashboard pages and their JSON API (INVENTORY 3.2 rows 4-6, 12-25, 3.3): the resident's
//! devices, one device's page, the admin pages, and the polled APIs (weak ETag without the
//! per-request values, 304, `Cache-Control: private, no-store`: the page's script keeps the
//! last body and its ETag itself and sends `If-None-Match`, so nothing needs the browser's
//! cache; the login is checked before the 304). The payloads are `netportal-telemetry`'s; every request has one Prometheus budget for
//! everything it shows.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use indexmap::IndexMap;
use minijinja::Value as Page;
use minijinja::context;
use minijinja::value::Serde;
use netportal_core::Db;
use netportal_core::conventions::{rfc3339, unix};
use netportal_core::registry::{self, DeviceRow, Person};
use netportal_pki::enroll::expires_soon;
use netportal_telemetry::telemetry::history::{self, HistoryOptions, Range};
use netportal_telemetry::telemetry::live::{self, Dashboard, DashboardOptions};
use netportal_telemetry::telemetry::{admin, house, identity, polled};
use regex::Regex;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::LazyLock;

use crate::ctx::{Admin, Ctx, User};
use crate::errors::Reject;
use crate::http::device_id;
use crate::letswifi::document;
use crate::login::redirect;
use crate::pipeline::Policy;
use crate::platform::enrol_options;
use crate::web::{App, Reg};

/// The renewal hint's window (days).
const EXPIRES_SOON_DAYS: i64 = 30;
/// The admin API's spans: (default, longest) in seconds.
const INCIDENT_SPAN: (f64, f64) = (7.0 * 86400.0, 400.0 * 86400.0);
const AUTH_SPAN: (f64, f64) = (86400.0, 31.0 * 86400.0);
const RAW_SPAN: (f64, f64) = (86400.0, 31.0 * 86400.0);
/// The incidents page's spans (`?range=`, when `?from=` is not given).
const INCIDENT_RANGES: [(&str, f64); 4] =
    [("7d", 7.0 * 86400.0), ("30d", 30.0 * 86400.0), ("90d", 90.0 * 86400.0), ("1y", 365.0 * 86400.0)];
/// The kinds the incidents page's filter offers.
pub const INCIDENT_KINDS: [&str; 10] = [
    "internet_down",
    "internet_degraded",
    "router_down",
    "dns_down",
    "ap_down",
    "ap_restarted",
    "switch_down",
    "switch_port_down",
    "unifi_data_stale",
    "radius_down",
];
/// The history ranges (`/api/devices/<id>/history`, the device page).
pub const HISTORY_RANGES: [&str; 6] = ["24h", "7d", "30d", "90d", "1y", "all"];

static INCIDENT_KIND: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z][a-z_]{0,39}$").expect("a valid regular expression"));
static LIMIT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[0-9]{1,4}$").expect("a valid regular expression"));
static UNIX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9]{1,12}(\.[0-9]+)?$").expect("a valid regular expression"));

/// A registry row as the templates read it (Python's keys; RFC 3339 times).
pub fn row_json(row: &DeviceRow) -> Value {
    json!({
        "id": row.id.to_string(), "owner": row.owner, "name": row.name, "platform": row.platform,
        "policy": row.policy, "created": rfc3339(row.created_at), "revoked": row.revoked_at.map(rfc3339),
        "expires": row.expires.map(rfc3339), "certificates": row.certificates,
        "last_seen": row.last_seen.map(rfc3339), "calling_station": row.calling_station,
        "first_seen": row.first_seen.map(rfc3339),
    })
}

/// `{sub: {sub, username, display}}` as the admin page reads the people.
pub fn people_json(people: &IndexMap<String, Person>) -> Value {
    Value::Object(
        people
            .iter()
            .map(|(sub, p)| (sub.clone(), json!({"sub": p.sub, "username": p.username, "display": p.display_name})))
            .collect(),
    )
}

fn serde<T: serde::Serialize>(value: &T) -> Page {
    Page::from(Serde(value))
}

fn dashboard_page(response: Result<Response, Reject>) -> Result<Response, Reject> {
    let mut response = response?;
    response.extensions_mut().insert(Policy::Dashboard);
    Ok(response)
}

/// The DASHBOARD of these rows with the renewal hint per device.
async fn dashboard_of(
    app: &App,
    page: &netportal_telemetry::telemetry::Page,
    db: &mut Db,
    rows: &[DeviceRow],
    owners: Option<&IndexMap<String, Person>>,
    admin: bool,
    detail: bool,
) -> Result<Dashboard, Reject> {
    let now = app.now();
    let opts = DashboardOptions {
        owners,
        admin,
        detail,
        interim_s: Some(i64::from(app.settings.acct_interim_s)),
        now: Some(unix(now)),
    };
    let mut payload = live::dashboard(page, db, rows, &opts).await?;
    for device in payload.devices.iter_mut() {
        let expires = rows.iter().find(|r| r.id.to_string() == device.id).and_then(|r| r.expires);
        device.expires_soon = Some(expires_soon(expires, now, EXPIRES_SOON_DAYS));
    }
    Ok(payload)
}

/// Every active device with its owner (the admin list and API).
async fn admin_dashboard(
    app: &App,
    page: &netportal_telemetry::telemetry::Page,
    db: &mut Db,
) -> Result<(Vec<DeviceRow>, IndexMap<String, Person>, Dashboard), Reject> {
    let people = registry::people(db).await?;
    let rows = registry::devices(db, None, false).await?;
    let payload = dashboard_of(app, page, db, &rows, Some(&people), true, false).await?;
    Ok((rows, people, payload))
}

/// A polled API's answer: 304 when the browser has this payload's ETag, else the JSON; both
/// with the ETag and `Cache-Control: private, no-store` (`polled::CACHE_CONTROL`).
fn polled_response(payload: Value, headers: &HeaderMap) -> Response {
    let tag = polled::etag(&payload);
    let inm = headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok());
    let mut response = if polled::matches(inm, &tag) {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        axum::Json(payload).into_response()
    };
    if let Ok(v) = HeaderValue::from_str(&tag) {
        response.headers_mut().insert(header::ETAG, v);
    }
    response.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static(polled::CACHE_CONTROL));
    response
}

fn to_json<T: serde::Serialize>(value: &T) -> Result<Value, Reject> {
    serde_json::to_value(value).map_err(|_| crate::errors::internal("payload not serialisable"))
}

/// The device of this URL for this person, not revoked, else 404: theirs, or another person's
/// for an admin. The admin view (other people's devices, conflicts, owners) needs the right
/// checked live: for another person's device it is required (refused or 503 without it), for
/// their own it is the admin's view when Authentik confirms it and the resident's when it cannot
/// be asked.
async fn visible_device(
    app: &App,
    ctx: &Ctx,
    db: &mut Db,
    id: &str,
    user: &User,
) -> Result<(DeviceRow, Option<Admin>), Reject> {
    let id = device_id(id).ok_or_else(Reject::not_found)?;
    let row = match registry::device(db, id, None).await? {
        Some(dev) if dev.revoked_at.is_none() => dev,
        _ => return Err(Reject::not_found()),
    };
    let own = row.owner == user.sub;
    if !own && !user.listed_admin {
        return Err(Reject::not_found());
    }
    match ctx.admin_for(app, db, user, !own).await? {
        None if !own => Err(Reject::not_found()),
        admin => Ok((row, admin)),
    }
}

/// Unix seconds from ISO 8601 (a date, or a time with or without an offset: UTC then) or Unix
/// seconds; the default when empty; `None` for anything else (Python `parse_time`).
pub fn parse_time(text: &str, default: f64) -> Option<f64> {
    let text = text.trim();
    if text.is_empty() {
        return Some(default);
    }
    if UNIX.is_match(text) {
        return text.parse().ok();
    }
    if text.len() > 40 {
        return None;
    }
    if let Ok(ts) = text.parse::<jiff::Timestamp>() {
        return Some(ts.as_millisecond() as f64 / 1000.0);
    }
    if let Ok(dt) = text.parse::<jiff::civil::DateTime>() {
        return dt.to_zoned(jiff::tz::TimeZone::UTC).ok().map(|z| z.timestamp().as_millisecond() as f64 / 1000.0);
    }
    None
}

/// `(since, until)` from `?from=&to=` (default: the last `span.0` seconds up to now; at most
/// `span.1`); `None`: unreadable, reversed or too long.
fn admin_span(ctx: &Ctx, now: f64, span: (f64, f64), incidents: bool) -> Option<(f64, f64)> {
    let until = parse_time(ctx.arg("to"), now)?;
    let mut default = span.0;
    if incidents
        && ctx.arg("from").is_empty()
        && let Some((_, s)) = INCIDENT_RANGES.iter().find(|(k, _)| *k == ctx.arg("range"))
    {
        default = *s;
    }
    let since = parse_time(ctx.arg("from"), until - default)?;
    (since <= until && until - since <= span.1).then_some((since, until))
}

/// `?kind=`: `None` for all, `Err` for an invalid one.
fn incident_kind(ctx: &Ctx) -> Result<Option<String>, ()> {
    match ctx.arg("kind") {
        "" => Ok(None),
        k if INCIDENT_KIND.is_match(k) => Ok(Some(k.to_string())),
        _ => Err(()),
    }
}

// --- pages ------------------------------------------------------------------------------------------

/// `GET /welcome`: the landing texts (the user shown when logged in; without a login in the
/// session no registry connection is taken).
pub async fn welcome(State(app): State<App>, ctx: Ctx) -> Result<Response, Reject> {
    let user = if ctx.session().login.is_some() {
        let mut reg = app.registry().await?;
        ctx.user(&mut reg).await?
    } else {
        None
    };
    app.page(&ctx, user.as_ref(), "landing.html", context! {})
}

/// `GET /`: the Let's Wi-Fi document for an app's probe (`Accept` with JSON, without HTML);
/// straight to the login when not logged in (no target remembered); else "My devices".
pub async fn index(State(app): State<App>, ctx: Ctx) -> Result<Response, Reject> {
    if ctx.accept.contains("application/json") && !ctx.accept.contains("text/html") {
        return Ok(axum::Json(document(&app.settings.base_url)).into_response());
    }
    if ctx.session().login.is_none() {
        return Ok(redirect("/login"));
    }
    let mut reg = app.registry().await?;
    let Some(user) = ctx.user(&mut reg).await? else {
        return Ok(redirect("/login"));
    };
    let page = app.telemetry.page();
    let rows = registry::devices(&mut reg, Some(&user.sub), false).await?;
    let payload = dashboard_of(&app, &page, &mut reg, &rows, None, false, false).await?;
    let rows_json: Vec<Value> = rows.iter().map(row_json).collect();
    let options = enrol_options(&ctx.user_agent, app.settings.passpoint);
    dashboard_page(app.page(
        &ctx,
        Some(&user),
        "devices.html",
        context! { devices => serde(&rows_json), dashboard => serde(&payload), options => options },
    ))
}

/// device.html's values: DASHBOARD of the device, DEVICE, the registry row, HISTORY of the
/// range asked for (an unknown one is 24h here), the ranges.
async fn device_context(
    app: &App,
    ctx: &Ctx,
    db: &mut Db,
    row: &DeviceRow,
    admin: Option<&Admin>,
) -> Result<BTreeMap<String, Page>, Reject> {
    let page = app.telemetry.page();
    let people = if admin.is_some() { Some(registry::people(db).await?) } else { None };
    let payload =
        dashboard_of(app, &page, db, std::slice::from_ref(row), people.as_ref(), admin.is_some(), true).await?;
    let range = Range::parse(ctx.arg("range")).unwrap_or(Range::H24);
    let opts = HistoryOptions {
        admin: admin.is_some(),
        now: Some(unix(app.now())),
        tz: Some(app.zone.clone()),
        ..Default::default()
    };
    let history = history::history(&page, db, row, range, opts).await?;
    let device = payload.devices.first().map(serde).unwrap_or_default();
    let mut values = BTreeMap::new();
    values.insert("dashboard".to_string(), serde(&payload));
    values.insert("device".to_string(), device);
    values.insert("row".to_string(), serde(&row_json(row)));
    values.insert("history".to_string(), serde(&history));
    values.insert("ranges".to_string(), Page::from(HISTORY_RANGES.to_vec()));
    values.insert("admin_view".to_string(), Page::from(false));
    values.insert("raw".to_string(), Page::from(()));
    Ok(values)
}

/// `GET /devices/<id>`.
pub async fn device_page(
    State(app): State<App>,
    ctx: Ctx,
    mut reg: Reg,
    Path(id): Path<String>,
) -> Result<Response, Reject> {
    let user = ctx.need_user(&mut reg).await?;
    let (row, admin) = visible_device(&app, &ctx, &mut reg, &id, &user).await?;
    let values = device_context(&app, &ctx, &mut reg, &row, admin.as_ref()).await?;
    dashboard_page(app.page(&ctx, Some(&user), "device.html", Page::from(values)))
}

/// `GET /admin`: the house's overview and every device.
pub async fn admin(State(app): State<App>, ctx: Ctx, right: Admin, mut reg: Reg) -> Result<Response, Reject> {
    let user = right.user();
    let page = app.telemetry.page();
    let (rows, people, payload) = admin_dashboard(&app, &page, &mut reg).await?;
    let overview = admin::overview(&page, &mut *reg, unix(app.now())).await;
    let rows_json: Vec<Value> = rows.iter().map(row_json).collect();
    dashboard_page(app.page(
        &ctx,
        Some(user),
        "admin.html",
        context! {
            devices => serde(&rows_json), people => serde(&people_json(&people)),
            dashboard => serde(&payload), overview => serde(&overview),
        },
    ))
}

/// `GET /admin/aps`.
pub async fn admin_aps(State(app): State<App>, ctx: Ctx, right: Admin, mut reg: Reg) -> Result<Response, Reject> {
    let page = app.telemetry.page();
    let aps = admin::aps(&page, &mut *reg, unix(app.now()), &app.zone).await?;
    dashboard_page(app.page(&ctx, Some(right.user()), "admin_aps.html", context! { aps => serde(&aps) }))
}

/// `GET /admin/incidents`: `?range=` or `?from=&to=`, `?kind=`; anything invalid: the last 7
/// days, all kinds (no error page).
pub async fn admin_incidents(State(app): State<App>, ctx: Ctx, right: Admin, mut reg: Reg) -> Result<Response, Reject> {
    let user = right.user();
    let now = unix(app.now());
    let (since, until, kind) = match (admin_span(&ctx, now, INCIDENT_SPAN, true), incident_kind(&ctx)) {
        (Some((s, u)), Ok(k)) => (s, u, k),
        _ => (now - INCIDENT_SPAN.0, now, None),
    };
    let page = app.telemetry.page();
    let payload = admin::incidents(&page, &mut *reg, since, until, kind.as_deref(), now).await?;
    let span = json!({"from": payload.from, "to": payload.to, "kind": kind.unwrap_or_default()});
    dashboard_page(app.page(
        &ctx,
        Some(user),
        "admin_incidents.html",
        context! { incidents => serde(&payload), span => serde(&span), incident_kinds => INCIDENT_KINDS.to_vec() },
    ))
}

/// `GET /admin/devices/<id>`: device.html for an admin, with the raw rows of the last 24 h.
pub async fn admin_device(
    State(app): State<App>,
    ctx: Ctx,
    right: Admin,
    mut reg: Reg,
    Path(id): Path<String>,
) -> Result<Response, Reject> {
    let user = right.user();
    let id = device_id(&id).ok_or_else(Reject::not_found)?;
    let row = match registry::device(&mut reg, id, None).await? {
        Some(dev) if dev.revoked_at.is_none() => dev,
        _ => return Err(Reject::not_found()),
    };
    let mut values = device_context(&app, &ctx, &mut reg, &row, Some(&right)).await?;
    let now = unix(app.now());
    let raw = device_raw(&app, &mut reg, &row, now - RAW_SPAN.0, now).await?;
    values.insert("admin_view".to_string(), Page::from(true));
    values.insert("raw".to_string(), serde(&raw));
    dashboard_page(app.page(&ctx, Some(user), "device.html", Page::from(values)))
}

async fn device_raw(app: &App, db: &mut Db, row: &DeviceRow, since: f64, until: f64) -> Result<admin::Raw, Reject> {
    let now = unix(app.now());
    let identities = identity::from_registry(db, std::slice::from_ref(row), now, true, None).await?;
    let identity = identities.get(&row.id).ok_or(Reject::Internal)?;
    let people = registry::people(db).await?;
    Ok(admin::raw(db, row, identity, since, until, &people, &app.zone, now).await?)
}

// --- the JSON API -----------------------------------------------------------------------------------

/// `GET /api/devices`: the person's own devices (polled).
pub async fn api_devices(
    State(app): State<App>,
    ctx: Ctx,
    mut reg: Reg,
    headers: HeaderMap,
) -> Result<Response, Reject> {
    let user = ctx.api_user(&mut reg).await?;
    let page = app.telemetry.page();
    let rows = registry::devices(&mut reg, Some(&user.sub), false).await?;
    let payload = dashboard_of(&app, &page, &mut reg, &rows, None, false, false).await?;
    Ok(polled_response(to_json(&payload)?, &headers))
}

/// `GET /api/devices/<id>`: one device as `/api/devices` shows it (`device`, no `counts`).
pub async fn api_device(
    State(app): State<App>,
    ctx: Ctx,
    mut reg: Reg,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, Reject> {
    let user = ctx.api_user(&mut reg).await?;
    let (row, admin) = visible_device(&app, &ctx, &mut reg, &id, &user).await?;
    let page = app.telemetry.page();
    let people = if admin.is_some() { Some(registry::people(&mut reg).await?) } else { None };
    let payload =
        dashboard_of(&app, &page, &mut reg, std::slice::from_ref(&row), people.as_ref(), admin.is_some(), true).await?;
    let one = payload.into_one().ok_or(Reject::Internal)?;
    Ok(polled_response(to_json(&one)?, &headers))
}

/// `GET /api/devices/<id>/history?range=`.
pub async fn api_history(
    State(app): State<App>,
    ctx: Ctx,
    mut reg: Reg,
    Path(id): Path<String>,
) -> Result<Response, Reject> {
    let user = ctx.api_user(&mut reg).await?;
    let (row, admin) = visible_device(&app, &ctx, &mut reg, &id, &user).await?;
    let key = ctx.args.get("range").map(String::as_str).unwrap_or("24h");
    let Some(range) = Range::parse(key) else {
        return Err(Reject::Json(StatusCode::BAD_REQUEST, "bad_range"));
    };
    let page = app.telemetry.page();
    let opts = HistoryOptions {
        admin: admin.is_some(),
        now: Some(unix(app.now())),
        tz: Some(app.zone.clone()),
        ..Default::default()
    };
    let history = history::history(&page, &mut *reg, &row, range, opts).await?;
    Ok(axum::Json(to_json(&history)?).into_response())
}

/// `GET /api/house`.
pub async fn api_house(State(app): State<App>, ctx: Ctx, mut reg: Reg) -> Result<Response, Reject> {
    ctx.api_user(&mut reg).await?;
    let page = app.telemetry.page();
    let house = house::house(page.budget.as_ref()).await;
    Ok(axum::Json(to_json(&house)?).into_response())
}

/// `GET /api/admin/devices?q=&state=`: every active device with its owner (polled; counts of
/// all devices, the poll hint of those shown).
pub async fn api_admin_devices(
    State(app): State<App>,
    ctx: Ctx,
    _right: Admin,
    mut reg: Reg,
    headers: HeaderMap,
) -> Result<Response, Reject> {
    let page = app.telemetry.page();
    let (_, _, mut payload) = admin_dashboard(&app, &page, &mut reg).await?;
    payload.filter(ctx.arg("q"), ctx.arg("state"));
    Ok(polled_response(to_json(&payload)?, &headers))
}

/// `GET /api/admin/overview`.
pub async fn api_admin_overview(State(app): State<App>, _right: Admin, mut reg: Reg) -> Result<Response, Reject> {
    let page = app.telemetry.page();
    let overview = admin::overview(&page, &mut *reg, unix(app.now())).await;
    Ok(axum::Json(to_json(&overview)?).into_response())
}

/// `GET /api/admin/aps`.
pub async fn api_admin_aps(State(app): State<App>, _right: Admin, mut reg: Reg) -> Result<Response, Reject> {
    let page = app.telemetry.page();
    let aps = admin::aps(&page, &mut *reg, unix(app.now()), &app.zone).await?;
    Ok(axum::Json(to_json(&aps)?).into_response())
}

/// `GET /api/admin/incidents?from=&to=|range=&kind=`.
pub async fn api_admin_incidents(
    State(app): State<App>,
    ctx: Ctx,
    _right: Admin,
    mut reg: Reg,
) -> Result<Response, Reject> {
    let now = unix(app.now());
    let Some((since, until)) = admin_span(&ctx, now, INCIDENT_SPAN, true) else {
        return Err(Reject::Json(StatusCode::BAD_REQUEST, "bad_range"));
    };
    let Ok(kind) = incident_kind(&ctx) else {
        return Err(Reject::Json(StatusCode::BAD_REQUEST, "bad_kind"));
    };
    let page = app.telemetry.page();
    let payload = admin::incidents(&page, &mut *reg, since, until, kind.as_deref(), now).await?;
    Ok(axum::Json(to_json(&payload)?).into_response())
}

/// `GET /api/admin/auth?result=reject&from=&to=&limit=`.
pub async fn api_admin_auth(State(app): State<App>, ctx: Ctx, _right: Admin, mut reg: Reg) -> Result<Response, Reject> {
    if ctx.args.get("result").map(String::as_str).unwrap_or("reject") != "reject" {
        return Err(Reject::Json(StatusCode::BAD_REQUEST, "bad_result"));
    }
    let now = unix(app.now());
    let Some((since, until)) = admin_span(&ctx, now, AUTH_SPAN, false) else {
        return Err(Reject::Json(StatusCode::BAD_REQUEST, "bad_range"));
    };
    let limit = match ctx.arg("limit") {
        "" => admin::AUTH_LIMIT,
        text => match text.parse::<i64>() {
            Ok(n) if LIMIT.is_match(text) && (1..=admin::AUTH_LIMIT).contains(&n) => n,
            _ => return Err(Reject::Json(StatusCode::BAD_REQUEST, "bad_limit")),
        },
    };
    let page = app.telemetry.page();
    let payload = admin::auth(&page, &mut *reg, since, until, limit).await?;
    Ok(axum::Json(to_json(&payload)?).into_response())
}

/// `GET /api/admin/devices/<id>/raw?from=&to=`: every source row of one device, also a revoked
/// one.
pub async fn api_admin_device_raw(
    State(app): State<App>,
    ctx: Ctx,
    _right: Admin,
    mut reg: Reg,
    Path(id): Path<String>,
) -> Result<Response, Reject> {
    let not_found = || Reject::Json(StatusCode::NOT_FOUND, "not_found");
    let id = device_id(&id).ok_or_else(not_found)?;
    let row = registry::device(&mut reg, id, None).await?.ok_or_else(not_found)?;
    let now = unix(app.now());
    let Some((since, until)) = admin_span(&ctx, now, RAW_SPAN, false) else {
        return Err(Reject::Json(StatusCode::BAD_REQUEST, "bad_range"));
    };
    let raw = device_raw(&app, &mut reg, &row, since, until).await?;
    Ok(axum::Json(to_json(&raw)?).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_time() {
        assert_eq!(parse_time("", 5.0), Some(5.0));
        assert_eq!(parse_time("1793000000", 0.0), Some(1_793_000_000.0));
        assert_eq!(parse_time("1793000000.5", 0.0), Some(1_793_000_000.5));
        assert_eq!(parse_time("2026-10-01T00:00:00Z", 0.0), Some(1_790_812_800.0));
        assert_eq!(parse_time("2026-10-01T02:00:00+02:00", 0.0), Some(1_790_812_800.0));
        assert_eq!(parse_time("2026-10-01T00:00:00", 0.0), Some(1_790_812_800.0));
        assert_eq!(parse_time("2026-10-01", 0.0), Some(1_790_812_800.0));
        assert_eq!(parse_time("yesterday", 0.0), None);
        assert_eq!(parse_time(&"9".repeat(13), 0.0), None);
        assert_eq!(parse_time("+5", 0.0), None);
    }

    #[test]
    fn test_limit_and_kind_patterns() {
        assert!(LIMIT.is_match("500"));
        for bad in ["²", "٣", "+5", "-1", "1.5", "12345"] {
            assert!(!LIMIT.is_match(bad), "{bad}");
        }
        assert!(INCIDENT_KIND.is_match("ap_down"));
        for bad in ["AP_DOWN", "1x", "AP\"", &"a".repeat(41)] {
            assert!(!INCIDENT_KIND.is_match(bad), "{bad}");
        }
    }
}
