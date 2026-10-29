//! Enrolment, one-time downloads, renewal, rename and revocation (INVENTORY 3.2 rows 7-11, 4.6,
//! 6.2, 7.1). Every action is audited; a revocation is committed before its Disconnect-Requests.
//! A new device and every certificate stay within the person's limits ([`crate::limits`]).

use axum::extract::{Path, State};
use axum::http::{HeaderName, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use minijinja::context;
use netportal_core::Db;
use netportal_core::registry;
use netportal_offboard::actions;
use netportal_pki::enroll::{Artefact, Format};
use serde_json::json;
use uuid::Uuid;

use crate::ctx::{Ctx, User};
use crate::errors::{Reject, internal};
use crate::http::device_id;
use crate::limits;
use crate::login::redirect;
use crate::platform::{FORMATS, cut_name, default_name};
use crate::web::{App, Reg};

/// A download link works this long (minutes).
pub const DOWNLOAD_MINUTES: i32 = 10;

/// The policy for a new device of this person: theirs from the last login or offboarding round,
/// the first one if none is known yet.
pub async fn owner_policy(app: &App, db: &mut Db, sub: &str) -> Result<String, Reject> {
    match registry::person_policy(db, sub).await? {
        Some(policy) => Ok(policy),
        None => app.settings.policies.list.first().map(|p| p.name.clone()).ok_or(Reject::Internal),
    }
}

/// A new certificate for the device in this format: issued now, recorded (the earlier ones of
/// the device end after the renewal overlap, or at once if issued within `at_once_within`) and
/// committed before the artefact goes out.
pub async fn issue_artefact(
    app: &App,
    db: &mut Db,
    device: Uuid,
    format: Format,
    at_once_within: Option<time::Duration>,
) -> Result<Artefact, Reject> {
    let issued = app.issuer.issue(device, app.now()).map_err(|_| internal("certificate not issued"))?;
    let serial = issued.serial_hex().map_err(|_| internal("certificate serial unreadable"))?;
    let not_after = issued.not_after().map_err(|_| internal("certificate validity unreadable"))?;
    registry::add_credential(db, device, &serial, not_after, app.settings.renew_overlap_days, at_once_within).await?;
    let artefact = app.issuer.artefact(&issued, device, format).map_err(|_| internal("artefact not built"))?;
    db.commit().await?;
    Ok(artefact)
}

/// The artefact with its HTTP framing (INVENTORY 6.4); never cached (it holds a private key).
pub fn artefact_response(artefact: Artefact) -> Response {
    let mut response = artefact.body.into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(artefact.framing.content_type));
    for (name, value) in artefact.framing.headers {
        if let Ok(name) = HeaderName::from_bytes(name.as_bytes()) {
            headers.insert(name, HeaderValue::from_static(value));
        }
    }
    if let Some(disposition) = artefact.framing.content_disposition()
        && let Ok(v) = HeaderValue::from_str(&disposition)
    {
        headers.insert(header::CONTENT_DISPOSITION, v);
    }
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn install_page(app: &App, ctx: &Ctx, user: &User, format: &str, token: &str, name: &str) -> Result<Response, Reject> {
    app.page(ctx, Some(user), "install.html", context! { profile => format, token => token, name => name })
}

/// `POST /enroll`: a new device of this format, its 10-minute one-time download link (within
/// the person's device limit and rate).
pub async fn enrol(State(app): State<App>, ctx: Ctx, mut reg: Reg) -> Result<Response, Reject> {
    let user = ctx.need_user(&mut reg, false).await?;
    let format = ctx.field("format");
    if !FORMATS.contains(&format) || (format == "android" && !app.settings.passpoint) {
        return Err(Reject::bad_request());
    }
    if let Some(over) = limits::new_device(&app, &mut reg, &user.sub).await? {
        return limits::page(&app, &ctx, &user, over);
    }
    let name = cut_name(ctx.field("name")).unwrap_or_else(|| default_name(format, &user.username));
    let policy = owner_policy(&app, &mut reg, &user.sub).await?;
    let device = registry::create_device(&mut reg, &user.sub, &name, format, &policy).await?;
    registry::audit(&mut reg, &user.sub, &format!("enrol:{format}"), Some(device)).await?;
    let token = registry::create_download(&mut reg, device, format, DOWNLOAD_MINUTES).await?;
    reg.commit().await?;
    app.metrics.enrolled(format);
    install_page(&app, &ctx, &user, format, &token, &name)
}

/// The device of this URL if this person may act on it: their own (any for an admin when
/// `admin_any`), not revoked; else 404.
async fn own_device(db: &mut Db, id: &str, user: &User, admin_any: bool) -> Result<registry::DeviceRow, Reject> {
    let id = device_id(id).ok_or_else(Reject::not_found)?;
    let owner = if admin_any && user.admin { None } else { Some(user.sub.as_str()) };
    match registry::device(db, id, owner).await? {
        Some(dev) if dev.revoked_at.is_none() => Ok(dev),
        _ => Err(Reject::not_found()),
    }
}

/// `POST /devices/<id>/renew`: a new download link for the device (own devices only, also for
/// admins); an app's device is renewed by the app.
pub async fn renew(State(app): State<App>, ctx: Ctx, mut reg: Reg, Path(id): Path<String>) -> Result<Response, Reject> {
    let user = ctx.need_user(&mut reg, false).await?;
    let dev = own_device(&mut reg, &id, &user, false).await?;
    if dev.platform == "letswifi" {
        let text = netportal_core::i18n::text(ctx.lang, "install_app").unwrap_or("");
        let message = netportal_core::i18n::fill(text, &[("host", &app.host)]);
        return app.page(&ctx, Some(&user), "message.html", context! { message => message });
    }
    if dev.platform == "android" && !app.settings.passpoint {
        return Err(Reject::bad_request());
    }
    let token = registry::create_download(&mut reg, dev.id, &dev.platform, DOWNLOAD_MINUTES).await?;
    registry::audit(&mut reg, &user.sub, "renew", Some(dev.id)).await?;
    reg.commit().await?;
    install_page(&app, &ctx, &user, &dev.platform, &token, &dev.name)
}

/// `GET /download/<token>`: once, by the device's owner, within 10 minutes, the device not
/// revoked, within the person's certificate rate: a new certificate in the format's artefact.
/// Someone else's token is not used up, nor one refused by the rate.
pub async fn download(
    State(app): State<App>,
    ctx: Ctx,
    mut reg: Reg,
    Path(token): Path<String>,
) -> Result<Response, Reject> {
    let user = ctx.need_user(&mut reg, false).await?;
    if let Some(over) = limits::new_certificate(&mut reg, &user.sub).await? {
        return limits::page(&app, &ctx, &user, over);
    }
    let Some((dev, format)) = registry::consume_download(&mut reg, &token, &user.sub).await? else {
        reg.commit().await?;
        return Err(Reject::not_found());
    };
    let format: Format = format.parse().map_err(|_| internal("download of an unknown format"))?;
    let artefact = issue_artefact(&app, &mut reg, dev.id, format, None).await?;
    Ok(artefact_response(artefact))
}

/// `POST /devices/<id>/rename`: the form (302 `/`; an empty name changes nothing) or the inline
/// rename of the dashboard (`{"ok", "name"}`: the name as stored, or the old one for an empty
/// name with 400).
pub async fn rename(
    State(app): State<App>,
    ctx: Ctx,
    mut reg: Reg,
    Path(id): Path<String>,
) -> Result<Response, Reject> {
    let _ = app;
    let as_json = ctx.wants_json();
    let user = if as_json { ctx.api_user(&mut reg, false).await? } else { ctx.need_user(&mut reg, false).await? };
    let dev = own_device(&mut reg, &id, &user, true).await?;
    let name = cut_name(ctx.field("name"));
    if let Some(name) = &name {
        registry::rename(&mut reg, dev.id, name).await?;
        reg.commit().await?;
    }
    if as_json {
        let status = if name.is_some() { StatusCode::OK } else { StatusCode::BAD_REQUEST };
        let body = json!({"ok": name.is_some(), "name": name.unwrap_or(dev.name)});
        return Ok((status, axum::Json(body)).into_response());
    }
    Ok(redirect("/"))
}

/// `POST /devices/<id>/revoke`: revoked in the registry (every new authentication fails), then
/// every running session cut with a Disconnect-Request; back to `/admin` only from there.
pub async fn revoke(
    State(app): State<App>,
    ctx: Ctx,
    mut reg: Reg,
    Path(id): Path<String>,
) -> Result<Response, Reject> {
    let user = ctx.need_user(&mut reg, false).await?;
    let dev = own_device(&mut reg, &id, &user, true).await?;
    for result in actions::revoke_now(&mut reg, dev.id, &user.sub, &app.disconnector).await? {
        app.metrics.disconnected(result.as_str());
    }
    Ok(redirect(if ctx.field("back") == "/admin" { "/admin" } else { "/" }))
}
