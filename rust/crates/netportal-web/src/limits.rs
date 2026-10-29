//! Limits per person (security review 2026-10-29, L5): how many active devices one person may
//! have (`NETPORTAL_MAX_DEVICES`, 20), and how fast new devices and certificates may come
//! ([`DEVICES_PER_HOUR`], [`CERTIFICATES_PER_DAY`]). Counted from the registry
//! (`registry::usage`), so they hold across restarts and for every way in: the enrol form, the
//! downloads, the apps' eap-configs.
//!
//! A refused request changes nothing: a page (409 for the device limit, 429 with `Retry-After`
//! for the rate), or JSON for the apps (`too_many_devices`, `slow_down`).

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use minijinja::context;
use netportal_core::Db;
use netportal_core::registry;
use time::Duration;

use crate::ctx::{Ctx, User};
use crate::errors::{Reject, json_error};
use crate::web::App;

/// New devices per person within an hour at most.
pub const DEVICES_PER_HOUR: i64 = 10;
/// Certificates (downloads, eap-configs) per person within 24 hours at most.
pub const CERTIFICATES_PER_DAY: i64 = 30;
/// What a 429 tells the client (seconds).
pub const RETRY_AFTER_S: &str = "900";

/// Why a request is over a limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Over {
    /// `NETPORTAL_MAX_DEVICES` active devices already
    Devices(u32),
    /// too many new devices or certificates lately
    Rate,
}

/// The limits a new device must stay within (one more device, and its first certificate).
pub async fn new_device(app: &App, db: &mut Db, owner: &str) -> Result<Option<Over>, Reject> {
    let usage = registry::usage(db, owner, Duration::hours(1), Duration::days(1)).await?;
    if usage.active_devices >= i64::from(app.settings.max_devices) {
        return Ok(Some(Over::Devices(app.settings.max_devices)));
    }
    if usage.devices_created >= DEVICES_PER_HOUR || usage.certificates_issued >= CERTIFICATES_PER_DAY {
        return Ok(Some(Over::Rate));
    }
    Ok(None)
}

/// The limit a new certificate of an existing device must stay within.
pub async fn new_certificate(db: &mut Db, owner: &str) -> Result<Option<Over>, Reject> {
    let usage = registry::usage(db, owner, Duration::hours(1), Duration::days(1)).await?;
    Ok((usage.certificates_issued >= CERTIFICATES_PER_DAY).then_some(Over::Rate))
}

fn log(owner: &str, over: Over) {
    match over {
        Over::Devices(n) => tracing::info!(target: "netportal.web", "{owner}: refused, {n} active devices already"),
        Over::Rate => {
            tracing::warn!(target: "netportal.web", "{owner}: refused, too many new devices or certificates lately")
        }
    }
}

/// The page that says so (or JSON for a script).
pub fn page(app: &App, ctx: &Ctx, user: &User, over: Over) -> Result<Response, Reject> {
    log(&user.sub, over);
    let (status, message) = match over {
        Over::Devices(n) => {
            let text = netportal_core::i18n::text(ctx.lang, "too_many_devices").unwrap_or("");
            (StatusCode::CONFLICT, netportal_core::i18n::fill(text, &[("n", &n.to_string())]))
        }
        Over::Rate => (
            StatusCode::TOO_MANY_REQUESTS,
            netportal_core::i18n::text(ctx.lang, "rate_limited").unwrap_or("").to_string(),
        ),
    };
    let mut response = if ctx.wants_json() {
        json_error(status, if status == StatusCode::CONFLICT { "too_many_devices" } else { "slow_down" })
    } else {
        app.page_with(ctx, Some(user), "message.html", context! { message => message }, status)?
    };
    if status == StatusCode::TOO_MANY_REQUESTS {
        response.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from_static(RETRY_AFTER_S));
    }
    Ok(response)
}

/// The apps' answer (the eap-config endpoint): JSON.
pub fn app_answer(owner: &str, over: Over) -> Response {
    log(owner, over);
    match over {
        Over::Devices(_) => json_error(StatusCode::CONFLICT, "too_many_devices"),
        Over::Rate => {
            let mut response = json_error(StatusCode::TOO_MANY_REQUESTS, "slow_down");
            response.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from_static(RETRY_AFTER_S));
            response.into_response()
        }
    }
}
