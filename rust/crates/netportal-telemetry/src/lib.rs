//! Dashboard telemetry, presence and diagnostics. Python counterparts: `netportal/telemetry/`
//! (`common`, `client`, `identity`, `house`, `live`, `timeline`, `history`, `admin`),
//! `netportal/presence.py` and `netportal/diagnostics.py`; INVENTORY 9. What the web calls:
//!
//! - one [`telemetry::Telemetry`] per process ([`telemetry::Telemetry::from_settings`]), one
//!   [`telemetry::Page`] per request ([`telemetry::Telemetry::page`]: the request's Prometheus
//!   budget);
//! - [`telemetry::live::dashboard`] (`/`, `/api/devices`, `/api/devices/<id>`, the admin list),
//!   [`telemetry::history::history`], [`telemetry::house::house`], the admin views in
//!   [`telemetry::admin`] (`overview`, `aps`, `incidents`, `auth`, `raw`);
//! - [`telemetry::polled`] for the polled APIs' ETag, 304 and poll hint.
//!
//! Registry reads go through [`telemetry::store::Store`] (implemented for
//! `netportal_core::Db`).

pub mod diagnostics;
pub mod presence;
pub mod telemetry;

#[cfg(test)]
mod tests;
