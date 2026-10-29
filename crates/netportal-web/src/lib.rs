//! The portal: routes, sessions, OIDC login, Let's Wi-Fi, templates, static files and `/metrics`.
//! Python counterparts: `netportal/web.py`, `netportal/metrics.py`, `netportal/wsgi.py`, the
//! templates and static files (served from `netportal/static/` unchanged). INVENTORY 3, 4, 10, 12.
//!
//! - [`web`]: the application state, the route table, `netportal serve`;
//! - [`pipeline`]: the request pipeline (session, CSRF, errors, security headers);
//! - [`session`], [`ctx`], [`clock`]: the session cookie, the request context, the clock;
//! - [`login`], [`oidc`]: the login with Authentik;
//! - [`dashboard`], [`devices`], [`letswifi`], [`ops`], [`static_files`]: the handlers;
//! - [`limits`]: devices and certificates per person;
//! - [`render`]: the templates and the server-side formatting;
//! - [`metrics`]: the `/metrics` exposition.

pub mod clock;
pub mod ctx;
pub mod dashboard;
pub mod devices;
pub mod errors;
pub mod http;
pub mod letswifi;
pub mod limits;
pub mod login;
pub mod metrics;
pub mod oidc;
pub mod ops;
pub mod pipeline;
pub mod platform;
pub mod render;
pub mod session;
pub mod static_files;
pub mod web;
