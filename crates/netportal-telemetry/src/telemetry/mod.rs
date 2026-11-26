//! The dashboard's telemetry (Python package `netportal/telemetry/`, INVENTORY 9.1-9.4, 9.6, 9.9).
//!
//! Parts: [`client`] (the Prometheus client: cache, single flight, cool-down, page budgets),
//! [`common`] (MACs, selectors, times, AP names), [`identity`] (a device's MAC windows and
//! conflicts: whose data it is), [`house`] (HOUSE), [`live`] (DEVICE and the `/api/devices`
//! payload), [`timeline`] (events from every source, merged), [`history`] (the detail page's
//! charts and timeline), [`admin`] (overview, APs, incidents, rejects, raw rows), [`store`] (the
//! registry reads), [`polled`] (ETag, 304 and poll hint of the polled APIs).
//!
//! Whose data it is: a device's data comes through its MAC windows ([`identity`]): a MAC's data
//! outside them belongs to nobody, and windows of different owners that overlap are withheld from
//! residents (admins see them marked). Only the house's EAP-TLS network counts (`essid` =
//! `NETPORTAL_SSID` on every client selector). Only validated MACs ever go into a query.
//!
//! Process-wide state (one [`Telemetry`] per web process, INVENTORY 9.14 #6): the Prometheus
//! client's cache and cool-down, the last AP map Prometheus gave (kept a day: presence places
//! sessions at their AP with it while Prometheus is down) and a 5 s cache of the house-wide
//! registry reads every dashboard makes. Each request takes a [`Page`] ([`Telemetry::page`]):
//! one Prometheus budget for everything the page shows.

pub mod admin;
pub mod client;
pub mod common;
pub mod history;
pub mod house;
pub mod identity;
pub mod live;
pub mod polled;
pub mod store;
pub mod timeline;

use std::sync::{Arc, Mutex};

use netportal_core::config::PortalSettings;
use netportal_core::registry::{AuthFailure, Incident};

use client::{Budget, Clock, Prometheus, monotonic};
use timeline::ApMap;

/// The last AP map Prometheus gave is used this long while it does not answer (seconds).
pub const KNOWN_APS_S: f64 = 86400.0;
/// House-wide registry reads (the rejects and incidents of 24 h) are shared this long between
/// requests, so the 5 s polls of a connecting device stay cheap (seconds).
pub const SHARED_S: f64 = 5.0;

#[derive(Default)]
struct SharedReads {
    failures: Option<(f64, Vec<AuthFailure>)>,
    incidents: Option<(f64, Vec<Incident>)>,
    known_aps: Option<(f64, ApMap)>,
}

/// The process-wide caches besides the Prometheus client's.
pub struct Shared {
    clock: Clock,
    reads: Mutex<SharedReads>,
}

impl Shared {
    fn new(clock: Clock) -> Self {
        Shared { clock, reads: Mutex::new(SharedReads::default()) }
    }

    fn reads(&self) -> std::sync::MutexGuard<'_, SharedReads> {
        self.reads.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn now(&self) -> f64 {
        (self.clock)()
    }

    pub(crate) fn failures(&self) -> Option<Vec<AuthFailure>> {
        let now = self.now();
        self.reads().failures.as_ref().filter(|(at, _)| now - at <= SHARED_S).map(|(_, v)| v.clone())
    }

    pub(crate) fn set_failures(&self, rows: &[AuthFailure]) {
        let now = self.now();
        self.reads().failures = Some((now, rows.to_vec()));
    }

    pub(crate) fn incidents(&self) -> Option<Vec<Incident>> {
        let now = self.now();
        self.reads().incidents.as_ref().filter(|(at, _)| now - at <= SHARED_S).map(|(_, v)| v.clone())
    }

    pub(crate) fn set_incidents(&self, rows: &[Incident]) {
        let now = self.now();
        self.reads().incidents = Some((now, rows.to_vec()));
    }

    /// The last AP map Prometheus answered (at most [`KNOWN_APS_S`] old), else an empty one.
    pub fn known_aps(&self) -> ApMap {
        let now = self.now();
        self.reads()
            .known_aps
            .as_ref()
            .filter(|(at, _)| now - at <= KNOWN_APS_S)
            .map(|(_, m)| m.clone())
            .unwrap_or_default()
    }

    pub(crate) fn set_known_aps(&self, map: &ApMap) {
        let now = self.now();
        self.reads().known_aps = Some((now, map.clone()));
    }
}

/// The telemetry of one web process: the Prometheus client (`None`: `NETPORTAL_PROMETHEUS_URL`
/// is not set, telemetry "off"), the house's SSID and the shared caches.
#[derive(Clone)]
pub struct Telemetry {
    prometheus: Option<Prometheus>,
    ssid: String,
    shared: Arc<Shared>,
}

impl Telemetry {
    pub fn new(prometheus: Option<Prometheus>, ssid: &str) -> Self {
        Self::with_clock(prometheus, ssid, monotonic())
    }

    /// [`Telemetry::new`] with a given monotonic clock for the shared caches (tests).
    pub fn with_clock(prometheus: Option<Prometheus>, ssid: &str, clock: Clock) -> Self {
        Telemetry { prometheus, ssid: ssid.to_string(), shared: Arc::new(Shared::new(clock)) }
    }

    /// From the portal's settings (`NETPORTAL_PROMETHEUS_URL`, `_TIMEOUT`, `NETPORTAL_SSID`).
    pub fn from_settings(settings: &PortalSettings) -> Result<Self, reqwest::Error> {
        let prometheus = match &settings.prometheus_url {
            Some(url) => Some(Prometheus::new(url, settings.prometheus_timeout, &settings.ssid)?),
            None => None,
        };
        Ok(Self::new(prometheus, &settings.ssid))
    }

    pub fn prometheus(&self) -> Option<&Prometheus> {
        self.prometheus.as_ref()
    }

    pub fn ssid(&self) -> &str {
        &self.ssid
    }

    /// One request's view: a fresh Prometheus budget shared by everything the page shows (the
    /// device page: live data and history together).
    pub fn page(&self) -> Page {
        Page {
            budget: self.prometheus.as_ref().map(Prometheus::within),
            ssid: self.ssid.clone(),
            shared: self.shared.clone(),
        }
    }
}

/// One request's telemetry: its Prometheus budget (`None`: telemetry off) and the process-wide
/// caches.
#[derive(Clone)]
pub struct Page {
    pub budget: Option<Budget>,
    /// the house's EAP-TLS network
    pub ssid: String,
    shared: Arc<Shared>,
}

impl Page {
    pub fn shared(&self) -> &Shared {
        &self.shared
    }

    /// `ok` with a Prometheus client, `off` without.
    pub fn telemetry(&self) -> &'static str {
        if self.budget.is_some() { live::OK } else { live::OFF }
    }
}
