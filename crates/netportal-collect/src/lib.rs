//! The collector: Loki/Prometheus -> connection events, incidents, daily rollups, retention.
//! Python counterpart: the package `netportal/collect/` (INVENTORY 9.10), module for module:
//!
//! - `settings`      the collector's settings (loaded by `netportal_core::config`)
//! - `sources`       small Prometheus and Loki clients with a time budget per job run
//! - `scheduler`     jobs, intervals, advisory locks, job bookkeeping, SIGTERM, heartbeat
//! - `jobs`          the job table
//! - `unifi_events`  UniFi system log (unpoller -> Loki) -> `connection_event`
//! - `incidents`     monitoring signals (Prometheus) -> `incident`
//! - `rollup`        Prometheus -> `device_day` / `ap_day` (house days)
//! - `days`          house days as UTC intervals
//! - `prune`         the retention (`registry::prune`), daily

pub mod days;
pub mod incidents;
pub mod jobs;
pub mod prune;
pub mod rollup;
pub mod scheduler;
pub mod settings;
pub mod sources;
pub mod unifi_events;
