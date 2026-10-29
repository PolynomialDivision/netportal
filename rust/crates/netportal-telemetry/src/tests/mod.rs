//! The ported Python tests (INVENTORY 14): one module per Python file, tests named after the
//! Python test they port. Prometheus is a fake HTTP server on 127.0.0.1, the registry an
//! in-memory [`fakes::FakeRegistry`] behind `Store`.

mod dashboard_api;
mod diagnostics;
mod fakes;
mod presence;
mod tables;
mod telemetry;
mod telemetry_registry;
mod telemetry_v2;
