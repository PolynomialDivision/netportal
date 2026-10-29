//! The core of the Rust netportal: settings (Python `config.py`, `collect/settings.py`), the
//! registry with its own schema and migrations (`registry.py`, `rust/migrations/`), the
//! translations (`i18n.py` data, exported to `i18n.json`), the number and time conventions, the
//! log format and the database connection type. Every other crate builds on it.

pub mod config;
pub mod conventions;
pub mod db;
pub mod i18n;
pub mod logging;
pub mod registry;

pub use db::{Db, Pool, PoolSettings};

/// The error of an entry point whose crate is not ported yet.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0} is not ported yet")]
pub struct NotPorted(pub &'static str);
