//! The IoT controller (`netportal iot`; house-infra docs/IOT-ACCESS.md, section 6.4): every
//! round it reads the desired state from the registry (`netportal_core::iot`), reads back what
//! UniFi and OPNsense have, applies the differences, writes `iot_sync` and the audit, touches
//! the heartbeat. Idempotent: a round with nothing to do calls no writing endpoint.
//!
//! - `unifi`     the UniFi legacy API: the IoT SSID's keys, kick and block, the client list
//! - `opnsense`  the OPNsense API: aliases (alias_util), rules (filter), states (diagnostics),
//!   the DHCP leases
//! - `desired`   the desired state from the registry: keys, blocks, aliases, rules
//! - `reconcile` one round: desired vs actual, the writes, `iot_sync`, the audit, the job row
//! - `run`       the loop, the advisory lock, the heartbeat, the signals

pub mod desired;
pub mod opnsense;
pub mod reconcile;
pub mod run;
pub mod unifi;

pub use reconcile::IotError;
pub use run::run;
