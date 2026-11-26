//! Offboarding: reconcile the registry with Authentik's directory (Python
//! `netportal/offboarding.py` and the `offboard` command of `netportal/__main__.py`, INVENTORY 8).
//!
//! - [`directory`]: the users API, read completely or not at all;
//! - [`offboarding`]: the round (guards, reconciliation, job record, lock) and the sidecar loop
//!   with its heartbeat;
//! - [`actions`]: revocation and policy moves with their Disconnect-Requests, shared with the
//!   portal (Python `web.revoke_now`, `web.apply_policy`);
//! - [`disconnect`]: the Disconnect-Request seam (the packet is `netportal-pki`'s);
//! - [`recheck`]: the Disconnect reconciliation, a second loop of the sidecar: live accounting
//!   sessions of revoked or moved devices are disconnected again.
//!
//! The portal uses [`directory`] too, for its live check of admin rights.
//!
//! The sidecar exposes no metrics: it has no HTTP endpoint and Prometheus does not reach it.
//! Everything it does is in the registry (audit `revoke` / `policy:<name>` / `disconnect:<result>`
//! by `offboarding` and `recheck`, `job.offboarding`, `job.disconnect_recheck` with its totals),
//! which the portal's `/metrics` exports.

pub mod actions;
pub mod directory;
pub mod disconnect;
pub mod offboarding;
pub mod recheck;
