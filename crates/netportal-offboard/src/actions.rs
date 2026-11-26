//! Revocation and policy moves with their Disconnect-Requests (Python `web.revoke_now`,
//! `web.apply_policy`, INVENTORY 7.1 and 8.2). Shared library functions: the offboarding round
//! uses them, and the portal (revocation by a user or an admin, the policy at login, a replayed
//! Let's Wi-Fi token) uses the same ones. They count nothing: the caller owns its metrics (the
//! portal's `netportal_disconnects_total{result}`), the audit table records every result for
//! both.
//!
//! A device can have more than one session at once (a Mac on Wi-Fi and on a wired 802.1X port,
//! a session an access point still holds after a roam): every one the registry knows is cut
//! (`registry::sessions_of`: the latest login and every open accounting session), the requests
//! sent at once, each result audited as `disconnect:<result>`; a device without any session is
//! audited once as `disconnect:no-session`.

use futures::future::join_all;
use netportal_core::Db;
use netportal_core::registry::{self, RadiusSession, RegistryError};
use uuid::Uuid;

use crate::disconnect::{DisconnectResult, Disconnector};

const LOG: &str = "netportal.actions";

/// Disconnect every session (at once); `[NoSession]` when there is none.
async fn disconnect_all<D: Disconnector>(sessions: &[RadiusSession], disconnector: &D) -> Vec<DisconnectResult> {
    if sessions.is_empty() {
        return vec![DisconnectResult::NoSession];
    }
    join_all(sessions.iter().map(|session| disconnector.disconnect(session))).await
}

/// Audit each result (`disconnect:<result>`) and commit.
async fn audit_results(
    db: &mut Db,
    actor: &str,
    device_id: Uuid,
    results: &[DisconnectResult],
) -> Result<(), RegistryError> {
    for result in results {
        registry::audit(db, actor, &format!("disconnect:{}", result.as_str()), Some(device_id)).await?;
    }
    db.commit().await?;
    Ok(())
}

fn labels(results: &[DisconnectResult]) -> String {
    results.iter().map(|r| r.as_str()).collect::<Vec<_>>().join(",")
}

/// Revoke the device (effective for every new authentication: committed first), then cut its
/// running sessions with Disconnect-Requests (effective now) and audit `disconnect:<result>` for
/// each. Audits `revoke` by `actor` (a sub, `offboarding`, `letswifi`). Returns the results (at
/// least one), except for a home device (platform `iot`, house-infra docs/IOT-ACCESS.md): it
/// has no RADIUS session a Disconnect-Request could end (PPSK, MAC authentication), the IoT
/// controller kicks and blocks it through UniFi on its next round, so none is sent and the
/// results are empty.
pub async fn revoke_now<D: Disconnector>(
    db: &mut Db,
    device_id: Uuid,
    actor: &str,
    disconnector: &D,
) -> Result<Vec<DisconnectResult>, RegistryError> {
    let home_device = registry::device(db, device_id, None).await?.is_some_and(|d| d.platform == "iot");
    let sessions = registry::revoke(db, device_id, actor, "revoke").await?;
    db.commit().await?;
    if home_device {
        tracing::info!(target: LOG, "revoked home device {device_id} by {actor}; the IoT controller cuts it");
        return Ok(Vec::new());
    }
    let results = disconnect_all(&sessions, disconnector).await;
    audit_results(db, actor, device_id, &results).await?;
    tracing::info!(target: LOG, "revoked device {device_id} by {actor}; disconnect: {}", labels(&results));
    Ok(results)
}

/// Give the person this policy. Their active devices that had another one move with it (each
/// audited `policy:<name>` in the same transaction as the move, committed before any packet is
/// sent); each session of a moved device then gets a Disconnect-Request, so it authenticates
/// again into the policy's VLAN (someone moved out: residents -> guests), audited
/// `disconnect:<result>`. Returns the moved devices with their results.
pub async fn apply_policy<D: Disconnector>(
    db: &mut Db,
    sub: &str,
    policy: &str,
    actor: &str,
    disconnector: &D,
) -> Result<Vec<(Uuid, Vec<DisconnectResult>)>, RegistryError> {
    let moved = registry::set_policy(db, sub, policy).await?;
    for (device_id, _) in &moved {
        registry::audit(db, actor, &format!("policy:{policy}"), Some(*device_id)).await?;
    }
    db.commit().await?;
    let mut out = Vec::with_capacity(moved.len());
    for (device_id, sessions) in moved {
        let results = disconnect_all(&sessions, disconnector).await;
        audit_results(db, actor, device_id, &results).await?;
        tracing::info!(
            target: LOG,
            "moved device {device_id} to policy {policy} by {actor}; disconnect: {}",
            labels(&results)
        );
        out.push((device_id, results));
    }
    Ok(out)
}
