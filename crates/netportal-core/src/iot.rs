//! Home (IoT) devices in the registry (migration 0006; house-infra docs/IOT-ACCESS.md): devices
//! of kind `iot` with their own Wi-Fi key and registered MAC, the shares, the access view the
//! portal, the controller and the discovery proxy all read, the controller's sync state and the
//! join attempts of unknown MACs.
//!
//! Conventions as in [`crate::registry`]: writers leave the transaction open, the caller commits.
//! The access rule lives in one place, the view `iot_access`; nothing here derives rights
//! otherwise.

use std::collections::BTreeMap;

use sqlx::Row;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::db::Db;
use crate::registry::{Result, audit, normalise_mac};

/// The device classes (`iot_device.class`): the help texts and the proxy's service types.
pub const CLASSES: [&str; 6] = ["cast", "airplay", "printer", "tv", "speaker", "other"];
/// The visibilities (`iot_device.visibility`).
pub const VISIBILITIES: [&str; 2] = ["private", "house"];
/// The controller's sync targets (`iot_sync.target`).
pub const SYNC_TARGETS: [&str; 5] = ["unifi_key", "unifi_block", "opnsense_alias", "opnsense_rule", "opnsense_states"];
/// The length of a generated Wi-Fi key.
pub const PSK_LENGTH: usize = 20;
/// Join attempts older than this are not offered for a claim.
pub const CLAIM_WINDOW: time::Duration = time::Duration::minutes(15);

/// The mDNS service types the proxy browses for a class (the owner's declared class only
/// chooses the help text and these; the proxy answers whatever the device announces).
pub fn service_types(class: &str) -> &'static [&'static str] {
    match class {
        "cast" => &["_googlecast._tcp"],
        "airplay" => &["_airplay._tcp", "_raop._tcp"],
        "printer" => &["_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp"],
        "tv" => &["_googlecast._tcp", "_airplay._tcp", "_raop._tcp", "_http._tcp"],
        "speaker" => &["_googlecast._tcp", "_airplay._tcp", "_raop._tcp", "_spotify-connect._tcp"],
        _ => &["_googlecast._tcp", "_airplay._tcp", "_raop._tcp", "_ipp._tcp", "_http._tcp"],
    }
}

/// A new Wi-Fi key: [`PSK_LENGTH`] characters of `[A-Za-z0-9]` (about 119 bits).
pub fn new_psk() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    (0..PSK_LENGTH)
        .map(|_| {
            let i: usize = rand::random_range(0..ALPHABET.len());
            ALPHABET[i] as char
        })
        .collect()
}

/// An IoT device as the pages and the controller read it.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow, serde::Serialize)]
pub struct IotDevice {
    pub id: Uuid,
    pub owner: String,
    pub owner_name: String,
    pub name: String,
    pub class: String,
    /// `aa:bb:cc:dd:ee:ff`, `None` until registered or claimed
    pub mac: Option<String>,
    pub mac_claimed_at: Option<OffsetDateTime>,
    /// the Wi-Fi key (only the owner's and the admins' pages show it)
    pub psk: String,
    pub psk_rotated_at: OffsetDateTime,
    pub visibility: String,
    pub created_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
    /// the latest RADIUS login with the MAC (MAC authentication), and the MAC's latest sighting
    pub last_seen: Option<OffsetDateTime>,
}

const DEVICE_LIST: &str = "
    SELECT d.id, d.owner, o.display_name AS owner_name, d.name, i.class, i.mac::text AS mac, i.mac_claimed_at,
           i.psk, i.psk_rotated_at, i.visibility, d.created_at, d.revoked_at,
           (SELECT max(m.last_seen) FROM device_mac m WHERE m.device_id = d.id) AS last_seen
    FROM device d JOIN iot_device i ON i.device_id = d.id JOIN person o ON o.sub = d.owner";

/// A share of a device.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow, serde::Serialize)]
pub struct Share {
    pub device_id: Uuid,
    pub grantee: String,
    pub grantee_name: String,
    pub granted_by: String,
    pub granted_at: OffsetDateTime,
}

/// A row of the access view: `basis` is `owner`, `share` or `house`.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct Access {
    pub sub: String,
    pub device_id: Uuid,
    pub basis: String,
}

/// The controller's state of one target and key.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow, serde::Serialize)]
pub struct SyncState {
    pub target: String,
    pub key: String,
    /// `applied`, `pending`, `failed`
    pub status: String,
    pub detail: String,
    pub updated_at: OffsetDateTime,
}

/// A MAC that tried to join the IoT SSID and was refused as unknown.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow, serde::Serialize)]
pub struct JoinAttempt {
    pub mac: String,
    pub first_seen: OffsetDateTime,
    pub last_seen: OffsetDateTime,
    pub tries: i32,
    pub ssid: Option<String>,
}

/// What a registration asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewDevice<'a> {
    pub owner: &'a str,
    pub name: &'a str,
    pub class: &'a str,
    /// any MAC form; `None`: registered without one (claimed later)
    pub mac: Option<&'a str>,
    pub policy: &'a str,
}

#[derive(Debug, thiserror::Error)]
pub enum IotError {
    #[error("{0}")]
    Registry(#[from] crate::registry::RegistryError),
    #[error("not a MAC address: {0:?}")]
    BadMac(String),
    #[error("the MAC {0} is registered already")]
    MacTaken(String),
    #[error("unknown class {0:?}")]
    BadClass(String),
    #[error("unknown visibility {0:?}")]
    BadVisibility(String),
}

impl From<sqlx::Error> for IotError {
    fn from(e: sqlx::Error) -> Self {
        IotError::Registry(e.into())
    }
}

fn is_unique_violation(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(d) if d.code().as_deref() == Some("23505"))
}

/// Register a home device: a `device` of kind `iot` plus its `iot_device` row with a fresh key
/// (returned with the id); the MAC, when given, also starts the device's MAC window
/// (`device_mac`), so presence and the collector treat it like any other device. Audited as
/// `iot:register`.
pub async fn register(db: &mut Db, new: NewDevice<'_>) -> std::result::Result<(Uuid, String), IotError> {
    if !CLASSES.contains(&new.class) {
        return Err(IotError::BadClass(new.class.to_string()));
    }
    let mac = match new.mac {
        Some(raw) => Some(normalise_mac(raw).ok_or_else(|| IotError::BadMac(raw.to_string()))?),
        None => None,
    };
    let id = Uuid::new_v4();
    let psk = new_psk();
    if let Some(mac) = &mac {
        release_revoked_mac(db, mac, new.owner).await?;
    }
    let conn = db.tx().await?;
    sqlx::query("INSERT INTO device (id, owner, name, kind, platform, policy) VALUES ($1, $2, $3, 'iot', 'iot', $4)")
        .bind(id)
        .bind(new.owner)
        .bind(new.name)
        .bind(new.policy)
        .execute(&mut *conn)
        .await?;
    let inserted = sqlx::query(
        "INSERT INTO iot_device (device_id, class, mac, mac_claimed_at, psk)
         VALUES ($1, $2, $3::macaddr, CASE WHEN $3::macaddr IS NULL THEN NULL ELSE now() END, $4)",
    )
    .bind(id)
    .bind(new.class)
    .bind(mac.as_deref())
    .bind(&psk)
    .execute(&mut *conn)
    .await;
    if let Err(e) = inserted {
        if is_unique_violation(&e) {
            return Err(IotError::MacTaken(mac.unwrap_or_default()));
        }
        return Err(e.into());
    }
    if let Some(mac) = &mac {
        start_mac_window(db, id, mac).await?;
    }
    audit(db, new.owner, "iot:register", Some(id)).await?;
    Ok((id, psk))
}

async fn start_mac_window(db: &mut Db, id: Uuid, mac: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO device_mac (device_id, mac, first_seen, last_seen, auth_count, randomized)
         VALUES ($1, $2::macaddr, now(), now(), 0, ($2::macaddr & '02:00:00:00:00:00') = '02:00:00:00:00:00')
         ON CONFLICT (device_id, mac) DO NOTHING",
    )
    .bind(id)
    .bind(mac)
    .execute(db.tx().await?)
    .await?;
    Ok(())
}

/// A MAC held by a revoked (removed) device is free for the next registration: the revoked row
/// loses it, so the controller lifts its UniFi block and the live device alone owns the MAC.
/// Audited as `iot:mac-released` on the old device.
async fn release_revoked_mac(db: &mut Db, mac: &str, actor: &str) -> Result<()> {
    let released: Vec<Uuid> = sqlx::query_scalar(
        "UPDATE iot_device i SET mac = NULL, mac_claimed_at = NULL
         FROM device d WHERE d.id = i.device_id AND i.mac = $1::macaddr AND d.revoked_at IS NOT NULL
         RETURNING i.device_id",
    )
    .bind(mac)
    .fetch_all(db.tx().await?)
    .await?;
    for old in released {
        audit(db, actor, "iot:mac-released", Some(old)).await?;
    }
    Ok(())
}

/// Bind a MAC to a device registered without one, or move it to another MAC (the device was
/// replaced); the join attempt of that MAC, if any, is consumed. Audited as `iot:claim`.
pub async fn claim_mac(db: &mut Db, id: Uuid, raw_mac: &str, actor: &str) -> std::result::Result<(), IotError> {
    let mac = normalise_mac(raw_mac).ok_or_else(|| IotError::BadMac(raw_mac.to_string()))?;
    release_revoked_mac(db, &mac, actor).await?;
    let updated = sqlx::query(
        "UPDATE iot_device SET mac = $2::macaddr, mac_claimed_at = now()
         FROM device d WHERE d.id = iot_device.device_id AND iot_device.device_id = $1 AND d.revoked_at IS NULL",
    )
    .bind(id)
    .bind(&mac)
    .execute(db.tx().await?)
    .await;
    match updated {
        Ok(_) => {}
        Err(e) if is_unique_violation(&e) => return Err(IotError::MacTaken(mac)),
        Err(e) => return Err(e.into()),
    }
    sqlx::query("DELETE FROM iot_join_attempt WHERE mac = $1::macaddr").bind(&mac).execute(db.tx().await?).await?;
    start_mac_window(db, id, &mac).await?;
    audit(db, actor, "iot:claim", Some(id)).await?;
    Ok(())
}

/// A new key for the device (the owner typed the old one into the wrong device, or wants it
/// gone); the controller replaces it in UniFi on its next round. Audited as `iot:rotate-key`.
pub async fn rotate_psk(db: &mut Db, id: Uuid, actor: &str) -> Result<String> {
    let psk = new_psk();
    sqlx::query(
        "UPDATE iot_device SET psk = $2, psk_rotated_at = now()
         FROM device d WHERE d.id = iot_device.device_id AND iot_device.device_id = $1 AND d.revoked_at IS NULL",
    )
    .bind(id)
    .bind(&psk)
    .execute(db.tx().await?)
    .await?;
    audit(db, actor, "iot:rotate-key", Some(id)).await?;
    Ok(psk)
}

/// Private, or visible to the whole house. Audited as `iot:visibility:<value>`.
pub async fn set_visibility(db: &mut Db, id: Uuid, visibility: &str, actor: &str) -> std::result::Result<(), IotError> {
    if !VISIBILITIES.contains(&visibility) {
        return Err(IotError::BadVisibility(visibility.to_string()));
    }
    sqlx::query("UPDATE iot_device SET visibility = $2 WHERE device_id = $1")
        .bind(id)
        .bind(visibility)
        .execute(db.tx().await?)
        .await?;
    audit(db, actor, &format!("iot:visibility:{visibility}"), Some(id)).await?;
    Ok(())
}

/// Share the device with a person (idempotent). Audited as `iot:share:<grantee>`.
pub async fn share(db: &mut Db, id: Uuid, grantee: &str, actor: &str) -> Result<bool> {
    let done = sqlx::query(
        "INSERT INTO iot_share (device_id, grantee, granted_by) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
    )
    .bind(id)
    .bind(grantee)
    .bind(actor)
    .execute(db.tx().await?)
    .await?;
    if done.rows_affected() > 0 {
        audit(db, actor, &format!("iot:share:{grantee}"), Some(id)).await?;
    }
    Ok(done.rows_affected() > 0)
}

/// Take a share away. Audited as `iot:unshare:<grantee>`.
pub async fn unshare(db: &mut Db, id: Uuid, grantee: &str, actor: &str) -> Result<bool> {
    let done = sqlx::query("DELETE FROM iot_share WHERE device_id = $1 AND grantee = $2")
        .bind(id)
        .bind(grantee)
        .execute(db.tx().await?)
        .await?;
    if done.rows_affected() > 0 {
        audit(db, actor, &format!("iot:unshare:{grantee}"), Some(id)).await?;
    }
    Ok(done.rows_affected() > 0)
}

/// Every share a person holds (as grantee) or gave: deleted when the person leaves.
pub async fn drop_shares_of(db: &mut Db, sub: &str) -> Result<u64> {
    let done = sqlx::query("DELETE FROM iot_share WHERE grantee = $1 OR granted_by = $1")
        .bind(sub)
        .execute(db.tx().await?)
        .await?;
    Ok(done.rows_affected())
}

/// The home devices a person owns, newest first; revoked ones only when asked.
pub async fn devices_of(db: &mut Db, owner: &str, include_revoked: bool) -> Result<Vec<IotDevice>> {
    let sql =
        format!("{DEVICE_LIST} WHERE d.owner = $1 AND ($2 OR d.revoked_at IS NULL) ORDER BY d.created_at DESC, d.id");
    Ok(sqlx::query_as(sqlx::AssertSqlSafe(sql)).bind(owner).bind(include_revoked).fetch_all(db.tx().await?).await?)
}

/// The home devices shared with a person (by a share or by house visibility), the owner's own
/// left out; newest first.
pub async fn shared_with(db: &mut Db, sub: &str) -> Result<Vec<IotDevice>> {
    let sql = format!(
        "{DEVICE_LIST} WHERE d.id IN (SELECT a.device_id FROM iot_access a WHERE a.sub = $1 AND a.basis <> 'owner')
         AND d.owner <> $1 ORDER BY d.created_at DESC, d.id"
    );
    Ok(sqlx::query_as(sqlx::AssertSqlSafe(sql)).bind(sub).fetch_all(db.tx().await?).await?)
}

/// Every home device (admins; the controller), revoked ones only when asked.
pub async fn all_devices(db: &mut Db, include_revoked: bool) -> Result<Vec<IotDevice>> {
    let sql = format!("{DEVICE_LIST} WHERE ($1 OR d.revoked_at IS NULL) ORDER BY d.created_at DESC, d.id");
    Ok(sqlx::query_as(sqlx::AssertSqlSafe(sql)).bind(include_revoked).fetch_all(db.tx().await?).await?)
}

/// One home device.
pub async fn device(db: &mut Db, id: Uuid) -> Result<Option<IotDevice>> {
    let sql = format!("{DEVICE_LIST} WHERE d.id = $1");
    Ok(sqlx::query_as(sqlx::AssertSqlSafe(sql)).bind(id).fetch_optional(db.tx().await?).await?)
}

/// The shares of a device, by the grantee's name.
pub async fn shares_of(db: &mut Db, id: Uuid) -> Result<Vec<Share>> {
    Ok(sqlx::query_as(
        "SELECT s.device_id, s.grantee, g.display_name AS grantee_name, s.granted_by, s.granted_at
         FROM iot_share s JOIN person g ON g.sub = s.grantee WHERE s.device_id = $1 ORDER BY g.display_name, s.grantee",
    )
    .bind(id)
    .fetch_all(db.tx().await?)
    .await?)
}

/// Whether a person may reach a device (the view `iot_access`): the owner, a grantee, or anyone
/// with a policy for a house-visible device.
pub async fn may_reach(db: &mut Db, sub: &str, id: Uuid) -> Result<bool> {
    Ok(sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM iot_access WHERE sub = $1 AND device_id = $2)")
        .bind(sub)
        .bind(id)
        .fetch_one(db.tx().await?)
        .await?)
}

/// The whole access view: every (person, device) pair with its basis.
pub async fn access(db: &mut Db) -> Result<Vec<Access>> {
    Ok(sqlx::query_as("SELECT sub, device_id, basis FROM iot_access ORDER BY sub, device_id, basis")
        .fetch_all(db.tx().await?)
        .await?)
}

/// `{device id: [subs]}` of the access view.
pub async fn access_by_device(db: &mut Db) -> Result<BTreeMap<Uuid, Vec<String>>> {
    let mut out: BTreeMap<Uuid, Vec<String>> = BTreeMap::new();
    for row in access(db).await? {
        let subs = out.entry(row.device_id).or_default();
        if !subs.contains(&row.sub) {
            subs.push(row.sub);
        }
    }
    Ok(out)
}

/// The controller writes what it did with a target and key.
pub async fn set_sync(db: &mut Db, target: &str, key: &str, status: &str, detail: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO iot_sync (target, key, status, detail, updated_at) VALUES ($1, $2, $3, left($4, 500), now())
         ON CONFLICT (target, key) DO UPDATE SET status = excluded.status, detail = excluded.detail, updated_at = now()",
    )
    .bind(target)
    .bind(key)
    .bind(status)
    .bind(detail)
    .execute(db.tx().await?)
    .await?;
    Ok(())
}

/// A target and key the controller no longer tracks (a deleted device's row).
pub async fn clear_sync(db: &mut Db, target: &str, key: &str) -> Result<()> {
    sqlx::query("DELETE FROM iot_sync WHERE target = $1 AND key = $2")
        .bind(target)
        .bind(key)
        .execute(db.tx().await?)
        .await?;
    Ok(())
}

/// Every sync row (the admin page, `/metrics`).
pub async fn sync_states(db: &mut Db) -> Result<Vec<SyncState>> {
    Ok(sqlx::query_as("SELECT target, key, status, detail, updated_at FROM iot_sync ORDER BY target, key")
        .fetch_all(db.tx().await?)
        .await?)
}

/// The sync rows of one device (every target whose key is the device id).
pub async fn sync_of_device(db: &mut Db, id: Uuid) -> Result<Vec<SyncState>> {
    Ok(sqlx::query_as("SELECT target, key, status, detail, updated_at FROM iot_sync WHERE key = $1 ORDER BY target")
        .bind(id.to_string())
        .fetch_all(db.tx().await?)
        .await?)
}

/// `{status: count}` of the sync rows.
pub async fn sync_counts(db: &mut Db) -> Result<BTreeMap<String, i64>> {
    let rows =
        sqlx::query("SELECT status, count(*) AS n FROM iot_sync GROUP BY status").fetch_all(db.tx().await?).await?;
    let mut out = BTreeMap::new();
    for r in rows {
        out.insert(r.try_get::<String, _>("status")?, r.try_get::<i64, _>("n")?);
    }
    Ok(out)
}

/// The join attempts of the last [`CLAIM_WINDOW`] whose MAC no device has, newest first.
pub async fn join_attempts(db: &mut Db) -> Result<Vec<JoinAttempt>> {
    Ok(sqlx::query_as(
        "SELECT j.mac::text AS mac, j.first_seen, j.last_seen, j.tries, j.ssid
         FROM iot_join_attempt j
         WHERE j.last_seen > now() - make_interval(secs => $1)
           AND NOT EXISTS (SELECT 1 FROM iot_device i WHERE i.mac = j.mac)
         ORDER BY j.last_seen DESC LIMIT 50",
    )
    .bind(CLAIM_WINDOW.as_seconds_f64())
    .fetch_all(db.tx().await?)
    .await?)
}

/// Join attempts older than a day are forgotten (the controller's housekeeping).
pub async fn prune_join_attempts(db: &mut Db) -> Result<u64> {
    let done = sqlx::query("DELETE FROM iot_join_attempt WHERE last_seen < now() - interval '1 day'")
        .execute(db.tx().await?)
        .await?;
    Ok(done.rows_affected())
}

/// A registered MAC with its device, for the proxy and the controller: every unrevoked IoT
/// device with a MAC.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct MacDevice {
    pub mac: String,
    pub device_id: Uuid,
    pub owner: String,
    pub class: String,
    pub visibility: String,
    pub name: String,
}

pub async fn mac_devices(db: &mut Db) -> Result<Vec<MacDevice>> {
    Ok(sqlx::query_as(
        "SELECT i.mac::text AS mac, d.id AS device_id, d.owner, i.class, i.visibility, d.name
         FROM iot_device i JOIN device d ON d.id = i.device_id
         WHERE i.mac IS NOT NULL AND d.revoked_at IS NULL ORDER BY i.mac",
    )
    .fetch_all(db.tx().await?)
    .await?)
}

/// The residents' current MAC windows: `{mac: owner}` of every certificate device's MAC whose
/// window is current (the proxy's identity of a querier in VLAN 30, the controller's source
/// addresses). A MAC claimed by devices of two owners at once belongs to nobody.
pub async fn current_resident_macs(db: &mut Db) -> Result<BTreeMap<String, String>> {
    let rows = sqlx::query(
        "SELECT w.mac::text AS mac, min(d.owner) AS owner, count(DISTINCT d.owner) AS owners
         FROM device_mac_window w JOIN device d ON d.id = w.device_id
         WHERE d.kind = 'cert' AND d.revoked_at IS NULL AND w.current AND now() <= w.window_end
         GROUP BY w.mac",
    )
    .fetch_all(db.tx().await?)
    .await?;
    let mut out = BTreeMap::new();
    for r in rows {
        if r.try_get::<i64, _>("owners")? == 1 {
            out.insert(r.try_get::<String, _>("mac")?, r.try_get::<String, _>("owner")?);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_and_classes() {
        let a = new_psk();
        let b = new_psk();
        assert_eq!(a.len(), PSK_LENGTH);
        assert!(a.chars().all(|c| c.is_ascii_alphanumeric()));
        assert_ne!(a, b);
        assert_eq!(service_types("airplay"), &["_airplay._tcp", "_raop._tcp"]);
        assert!(service_types("other").contains(&"_googlecast._tcp"));
        assert!(CLASSES.contains(&"printer"));
    }
}
