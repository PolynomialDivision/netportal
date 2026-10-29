//! The device registry (Python: `netportal/registry.py`, INVENTORY 5.8 and 9.11): the schema
//! (`migrations/`), the FreeRADIUS role's rights (`sql/radius_grants.sql`) and every
//! query the portal, the offboarding and the collector make.
//!
//! Conventions: times are `OffsetDateTime` (UTC), MACs normalised strings `aa:bb:cc:dd:ee:ff`,
//! addresses strings. Functions that write leave the transaction open: the caller commits
//! ([`Db`]); [`migrate`] and [`init`] commit themselves.

use std::collections::{BTreeMap, BTreeSet};

use indexmap::IndexMap;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::types::Json;
use sqlx::{Executor, Row};
use time::{Date, Duration, OffsetDateTime};
use uuid::Uuid;

use crate::config::Policy;
use crate::db::Db;

const LOG: &str = "netportal.registry";

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("database: {0}")]
    Db(#[from] sqlx::Error),
    #[error("migration: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    /// An argument the registry refuses (an invalid AP MAC, ...).
    #[error("{0}")]
    Invalid(String),
    /// A state the code cannot resolve (an incident neither found nor inserted).
    #[error("{0}")]
    Conflict(String),
}

pub type Result<T> = std::result::Result<T, RegistryError>;

// --- schema ----------------------------------------------------------------------------------------

/// The migrations (`migrations/NNNN_name.sql`), embedded at build time; sqlx's migrator
/// records them in `_sqlx_migrations` with their checksums and refuses a changed applied one.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

/// The FreeRADIUS role's rights, applied after every migration run (declarative, may change).
pub const RADIUS_GRANTS_SQL: &str = include_str!("../../../sql/radius_grants.sql");
/// The discovery proxy's read-only role's rights, applied the same way (migration 0006).
pub const DISCOVERY_GRANTS_SQL: &str = include_str!("../../../sql/discovery_grants.sql");

/// sqlx's ledger table (version, description, checksum, success, ...).
pub const MIGRATIONS_TABLE: &str = "_sqlx_migrations";

/// Serialises the grants and the seeds of concurrently starting processes.
const SCHEMA_LOCK: &str = "netportal-schema";

/// What [`migrate`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrateReport {
    /// versions applied by this run
    pub applied: Vec<i64>,
    /// the highest applied version
    pub version: Option<i64>,
    /// applied versions this binary does not know (a newer release ran; left alone)
    pub unknown: Vec<i64>,
    /// whether the role radius exists (FreeRADIUS cannot read the registry without it)
    pub radius_role: bool,
}

async fn applied_versions(db: &mut Db) -> Result<Vec<i64>> {
    let conn = db.autocommit().await?;
    let exists: bool =
        sqlx::query_scalar("SELECT to_regclass('_sqlx_migrations') IS NOT NULL").fetch_one(&mut *conn).await?;
    if !exists {
        return Ok(Vec::new());
    }
    Ok(sqlx::query_scalar("SELECT version FROM _sqlx_migrations WHERE success ORDER BY version")
        .fetch_all(&mut *conn)
        .await?)
}

/// Bring the schema up to date (each migration in its own transaction, recorded with its
/// SHA-384 checksum in `_sqlx_migrations`, all under a session advisory lock), then apply the radius role's grants (in one transaction under the schema lock).
/// Applied migrations unknown to this binary are left alone (migrations only add). A changed
/// applied migration is refused (nothing changes). A missing radius role is a warning.
pub async fn migrate(db: &mut Db) -> Result<MigrateReport> {
    db.rollback().await?;
    // one migrating process at a time (the web and init-db may start together)
    sqlx::query("SELECT pg_advisory_lock(hashtext($1))").bind(SCHEMA_LOCK).execute(db.autocommit().await?).await?;
    let result = migrate_locked(db).await;
    let unlocked =
        sqlx::query("SELECT pg_advisory_unlock(hashtext($1))").bind(SCHEMA_LOCK).execute(db.autocommit().await?).await;
    let report = result?;
    unlocked?;
    if !report.radius_role {
        tracing::warn!(target: LOG, "the database role radius does not exist: FreeRADIUS cannot read the registry \
                                     (the stack creates it: house-infra stacks/netaccess files/init-radius-role.sh)");
    }
    Ok(report)
}

async fn migrate_locked(db: &mut Db) -> Result<MigrateReport> {
    use sqlx::migrate::{Migrate, MigrateError};
    let before = applied_versions(db).await?;
    let conn = db.autocommit().await?;
    conn.ensure_migrations_table(MIGRATIONS_TABLE).await?;
    if let Some(version) = conn.dirty_version(MIGRATIONS_TABLE).await? {
        return Err(MigrateError::Dirty(version).into());
    }
    let recorded: BTreeMap<i64, Vec<u8>> = conn
        .list_applied_migrations(MIGRATIONS_TABLE)
        .await?
        .into_iter()
        .map(|m| (m.version, m.checksum.to_vec()))
        .collect();
    for m in MIGRATOR.iter().filter(|m| !m.migration_type.is_down_migration()) {
        match recorded.get(&m.version) {
            Some(checksum) if checksum.as_slice() != m.checksum.as_ref() => {
                return Err(MigrateError::VersionMismatch(m.version).into());
            }
            Some(_) => {}
            None => {
                tracing::info!(target: LOG, "applying migration {:04} ({})", m.version, m.description);
                conn.apply(MIGRATIONS_TABLE, m).await?;
            }
        }
    }
    let after = applied_versions(db).await?;
    let known: BTreeSet<i64> = MIGRATOR.iter().map(|m| m.version).collect();
    let applied: Vec<i64> = after.iter().copied().filter(|v| !before.contains(v)).collect();
    let unknown: Vec<i64> = after.iter().copied().filter(|v| !known.contains(v)).collect();
    if !unknown.is_empty() {
        tracing::info!(target: LOG, "the schema has migrations this release does not know (a newer one ran): {unknown:?}");
    }
    let radius_role = apply_grants(db).await?;
    Ok(MigrateReport { version: after.last().copied(), applied, unknown, radius_role })
}

async fn apply_grants(db: &mut Db) -> Result<bool> {
    let result = async {
        let conn = db.tx().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))").bind(SCHEMA_LOCK).execute(&mut *conn).await?;
        conn.execute(sqlx::raw_sql(RADIUS_GRANTS_SQL)).await?;
        conn.execute(sqlx::raw_sql(DISCOVERY_GRANTS_SQL)).await?;
        let role: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'radius')")
            .fetch_one(&mut *conn)
            .await?;
        Ok::<bool, sqlx::Error>(role)
    }
    .await;
    match result {
        Ok(role) => {
            db.commit().await?;
            Ok(role)
        }
        Err(e) => {
            db.rollback().await?;
            Err(e.into())
        }
    }
}

/// The schema ([`migrate`]) and the seeds: the policies with their VLANs (upserted; never
/// deleted, devices refer to them) and the offboarding job (a fresh registry counts as
/// reconciled now, so an offboarding that never succeeds alerts an hour later). Commits.
pub async fn init(db: &mut Db, policies: &[Policy]) -> Result<MigrateReport> {
    let report = migrate(db).await?;
    let conn = db.tx().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))").bind(SCHEMA_LOCK).execute(&mut *conn).await?;
    for policy in policies {
        sqlx::query(
            "INSERT INTO policy (name, vlan) VALUES ($1, $2)
             ON CONFLICT (name) DO UPDATE SET vlan = excluded.vlan",
        )
        .bind(&policy.name)
        .bind(i32::from(policy.vlan))
        .execute(&mut *conn)
        .await?;
    }
    sqlx::query("INSERT INTO job (name, last_success) VALUES ('offboarding', now()) ON CONFLICT (name) DO NOTHING")
        .execute(&mut *conn)
        .await?;
    db.commit().await?;
    Ok(report)
}

// --- tokens and MACs -------------------------------------------------------------------------------

/// The stored form of a token: SHA-256 hex of its text.
pub fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// A new random token: 32 bytes, base64url without padding (43 characters).
pub fn new_token() -> String {
    use base64::Engine;
    let bytes: [u8; 32] = rand::random();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// `aa:bb:cc:dd:ee:ff` from what an access point sends (`AA-BB-CC-DD-EE-FF`), the colon form or
/// 12 bare hex digits, any case, surrounding ASCII whitespace ignored; `None` for anything else
/// (mixed separators, dots, junk). The twin of SQL `np_mac` (tested against it).
pub fn normalise_mac(raw: &str) -> Option<String> {
    let mac = raw.trim_matches([' ', '\t', '\n', '\r', '\x0c', '\x0b']).to_ascii_lowercase();
    let hex = |s: &str| s.len() == 2 && s.bytes().all(|b| b.is_ascii_hexdigit());
    if mac.len() == 12 && mac.bytes().all(|b| b.is_ascii_hexdigit()) {
        let parts: Vec<&str> = (0..6).map(|i| &mac[i * 2..i * 2 + 2]).collect();
        return Some(parts.join(":"));
    }
    if mac.len() == 17 {
        let sep = mac.as_bytes()[2];
        if sep == b':' || sep == b'-' {
            let parts: Vec<&str> = mac.split(sep as char).collect();
            if parts.len() == 6 && parts.iter().all(|p| hex(p)) {
                return Some(parts.join(":"));
            }
        }
    }
    None
}

/// The locally administered bit (what phones set for a private address) of a normalised MAC.
pub fn is_randomized(mac: &str) -> bool {
    mac.get(..2).and_then(|b| u8::from_str_radix(b, 16).ok()).is_some_and(|b| b & 0x02 != 0)
}

/// A device's window on a MAC ends WINDOW_GRACE after its last_seen, the current one
/// CURRENT_WINDOW after it but not beyond now (the rule is the view `device_mac_window`).
pub const WINDOW_GRACE: Duration = Duration::minutes(15);
pub const CURRENT_WINDOW: Duration = Duration::minutes(12 * 60 + 15);

/// Repeated rejects within REJECT_REPEAT of a row's latest try add to it; a row spans at most
/// REJECT_SPAN (the rule is SQL `radius.reject`).
pub const REJECT_REPEAT: Duration = Duration::seconds(60);
pub const REJECT_SPAN: Duration = Duration::hours(1);

fn limit(limit: i64, cap: i64) -> i64 {
    limit.clamp(1, cap)
}

// --- people ----------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct Person {
    pub sub: String,
    pub username: String,
    pub display_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct PersonState {
    pub is_admin: bool,
}

/// A RADIUS session of a device: where a Disconnect-Request goes (the access point or switch,
/// the MAC as it sent it, the outer identity when known).
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct RadiusSession {
    pub nas_ip: String,
    pub calling_station: String,
    pub user_name: String,
    /// the accounting session's Acct-Session-Id when the request names one session (the
    /// reconciliation's), else empty (every session of the MAC at that access point)
    pub acct_session_id: String,
}

/// Accounting sessions still open after this long without an update are not disconnected (the
/// access point lost them; the Accept's Session-Timeout ended them).
pub const OPEN_SESSION_HOURS: i32 = 24;
/// Disconnect targets per device at most.
pub const SESSION_TARGETS: i64 = 16;

/// Every session of the device a Disconnect-Request should reach: its latest login
/// (`radius_session`, with the outer identity) and every accounting session still open
/// (`radius_acct`, stopped IS NULL, updated in the last [`OPEN_SESSION_HOURS`]; a Mac on Wi-Fi
/// and on the wired port has two), one per access point and MAC, the latest login first.
const SESSIONS_OF: &str = "
    SELECT nas_ip, calling_station, user_name, '' AS acct_session_id FROM (
        SELECT DISTINCT ON (nas_ip, mac) nas_ip, calling_station, user_name, pri FROM (
            SELECT host(s.nas_ip) AS nas_ip, s.calling_station, s.user_name,
                   np_mac(s.calling_station) AS mac, 0 AS pri
            FROM radius_session s WHERE s.device_id = $1
            UNION ALL
            SELECT host(a.nas_ip), upper(replace(a.mac::text, ':', '-')), '', a.mac, 1
            FROM radius_acct a
            WHERE a.device_id = $1 AND a.stopped IS NULL AND a.mac IS NOT NULL
              AND a.updated > now() - make_interval(hours => $2)
        ) t
        ORDER BY nas_ip, mac, pri
    ) u
    ORDER BY pri, nas_ip
    LIMIT $3";

/// The Disconnect targets of a device (see [`SESSIONS_OF`]).
pub async fn sessions_of(db: &mut Db, device_id: Uuid) -> Result<Vec<RadiusSession>> {
    Ok(sqlx::query_as(SESSIONS_OF)
        .bind(device_id)
        .bind(OPEN_SESSION_HOURS)
        .bind(SESSION_TARGETS)
        .fetch_all(db.tx().await?)
        .await?)
}

/// A login: the person's names and admin flag now; clears an offboarding.
pub async fn upsert_person(db: &mut Db, sub: &str, username: &str, display_name: &str, is_admin: bool) -> Result<()> {
    sqlx::query(
        "INSERT INTO person (sub, username, display_name, is_admin) VALUES ($1, $2, $3, $4)
         ON CONFLICT (sub) DO UPDATE SET username = excluded.username, display_name = excluded.display_name,
             is_admin = excluded.is_admin, last_login_at = now(), offboarded_at = NULL, absent_since = NULL",
    )
    .bind(sub)
    .bind(username)
    .bind(display_name)
    .bind(is_admin)
    .execute(db.tx().await?)
    .await?;
    Ok(())
}

/// Whether the person is in the admin groups now (the offboarding round from the directory, the
/// portal's live check). Losing the right also ends every portal session of the person
/// ([`end_sessions`]): the next page logs in again and gets the groups from Authentik. Returns
/// whether the right was taken away now.
pub async fn set_admin(db: &mut Db, sub: &str, is_admin: bool) -> Result<bool> {
    let lost: Option<bool> = sqlx::query_scalar(
        "UPDATE person SET is_admin = $2 WHERE sub = $1 AND is_admin IS DISTINCT FROM $2 RETURNING NOT $2",
    )
    .bind(sub)
    .bind(is_admin)
    .fetch_optional(db.tx().await?)
    .await?;
    let lost = lost.unwrap_or(false);
    if lost {
        end_sessions(db, sub).await?;
    }
    Ok(lost)
}

/// The person's policy, `None` when unknown (or no such person).
pub async fn person_policy(db: &mut Db, sub: &str) -> Result<Option<String>> {
    let policy: Option<Option<String>> =
        sqlx::query_scalar("SELECT policy FROM person WHERE sub = $1").bind(sub).fetch_optional(db.tx().await?).await?;
    Ok(policy.flatten())
}

/// The person's policy now; their active devices that had another one move with it. Returns
/// the moved devices with their RADIUS sessions ([`sessions_of`]: a Disconnect makes each log in
/// again, into the new VLAN).
pub async fn set_policy(db: &mut Db, sub: &str, policy: &str) -> Result<Vec<(Uuid, Vec<RadiusSession>)>> {
    let conn = db.tx().await?;
    sqlx::query("UPDATE person SET policy = $2 WHERE sub = $1 AND policy IS DISTINCT FROM $2")
        .bind(sub)
        .bind(policy)
        .execute(&mut *conn)
        .await?;
    let moved: Vec<Uuid> = sqlx::query_scalar(
        "UPDATE device SET policy = $2 WHERE owner = $1 AND revoked_at IS NULL AND policy <> $2 RETURNING id",
    )
    .bind(sub)
    .bind(policy)
    .fetch_all(&mut *conn)
    .await?;
    let mut result = Vec::with_capacity(moved.len());
    for id in moved {
        result.push((id, sessions_of(db, id).await?));
    }
    Ok(result)
}

/// Everyone the registry knows, by sub.
pub async fn people(db: &mut Db) -> Result<IndexMap<String, Person>> {
    let rows = sqlx::query_as::<_, Person>("SELECT sub, username, display_name FROM person ORDER BY sub")
        .fetch_all(db.tx().await?)
        .await?;
    Ok(rows.into_iter().map(|p| (p.sub.clone(), p)).collect())
}

/// The person's rights while active (logged in, not offboarded since), else `None` (the portal
/// asks [`session_rights`] on every request instead: the same with the session's row).
pub async fn person_state(db: &mut Db, sub: &str) -> Result<Option<PersonState>> {
    Ok(sqlx::query_as("SELECT is_admin FROM person WHERE sub = $1 AND offboarded_at IS NULL")
        .bind(sub)
        .fetch_optional(db.tx().await?)
        .await?)
}

/// Everyone the offboarding looks at: people not offboarded, owners of active devices and of
/// live app grants.
pub async fn subjects_to_check(db: &mut Db) -> Result<BTreeSet<String>> {
    let subs: Vec<String> = sqlx::query_scalar(
        "SELECT sub FROM person WHERE offboarded_at IS NULL
         UNION SELECT owner FROM device WHERE revoked_at IS NULL
         UNION SELECT owner FROM oauth_grant WHERE revoked_at IS NULL",
    )
    .fetch_all(db.tx().await?)
    .await?;
    Ok(subs.into_iter().collect())
}

/// The owners of active devices (the base of the offboarding's mass-removal hold).
pub async fn owners_of_active_devices(db: &mut Db) -> Result<BTreeSet<String>> {
    let subs: Vec<String> = sqlx::query_scalar("SELECT DISTINCT owner FROM device WHERE revoked_at IS NULL")
        .fetch_all(db.tx().await?)
        .await?;
    Ok(subs.into_iter().collect())
}

/// What the registry knows of a person the directory no longer allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Absence {
    /// when a round first found them without access (cleared when a round or a login finds
    /// them allowed again)
    pub absent_since: Option<OffsetDateTime>,
    /// offboarded already (devices left from an earlier round go at once)
    pub offboarded: bool,
}

/// [`Absence`] of each of these people (subjects without a person row are left out).
pub async fn absence(db: &mut Db, subs: &[String]) -> Result<BTreeMap<String, Absence>> {
    let rows: Vec<(String, Option<OffsetDateTime>, bool)> =
        sqlx::query_as("SELECT sub, absent_since, offboarded_at IS NOT NULL FROM person WHERE sub = ANY($1)")
            .bind(subs)
            .fetch_all(db.tx().await?)
            .await?;
    Ok(rows.into_iter().map(|(sub, absent_since, offboarded)| (sub, Absence { absent_since, offboarded })).collect())
}

/// Note that a round found the person without access (kept when already set; a subject without
/// a person row, e.g. only a device owner, gets none and is offboarded at once).
pub async fn mark_absent(db: &mut Db, sub: &str) -> Result<()> {
    sqlx::query("UPDATE person SET absent_since = now() WHERE sub = $1 AND absent_since IS NULL")
        .bind(sub)
        .execute(db.tx().await?)
        .await?;
    Ok(())
}

/// The person is allowed again (in the directory's groups): their absence mark goes.
pub async fn clear_absent(db: &mut Db, sub: &str) -> Result<()> {
    sqlx::query("UPDATE person SET absent_since = NULL WHERE sub = $1 AND absent_since IS NOT NULL")
        .bind(sub)
        .execute(db.tx().await?)
        .await?;
    Ok(())
}

// --- portal sessions ---------------------------------------------------------------------------------

/// A portal session ends this long after its login however busy (the 8 h idle limit is the
/// cookie's own timestamp, checked by the web).
pub const SESSION_LIFETIME: Duration = Duration::hours(12);

/// A new portal session of the person (the login): its id for the session cookie (32 random
/// bytes, base64url; only its SHA-256 is stored). The person's ended and expired rows go now.
pub async fn start_session(db: &mut Db, sub: &str) -> Result<String> {
    let id = new_token();
    let conn = db.tx().await?;
    sqlx::query(
        "DELETE FROM web_session
         WHERE sub = $1 AND (ended_at IS NOT NULL OR created_at <= now() - make_interval(secs => $2))",
    )
    .bind(sub)
    .bind(SESSION_LIFETIME.as_seconds_f64())
    .execute(&mut *conn)
    .await?;
    sqlx::query("INSERT INTO web_session (id_hash, sub) VALUES ($1, $2)")
        .bind(token_hash(&id))
        .bind(sub)
        .execute(&mut *conn)
        .await?;
    Ok(id)
}

/// The rights of the person while this portal session of theirs lives (not ended, younger than
/// [`SESSION_LIFETIME`], the person not offboarded), else `None`. Asked on every request that
/// needs a login (one query): rights come from here, not from the cookie.
pub async fn session_rights(db: &mut Db, session_id: &str, sub: &str) -> Result<Option<PersonState>> {
    Ok(sqlx::query_as(
        "SELECT p.is_admin FROM web_session s JOIN person p ON p.sub = s.sub
         WHERE s.id_hash = $1 AND s.sub = $2 AND s.ended_at IS NULL AND p.offboarded_at IS NULL
           AND s.created_at > now() - make_interval(secs => $3)",
    )
    .bind(token_hash(session_id))
    .bind(sub)
    .bind(SESSION_LIFETIME.as_seconds_f64())
    .fetch_optional(db.tx().await?)
    .await?)
}

/// End this portal session (a logout: the person's other sessions stay). Returns whether it was
/// still open.
pub async fn end_session(db: &mut Db, session_id: &str) -> Result<bool> {
    let n = sqlx::query("UPDATE web_session SET ended_at = now() WHERE id_hash = $1 AND ended_at IS NULL")
        .bind(token_hash(session_id))
        .execute(db.tx().await?)
        .await?
        .rows_affected();
    Ok(n > 0)
}

/// End every portal session of the person ("log out everywhere", an offboarding, the loss of the
/// admin right): every cookie of theirs, copies included, is no login from now on. Returns how
/// many were open.
pub async fn end_sessions(db: &mut Db, sub: &str) -> Result<u64> {
    Ok(sqlx::query("UPDATE web_session SET ended_at = now() WHERE sub = $1 AND ended_at IS NULL")
        .bind(sub)
        .execute(db.tx().await?)
        .await?
        .rows_affected())
}

/// The person lost access: no portal session (now; a later login starts new ones), no admin
/// right, no app grants (devices: revoke each).
pub async fn offboard_person(db: &mut Db, sub: &str) -> Result<()> {
    let conn = db.tx().await?;
    sqlx::query("UPDATE person SET offboarded_at = now(), is_admin = false WHERE sub = $1 AND offboarded_at IS NULL")
        .bind(sub)
        .execute(&mut *conn)
        .await?;
    sqlx::query("UPDATE oauth_grant SET revoked_at = now() WHERE owner = $1 AND revoked_at IS NULL")
        .bind(sub)
        .execute(&mut *conn)
        .await?;
    end_sessions(db, sub).await?;
    Ok(())
}

// --- devices ---------------------------------------------------------------------------------------

/// A device as the pages show it: its certificates' latest expiry (of those not retired), their
/// number, and its latest RADIUS login (`last_seen`, the MAC as the AP sent it, the first login
/// with that MAC).
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct DeviceRow {
    pub id: Uuid,
    pub owner: String,
    pub name: String,
    pub platform: String,
    pub policy: String,
    pub created_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
    pub expires: Option<OffsetDateTime>,
    pub certificates: i64,
    pub last_seen: Option<OffsetDateTime>,
    pub calling_station: Option<String>,
    pub first_seen: Option<OffsetDateTime>,
}

const DEVICE_LIST: &str = "
    SELECT d.id, d.owner, d.name, d.platform, d.policy, d.created_at, d.revoked_at,
           (SELECT max(c.not_after) FROM credential c WHERE c.device_id = d.id
              AND (c.retired_at IS NULL OR c.retired_at > now())) AS expires,
           (SELECT count(*) FROM credential c WHERE c.device_id = d.id) AS certificates,
           s.updated AS last_seen, s.calling_station, s.first_seen
    FROM device d LEFT JOIN radius_session s ON s.device_id = d.id";

/// A new certificate device; returns its id (also the certificate subject).
pub async fn create_device(db: &mut Db, owner: &str, name: &str, platform: &str, policy: &str) -> Result<Uuid> {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO device (id, owner, name, kind, platform, policy) VALUES ($1, $2, $3, 'cert', $4, $5)")
        .bind(id)
        .bind(owner)
        .bind(name)
        .bind(platform)
        .bind(policy)
        .execute(db.tx().await?)
        .await?;
    Ok(id)
}

/// What a person has done lately, for the portal's limits: active devices, devices created and
/// certificates issued within the given windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Usage {
    pub active_devices: i64,
    pub devices_created: i64,
    pub certificates_issued: i64,
}

/// [`Usage`] of a person: devices created in the last `devices_window`, certificates issued
/// (downloads and the apps' eap-configs) in the last `certificates_window`.
pub async fn usage(db: &mut Db, owner: &str, devices_window: Duration, certificates_window: Duration) -> Result<Usage> {
    let row = sqlx::query(
        "SELECT (SELECT count(*) FROM device WHERE owner = $1 AND revoked_at IS NULL) AS active,
                (SELECT count(*) FROM device WHERE owner = $1 AND created_at > now() - make_interval(secs => $2)) AS created,
                (SELECT count(*) FROM credential c JOIN device d ON d.id = c.device_id
                  WHERE d.owner = $1 AND c.issued_at > now() - make_interval(secs => $3)) AS issued",
    )
    .bind(owner)
    .bind(devices_window.as_seconds_f64())
    .bind(certificates_window.as_seconds_f64())
    .fetch_one(db.tx().await?)
    .await?;
    Ok(Usage {
        active_devices: row.try_get("active")?,
        devices_created: row.try_get("created")?,
        certificates_issued: row.try_get("issued")?,
    })
}

/// Devices (of one owner, or all), newest first; revoked ones only when asked.
pub async fn devices(db: &mut Db, owner: Option<&str>, include_revoked: bool) -> Result<Vec<DeviceRow>> {
    let sql = format!(
        "{DEVICE_LIST} WHERE ($1::text IS NULL OR d.owner = $1) AND ($2 OR d.revoked_at IS NULL)
         ORDER BY d.created_at DESC, d.id"
    );
    Ok(sqlx::query_as(sqlx::AssertSqlSafe(sql)).bind(owner).bind(include_revoked).fetch_all(db.tx().await?).await?)
}

/// One device (of this owner, when given).
pub async fn device(db: &mut Db, id: Uuid, owner: Option<&str>) -> Result<Option<DeviceRow>> {
    let sql = format!("{DEVICE_LIST} WHERE d.id = $1 AND ($2::text IS NULL OR d.owner = $2)");
    Ok(sqlx::query_as(sqlx::AssertSqlSafe(sql)).bind(id).bind(owner).fetch_optional(db.tx().await?).await?)
}

/// `{mac: owners}`: whose active devices last logged in with one of these MACs (any form; by the
/// latest session only, the v1 rule; the pages use [`device_windows`] / [`window_conflicts`]).
/// Kept for the integration test and admin scripts.
pub async fn mac_claims(db: &mut Db, macs: &[&str]) -> Result<BTreeMap<String, BTreeSet<String>>> {
    let wanted: BTreeSet<String> = macs.iter().filter_map(|m| normalise_mac(m)).collect();
    if wanted.is_empty() {
        return Ok(BTreeMap::new());
    }
    let wanted: Vec<String> = wanted.into_iter().collect();
    let rows = sqlx::query(
        "SELECT np_mac(s.calling_station)::text AS mac, d.owner
         FROM radius_session s JOIN device d ON d.id = s.device_id
         WHERE d.revoked_at IS NULL AND np_mac(s.calling_station) = ANY($1::macaddr[])",
    )
    .bind(&wanted)
    .fetch_all(db.tx().await?)
    .await?;
    let mut claims: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for r in rows {
        claims.entry(r.try_get("mac")?).or_default().insert(r.try_get("owner")?);
    }
    Ok(claims)
}

/// Rename a device that is not revoked.
pub async fn rename(db: &mut Db, id: Uuid, name: &str) -> Result<()> {
    sqlx::query("UPDATE device SET name = $2 WHERE id = $1 AND revoked_at IS NULL")
        .bind(id)
        .bind(name)
        .execute(db.tx().await?)
        .await?;
    Ok(())
}

/// Revoke a device and its app grants, audited as `reason` (`revoke`); returns its RADIUS
/// sessions ([`sessions_of`], for the Disconnect-Requests).
pub async fn revoke(db: &mut Db, id: Uuid, actor: &str, reason: &str) -> Result<Vec<RadiusSession>> {
    let conn = db.tx().await?;
    sqlx::query("UPDATE device SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL")
        .bind(id)
        .execute(&mut *conn)
        .await?;
    sqlx::query("UPDATE oauth_grant SET revoked_at = now() WHERE device_id = $1 AND revoked_at IS NULL")
        .bind(id)
        .execute(&mut *conn)
        .await?;
    audit(db, actor, reason, Some(id)).await?;
    sessions_of(db, id).await
}

/// A new certificate for the device (serial as lowercase hex); its earlier ones end after the
/// renewal overlap (`overlap_days` x 24 h), except those issued within `at_once_within` (a
/// re-issue shortly after the last one: the earlier certificate was a retry, or someone mints
/// certificates; it ends now, so a device holds at most one certificate in its overlap).
pub async fn add_credential(
    db: &mut Db,
    id: Uuid,
    serial_hex: &str,
    not_after: OffsetDateTime,
    overlap_days: u32,
    at_once_within: Option<Duration>,
) -> Result<()> {
    let conn = db.tx().await?;
    sqlx::query(
        "UPDATE credential SET retired_at = CASE WHEN issued_at > now() - make_interval(secs => $3) THEN now()
                                                 ELSE now() + make_interval(days => $2) END
         WHERE device_id = $1 AND retired_at IS NULL",
    )
    .bind(id)
    .bind(i32::try_from(overlap_days).unwrap_or(i32::MAX))
    .bind(at_once_within.map(|d| d.as_seconds_f64()).unwrap_or(-1.0))
    .execute(&mut *conn)
    .await?;
    sqlx::query("INSERT INTO credential (serial, device_id, not_after) VALUES ($1, $2, $3)")
        .bind(serial_hex.to_ascii_lowercase())
        .bind(id)
        .bind(not_after)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// An audit row: who (a sub, `offboarding`, `system`) did what to which device.
pub async fn audit(db: &mut Db, actor: &str, action: &str, device_id: Option<Uuid>) -> Result<()> {
    sqlx::query("INSERT INTO audit (actor, action, device_id) VALUES ($1, $2, $3)")
        .bind(actor)
        .bind(action)
        .bind(device_id)
        .execute(db.tx().await?)
        .await?;
    Ok(())
}

// --- the Disconnect reconciliation ------------------------------------------------------------------

/// A lock must be this old before the reconciliation acts on it: the portal's or the
/// offboarding's own Disconnect-Requests (3 tries of 2 s) are done by then.
pub const RECHECK_GRACE: Duration = Duration::seconds(20);
/// A settled session the access point reports this long after it was settled is live again.
pub const RECHECK_HEARD_SLACK: Duration = Duration::seconds(60);
/// Why a live session should not be there any more (`disconnect_recheck.reason`, the label of
/// `netportal_locked_sessions_live`).
pub const LOCK_REASONS: [&str; 3] = ["revoked", "credential", "vlan"];
/// Live locked sessions read per round at most.
pub const LOCKED_SESSIONS_MAX: i64 = 1000;

/// The live accounting sessions of locked devices, with their reconciliation state. Live: no
/// Stop, and a Start or Interim-Update within two accounting intervals plus 60 s (the session's
/// measured interval or `$1`, NETPORTAL_ACCT_INTERIM_S, whichever is longer; the presence's
/// stale rule). Locked, in this order:
/// - `revoked`: the device is revoked;
/// - `credential`: the certificate the session's login used is retired or expired, or the
///   device has no valid certificate left;
/// - `vlan`: the session's login put it into another VLAN than the device's policy gives now
///   (`radius_auth.vlan`), or, for a login without a recorded VLAN, the device moved to another
///   policy after the session opened.
///
/// The session's login is the device's latest Accept with the session's MAC before the registry
/// first heard of the session (`opened_at`, the registry's clock). Only locks older than `$2`
/// seconds count ([`RECHECK_GRACE`]).
const LOCKED_LIVE: &str = "
    WITH live AS (
        SELECT a.nas_ip, a.acct_session_id, a.device_id, a.mac, a.updated, a.opened_at
        FROM radius_acct a
        WHERE a.stopped IS NULL AND a.device_id IS NOT NULL AND a.mac IS NOT NULL
          AND a.updated > now() - make_interval(secs => 2 * greatest(coalesce(a.interim_s, 0), $1) + 60)
    ), judged AS (
        SELECT l.*, d.revoked_at, p.vlan AS policy_vlan, login.at AS login_at, login.vlan AS login_vlan,
               least(coalesce(c.retired_at, 'infinity'), c.not_after) AS cert_until,
               (SELECT max(least(coalesce(c2.retired_at, 'infinity'), c2.not_after))
                  FROM credential c2 WHERE c2.device_id = d.id) AS device_until,
               (SELECT max(au.at) FROM audit au
                 WHERE au.device_id = d.id AND au.action LIKE 'policy:%') AS moved_at
        FROM live l
        JOIN device d ON d.id = l.device_id AND d.kind = 'cert'
        JOIN policy p ON p.name = d.policy
        LEFT JOIN LATERAL (
            SELECT r.at, r.serial, r.vlan FROM radius_auth r
            WHERE r.device_id = l.device_id AND r.result = 'accept' AND r.mac = l.mac AND r.at <= l.opened_at
            ORDER BY r.at DESC LIMIT 1
        ) login ON true
        LEFT JOIN credential c ON c.serial = login.serial AND c.device_id = d.id
    ), locked AS (
        SELECT j.*,
            CASE WHEN j.revoked_at IS NOT NULL THEN 'revoked'
                 WHEN j.cert_until <= now() OR coalesce(j.device_until, '-infinity') <= now() THEN 'credential'
                 WHEN j.login_vlan IS NOT NULL AND j.login_vlan <> j.policy_vlan THEN 'vlan'
                 WHEN j.login_vlan IS NULL AND j.moved_at > j.opened_at THEN 'vlan'
            END AS reason,
            CASE WHEN j.revoked_at IS NOT NULL THEN j.revoked_at
                 WHEN j.cert_until <= now() THEN j.cert_until
                 WHEN coalesce(j.device_until, '-infinity') <= now() THEN coalesce(j.device_until, '-infinity')
                 ELSE coalesce(j.moved_at, j.login_at, '-infinity')
            END AS lock_at
        FROM judged j
    )
    SELECT host(k.nas_ip) AS nas_ip, k.acct_session_id, k.device_id, k.mac::text AS mac, k.updated, k.reason,
           coalesce(r.tries, 0) AS tries, r.settled, r.settled_at, r.next_at
    FROM locked k
    LEFT JOIN disconnect_recheck r ON r.nas_ip = k.nas_ip AND r.acct_session_id = k.acct_session_id
    WHERE k.reason IS NOT NULL AND k.lock_at < now() - make_interval(secs => $2)
    ORDER BY k.updated DESC
    LIMIT $3";

/// A live accounting session of a locked device ([`locked_live_sessions`]).
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct LockedSession {
    pub nas_ip: String,
    pub acct_session_id: String,
    pub device_id: Uuid,
    /// `aa:bb:cc:dd:ee:ff`
    pub mac: String,
    /// its latest Start or Interim-Update
    pub updated: OffsetDateTime,
    /// one of [`LOCK_REASONS`]
    pub reason: String,
    /// Disconnect-Requests the reconciliation sent for it so far
    pub tries: i32,
    /// `ack`, `not_found`, `stale`, `given_up`, or `None` while open
    pub settled: Option<String>,
    pub settled_at: Option<OffsetDateTime>,
    /// when its next try is due (`None`: never tried)
    pub next_at: Option<OffsetDateTime>,
}

impl LockedSession {
    /// Reported by the access point after it was settled (an Interim-Update after an ACK).
    fn heard_since_settled(&self) -> bool {
        self.settled_at.is_some_and(|at| self.updated > at + RECHECK_HEARD_SLACK)
    }

    /// Whether the reconciliation sends a Disconnect-Request now: never tried, or its retry due;
    /// a session settled by an ACK (or as stale) that the access point reports again, while
    /// fewer than `max_tries` were sent. Never one an access point answered "no such session"
    /// (`not_found`) or one given up.
    pub fn due(&self, now: OffsetDateTime, max_tries: i32) -> bool {
        match self.settled.as_deref() {
            None => self.next_at.is_none_or(|at| at <= now),
            Some("ack" | "stale") => self.heard_since_settled() && self.tries < max_tries,
            _ => false,
        }
    }

    /// Whether it counts as still connected after the reconciliation's tries
    /// (`netportal_locked_sessions_live`): not settled, given up, or reported again since it was
    /// settled.
    pub fn still_live(&self) -> bool {
        match self.settled.as_deref() {
            None | Some("given_up") => true,
            Some(_) => self.heard_since_settled(),
        }
    }

    /// The Disconnect target: this one session at its access point (Acct-Session-Id and the MAC
    /// as hostapd formats it).
    pub fn target(&self) -> RadiusSession {
        RadiusSession {
            nas_ip: self.nas_ip.clone(),
            calling_station: self.mac.to_ascii_uppercase().replace(':', "-"),
            user_name: String::new(),
            acct_session_id: self.acct_session_id.clone(),
        }
    }
}

/// Every live accounting session of a locked device whose lock is older than `grace` (at most
/// [`LOCKED_SESSIONS_MAX`], the most recently heard first), see [`LOCKED_LIVE`]. `interim_s`:
/// NETPORTAL_ACCT_INTERIM_S.
pub async fn locked_live_sessions(db: &mut Db, interim_s: u32, grace: Duration) -> Result<Vec<LockedSession>> {
    Ok(sqlx::query_as(LOCKED_LIVE)
        .bind(f64::from(interim_s))
        .bind(grace.as_seconds_f64())
        .bind(LOCKED_SESSIONS_MAX)
        .fetch_all(db.tx().await?)
        .await?)
}

/// `netportal_locked_sessions_live{reason}`: the [`locked_live_sessions`] past [`RECHECK_GRACE`]
/// that are still live after the reconciliation's tries ([`LockedSession::still_live`]), per
/// reason of [`LOCK_REASONS`] in that order.
pub async fn locked_live_counts(db: &mut Db, interim_s: u32) -> Result<Vec<(&'static str, i64)>> {
    let sessions = locked_live_sessions(db, interim_s, RECHECK_GRACE).await?;
    Ok(LOCK_REASONS
        .iter()
        .map(|reason| (*reason, sessions.iter().filter(|s| s.reason == *reason && s.still_live()).count() as i64))
        .collect())
}

/// One Disconnect-Request of the reconciliation for this session: its `result`
/// (`disconnect_recheck.last_result`), `settled` when it settles the session (`ack`,
/// `not_found`, `given_up`), else the next try in `retry_in`.
pub async fn record_recheck(
    db: &mut Db,
    session: &LockedSession,
    result: &str,
    settled: Option<&str>,
    retry_in: Duration,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO disconnect_recheck AS r (nas_ip, acct_session_id, device_id, reason, tries, last_at, last_result,
                                             next_at, settled, settled_at)
         VALUES ($1::inet, $2, $3, $4, 1, now(), $5, now() + make_interval(secs => $6), $7,
                 CASE WHEN $7::text IS NOT NULL THEN now() END)
         ON CONFLICT (nas_ip, acct_session_id) DO UPDATE SET
             device_id = EXCLUDED.device_id, reason = EXCLUDED.reason, tries = r.tries + 1, last_at = now(),
             last_result = EXCLUDED.last_result, next_at = EXCLUDED.next_at, settled = EXCLUDED.settled,
             settled_at = EXCLUDED.settled_at",
    )
    .bind(&session.nas_ip)
    .bind(&session.acct_session_id)
    .bind(session.device_id)
    .bind(&session.reason)
    .bind(result)
    .bind(retry_in.as_seconds_f64())
    .bind(settled)
    .execute(db.tx().await?)
    .await?;
    Ok(())
}

/// After a round over the `live` sessions (all of [`locked_live_sessions`]): open entries of
/// sessions no longer among them are settled as `stale` (a Stop, no update for two intervals,
/// or no longer locked); settled entries of such sessions go a day after they settled. Returns
/// the sessions settled as stale now.
pub async fn settle_rechecks(db: &mut Db, live: &[LockedSession]) -> Result<u64> {
    let nas: Vec<&str> = live.iter().map(|s| s.nas_ip.as_str()).collect();
    let ids: Vec<&str> = live.iter().map(|s| s.acct_session_id.as_str()).collect();
    let conn = db.tx().await?;
    let stale = sqlx::query(
        "UPDATE disconnect_recheck SET settled = 'stale', settled_at = now()
         WHERE settled IS NULL
           AND (host(nas_ip), acct_session_id) NOT IN (SELECT * FROM unnest($1::text[], $2::text[]))",
    )
    .bind(&nas)
    .bind(&ids)
    .execute(&mut *conn)
    .await?
    .rows_affected();
    sqlx::query(
        "DELETE FROM disconnect_recheck
         WHERE settled_at < now() - interval '1 day'
           AND (host(nas_ip), acct_session_id) NOT IN (SELECT * FROM unnest($1::text[], $2::text[]))",
    )
    .bind(&nas)
    .bind(&ids)
    .execute(&mut *conn)
    .await?;
    Ok(stale)
}

// --- retention ---------------------------------------------------------------------------------------

/// radius_auth, radius_acct, connection_event, device_mac of revoked devices
pub const RETENTION_DAYS: i64 = 400;
pub const AUDIT_DAYS: i64 = 90;
/// Rows per DELETE: every statement stays short, also with a large backlog.
pub const PRUNE_BATCH: i64 = 10_000;

/// Housekeeping: RADIUS decisions, accounting sessions and UniFi events older than 400 days,
/// the MAC identities of revoked devices 400 days after their last use, audit rows after
/// `audit_days`, expired tokens and downloads, ended and expired portal sessions. Rollups and
/// incidents are kept. Every table in
/// DELETEs of at most `batch` rows until one deletes fewer; with `commit` each is committed
/// (no statement or transaction grows with the backlog), else the caller commits. Returns the
/// rows deleted per table.
pub async fn prune(
    db: &mut Db,
    now: Option<OffsetDateTime>,
    audit_days: i64,
    batch: i64,
    commit: bool,
) -> Result<IndexMap<&'static str, u64>> {
    let now = now.unwrap_or_else(OffsetDateTime::now_utc);
    let cutoff = now - Duration::days(RETENTION_DAYS);
    let statements: [(&'static str, &str, OffsetDateTime); 8] = [
        ("radius_auth", "SELECT ctid FROM radius_auth WHERE at < $1", cutoff),
        ("radius_acct", "SELECT ctid FROM radius_acct WHERE updated < $1", cutoff),
        ("connection_event", "SELECT ctid FROM connection_event WHERE at < $1", cutoff),
        (
            "device_mac",
            "SELECT m.ctid FROM device_mac m JOIN device d ON d.id = m.device_id
             WHERE d.revoked_at IS NOT NULL AND m.last_seen < $1",
            cutoff,
        ),
        ("audit", "SELECT ctid FROM audit WHERE at < $1", now - Duration::days(audit_days)),
        ("download", "SELECT ctid FROM download WHERE expires_at < $1", now),
        ("oauth_token", "SELECT ctid FROM oauth_token WHERE expires_at < $1", now),
        (
            "web_session",
            "SELECT ctid FROM web_session WHERE ended_at IS NOT NULL OR created_at < $1",
            now - SESSION_LIFETIME,
        ),
    ];
    let batch = batch.max(1);
    let mut deleted = IndexMap::new();
    for (table, select, bound) in statements {
        let sql = format!("DELETE FROM {table} WHERE ctid = ANY(ARRAY({select} LIMIT $2))");
        let mut total = 0u64;
        loop {
            let n = sqlx::query(sqlx::AssertSqlSafe(sql.as_str()))
                .bind(bound)
                .bind(batch)
                .execute(db.tx().await?)
                .await?
                .rows_affected();
            total += n;
            if commit {
                db.commit().await?;
            }
            if n < batch as u64 {
                break;
            }
        }
        deleted.insert(table, total);
    }
    Ok(deleted)
}

// --- one-time downloads ------------------------------------------------------------------------------

/// A one-time download of the device's profile in `format`, valid for `minutes`; returns the
/// token (only its hash is stored).
pub async fn create_download(db: &mut Db, device_id: Uuid, format: &str, minutes: i32) -> Result<String> {
    let token = new_token();
    sqlx::query(
        "INSERT INTO download (token_hash, device_id, format, expires_at)
         VALUES ($1, $2, $3, now() + make_interval(mins => $4))",
    )
    .bind(token_hash(&token))
    .bind(device_id)
    .bind(format)
    .bind(minutes)
    .execute(db.tx().await?)
    .await?;
    Ok(token)
}

/// The download for this token and owner, once: (device, format), or `None` (unknown, expired,
/// someone else's: then it is left alone, or the device is revoked).
pub async fn consume_download(db: &mut Db, token: &str, owner: &str) -> Result<Option<(DeviceRow, String)>> {
    let row = sqlx::query(
        "DELETE FROM download dl USING device d
         WHERE dl.token_hash = $1 AND dl.expires_at > now() AND d.id = dl.device_id AND d.owner = $2
         RETURNING dl.device_id, dl.format",
    )
    .bind(token_hash(token))
    .bind(owner)
    .fetch_optional(db.tx().await?)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let (device_id, format): (Uuid, String) = (row.try_get("device_id")?, row.try_get("format")?);
    match device(db, device_id, None).await? {
        Some(dev) if dev.revoked_at.is_none() => Ok(Some((dev, format))),
        _ => Ok(None),
    }
}

// --- OAuth (Let's Wi-Fi) -----------------------------------------------------------------------------

/// A grant of the person to an app client for a device of this name.
pub async fn create_grant(db: &mut Db, owner: &str, client_id: &str, device_name: &str) -> Result<Uuid> {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO oauth_grant (id, owner, client_id, device_name) VALUES ($1, $2, $3, $4)")
        .bind(id)
        .bind(owner)
        .bind(client_id)
        .bind(device_name)
        .execute(db.tx().await?)
        .await?;
    Ok(id)
}

/// A token of `kind` (`code`, `access`, `refresh`) for the grant, valid `seconds`; codes carry
/// the PKCE challenge and the redirect URI. Returns the token (only its hash is stored).
pub async fn issue_token(
    db: &mut Db,
    grant_id: Uuid,
    kind: &str,
    seconds: i64,
    pkce_challenge: Option<&str>,
    redirect_uri: Option<&str>,
) -> Result<String> {
    let token = new_token();
    sqlx::query(
        "INSERT INTO oauth_token (token_hash, grant_id, kind, expires_at, pkce_challenge, redirect_uri)
         VALUES ($1, $2, $3, now() + make_interval(secs => $4), $5, $6)",
    )
    .bind(token_hash(&token))
    .bind(grant_id)
    .bind(kind)
    .bind(seconds as f64)
    .bind(pkce_challenge)
    .bind(redirect_uri)
    .execute(db.tx().await?)
    .await?;
    Ok(token)
}

/// A token's grant as [`use_token`] returns it.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct TokenGrant {
    pub grant_id: Uuid,
    pub used_at: Option<OffsetDateTime>,
    pub live: bool,
    pub pkce_challenge: Option<String>,
    pub redirect_uri: Option<String>,
    pub owner: String,
    pub client_id: String,
    pub device_name: String,
    pub device_id: Option<Uuid>,
    pub revoked_at: Option<OffsetDateTime>,
    pub owner_active: bool,
}

/// What [`use_token`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenUse {
    /// unknown, of another kind, expired, of a revoked grant or of an offboarded person
    Invalid,
    /// valid (a single-use token is marked used until the caller's commit)
    Valid(TokenGrant),
    /// a single-use token used before: nothing was changed; the caller decides (a replayed
    /// code or refresh token revokes the grant and its device: [`revoke_grant`])
    Replayed(TokenGrant),
}

impl TokenUse {
    /// The grant of a valid token, else `None`.
    pub fn valid(self) -> Option<TokenGrant> {
        match self {
            TokenUse::Valid(grant) => Some(grant),
            _ => None,
        }
    }
}

/// A token of this kind, marked used when `single_use` ([`TokenUse`]). Tokens of an offboarded
/// person stop working at once. The token and its grant stay locked until the caller's commit, so
/// two concurrent uses of one code or refresh token cannot both see it unused, and two first
/// eap-config calls of a grant cannot both create a device.
pub async fn use_token(db: &mut Db, token: &str, kind: &str, single_use: bool) -> Result<TokenUse> {
    let hash = token_hash(token);
    let row: Option<TokenGrant> = sqlx::query_as(
        "SELECT t.grant_id, t.used_at, t.expires_at > now() AS live, t.pkce_challenge, t.redirect_uri,
                g.owner, g.client_id, g.device_name, g.device_id, g.revoked_at,
                (p.offboarded_at IS NULL) AS owner_active
         FROM oauth_token t JOIN oauth_grant g ON g.id = t.grant_id
         JOIN person p ON p.sub = g.owner
         WHERE t.token_hash = $1 AND t.kind = $2
         FOR UPDATE OF t, g",
    )
    .bind(&hash)
    .bind(kind)
    .fetch_optional(db.tx().await?)
    .await?;
    let Some(row) = row else {
        return Ok(TokenUse::Invalid);
    };
    if !row.live || row.revoked_at.is_some() || !row.owner_active {
        return Ok(TokenUse::Invalid);
    }
    if single_use {
        if row.used_at.is_some() {
            return Ok(TokenUse::Replayed(row));
        }
        sqlx::query("UPDATE oauth_token SET used_at = now() WHERE token_hash = $1")
            .bind(&hash)
            .execute(db.tx().await?)
            .await?;
    }
    Ok(TokenUse::Valid(row))
}

/// Revoke a grant (every token it issued stops; its device is revoked by the caller, with its
/// Disconnect-Requests).
pub async fn revoke_grant(db: &mut Db, grant_id: Uuid) -> Result<()> {
    sqlx::query("UPDATE oauth_grant SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL")
        .bind(grant_id)
        .execute(db.tx().await?)
        .await?;
    Ok(())
}

/// The device a grant's app got (at its first eap-config).
pub async fn bind_grant(db: &mut Db, grant_id: Uuid, device_id: Uuid) -> Result<()> {
    sqlx::query("UPDATE oauth_grant SET device_id = $2 WHERE id = $1")
        .bind(grant_id)
        .bind(device_id)
        .execute(db.tx().await?)
        .await?;
    Ok(())
}

// --- MAC windows -------------------------------------------------------------------------------------

/// A device's window on a MAC (view `device_mac_window`).
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct MacWindow {
    pub mac: String,
    pub first_seen: OffsetDateTime,
    pub last_seen: OffsetDateTime,
    pub window_end: OffsetDateTime,
    pub current: bool,
    pub randomized: bool,
    pub auth_count: i32,
}

/// Where devices of other owners had overlapping windows on one of a device's MACs.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct WindowConflict {
    pub mac: String,
    pub other_owners: i64,
    pub from: OffsetDateTime,
    pub to: OffsetDateTime,
}

fn bounds(since: Option<OffsetDateTime>, until: Option<OffsetDateTime>) -> (OffsetDateTime, OffsetDateTime) {
    (since.unwrap_or(OffsetDateTime::UNIX_EPOCH), until.unwrap_or(time::macros::datetime!(9999-01-01 00:00 UTC)))
}

fn keyed<T>(ids: &[Uuid]) -> IndexMap<Uuid, Vec<T>> {
    ids.iter().map(|id| (*id, Vec::new())).collect()
}

/// The windows of the given devices that overlap [since, until] (`None`: open), oldest first;
/// every requested id is a key.
pub async fn device_windows(
    db: &mut Db,
    ids: &[Uuid],
    since: Option<OffsetDateTime>,
    until: Option<OffsetDateTime>,
) -> Result<IndexMap<Uuid, Vec<MacWindow>>> {
    let mut result = keyed(ids);
    if result.is_empty() {
        return Ok(result);
    }
    let (lo, hi) = bounds(since, until);
    let rows = sqlx::query(
        "SELECT device_id, mac::text AS mac, first_seen, last_seen, window_end, current, randomized, auth_count
         FROM device_mac_window
         WHERE device_id = ANY($1) AND first_seen <= $3 AND window_end >= $2
         ORDER BY first_seen, mac",
    )
    .bind(ids)
    .bind(lo)
    .bind(hi)
    .fetch_all(db.tx().await?)
    .await?;
    for r in rows {
        let id: Uuid = r.try_get("device_id")?;
        let window = <MacWindow as sqlx::FromRow<_>>::from_row(&r)?;
        result.entry(id).or_default().push(window);
    }
    Ok(result)
}

/// `{device: conflicts}`: overlapping windows of other owners on the device's MACs (revoked
/// devices count), from/to clipped to [since, until]; devices without one are not keys.
pub async fn window_conflicts(
    db: &mut Db,
    ids: &[Uuid],
    since: Option<OffsetDateTime>,
    until: Option<OffsetDateTime>,
) -> Result<IndexMap<Uuid, Vec<WindowConflict>>> {
    let mut result: IndexMap<Uuid, Vec<WindowConflict>> = IndexMap::new();
    if ids.is_empty() {
        return Ok(result);
    }
    let (lo, hi) = bounds(since, until);
    let rows = sqlx::query(
        r#"SELECT m.device_id, m.mac::text AS mac, count(DISTINCT od.owner) AS other_owners,
                  greatest(min(greatest(m.first_seen, o.first_seen)), $2) AS "from",
                  least(max(least(m.window_end, o.window_end)), $3) AS "to"
           FROM device_mac_window m
           JOIN device d ON d.id = m.device_id
           JOIN device_mac_window o ON o.mac = m.mac AND o.device_id <> m.device_id
           JOIN device od ON od.id = o.device_id AND od.owner <> d.owner
           WHERE m.device_id = ANY($1)
             AND o.first_seen <= m.window_end AND m.first_seen <= o.window_end
             AND greatest(m.first_seen, o.first_seen) <= $3
             AND least(m.window_end, o.window_end) >= $2
           GROUP BY m.device_id, m.mac ORDER BY 1, 4"#,
    )
    .bind(ids)
    .bind(lo)
    .bind(hi)
    .fetch_all(db.tx().await?)
    .await?;
    for r in rows {
        let id: Uuid = r.try_get("device_id")?;
        let conflict = <WindowConflict as sqlx::FromRow<_>>::from_row(&r)?;
        result.entry(id).or_default().push(conflict);
    }
    Ok(result)
}

/// The device whose window on this MAC (any form) contains `at`; `None` when there is none or
/// devices of more than one owner claim it then (SQL `np_device_for_mac`).
pub async fn device_for_mac(db: &mut Db, mac: &str, at: OffsetDateTime) -> Result<Option<Uuid>> {
    let Some(mac) = normalise_mac(mac) else {
        return Ok(None);
    };
    Ok(sqlx::query_scalar("SELECT np_device_for_mac($1::macaddr, $2)")
        .bind(mac)
        .bind(at)
        .fetch_one(db.tx().await?)
        .await?)
}

// --- RADIUS: decisions and accounting ------------------------------------------------------------------

/// A RADIUS decision of a device. `matched`: `device` (logged with the device: its logins, rejects
/// of its certificate) or `mac` (a reject without a known certificate from one of its MACs inside
/// its window there). `tries`: the decisions of the row (repeated rejects), the last at `last_at`.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct AuthEvent {
    pub at: OffsetDateTime,
    pub result: String,
    pub reason: String,
    pub mac: Option<String>,
    pub bssid: Option<String>,
    pub ssid: Option<String>,
    pub nas_ip: Option<String>,
    pub matched: String,
    pub tries: i32,
    pub last_at: Option<OffsetDateTime>,
}

/// The device's decisions in [since, until] (by their first time), oldest first (the newest
/// `limit`, at most 10000).
pub async fn auth_events(
    db: &mut Db,
    device_id: Uuid,
    since: OffsetDateTime,
    until: OffsetDateTime,
    limit_rows: i64,
) -> Result<Vec<AuthEvent>> {
    let mut rows: Vec<AuthEvent> = sqlx::query_as(
        "SELECT at, result, reason, mac, bssid, ssid, nas_ip, matched, tries, last_at FROM (
             SELECT a.id, a.at, a.result, a.reason, a.mac::text AS mac, a.bssid::text AS bssid, a.ssid,
                    host(a.nas_ip) AS nas_ip, 'device' AS matched, a.tries, a.last_at
             FROM radius_auth a WHERE a.device_id = $1 AND a.at BETWEEN $2 AND $3
             UNION ALL
             SELECT a.id, a.at, a.result, a.reason, a.mac::text, a.bssid::text, a.ssid, host(a.nas_ip), 'mac',
                    a.tries, a.last_at
             FROM radius_auth a
             WHERE a.device_id IS NULL AND a.result = 'reject' AND a.at BETWEEN $2 AND $3
               AND EXISTS (SELECT 1 FROM device_mac_window m WHERE m.device_id = $1 AND m.mac = a.mac
                           AND a.at BETWEEN m.first_seen AND m.window_end)
         ) e ORDER BY at DESC, id DESC LIMIT $4",
    )
    .bind(device_id)
    .bind(since)
    .bind(until)
    .bind(limit(limit_rows, 10_000))
    .fetch_all(db.tx().await?)
    .await?;
    rows.reverse();
    Ok(rows)
}

/// A reject for the admin view; device and owner only when the certificate is ours.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct AuthFailure {
    pub at: OffsetDateTime,
    pub reason: String,
    pub serial: Option<String>,
    pub device_id: Option<Uuid>,
    pub owner: Option<String>,
    pub owner_name: Option<String>,
    pub device_name: Option<String>,
    pub mac: Option<String>,
    pub bssid: Option<String>,
    pub ssid: Option<String>,
    pub nas_ip: Option<String>,
    pub tries: i32,
    pub last_at: Option<OffsetDateTime>,
}

/// Rejects in [since, until] (until `None`: now), newest first (at most `limit`, cap 10000).
pub async fn auth_failures(
    db: &mut Db,
    since: OffsetDateTime,
    until: Option<OffsetDateTime>,
    limit_rows: i64,
) -> Result<Vec<AuthFailure>> {
    Ok(sqlx::query_as(
        "SELECT a.at, a.reason, a.serial, a.device_id, d.owner, p.display_name AS owner_name,
                d.name AS device_name, a.mac::text AS mac, a.bssid::text AS bssid, a.ssid, host(a.nas_ip) AS nas_ip,
                a.tries, a.last_at
         FROM radius_auth a
         LEFT JOIN device d ON d.id = a.device_id
         LEFT JOIN person p ON p.sub = d.owner
         WHERE a.result = 'reject' AND a.at >= $1 AND a.at <= coalesce($2, now())
         ORDER BY a.at DESC, a.id DESC LIMIT $3",
    )
    .bind(since)
    .bind(until)
    .bind(limit(limit_rows, 10_000))
    .fetch_all(db.tx().await?)
    .await?)
}

/// An accounting session. `stopped` `None`: open (or its Stop never came: see `updated`);
/// `interim_s`: the measured accounting interval (`None`: not measured yet).
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct AcctSession {
    pub nas_ip: String,
    pub acct_session_id: String,
    pub link: String,
    pub mac: Option<String>,
    pub bssid: Option<String>,
    pub ssid: Option<String>,
    pub framed_ip: Option<String>,
    pub started: Option<OffsetDateTime>,
    pub updated: OffsetDateTime,
    pub stopped: Option<OffsetDateTime>,
    pub session_time_s: Option<i64>,
    pub input_octets: Option<i64>,
    pub output_octets: Option<i64>,
    pub terminate_cause: Option<String>,
    pub interim_s: Option<i32>,
}

/// The device's sessions overlapping [since, until], oldest first (the newest `limit`).
pub async fn acct_sessions(
    db: &mut Db,
    device_id: Uuid,
    since: OffsetDateTime,
    until: OffsetDateTime,
    limit_rows: i64,
) -> Result<Vec<AcctSession>> {
    let mut rows: Vec<AcctSession> = sqlx::query_as(
        "SELECT host(nas_ip) AS nas_ip, acct_session_id, link, mac::text AS mac, bssid::text AS bssid, ssid,
                host(framed_ip) AS framed_ip, started, updated, stopped, session_time_s, input_octets,
                output_octets, terminate_cause, interim_s
         FROM radius_acct
         WHERE device_id = $1 AND coalesce(started, updated) <= $3 AND coalesce(stopped, updated) >= $2
         ORDER BY coalesce(started, updated) DESC LIMIT $4",
    )
    .bind(device_id)
    .bind(since)
    .bind(until)
    .bind(limit(limit_rows, 10_000))
    .fetch_all(db.tx().await?)
    .await?;
    rows.reverse();
    Ok(rows)
}

/// The presence rules read a few of each device's newest sessions and UniFi events.
pub const PRESENCE_SESSIONS: i64 = 5;
pub const PRESENCE_EVENTS: i64 = 3;

/// A recent session for the presence rules, with the NAS's measured interval.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct LatestSession {
    pub nas_ip: String,
    pub acct_session_id: String,
    pub link: String,
    pub mac: Option<String>,
    pub bssid: Option<String>,
    pub ssid: Option<String>,
    pub started: Option<OffsetDateTime>,
    pub updated: OffsetDateTime,
    pub stopped: Option<OffsetDateTime>,
    pub terminate_cause: Option<String>,
    pub session_time_s: Option<i64>,
    pub interim_s: Option<i32>,
    pub nas_interim_s: Option<i32>,
}

/// `{device: sessions}`, newest update first, at most `per_device` (cap 100) each, in one query;
/// every requested id is a key.
pub async fn latest_sessions(db: &mut Db, ids: &[Uuid], per_device: i64) -> Result<IndexMap<Uuid, Vec<LatestSession>>> {
    let mut result = keyed(ids);
    if result.is_empty() {
        return Ok(result);
    }
    let rows = sqlx::query(
        "SELECT d.id AS device_id, s.*
         FROM unnest($1::uuid[]) AS d(id)
         CROSS JOIN LATERAL (
             SELECT host(a.nas_ip) AS nas_ip, a.acct_session_id, a.link, a.mac::text AS mac,
                    a.bssid::text AS bssid, a.ssid, a.started, a.updated, a.stopped, a.terminate_cause,
                    a.session_time_s, a.interim_s, n.interim_s AS nas_interim_s
             FROM radius_acct a LEFT JOIN radius_nas n ON n.nas_ip = a.nas_ip
             WHERE a.device_id = d.id
             ORDER BY a.updated DESC LIMIT $2) s",
    )
    .bind(ids)
    .bind(limit(per_device, 100))
    .fetch_all(db.tx().await?)
    .await?;
    for r in rows {
        let id: Uuid = r.try_get("device_id")?;
        let session = <LatestSession as sqlx::FromRow<_>>::from_row(&r)?;
        result.entry(id).or_default().push(session);
    }
    Ok(result)
}

/// A recent UniFi event for the presence rules.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct LatestEvent {
    pub at: OffsetDateTime,
    pub kind: String,
    pub mac: String,
    pub ap_mac: Option<String>,
    pub ap_name: Option<String>,
}

/// `{device: events}`: the newest connected / disconnected / roamed events (of this SSID, or
/// without one, when given), newest first, at most `per_device` (cap 100) each; every requested
/// id is a key.
pub async fn latest_connection_events(
    db: &mut Db,
    ids: &[Uuid],
    per_device: i64,
    ssid: Option<&str>,
) -> Result<IndexMap<Uuid, Vec<LatestEvent>>> {
    let mut result = keyed(ids);
    if result.is_empty() {
        return Ok(result);
    }
    let rows = sqlx::query(
        "SELECT d.id AS device_id, e.*
         FROM unnest($1::uuid[]) AS d(id)
         CROSS JOIN LATERAL (
             SELECT c.at, c.kind, c.mac::text AS mac, c.ap_mac::text AS ap_mac, c.ap_name
             FROM connection_event c
             WHERE c.device_id = d.id AND c.kind IN ('connected', 'disconnected', 'roamed')
               AND ($2::text IS NULL OR c.ssid IS NULL OR c.ssid = $2)
             ORDER BY c.at DESC, c.id DESC LIMIT $3) e",
    )
    .bind(ids)
    .bind(ssid)
    .bind(limit(per_device, 100))
    .fetch_all(db.tx().await?)
    .await?;
    for r in rows {
        let id: Uuid = r.try_get("device_id")?;
        let event = <LatestEvent as sqlx::FromRow<_>>::from_row(&r)?;
        result.entry(id).or_default().push(event);
    }
    Ok(result)
}

// --- UniFi connection events ---------------------------------------------------------------------------

pub const EVENT_KINDS: [&str; 4] = ["connected", "disconnected", "roamed", "other"];

/// A stored connection event.
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct ConnectionEvent {
    pub at: OffsetDateTime,
    pub kind: String,
    pub source: String,
    pub mac: String,
    pub ap_mac: Option<String>,
    pub ap_name: Option<String>,
    pub from_ap_mac: Option<String>,
    pub from_ap_name: Option<String>,
    pub ssid: Option<String>,
    pub radio: Option<String>,
    pub channel: Option<i32>,
    pub rssi: Option<i32>,
    pub duration_s: Option<i64>,
    pub rx_bytes: Option<i64>,
    pub tx_bytes: Option<i64>,
    pub detail: Json<Value>,
}

/// The device's connection events in [since, until], oldest first (the newest `limit`).
pub async fn connection_events(
    db: &mut Db,
    device_id: Uuid,
    since: OffsetDateTime,
    until: OffsetDateTime,
    limit_rows: i64,
) -> Result<Vec<ConnectionEvent>> {
    let mut rows: Vec<ConnectionEvent> = sqlx::query_as(
        "SELECT at, kind, source, mac::text AS mac, ap_mac::text AS ap_mac, ap_name,
                from_ap_mac::text AS from_ap_mac, from_ap_name, ssid, radio, channel, rssi, duration_s,
                rx_bytes, tx_bytes, detail
         FROM connection_event WHERE device_id = $1 AND at BETWEEN $2 AND $3
         ORDER BY at DESC, id DESC LIMIT $4",
    )
    .bind(device_id)
    .bind(since)
    .bind(until)
    .bind(limit(limit_rows, 10_000))
    .fetch_all(db.tx().await?)
    .await?;
    rows.reverse();
    Ok(rows)
}

/// A connection event to store ([`insert_connection_events`]).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct NewConnectionEvent {
    pub at: Option<OffsetDateTime>,
    pub kind: String,
    /// empty: `unifi_syslog`
    pub source: String,
    pub mac: String,
    pub ap_mac: Option<String>,
    pub ap_name: Option<String>,
    pub from_ap_mac: Option<String>,
    pub from_ap_name: Option<String>,
    pub ssid: Option<String>,
    pub radio: Option<String>,
    pub channel: Option<i32>,
    pub rssi: Option<i32>,
    pub duration_s: Option<i64>,
    pub rx_bytes: Option<i64>,
    pub tx_bytes: Option<i64>,
    /// the raw fields not mapped (a JSON object; anything else is stored as `{}`)
    pub detail: Option<Value>,
    /// unique per source event (idempotent ingest); cut to 512 characters
    pub dedup_key: String,
    /// `None`: resolved by the MAC's window at the event's time
    pub device_id: Option<Uuid>,
}

/// Store connection events idempotently. Rows without a valid MAC, time or dedup key are
/// skipped; an unknown kind is stored as `other`; a repeated dedup key is ignored. A resolved
/// event extends its device's window (`device_mac.last_seen`). Returns the rows inserted; the
/// caller commits.
pub async fn insert_connection_events(db: &mut Db, rows: &[NewConnectionEvent]) -> Result<u64> {
    let mut inserted = 0;
    for row in rows {
        let (Some(mac), Some(at)) = (normalise_mac(&row.mac), row.at) else {
            continue;
        };
        if row.dedup_key.is_empty() {
            continue;
        }
        let kind = if EVENT_KINDS.contains(&row.kind.as_str()) { row.kind.as_str() } else { "other" };
        let source = if row.source.is_empty() { "unifi_syslog" } else { row.source.as_str() };
        let detail = match &row.detail {
            Some(Value::Object(map)) => Value::Object(map.clone()),
            _ => Value::Object(Default::default()),
        };
        let dedup_key: String = row.dedup_key.chars().take(512).collect();
        let device_id = match row.device_id {
            Some(id) => Some(id),
            None => device_for_mac(db, &mac, at).await?,
        };
        let done = sqlx::query(
            "INSERT INTO connection_event (at, kind, source, mac, ap_mac, ap_name, from_ap_mac, from_ap_name, ssid,
                                           radio, channel, rssi, duration_s, rx_bytes, tx_bytes, detail, dedup_key,
                                           device_id)
             VALUES ($1, $2, $3, $4::macaddr, $5::macaddr, $6, $7::macaddr, $8, $9, $10, $11, $12, $13, $14, $15,
                     $16, $17, $18)
             ON CONFLICT (dedup_key) DO NOTHING",
        )
        .bind(at)
        .bind(kind)
        .bind(source)
        .bind(&mac)
        .bind(row.ap_mac.as_deref().and_then(normalise_mac))
        .bind(&row.ap_name)
        .bind(row.from_ap_mac.as_deref().and_then(normalise_mac))
        .bind(&row.from_ap_name)
        .bind(&row.ssid)
        .bind(&row.radio)
        .bind(row.channel)
        .bind(row.rssi)
        .bind(row.duration_s)
        .bind(row.rx_bytes)
        .bind(row.tx_bytes)
        .bind(Json(detail))
        .bind(dedup_key)
        .bind(device_id)
        .execute(db.tx().await?)
        .await?
        .rows_affected();
        if done > 0 {
            inserted += 1;
            if let Some(id) = device_id {
                sqlx::query(
                    "UPDATE device_mac SET last_seen = greatest(last_seen, $1)
                     WHERE device_id = $2 AND mac = $3::macaddr",
                )
                .bind(at)
                .bind(id)
                .bind(&mac)
                .execute(db.tx().await?)
                .await?;
            }
        }
    }
    Ok(inserted)
}

// --- rollups -----------------------------------------------------------------------------------------

/// One device and house day (the collector's rollup writes complete rows).
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct DeviceDay {
    pub device_id: Uuid,
    pub day: Date,
    pub online_s: Option<i32>,
    pub stale_s: Option<i32>,
    pub signal_avg_dbm: Option<f64>,
    pub signal_p10_dbm: Option<f64>,
    pub snr_avg_db: Option<f64>,
    pub health_avg: Option<f64>,
    pub health_min: Option<f64>,
    pub retry_ratio_avg: Option<f64>,
    pub rx_bytes: Option<i64>,
    pub tx_bytes: Option<i64>,
    pub link_rx_avg_bps: Option<f64>,
    pub roams: Option<i32>,
    pub reconnects: Option<i32>,
    pub disconnects: Option<i32>,
    /// `{ap_mac: seconds}`
    pub aps: Json<Value>,
    /// `{"2.4"|"5"|"6": seconds}`
    pub bands: Json<Value>,
    pub macs: Option<i32>,
    pub auth_ok: Option<i32>,
    pub auth_failed: Option<i32>,
    /// set by the database (ignored when writing)
    pub computed_at: Option<OffsetDateTime>,
}

/// One access point (by MAC) and house day.
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct ApDay {
    pub ap_mac: String,
    pub day: Date,
    pub ap_name: Option<String>,
    pub clients_avg: Option<f64>,
    pub clients_max: Option<i32>,
    /// `{radio: ratio}`
    pub channel_util_avg: Json<Value>,
    pub weak_client_share: Option<f64>,
    pub restarts: Option<i32>,
    pub down_s: Option<i32>,
    /// set by the database (ignored when writing)
    pub computed_at: Option<OffsetDateTime>,
}

fn object(value: &Json<Value>) -> Json<Value> {
    match &value.0 {
        Value::Object(_) => value.clone(),
        _ => Json(Value::Object(Default::default())),
    }
}

/// Store a device's day (replacing an earlier computation of it); idempotent.
pub async fn upsert_device_day(db: &mut Db, row: &DeviceDay) -> Result<()> {
    sqlx::query(
        "INSERT INTO device_day (device_id, day, online_s, stale_s, signal_avg_dbm, signal_p10_dbm, snr_avg_db,
                                 health_avg, health_min, retry_ratio_avg, rx_bytes, tx_bytes, link_rx_avg_bps,
                                 roams, reconnects, disconnects, aps, bands, macs, auth_ok, auth_failed)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)
         ON CONFLICT (device_id, day) DO UPDATE SET
             online_s = EXCLUDED.online_s, stale_s = EXCLUDED.stale_s, signal_avg_dbm = EXCLUDED.signal_avg_dbm,
             signal_p10_dbm = EXCLUDED.signal_p10_dbm, snr_avg_db = EXCLUDED.snr_avg_db,
             health_avg = EXCLUDED.health_avg, health_min = EXCLUDED.health_min,
             retry_ratio_avg = EXCLUDED.retry_ratio_avg, rx_bytes = EXCLUDED.rx_bytes, tx_bytes = EXCLUDED.tx_bytes,
             link_rx_avg_bps = EXCLUDED.link_rx_avg_bps, roams = EXCLUDED.roams, reconnects = EXCLUDED.reconnects,
             disconnects = EXCLUDED.disconnects, aps = EXCLUDED.aps, bands = EXCLUDED.bands, macs = EXCLUDED.macs,
             auth_ok = EXCLUDED.auth_ok, auth_failed = EXCLUDED.auth_failed, computed_at = now()",
    )
    .bind(row.device_id)
    .bind(row.day)
    .bind(row.online_s)
    .bind(row.stale_s)
    .bind(row.signal_avg_dbm)
    .bind(row.signal_p10_dbm)
    .bind(row.snr_avg_db)
    .bind(row.health_avg)
    .bind(row.health_min)
    .bind(row.retry_ratio_avg)
    .bind(row.rx_bytes)
    .bind(row.tx_bytes)
    .bind(row.link_rx_avg_bps)
    .bind(row.roams)
    .bind(row.reconnects)
    .bind(row.disconnects)
    .bind(object(&row.aps))
    .bind(object(&row.bands))
    .bind(row.macs)
    .bind(row.auth_ok)
    .bind(row.auth_failed)
    .execute(db.tx().await?)
    .await?;
    Ok(())
}

/// Store an access point's day (replacing an earlier computation); the AP MAC in any form.
pub async fn upsert_ap_day(db: &mut Db, row: &ApDay) -> Result<()> {
    let Some(mac) = normalise_mac(&row.ap_mac) else {
        return Err(RegistryError::Invalid(format!("ap_day: invalid ap_mac {:?}", row.ap_mac)));
    };
    sqlx::query(
        "INSERT INTO ap_day (ap_mac, day, ap_name, clients_avg, clients_max, channel_util_avg, weak_client_share,
                             restarts, down_s)
         VALUES ($1::macaddr, $2, $3, $4, $5, $6, $7, $8, $9)
         ON CONFLICT (ap_mac, day) DO UPDATE SET
             ap_name = EXCLUDED.ap_name, clients_avg = EXCLUDED.clients_avg, clients_max = EXCLUDED.clients_max,
             channel_util_avg = EXCLUDED.channel_util_avg, weak_client_share = EXCLUDED.weak_client_share,
             restarts = EXCLUDED.restarts, down_s = EXCLUDED.down_s, computed_at = now()",
    )
    .bind(mac)
    .bind(row.day)
    .bind(&row.ap_name)
    .bind(row.clients_avg)
    .bind(row.clients_max)
    .bind(object(&row.channel_util_avg))
    .bind(row.weak_client_share)
    .bind(row.restarts)
    .bind(row.down_s)
    .execute(db.tx().await?)
    .await?;
    Ok(())
}

/// The device's days since_day..=until_day, by day.
pub async fn device_days(db: &mut Db, device_id: Uuid, since_day: Date, until_day: Date) -> Result<Vec<DeviceDay>> {
    Ok(sqlx::query_as("SELECT * FROM device_day WHERE device_id = $1 AND day BETWEEN $2 AND $3 ORDER BY day")
        .bind(device_id)
        .bind(since_day)
        .bind(until_day)
        .fetch_all(db.tx().await?)
        .await?)
}

/// Access point days since_day..=until_day of the given AP MACs (any form; `None`: all), by day
/// and AP.
pub async fn ap_days(db: &mut Db, since_day: Date, until_day: Date, ap_macs: Option<&[&str]>) -> Result<Vec<ApDay>> {
    let macs: Option<Vec<String>> = ap_macs.map(|m| m.iter().filter_map(|m| normalise_mac(m)).collect());
    Ok(sqlx::query_as(
        "SELECT ap_mac::text AS ap_mac, day, ap_name, clients_avg, clients_max, channel_util_avg, weak_client_share,
                restarts, down_s, computed_at
         FROM ap_day
         WHERE day BETWEEN $1 AND $2 AND ($3::macaddr[] IS NULL OR ap_mac = ANY($3::macaddr[]))
         ORDER BY day, ap_mac",
    )
    .bind(since_day)
    .bind(until_day)
    .bind(macs)
    .fetch_all(db.tx().await?)
    .await?)
}

// --- incidents ---------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct Incident {
    pub id: i64,
    pub kind: String,
    pub subject: String,
    pub subject_name: Option<String>,
    pub started: OffsetDateTime,
    pub ended: Option<OffsetDateTime>,
    pub basis: String,
    pub detail: Json<Value>,
}

/// Incidents overlapping [since, until] (until `None`: no upper bound; open ones overlap
/// everything after their start), of these kinds / subjects (`None`: any; an empty list: none),
/// by start.
pub async fn incidents(
    db: &mut Db,
    since: OffsetDateTime,
    until: Option<OffsetDateTime>,
    kinds: Option<&[&str]>,
    subjects: Option<&[&str]>,
) -> Result<Vec<Incident>> {
    Ok(sqlx::query_as(
        "SELECT id, kind, subject, subject_name, started, ended, basis, detail FROM incident
         WHERE ($2::timestamptz IS NULL OR started <= $2) AND (ended IS NULL OR ended >= $1)
           AND ($3::text[] IS NULL OR kind = ANY($3)) AND ($4::text[] IS NULL OR subject = ANY($4))
         ORDER BY started, id",
    )
    .bind(since)
    .bind(until)
    .bind(kinds)
    .bind(subjects)
    .fetch_all(db.tx().await?)
    .await?)
}

/// Open an incident (or find it) and return its id. Idempotent: an open incident of the same
/// kind and subject is returned (one open per kind and subject), as is one with the same start
/// (closed or not); the name and detail of a found one are refreshed (a `None` name and an empty
/// detail keep the stored ones).
pub async fn open_incident(
    db: &mut Db,
    kind: &str,
    subject: &str,
    subject_name: Option<&str>,
    started: OffsetDateTime,
    basis: &str,
    detail: Option<&Value>,
) -> Result<i64> {
    let detail = match detail {
        Some(Value::Object(map)) => Value::Object(map.clone()),
        _ => Value::Object(Default::default()),
    };
    // two rounds: a concurrent opener may win the race, then its row is found
    for _ in 0..2 {
        let found: Option<i64> = sqlx::query_scalar(
            "SELECT id FROM incident WHERE kind = $1 AND subject = $2 AND (ended IS NULL OR started = $3)
             ORDER BY (ended IS NULL) DESC LIMIT 1",
        )
        .bind(kind)
        .bind(subject)
        .bind(started)
        .fetch_optional(db.tx().await?)
        .await?;
        if let Some(id) = found {
            sqlx::query(
                "UPDATE incident SET subject_name = coalesce($2, subject_name),
                                     detail = CASE WHEN $3 = '{}'::jsonb THEN detail ELSE $3 END
                 WHERE id = $1",
            )
            .bind(id)
            .bind(subject_name)
            .bind(Json(&detail))
            .execute(db.tx().await?)
            .await?;
            return Ok(id);
        }
        let inserted: Option<i64> = sqlx::query_scalar(
            "INSERT INTO incident (kind, subject, subject_name, started, basis, detail)
             VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING RETURNING id",
        )
        .bind(kind)
        .bind(subject)
        .bind(subject_name)
        .bind(started)
        .bind(basis)
        .bind(Json(&detail))
        .fetch_optional(db.tx().await?)
        .await?;
        if let Some(id) = inserted {
            return Ok(id);
        }
    }
    Err(RegistryError::Conflict(format!("incident {kind}/{subject}: neither found nor inserted")))
}

/// End the open incident of this kind and subject (not before its start); returns how many
/// were closed (0 or 1).
pub async fn close_incident(db: &mut Db, kind: &str, subject: &str, ended: OffsetDateTime) -> Result<u64> {
    Ok(sqlx::query(
        "UPDATE incident SET ended = greatest(started, $3) WHERE kind = $1 AND subject = $2 AND ended IS NULL",
    )
    .bind(kind)
    .bind(subject)
    .bind(ended)
    .execute(db.tx().await?)
    .await?
    .rows_affected())
}

// --- jobs and monitoring --------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct JobStatus {
    pub name: String,
    pub last_success: Option<OffsetDateTime>,
    pub last_attempt: Option<OffsetDateTime>,
    pub last_error: Option<String>,
    pub duration_s: Option<f64>,
    pub cursor: Json<Value>,
}

/// A job succeeded now (the offboarding).
pub async fn mark_job(db: &mut Db, name: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO job (name, last_success, last_attempt) VALUES ($1, now(), now())
         ON CONFLICT (name) DO UPDATE SET last_success = now(), last_attempt = now(), last_error = NULL",
    )
    .bind(name)
    .execute(db.tx().await?)
    .await?;
    Ok(())
}

/// A job run starts: last_attempt = now (the row is created for a new job).
pub async fn job_begin(db: &mut Db, name: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO job (name, last_attempt) VALUES ($1, now()) ON CONFLICT (name) DO UPDATE SET last_attempt = now()",
    )
    .bind(name)
    .execute(db.tx().await?)
    .await?;
    Ok(())
}

/// A job run ended: `ok` sets last_success and clears last_error, otherwise last_error (cut to
/// 2000 characters) is set; duration and cursor (a JSON object, replacing the stored one) when
/// given.
pub async fn job_end(
    db: &mut Db,
    name: &str,
    ok: bool,
    error: Option<&str>,
    duration_s: Option<f64>,
    cursor: Option<&Value>,
) -> Result<()> {
    let error: Option<String> =
        (!ok).then(|| error.filter(|e| !e.is_empty()).unwrap_or("failed").chars().take(2000).collect());
    let cursor = cursor.and_then(|c| c.is_object().then(|| Json(c.clone())));
    sqlx::query(
        "INSERT INTO job (name, last_attempt, last_success, last_error, duration_s, cursor)
         VALUES ($1, now(), CASE WHEN $2 THEN now() END, $3, $4, coalesce($5, '{}'::jsonb))
         ON CONFLICT (name) DO UPDATE SET
             last_success = CASE WHEN $2 THEN now() ELSE job.last_success END,
             last_error = $3,
             duration_s = coalesce($4, job.duration_s),
             cursor = coalesce($5, job.cursor)",
    )
    .bind(name)
    .bind(ok)
    .bind(error)
    .bind(duration_s.filter(|d| d.is_finite() && *d >= 0.0))
    .bind(cursor)
    .execute(db.tx().await?)
    .await?;
    Ok(())
}

/// Every job's state, by name.
pub async fn job_status(db: &mut Db) -> Result<Vec<JobStatus>> {
    Ok(sqlx::query_as("SELECT name, last_success, last_attempt, last_error, duration_s, cursor FROM job ORDER BY name")
        .fetch_all(db.tx().await?)
        .await?)
}

/// The job's stored cursor (`{}` for a job without one, `None` for an unknown job).
pub async fn job_cursor(db: &mut Db, name: &str) -> Result<Option<Value>> {
    let cursor: Option<Json<Value>> =
        sqlx::query_scalar("SELECT cursor FROM job WHERE name = $1").bind(name).fetch_optional(db.tx().await?).await?;
    Ok(cursor.map(|c| c.0))
}

/// Disconnect results counted for `/metrics` (`audit.action = 'disconnect:<result>'`).
pub const DISCONNECT_RESULTS: [&str; 7] = ["ack", "no-session", "skipped", "timeout", "nak", "not-found", "error"];

/// Counts for `/metrics`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stats {
    pub active: i64,
    pub revoked: i64,
    /// devices with a certificate RADIUS accepts now (a device in its renewal overlap counts
    /// once, like `expiring_30d` and `expired`)
    pub valid_certificates: i64,
    pub expiring_30d: i64,
    pub expired: i64,
    pub offboarding_last_success: Option<OffsetDateTime>,
    pub radius_role: bool,
    pub schema_version: Option<i64>,
    /// per result of [`DISCONNECT_RESULTS`], in that order
    pub disconnects_1h: Vec<(&'static str, i64)>,
}

/// Counts for `/metrics`, from the registry (also what the offboarding sidecar did).
pub async fn stats(db: &mut Db) -> Result<Stats> {
    let conn = db.tx().await?;
    let row = sqlx::query(
        "SELECT
            (SELECT count(*) FROM device WHERE revoked_at IS NULL) AS active,
            (SELECT count(*) FROM device WHERE revoked_at IS NOT NULL) AS revoked,
            (SELECT count(DISTINCT device_id) FROM radius.valid_cert) AS valid_certificates,
            (SELECT count(DISTINCT c.device_id) FROM credential c JOIN device d ON d.id = c.device_id
               WHERE d.revoked_at IS NULL AND c.retired_at IS NULL
                 AND c.not_after BETWEEN now() AND now() + interval '30 days') AS expiring_30d,
            (SELECT count(DISTINCT c.device_id) FROM credential c JOIN device d ON d.id = c.device_id
               WHERE d.revoked_at IS NULL AND c.retired_at IS NULL AND c.not_after <= now()) AS expired,
            (SELECT last_success FROM job WHERE name = 'offboarding') AS offboarding_last_success,
            EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'radius') AS radius_role,
            (SELECT max(version) FROM _sqlx_migrations WHERE success) AS schema_version",
    )
    .fetch_one(&mut *conn)
    .await?;
    let recent: Vec<(String, i64)> = sqlx::query_as(
        "SELECT action, count(*) FROM audit
         WHERE action LIKE 'disconnect:%' AND at > now() - interval '1 hour' GROUP BY action",
    )
    .fetch_all(&mut *conn)
    .await?;
    let recent: BTreeMap<String, i64> = recent.into_iter().collect();
    Ok(Stats {
        active: row.try_get("active")?,
        revoked: row.try_get("revoked")?,
        valid_certificates: row.try_get("valid_certificates")?,
        expiring_30d: row.try_get("expiring_30d")?,
        expired: row.try_get("expired")?,
        offboarding_last_success: row.try_get("offboarding_last_success")?,
        radius_role: row.try_get("radius_role")?,
        schema_version: row.try_get("schema_version")?,
        disconnects_1h: DISCONNECT_RESULTS
            .iter()
            .map(|r| (*r, recent.get(&format!("disconnect:{r}")).copied().unwrap_or(0)))
            .collect(),
    })
}

/// The normaliser's cases (Python tests/test_registry.py MAC_CASES), shared by the unit test and
/// the SQL twin's test (tests/registry_db.rs): input, expected result.
pub const MAC_CASES: &[(&str, Option<&str>)] = &[
    ("AA-BB-CC-DD-EE-FF", Some("aa:bb:cc:dd:ee:ff")),
    ("aa:bb:cc:dd:ee:ff", Some("aa:bb:cc:dd:ee:ff")),
    ("AABBCCDDEEFF", Some("aa:bb:cc:dd:ee:ff")),
    ("  aa-bb-cc-dd-ee-0f\n", Some("aa:bb:cc:dd:ee:0f")),
    ("\tAABBCCDDEE01 ", Some("aa:bb:cc:dd:ee:01")),
    ("aa:bb-cc:dd:ee:ff", None),
    ("aabb.ccdd.eeff", None),
    ("aa:bb:cc:dd:ee", None),
    ("aa:bb:cc:dd:ee:ff:00", None),
    ("gg:bb:cc:dd:ee:ff", None),
    ("aabbccddeef", None),
    ("", None),
    ("anonymous@scharni.org", None),
    ("aa bb cc dd ee ff", None),
    ("a:b:c:d:e:f", None),
    ("AA:BB:CC:DD:EE:FF;DROP", None),
    ("\u{a0}aa:bb:cc:dd:ee:ff", None),
    ("aa:bb:cc:dd:ee:f\u{e9}", None),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalise_mac_cases() {
        for (raw, expected) in MAC_CASES {
            assert_eq!(normalise_mac(raw).as_deref(), *expected, "{raw:?}");
        }
    }

    #[test]
    fn test_randomized() {
        assert!(is_randomized("02:00:00:00:00:01"));
        assert!(is_randomized("aa:bb:cc:dd:ee:ff")); // 0xaa has the bit
        assert!(!is_randomized("a4:83:e7:00:00:01"));
        assert!(!is_randomized("x"));
    }

    #[test]
    fn test_tokens() {
        let token = new_token();
        assert_eq!(token.len(), 43);
        assert!(token.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
        assert_ne!(token, new_token());
        assert_eq!(token_hash("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn test_migration_files() {
        let names: Vec<(i64, &str)> = MIGRATOR.iter().map(|m| (m.version, m.description.as_ref())).collect();
        assert_eq!(
            names,
            [
                (1, "registry"),
                (2, "radius contract"),
                (3, "session epoch"),
                (4, "security review"),
                (5, "sessions and rechecks"),
                (6, "iot")
            ]
        );
        // every file in migrations is embedded (a new file needs a rebuild, not a code change)
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../migrations");
        let mut files: Vec<String> = std::fs::read_dir(dir)
            .map(|d| d.filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().to_string()).collect())
            .unwrap_or_default();
        files.sort();
        assert_eq!(
            files,
            [
                "0001_registry.sql",
                "0002_radius_contract.sql",
                "0003_session_epoch.sql",
                "0004_security_review.sql",
                "0005_sessions_and_rechecks.sql",
                "0006_iot.sql"
            ]
        );
    }

    #[test]
    fn test_contract_functions_are_hardened() {
        let sql = MIGRATOR.iter().find(|m| m.version == 2).map(|m| m.sql.as_ref()).unwrap_or("");
        let v5 = MIGRATOR.iter().find(|m| m.version == 5).map(|m| m.sql.as_ref()).unwrap_or("");
        for (name, sql) in [
            ("radius.login", sql),
            ("radius.reject", sql),
            ("radius.accounting", sql),
            ("radius.cert_status", sql),
            ("radius.login", v5),
        ] {
            let head = sql.split(&format!("CREATE FUNCTION {name}(")).nth(1).unwrap_or("");
            let head = head.split(" AS $$").next().unwrap_or("");
            assert!(head.contains("SECURITY DEFINER"), "{name}");
            assert!(head.contains("SET search_path = public, pg_temp"), "{name}");
        }
        assert!(RADIUS_GRANTS_SQL.contains("REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC"));
    }
}
