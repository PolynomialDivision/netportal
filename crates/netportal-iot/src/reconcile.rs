//! One reconciliation round (house-infra docs/IOT-ACCESS.md 6.4): the IoT offboarding, the
//! desired state ([`crate::desired`]) against what UniFi and OPNsense have, the differences
//! applied, `iot_sync` and the audit written, the job row `iot`.
//!
//! Idempotent: a round with nothing to do calls no writing endpoint (the integration test
//! proves it with fake servers). A failed backend call fails that target's `iot_sync` rows,
//! not the round: the round reports (`unifi_ok`, `opnsense_ok` in the job cursor) and goes on;
//! only a registry error fails the round.
//!
//! Order of a round:
//! 1. offboarding: persons with `offboarded_at` lose every share they hold or gave
//!    (`iot::drop_shares_of`) and their home devices are revoked (the offboarding sidecar does
//!    that too; this catches what it missed);
//! 2. the registry rows, the DHCP leases and the interfaces, the desired state;
//! 3. UniFi: the SSID's keys set to exactly the unrevoked devices' (one `PUT`), revoked devices'
//!    MACs blocked and kicked once, MACs blocked for devices that are gone unblocked;
//! 4. OPNsense: alias objects made, their contents brought to the desired addresses
//!    (`alias_util`, live), rules made/updated/removed and applied, the states of pairs whose
//!    access went away since the last round killed, stale alias objects removed;
//! 5. housekeeping: stale `iot_sync` rows, old join attempts.
//!
//! The "previous" alias contents (for the state kills) are read back from OPNsense on a full
//! round (every `NETPORTAL_IOT_READBACK_S`, and the first round), else taken from the previous
//! round's result ([`Memory`]).

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use netportal_core::Db;
use netportal_core::config::IotSettings;
use netportal_core::iot::{self, IotDevice};
use netportal_core::registry::{self, RegistryError, normalise_mac};
use serde_json::{Value, json};
use sqlx::{Executor, Row};
use uuid::Uuid;

use crate::desired::{self, Cidr, Desired, Lease, Names, device_hash};
use crate::opnsense::{AliasRow, OpnsenseClient, OpnsenseError, RuleRow};
use crate::unifi::{Ppsk, UnifiClient, UnifiError};

const LOG: &str = "netportal.iot";

/// The job name in the registry (`job.name`; the web's `/metrics` reads its cursor).
pub const JOB: &str = "iot";
/// The actor of the round's audit rows.
pub const ACTOR: &str = "iot";
/// `pg_try_advisory_lock(hashtext(LOCK_KEY))`: two controllers never reconcile at once.
pub const LOCK_KEY: &str = "netportal-iot";
const STATEMENT_TIMEOUT: &str = "SET statement_timeout = '60s'";
const LOCK_TIMEOUT: &str = "SET lock_timeout = '10s'";
/// An accounting session without an update for longer no longer says where a MAC is (the
/// interim interval is 5 minutes; the portal's rule is two of them plus a minute).
const SESSION_FRESH_MINUTES: i32 = 15;
/// `iot_sync.detail` holds at most this many characters.
const DETAIL_CHARS: usize = 500;

/// A failed round, or a reason the controller cannot start.
#[derive(Debug, thiserror::Error)]
pub enum IotError {
    #[error("{0}")]
    Registry(RegistryError),
    /// Another process holds the controller's lock.
    #[error("another iot round is running")]
    Locked,
    #[error("{0}")]
    Unifi(UnifiError),
    #[error("{0}")]
    Opnsense(OpnsenseError),
    #[error("{0}")]
    Config(String),
    #[error("heartbeat {path}: {error}")]
    Heartbeat { path: String, error: std::io::Error },
    #[error("signal handler: {0}")]
    Signal(std::io::Error),
}

impl From<RegistryError> for IotError {
    fn from(e: RegistryError) -> Self {
        IotError::Registry(e)
    }
}

impl From<sqlx::Error> for IotError {
    fn from(e: sqlx::Error) -> Self {
        IotError::Registry(RegistryError::Db(e))
    }
}

impl From<UnifiError> for IotError {
    fn from(e: UnifiError) -> Self {
        IotError::Unifi(e)
    }
}

impl From<OpnsenseError> for IotError {
    fn from(e: OpnsenseError) -> Self {
        IotError::Opnsense(e)
    }
}

/// The backends of a round; `None`: not configured (its rows stay pending).
#[derive(Debug, Clone, Copy, Default)]
pub struct Backends<'a> {
    pub unifi: Option<&'a UnifiClient>,
    pub opnsense: Option<&'a OpnsenseClient>,
}

/// What the controller keeps between rounds.
#[derive(Debug, Default)]
pub struct Memory {
    /// when OPNsense was last read back whole
    pub last_full: Option<Instant>,
    /// the alias contents as the previous round left them (the cheaper rounds' "previous")
    pub alias_contents: Option<BTreeMap<String, BTreeSet<String>>>,
}

/// What a round did and found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoundReport {
    /// unrevoked home devices
    pub devices: usize,
    pub shares: usize,
    pub sync_pending: usize,
    pub sync_failed: usize,
    pub address_conflicts: usize,
    /// every UniFi call of the round succeeded (false when not configured)
    pub unifi_ok: bool,
    pub opnsense_ok: bool,
    /// the SSID's keys were written
    pub keys_written: bool,
    pub blocked: usize,
    pub kicked: usize,
    pub unblocked: usize,
    /// alias objects or contents changed
    pub aliases_changed: usize,
    pub rules_changed: usize,
    pub states_killed: usize,
    pub shares_dropped: u64,
    pub devices_revoked: usize,
    pub join_attempts_pruned: u64,
}

impl RoundReport {
    /// The job cursor the web's `/metrics` reads (exactly these keys).
    pub fn cursor(&self) -> Value {
        json!({
            "devices": self.devices,
            "shares": self.shares,
            "sync_pending": self.sync_pending,
            "sync_failed": self.sync_failed,
            "address_conflicts": self.address_conflicts,
            "unifi_ok": u8::from(self.unifi_ok),
            "opnsense_ok": u8::from(self.opnsense_ok),
        })
    }

    /// Whether anything was written to a backend.
    pub fn wrote(&self) -> bool {
        self.keys_written
            || self.blocked
                + self.kicked
                + self.unblocked
                + self.aliases_changed
                + self.rules_changed
                + self.states_killed
                > 0
    }
}

// --- the sync rows ----------------------------------------------------------------------------------

/// The `iot_sync` rows: written only when they change, so a round with nothing to do leaves
/// the table alone; rows neither touched nor expected are removed at the end.
struct Sync {
    existing: BTreeMap<(String, String), (String, String)>,
    touched: BTreeSet<(String, String)>,
}

fn cut(detail: &str) -> String {
    detail.chars().take(DETAIL_CHARS).collect()
}

impl Sync {
    async fn load(db: &mut Db) -> Result<Sync, IotError> {
        let rows = iot::sync_states(db).await?;
        Ok(Sync {
            existing: rows.into_iter().map(|r| ((r.target, r.key), (r.status, r.detail))).collect(),
            touched: BTreeSet::new(),
        })
    }

    async fn set(&mut self, db: &mut Db, target: &str, key: &str, status: &str, detail: &str) -> Result<(), IotError> {
        let id = (target.to_string(), key.to_string());
        let value = (status.to_string(), cut(detail));
        self.touched.insert(id.clone());
        if self.existing.get(&id) == Some(&value) {
            return Ok(());
        }
        iot::set_sync(db, target, key, status, &value.1).await?;
        self.existing.insert(id, value);
        Ok(())
    }

    /// The detail of a row, if there is one.
    fn detail_of(&self, target: &str, key: &str) -> Option<&str> {
        self.existing.get(&(target.to_string(), key.to_string())).map(|(_, detail)| detail.as_str())
    }

    /// Rows of a target, as `(key, detail)`.
    fn rows_of(&self, target: &str) -> Vec<(String, String)> {
        self.existing
            .iter()
            .filter(|((t, _), _)| t == target)
            .map(|((_, k), (_, detail))| (k.clone(), detail.clone()))
            .collect()
    }

    /// Remove the rows neither touched this round nor in `keep`.
    async fn prune(&mut self, db: &mut Db, keep: &BTreeSet<(String, String)>) -> Result<usize, IotError> {
        let stale: Vec<(String, String)> =
            self.existing.keys().filter(|id| !self.touched.contains(*id) && !keep.contains(*id)).cloned().collect();
        for (target, key) in &stale {
            iot::clear_sync(db, target, key).await?;
            self.existing.remove(&(target.clone(), key.clone()));
        }
        Ok(stale.len())
    }
}

// --- the registry side ---------------------------------------------------------------------------------

/// The IoT part of the offboarding: persons marked `offboarded_at` lose their shares and their
/// home devices are revoked (the controller's next steps then remove keys, block, kick and
/// drop aliases and rules like for any revoked device).
async fn offboard(db: &mut Db, report: &mut RoundReport) -> Result<(), IotError> {
    let subs: Vec<String> = sqlx::query_scalar(
        "SELECT p.sub FROM person p
         WHERE p.offboarded_at IS NOT NULL
           AND EXISTS (SELECT 1 FROM iot_share s WHERE s.grantee = p.sub OR s.granted_by = p.sub)
         ORDER BY p.sub",
    )
    .fetch_all(db.tx().await?)
    .await?;
    for sub in subs {
        let dropped = iot::drop_shares_of(db, &sub).await?;
        registry::audit(db, ACTOR, &format!("iot:shares-dropped:{sub}"), None).await?;
        report.shares_dropped += dropped;
        tracing::info!(target: LOG, "{sub} is offboarded: {dropped} share(s) dropped");
    }
    let devices: Vec<Uuid> = sqlx::query_scalar(
        "SELECT d.id FROM device d JOIN person p ON p.sub = d.owner
         WHERE d.kind = 'iot' AND d.revoked_at IS NULL AND p.offboarded_at IS NOT NULL ORDER BY d.id",
    )
    .fetch_all(db.tx().await?)
    .await?;
    for id in devices {
        // the sessions are not needed: an IoT device is cut by UniFi (kick), not by Disconnect
        registry::revoke(db, id, ACTOR, "revoke").await?;
        report.devices_revoked += 1;
        tracing::info!(target: LOG, "home device {id} of an offboarded person revoked");
    }
    db.commit().await?;
    Ok(())
}

/// `(mac, framed_ip)` of the open accounting sessions updated lately.
async fn open_sessions(db: &mut Db) -> Result<Vec<(String, String)>, IotError> {
    let rows = sqlx::query(
        "SELECT mac::text AS mac, host(framed_ip) AS ip FROM radius_acct
         WHERE stopped IS NULL AND mac IS NOT NULL AND framed_ip IS NOT NULL
           AND updated > now() - make_interval(mins => $1)",
    )
    .bind(SESSION_FRESH_MINUTES)
    .fetch_all(db.tx().await?)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        out.push((r.try_get::<String, _>("mac")?, r.try_get::<String, _>("ip")?));
    }
    Ok(out)
}

async fn count_shares(db: &mut Db) -> Result<usize, IotError> {
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM iot_share").fetch_one(db.tx().await?).await?;
    Ok(usize::try_from(n).unwrap_or(0))
}

// --- UniFi ---------------------------------------------------------------------------------------------

struct UnifiView {
    network_id: String,
    wlan: crate::unifi::Wlan,
    blocked: BTreeSet<String>,
    connected: BTreeSet<String>,
}

async fn read_unifi(unifi: &UnifiClient, settings: &IotSettings) -> Result<UnifiView, UnifiError> {
    unifi.login().await?;
    let network_id = unifi.network_id(&settings.unifi_iot_network).await?;
    let wlan = unifi.wlan(&settings.unifi_iot_ssid).await?;
    let blocked = unifi.blocked().await?.into_iter().collect();
    let connected = unifi.clients().await?.into_iter().map(|c| c.mac).collect();
    Ok(UnifiView { network_id, wlan, blocked, connected })
}

/// The UniFi part of a round; returns whether every call succeeded.
async fn apply_unifi(
    db: &mut Db,
    settings: &IotSettings,
    unifi: &UnifiClient,
    desired: &Desired,
    devices: &[IotDevice],
    sync: &mut Sync,
    report: &mut RoundReport,
) -> Result<bool, IotError> {
    let key_ids: Vec<Uuid> = desired.keys.iter().map(|(id, _)| *id).collect();
    let view = match read_unifi(unifi, settings).await {
        Ok(view) => view,
        Err(e) => {
            tracing::error!(target: LOG, "{e}");
            let detail = e.to_string();
            for id in &key_ids {
                sync.set(db, "unifi_key", &id.to_string(), "failed", &detail).await?;
            }
            for id in desired.blocked.values() {
                sync.set(db, "unifi_block", &id.to_string(), "failed", &detail).await?;
            }
            if unifi.logged_in() {
                unifi.logout().await;
            }
            return Ok(false);
        }
    };
    let mut ok = true;

    // the keys: exactly the unrevoked devices', each mapped to the IoT network
    let wanted: Vec<Ppsk> = desired
        .keys
        .iter()
        .map(|(_, psk)| Ppsk { password: psk.clone(), networkconf_id: view.network_id.clone() })
        .collect();
    let wanted_set: BTreeSet<&Ppsk> = wanted.iter().collect();
    let current_set: BTreeSet<&Ppsk> = view.wlan.private_preshared_keys.iter().collect();
    let current_passwords: BTreeSet<&str> =
        view.wlan.private_preshared_keys.iter().map(|k| k.password.as_str()).collect();
    let revoked_with_key: Vec<&IotDevice> =
        devices.iter().filter(|d| d.revoked_at.is_some() && current_passwords.contains(d.psk.as_str())).collect();
    // PPSK on exactly while there are keys (UniFi refuses "on" with none)
    if wanted_set != current_set || view.wlan.private_preshared_keys_enabled != !wanted.is_empty() {
        match unifi.set_ppsk(&view.wlan.id, &wanted).await {
            Ok(()) => {
                report.keys_written = true;
                tracing::info!(target: LOG, "UniFi: {} key(s) set on {}", wanted.len(), settings.unifi_iot_ssid);
                for (id, psk) in &desired.keys {
                    if !current_passwords.contains(psk.as_str()) {
                        registry::audit(db, ACTOR, "iot:unifi-key", Some(*id)).await?;
                    }
                    sync.set(db, "unifi_key", &id.to_string(), "applied", "key in the SSID").await?;
                }
                for d in &revoked_with_key {
                    registry::audit(db, ACTOR, "iot:unifi-key-removed", Some(d.id)).await?;
                }
            }
            Err(e) => {
                ok = false;
                tracing::error!(target: LOG, "{e}");
                let detail = e.to_string();
                for id in &key_ids {
                    sync.set(db, "unifi_key", &id.to_string(), "failed", &detail).await?;
                }
                for d in &revoked_with_key {
                    sync.set(db, "unifi_key", &d.id.to_string(), "failed", &format!("key not removed: {detail}"))
                        .await?;
                }
            }
        }
    } else {
        for id in &key_ids {
            sync.set(db, "unifi_key", &id.to_string(), "applied", "key in the SSID").await?;
        }
    }
    for id in &desired.keys_over_cap {
        let detail = format!("no key: over NETPORTAL_IOT_MAX_KEYS ({})", settings.max_keys);
        sync.set(db, "unifi_key", &id.to_string(), "pending", &detail).await?;
    }

    // revoked devices: blocked, and kicked once (again while they still show as connected)
    for (mac, id) in &desired.blocked {
        if view.blocked.contains(mac) {
            if view.connected.contains(mac) {
                match unifi.kick(mac).await {
                    Ok(()) => {
                        registry::audit(db, ACTOR, "iot:kick", Some(*id)).await?;
                        report.kicked += 1;
                    }
                    Err(e) => tracing::warn!(target: LOG, "{e}"),
                }
            }
            // the row stays as the block left it ("blocked <mac>, kicked"): no churn
            let detail = match sync.detail_of("unifi_block", &id.to_string()) {
                Some(d) if d.starts_with(&format!("blocked {mac}")) => d.to_string(),
                _ => format!("blocked {mac}"),
            };
            sync.set(db, "unifi_block", &id.to_string(), "applied", &detail).await?;
            continue;
        }
        match unifi.block(mac).await {
            Ok(()) => {
                registry::audit(db, ACTOR, "iot:block", Some(*id)).await?;
                report.blocked += 1;
                let kicked = match unifi.kick(mac).await {
                    Ok(()) => {
                        registry::audit(db, ACTOR, "iot:kick", Some(*id)).await?;
                        report.kicked += 1;
                        ", kicked"
                    }
                    Err(e) => {
                        tracing::warn!(target: LOG, "{e}");
                        ""
                    }
                };
                tracing::info!(target: LOG, "UniFi: blocked the MAC of revoked device {id}{kicked}");
                sync.set(db, "unifi_block", &id.to_string(), "applied", &format!("blocked {mac}{kicked}")).await?;
            }
            Err(e) => {
                ok = false;
                tracing::error!(target: LOG, "{e}");
                sync.set(db, "unifi_block", &id.to_string(), "failed", &e.to_string()).await?;
            }
        }
    }

    // MACs blocked for devices that are gone from the registry (the row remembers the MAC)
    let still_blocked: BTreeSet<String> = desired.blocked.values().map(Uuid::to_string).collect();
    for (key, detail) in sync.rows_of("unifi_block") {
        if still_blocked.contains(&key) {
            continue;
        }
        let Some(mac) = detail.split([' ', ',']).find_map(normalise_mac) else {
            continue;
        };
        if !view.blocked.contains(&mac) {
            continue; // nothing to undo; the row is pruned
        }
        match unifi.unblock(&mac).await {
            Ok(()) => {
                registry::audit(db, ACTOR, "iot:unblock", key.parse().ok()).await?;
                report.unblocked += 1;
                tracing::info!(target: LOG, "UniFi: unblocked the MAC of former device {key}");
            }
            Err(e) => {
                ok = false;
                tracing::error!(target: LOG, "{e}");
                sync.set(db, "unifi_block", &key, "failed", &format!("blocked {mac}; unblock: {e}")).await?;
            }
        }
    }
    unifi.logout().await;
    Ok(ok)
}

// --- OPNsense -------------------------------------------------------------------------------------------

/// Kill the states between two addresses: those of the device's address that have the other
/// end as the resident (either direction), one `del_state` each.
async fn kill_pair(opn: &OpnsenseClient, src: &str, dst: &str) -> Result<usize, OpnsenseError> {
    let mut n = 0;
    for s in opn.states(dst).await? {
        if (s.src == src && s.dst == dst) || (s.src == dst && s.dst == src) {
            opn.del_state(&s.id, &s.creatorid).await?;
            n += 1;
        }
    }
    Ok(n)
}

/// Kill every state from or to an address (a revoked device's): `kill_states` with the
/// address as the filter, else (a version without it) the states queried and removed one by
/// one.
async fn kill_address(opn: &OpnsenseClient, address: &str) -> Result<usize, OpnsenseError> {
    match opn.kill_states(address).await {
        Ok(n) => return Ok(usize::try_from(n.unwrap_or(0)).unwrap_or(0)),
        Err(e) if e.is_not_found() => {}
        Err(e) => return Err(e),
    }
    let mut n = 0;
    for s in opn.states(address).await? {
        if s.src == address || s.dst == address {
            opn.del_state(&s.id, &s.creatorid).await?;
            n += 1;
        }
    }
    Ok(n)
}

async fn fail_opnsense(db: &mut Db, desired: &Desired, sync: &mut Sync, detail: &str) -> Result<(), IotError> {
    for name in desired.aliases.keys() {
        sync.set(db, "opnsense_alias", name, "failed", detail).await?;
    }
    for rule in desired.rules.values() {
        sync.set(db, "opnsense_rule", &rule.key, "failed", detail).await?;
    }
    Ok(())
}

/// The OPNsense part of a round; returns whether every call succeeded.
#[allow(clippy::too_many_arguments)]
async fn apply_opnsense(
    db: &mut Db,
    settings: &IotSettings,
    opn: &OpnsenseClient,
    desired: &Desired,
    devices: &[IotDevice],
    memory: &mut Memory,
    full: bool,
    sync: &mut Sync,
    report: &mut RoundReport,
) -> Result<bool, IotError> {
    let names = Names::new(&settings.prefix);
    let mut ok = true;

    // read back: the alias objects and rules of ours, and the alias contents (full rounds)
    let aliases = match opn.aliases().await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(target: LOG, "{e}");
            fail_opnsense(db, desired, sync, &e.to_string()).await?;
            return Ok(false);
        }
    };
    let rules = match opn.rules().await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(target: LOG, "{e}");
            fail_opnsense(db, desired, sync, &e.to_string()).await?;
            return Ok(false);
        }
    };
    let ours_aliases: BTreeMap<String, AliasRow> = aliases
        .into_iter()
        .filter(|a| a.is_ours() && names.is_our_alias(&a.name))
        .map(|a| (a.name.clone(), a))
        .collect();
    let ours_rules: BTreeMap<String, RuleRow> =
        rules.into_iter().filter(RuleRow::is_ours).map(|r| (r.description().to_string(), r)).collect();
    let read_whole = full || memory.alias_contents.is_none();
    let mut previous: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut unreadable: BTreeSet<String> = BTreeSet::new();
    if read_whole {
        for name in ours_aliases.keys() {
            match opn.alias_content(name).await {
                Ok(content) => {
                    previous.insert(name.clone(), content.into_iter().collect());
                }
                Err(e) => {
                    ok = false;
                    tracing::error!(target: LOG, "{e}");
                    unreadable.insert(name.clone());
                }
            }
        }
    } else if let Some(remembered) = &memory.alias_contents {
        previous = remembered
            .iter()
            .filter(|(n, _)| ours_aliases.contains_key(*n))
            .map(|(n, c)| (n.clone(), c.clone()))
            .collect();
    }

    // 1. alias objects that are missing
    let mut failed_aliases: BTreeSet<String> = unreadable.clone();
    let mut objects_changed = false;
    for (name, alias) in &desired.aliases {
        if ours_aliases.contains_key(name) {
            continue;
        }
        match opn.add_alias(name, &alias.description).await {
            Ok(_) => {
                objects_changed = true;
                report.aliases_changed += 1;
                registry::audit(db, ACTOR, &format!("iot:alias:{name}"), alias.device_id).await?;
                tracing::info!(target: LOG, "OPNsense: alias {name} made");
            }
            Err(e) => {
                ok = false;
                tracing::error!(target: LOG, "{e}");
                sync.set(db, "opnsense_alias", name, "failed", &e.to_string()).await?;
                failed_aliases.insert(name.clone());
            }
        }
    }
    if objects_changed && let Err(e) = opn.reconfigure_aliases().await {
        ok = false;
        tracing::error!(target: LOG, "{e}");
    }

    // 2. contents, live
    let mut applied: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (name, alias) in &desired.aliases {
        if failed_aliases.contains(name) {
            continue;
        }
        let current = previous.get(name).cloned().unwrap_or_default();
        let mut content = current.clone();
        let mut failed: Option<OpnsenseError> = None;
        for addr in alias.content.difference(&current) {
            match opn.alias_add(name, addr).await {
                Ok(()) => {
                    content.insert(addr.clone());
                }
                Err(e) => failed = Some(e),
            }
        }
        for addr in current.difference(&alias.content) {
            match opn.alias_delete(name, addr).await {
                Ok(()) => {
                    content.remove(addr);
                }
                Err(e) => failed = Some(e),
            }
        }
        if content != current {
            report.aliases_changed += 1;
            registry::audit(db, ACTOR, &format!("iot:alias:{name}"), alias.device_id).await?;
            tracing::info!(target: LOG, "OPNsense: alias {name} now holds {} address(es)", content.len());
        }
        match failed {
            None => sync.set(db, "opnsense_alias", name, "applied", &format!("{} address(es)", content.len())).await?,
            Some(e) => {
                ok = false;
                tracing::error!(target: LOG, "{e}");
                sync.set(db, "opnsense_alias", name, "failed", &e.to_string()).await?;
            }
        }
        applied.insert(name.clone(), content);
    }

    // 3. rules
    let mut rules_changed = false;
    for (description, rule) in &desired.rules {
        let fields = rule.fields();
        let outcome = match ours_rules.get(description) {
            Some(row) => {
                let same = fields.iter().all(|(k, v)| row.fields.get(*k).map(String::as_str) == Some(v.as_str()));
                if same { Ok(false) } else { opn.set_rule(&row.uuid, &fields).await.map(|()| true) }
            }
            None => opn.add_rule(&fields).await.map(|_| true),
        };
        match outcome {
            Ok(changed) => {
                if changed {
                    rules_changed = true;
                    report.rules_changed += 1;
                    registry::audit(db, ACTOR, &format!("iot:rule:{}", rule.key), None).await?;
                    tracing::info!(target: LOG, "OPNsense: rule {description:?} written");
                }
                sync.set(db, "opnsense_rule", &rule.key, "applied", "rule in place").await?;
            }
            Err(e) => {
                ok = false;
                tracing::error!(target: LOG, "{e}");
                sync.set(db, "opnsense_rule", &rule.key, "failed", &e.to_string()).await?;
            }
        }
    }
    for (description, row) in &ours_rules {
        if desired.rules.contains_key(description) {
            continue;
        }
        match opn.del_rule(&row.uuid).await {
            Ok(()) => {
                rules_changed = true;
                report.rules_changed += 1;
                registry::audit(db, ACTOR, &format!("iot:rule-removed:{description}"), None).await?;
                tracing::info!(target: LOG, "OPNsense: rule {description:?} removed");
            }
            Err(e) => {
                ok = false;
                tracing::error!(target: LOG, "{e}");
            }
        }
    }
    if let Some(why) = &desired.rules_blocked {
        ok = false;
        tracing::error!(target: LOG, "OPNsense: no rules: {why}");
        for hash in desired.persons.keys() {
            sync.set(db, "opnsense_rule", hash, "failed", why).await?;
        }
        sync.set(db, "opnsense_rule", "house", "failed", why).await?;
    }
    if rules_changed && let Err(e) = opn.apply_rules().await {
        ok = false;
        tracing::error!(target: LOG, "{e}");
        for rule in desired.rules.values() {
            sync.set(db, "opnsense_rule", &rule.key, "failed", &format!("apply: {e}")).await?;
        }
    }

    // 4. states of what is no longer allowed: a device address that went away (revoked,
    //    moved), then every pair whose access ended
    let by_hash: BTreeMap<String, Uuid> = devices.iter().map(|d| (device_hash(d.id), d.id)).collect();
    let by_address: BTreeMap<String, Uuid> = desired.addresses.iter().map(|(id, a)| (a.clone(), *id)).collect();
    let mut gone: BTreeMap<String, Option<Uuid>> = BTreeMap::new();
    for (name, content) in &previous {
        let Some(("dev", hash)) = names.hash_of(name) else {
            continue;
        };
        let now = applied.get(name).or_else(|| desired.aliases.get(name).map(|a| &a.content));
        for addr in content {
            if now.is_none_or(|c| !c.contains(addr)) {
                gone.insert(addr.clone(), by_hash.get(&hash).copied());
            }
        }
    }
    for (addr, device) in &gone {
        let key = device.map(|id| id.to_string()).unwrap_or_else(|| addr.clone());
        match kill_address(opn, addr).await {
            Ok(n) => {
                report.states_killed += n;
                if n > 0 {
                    registry::audit(db, ACTOR, "iot:states-killed", *device).await?;
                }
                tracing::info!(target: LOG, "OPNsense: {n} state(s) of {addr} killed (device gone)");
                sync.set(db, "opnsense_states", &key, "applied", &format!("{n} state(s) killed")).await?;
            }
            Err(e) => {
                ok = false;
                tracing::error!(target: LOG, "{e}");
                sync.set(db, "opnsense_states", &key, "failed", &e.to_string()).await?;
            }
        }
    }
    let previous_pairs = names.pairs_of(&previous);
    let current_pairs = names.pairs_of(&applied);
    for (src, dst) in previous_pairs.difference(&current_pairs) {
        if gone.contains_key(dst) {
            continue;
        }
        let device = by_address.get(dst).copied();
        let key = device.map(|id| id.to_string()).unwrap_or_else(|| dst.clone());
        match kill_pair(opn, src, dst).await {
            Ok(n) => {
                report.states_killed += n;
                if n > 0 {
                    registry::audit(db, ACTOR, "iot:states-killed", device).await?;
                    tracing::info!(target: LOG, "OPNsense: {n} state(s) between {src} and {dst} killed");
                }
                sync.set(db, "opnsense_states", &key, "applied", &format!("{n} state(s) killed")).await?;
            }
            Err(e) => {
                ok = false;
                tracing::error!(target: LOG, "{e}");
                sync.set(db, "opnsense_states", &key, "failed", &e.to_string()).await?;
            }
        }
    }

    // 5. alias objects of ours that are no longer wanted (after the rules that used them)
    let mut stale_changed = false;
    for (name, row) in &ours_aliases {
        if desired.aliases.contains_key(name) {
            continue;
        }
        match opn.del_alias(&row.uuid).await {
            Ok(()) => {
                stale_changed = true;
                report.aliases_changed += 1;
                registry::audit(db, ACTOR, &format!("iot:alias-removed:{name}"), None).await?;
                tracing::info!(target: LOG, "OPNsense: alias {name} removed");
            }
            Err(e) => {
                ok = false;
                tracing::error!(target: LOG, "{e}");
                sync.set(db, "opnsense_alias", name, "failed", &format!("not removed: {e}")).await?;
            }
        }
    }
    if stale_changed && let Err(e) = opn.reconfigure_aliases().await {
        ok = false;
        tracing::error!(target: LOG, "{e}");
    }
    // what the next (cheaper) round takes as "previous": unreadable aliases keep nothing
    memory.alias_contents = Some(applied);
    if read_whole && unreadable.is_empty() {
        memory.last_full = Some(Instant::now());
    }
    Ok(ok)
}

// --- the round --------------------------------------------------------------------------------------------

/// The `iot_sync` rows that belong to the desired state (kept at the end of the round).
fn expected_rows(desired: &Desired, devices: &[IotDevice]) -> BTreeSet<(String, String)> {
    let mut keep = BTreeSet::new();
    for (id, _) in &desired.keys {
        keep.insert(("unifi_key".to_string(), id.to_string()));
    }
    for id in &desired.keys_over_cap {
        keep.insert(("unifi_key".to_string(), id.to_string()));
    }
    for id in desired.blocked.values() {
        keep.insert(("unifi_block".to_string(), id.to_string()));
    }
    for name in desired.aliases.keys() {
        keep.insert(("opnsense_alias".to_string(), name.clone()));
    }
    for rule in desired.rules.values() {
        keep.insert(("opnsense_rule".to_string(), rule.key.clone()));
    }
    for d in devices {
        keep.insert(("opnsense_states".to_string(), d.id.to_string()));
    }
    keep
}

/// Bring UniFi and OPNsense in line with the registry, on this connection (the caller holds
/// the lock and records the job). `full`: read the alias contents back from OPNsense.
pub async fn reconcile(
    db: &mut Db,
    settings: &IotSettings,
    backends: &Backends<'_>,
    memory: &mut Memory,
    full: bool,
) -> Result<RoundReport, IotError> {
    let mut report = RoundReport::default();
    offboard(db, &mut report).await?;

    let devices = iot::all_devices(db, true).await?;
    let access = iot::access(db).await?;
    let resident_macs = iot::current_resident_macs(db).await?;
    let sessions = open_sessions(db).await?;
    report.shares = count_shares(db).await?;
    report.devices = devices.iter().filter(|d| d.revoked_at.is_none()).count();
    let mut sync = Sync::load(db).await?;
    db.commit().await?;

    // what the desired state needs from OPNsense: the leases, the interfaces
    let mut leases: Vec<Lease> = Vec::new();
    let mut residents_iface: Option<String> = None;
    let mut iot_iface: Option<String> = None;
    let mut opnsense_down: Option<String> = None;
    if let Some(opn) = backends.opnsense {
        let read = async {
            leases = opn.leases().await?;
            residents_iface = opn.interface_by_gateway(&settings.residents_gateway).await?;
            if residents_iface.is_none() {
                tracing::error!(target: LOG, "OPNsense: no interface has the address {}", settings.residents_gateway);
            }
            if settings.reverse_rules {
                iot_iface = opn.interface_by_gateway(&settings.iot_gateway).await?;
                if iot_iface.is_none() {
                    tracing::error!(target: LOG, "OPNsense: no interface has the address {}", settings.iot_gateway);
                }
            }
            Ok::<(), OpnsenseError>(())
        }
        .await;
        if let Err(e) = read {
            tracing::error!(target: LOG, "{e}");
            opnsense_down = Some(e.to_string());
        }
    }
    let desired = desired::compute(
        &desired::Inputs {
            devices: &devices,
            access: &access,
            resident_macs: &resident_macs,
            leases: &leases,
            sessions: &sessions,
            now: time::OffsetDateTime::now_utc().unix_timestamp(),
        },
        &desired::Settings {
            prefix: settings.prefix.clone(),
            residents_cidr: Cidr::parse(&settings.residents_cidr)
                .ok_or_else(|| IotError::Config(format!("NETPORTAL_RESIDENTS_CIDR {:?}", settings.residents_cidr)))?,
            iot_cidr: Cidr::parse(&settings.iot_cidr)
                .ok_or_else(|| IotError::Config(format!("NETPORTAL_IOT_CIDR {:?}", settings.iot_cidr)))?,
            residents_iface,
            iot_iface,
            reverse_rules: settings.reverse_rules,
            max_keys: settings.max_keys,
        },
    );
    report.address_conflicts = desired.conflicts.len();
    for conflict in &desired.conflicts {
        tracing::warn!(target: LOG, "address conflict, left out: {conflict}");
    }

    match backends.unifi {
        Some(unifi) => {
            report.unifi_ok = apply_unifi(db, settings, unifi, &desired, &devices, &mut sync, &mut report).await?;
        }
        None => {
            for id in desired.keys.iter().map(|(id, _)| id).chain(desired.keys_over_cap.iter()) {
                sync.set(db, "unifi_key", &id.to_string(), "pending", "UniFi is not configured").await?;
            }
            for id in desired.blocked.values() {
                sync.set(db, "unifi_block", &id.to_string(), "pending", "UniFi is not configured").await?;
            }
        }
    }
    db.commit().await?;

    match (backends.opnsense, opnsense_down) {
        (Some(opn), None) => {
            report.opnsense_ok =
                apply_opnsense(db, settings, opn, &desired, &devices, memory, full, &mut sync, &mut report).await?;
        }
        (Some(_), Some(detail)) => fail_opnsense(db, &desired, &mut sync, &detail).await?,
        (None, _) => {
            for name in desired.aliases.keys() {
                sync.set(db, "opnsense_alias", name, "pending", "OPNsense is not configured").await?;
            }
            for hash in desired.persons.keys() {
                sync.set(db, "opnsense_rule", hash, "pending", "OPNsense is not configured").await?;
            }
            sync.set(db, "opnsense_rule", "house", "pending", "OPNsense is not configured").await?;
        }
    }
    db.commit().await?;

    sync.prune(db, &expected_rows(&desired, &devices)).await?;
    report.join_attempts_pruned = iot::prune_join_attempts(db).await?;
    let counts = iot::sync_counts(db).await?;
    report.sync_pending = usize::try_from(counts.get("pending").copied().unwrap_or(0)).unwrap_or(0);
    report.sync_failed = usize::try_from(counts.get("failed").copied().unwrap_or(0)).unwrap_or(0);
    db.commit().await?;
    Ok(report)
}

async fn record(
    db: &mut Db,
    ok: bool,
    error: Option<&str>,
    duration: Option<f64>,
    cursor: Option<&Value>,
) -> Result<(), RegistryError> {
    db.rollback().await?;
    registry::job_end(db, JOB, ok, error, duration, cursor).await?;
    db.commit().await?;
    Ok(())
}

/// One round against the database: lock, `job_begin`, [`reconcile`], `job_end` with the
/// cursor (success) or the error. A full read-back when the last one is older than
/// `NETPORTAL_IOT_READBACK_S` (and on the first round).
pub async fn round(
    settings: &IotSettings,
    backends: &Backends<'_>,
    memory: &mut Memory,
) -> Result<RoundReport, IotError> {
    let started = Instant::now();
    let full = memory.last_full.is_none_or(|t| t.elapsed() >= settings.readback);
    let mut db = Db::connect(settings.database_url.expose()).await?;
    let held: bool = {
        let conn = db.autocommit().await?;
        conn.execute(STATEMENT_TIMEOUT).await?;
        conn.execute(LOCK_TIMEOUT).await?;
        sqlx::query_scalar("SELECT pg_try_advisory_lock(hashtext($1))").bind(LOCK_KEY).fetch_one(&mut *conn).await?
    };
    if !held {
        let _ = db.close().await;
        return Err(IotError::Locked);
    }
    let result = async {
        registry::job_begin(&mut db, JOB).await?;
        db.commit().await?;
        reconcile(&mut db, settings, backends, memory, full).await
    }
    .await;
    let duration = Some(started.elapsed().as_secs_f64());
    let result = match result {
        Ok(report) => match record(&mut db, true, None, duration, Some(&report.cursor())).await {
            Ok(()) => Ok(report),
            Err(e) => Err(e.into()),
        },
        Err(error) => {
            if let Err(e) = record(&mut db, false, Some(&error.to_string()), duration, None).await {
                tracing::warn!(target: LOG, "could not record the failed round: {e}");
            }
            Err(error)
        }
    };
    let _ = db.rollback().await;
    if let Ok(conn) = db.autocommit().await {
        let _ = sqlx::query("SELECT pg_advisory_unlock(hashtext($1))").bind(LOCK_KEY).execute(conn).await;
    }
    let _ = db.close().await; // closing releases the lock anyway
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cursor_keys() {
        let report = RoundReport { devices: 2, shares: 1, sync_failed: 3, unifi_ok: true, ..RoundReport::default() };
        let cursor = report.cursor();
        let keys: Vec<&String> = cursor.as_object().expect("object").keys().collect();
        assert_eq!(
            keys,
            ["address_conflicts", "devices", "opnsense_ok", "shares", "sync_failed", "sync_pending", "unifi_ok"]
        );
        assert_eq!((cursor["unifi_ok"].as_u64(), cursor["opnsense_ok"].as_u64()), (Some(1), Some(0)));
        assert!(!report.wrote());
        assert!(RoundReport { kicked: 1, ..RoundReport::default() }.wrote());
        assert_eq!(cut(&"x".repeat(900)).chars().count(), DETAIL_CHARS);
    }
}
