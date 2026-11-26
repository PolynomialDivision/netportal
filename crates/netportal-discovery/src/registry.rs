//! The registry as the proxy sees it: a snapshot of the registered devices by MAC, the access
//! view and the residents' current MACs, read every `refresh` with the read-only role
//! (`sql/discovery_grants.sql`: SELECT only). The last good snapshot is kept while the registry
//! is unreadable; after `stale_after` without one, only house-visible devices are answered
//! (design 6.5), logged once.

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

use netportal_core::Db;
use netportal_core::iot::{self, Access, CLASSES, MacDevice};
use netportal_core::registry::RegistryError;
use uuid::Uuid;

use crate::LOG;
use crate::frame::Mac;
use crate::wire::{self, Name};

/// What one read of the registry gave.
#[derive(Debug, Clone)]
pub struct Snapshot {
    devices: HashMap<Mac, MacDevice>,
    /// device id → the subs that may reach it (any basis)
    access: HashMap<Uuid, Vec<String>>,
    residents: HashMap<Mac, String>,
    /// the service types to browse: the registered classes' plus the configured extra ones
    pub service_types: Vec<Name>,
}

impl Snapshot {
    pub fn new(
        devices: Vec<MacDevice>,
        access: Vec<Access>,
        residents: BTreeMap<String, String>,
        extra: &[String],
    ) -> Snapshot {
        let mut by_mac = HashMap::new();
        for device in devices {
            match Mac::parse(&device.mac) {
                Some(mac) => {
                    by_mac.insert(mac, device);
                }
                None => {
                    tracing::warn!(target: LOG, "device {}: {:?} is not a MAC, skipped", device.device_id, device.mac)
                }
            }
        }
        let mut by_device: HashMap<Uuid, Vec<String>> = HashMap::new();
        for row in access {
            let subs = by_device.entry(row.device_id).or_default();
            if !subs.contains(&row.sub) {
                subs.push(row.sub);
            }
        }
        let residents = residents.into_iter().filter_map(|(mac, owner)| Some((Mac::parse(&mac)?, owner))).collect();
        let service_types = service_types(by_mac.values().map(|d| d.class.as_str()), extra);
        Snapshot { devices: by_mac, access: by_device, residents, service_types }
    }

    /// The registered device with this MAC.
    pub fn device_of(&self, mac: Mac) -> Option<&MacDevice> {
        self.devices.get(&mac)
    }

    /// The resident whose device currently uses this MAC (`None`: nobody).
    pub fn person_of(&self, mac: Mac) -> Option<&str> {
        self.residents.get(&mac).map(String::as_str)
    }

    /// Whether the access view has the pair (owner, share or house).
    pub fn may_reach(&self, sub: &str, device: Uuid) -> bool {
        self.access.get(&device).is_some_and(|subs| subs.iter().any(|s| s == sub))
    }

    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    pub fn resident_mac_count(&self) -> usize {
        self.residents.len()
    }

    pub fn access_count(&self) -> usize {
        self.access.values().map(Vec::len).sum()
    }
}

/// The service types of these classes plus the extra ones, as names (`_x._tcp.local`), sorted.
pub fn service_types<'a>(classes: impl Iterator<Item = &'a str>, extra: &[String]) -> Vec<Name> {
    let mut types: Vec<&str> =
        classes.flat_map(|c| iot::service_types(c).iter().copied()).chain(extra.iter().map(String::as_str)).collect();
    types.sort_unstable();
    types.dedup();
    types.into_iter().filter_map(|t| wire::name(&format!("{t}.local"))).collect()
}

/// Every class's service types (before the first snapshot, and the probe).
pub fn all_service_types(extra: &[String]) -> Vec<Name> {
    service_types(CLASSES.iter().copied(), extra)
}

/// One read: the three queries in one transaction (a consistent view), rolled back afterwards
/// (nothing was written; the role could not anyway).
pub async fn load(db: &mut Db, extra: &[String]) -> Result<Snapshot, RegistryError> {
    let result = async {
        let devices = iot::mac_devices(db).await?;
        let access = iot::access(db).await?;
        let residents = iot::current_resident_macs(db).await?;
        Ok(Snapshot::new(devices, access, residents, extra))
    }
    .await;
    let _ = db.rollback().await;
    result
}

/// A database error's kind only (its text may hold values).
fn kind_of(error: &sqlx::Error) -> &'static str {
    match error {
        sqlx::Error::Io(_) | sqlx::Error::Tls(_) => "connection failed",
        sqlx::Error::Configuration(_) => "bad database URL",
        sqlx::Error::Database(_) => "refused by the database",
        sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed => "no connection",
        _ => "database error",
    }
}

fn describe(error: &RegistryError) -> String {
    match error {
        RegistryError::Db(e) => kind_of(e).to_string(),
        other => other.to_string(),
    }
}

/// Reads the registry round after round over one connection, reopened after a failure.
pub struct Reader {
    url: String,
    db: Option<Db>,
}

impl Reader {
    pub fn new(url: &str) -> Reader {
        Reader { url: url.to_string(), db: None }
    }

    pub async fn read(&mut self, extra: &[String]) -> Result<Snapshot, String> {
        if self.db.is_none() {
            self.db = Some(Db::connect(&self.url).await.map_err(|e| kind_of(&e).to_string())?);
        }
        let Some(db) = self.db.as_mut() else { return Err("no connection".into()) };
        match load(db, extra).await {
            Ok(snapshot) => Ok(snapshot),
            Err(e) => {
                // dropping the connection closes it; the next round opens a new one
                self.db = None;
                Err(describe(&e))
            }
        }
    }
}

/// What the answers may use: everything, house-visible devices only (the registry went stale),
/// or nothing (no snapshot was ever read).
#[derive(Debug, Clone, Copy)]
pub enum View<'a> {
    Full(&'a Snapshot),
    HouseOnly(&'a Snapshot),
    Nothing,
}

/// The last good snapshot with the time it was read, and the stale rule.
#[derive(Debug, Default)]
pub struct State {
    snapshot: Option<Snapshot>,
    last_ok: Option<Instant>,
    failing: bool,
    stale: bool,
}

impl State {
    pub fn new() -> State {
        State::default()
    }

    pub fn snapshot(&self) -> Option<&Snapshot> {
        self.snapshot.as_ref()
    }

    /// Seconds since the last good read.
    pub fn age(&self, now: Instant) -> Option<Duration> {
        self.last_ok.map(|t| now.saturating_duration_since(t))
    }

    /// Takes the result of a read (a failure keeps the last snapshot; logged at the first of a
    /// streak and at recovery).
    pub fn update(&mut self, result: Result<Snapshot, String>, now: Instant) {
        match result {
            Ok(snapshot) => {
                if self.failing {
                    tracing::info!(target: LOG, "registry readable again");
                }
                self.failing = false;
                tracing::debug!(
                    target: LOG,
                    "registry: {} devices, {} access rows, {} resident MACs",
                    snapshot.device_count(),
                    snapshot.access_count(),
                    snapshot.resident_mac_count()
                );
                self.snapshot = Some(snapshot);
                self.last_ok = Some(now);
            }
            Err(e) => {
                if !self.failing {
                    tracing::warn!(target: LOG, "registry unreadable ({e}): keeping the last state");
                }
                self.failing = true;
            }
        }
    }

    pub fn is_stale(&self, now: Instant, stale_after: Duration) -> bool {
        self.last_ok.is_none_or(|t| now.saturating_duration_since(t) > stale_after)
    }

    /// Logs the stale transition once (and the recovery); called by the housekeeping.
    pub fn check_stale(&mut self, now: Instant, stale_after: Duration) {
        let stale = self.snapshot.is_some() && self.is_stale(now, stale_after);
        if stale && !self.stale {
            tracing::warn!(
                target: LOG,
                "registry unreadable for more than {} s: answering house-visible devices only",
                stale_after.as_secs()
            );
        } else if !stale && self.stale {
            tracing::info!(target: LOG, "registry fresh again: answering shared devices again");
        }
        self.stale = stale;
    }

    pub fn view(&self, now: Instant, stale_after: Duration) -> View<'_> {
        match &self.snapshot {
            None => View::Nothing,
            Some(s) if self.is_stale(now, stale_after) => View::HouseOnly(s),
            Some(s) => View::Full(s),
        }
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    pub const ALICE_MAC: Mac = Mac([0x02, 0xaa, 0x00, 0x00, 0x00, 0x01]);
    pub const BOB_MAC: Mac = Mac([0x02, 0xbb, 0x00, 0x00, 0x00, 0x02]);

    pub fn device(mac: Mac, owner: &str, class: &str, visibility: &str) -> MacDevice {
        MacDevice {
            mac: mac.to_string(),
            device_id: Uuid::new_v4(),
            owner: owner.into(),
            class: class.into(),
            visibility: visibility.into(),
            name: format!("{owner}'s {class}"),
        }
    }

    /// Alice (MAC `ALICE_MAC`) owns the device, Bob (`BOB_MAC`) has no share; with
    /// `visibility` house, both have the `house` basis.
    pub fn snapshot(device: MacDevice) -> Snapshot {
        let mut access = vec![Access { sub: "alice".into(), device_id: device.device_id, basis: "owner".into() }];
        if device.visibility == "house" {
            for sub in ["alice", "bob"] {
                access.push(Access { sub: sub.into(), device_id: device.device_id, basis: "house".into() });
            }
        }
        let residents =
            BTreeMap::from([(ALICE_MAC.to_string(), "alice".to_string()), (BOB_MAC.to_string(), "bob".to_string())]);
        Snapshot::new(vec![device], access, residents, &[])
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use crate::cache::testing::CAST_MAC;

    #[test]
    fn snapshot_lookups_and_service_types() {
        let dev = device(CAST_MAC, "alice", "cast", "private");
        let id = dev.device_id;
        let s = snapshot(dev);
        assert_eq!(s.device_of(CAST_MAC).map(|d| d.device_id), Some(id));
        assert_eq!(s.person_of(ALICE_MAC), Some("alice"));
        assert_eq!(s.person_of(Mac::ZERO), None);
        assert!(s.may_reach("alice", id));
        assert!(!s.may_reach("bob", id));
        assert_eq!(s.service_types, vec![wire::name("_googlecast._tcp.local").unwrap()]);
        let extra = vec!["_hap._tcp".to_string()];
        let types = service_types(["airplay", "cast"].into_iter(), &extra);
        let text: Vec<String> = types.iter().map(|n| n.to_utf8()).collect();
        assert_eq!(text, ["_airplay._tcp.local.", "_googlecast._tcp.local.", "_hap._tcp.local.", "_raop._tcp.local."]);
        assert!(all_service_types(&[]).len() >= 8);
    }

    #[test]
    fn stale_rule() {
        let now = Instant::now();
        let stale_after = Duration::from_secs(600);
        let mut state = State::new();
        assert!(matches!(state.view(now, stale_after), View::Nothing));
        state.update(Err("down".into()), now);
        assert!(matches!(state.view(now, stale_after), View::Nothing));
        state.update(Ok(snapshot(device(CAST_MAC, "alice", "cast", "private"))), now);
        assert!(matches!(state.view(now + Duration::from_secs(600), stale_after), View::Full(_)));
        state.update(Err("down".into()), now + Duration::from_secs(10));
        assert!(matches!(state.view(now + Duration::from_secs(601), stale_after), View::HouseOnly(_)));
        state.check_stale(now + Duration::from_secs(601), stale_after);
        state.update(Ok(snapshot(device(CAST_MAC, "alice", "cast", "private"))), now + Duration::from_secs(700));
        assert!(matches!(state.view(now + Duration::from_secs(701), stale_after), View::Full(_)));
        state.check_stale(now + Duration::from_secs(701), stale_after);
        assert_eq!(state.age(now + Duration::from_secs(710)), Some(Duration::from_secs(10)));
    }
}
