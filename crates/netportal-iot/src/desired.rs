//! The desired state from the registry (house-infra docs/IOT-ACCESS.md 6.4): a plain structure
//! the reconciliation compares with what UniFi and OPNsense have, computed from rows only (no
//! I/O), so it is unit-tested here.
//!
//! - UniFi: one key per unrevoked home device (at most `NETPORTAL_IOT_MAX_KEYS`), the MACs of
//!   revoked devices blocked.
//! - Addresses: a MAC's address comes from the DHCP leases and the open accounting sessions
//!   (`radius_acct.framed_ip`), inside the VLAN's network; a MAC with two addresses, or an
//!   address with two MACs, is a conflict: logged, left out, counted.
//! - OPNsense: host aliases `<prefix>_dev_<8 hex of the device id>` (the device's address),
//!   `<prefix>_src_<h>` and `<prefix>_to_<h>` per person with access (`h`: 8 hex of
//!   sha256(sub); their resident devices' addresses, the devices they may reach), `<prefix>_house`
//!   (house-visible devices) and `<prefix>_house_src` (every resident address); one `pass` rule
//!   per person and one for the house on the residents' interface, any protocol and port, and
//!   with `NETPORTAL_IOT_REVERSE_RULES` the mirrored rules on the IoT interface. Descriptions
//!   start with `netportal:` ([`crate::opnsense::DESCRIPTION_PREFIX`]).
//!
//! The house basis of the access view is served by the house rule alone; a person's own
//! aliases carry the devices they own or were given.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use netportal_core::iot::{Access, IotDevice};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::opnsense::DESCRIPTION_PREFIX;

/// The sequence of the controller's rules: before house-infra's static rules (100, 110, ...),
/// so a static block of VLAN 30 -> 40 behind them does not shadow the allows. The same for all
/// of them: they are `pass quick` rules that do not overlap.
pub const RULE_SEQUENCE: &str = "50";

/// A DHCP lease as OPNsense lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    /// `aa:bb:cc:dd:ee:ff`
    pub mac: String,
    pub address: String,
    /// epoch seconds; `None` or 0: no expiry (static)
    pub expire: Option<i64>,
    pub hostname: String,
}

/// An IPv4 network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    net: u32,
    mask: u32,
}

impl Cidr {
    /// `10.0.30.0/24`.
    pub fn parse(text: &str) -> Option<Cidr> {
        let (addr, bits) = text.trim().split_once('/')?;
        let addr: Ipv4Addr = addr.parse().ok()?;
        let bits: u32 = bits.parse().ok()?;
        if bits > 32 {
            return None;
        }
        let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
        Some(Cidr { net: u32::from(addr) & mask, mask })
    }

    pub fn contains(&self, address: &str) -> bool {
        address.trim().parse::<Ipv4Addr>().is_ok_and(|a| u32::from(a) & self.mask == self.net)
    }
}

/// 8 hex characters of sha256 of the person's sub: the person's part of alias and rule names.
pub fn person_hash(sub: &str) -> String {
    hex::encode(Sha256::digest(sub.as_bytes()))[..8].to_string()
}

/// 8 hex characters of the device id.
pub fn device_hash(id: Uuid) -> String {
    id.simple().to_string()[..8].to_string()
}

/// The names of the controller's objects for a prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Names {
    pub prefix: String,
}

impl Names {
    pub fn new(prefix: &str) -> Names {
        Names { prefix: prefix.to_string() }
    }

    pub fn dev(&self, id: Uuid) -> String {
        format!("{}_dev_{}", self.prefix, device_hash(id))
    }

    pub fn src(&self, hash: &str) -> String {
        format!("{}_src_{hash}", self.prefix)
    }

    pub fn to(&self, hash: &str) -> String {
        format!("{}_to_{hash}", self.prefix)
    }

    pub fn house(&self) -> String {
        format!("{}_house", self.prefix)
    }

    pub fn house_src(&self) -> String {
        format!("{}_house_src", self.prefix)
    }

    pub fn person_rule(&self, hash: &str) -> String {
        format!("{DESCRIPTION_PREFIX} {} person {hash}", self.prefix)
    }

    pub fn house_rule(&self) -> String {
        format!("{DESCRIPTION_PREFIX} {} house", self.prefix)
    }

    pub fn person_reverse_rule(&self, hash: &str) -> String {
        format!("{DESCRIPTION_PREFIX} {} person {hash} reverse", self.prefix)
    }

    pub fn house_reverse_rule(&self) -> String {
        format!("{DESCRIPTION_PREFIX} {} house reverse", self.prefix)
    }

    /// The person hash of a `_src_` or `_to_` alias name of ours, the 8 hex of a `_dev_` one.
    pub fn hash_of(&self, alias: &str) -> Option<(&'static str, String)> {
        let rest = alias.strip_prefix(&self.prefix)?;
        for (kind, infix) in [("src", "_src_"), ("to", "_to_"), ("dev", "_dev_")] {
            if let Some(h) = rest.strip_prefix(infix)
                && h.len() == 8
                && h.bytes().all(|b| b.is_ascii_hexdigit())
            {
                return Some((kind, h.to_string()));
            }
        }
        None
    }

    /// Whether this alias name is one the controller makes (any of the five forms).
    pub fn is_our_alias(&self, alias: &str) -> bool {
        alias == self.house() || alias == self.house_src() || self.hash_of(alias).is_some()
    }

    /// The allowed (source, destination) address pairs of alias contents: every `_src_<h>` with
    /// its `_to_<h>`, and `_house_src` with `_house`.
    pub fn pairs_of(&self, contents: &BTreeMap<String, BTreeSet<String>>) -> BTreeSet<(String, String)> {
        let mut pairs = BTreeSet::new();
        let empty = BTreeSet::new();
        let mut add = |sources: &BTreeSet<String>, targets: &BTreeSet<String>| {
            for s in sources {
                for t in targets {
                    pairs.insert((s.clone(), t.clone()));
                }
            }
        };
        for (name, sources) in contents {
            if let Some(("src", h)) = self.hash_of(name) {
                add(sources, contents.get(&self.to(&h)).unwrap_or(&empty));
            }
        }
        if let Some(sources) = contents.get(&self.house_src()) {
            add(sources, contents.get(&self.house()).unwrap_or(&empty));
        }
        pairs
    }
}

/// A host alias the controller wants, with its content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alias {
    pub name: String,
    pub description: String,
    pub content: BTreeSet<String>,
    /// the device of a `_dev_` alias (for the audit)
    pub device_id: Option<Uuid>,
}

/// A rule the controller wants: identified by its description.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// the `iot_sync` key: the person hash, `house`, or `<that> reverse`
    pub key: String,
    pub description: String,
    pub interface: String,
    pub source_net: String,
    pub destination_net: String,
}

impl Rule {
    /// The fields as the API takes them (house.py's kind `filter`, every value a string).
    pub fn fields(&self) -> BTreeMap<&'static str, String> {
        [
            ("enabled", "1".to_string()),
            ("sequence", RULE_SEQUENCE.to_string()),
            ("action", "pass".to_string()),
            ("quick", "1".to_string()),
            ("interface", self.interface.clone()),
            ("direction", "in".to_string()),
            ("ipprotocol", "inet".to_string()),
            ("protocol", "any".to_string()),
            ("source_net", self.source_net.clone()),
            ("source_not", "0".to_string()),
            ("destination_net", self.destination_net.clone()),
            ("destination_not", "0".to_string()),
            ("destination_port", String::new()),
            ("log", "0".to_string()),
            ("description", self.description.clone()),
        ]
        .into()
    }
}

/// What the computation needs of the settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub prefix: String,
    pub residents_cidr: Cidr,
    pub iot_cidr: Cidr,
    /// the residents' interface identifier (`opt2`), `None`: unknown, no rules
    pub residents_iface: Option<String>,
    /// the IoT interface identifier, for the reverse rules
    pub iot_iface: Option<String>,
    pub reverse_rules: bool,
    pub max_keys: usize,
}

/// The rows the computation reads.
#[derive(Debug, Clone, Copy)]
pub struct Inputs<'a> {
    /// every home device, revoked ones included (`iot::all_devices(true)`)
    pub devices: &'a [IotDevice],
    /// the access view (`iot::access`)
    pub access: &'a [Access],
    /// `{mac: owner}` of the residents' current MAC windows (`iot::current_resident_macs`)
    pub resident_macs: &'a BTreeMap<String, String>,
    pub leases: &'a [Lease],
    /// `(mac, framed_ip)` of the open accounting sessions
    pub sessions: &'a [(String, String)],
    /// now, epoch seconds (lease expiry)
    pub now: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Desired {
    /// `(device id, key)` of the unrevoked devices, oldest first, at most `max_keys`
    pub keys: Vec<(Uuid, String)>,
    /// unrevoked devices beyond `max_keys` (no key in the SSID; reported)
    pub keys_over_cap: Vec<Uuid>,
    /// `{mac: device id}` of the revoked devices with a MAC
    pub blocked: BTreeMap<String, Uuid>,
    /// `{device id: mac}` of the unrevoked devices with a MAC
    pub device_macs: BTreeMap<Uuid, String>,
    /// `{device id: address}` of those whose address is known (and not in conflict)
    pub addresses: BTreeMap<Uuid, String>,
    /// by name
    pub aliases: BTreeMap<String, Alias>,
    /// by description
    pub rules: BTreeMap<String, Rule>,
    /// `{hash: sub}` of the persons with aliases
    pub persons: BTreeMap<String, String>,
    /// what was left out, one line each
    pub conflicts: Vec<String>,
    /// why no rule could be computed (no residents' interface)
    pub rules_blocked: Option<String>,
}

impl Desired {
    /// `{alias name: content}` of the aliases.
    pub fn contents(&self) -> BTreeMap<String, BTreeSet<String>> {
        self.aliases.iter().map(|(n, a)| (n.clone(), a.content.clone())).collect()
    }
}

/// `{mac: address}` of the wanted MACs inside `cidr`, from the leases (unexpired) and the open
/// sessions, and the conflicts (a MAC with two addresses, an address with two MACs) left out.
pub fn resolve<'a>(
    wanted: impl IntoIterator<Item = &'a str>,
    cidr: &Cidr,
    leases: &[Lease],
    sessions: &[(String, String)],
    now: i64,
) -> (BTreeMap<String, String>, Vec<String>) {
    let mut by_mac: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut by_addr: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut note = |mac: &str, addr: &str| {
        if !cidr.contains(addr) {
            return;
        }
        by_mac.entry(mac.to_string()).or_default().insert(addr.trim().to_string());
        by_addr.entry(addr.trim().to_string()).or_default().insert(mac.to_string());
    };
    for lease in leases {
        if lease.expire.is_some_and(|e| e > 0 && e < now) {
            continue;
        }
        note(&lease.mac, &lease.address);
    }
    for (mac, ip) in sessions {
        note(mac, ip);
    }
    let mut out = BTreeMap::new();
    let mut conflicts = Vec::new();
    for mac in wanted {
        let Some(addrs) = by_mac.get(mac) else {
            continue;
        };
        if addrs.len() > 1 {
            conflicts.push(format!("MAC {mac} has {} addresses", addrs.len()));
            continue;
        }
        let Some(addr) = addrs.iter().next() else {
            continue;
        };
        let owners = by_addr.get(addr).map(BTreeSet::len).unwrap_or(0);
        if owners > 1 {
            conflicts.push(format!("address {addr} has {owners} MACs"));
            continue;
        }
        out.insert(mac.to_string(), addr.clone());
    }
    (out, conflicts)
}

/// The desired state of these rows.
pub fn compute(inputs: &Inputs<'_>, settings: &Settings) -> Desired {
    let names = Names::new(&settings.prefix);
    let mut out = Desired::default();

    let mut unrevoked: Vec<&IotDevice> = inputs.devices.iter().filter(|d| d.revoked_at.is_none()).collect();
    // the oldest devices keep their keys when the cap bites
    unrevoked.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
    for (i, d) in unrevoked.iter().enumerate() {
        if i < settings.max_keys {
            out.keys.push((d.id, d.psk.clone()));
        } else {
            out.keys_over_cap.push(d.id);
        }
        if let Some(mac) = &d.mac {
            out.device_macs.insert(d.id, mac.clone());
        }
    }
    for d in inputs.devices.iter().filter(|d| d.revoked_at.is_some()) {
        if let Some(mac) = &d.mac {
            out.blocked.insert(mac.clone(), d.id);
        }
    }

    // addresses: the devices' in the IoT VLAN, the residents' in theirs
    let (dev_addr, mut conflicts) = resolve(
        out.device_macs.values().map(String::as_str),
        &settings.iot_cidr,
        inputs.leases,
        inputs.sessions,
        inputs.now,
    );
    for (id, mac) in &out.device_macs {
        if let Some(addr) = dev_addr.get(mac) {
            out.addresses.insert(*id, addr.clone());
        }
    }
    let (res_addr, more) = resolve(
        inputs.resident_macs.keys().map(String::as_str),
        &settings.residents_cidr,
        inputs.leases,
        inputs.sessions,
        inputs.now,
    );
    conflicts.extend(more);
    out.conflicts = conflicts;

    // one alias per device with a MAC
    for id in out.device_macs.keys() {
        let content: BTreeSet<String> = out.addresses.get(id).cloned().into_iter().collect();
        out.aliases.insert(
            names.dev(*id),
            Alias {
                name: names.dev(*id),
                description: format!("{DESCRIPTION_PREFIX} device {}", device_hash(*id)),
                content,
                device_id: Some(*id),
            },
        );
    }

    // per person: their devices by ownership or share (the house basis is the house rule's)
    let unrevoked_ids: BTreeSet<Uuid> = unrevoked.iter().map(|d| d.id).collect();
    let mut per_person: BTreeMap<&str, BTreeSet<Uuid>> = BTreeMap::new();
    for row in inputs.access.iter().filter(|a| a.basis != "house" && unrevoked_ids.contains(&a.device_id)) {
        per_person.entry(row.sub.as_str()).or_default().insert(row.device_id);
    }
    let residents_iface = settings.residents_iface.clone();
    let reverse_iface = if settings.reverse_rules { settings.iot_iface.clone() } else { None };
    for (sub, devices) in per_person {
        let hash = person_hash(sub);
        let sources: BTreeSet<String> = inputs
            .resident_macs
            .iter()
            .filter(|(_, owner)| owner.as_str() == sub)
            .filter_map(|(mac, _)| res_addr.get(mac).cloned())
            .collect();
        let targets: BTreeSet<String> = devices.iter().filter_map(|id| out.addresses.get(id).cloned()).collect();
        out.aliases.insert(
            names.src(&hash),
            Alias {
                name: names.src(&hash),
                description: format!("{DESCRIPTION_PREFIX} sources of {hash}"),
                content: sources,
                device_id: None,
            },
        );
        out.aliases.insert(
            names.to(&hash),
            Alias {
                name: names.to(&hash),
                description: format!("{DESCRIPTION_PREFIX} devices for {hash}"),
                content: targets,
                device_id: None,
            },
        );
        if let Some(iface) = &residents_iface {
            out.rules.insert(
                names.person_rule(&hash),
                Rule {
                    key: hash.clone(),
                    description: names.person_rule(&hash),
                    interface: iface.clone(),
                    source_net: names.src(&hash),
                    destination_net: names.to(&hash),
                },
            );
            if let Some(iot_iface) = &reverse_iface {
                out.rules.insert(
                    names.person_reverse_rule(&hash),
                    Rule {
                        key: format!("{hash} reverse"),
                        description: names.person_reverse_rule(&hash),
                        interface: iot_iface.clone(),
                        source_net: names.to(&hash),
                        destination_net: names.src(&hash),
                    },
                );
            }
        }
        out.persons.insert(hash, sub.to_string());
    }

    // the house: every resident may reach every house-visible device
    let house_devices: BTreeSet<String> = unrevoked
        .iter()
        .filter(|d| d.visibility == "house")
        .filter_map(|d| out.addresses.get(&d.id).cloned())
        .collect();
    out.aliases.insert(
        names.house(),
        Alias {
            name: names.house(),
            description: format!("{DESCRIPTION_PREFIX} house devices"),
            content: house_devices,
            device_id: None,
        },
    );
    out.aliases.insert(
        names.house_src(),
        Alias {
            name: names.house_src(),
            description: format!("{DESCRIPTION_PREFIX} house sources"),
            content: res_addr.values().cloned().collect(),
            device_id: None,
        },
    );
    match &residents_iface {
        Some(iface) => {
            out.rules.insert(
                names.house_rule(),
                Rule {
                    key: "house".into(),
                    description: names.house_rule(),
                    interface: iface.clone(),
                    source_net: names.house_src(),
                    destination_net: names.house(),
                },
            );
            if let Some(iot_iface) = &reverse_iface {
                out.rules.insert(
                    names.house_reverse_rule(),
                    Rule {
                        key: "house reverse".into(),
                        description: names.house_reverse_rule(),
                        interface: iot_iface.clone(),
                        source_net: names.house(),
                        destination_net: names.house_src(),
                    },
                );
            }
        }
        None => out.rules_blocked = Some("the residents' interface was not found by its gateway address".into()),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::OffsetDateTime;

    fn settings() -> Settings {
        Settings {
            prefix: "np_iot".into(),
            residents_cidr: Cidr::parse("10.0.30.0/24").expect("cidr"),
            iot_cidr: Cidr::parse("10.0.40.0/24").expect("cidr"),
            residents_iface: Some("opt2".into()),
            iot_iface: Some("opt3".into()),
            reverse_rules: false,
            max_keys: 200,
        }
    }

    /// A test id whose 8-hex device hash differs per number.
    fn uid(n: u128) -> Uuid {
        Uuid::from_u128((n << 120) | n)
    }

    fn device(id: u128, owner: &str, mac: Option<&str>, visibility: &str, revoked: bool, age_s: i64) -> IotDevice {
        let now = OffsetDateTime::now_utc();
        IotDevice {
            id: uid(id),
            owner: owner.into(),
            owner_name: owner.into(),
            name: format!("dev-{id}"),
            class: "cast".into(),
            mac: mac.map(str::to_string),
            mac_claimed_at: mac.map(|_| now),
            psk: format!("key{id:017}"),
            psk_rotated_at: now,
            visibility: visibility.into(),
            created_at: now - time::Duration::seconds(age_s),
            revoked_at: revoked.then_some(now),
            last_seen: None,
        }
    }

    fn access(sub: &str, id: u128, basis: &str) -> Access {
        Access { sub: sub.into(), device_id: uid(id), basis: basis.into() }
    }

    fn lease(mac: &str, address: &str, expire: Option<i64>) -> Lease {
        Lease { mac: mac.into(), address: address.into(), expire, hostname: String::new() }
    }

    #[test]
    fn test_hashes_and_names() {
        let h = person_hash("sub-alice");
        assert_eq!(h.len(), 8);
        assert!(h.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(h, person_hash("sub-alice"));
        assert_ne!(h, person_hash("sub-bob"));
        // sha256("sub-alice") starts with these 8 hex digits (fixed by the function)
        assert_eq!(h, hex::encode(Sha256::digest(b"sub-alice"))[..8]);
        let id = Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef);
        assert_eq!(device_hash(id), "01234567");
        let names = Names::new("np_iot");
        assert_eq!(names.dev(id), "np_iot_dev_01234567");
        assert_eq!(names.src(&h), format!("np_iot_src_{h}"));
        assert_eq!(names.to(&h), format!("np_iot_to_{h}"));
        assert_eq!((names.house(), names.house_src()), ("np_iot_house".into(), "np_iot_house_src".into()));
        assert_eq!(names.person_rule(&h), format!("netportal: np_iot person {h}"));
        assert_eq!(names.house_rule(), "netportal: np_iot house");
        assert_eq!(names.person_reverse_rule(&h), format!("netportal: np_iot person {h} reverse"));
        assert_eq!(names.hash_of(&names.src(&h)), Some(("src", h.clone())));
        assert_eq!(names.hash_of("np_iot_dev_01234567"), Some(("dev", "01234567".into())));
        assert_eq!(names.hash_of("np_iot_src_xyz"), None);
        assert!(names.is_our_alias("np_iot_house") && !names.is_our_alias("house_infra_x"));
        assert!(Cidr::parse("10.0.30.0/24").expect("cidr").contains("10.0.30.7"));
        assert!(!Cidr::parse("10.0.30.0/24").expect("cidr").contains("10.0.40.7"));
        assert!(Cidr::parse("10.0.30.0/33").is_none() && Cidr::parse("junk").is_none());
    }

    #[test]
    fn test_resolve_conflicts() {
        let cidr = Cidr::parse("10.0.30.0/24").expect("cidr");
        let leases = [
            lease("aa:00:00:00:00:01", "10.0.30.11", Some(4_000_000_000)),
            lease("aa:00:00:00:00:02", "10.0.30.12", Some(4_000_000_000)),
            lease("aa:00:00:00:00:02", "10.0.30.13", Some(4_000_000_000)), // two addresses
            lease("aa:00:00:00:00:03", "10.0.30.14", Some(4_000_000_000)),
            lease("aa:00:00:00:00:09", "10.0.30.14", Some(4_000_000_000)), // the same address
            lease("aa:00:00:00:00:04", "10.0.30.15", Some(1)),             // expired
            lease("aa:00:00:00:00:05", "10.0.40.15", None),                // another VLAN
        ];
        let sessions = [("aa:00:00:00:00:06".to_string(), "10.0.30.16".to_string())];
        let wanted = [
            "aa:00:00:00:00:01",
            "aa:00:00:00:00:02",
            "aa:00:00:00:00:03",
            "aa:00:00:00:00:04",
            "aa:00:00:00:00:05",
            "aa:00:00:00:00:06",
            "aa:00:00:00:00:07",
        ];
        let (found, conflicts) = resolve(wanted, &cidr, &leases, &sessions, 1_000_000);
        assert_eq!(
            found,
            [
                ("aa:00:00:00:00:01".to_string(), "10.0.30.11".to_string()),
                ("aa:00:00:00:00:06".into(), "10.0.30.16".into())
            ]
            .into()
        );
        assert_eq!(conflicts, ["MAC aa:00:00:00:00:02 has 2 addresses", "address 10.0.30.14 has 2 MACs"]);
        // a lease and a session that agree are one address
        let (found, conflicts) =
            resolve(["aa:00:00:00:00:01"], &cidr, &leases, &[("aa:00:00:00:00:01".into(), "10.0.30.11".into())], 0);
        assert_eq!(found.len(), 1);
        assert!(conflicts.is_empty());
    }

    #[test]
    fn test_desired_state() {
        let devices = [
            device(1, "alice", Some("aa:00:00:00:00:a1"), "private", false, 300),
            device(2, "alice", Some("aa:00:00:00:00:a2"), "house", false, 200),
            device(3, "bob", None, "private", false, 100),
            device(4, "carol", Some("aa:00:00:00:00:a4"), "private", true, 400),
        ];
        let access = [
            access("alice", 1, "owner"),
            access("alice", 2, "owner"),
            access("bob", 1, "share"),
            access("bob", 3, "owner"),
            access("alice", 2, "house"),
            access("bob", 2, "house"),
            access("dave", 2, "house"),
        ];
        let resident_macs: BTreeMap<String, String> = [
            ("bb:00:00:00:00:01".to_string(), "alice".to_string()),
            ("bb:00:00:00:00:02".to_string(), "bob".to_string()),
            ("bb:00:00:00:00:03".to_string(), "bob".to_string()),
        ]
        .into();
        let leases = [
            lease("aa:00:00:00:00:a1", "10.0.40.11", None),
            lease("aa:00:00:00:00:a2", "10.0.40.12", None),
            lease("bb:00:00:00:00:01", "10.0.30.21", None),
            lease("bb:00:00:00:00:02", "10.0.30.22", None),
        ];
        let sessions = [("bb:00:00:00:00:03".to_string(), "10.0.30.23".to_string())];
        let inputs = Inputs {
            devices: &devices,
            access: &access,
            resident_macs: &resident_macs,
            leases: &leases,
            sessions: &sessions,
            now: 1_000,
        };
        let d = compute(&inputs, &settings());
        // keys of the unrevoked devices, oldest first
        assert_eq!(d.keys.iter().map(|(id, _)| *id).collect::<Vec<_>>(), [uid(1), uid(2), uid(3)]);
        assert_eq!(d.keys[0].1, devices[0].psk);
        assert!(d.keys_over_cap.is_empty());
        assert_eq!(d.blocked, [("aa:00:00:00:00:a4".to_string(), uid(4))].into());
        assert_eq!(d.addresses, [(uid(1), "10.0.40.11".to_string()), (uid(2), "10.0.40.12".into())].into());
        assert!(d.conflicts.is_empty());
        let names = Names::new("np_iot");
        let (a, b) = (person_hash("alice"), person_hash("bob"));
        let set = |items: &[&str]| items.iter().map(|s| s.to_string()).collect::<BTreeSet<_>>();
        assert_eq!(d.aliases[&names.dev(uid(1))].content, set(&["10.0.40.11"]));
        assert_eq!(d.aliases[&names.dev(uid(1))].device_id, Some(uid(1)));
        assert_eq!(d.aliases[&names.src(&a)].content, set(&["10.0.30.21"]));
        assert_eq!(d.aliases[&names.to(&a)].content, set(&["10.0.40.11", "10.0.40.12"]));
        assert_eq!(d.aliases[&names.src(&b)].content, set(&["10.0.30.22", "10.0.30.23"]));
        // bob reaches alice's first device by the share; his own has no MAC yet: no address
        assert_eq!(d.aliases[&names.to(&b)].content, set(&["10.0.40.11"]));
        assert_eq!(d.aliases[&names.house()].content, set(&["10.0.40.12"]));
        assert_eq!(d.aliases[&names.house_src()].content, set(&["10.0.30.21", "10.0.30.22", "10.0.30.23"]));
        // dave has house access only: no aliases of his own
        assert!(!d.persons.values().any(|s| s == "dave"));
        assert_eq!(d.persons, [(a.clone(), "alice".to_string()), (b.clone(), "bob".to_string())].into());
        assert!(d.aliases.values().all(|al| al.description.starts_with("netportal:")));
        // rules: one per person and the house, on the residents' interface
        assert_eq!(d.rules.len(), 3);
        let rule = &d.rules[&names.person_rule(&a)];
        assert_eq!((rule.key.as_str(), rule.interface.as_str()), (a.as_str(), "opt2"));
        let fields = rule.fields();
        assert_eq!(fields["source_net"], names.src(&a));
        assert_eq!(fields["destination_net"], names.to(&a));
        assert_eq!(
            (fields["action"].as_str(), fields["quick"].as_str(), fields["protocol"].as_str()),
            ("pass", "1", "any")
        );
        assert_eq!((fields["sequence"].as_str(), fields["destination_port"].as_str()), (RULE_SEQUENCE, ""));
        assert_eq!(fields.len(), 15);
        assert_eq!(d.rules[&names.house_rule()].key, "house");
        // the allowed pairs
        let pairs = names.pairs_of(&d.contents());
        assert!(pairs.contains(&("10.0.30.21".into(), "10.0.40.11".into())));
        assert!(pairs.contains(&("10.0.30.22".into(), "10.0.40.11".into())));
        assert!(pairs.contains(&("10.0.30.22".into(), "10.0.40.12".into()))); // house
        assert!(!pairs.contains(&("10.0.30.22".into(), "10.0.40.13".into())));
        assert_eq!(pairs.len(), 2 + 1 + 3);
        // reverse rules on the IoT interface
        let d = compute(&inputs, &Settings { reverse_rules: true, ..settings() });
        assert_eq!(d.rules.len(), 6);
        let reverse = &d.rules[&names.person_reverse_rule(&b)];
        assert_eq!((reverse.key.as_str(), reverse.interface.as_str()), (format!("{b} reverse").as_str(), "opt3"));
        assert_eq!((reverse.source_net.clone(), reverse.destination_net.clone()), (names.to(&b), names.src(&b)));
        // no interface: aliases, no rules
        let d = compute(&inputs, &Settings { residents_iface: None, ..settings() });
        assert!(d.rules.is_empty() && d.rules_blocked.is_some() && d.aliases.len() == 2 + 4 + 2);
        // the key cap keeps the oldest
        let d = compute(&inputs, &Settings { max_keys: 2, ..settings() });
        assert_eq!(d.keys.iter().map(|(id, _)| *id).collect::<Vec<_>>(), [uid(1), uid(2)]);
        assert_eq!(d.keys_over_cap, [uid(3)]);
    }

    #[test]
    fn test_conflicting_device_is_left_out() {
        let devices = [device(1, "alice", Some("aa:00:00:00:00:a1"), "house", false, 10)];
        let access = [access("alice", 1, "owner")];
        let leases = [lease("aa:00:00:00:00:a1", "10.0.40.11", None), lease("aa:00:00:00:00:a1", "10.0.40.12", None)];
        let inputs = Inputs {
            devices: &devices,
            access: &access,
            resident_macs: &BTreeMap::new(),
            leases: &leases,
            sessions: &[],
            now: 0,
        };
        let d = compute(&inputs, &settings());
        assert!(d.addresses.is_empty());
        assert_eq!(d.conflicts.len(), 1);
        assert!(d.aliases["np_iot_house"].content.is_empty());
        assert_eq!(d.keys.len(), 1);
    }
}
