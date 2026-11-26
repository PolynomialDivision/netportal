//! The engine without sockets: takes the frames of both legs, keeps the cache and the registry
//! state, applies the rate limits and hands back what to send. Everything here is driven by an
//! explicit `now`, so the tests run it without sockets or sleeps.
//!
//! Limits: at most [`RATE_LIMIT`] answers per second per querier (a token bucket keyed by MAC,
//! then dropped); a record is multicast at most once per [`MULTICAST_GAP`] (RFC 6762 §6).

use std::collections::HashMap;
use std::net::SocketAddrV4;
use std::time::{Duration, Instant};

use crate::LOG;
use crate::answer::{self, Delivery, Querier};
use crate::cache::Cache;
use crate::frame::{Frame, Mac};
use crate::registry::{self, Snapshot, State};
use crate::wire::{self, Name, RecordType};

/// Answers per second per querier, then dropped.
pub const RATE_LIMIT: u32 = 20;
/// The same record is not multicast more often than this.
pub const MULTICAST_GAP: Duration = Duration::from_secs(1);
/// The browser's PTR queries go out this often (RFC 6762 §5.2 allows up to one per hour; one
/// per minute keeps the cache warm between the devices' announcements).
pub const BROWSE_EVERY: Duration = Duration::from_secs(60);
/// A multicast answer for shared records waits a random time in this range (§6).
pub const SHARED_DELAY_MS: std::ops::RangeInclusive<u64> = 20..=120;

/// Where a datagram goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Unicast(SocketAddrV4),
    Multicast,
}

/// A datagram to send on the residents' leg.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outgoing {
    pub target: Target,
    pub delay: Duration,
    pub payload: Vec<u8>,
}

/// What a frame on the IoT leg was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IotEvent {
    /// a response: this many records taken into the cache
    Announcement(usize),
    /// a query (devices browse too); not answered, the leg is listen-only
    Query,
    /// not an mDNS message
    Junk,
}

/// The counters of one summary period.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    pub queries: u64,
    pub unicast: u64,
    pub multicast: u64,
    /// answers dropped by the per-querier rate limit
    pub rate_limited: u64,
    pub announcements: u64,
    pub learned: u64,
    pub junk: u64,
}

struct Bucket {
    tokens: f64,
    at: Instant,
}

impl Bucket {
    fn take(&mut self, now: Instant) -> bool {
        let refill = now.saturating_duration_since(self.at).as_secs_f64() * f64::from(RATE_LIMIT);
        self.tokens = (self.tokens + refill).min(f64::from(RATE_LIMIT));
        self.at = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

pub struct Proxy {
    ttl: u32,
    stale_after: Duration,
    extra_services: Vec<String>,
    cache: Cache,
    registry: State,
    buckets: HashMap<Mac, Bucket>,
    multicast_last: HashMap<(Name, RecordType), Instant>,
    stats: Stats,
}

impl Proxy {
    pub fn new(ttl: u32, stale_after: Duration, extra_services: &[String]) -> Proxy {
        Proxy {
            ttl,
            stale_after,
            extra_services: extra_services.to_vec(),
            cache: Cache::new(),
            registry: State::new(),
            buckets: HashMap::new(),
            multicast_last: HashMap::new(),
            stats: Stats::default(),
        }
    }

    pub fn cache(&self) -> &Cache {
        &self.cache
    }

    pub fn registry(&self) -> &State {
        &self.registry
    }

    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// The result of a registry read.
    pub fn update_registry(&mut self, result: Result<Snapshot, String>, now: Instant) {
        self.registry.update(result, now);
    }

    /// Whether a source MAC is a registered device (by the last snapshot).
    pub fn is_registered(&self, mac: Mac) -> bool {
        self.registry.snapshot().is_some_and(|s| s.device_of(mac).is_some())
    }

    /// The service types to browse: the registered classes' plus the extra ones; every class's
    /// before the first snapshot.
    pub fn service_types(&self) -> Vec<Name> {
        match self.registry.snapshot() {
            Some(s) => s.service_types.clone(),
            None => registry::all_service_types(&self.extra_services),
        }
    }

    /// The browser's query: one message with a PTR question per service type.
    pub fn browse_query(&self) -> Option<Vec<u8>> {
        let questions: Vec<_> = self.service_types().into_iter().map(wire::ptr_question).collect();
        if questions.is_empty() {
            return None;
        }
        wire::encode_query(questions, Vec::new()).ok()
    }

    /// The re-queries due for registered devices' records (one message), if any.
    pub fn requery(&mut self, now: Instant) -> Option<Vec<u8>> {
        let snapshot = self.registry.snapshot()?;
        let questions = self.cache.requeries(now, |mac| snapshot.device_of(mac).is_some());
        if questions.is_empty() {
            return None;
        }
        wire::encode_query(questions, Vec::new()).ok()
    }

    /// A frame of the IoT leg: announcements go into the cache.
    pub fn on_iot(&mut self, frame: &Frame<'_>, now: Instant) -> IotEvent {
        let Some(message) = wire::parse(frame.payload) else {
            self.stats.junk += 1;
            return IotEvent::Junk;
        };
        if wire::is_query(&message) {
            return IotEvent::Query;
        }
        let learned = self.cache.learn(frame.src_mac, *frame.src.ip(), &message, now);
        self.stats.announcements += 1;
        self.stats.learned += learned as u64;
        tracing::debug!(target: LOG, "{} {}: {} ({learned} records taken)", frame.src_mac, frame.src.ip(), wire::describe(&message));
        IotEvent::Announcement(learned)
    }

    /// A frame of the residents' leg: a query gets its answers (responses of other responders
    /// are ignored).
    pub fn on_resident(&mut self, frame: &Frame<'_>, now: Instant) -> Vec<Outgoing> {
        let Some(message) = wire::parse(frame.payload) else {
            self.stats.junk += 1;
            return Vec::new();
        };
        if !wire::is_query(&message) {
            return Vec::new();
        }
        self.stats.queries += 1;
        let querier = Querier { mac: frame.src_mac, addr: frame.src };
        let view = self.registry.view(now, self.stale_after);
        let answers = answer::decide(&message, &querier, &self.cache, view, self.ttl, now);
        let mut out = Vec::new();
        for mut answer in answers {
            if answer.delivery == Delivery::Multicast {
                // the one-second rule: a record multicast within the last second is not repeated
                answer.response.answers.retain(|r| self.multicast_allowed(r.name.clone(), r.record_type(), now));
                if answer.response.answers.is_empty() {
                    continue;
                }
                for r in &answer.response.additionals {
                    self.multicast_last.insert((r.name.clone(), r.record_type()), now);
                }
            }
            let bucket = self.buckets.entry(querier.mac).or_insert(Bucket { tokens: f64::from(RATE_LIMIT), at: now });
            if !bucket.take(now) {
                self.stats.rate_limited += 1;
                tracing::debug!(target: LOG, "{} {}: rate limit, answer dropped", querier.mac, querier.addr);
                continue;
            }
            let payload = match wire::encode_response(&answer.response) {
                Ok(bytes) => bytes,
                Err(e) => {
                    tracing::warn!(target: LOG, "answer not encoded: {e}");
                    continue;
                }
            };
            let (target, delay) = match answer.delivery {
                Delivery::Unicast => {
                    self.stats.unicast += 1;
                    (Target::Unicast(querier.addr), Duration::ZERO)
                }
                Delivery::Multicast => {
                    self.stats.multicast += 1;
                    (Target::Multicast, Duration::from_millis(rand::random_range(SHARED_DELAY_MS)))
                }
            };
            let records: Vec<String> = answer.records().map(wire::describe_record).collect();
            tracing::debug!(
                target: LOG,
                "{} {}: {} -> {:?}{} [{}]",
                querier.mac,
                querier.addr,
                wire::describe(&message),
                target,
                if answer.legacy { " (legacy)" } else { "" },
                records.join(", ")
            );
            out.push(Outgoing { target, delay, payload });
        }
        out
    }

    fn multicast_allowed(&mut self, name: Name, record_type: RecordType, now: Instant) -> bool {
        let key = (name, record_type);
        if self.multicast_last.get(&key).is_some_and(|last| now.saturating_duration_since(*last) < MULTICAST_GAP) {
            return false;
        }
        self.multicast_last.insert(key, now);
        true
    }

    /// Expiry, the stale check, the limits' tables; every few seconds.
    pub fn housekeeping(&mut self, now: Instant) {
        let dropped = self.cache.expire(now);
        if dropped > 0 {
            tracing::debug!(target: LOG, "{dropped} records expired");
        }
        self.registry.check_stale(now, self.stale_after);
        self.buckets.retain(|_, b| now.saturating_duration_since(b.at) < Duration::from_secs(10));
        self.multicast_last.retain(|_, t| now.saturating_duration_since(*t) < MULTICAST_GAP);
    }

    /// The counters since the last summary (reset), with the cache's state, as one line.
    pub fn summary(&mut self, now: Instant) -> String {
        let stats = std::mem::take(&mut self.stats);
        let (mut registered, mut unclaimed) = (0usize, 0usize);
        for source in self.cache.sources() {
            if self.is_registered(source.mac) {
                registered += 1;
            } else {
                unclaimed += 1;
            }
        }
        let registry = match self.registry.age(now) {
            Some(age) => format!("{} s old", age.as_secs()),
            None => "never read".to_string(),
        };
        format!(
            "last minute: {} queries, {} unicast and {} multicast answers, {} rate-limited, {} announcements ({} records), {} junk; \
             cache: {} records of {registered} registered devices, {unclaimed} unclaimed sources; registry {registry}",
            stats.queries,
            stats.unicast,
            stats.multicast,
            stats.rate_limited,
            stats.announcements,
            stats.learned,
            stats.junk,
            self.cache.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::testing::*;
    use crate::frame::testing::ethernet_frame;
    use crate::frame::{MDNS_GROUP, MDNS_PORT, parse_ethernet};
    use crate::registry::testing::*;
    use crate::wire::{Message, Query, RecordType, encode_query, ptr_question};
    use std::net::Ipv4Addr;

    const RESIDENT: Ipv4Addr = Ipv4Addr::new(10, 0, 30, 7);

    fn proxy(visibility: &str, now: Instant) -> Proxy {
        let mut proxy = Proxy::new(120, Duration::from_secs(600), &[]);
        proxy.update_registry(Ok(snapshot(device(CAST_MAC, "alice", "cast", visibility))), now);
        let frame = ethernet_frame(
            CAST_MAC,
            SocketAddrV4::new(CAST_ADDR, MDNS_PORT),
            SocketAddrV4::new(MDNS_GROUP, MDNS_PORT),
            &cast_announcement(),
        );
        assert_eq!(proxy.on_iot(&parse_ethernet(&frame).unwrap(), now), IotEvent::Announcement(4));
        proxy
    }

    fn qu_ptr(port: u16) -> Vec<u8> {
        let mut q = ptr_question(service());
        q.set_mdns_unicast_response(true);
        ethernet_frame(
            ALICE_MAC,
            SocketAddrV4::new(RESIDENT, port),
            SocketAddrV4::new(MDNS_GROUP, MDNS_PORT),
            &encode_query(vec![q], vec![]).unwrap(),
        )
    }

    #[test]
    fn answers_a_query_on_the_residents_leg() {
        let now = Instant::now();
        let mut proxy = proxy("private", now);
        let frame = qu_ptr(MDNS_PORT);
        let out = proxy.on_resident(&parse_ethernet(&frame).unwrap(), now);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].target, Target::Unicast(SocketAddrV4::new(RESIDENT, MDNS_PORT)));
        assert_eq!(out[0].delay, Duration::ZERO);
        let response = Message::from_vec(&out[0].payload).unwrap();
        assert_eq!(response.answers.len() + response.additionals.len(), 4);
        assert_eq!(proxy.stats().unicast, 1);
        // the IoT leg's own queries and junk
        let iot_query = ethernet_frame(
            CAST_MAC,
            SocketAddrV4::new(CAST_ADDR, MDNS_PORT),
            SocketAddrV4::new(MDNS_GROUP, MDNS_PORT),
            &encode_query(vec![ptr_question(service())], vec![]).unwrap(),
        );
        assert_eq!(proxy.on_iot(&parse_ethernet(&iot_query).unwrap(), now), IotEvent::Query);
        let junk = ethernet_frame(
            CAST_MAC,
            SocketAddrV4::new(CAST_ADDR, MDNS_PORT),
            SocketAddrV4::new(MDNS_GROUP, MDNS_PORT),
            b"x",
        );
        assert_eq!(proxy.on_iot(&parse_ethernet(&junk).unwrap(), now), IotEvent::Junk);
        assert!(proxy.summary(now).contains("1 queries, 1 unicast"));
        assert_eq!(proxy.stats(), Stats::default(), "reset by the summary");
    }

    #[test]
    fn rate_limit_per_querier() {
        let now = Instant::now();
        let mut proxy = proxy("private", now);
        let frame = qu_ptr(MDNS_PORT);
        let parsed = parse_ethernet(&frame).unwrap();
        let sent = (0..30).filter(|_| !proxy.on_resident(&parsed, now).is_empty()).count();
        assert_eq!(sent, RATE_LIMIT as usize);
        assert_eq!(proxy.stats().rate_limited, 10);
        // half a second later: ten more
        let later = now + Duration::from_millis(500);
        let sent = (0..30).filter(|_| !proxy.on_resident(&parsed, later).is_empty()).count();
        assert_eq!(sent, 10);
        // another querier has its own budget
        let mut other = qu_ptr(MDNS_PORT);
        other[6..12].copy_from_slice(&BOB_MAC.0);
        let mut house = self::proxy("house", now);
        assert_eq!(house.on_resident(&parse_ethernet(&other).unwrap(), later).len(), 2, "unicast and multicast");
    }

    #[test]
    fn multicast_answers_wait_and_repeat_only_after_a_second() {
        let now = Instant::now();
        let mut proxy = proxy("house", now);
        let frame = ethernet_frame(
            BOB_MAC,
            SocketAddrV4::new(RESIDENT, MDNS_PORT),
            SocketAddrV4::new(MDNS_GROUP, MDNS_PORT),
            &encode_query(vec![ptr_question(service())], vec![]).unwrap(),
        );
        let parsed = parse_ethernet(&frame).unwrap();
        let out = proxy.on_resident(&parsed, now);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].target, Target::Multicast);
        assert!((20..=120).contains(&out[0].delay.as_millis()));
        assert!(proxy.on_resident(&parsed, now + Duration::from_millis(500)).is_empty(), "within a second");
        assert_eq!(proxy.on_resident(&parsed, now + Duration::from_millis(1001)).len(), 1);
        proxy.housekeeping(now + Duration::from_secs(5));
        assert_eq!(proxy.stats().multicast, 2);
    }

    #[test]
    fn browse_and_requery_messages() {
        let now = Instant::now();
        let mut proxy = Proxy::new(120, Duration::from_secs(600), &["_hap._tcp".to_string()]);
        let browse = Message::from_vec(&proxy.browse_query().unwrap()).unwrap();
        assert!(browse.queries.iter().all(|q| q.query_type == RecordType::PTR && !q.mdns_unicast_response));
        assert!(browse.queries.iter().any(|q| q.name.to_utf8() == "_hap._tcp.local."));
        assert!(browse.queries.len() > 8, "every class before the first snapshot");
        assert!(proxy.requery(now).is_none(), "no registry, nothing registered");
        let mut proxy = self::proxy("private", now);
        let browse = Message::from_vec(&proxy.browse_query().unwrap()).unwrap();
        assert_eq!(browse.queries.len(), 1, "the registered class only");
        assert!(proxy.requery(now + Duration::from_secs(30)).is_none());
        let requery = Message::from_vec(&proxy.requery(now + Duration::from_secs(60)).unwrap()).unwrap();
        let questions: Vec<Query> = requery.queries;
        assert_eq!(questions.len(), 2);
        assert!(questions.iter().any(|q| q.query_type == RecordType::A));
    }
}
