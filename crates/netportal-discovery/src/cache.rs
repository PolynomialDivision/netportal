//! The records learned on the IoT leg, per source MAC: the PTR (service type → instance), SRV,
//! TXT and A/AAAA records with their TTLs and the time they were learned. A record is forgotten
//! at its TTL; records of registered devices are asked for again at [`REQUERY_AT`] percent of
//! it, so a living device never drops out of the cache between announcements. Whether a source
//! is a registered device is decided at answer time against the registry snapshot, so a MAC
//! claimed in the portal later is answered without being learned again; until then its records
//! sit here as "unclaimed" (the admin view, `--probe`), never answered.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crate::frame::Mac;
use crate::wire::{DNSClass, Message, MessageType, Name, Query, Record, RecordType};

/// Sources (MACs) kept at most: a hostile VLAN 40 device cannot grow the cache without bound.
pub const MAX_SOURCES: usize = 1024;
/// Records per source at most.
pub const MAX_RECORDS: usize = 256;
/// A registered device's record is queried again at these percentages of its TTL.
pub const REQUERY_AT: [u64; 2] = [50, 80];
/// A source without records is remembered this long (its MAC was seen) before it is dropped.
pub const EMPTY_SOURCE_MEMORY: Duration = Duration::from_secs(3600);

/// One record as learned.
#[derive(Debug, Clone)]
pub struct Cached {
    /// with the TTL and the cache-flush bit as announced
    pub record: Record,
    pub learned: Instant,
    /// how many of [`REQUERY_AT`] were sent since it was learned
    requeries: usize,
}

impl Cached {
    pub fn expires(&self) -> Instant {
        self.learned + Duration::from_secs(u64::from(self.record.ttl))
    }

    /// Seconds left of the announced TTL (0 when expired).
    pub fn remaining(&self, now: Instant) -> u32 {
        u32::try_from(self.expires().saturating_duration_since(now).as_secs()).unwrap_or(u32::MAX)
    }
}

/// Everything learned from one MAC.
#[derive(Debug, Clone)]
pub struct Source {
    pub mac: Mac,
    /// the address of the last datagram
    pub addr: Ipv4Addr,
    pub first_seen: Instant,
    pub last_seen: Instant,
    pub records: Vec<Cached>,
}

impl Source {
    /// The records of a name, of one type or of every type.
    pub fn find<'a, 'n>(
        &'a self,
        name: &'n Name,
        record_type: Option<RecordType>,
    ) -> impl Iterator<Item = &'a Cached> + use<'a, 'n> {
        self.records
            .iter()
            .filter(move |c| c.record.name == *name && record_type.is_none_or(|t| c.record.record_type() == t))
    }
}

#[derive(Debug, Default)]
pub struct Cache {
    sources: HashMap<Mac, Source>,
}

/// The record types the proxy keeps (a DNS-SD service is these; NSEC and the rest are not).
fn keep(record: &Record) -> bool {
    record.dns_class == DNSClass::IN
        && matches!(
            record.record_type(),
            RecordType::PTR | RecordType::SRV | RecordType::TXT | RecordType::A | RecordType::AAAA
        )
}

impl Cache {
    pub fn new() -> Cache {
        Cache::default()
    }

    /// Absorbs the records of a response (the answer and additional sections; a goodbye, TTL 0,
    /// removes). A record with the cache-flush bit replaces the source's records of that name
    /// and type (§10.2, with the whole message taken as the new set). Returns the records taken.
    pub fn learn(&mut self, mac: Mac, addr: Ipv4Addr, message: &Message, now: Instant) -> usize {
        if message.message_type != MessageType::Response {
            return 0;
        }
        if !self.sources.contains_key(&mac) && self.sources.len() >= MAX_SOURCES {
            return 0;
        }
        let source = self.sources.entry(mac).or_insert_with(|| Source {
            mac,
            addr,
            first_seen: now,
            last_seen: now,
            records: Vec::new(),
        });
        source.last_seen = now;
        source.addr = addr;
        let records: Vec<&Record> = message.answers.iter().chain(&message.additionals).filter(|r| keep(r)).collect();
        for record in records.iter().filter(|r| r.mdns_cache_flush && r.ttl > 0) {
            source
                .records
                .retain(|c| !(c.record.name == record.name && c.record.record_type() == record.record_type()));
        }
        let mut taken = 0;
        for record in records {
            if record.ttl == 0 {
                source.records.retain(|c| c.record != *record);
                taken += 1;
                continue;
            }
            if let Some(cached) = source.records.iter_mut().find(|c| c.record == *record) {
                cached.record.ttl = record.ttl;
                cached.record.mdns_cache_flush = record.mdns_cache_flush;
                cached.learned = now;
                cached.requeries = 0;
                taken += 1;
            } else if source.records.len() < MAX_RECORDS {
                source.records.push(Cached { record: record.clone(), learned: now, requeries: 0 });
                taken += 1;
            }
        }
        taken
    }

    /// Forgets expired records and long-empty sources; returns the records dropped.
    pub fn expire(&mut self, now: Instant) -> usize {
        let mut dropped = 0;
        for source in self.sources.values_mut() {
            let before = source.records.len();
            source.records.retain(|c| c.expires() > now);
            dropped += before - source.records.len();
        }
        self.sources
            .retain(|_, s| !s.records.is_empty() || now.saturating_duration_since(s.last_seen) < EMPTY_SOURCE_MEMORY);
        dropped
    }

    /// The questions due now for the records of registered sources (each record once per
    /// threshold of [`REQUERY_AT`]).
    pub fn requeries(&mut self, now: Instant, registered: impl Fn(Mac) -> bool) -> Vec<Query> {
        let mut questions: Vec<Query> = Vec::new();
        for source in self.sources.values_mut().filter(|s| registered(s.mac)) {
            for cached in &mut source.records {
                let Some(&threshold) = REQUERY_AT.get(cached.requeries) else { continue };
                let ttl = u64::from(cached.record.ttl);
                if now.saturating_duration_since(cached.learned).as_secs() * 100 < ttl * threshold {
                    continue;
                }
                cached.requeries += 1;
                let question = Query::query(cached.record.name.clone(), cached.record.record_type());
                if !questions.contains(&question) {
                    questions.push(question);
                }
            }
        }
        questions
    }

    pub fn source(&self, mac: Mac) -> Option<&Source> {
        self.sources.get(&mac)
    }

    pub fn sources(&self) -> impl Iterator<Item = &Source> {
        self.sources.values()
    }

    /// Records in total.
    pub fn len(&self) -> usize {
        self.sources.values().map(|s| s.records.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
pub(crate) mod testing {
    //! A Chromecast-like announcement, as the tests of this crate use it.

    use super::*;
    use crate::wire::{RData, Response, encode_response, name};
    use hickory_proto::rr::rdata::{A, PTR, SRV, TXT};

    pub const CAST_MAC: Mac = Mac([0xd4, 0xf5, 0x47, 0x01, 0x02, 0x03]);
    pub const CAST_ADDR: Ipv4Addr = Ipv4Addr::new(10, 0, 40, 23);

    pub fn service() -> Name {
        name("_googlecast._tcp.local").unwrap()
    }

    /// `Living Room._googlecast._tcp.local` (a label with a space, as devices announce them).
    pub fn instance() -> Name {
        Name::from_labels([b"Living Room".as_slice(), b"_googlecast", b"_tcp", b"local"]).unwrap()
    }

    pub fn host() -> Name {
        name("d4f54701-0203-4bcd-8ef0-123456789abc.local").unwrap()
    }

    /// PTR (TTL 4500), SRV and TXT (TTL 120, cache flush) and A (TTL 120, cache flush).
    pub fn cast_records() -> Vec<Record> {
        let ptr = Record::from_rdata(service(), 4500, RData::PTR(PTR(instance())));
        let mut srv = Record::from_rdata(instance(), 120, RData::SRV(SRV::new(0, 0, 8009, host())));
        srv.mdns_cache_flush = true;
        let txt = TXT::from_bytes(vec![b"id=abc123".as_slice(), b"fn=Living Room", b"md=Chromecast"]);
        let mut txt = Record::from_rdata(instance(), 4500, RData::TXT(txt));
        txt.mdns_cache_flush = true;
        let mut a = Record::from_rdata(host(), 120, RData::A(A(CAST_ADDR)));
        a.mdns_cache_flush = true;
        vec![ptr, srv, txt, a]
    }

    /// The announcement as bytes: the PTR answers, the rest additional.
    pub fn cast_announcement() -> Vec<u8> {
        let mut records = cast_records();
        let rest = records.split_off(1);
        encode_response(&Response { answers: records, additionals: rest, ..Default::default() }).unwrap()
    }

    /// A cache that learned the announcement at `now`.
    pub fn cache_with_cast(now: Instant) -> Cache {
        let mut cache = Cache::new();
        let message = Message::from_vec(&cast_announcement()).unwrap();
        assert_eq!(cache.learn(CAST_MAC, CAST_ADDR, &message, now), 4);
        cache
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use crate::wire::{RData, Response, encode_response};
    use hickory_proto::rr::rdata::A;

    #[test]
    fn learns_an_announcement() {
        let now = Instant::now();
        let cache = cache_with_cast(now);
        let source = cache.source(CAST_MAC).unwrap();
        assert_eq!(source.addr, CAST_ADDR);
        assert_eq!(source.records.len(), 4);
        let ptr: Vec<_> = source.find(&service(), Some(RecordType::PTR)).collect();
        assert_eq!(ptr.len(), 1);
        assert_eq!(ptr[0].record.ttl, 4500);
        assert!(!ptr[0].record.mdns_cache_flush);
        let srv: Vec<_> = source.find(&instance(), Some(RecordType::SRV)).collect();
        assert!(srv[0].record.mdns_cache_flush);
        assert_eq!(srv[0].remaining(now + Duration::from_secs(50)), 70);
        assert_eq!(srv[0].remaining(now + Duration::from_secs(500)), 0);
        assert_eq!(source.find(&instance(), None).count(), 2, "SRV and TXT");
        assert_eq!(cache.len(), 4);
    }

    #[test]
    fn queries_are_not_learned_and_junk_is_ignored() {
        let now = Instant::now();
        let mut cache = Cache::new();
        let query =
            Message::from_vec(&crate::wire::encode_query(vec![crate::wire::ptr_question(service())], vec![]).unwrap())
                .unwrap();
        assert_eq!(cache.learn(CAST_MAC, CAST_ADDR, &query, now), 0);
        assert!(cache.is_empty());
    }

    #[test]
    fn cache_flush_replaces_goodbye_removes_expiry_forgets() {
        let now = Instant::now();
        let mut cache = cache_with_cast(now);
        // a new address with the cache-flush bit replaces the old A record
        let mut a = Record::from_rdata(host(), 120, RData::A(A(Ipv4Addr::new(10, 0, 40, 99))));
        a.mdns_cache_flush = true;
        let update =
            Message::from_vec(&encode_response(&Response { answers: vec![a], ..Default::default() }).unwrap()).unwrap();
        assert_eq!(cache.learn(CAST_MAC, CAST_ADDR, &update, now + Duration::from_secs(1)), 1);
        let source = cache.source(CAST_MAC).unwrap();
        let addresses: Vec<_> = source.find(&host(), Some(RecordType::A)).collect();
        assert_eq!(addresses.len(), 1);
        assert_eq!(addresses[0].record.data, RData::A(A(Ipv4Addr::new(10, 0, 40, 99))));
        // a goodbye (TTL 0) removes the PTR
        let mut bye = cast_records().swap_remove(0);
        bye.ttl = 0;
        let bye = Message::from_vec(&encode_response(&Response { answers: vec![bye], ..Default::default() }).unwrap())
            .unwrap();
        cache.learn(CAST_MAC, CAST_ADDR, &bye, now + Duration::from_secs(2));
        assert_eq!(cache.source(CAST_MAC).unwrap().find(&service(), Some(RecordType::PTR)).count(), 0);
        // the 120 s records expire, the 4500 s TXT stays
        assert_eq!(cache.expire(now + Duration::from_secs(121)), 2);
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.expire(now + Duration::from_secs(4501)), 1);
        assert!(cache.source(CAST_MAC).is_none(), "silent for more than an hour: forgotten with its last record");
        // a source seen recently is remembered a while after its records expired
        let other = Mac([1, 2, 3, 4, 5, 6]);
        let a = Record::from_rdata(host(), 120, RData::A(A(Ipv4Addr::new(10, 0, 40, 98))));
        let short =
            Message::from_vec(&encode_response(&Response { answers: vec![a], ..Default::default() }).unwrap()).unwrap();
        let later = now + Duration::from_secs(5000);
        assert_eq!(cache.learn(other, Ipv4Addr::new(10, 0, 40, 98), &short, later), 1);
        assert_eq!(cache.expire(later + Duration::from_secs(121)), 1);
        assert!(cache.source(other).is_some_and(|s| s.records.is_empty()));
        cache.expire(later + EMPTY_SOURCE_MEMORY);
        assert!(cache.source(other).is_none());
    }

    #[test]
    fn requeries_registered_records_at_half_their_ttl() {
        let now = Instant::now();
        let mut cache = cache_with_cast(now);
        assert!(cache.requeries(now + Duration::from_secs(59), |_| true).is_empty());
        let due = cache.requeries(now + Duration::from_secs(60), |_| true);
        let types: Vec<_> = due.iter().map(|q| (q.name.clone(), q.query_type)).collect();
        assert_eq!(due.len(), 2, "SRV and A at 50 % of 120 s: {types:?}");
        assert!(cache.requeries(now + Duration::from_secs(61), |_| true).is_empty(), "asked once per threshold");
        assert_eq!(cache.requeries(now + Duration::from_secs(96), |_| true).len(), 2, "again at 80 %");
        assert!(cache.requeries(now + Duration::from_secs(100), |_| true).is_empty());
        let mut fresh = cache_with_cast(now);
        assert!(
            fresh.requeries(now + Duration::from_secs(100), |_| false).is_empty(),
            "unclaimed sources are not asked"
        );
    }
}
