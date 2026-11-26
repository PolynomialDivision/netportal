//! The decision: what to answer, to whom, how. A pure function over the parsed query, the
//! querier (MAC and address), the cache and the registry view (RFC 6762 §5.4, §6, §6.7, §7.1;
//! design 6.5):
//!
//! - the querier's MAC names the person (an unknown MAC: nobody); a person reaches the devices
//!   the access view lists (owner, share or house); nobody reaches house-visible devices only;
//!   with a stale registry, everyone is nobody;
//! - private devices are answered by unicast to the querier, and only when the question asked
//!   for it (the QU bit) or the query is a legacy one (source port other than 5353); a QM
//!   question about a private device gets no answer at all (everything multicast is seen by the
//!   whole VLAN);
//! - house-visible devices are answered by multicast (after the shared random delay, applied by
//!   the caller), plus unicast when the question asked for it; a legacy query only by unicast;
//! - records the query already lists with at least half the TTL left are not repeated; TTLs
//!   are the remaining announced TTL capped at the configured one (10 s for a legacy answer);
//!   the cache-flush bit stays as the device set it (never in a legacy answer);
//! - never a name that is not in the cache: the proxy has no records of its own.

use std::net::SocketAddrV4;
use std::time::Instant;

use crate::cache::{Cache, Cached, Source};
use crate::frame::{MDNS_PORT, Mac};
use crate::registry::View;
use crate::wire::{self, DNSClass, LEGACY_TTL, Message, Name, Query, RData, Record, RecordType};

/// Who asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Querier {
    pub mac: Mac,
    pub addr: SocketAddrV4,
}

/// How an answer leaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// to the querier's address, at once
    Unicast,
    /// to the group, after the shared random delay (20-120 ms)
    Multicast,
}

/// One response datagram to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub delivery: Delivery,
    /// the response to a legacy query: id and questions repeated, short TTLs, no cache-flush
    pub legacy: bool,
    pub response: wire::Response,
}

impl Answer {
    pub fn records(&self) -> impl Iterator<Item = &Record> {
        self.response.answers.iter().chain(&self.response.additionals)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reach {
    Private,
    House,
}

/// Records picked for one delivery, in order, without duplicates.
#[derive(Default)]
struct Picked<'c> {
    answers: Vec<&'c Cached>,
    additionals: Vec<&'c Cached>,
}

fn push_unique<'c>(list: &mut Vec<&'c Cached>, cached: &'c Cached) {
    if !list.iter().any(|c| c.record == cached.record) {
        list.push(cached);
    }
}

impl<'c> Picked<'c> {
    fn merge(&mut self, other: &Picked<'c>) {
        for c in &other.answers {
            push_unique(&mut self.answers, c);
        }
        for c in &other.additionals {
            push_unique(&mut self.additionals, c);
        }
    }
}

/// The SRV and TXT of an instance, with the addresses of the SRV target (RFC 6763 §12.1).
fn instance_records<'c>(source: &'c Source, instance: &Name, now: Instant, out: &mut Vec<&'c Cached>) {
    for cached in source.find(instance, None).filter(|c| c.remaining(now) > 0) {
        match &cached.record.data {
            RData::SRV(srv) => {
                push_unique(out, cached);
                host_records(source, &srv.target, now, out);
            }
            RData::TXT(_) => push_unique(out, cached),
            _ => {}
        }
    }
}

/// The A/AAAA records of a host name (RFC 6763 §12.2).
fn host_records<'c>(source: &'c Source, host: &Name, now: Instant, out: &mut Vec<&'c Cached>) {
    for cached in source.find(host, None).filter(|c| c.remaining(now) > 0) {
        if matches!(cached.record.record_type(), RecordType::A | RecordType::AAAA) {
            push_unique(out, cached);
        }
    }
}

/// What one source has for one question.
fn pick<'c>(question: &Query, source: &'c Source, now: Instant) -> Picked<'c> {
    let mut picked = Picked::default();
    let live = |c: &&Cached| c.remaining(now) > 0;
    match question.query_type {
        RecordType::PTR => {
            for cached in source.find(&question.name, Some(RecordType::PTR)).filter(live) {
                push_unique(&mut picked.answers, cached);
                if let RData::PTR(target) = &cached.record.data {
                    instance_records(source, target, now, &mut picked.additionals);
                }
            }
        }
        RecordType::SRV => {
            for cached in source.find(&question.name, Some(RecordType::SRV)).filter(live) {
                push_unique(&mut picked.answers, cached);
                if let RData::SRV(srv) = &cached.record.data {
                    host_records(source, &srv.target, now, &mut picked.additionals);
                }
            }
        }
        RecordType::TXT | RecordType::A | RecordType::AAAA => {
            for cached in source.find(&question.name, Some(question.query_type)).filter(live) {
                push_unique(&mut picked.answers, cached);
            }
        }
        RecordType::ANY => {
            for cached in source.find(&question.name, None).filter(live) {
                push_unique(&mut picked.answers, cached);
                match &cached.record.data {
                    RData::PTR(target) => instance_records(source, target, now, &mut picked.additionals),
                    RData::SRV(srv) => host_records(source, &srv.target, now, &mut picked.additionals),
                    _ => {}
                }
            }
        }
        _ => {}
    }
    picked
}

/// The records as sent: the remaining TTL capped, the cache-flush bit as announced (never for
/// a legacy answer), known answers left out.
fn finish(
    picked: Picked<'_>,
    delivery: Delivery,
    legacy: bool,
    query: &Message,
    ttl_cap: u32,
    now: Instant,
) -> Option<Answer> {
    let cap = if legacy { ttl_cap.min(LEGACY_TTL) } else { ttl_cap };
    let prepare = |c: &&Cached| {
        let mut record = c.record.clone();
        record.ttl = c.remaining(now).min(cap);
        record.mdns_cache_flush = c.record.mdns_cache_flush && !legacy;
        record
    };
    let answers: Vec<Record> =
        picked.answers.iter().map(prepare).filter(|r| !wire::is_known(&query.answers, r, r.ttl)).collect();
    if answers.is_empty() {
        return None;
    }
    let additionals: Vec<Record> = picked
        .additionals
        .iter()
        .map(prepare)
        .filter(|r| !answers.contains(r) && !wire::is_known(&query.answers, r, r.ttl))
        .collect();
    let response = wire::Response {
        id: if legacy { query.id } else { 0 },
        questions: if legacy { query.queries.clone() } else { Vec::new() },
        answers,
        additionals,
    };
    Some(Answer { delivery, legacy, response })
}

/// The answers to one query: at most one unicast and one multicast datagram.
pub fn decide(
    query: &Message,
    querier: &Querier,
    cache: &Cache,
    view: View<'_>,
    ttl_cap: u32,
    now: Instant,
) -> Vec<Answer> {
    if !wire::is_query(query) {
        return Vec::new();
    }
    let (snapshot, house_only) = match view {
        View::Full(s) => (s, false),
        View::HouseOnly(s) => (s, true),
        View::Nothing => return Vec::new(),
    };
    let legacy = querier.addr.port() != MDNS_PORT;
    let person = if house_only { None } else { snapshot.person_of(querier.mac) };
    let reachable: Vec<(&Source, Reach)> = cache
        .sources()
        .filter_map(|source| {
            let device = snapshot.device_of(source.mac)?;
            if device.visibility == "house" {
                Some((source, Reach::House))
            } else if person.is_some_and(|p| snapshot.may_reach(p, device.device_id)) {
                Some((source, Reach::Private))
            } else {
                None
            }
        })
        .collect();
    if reachable.is_empty() {
        return Vec::new();
    }
    let mut unicast = Picked::default();
    let mut multicast = Picked::default();
    for question in &query.queries {
        if !matches!(question.query_class, DNSClass::IN | DNSClass::ANY) {
            continue;
        }
        let unicast_wanted = legacy || question.mdns_unicast_response;
        for (source, reach) in &reachable {
            let (to_unicast, to_multicast) = match reach {
                Reach::Private => (unicast_wanted, false),
                Reach::House => (unicast_wanted, !legacy),
            };
            if !to_unicast && !to_multicast {
                continue;
            }
            let picked = pick(question, source, now);
            if to_unicast {
                unicast.merge(&picked);
            }
            if to_multicast {
                multicast.merge(&picked);
            }
        }
    }
    let mut out = Vec::new();
    out.extend(finish(unicast, Delivery::Unicast, legacy, query, ttl_cap, now));
    out.extend(finish(multicast, Delivery::Multicast, false, query, ttl_cap, now));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::testing::*;
    use crate::registry::Snapshot;
    use crate::registry::testing::*;
    use crate::wire::{encode_query, name, ptr_question};
    use std::net::Ipv4Addr;
    use std::time::Duration;

    const TTL_CAP: u32 = 120;

    fn querier(mac: Mac, port: u16) -> Querier {
        Querier { mac, addr: SocketAddrV4::new(Ipv4Addr::new(10, 0, 30, 7), port) }
    }

    fn query(questions: Vec<Query>, known: Vec<Record>) -> Message {
        Message::from_vec(&encode_query(questions, known).unwrap()).unwrap()
    }

    fn qu(mut question: Query) -> Query {
        question.set_mdns_unicast_response(true);
        question
    }

    fn private_snapshot() -> Snapshot {
        snapshot(device(CAST_MAC, "alice", "cast", "private"))
    }

    fn types(answer: &Answer) -> Vec<RecordType> {
        answer.records().map(Record::record_type).collect()
    }

    #[test]
    fn qu_ptr_from_the_owner_is_answered_by_unicast_with_capped_ttls() {
        let now = Instant::now();
        let cache = cache_with_cast(now);
        let s = private_snapshot();
        let q = query(vec![qu(ptr_question(service()))], vec![]);
        let answers =
            decide(&q, &querier(ALICE_MAC, 5353), &cache, View::Full(&s), TTL_CAP, now + Duration::from_secs(30));
        assert_eq!(answers.len(), 1);
        let a = &answers[0];
        assert_eq!(a.delivery, Delivery::Unicast);
        assert!(!a.legacy);
        assert_eq!(types(a), [RecordType::PTR, RecordType::SRV, RecordType::A, RecordType::TXT]);
        assert_eq!(a.response.id, 0);
        assert!(a.response.questions.is_empty());
        let ttls: Vec<u32> = a.records().map(|r| r.ttl).collect();
        assert_eq!(ttls, [120, 90, 90, 120], "4500 capped, 120 minus 30 s remaining");
        let flush: Vec<bool> = a.records().map(|r| r.mdns_cache_flush).collect();
        assert_eq!(flush, [false, true, true, true]);
    }

    #[test]
    fn without_access_nothing_is_answered() {
        let now = Instant::now();
        let cache = cache_with_cast(now);
        let s = private_snapshot();
        let q = query(vec![qu(ptr_question(service()))], vec![]);
        assert!(decide(&q, &querier(BOB_MAC, 5353), &cache, View::Full(&s), TTL_CAP, now).is_empty(), "no share");
        assert!(decide(&q, &querier(Mac::ZERO, 5353), &cache, View::Full(&s), TTL_CAP, now).is_empty(), "nobody");
        let unknown = query(vec![qu(ptr_question(name("_ipp._tcp.local").unwrap()))], vec![]);
        assert!(
            decide(&unknown, &querier(ALICE_MAC, 5353), &cache, View::Full(&s), TTL_CAP, now).is_empty(),
            "not cached"
        );
        assert!(
            decide(&q, &querier(ALICE_MAC, 5353), &Cache::new(), View::Full(&s), TTL_CAP, now).is_empty(),
            "empty cache"
        );
        assert!(decide(&q, &querier(ALICE_MAC, 5353), &cache, View::Nothing, TTL_CAP, now).is_empty(), "no registry");
        let unclaimed = snapshot(device(Mac([9; 6]), "alice", "cast", "house"));
        assert!(
            decide(&q, &querier(ALICE_MAC, 5353), &cache, View::Full(&unclaimed), TTL_CAP, now).is_empty(),
            "MAC not registered"
        );
    }

    #[test]
    fn qm_for_a_private_device_is_not_answered() {
        let now = Instant::now();
        let cache = cache_with_cast(now);
        let s = private_snapshot();
        let q = query(vec![ptr_question(service())], vec![]);
        assert!(decide(&q, &querier(ALICE_MAC, 5353), &cache, View::Full(&s), TTL_CAP, now).is_empty());
    }

    #[test]
    fn house_visible_devices_are_multicast_and_also_unicast_for_qu() {
        let now = Instant::now();
        let cache = cache_with_cast(now);
        let s = snapshot(device(CAST_MAC, "alice", "cast", "house"));
        let qm = query(vec![ptr_question(service())], vec![]);
        let answers = decide(&qm, &querier(Mac::ZERO, 5353), &cache, View::Full(&s), TTL_CAP, now);
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].delivery, Delivery::Multicast);
        assert_eq!(types(&answers[0]).len(), 4);
        let qu_query = query(vec![qu(ptr_question(service()))], vec![]);
        let answers = decide(&qu_query, &querier(BOB_MAC, 5353), &cache, View::Full(&s), TTL_CAP, now);
        let deliveries: Vec<Delivery> = answers.iter().map(|a| a.delivery).collect();
        assert_eq!(deliveries, [Delivery::Unicast, Delivery::Multicast]);
        // the stale rule: house-visible devices still, private ones not
        let answers = decide(&qm, &querier(ALICE_MAC, 5353), &cache, View::HouseOnly(&s), TTL_CAP, now);
        assert_eq!(answers.len(), 1);
        let private = private_snapshot();
        let q = query(vec![qu(ptr_question(service()))], vec![]);
        assert!(decide(&q, &querier(ALICE_MAC, 5353), &cache, View::HouseOnly(&private), TTL_CAP, now).is_empty());
    }

    #[test]
    fn known_answers_are_suppressed() {
        let now = Instant::now();
        let cache = cache_with_cast(now);
        let s = private_snapshot();
        let mut known = cast_records().swap_remove(0);
        known.ttl = 100;
        let q = query(vec![qu(ptr_question(service()))], vec![known.clone()]);
        assert!(decide(&q, &querier(ALICE_MAC, 5353), &cache, View::Full(&s), TTL_CAP, now).is_empty());
        known.ttl = 30;
        let q = query(vec![qu(ptr_question(service()))], vec![known]);
        assert_eq!(
            decide(&q, &querier(ALICE_MAC, 5353), &cache, View::Full(&s), TTL_CAP, now).len(),
            1,
            "less than half left"
        );
    }

    #[test]
    fn legacy_queries_get_a_unicast_answer_with_id_questions_and_short_ttls() {
        let now = Instant::now();
        let cache = cache_with_cast(now);
        let mut q = query(vec![ptr_question(service())], vec![]);
        q.metadata.id = 0x1234;
        let s = private_snapshot();
        let answers = decide(&q, &querier(ALICE_MAC, 40000), &cache, View::Full(&s), TTL_CAP, now);
        assert_eq!(answers.len(), 1);
        let a = &answers[0];
        assert_eq!((a.delivery, a.legacy, a.response.id), (Delivery::Unicast, true, 0x1234));
        assert_eq!(a.response.questions, q.queries);
        assert!(a.records().all(|r| r.ttl == LEGACY_TTL && !r.mdns_cache_flush));
        // a house-visible device: unicast only for a legacy query
        let house = snapshot(device(CAST_MAC, "alice", "cast", "house"));
        let answers = decide(&q, &querier(Mac::ZERO, 40000), &cache, View::Full(&house), TTL_CAP, now);
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].delivery, Delivery::Unicast);
    }

    #[test]
    fn instance_and_host_questions() {
        let now = Instant::now();
        let cache = cache_with_cast(now);
        let s = private_snapshot();
        let who = querier(ALICE_MAC, 5353);
        let srv = query(vec![qu(Query::query(instance(), RecordType::SRV))], vec![]);
        let answers = decide(&srv, &who, &cache, View::Full(&s), TTL_CAP, now);
        assert_eq!(types(&answers[0]), [RecordType::SRV, RecordType::A]);
        let a = query(vec![qu(Query::query(host(), RecordType::A))], vec![]);
        assert_eq!(types(&decide(&a, &who, &cache, View::Full(&s), TTL_CAP, now)[0]), [RecordType::A]);
        let any = query(vec![qu(Query::query(instance(), RecordType::ANY))], vec![]);
        assert_eq!(
            types(&decide(&any, &who, &cache, View::Full(&s), TTL_CAP, now)[0]),
            [RecordType::SRV, RecordType::TXT, RecordType::A]
        );
        let two = query(vec![qu(ptr_question(service())), qu(Query::query(host(), RecordType::A))], vec![]);
        let answers = decide(&two, &who, &cache, View::Full(&s), TTL_CAP, now);
        assert_eq!(answers.len(), 1, "one datagram for both questions");
        assert_eq!(answers[0].records().count(), 4, "the A record once");
        let aaaa = query(vec![qu(Query::query(host(), RecordType::AAAA))], vec![]);
        assert!(decide(&aaaa, &who, &cache, View::Full(&s), TTL_CAP, now).is_empty());
        let expired = decide(&srv, &who, &cache, View::Full(&s), TTL_CAP, now + Duration::from_secs(121));
        assert!(expired.is_empty(), "nothing past its TTL");
    }

    #[test]
    fn responses_and_other_opcodes_are_ignored() {
        let now = Instant::now();
        let cache = cache_with_cast(now);
        let s = private_snapshot();
        let response = Message::from_vec(&cast_announcement()).unwrap();
        assert!(decide(&response, &querier(ALICE_MAC, 5353), &cache, View::Full(&s), TTL_CAP, now).is_empty());
    }
}
