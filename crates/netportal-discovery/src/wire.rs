//! The DNS wire format through hickory-proto (never a parser of our own) and the mDNS
//! conventions on top (RFC 6762): the QU bit is the top bit of a question's class, the
//! cache-flush bit the top bit of a record's class (both handled by hickory's `mdns` feature); a
//! response carries id 0, QR and AA, no question (§6), except the response to a legacy query from
//! a port other than 5353 (§6.7), which repeats the id and the questions, carries no cache-flush
//! bit and TTLs of at most [`LEGACY_TTL`].

use hickory_proto::ProtoError;
pub use hickory_proto::op::{Message, MessageType, OpCode, Query};
pub use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};

/// Records in a legacy unicast response live at most this long (§6.7).
pub const LEGACY_TTL: u32 = 10;

/// Parses a datagram; `None` for anything hickory cannot read (a truncated or foreign packet).
pub fn parse(bytes: &[u8]) -> Option<Message> {
    Message::from_vec(bytes).ok()
}

/// A query (QR 0) with the standard opcode: the only messages the residents' leg answers.
pub fn is_query(message: &Message) -> bool {
    message.message_type == MessageType::Query && message.op_code == OpCode::Query
}

/// A fully qualified name from text (`_googlecast._tcp.local`): the form the wire uses, so it
/// compares equal to decoded names. `None` for text hickory refuses.
pub fn name(text: &str) -> Option<Name> {
    let mut name = Name::from_ascii(text).ok()?;
    name.set_fqdn(true);
    Some(name)
}

/// A PTR question for a service type (QM: the answers are multicast, as a browser expects).
pub fn ptr_question(service: Name) -> Query {
    Query::query(service, RecordType::PTR)
}

/// A query message (id 0, RFC 6762 §18.1) with its questions and known answers.
pub fn encode_query(questions: Vec<Query>, known: Vec<Record>) -> Result<Vec<u8>, ProtoError> {
    let mut message = Message::new(0, MessageType::Query, OpCode::Query);
    message.queries = questions;
    message.answers = known;
    message.to_vec()
}

/// What goes into a response.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Response {
    /// 0, or the query's id for a legacy query
    pub id: u16,
    /// empty, or the query's questions for a legacy query
    pub questions: Vec<Query>,
    pub answers: Vec<Record>,
    pub additionals: Vec<Record>,
}

/// An authoritative response (QR, AA, opcode 0, rcode 0).
pub fn encode_response(response: &Response) -> Result<Vec<u8>, ProtoError> {
    let mut message = Message::response(response.id, OpCode::Query);
    message.metadata.authoritative = true;
    message.queries = response.questions.clone();
    message.answers = response.answers.clone();
    message.additionals = response.additionals.clone();
    message.to_vec()
}

/// Known-answer suppression (§7.1): the querier listed this record with at least half the TTL
/// we would send, so it is not repeated. Record equality is name, class and rdata (case-insensitive
/// names), the RFC's rule.
pub fn is_known(known: &[Record], record: &Record, ttl: u32) -> bool {
    known.iter().any(|k| k == record && k.ttl >= ttl / 2)
}

/// `name TYPE ttl [flush] -> data` for logs and the probe.
pub fn describe_record(record: &Record) -> String {
    let flush = if record.mdns_cache_flush { " flush" } else { "" };
    let data = match &record.data {
        RData::PTR(target) => target.to_utf8(),
        RData::SRV(srv) => format!("{}:{}", srv.target.to_utf8(), srv.port),
        RData::A(a) => a.0.to_string(),
        RData::AAAA(aaaa) => aaaa.0.to_string(),
        RData::TXT(txt) => format!("{} strings", txt.txt_data.len()),
        other => other.record_type().to_string(),
    };
    format!("{} {} ttl {}{flush} -> {data}", record.name.to_utf8(), record.record_type(), record.ttl)
}

/// One line for logs and the probe: the questions of a query (with QU), the records of a response.
pub fn describe(message: &Message) -> String {
    if is_query(message) {
        let questions: Vec<String> = message
            .queries
            .iter()
            .map(|q| {
                let qu = if q.mdns_unicast_response { " QU" } else { "" };
                format!("{} {}{qu}", q.name.to_utf8(), q.query_type)
            })
            .collect();
        let known = message.answers.len();
        format!("query {} [{}] {known} known", message.id, questions.join(", "))
    } else {
        let records: Vec<String> = message.answers.iter().chain(&message.additionals).map(describe_record).collect();
        format!("response [{}]", records.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::{A, PTR};
    use std::net::Ipv4Addr;

    #[test]
    fn names_from_text_equal_names_from_the_wire() {
        let wire = Message::from_vec(
            &encode_query(vec![ptr_question(name("_googlecast._tcp.local").unwrap())], vec![]).unwrap(),
        )
        .unwrap();
        assert_eq!(wire.queries[0].name, name("_GoogleCast._tcp.local").unwrap());
        assert!(wire.queries[0].name.is_fqdn());
        assert!(name("").is_none() || name("").unwrap().is_root());
    }

    #[test]
    fn qu_and_cache_flush_bits_round_trip() {
        let mut q = ptr_question(name("_airplay._tcp.local").unwrap());
        q.set_mdns_unicast_response(true);
        let bytes = encode_query(vec![q], vec![]).unwrap();
        // the question class: 0x8001 = QU | IN
        assert_eq!(&bytes[bytes.len() - 2..], &[0x80, 0x01]);
        let parsed = parse(&bytes).unwrap();
        assert!(parsed.queries[0].mdns_unicast_response);
        assert_eq!(parsed.queries[0].query_class, DNSClass::IN);

        let mut a = Record::from_rdata(name("tv.local").unwrap(), 120, RData::A(A(Ipv4Addr::new(10, 0, 40, 9))));
        a.mdns_cache_flush = true;
        let ptr = Record::from_rdata(
            name("_airplay._tcp.local").unwrap(),
            4500,
            RData::PTR(PTR(name("TV._airplay._tcp.local").unwrap())),
        );
        let bytes =
            encode_response(&Response { answers: vec![ptr], additionals: vec![a.clone()], ..Default::default() })
                .unwrap();
        assert_eq!(bytes[..4], [0, 0, 0x84, 0], "id 0, QR and AA, no RD");
        let parsed = parse(&bytes).unwrap();
        assert!(!is_query(&parsed));
        assert!(parsed.additionals[0].mdns_cache_flush);
        assert!(!parsed.answers[0].mdns_cache_flush);
        assert_eq!(parsed.additionals[0], a);
        let text = describe(&parsed);
        assert!(text.contains("_airplay._tcp.local. PTR ttl 4500 -> TV._airplay._tcp.local."), "{text}");
        assert!(text.contains("tv.local. A ttl 120 flush -> 10.0.40.9"), "{text}");
    }

    #[test]
    fn known_answers() {
        let ptr = Record::from_rdata(
            name("_airplay._tcp.local").unwrap(),
            60,
            RData::PTR(PTR(name("TV._airplay._tcp.local").unwrap())),
        );
        // we would send a TTL of 120: a known answer with at least 60 s left is not repeated
        let mut known = ptr.clone();
        known.ttl = 60;
        assert!(is_known(&[known.clone()], &ptr, 120));
        known.ttl = 59;
        assert!(!is_known(&[known.clone()], &ptr, 120));
        let other = Record::from_rdata(
            name("_airplay._tcp.local").unwrap(),
            120,
            RData::PTR(PTR(name("Other._airplay._tcp.local").unwrap())),
        );
        assert!(!is_known(&[other], &ptr, 120));
    }
}
