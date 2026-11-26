//! RADIUS Dynamic Authorization (RFC 5176): a Disconnect-Request to the access point that
//! holds a device's session, so a revocation or a policy move takes effect now and not at the
//! next re-authentication (Python `netportal/disconnect.py`).
//!
//! Small on purpose (no RADIUS library): one request, retransmitted unchanged, one answer.
//!
//! * **Request.** Code 40, a random identifier, attributes `Message-Authenticator (80)` (first),
//!   `User-Name (1)` and `Calling-Station-Id (31)` as the access point recorded them,
//!   `Acct-Session-Id (44)` when the request is for one accounting session (the reconciliation's:
//!   hostapd then cuts only that session and answers a NAK with Error-Cause 503 when it has no
//!   such session) (each left out when empty: RFC 2865 5 forbids zero-length values),
//!   `NAS-IP-Address (4)`, `Event-Timestamp (55)` (hostapd drops a request outside its 300 s
//!   window and, with `radius_das_require_event_timestamp`, one without it). Message-Authenticator is HMAC-MD5 over
//!   the packet with the authenticator field and its own value zeroed (RFC 5176 3.3, RFC 3579
//!   3.2); the Request Authenticator is MD5(Code, Identifier, Length, 16 zero octets,
//!   Attributes, Secret) over the final attributes (RFC 5176 2.3). Message-Authenticator is the
//!   first attribute, as the BlastRADIUS mitigations recommend for every packet (hostapd and
//!   FreeRADIUS put it first in their own replies; its position does not matter to a receiver).
//! * **Replies** are accepted only from the NAS address and port the request went to (connected
//!   socket: the kernel drops datagrams from any other source), with the same identifier, code
//!   41 or 42, a valid Response Authenticator (MD5(Code, Identifier, Length, Request
//!   Authenticator, Attributes, Secret)), well-formed attributes and a valid Message-Authenticator
//!   (computed with the Request Authenticator in the authenticator field; at most one). Anything
//!   else is ignored and the wait goes on, so a forged or stale datagram cannot end it. These
//!   checks hold whatever the configuration says. The Python version checked the Response
//!   Authenticator only.
//! * **The one setting** [`DaeConfig::require_reply_message_authenticator`]
//!   (`NETPORTAL_DAE_REQUIRE_REPLY_MESSAGE_AUTHENTICATOR`, default on) only decides whether a
//!   reply WITHOUT Message-Authenticator is accepted. hostapd (`radius_das.c`, every UniFi access
//!   point) adds one to every Disconnect-ACK/NAK, so it stays on; turn it off only after the test
//!   against the real UniFi access points (docs/CUTOVER.md) showed that they do not sign. With it
//!   off, a reply without one still needs its Response Authenticator (keyed MD5 with the secret),
//!   a present but wrong or doubled one is still refused, and every accepted unsigned reply is
//!   logged as a warning. The damage of a forged ACK (the device keeps its session) is bounded by
//!   the reconciliation (`netportal_offboard::recheck`): a revoked device's session that is still
//!   live in accounting is disconnected again.
//! * **Timing.** 2 s per try, 3 tries (RFC 5080 2.2.1: retransmissions keep the identifier and
//!   the authenticator), then `timeout`.
//! * **Result.** [`Outcome`]: `ack`, `nak` (with the Error-Cause, RFC 5176 3.6), `timeout`,
//!   `error` (no IPv4 NAS address, an unreachable network, an attribute too long), `skipped`
//!   (no DAE secret configured) and `no-session` (nothing to disconnect). Its
//!   [`Outcome::label`] is the audit (`disconnect:<label>`) and metric label.

use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use md5::{Digest, Md5};
use subtle::ConstantTimeEq;
use tokio::net::UdpSocket;
use zeroize::Zeroizing;

pub const DISCONNECT_REQUEST: u8 = 40;
pub const DISCONNECT_ACK: u8 = 41;
pub const DISCONNECT_NAK: u8 = 42;

pub const USER_NAME: u8 = 1;
pub const NAS_IP_ADDRESS: u8 = 4;
pub const CALLING_STATION_ID: u8 = 31;
pub const ACCT_SESSION_ID: u8 = 44;
pub const EVENT_TIMESTAMP: u8 = 55;
pub const MESSAGE_AUTHENTICATOR: u8 = 80;
pub const ERROR_CAUSE: u8 = 101;

/// RFC 2865 3: the largest RADIUS packet.
const MAX_PACKET: usize = 4096;

/// A RADIUS session of a device, as the registry knows it (`radius_session`, `radius_acct`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Session {
    /// NAS-IP-Address (or the packet source) of the access point
    pub nas_ip: String,
    /// Calling-Station-Id as the access point sent it
    pub calling_station: String,
    /// the outer User-Name
    pub user_name: String,
    /// the accounting session's Acct-Session-Id to cut only that session; empty: every session
    /// of the MAC
    pub acct_session_id: String,
}

/// Where and how Disconnect-Requests go (`NETPORTAL_DAE_SECRET`, `NETPORTAL_DAE_PORT`).
#[derive(Clone)]
pub struct DaeConfig {
    secret: Zeroizing<Vec<u8>>,
    /// the access points' DAE port (3799)
    pub port: u16,
    /// wait per try (2 s)
    pub timeout: Duration,
    /// tries in all, the first included (3)
    pub tries: u32,
    /// refuse replies without Message-Authenticator (on)
    pub require_reply_message_authenticator: bool,
}

impl std::fmt::Debug for DaeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DaeConfig")
            .field("port", &self.port)
            .field("timeout", &self.timeout)
            .field("tries", &self.tries)
            .field("require_reply_message_authenticator", &self.require_reply_message_authenticator)
            .finish_non_exhaustive()
    }
}

impl DaeConfig {
    /// The defaults: 2 s per try, 3 tries, Message-Authenticator required on replies.
    pub fn new(secret: &[u8], port: u16) -> Self {
        DaeConfig {
            secret: Zeroizing::new(secret.to_vec()),
            port,
            timeout: Duration::from_secs(2),
            tries: 3,
            require_reply_message_authenticator: true,
        }
    }
}

/// An RFC 5176 3.6 Error-Cause value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ErrorCause(pub u32);

impl ErrorCause {
    /// The RFC 5176 name, if the value is one of its registry.
    pub fn name(self) -> Option<&'static str> {
        Some(match self.0 {
            201 => "Residual Session Context Removed",
            202 => "Invalid EAP Packet (Ignored)",
            401 => "Unsupported Attribute",
            402 => "Missing Attribute",
            403 => "NAS Identification Mismatch",
            404 => "Invalid Request",
            405 => "Unsupported Service",
            406 => "Unsupported Extension",
            407 => "Invalid Attribute Value",
            501 => "Administratively Prohibited",
            502 => "Request Not Routable (Proxy)",
            503 => "Session Context Not Found",
            504 => "Session Context Not Removable",
            505 => "Other Proxy Processing Error",
            506 => "Resources Unavailable",
            507 => "Request Initiated",
            508 => "Multiple Session Selection Unsupported",
            _ => return None,
        })
    }
}

/// Why no request could be sent.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DisconnectError {
    #[error("the NAS address {0:?} is not an IPv4 address")]
    NoIpv4Address(String),
    #[error("{0} is longer than 253 octets")]
    AttributeTooLong(&'static str),
    #[error("network: {0}")]
    Io(String),
}

/// The result of one Disconnect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Disconnect-ACK: the session is gone
    Ack,
    /// Disconnect-NAK, with the Error-Cause if the access point gave one
    Nak { error_cause: Option<ErrorCause> },
    /// no valid reply after every try
    Timeout,
    /// nothing could be sent
    Error(DisconnectError),
    /// no DAE secret configured
    Skipped,
    /// no RADIUS session known for the device
    NoSession,
}

impl Outcome {
    /// The audit (`disconnect:<label>`) and metric label, as in the Python version, except
    /// `not-found` (a NAK with Error-Cause 503: the access point has no such session), which
    /// Python counted as `nak`.
    pub fn label(&self) -> &'static str {
        match self {
            Outcome::Ack => "ack",
            Outcome::Nak { error_cause: Some(SESSION_CONTEXT_NOT_FOUND) } => "not-found",
            Outcome::Nak { .. } => "nak",
            Outcome::Timeout => "timeout",
            Outcome::Error(_) => "error",
            Outcome::Skipped => "skipped",
            Outcome::NoSession => "no-session",
        }
    }
}

fn hmac_md5(secret: &[u8], parts: &[&[u8]]) -> [u8; 16] {
    // HMAC accepts keys of any length; the error branch cannot happen
    let mut mac = match <Hmac<Md5> as KeyInit>::new_from_slice(secret) {
        Ok(mac) => mac,
        Err(_) => return [0; 16],
    };
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

fn md5(parts: &[&[u8]]) -> [u8; 16] {
    let mut h = Md5::new();
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}

fn attr(out: &mut Vec<u8>, kind: u8, value: &[u8], name: &'static str) -> Result<(), DisconnectError> {
    if value.len() > 253 {
        return Err(DisconnectError::AttributeTooLong(name));
    }
    out.push(kind);
    out.push(value.len() as u8 + 2);
    out.extend_from_slice(value);
    Ok(())
}

/// The Disconnect-Request packet (deterministic for given inputs); empty values are left out.
pub fn build_request(
    identifier: u8,
    secret: &[u8],
    user_name: &str,
    calling_station: &str,
    acct_session_id: &str,
    nas_ip: Ipv4Addr,
    event_timestamp: u32,
) -> Result<Vec<u8>, DisconnectError> {
    let mut attrs = Vec::new();
    attr(&mut attrs, MESSAGE_AUTHENTICATOR, &[0; 16], "Message-Authenticator")?;
    if !user_name.is_empty() {
        attr(&mut attrs, USER_NAME, user_name.as_bytes(), "User-Name")?;
    }
    if !calling_station.is_empty() {
        attr(&mut attrs, CALLING_STATION_ID, calling_station.as_bytes(), "Calling-Station-Id")?;
    }
    if !acct_session_id.is_empty() {
        attr(&mut attrs, ACCT_SESSION_ID, acct_session_id.as_bytes(), "Acct-Session-Id")?;
    }
    attr(&mut attrs, NAS_IP_ADDRESS, &nas_ip.octets(), "NAS-IP-Address")?;
    attr(&mut attrs, EVENT_TIMESTAMP, &event_timestamp.to_be_bytes(), "Event-Timestamp")?;
    let length = 20 + attrs.len(); // at most 20 + 18 + 3 * 255 + 6 + 6, far below 4096
    let header = [DISCONNECT_REQUEST, identifier, (length >> 8) as u8, length as u8];
    let ma = hmac_md5(secret, &[&header, &[0; 16], &attrs]);
    attrs[2..18].copy_from_slice(&ma);
    let authenticator = md5(&[&header, &[0; 16], &attrs, secret]);
    Ok([&header[..], &authenticator, &attrs].concat())
}

/// The attributes of a packet as (type, value); None if the list is malformed.
pub fn parse_attributes(data: &[u8]) -> Option<Vec<(u8, &[u8])>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let kind = *data.get(i)?;
        let len = usize::from(*data.get(i + 1)?);
        if len < 2 || i + len > data.len() {
            return None;
        }
        out.push((kind, &data[i + 2..i + len]));
        i += len;
    }
    Some(out)
}

/// A reply that answers the request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    pub code: u8,
    pub error_cause: Option<ErrorCause>,
    /// it carried a (valid) Message-Authenticator; `false` only when the check allowed a reply
    /// without one
    pub signed: bool,
}

/// Error-Cause 503 Session-Context-Not-Found (RFC 5176 3.6): the access point has no such
/// session.
pub const SESSION_CONTEXT_NOT_FOUND: ErrorCause = ErrorCause(503);

/// [`check_reply`]'s refusal of a reply whose Response Authenticator is right but which carries
/// no Message-Authenticator (while one is required).
pub const NO_MESSAGE_AUTHENTICATOR: &str = "no Message-Authenticator";

/// Checks a datagram against the request it should answer (see the module docs); the error
/// says why it was ignored. `require_message_authenticator` only decides about a reply without
/// Message-Authenticator; every other check is unconditional.
pub fn check_reply(
    datagram: &[u8],
    request: &[u8],
    secret: &[u8],
    require_message_authenticator: bool,
) -> Result<Reply, &'static str> {
    if datagram.len() < 20 || request.len() < 20 {
        return Err("shorter than a RADIUS header");
    }
    let length = usize::from(u16::from_be_bytes([datagram[2], datagram[3]]));
    if length < 20 || length > datagram.len() || length > MAX_PACKET {
        return Err("bad length field");
    }
    let packet = &datagram[..length]; // octets beyond Length are padding (RFC 2865 3)
    if packet[1] != request[1] {
        return Err("other identifier");
    }
    let code = packet[0];
    if code != DISCONNECT_ACK && code != DISCONNECT_NAK {
        return Err("not a Disconnect-ACK or -NAK");
    }
    let request_authenticator = &request[4..20];
    let expected = md5(&[&packet[..4], request_authenticator, &packet[20..], secret]);
    if !bool::from(expected.ct_eq(&packet[4..20])) {
        return Err("bad Response Authenticator");
    }
    let attrs = parse_attributes(&packet[20..]).ok_or("malformed attributes")?;
    let mut offset = 20;
    let mut ma_seen = false;
    for (kind, value) in &attrs {
        if *kind == MESSAGE_AUTHENTICATOR {
            if value.len() != 16 || ma_seen {
                return Err("bad Message-Authenticator");
            }
            let mut zeroed = packet.to_vec();
            zeroed[4..20].copy_from_slice(request_authenticator);
            zeroed[offset + 2..offset + 18].fill(0);
            if !bool::from(hmac_md5(secret, &[&zeroed]).ct_eq(value)) {
                return Err("bad Message-Authenticator");
            }
            ma_seen = true;
        }
        offset += 2 + value.len();
    }
    if require_message_authenticator && !ma_seen {
        return Err(NO_MESSAGE_AUTHENTICATOR);
    }
    let error_cause = attrs
        .iter()
        .find(|(kind, value)| *kind == ERROR_CAUSE && value.len() == 4)
        .map(|(_, v)| ErrorCause(u32::from_be_bytes([v[0], v[1], v[2], v[3]])));
    Ok(Reply { code, error_cause, signed: ma_seen })
}

/// Sends a Disconnect-Request for a stored session and waits for its answer.
pub async fn disconnect(session: Option<&Session>, dae: Option<&DaeConfig>) -> Outcome {
    let Some(dae) = dae.filter(|d| !d.secret.is_empty()) else {
        return Outcome::Skipped;
    };
    let Some(session) = session else {
        return Outcome::NoSession;
    };
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let outcome = send(session, dae, u32::try_from(now).unwrap_or(u32::MAX)).await;
    tracing::debug!(nas = %session.nas_ip, result = outcome.label(), "Disconnect-Request");
    outcome
}

/// Every reply accepted without Message-Authenticator (the requirement is off) is logged: its
/// only protection is the Response Authenticator.
fn unsigned_reply_accepted(nas: Ipv4Addr) {
    tracing::warn!(
        target: "netportal.disconnect",
        "accepted a Disconnect reply from {nas} without Message-Authenticator \
         (NETPORTAL_DAE_REQUIRE_REPLY_MESSAGE_AUTHENTICATOR=false; only its Response Authenticator was checked)"
    );
}

fn io_error(e: std::io::Error) -> Outcome {
    Outcome::Error(DisconnectError::Io(e.to_string()))
}

async fn send(session: &Session, dae: &DaeConfig, event_timestamp: u32) -> Outcome {
    let Ok(nas) = session.nas_ip.trim().parse::<Ipv4Addr>() else {
        return Outcome::Error(DisconnectError::NoIpv4Address(session.nas_ip.clone()));
    };
    let mut id = [0u8; 1];
    if let Err(e) = openssl::rand::rand_bytes(&mut id) {
        return Outcome::Error(DisconnectError::Io(e.to_string()));
    }
    let packet = match build_request(
        id[0],
        &dae.secret,
        &session.user_name,
        &session.calling_station,
        &session.acct_session_id,
        nas,
        event_timestamp,
    ) {
        Ok(packet) => packet,
        Err(e) => return Outcome::Error(e),
    };
    let socket = match UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await {
        Ok(socket) => socket,
        Err(e) => return io_error(e),
    };
    if let Err(e) = socket.connect((nas, dae.port)).await {
        return io_error(e);
    }
    let mut buf = vec![0u8; MAX_PACKET];
    for _ in 0..dae.tries.max(1) {
        match socket.send(&packet).await {
            Ok(_) => {}
            // an ICMP port unreachable of the previous try, reported on this send
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => continue,
            Err(e) => return io_error(e),
        }
        let deadline = tokio::time::Instant::now() + dae.timeout;
        loop {
            match tokio::time::timeout_at(deadline, socket.recv(&mut buf)).await {
                Err(_) => break,
                // ICMP port unreachable: nobody listens; the next try may still be answered
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => break,
                Ok(Err(e)) => return io_error(e),
                Ok(Ok(n)) => {
                    match check_reply(&buf[..n], &packet, &dae.secret, dae.require_reply_message_authenticator) {
                        Ok(reply) => {
                            if !reply.signed {
                                unsigned_reply_accepted(nas);
                            }
                            if reply.code == DISCONNECT_ACK {
                                return Outcome::Ack;
                            }
                            return Outcome::Nak { error_cause: reply.error_cause };
                        }
                        // a reply that is right in everything but its missing signature: the
                        // access point does not sign; say so, or every revocation reads `timeout`
                        Err(NO_MESSAGE_AUTHENTICATOR) => tracing::warn!(
                            target: "netportal.disconnect",
                            "Disconnect reply from {nas} ignored: it has no Message-Authenticator \
                             (NETPORTAL_DAE_REQUIRE_REPLY_MESSAGE_AUTHENTICATOR=false accepts such replies)"
                        ),
                        Err(why) => tracing::debug!(nas = %nas, why, "ignored a datagram on the DAE socket"),
                    }
                }
            }
        }
    }
    Outcome::Timeout
}
