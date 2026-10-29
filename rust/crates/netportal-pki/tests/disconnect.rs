//! RFC 5176 Disconnect-Request (INVENTORY 7.1; Python `tests/test_units.py:DisconnectTests`),
//! against a local UDP fake access point, and against the contract suite's independent fake
//! (`rust/tests/contract/fake_nas.py`) when python3 is there.

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hmac::{Hmac, KeyInit, Mac};
use md5::{Digest, Md5};
use netportal_pki::disconnect::{
    self, DaeConfig, DisconnectError, ErrorCause, Outcome, Session, build_request, check_reply, parse_attributes,
};
use tokio::net::UdpSocket;

const SECRET: &[u8] = b"s3cret";

fn md5(data: &[u8]) -> Vec<u8> {
    Md5::digest(data).to_vec()
}

fn hmac_md5(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Md5> as KeyInit>::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// The receiver's checks, written from RFC 5176 2.3 / RFC 3579 3.2 like `fake_nas.decode`.
fn request_is_valid(pkt: &[u8], secret: &[u8]) -> bool {
    let length = usize::from(u16::from_be_bytes([pkt[2], pkt[3]]));
    if pkt[0] != 40 || length != pkt.len() {
        return false;
    }
    let expect = md5(&[&pkt[..4], &[0u8; 16][..], &pkt[20..], secret].concat());
    if expect != pkt[4..20] {
        return false;
    }
    let mut offset = 20;
    for (kind, value) in parse_attributes(&pkt[20..]).unwrap() {
        if kind == 80 && value.len() == 16 {
            let mut zeroed = pkt.to_vec();
            zeroed[4..20].fill(0);
            zeroed[offset + 2..offset + 18].fill(0);
            return hmac_md5(secret, &zeroed) == value;
        }
        offset += 2 + value.len();
    }
    false
}

/// An ACK/NAK the way hostapd builds it: Message-Authenticator first (optional here), then
/// `extra` attributes; MA over the reply with the Request Authenticator in place.
fn reply(request: &[u8], code: u8, secret: &[u8], extra: &[u8], with_ma: bool) -> Vec<u8> {
    let mut attrs = Vec::new();
    if with_ma {
        attrs.extend([80, 18]);
        attrs.extend([0u8; 16]);
    }
    attrs.extend_from_slice(extra);
    let len = 20 + attrs.len();
    let header = [code, request[1], (len >> 8) as u8, len as u8];
    if with_ma {
        let mac = hmac_md5(secret, &[&header[..], &request[4..20], &attrs].concat());
        attrs[2..18].copy_from_slice(&mac);
    }
    let auth = md5(&[&header[..], &request[4..20], &attrs, secret].concat());
    [&header[..], &auth, &attrs].concat()
}

#[test]
fn test_packet() {
    let pkt = build_request(
        7,
        SECRET,
        "anonymous@scharni.org",
        "02-00-00-00-00-01",
        Ipv4Addr::new(10, 0, 10, 21),
        1_760_000_000,
    )
    .unwrap();
    assert_eq!((pkt[0], pkt[1], usize::from(u16::from_be_bytes([pkt[2], pkt[3]]))), (40, 7, pkt.len()));
    // Request Authenticator (RFC 5176 2.3) over the attributes as sent
    assert_eq!(pkt[4..20], md5(&[&pkt[..4], &[0u8; 16][..], &pkt[20..], SECRET].concat())[..]);
    assert!(request_is_valid(&pkt, SECRET));
    assert!(!request_is_valid(&pkt, b"other"));
    let attrs = parse_attributes(&pkt[20..]).unwrap();
    let types: Vec<u8> = attrs.iter().map(|(t, _)| *t).collect();
    assert_eq!(types, [80, 1, 31, 4, 55], "Message-Authenticator first");
    assert_eq!(attrs[1].1, b"anonymous@scharni.org");
    assert_eq!(attrs[2].1, b"02-00-00-00-00-01");
    assert_eq!(attrs[3].1, [10, 0, 10, 21]);
    // Event-Timestamp (55), 4 octets, for access points that require it
    let stamp = [&[55u8, 6][..], &1_760_000_000u32.to_be_bytes()].concat();
    assert!(pkt.windows(6).any(|w| w == stamp.as_slice()));
    // deterministic for the same inputs
    let again = build_request(
        7,
        SECRET,
        "anonymous@scharni.org",
        "02-00-00-00-00-01",
        Ipv4Addr::new(10, 0, 10, 21),
        1_760_000_000,
    )
    .unwrap();
    assert_eq!(pkt, again);
}

#[test]
fn test_empty_values_are_left_out_and_long_ones_refused() {
    let pkt = build_request(1, SECRET, "", "", Ipv4Addr::new(10, 0, 0, 1), 1).unwrap();
    let types: Vec<u8> = parse_attributes(&pkt[20..]).unwrap().iter().map(|(t, _)| *t).collect();
    assert_eq!(types, [80, 4, 55]);
    assert!(request_is_valid(&pkt, SECRET));
    let long = "x".repeat(254);
    assert_eq!(
        build_request(1, SECRET, &long, "", Ipv4Addr::LOCALHOST, 1).unwrap_err(),
        DisconnectError::AttributeTooLong("User-Name")
    );
    assert!(build_request(1, SECRET, &"x".repeat(253), "", Ipv4Addr::LOCALHOST, 1).is_ok());
}

#[test]
fn test_reply_check() {
    let req = build_request(9, SECRET, "u", "02-00-00-00-00-01", Ipv4Addr::new(10, 0, 10, 21), 5).unwrap();
    let good = reply(&req, 41, SECRET, &[], true);
    assert_eq!(check_reply(&good, &req, SECRET, true).unwrap().code, 41);
    assert!(check_reply(&good, &req, b"other", true).is_err(), "wrong secret");
    let mut other_id = good.clone();
    other_id[1] = 8;
    assert!(check_reply(&other_id, &req, SECRET, true).is_err(), "other identifier");
    // a tampered Message-Authenticator with a recomputed Response Authenticator (an attacker who
    // could forge MD5 but not the HMAC) is refused
    let mut tampered = good.clone();
    tampered[22] ^= 1;
    let auth = md5(&[&tampered[..4], &req[4..20], &tampered[20..], SECRET].concat());
    tampered[4..20].copy_from_slice(&auth);
    assert_eq!(check_reply(&tampered, &req, SECRET, true), Err("bad Message-Authenticator"));
    // without Message-Authenticator: refused unless allowed
    let bare = reply(&req, 41, SECRET, &[], false);
    assert_eq!(check_reply(&bare, &req, SECRET, true), Err("no Message-Authenticator"));
    assert_eq!(check_reply(&bare, &req, SECRET, false).unwrap().code, 41);
    // NAK with Error-Cause 503 (Session Context Not Found)
    let nak = reply(&req, 42, SECRET, &[101, 6, 0, 0, 1, 247], true);
    let r = check_reply(&nak, &req, SECRET, true).unwrap();
    assert_eq!((r.code, r.error_cause), (42, Some(ErrorCause(503))));
    assert_eq!(ErrorCause(503).name(), Some("Session Context Not Found"));
    // padding after Length is ignored (RFC 2865 3); a Length beyond the datagram is not
    let mut padded = good.clone();
    padded.extend([0, 0, 0]);
    assert!(check_reply(&padded, &req, SECRET, true).is_ok());
    let mut long = good.clone();
    long[3] += 1;
    assert!(check_reply(&long, &req, SECRET, true).is_err());
    // not an answer to a Disconnect-Request
    assert!(check_reply(&reply(&req, 2, SECRET, &[], true), &req, SECRET, true).is_err());
    assert!(check_reply(&good[..19], &req, SECRET, true).is_err());
    // malformed attributes
    let bad = reply(&req, 41, SECRET, &[1, 1], true);
    assert_eq!(check_reply(&bad, &req, SECRET, true), Err("malformed attributes"));
}

/// What the fake access point does with each request.
#[derive(Clone, Copy)]
enum Mode {
    Ack,
    NakNotFound,
    Silent,
    ForgedThenAck,
    AckWithoutMa,
}

struct FakeNas {
    port: u16,
    received: Arc<Mutex<Vec<Vec<u8>>>>,
}

async fn fake_nas(mode: Mode) -> FakeNas {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = sock.local_addr().unwrap().port();
    let received = Arc::new(Mutex::new(Vec::new()));
    let seen = received.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
            let req = buf[..n].to_vec();
            seen.lock().unwrap().push(req.clone());
            if !request_is_valid(&req, SECRET) {
                continue;
            }
            let answers = match mode {
                Mode::Ack => vec![reply(&req, 41, SECRET, &[], true)],
                Mode::NakNotFound => vec![reply(&req, 42, SECRET, &[101, 6, 0, 0, 1, 247], true)],
                Mode::Silent => vec![],
                Mode::ForgedThenAck => vec![
                    reply(&req, 42, b"attacker", &[], true),
                    [&[42u8, req[1], 0, 20][..], &[0u8; 16]].concat(),
                    reply(&req, 41, SECRET, &[], true),
                ],
                Mode::AckWithoutMa => vec![reply(&req, 41, SECRET, &[], false)],
            };
            for a in answers {
                let _ = sock.send_to(&a, peer).await;
            }
        }
    });
    FakeNas { port, received }
}

fn session() -> Session {
    Session {
        nas_ip: "127.0.0.1".into(),
        calling_station: "02:00:00:00:aa:42".into(),
        user_name: "anonymous@scharni.org".into(),
    }
}

fn dae(port: u16) -> DaeConfig {
    let mut d = DaeConfig::new(SECRET, port);
    d.timeout = Duration::from_millis(200);
    d
}

#[tokio::test]
async fn test_ack() {
    let nas = fake_nas(Mode::Ack).await;
    let started = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    assert_eq!(disconnect::disconnect(Some(&session()), Some(&dae(nas.port))).await, Outcome::Ack);
    let got = nas.received.lock().unwrap().clone();
    assert_eq!(got.len(), 1);
    let attrs = parse_attributes(&got[0][20..]).unwrap();
    let find = |t: u8| attrs.iter().find(|(k, _)| *k == t).map(|(_, v)| v.to_vec()).unwrap();
    assert_eq!(find(1), b"anonymous@scharni.org");
    assert_eq!(find(31), b"02:00:00:00:aa:42");
    assert_eq!(find(4), [127, 0, 0, 1]);
    let stamp = u64::from(u32::from_be_bytes(find(55).try_into().unwrap()));
    assert!(stamp.abs_diff(started) < 60);
    assert_eq!(Outcome::Ack.label(), "ack");
}

#[tokio::test]
async fn test_nak_carries_the_error_cause() {
    let nas = fake_nas(Mode::NakNotFound).await;
    let outcome = disconnect::disconnect(Some(&session()), Some(&dae(nas.port))).await;
    assert_eq!(outcome, Outcome::Nak { error_cause: Some(ErrorCause(503)) });
    assert_eq!(outcome.label(), "nak");
}

#[tokio::test]
async fn test_timeout_retries_the_same_packet() {
    let nas = fake_nas(Mode::Silent).await;
    let started = std::time::Instant::now();
    let outcome = disconnect::disconnect(Some(&session()), Some(&dae(nas.port))).await;
    assert_eq!(outcome, Outcome::Timeout);
    assert_eq!(outcome.label(), "timeout");
    assert!(started.elapsed() >= Duration::from_millis(550));
    let got = nas.received.lock().unwrap().clone();
    assert_eq!(got.len(), 3, "3 tries");
    assert!(got.iter().all(|p| p == &got[0]), "RFC 5080 2.2.1: same identifier and authenticator");
}

#[tokio::test]
async fn test_forged_replies_are_ignored() {
    let nas = fake_nas(Mode::ForgedThenAck).await;
    assert_eq!(disconnect::disconnect(Some(&session()), Some(&dae(nas.port))).await, Outcome::Ack);
}

#[tokio::test]
async fn test_reply_without_message_authenticator() {
    let nas = fake_nas(Mode::AckWithoutMa).await;
    assert_eq!(disconnect::disconnect(Some(&session()), Some(&dae(nas.port))).await, Outcome::Timeout);
    let mut lax = dae(nas.port);
    lax.require_reply_message_authenticator = false;
    assert_eq!(disconnect::disconnect(Some(&session()), Some(&lax)).await, Outcome::Ack);
}

#[tokio::test]
async fn test_nothing_to_do() {
    assert_eq!(disconnect::disconnect(None, Some(&dae(3799))).await, Outcome::NoSession);
    assert_eq!(Outcome::NoSession.label(), "no-session");
    assert_eq!(disconnect::disconnect(Some(&session()), None).await, Outcome::Skipped);
    assert_eq!(disconnect::disconnect(Some(&session()), Some(&DaeConfig::new(b"", 3799))).await, Outcome::Skipped);
    assert_eq!(Outcome::Skipped.label(), "skipped");
}

#[tokio::test]
async fn test_unusable_address_is_an_error_not_a_crash() {
    // a session without NAS-IP-Address (or an IPv6 one) must not break the revocation
    for nas_ip in ["", "fe80::1", "10.0.0", "nas.example"] {
        let s = Session { nas_ip: nas_ip.into(), ..session() };
        let outcome = disconnect::disconnect(Some(&s), Some(&dae(3799))).await;
        assert!(matches!(outcome, Outcome::Error(DisconnectError::NoIpv4Address(_))), "{nas_ip}: {outcome:?}");
        assert_eq!(outcome.label(), "error");
    }
    let s = Session { user_name: "x".repeat(300), ..session() };
    assert!(matches!(disconnect::disconnect(Some(&s), Some(&dae(3799))).await, Outcome::Error(_)));
}

#[tokio::test]
async fn test_nobody_listening_is_a_timeout() {
    let closed = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    assert_eq!(disconnect::disconnect(Some(&session()), Some(&dae(port))).await, Outcome::Timeout);
}

/// The contract suite's fake access point (an independent Python implementation of RFC 5176
/// and RFC 3579) accepts the request and its ACK passes our checks.
#[tokio::test]
async fn test_the_contract_fake_nas_accepts_it() {
    let fake = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/contract");
    if !fake.join("fake_nas.py").exists() {
        eprintln!("SKIPPED: {} missing", fake.display());
        return;
    }
    let script = format!(
        "import sys, time, json; sys.path.insert(0, {dir:?}); from fake_nas import FakeNas\n\
         n = FakeNas(0, 's3cret'); print(n.sock.getsockname()[1], flush=True)\n\
         got = n.wait(1, timeout=10); p = got[0] if got else {{}}\n\
         print(json.dumps({{k: p.get(k) for k in ('valid', 'request_authenticator_ok', 'message_authenticator_ok', 'types')}}), flush=True)",
        dir = fake.display().to_string()
    );
    let mut child = match tokio::process::Command::new("python3")
        .args(["-I", "-c", &script])
        .stdout(std::process::Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(_) => {
            eprintln!("SKIPPED: python3 is not installed");
            return;
        }
    };
    use tokio::io::{AsyncBufReadExt, BufReader};
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let port: u16 = lines.next_line().await.unwrap().unwrap().trim().parse().unwrap();
    assert_eq!(disconnect::disconnect(Some(&session()), Some(&dae(port))).await, Outcome::Ack);
    let verdict = lines.next_line().await.unwrap().unwrap();
    assert!(verdict.contains("\"valid\": true"), "{verdict}");
    assert!(verdict.contains("\"message_authenticator_ok\": true"), "{verdict}");
    let _ = child.kill().await;
}

/// A real Dynamic Authorization server (run by hand): `NETPORTAL_PKI_LIVE_DAE=host:port:secret
/// cargo test -p netportal-pki --test disconnect -- --ignored live`.
#[tokio::test]
#[ignore]
async fn live_dae_server() {
    let Ok(target) = std::env::var("NETPORTAL_PKI_LIVE_DAE") else {
        eprintln!("SKIPPED: NETPORTAL_PKI_LIVE_DAE not set");
        return;
    };
    let mut it = target.splitn(3, ':');
    let (host, port, secret) = (it.next().unwrap(), it.next().unwrap(), it.next().unwrap());
    let s = Session { nas_ip: host.into(), ..session() };
    let outcome =
        disconnect::disconnect(Some(&s), Some(&DaeConfig::new(secret.as_bytes(), port.parse().unwrap()))).await;
    println!("live DAE outcome: {outcome:?}");
    assert!(matches!(outcome, Outcome::Ack | Outcome::Nak { .. }), "{outcome:?}");
}
