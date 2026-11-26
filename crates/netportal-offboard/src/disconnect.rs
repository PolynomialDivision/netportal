//! Cutting a running Wi-Fi session: the RADIUS Disconnect-Request (RFC 5176) to the access point
//! of the device's latest login (INVENTORY 7.1). The packet itself is `netportal-pki`'s
//! (`netportal_pki::disconnect`, Python `disconnect.py`); this module is the seam the offboarding
//! (and, through [`crate::actions`], the portal) calls, so the rounds can be tested with a fake,
//! and the registry's session row meets pki's (which does not depend on `netportal-core`).

use std::future::Future;

use netportal_core::config::DaeSettings;
use netportal_core::registry::RadiusSession;
use netportal_pki::disconnect::{DaeConfig, Outcome, Session};

const LOG: &str = "netportal.disconnect";

/// What became of a Disconnect-Request; recorded as audit `disconnect:<as_str()>` (counted by
/// `/metrics` as `netportal_disconnects_last_hour{result}`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DisconnectResult {
    /// Disconnect-ACK with a valid Response Authenticator
    Ack,
    /// Disconnect-NAK (the access point refused: an attribute, the NAS, ...)
    Nak,
    /// Disconnect-NAK with Error-Cause 503 Session-Context-Not-Found: the access point has no
    /// such session (`not-found`, not `nak`: the alert on failed Disconnects must not fire for a
    /// device that is simply not connected, e.g. after an access point restarted)
    NotFound,
    /// no valid answer after every try
    Timeout,
    /// not sent: no IPv4 address, unreachable network, ...
    Error,
    /// not sent: no `NETPORTAL_DAE_SECRET`
    Skipped,
    /// not sent: the device never logged in (no `radius_session` row)
    NoSession,
}

impl DisconnectResult {
    pub const ALL: [DisconnectResult; 7] = [
        DisconnectResult::Ack,
        DisconnectResult::NoSession,
        DisconnectResult::Skipped,
        DisconnectResult::Timeout,
        DisconnectResult::Nak,
        DisconnectResult::NotFound,
        DisconnectResult::Error,
    ];

    /// The result string of the audit action and the metric label.
    pub fn as_str(self) -> &'static str {
        match self {
            DisconnectResult::Ack => "ack",
            DisconnectResult::Nak => "nak",
            DisconnectResult::NotFound => "not-found",
            DisconnectResult::Timeout => "timeout",
            DisconnectResult::Error => "error",
            DisconnectResult::Skipped => "skipped",
            DisconnectResult::NoSession => "no-session",
        }
    }

    /// Whether the session is known to be gone: an ACK, the access point has no such session,
    /// or there was none to cut. Anything else leaves the device possibly connected until the
    /// reconciliation or the RADIUS Session-Timeout ends it.
    pub fn confirmed(self) -> bool {
        matches!(self, DisconnectResult::Ack | DisconnectResult::NotFound | DisconnectResult::NoSession)
    }
}

/// Sends Disconnect-Requests (the real one: [`RadiusDisconnector`]; tests: a fake).
pub trait Disconnector: Sync {
    /// Disconnect this session; never fails, the outcome is the result.
    fn disconnect(&self, session: &RadiusSession) -> impl Future<Output = DisconnectResult> + Send;
}

/// Disconnect-Requests to `(nas_ip, NETPORTAL_DAE_PORT)` with `NETPORTAL_DAE_SECRET`, through
/// `netportal_pki::disconnect` (2 s per try, 3 tries, replies checked including their
/// Message-Authenticator unless `NETPORTAL_DAE_REQUIRE_REPLY_MESSAGE_AUTHENTICATOR` is false);
/// without a secret every request is [`DisconnectResult::Skipped`].
#[derive(Debug, Clone)]
pub struct RadiusDisconnector {
    dae: Option<DaeConfig>,
}

impl RadiusDisconnector {
    pub fn new(dae: &DaeSettings) -> RadiusDisconnector {
        RadiusDisconnector {
            dae: dae.secret.as_ref().map(|s| {
                let mut config = DaeConfig::new(s.expose().as_bytes(), dae.port);
                config.require_reply_message_authenticator = dae.require_reply_message_authenticator;
                config
            }),
        }
    }
}

impl Disconnector for RadiusDisconnector {
    async fn disconnect(&self, session: &RadiusSession) -> DisconnectResult {
        let session = Session {
            nas_ip: session.nas_ip.clone(),
            calling_station: session.calling_station.clone(),
            user_name: session.user_name.clone(),
            acct_session_id: session.acct_session_id.clone(),
        };
        let outcome = netportal_pki::disconnect::disconnect(Some(&session), self.dae.as_ref()).await;
        result_of(&session.nas_ip, &outcome)
    }
}

/// The result of pki's outcome; the details that the result string drops are logged.
fn result_of(nas_ip: &str, outcome: &Outcome) -> DisconnectResult {
    match outcome {
        Outcome::Ack => DisconnectResult::Ack,
        Outcome::Nak { error_cause } => {
            if let Some(cause) = error_cause {
                tracing::info!(
                    target: LOG,
                    "Disconnect-NAK from {nas_ip}: Error-Cause {} {}",
                    cause.0,
                    cause.name().unwrap_or("")
                );
            }
            if *error_cause == Some(netportal_pki::disconnect::SESSION_CONTEXT_NOT_FOUND) {
                DisconnectResult::NotFound
            } else {
                DisconnectResult::Nak
            }
        }
        Outcome::Timeout => DisconnectResult::Timeout,
        Outcome::Error(e) => {
            tracing::warn!(target: LOG, "Disconnect-Request to {nas_ip} not sent: {e}");
            DisconnectResult::Error
        }
        Outcome::Skipped => DisconnectResult::Skipped,
        Outcome::NoSession => DisconnectResult::NoSession,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_result_strings() {
        let names: Vec<&str> = DisconnectResult::ALL.iter().map(|r| r.as_str()).collect();
        assert_eq!(names, netportal_core::registry::DISCONNECT_RESULTS);
    }

    #[tokio::test]
    async fn test_without_a_secret_nothing_is_sent() {
        let d = RadiusDisconnector::new(&DaeSettings::new(3799, None));
        let session = RadiusSession {
            nas_ip: "192.0.2.1".into(),
            calling_station: "02-00-00-00-00-01".into(),
            user_name: "anonymous@example.org".into(),
            acct_session_id: String::new(),
        };
        assert_eq!(d.disconnect(&session).await, DisconnectResult::Skipped);
    }

    #[test]
    fn test_every_outcome_maps_to_its_label() {
        use netportal_pki::disconnect::{DisconnectError, ErrorCause};
        for outcome in [
            Outcome::Ack,
            Outcome::Nak { error_cause: Some(ErrorCause(503)) },
            Outcome::Nak { error_cause: None },
            Outcome::Timeout,
            Outcome::Error(DisconnectError::NoIpv4Address("fe80::1".into())),
            Outcome::Skipped,
            Outcome::NoSession,
        ] {
            assert_eq!(result_of("192.0.2.1", &outcome).as_str(), outcome.label());
        }
        // 503 Session-Context-Not-Found is told apart (the reconciliation settles on it)
        assert_eq!(
            result_of("192.0.2.1", &Outcome::Nak { error_cause: Some(ErrorCause(503)) }),
            DisconnectResult::NotFound
        );
        assert_eq!(result_of("192.0.2.1", &Outcome::Nak { error_cause: Some(ErrorCause(404)) }), DisconnectResult::Nak);
        let confirmed: Vec<bool> = DisconnectResult::ALL.iter().map(|r| r.confirmed()).collect();
        assert_eq!(confirmed, [true, true, false, false, false, true, false]);
        assert!(DisconnectResult::NotFound.confirmed());
    }

    #[tokio::test]
    async fn test_the_request_goes_to_the_access_point_of_the_session() {
        // a NAS that never answers: the request arrives (code 40, the session's attributes) on
        // the configured port, and after every try the result is a timeout
        let nas = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let port = nas.local_addr().expect("address").port();
        let secret = netportal_core::config::Secret::new("dae-secret".to_string());
        let d = RadiusDisconnector::new(&DaeSettings::new(port, Some(secret)));
        let session = RadiusSession {
            nas_ip: "127.0.0.1".into(),
            calling_station: "02-00-00-00-00-01".into(),
            user_name: "anonymous@example.org".into(),
            acct_session_id: String::new(),
        };
        let listen = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            let n = nas.recv(&mut buf).await.expect("request");
            buf[..n].to_vec()
        });
        assert_eq!(d.disconnect(&session).await, DisconnectResult::Timeout);
        let packet = listen.await.expect("listener");
        assert_eq!(packet[0], 40);
        let attrs = netportal_pki::disconnect::parse_attributes(&packet[20..]).expect("attributes");
        assert!(attrs.contains(&(31, b"02-00-00-00-00-01".as_slice())));
        assert!(attrs.contains(&(1, b"anonymous@example.org".as_slice())));
    }

    #[tokio::test]
    async fn test_a_session_without_an_ipv4_address_is_an_error() {
        let secret = netportal_core::config::Secret::new("dae-secret".to_string());
        let d = RadiusDisconnector::new(&DaeSettings::new(3799, Some(secret)));
        let session = RadiusSession {
            nas_ip: "fe80::1".into(),
            calling_station: "02-00-00-00-00-01".into(),
            user_name: "u".into(),
            acct_session_id: String::new(),
        };
        assert_eq!(d.disconnect(&session).await, DisconnectResult::Error);
    }
}
