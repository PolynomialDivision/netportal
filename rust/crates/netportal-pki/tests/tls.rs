//! A TLS handshake with client authentication, the core of EAP-TLS, between a supplicant that
//! uses the identity from a downloaded artefact and pins root + server name (as the profiles
//! configure it), and a server configured like FreeRADIUS (`radius/mods/eap`: the RADIUS server
//! certificate, `ca_file` = device CA chain, a client certificate required, `check_cert_issuer`
//! = the device CA's DN), for TLS 1.2 and 1.3. The real EAP-TLS logins through FreeRADIUS are
//! the integration suite's (`tests/integration/e2e.py`).

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use common::{fixture, now};
use netportal_pki::pki::{self, Issued};
use openssl::pkcs12::Pkcs12;
use openssl::ssl::{SslAcceptor, SslConnector, SslMethod, SslVerifyMode, SslVersion};
use openssl::x509::X509;
use openssl::x509::store::X509StoreBuilder;
use uuid::Uuid;

struct Identity {
    key: openssl::pkey::PKey<openssl::pkey::Private>,
    cert: X509,
    chain: Vec<X509>,
}

fn identity_from_p12(der: &[u8], password: &str) -> Identity {
    let p = Pkcs12::from_der(der).unwrap().parse2(password).unwrap();
    Identity {
        key: p.pkey.unwrap(),
        cert: p.cert.unwrap(),
        chain: p.ca.map(|s| s.into_iter().collect()).unwrap_or_default(),
    }
}

/// One handshake; Ok(issuer DN of the client certificate as the server saw it).
fn handshake(f: &common::Fixture, client: &Identity, version: SslVersion) -> Result<String, String> {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut acceptor = SslAcceptor::mozilla_modern_v5(SslMethod::tls_server()).unwrap();
    acceptor.set_min_proto_version(Some(SslVersion::TLS1_2)).unwrap();
    acceptor.set_private_key(f.server.key()).unwrap();
    acceptor.set_certificate(f.server.cert()).unwrap();
    let mut store = X509StoreBuilder::new().unwrap();
    store.add_cert(f.device_ca.cert().to_owned()).unwrap();
    store.add_cert(f.root.cert().to_owned()).unwrap();
    acceptor.set_verify_cert_store(store.build()).unwrap();
    acceptor.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    let acceptor = acceptor.build();
    let server = thread::spawn(move || -> Result<String, String> {
        let (stream, _) = listener.accept().map_err(|e| e.to_string())?;
        let mut tls = acceptor.accept(stream).map_err(|e| format!("server: {e}"))?;
        let peer = tls.ssl().peer_certificate().ok_or("no client certificate")?;
        let issuer: Vec<String> =
            peer.issuer_name().entries().map(|e| format!("/CN={}", e.data().to_string().unwrap())).collect();
        let mut buf = [0u8; 2];
        tls.read_exact(&mut buf).map_err(|e| e.to_string())?;
        tls.write_all(b"ok").map_err(|e| e.to_string())?;
        Ok(issuer.concat())
    });
    let mut connector = SslConnector::builder(SslMethod::tls_client()).unwrap();
    connector.set_min_proto_version(Some(version)).unwrap();
    connector.set_max_proto_version(Some(version)).unwrap();
    // the profile's anchor: the root only
    let mut anchors = X509StoreBuilder::new().unwrap();
    anchors.add_cert(f.root.cert().to_owned()).unwrap();
    connector.set_verify_cert_store(anchors.build()).unwrap();
    connector.set_private_key(&client.key).unwrap();
    connector.set_certificate(&client.cert).unwrap();
    for c in &client.chain {
        connector.add_extra_chain_cert(c.clone()).unwrap();
    }
    let connector = connector.build();
    let client_result = (|| -> Result<(), String> {
        let stream = TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
        // TLSTrustedServerNames / ServerID / AAAServerTrustedNames: the pinned name
        let mut tls = connector.connect("radius.scharni.org", stream).map_err(|e| format!("client: {e}"))?;
        assert_eq!(tls.ssl().version2(), Some(version));
        tls.write_all(b"hi").map_err(|e| e.to_string())?;
        let mut buf = [0u8; 2];
        tls.read_exact(&mut buf).map_err(|e| e.to_string())?;
        Ok(())
    })();
    let server_result = server.join().unwrap();
    client_result?;
    server_result
}

#[test]
fn test_eap_tls_handshake_with_the_artefact_identity() {
    let f = fixture();
    let body = netportal_pki::profiles::eap_config(&f.net, &f.issued, &[f.device_ca.cert()]).unwrap();
    let tree = common::parse_xml(&body);
    let client = tree.path("EAPIdentityProvider/AuthenticationMethods/AuthenticationMethod/ClientSideCredential");
    use base64::Engine;
    let p12 =
        base64::engine::general_purpose::STANDARD.decode(&client.child("ClientCertificate").unwrap().text).unwrap();
    let identity = identity_from_p12(&p12, &client.child("Passphrase").unwrap().text);
    for version in [SslVersion::TLS1_2, SslVersion::TLS1_3] {
        let issuer = handshake(&f, &identity, version).unwrap();
        // FreeRADIUS check_cert_issuer
        assert_eq!(issuer, "/CN=Test Device CA");
    }
}

#[test]
fn test_a_certificate_of_another_ca_is_refused() {
    let f = fixture();
    let other = fixture();
    let foreign = pki::device_cert(&other.device_ca, Uuid::new_v4(), "scharni.org", 30, now()).unwrap();
    let identity = Identity {
        key: foreign.key().to_owned(),
        cert: foreign.cert().to_owned(),
        chain: vec![other.device_ca.cert().to_owned()],
    };
    assert!(handshake(&f, &identity, SslVersion::TLS1_3).is_err());
}

#[test]
fn test_a_root_signed_client_certificate_fails_the_issuer_check() {
    // FreeRADIUS trusts the root too (ca_file holds the chain); check_cert_issuer refuses a
    // client certificate signed directly by the root, which the server sees as a different issuer
    let f = fixture();
    let root_signed: Issued = pki::device_cert(&f.root, Uuid::new_v4(), "scharni.org", 30, now()).unwrap();
    let identity = Identity { key: root_signed.key().to_owned(), cert: root_signed.cert().to_owned(), chain: vec![] };
    if let Ok(issuer) = handshake(&f, &identity, SslVersion::TLS1_2) {
        assert_ne!(issuer, "/CN=Test Device CA");
    }
}

/// Writes a ceremony and one eap-config artefact's PKCS#12 for a manual EAP-TLS run with
/// eapol_test against FreeRADIUS: `NETPORTAL_PKI_EXPORT=<dir> cargo test -p netportal-pki
/// --test tls -- --ignored export`.
#[test]
#[ignore]
fn export_for_eapol_test() {
    use base64::Engine;
    let Ok(dir) = std::env::var("NETPORTAL_PKI_EXPORT") else {
        eprintln!("SKIPPED: NETPORTAL_PKI_EXPORT not set");
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    let request =
        netportal_pki::ceremony::Request { name: "Test".into(), server_name: "radius.scharni.org".into(), realm: None };
    netportal_pki::ceremony::run(&dir, &request, now()).unwrap();
    let read = |n: &str| std::fs::read(dir.join(n)).unwrap();
    let issuer = netportal_pki::enroll::Issuer::new(netportal_pki::enroll::IssuerConfig {
        root_pem: &read("root.pem"),
        device_ca_pem: &read("device-ca.pem"),
        device_ca_key_pem: &read("device-ca.key"),
        realm: "scharni.org",
        ssid: "Scharni",
        radius_server_name: "radius.scharni.org",
        display_name: "Scharni",
        cert_days: 365,
        profile_signer: None,
    })
    .unwrap();
    let device = Uuid::new_v4();
    let issued = issuer.issue(device, now()).unwrap();
    let body = issuer.artefact(&issued, device, netportal_pki::enroll::Format::EapConfig).unwrap().body;
    let tree = common::parse_xml(&body);
    let client = tree.path("EAPIdentityProvider/AuthenticationMethods/AuthenticationMethod/ClientSideCredential");
    let p12 =
        base64::engine::general_purpose::STANDARD.decode(&client.child("ClientCertificate").unwrap().text).unwrap();
    std::fs::write(dir.join("client.p12"), p12).unwrap();
    std::fs::write(dir.join("client.pass"), &client.child("Passphrase").unwrap().text).unwrap();
    let android = issuer.artefact(&issued, device, netportal_pki::enroll::Format::Android).unwrap().body;
    std::fs::write(dir.join("client-clear.p12"), &common::aosp_parse(&android).2[2].2).unwrap();
    println!("exported {} (serial {})", dir.display(), issued.serial_hex().unwrap());
}
