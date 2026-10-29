//! The CA ceremony and the certificate profiles (INVENTORY 6.1, 6.2; Python
//! `tests/test_profiles.py:PasspointTests.test_no_personal_data_in_the_certificate`, the
//! contract suite's `test_config.PkiTests` and `test_artefacts.CertificateTests`).

mod common;

use std::os::unix::fs::PermissionsExt;

use common::{fixture, have, now, openssl, x509_text};
use netportal_pki::Error;
use netportal_pki::ceremony::{self, FILES, Request};
use netportal_pki::enroll::{Issuer, IssuerConfig};
use netportal_pki::pki::{self, Issued, Purpose};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::x509::X509;
use openssl::x509::extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName};
use time::Duration;
use uuid::Uuid;

fn request(name: &str, server: &str) -> Request {
    Request { name: name.into(), server_name: server.into(), realm: None }
}

fn mode(path: &std::path::Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn test_ceremony_files_and_modes() {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("pki");
    let report = ceremony::run(&out, &request("Contract", "radius.example.test"), now()).unwrap();
    assert_eq!(mode(&out), 0o700);
    assert_eq!(report.files.len(), 7);
    for (name, secret) in FILES {
        let m = mode(&out.join(name));
        assert_eq!(m, if secret { 0o600 } else { 0o644 }, "{name}: {m:o}");
    }
    assert_eq!(report.device_ca_dn, "/CN=Contract Device CA");
    assert_eq!(report.realm, "example.test");
    assert!(report.summary().contains("check_cert_issuer: /CN=Contract Device CA"));
    let read = |n: &str| std::fs::read(out.join(n)).unwrap();
    let root = X509::from_pem(&read("root.pem")).unwrap();
    let ca = X509::from_pem(&read("device-ca.pem")).unwrap();
    let server = X509::from_pem(&read("radius-server.pem")).unwrap();
    // the chain file FreeRADIUS reads: device CA, then root
    let chain = X509::stack_from_pem(&read("device-ca-chain.pem")).unwrap();
    assert_eq!(chain.len(), 2);
    assert_eq!(chain[0].to_der().unwrap(), ca.to_der().unwrap());
    assert_eq!(chain[1].to_der().unwrap(), root.to_der().unwrap());
    // keys belong to their certificates (PKCS#8 PEM, unencrypted)
    for (cert, key) in
        [("root.pem", "root.key"), ("device-ca.pem", "device-ca.key"), ("radius-server.pem", "radius-server.key")]
    {
        assert!(String::from_utf8(read(key)).unwrap().starts_with("-----BEGIN PRIVATE KEY-----"));
        Issued::from_pem(&read(cert), &read(key)).unwrap();
    }
    assert_eq!(report.root_sha256, pki::fingerprint_sha256(&root).unwrap());
    pki::verify(&server, &[], &root, Purpose::TlsServer).unwrap();
    // the portal starts with these files
    let issuer = Issuer::new(IssuerConfig {
        root_pem: &read("root.pem"),
        device_ca_pem: &read("device-ca.pem"),
        device_ca_key_pem: &read("device-ca.key"),
        realm: "example.test",
        ssid: "Contract",
        radius_server_name: "radius.example.test",
        display_name: "Contract",
        cert_days: 365,
        profile_signer: None,
    })
    .unwrap();
    assert_eq!(issuer.device_ca().to_der().unwrap(), ca.to_der().unwrap());
}

#[test]
fn test_ceremony_refuses_to_overwrite() {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path();
    ceremony::run(out, &request("Test", "radius.scharni.org"), now()).unwrap();
    let before: Vec<Vec<u8>> = FILES.iter().map(|(n, _)| std::fs::read(out.join(n)).unwrap()).collect();
    match ceremony::run(out, &request("Test", "radius.scharni.org"), now()) {
        Err(Error::Exists(paths)) => assert_eq!(paths.len(), 7),
        other => panic!("expected Exists, got {other:?}"),
    }
    let after: Vec<Vec<u8>> = FILES.iter().map(|(n, _)| std::fs::read(out.join(n)).unwrap()).collect();
    assert_eq!(before, after, "nothing was overwritten");
}

#[test]
fn test_ceremony_refuses_a_single_leftover_and_writes_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("radius-server.key"), b"old").unwrap();
    assert!(matches!(ceremony::run(tmp.path(), &request("Test", "radius.scharni.org"), now()), Err(Error::Exists(_))));
    let names: Vec<_> = std::fs::read_dir(tmp.path()).unwrap().map(|e| e.unwrap().file_name()).collect();
    assert_eq!(names, vec![std::ffi::OsString::from("radius-server.key")]);
    assert_eq!(std::fs::read(tmp.path().join("radius-server.key")).unwrap(), b"old");
}

#[test]
fn test_ceremony_input_checks() {
    let now = now();
    for name in ["", " Lead", "a/b", "x=y", "Ünïcode", &"x".repeat(52)] {
        assert!(ceremony::generate(&request(name, "radius.scharni.org"), now).is_err(), "{name:?}");
    }
    assert!(ceremony::generate(&request("Test", "radius"), now).is_err(), "no realm derivable");
    let explicit = Request { realm: Some("House.Example.NET".into()), ..request("Test", "radius") };
    assert!(ceremony::generate(&explicit, now).is_err(), "server name needs two labels");
    let explicit = Request { realm: Some("House.Example.NET".into()), ..request("Test", "radius.scharni.org") };
    assert_eq!(ceremony::generate(&explicit, now).unwrap().realm, "house.example.net");
}

#[test]
fn test_renew_server_keeps_the_cas() {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path();
    ceremony::run(out, &request("Test", "radius.scharni.org"), now()).unwrap();
    let old = std::fs::read(out.join("radius-server.pem")).unwrap();
    assert!(matches!(ceremony::renew_server(out, "radius.scharni.org", now()), Err(Error::Exists(_))));
    for name in ["radius-server.pem", "radius-server.key"] {
        std::fs::rename(out.join(name), out.join(format!("{name}.old"))).unwrap();
    }
    let files = ceremony::renew_server(out, "radius.scharni.org", now()).unwrap();
    assert_eq!(files.len(), 2);
    assert_eq!(mode(&out.join("radius-server.key")), 0o600);
    let new = std::fs::read(out.join("radius-server.pem")).unwrap();
    assert_ne!(old, new);
    let root = X509::from_pem(&std::fs::read(out.join("root.pem")).unwrap()).unwrap();
    pki::verify(&X509::from_pem(&new).unwrap(), &[], &root, Purpose::TlsServer).unwrap();
    // another server name is not permitted by the root: refused, nothing written
    for name in ["radius-server.pem", "radius-server.key"] {
        std::fs::rename(out.join(name), out.join(format!("{name}.second"))).unwrap();
    }
    let err = ceremony::renew_server(out, "radius.other.example", now()).unwrap_err();
    assert!(err.to_string().contains("new ceremony"), "{err}");
    assert!(!out.join("radius-server.pem").exists());
}

#[test]
fn test_the_root_is_an_anchor_for_its_server_name_only() {
    // security review 2026-10-29 L7: even a certificate the root itself signed is refused for
    // another DNS name or an IP address; the house's own chains verify
    let f = fixture();
    pki::verify(f.server.cert(), &[], f.root.cert(), Purpose::TlsServer).unwrap();
    pki::verify(f.issued.cert(), &[f.device_ca.cert()], f.root.cert(), Purpose::TlsClient).unwrap();
    // a name under the server name is within the subtree (RFC 5280 4.2.1.10)
    let below = pki::make_server_cert(&f.root, "eap.radius.scharni.org", 30, now()).unwrap();
    pki::verify(below.cert(), &[], f.root.cert(), Purpose::TlsServer).unwrap();
    for other in ["www.example.com", "scharni.org", "portal.scharni.org"] {
        let cert = pki::make_server_cert(&f.root, other, 30, now()).unwrap();
        let err = pki::verify(cert.cert(), &[], f.root.cert(), Purpose::TlsServer).unwrap_err();
        assert!(err.to_string().contains("permitted subtree"), "{other}: {err}");
    }
    // a mailbox outside the realm, signed by the root directly
    let outside = forged(&f.root, "x", None, Some("x@example.com"), false);
    assert!(pki::verify(&outside, &[], f.root.cert(), Purpose::TlsClient).is_err());
    if have("openssl") {
        // the same as a supplicant (wpa_supplicant/OpenSSL) checks it: name constraints of the anchor
        let (ok, out) = openssl(
            &[
                "verify",
                "-purpose",
                "sslserver",
                "-verify_hostname",
                "radius.scharni.org",
                "-CAfile",
                "{root.pem}",
                "{server.pem}",
            ],
            &[("root.pem", &f.root.cert_pem().unwrap()), ("server.pem", &f.server.cert_pem().unwrap())],
        );
        assert!(ok && out.contains(": OK"), "{out}");
        let fake = pki::make_server_cert(&f.root, "www.example.com", 30, now()).unwrap();
        let (ok, out) = openssl(
            &["verify", "-purpose", "sslserver", "-CAfile", "{root.pem}", "{fake.pem}"],
            &[("root.pem", &f.root.cert_pem().unwrap()), ("fake.pem", &fake.cert_pem().unwrap())],
        );
        assert!(!ok && out.contains("permitted subtree violation"), "{out}");
    }
}

#[test]
fn test_root_profile() {
    if !have("openssl") {
        return;
    }
    let f = fixture();
    let text = x509_text(f.root.cert());
    assert!(text.contains("Subject: CN=Test Network Root"), "{text}");
    assert!(text.contains("Issuer: CN=Test Network Root"), "{text}");
    assert!(text.contains("NIST CURVE: P-384"), "{text}");
    assert!(text.contains("Signature Algorithm: ecdsa-with-SHA384"), "{text}");
    assert!(text.contains("X509v3 Basic Constraints: critical\n                CA:TRUE, pathlen:1"), "{text}");
    assert!(text.contains("X509v3 Key Usage: critical\n                Certificate Sign, CRL Sign\n"), "{text}");
    assert!(text.contains("X509v3 Subject Key Identifier"), "{text}");
    assert!(!text.contains("Authority Key Identifier"), "{text}");
    assert!(!text.contains("Extended Key Usage"), "{text}");
    // a trust anchor for the RADIUS server's name and the realm's mailboxes only (L7)
    assert!(text.contains("X509v3 Name Constraints: critical"), "{text}");
    assert!(
        text.contains("Permitted:\n                  DNS:radius.scharni.org\n                  email:scharni.org\n"),
        "{text}"
    );
    assert!(
        text.contains(
            "Excluded:\n                  IP:0.0.0.0/0.0.0.0\n                  IP:0:0:0:0:0:0:0:0/0:0:0:0:0:0:0:0\n"
        ),
        "{text}"
    );
    let days = (f.root.not_after().unwrap() - f.root.not_before().unwrap()).whole_days();
    assert_eq!(days, 7300);
}

#[test]
fn test_device_ca_profile() {
    if !have("openssl") {
        return;
    }
    let f = fixture();
    let text = x509_text(f.device_ca.cert());
    assert!(text.contains("Subject: CN=Test Device CA"), "{text}");
    assert!(text.contains("Issuer: CN=Test Network Root"), "{text}");
    assert!(text.contains("NIST CURVE: P-384"), "{text}");
    assert!(text.contains("Signature Algorithm: ecdsa-with-SHA384"), "{text}");
    assert!(text.contains("X509v3 Basic Constraints: critical\n                CA:TRUE, pathlen:0"), "{text}");
    assert!(text.contains("X509v3 Key Usage: critical\n                Certificate Sign, CRL Sign\n"), "{text}");
    assert!(text.contains("X509v3 Extended Key Usage: \n                TLS Web Client Authentication\n"), "{text}");
    assert!(text.contains("X509v3 Name Constraints: critical"), "{text}");
    assert!(text.contains("Permitted:\n                  email:scharni.org\n"), "{text}");
    assert!(text.contains("Excluded:\n                  DNS:\n                  IP:0.0.0.0/0.0.0.0\n                  IP:0:0:0:0:0:0:0:0/0:0:0:0:0:0:0:0\n"), "{text}");
    let days = (f.device_ca.not_after().unwrap() - f.device_ca.not_before().unwrap()).whole_days();
    assert_eq!(days, 3650);
    // AKI = the root's SKI
    assert_eq!(
        f.device_ca.cert().authority_key_id().unwrap().as_slice(),
        f.root.cert().subject_key_id().unwrap().as_slice()
    );
}

#[test]
fn test_server_profile() {
    if !have("openssl") {
        return;
    }
    let f = fixture();
    let text = x509_text(f.server.cert());
    assert!(text.contains("Subject: CN=radius.scharni.org"), "{text}");
    assert!(text.contains("Issuer: CN=Test Network Root"), "{text}");
    assert!(text.contains("NIST CURVE: P-256"), "{text}");
    assert!(text.contains("X509v3 Basic Constraints: critical\n                CA:FALSE"), "{text}");
    assert!(text.contains("X509v3 Key Usage: critical\n                Digital Signature\n"), "{text}");
    assert!(text.contains("X509v3 Extended Key Usage: \n                TLS Web Server Authentication\n"), "{text}");
    assert!(text.contains("X509v3 Subject Alternative Name: \n                DNS:radius.scharni.org\n"), "{text}");
    // Apple: at most 825 days
    let days = (f.server.not_after().unwrap() - f.server.not_before().unwrap()).whole_days();
    assert_eq!(days, 825);
    let (ok, out) = openssl(
        &[
            "verify",
            "-purpose",
            "sslserver",
            "-verify_hostname",
            "radius.scharni.org",
            "-CAfile",
            "{root.pem}",
            "{server.pem}",
        ],
        &[("root.pem", &f.root.cert_pem().unwrap()), ("server.pem", &f.server.cert_pem().unwrap())],
    );
    assert!(ok && out.contains(": OK"), "{out}");
}

#[test]
fn test_no_personal_data_in_the_certificate() {
    let f = fixture();
    let entries: Vec<_> = f.issued.cert().subject_name().entries().collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].object().nid(), Nid::COMMONNAME);
    assert_eq!(entries[0].data().to_string().unwrap(), format!("{}@scharni.org", f.device_id));
}

#[test]
fn test_device_certificate_profile() {
    if !have("openssl") {
        return;
    }
    let f = fixture();
    let nai = format!("{}@scharni.org", f.device_id);
    let text = x509_text(f.issued.cert());
    assert!(text.contains(&format!("Subject: CN={nai}\n")), "{text}");
    assert!(text.contains("Issuer: CN=Test Device CA"), "{text}");
    assert!(text.contains("NIST CURVE: P-256"), "{text}");
    assert!(text.contains("Signature Algorithm: ecdsa-with-SHA384"), "{text}");
    assert!(text.contains("X509v3 Basic Constraints: critical\n                CA:FALSE"), "{text}");
    assert!(text.contains("X509v3 Key Usage: critical\n                Digital Signature\n"), "{text}");
    assert!(text.contains("X509v3 Extended Key Usage: \n                TLS Web Client Authentication\n"), "{text}");
    assert!(text.contains(&format!("X509v3 Subject Alternative Name: \n                email:{nai}\n")), "{text}");
    assert!(text.contains("X509v3 Subject Key Identifier"), "{text}");
    assert_eq!(
        f.issued.cert().authority_key_id().unwrap().as_slice(),
        f.device_ca.cert().subject_key_id().unwrap().as_slice()
    );
    // validity: from 5 minutes ago, 365 days
    let start = f.issued.not_before().unwrap();
    assert!(start <= now() - Duration::minutes(4) && start >= now() - Duration::minutes(6));
    assert_eq!((f.issued.not_after().unwrap() - start).whole_days(), 365);
    // serial: positive, exactly 128 bits; the registry form is 32 lowercase hex digits
    let serial = f.issued.cert().serial_number().to_bn().unwrap();
    assert!(!serial.is_negative());
    assert_eq!(serial.num_bits(), 128);
    let hex = f.issued.serial_hex().unwrap();
    assert_eq!(hex.len(), 32);
    assert!(hex.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)), "{hex}");
    // what `openssl x509 -serial` (the same bytes FreeRADIUS formats) says
    let (_, out) =
        openssl(&["x509", "-noout", "-serial", "-in", "{c.pem}"], &[("c.pem", &f.issued.cert_pem().unwrap())]);
    assert_eq!(out.trim().to_ascii_lowercase(), format!("serial={hex}"));
}

#[test]
fn test_every_certificate_verifies_as_freeradius_checks_it() {
    if !have("openssl") {
        return;
    }
    let f = fixture();
    pki::verify(f.issued.cert(), &[f.device_ca.cert()], f.root.cert(), Purpose::TlsClient).unwrap();
    // FreeRADIUS: ca_file = device-ca-chain.pem (device CA + root)
    let mut chain = f.device_ca.cert_pem().unwrap();
    chain.extend(f.root.cert_pem().unwrap());
    let (ok, out) = openssl(
        &["verify", "-purpose", "sslclient", "-CAfile", "{chain.pem}", "{leaf.pem}"],
        &[("chain.pem", &chain), ("leaf.pem", &f.issued.cert_pem().unwrap())],
    );
    assert!(ok && out.contains(": OK"), "{out}");
    // a supplicant's view: root trusted, device CA untrusted
    let (ok, out) = openssl(
        &["verify", "-purpose", "sslclient", "-CAfile", "{root.pem}", "-untrusted", "{ca.pem}", "{leaf.pem}"],
        &[
            ("root.pem", &f.root.cert_pem().unwrap()),
            ("ca.pem", &f.device_ca.cert_pem().unwrap()),
            ("leaf.pem", &f.issued.cert_pem().unwrap()),
        ],
    );
    assert!(ok && out.contains(": OK"), "{out}");
    // a device certificate is no server certificate
    assert!(pki::verify(f.issued.cert(), &[f.device_ca.cert()], f.root.cert(), Purpose::TlsServer).is_err());
}

/// A certificate signed with the device CA's key for any other purpose than the one it may
/// sign, built by hand (as an attacker with the stolen key would).
fn forged(device_ca: &Issued, cn: &str, dns: Option<&str>, email: Option<&str>, server: bool) -> X509 {
    let key = pki::generate_key(pki::Curve::P256).unwrap();
    let mut name = openssl::x509::X509Name::builder().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, cn).unwrap();
    let name = name.build();
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    let serial = openssl::bn::BigNum::from_u32(4711).unwrap().to_asn1_integer().unwrap();
    b.set_serial_number(&serial).unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(device_ca.cert().subject_name()).unwrap();
    b.set_pubkey(&key).unwrap();
    b.set_not_before(&openssl::asn1::Asn1Time::days_from_now(0).unwrap()).unwrap();
    b.set_not_after(&openssl::asn1::Asn1Time::days_from_now(30).unwrap()).unwrap();
    b.append_extension(BasicConstraints::new().build().unwrap()).unwrap();
    b.append_extension(KeyUsage::new().digital_signature().build().unwrap()).unwrap();
    let mut eku = ExtendedKeyUsage::new();
    if server {
        eku.server_auth();
    } else {
        eku.client_auth();
    }
    b.append_extension(eku.build().unwrap()).unwrap();
    let mut san = SubjectAlternativeName::new();
    if let Some(dns) = dns {
        san.dns(dns);
    }
    if let Some(email) = email {
        san.email(email);
    }
    let san = san.build(&b.x509v3_context(Some(device_ca.cert()), None)).unwrap();
    b.append_extension(san).unwrap();
    b.sign(device_ca.key(), MessageDigest::sha384()).unwrap();
    b.build()
}

#[test]
fn test_the_device_ca_cannot_mint_server_certificates() {
    if !have("openssl") {
        return;
    }
    let f = fixture();
    let fake = forged(&f.device_ca, "www.example.com", Some("www.example.com"), None, true);
    let err = pki::verify(&fake, &[f.device_ca.cert()], f.root.cert(), Purpose::TlsServer).unwrap_err();
    assert!(err.to_string().contains("excluded subtree") || err.to_string().contains("unsuitable"), "{err}");
    let (ok, out) = openssl(
        &["verify", "-purpose", "sslserver", "-CAfile", "{root.pem}", "-untrusted", "{ca.pem}", "{fake.pem}"],
        &[
            ("root.pem", &f.root.cert_pem().unwrap()),
            ("ca.pem", &f.device_ca.cert_pem().unwrap()),
            ("fake.pem", &fake.to_pem().unwrap()),
        ],
    );
    assert!(!ok, "{out}");
    // even without the purpose check, the name constraints refuse the DNS name: the root's (only
    // the server's name) and the device CA's (no DNS name at all), also for the server's own name
    for (cn, violation) in
        [("www.example.com", "permitted subtree violation"), ("radius.scharni.org", "excluded subtree violation")]
    {
        let fake = forged(&f.device_ca, cn, Some(cn), None, true);
        let (ok, out) = openssl(
            &["verify", "-CAfile", "{root.pem}", "-untrusted", "{ca.pem}", "{fake.pem}"],
            &[
                ("root.pem", &f.root.cert_pem().unwrap()),
                ("ca.pem", &f.device_ca.cert_pem().unwrap()),
                ("fake.pem", &fake.to_pem().unwrap()),
            ],
        );
        assert!(!ok && out.contains(violation), "{cn}: {out}");
    }
}

#[test]
fn test_the_device_ca_issues_only_for_its_realm() {
    let f = fixture();
    let other = pki::device_cert(&f.device_ca, Uuid::new_v4(), "other.example", 30, now()).unwrap();
    let err = pki::verify(other.cert(), &[f.device_ca.cert()], f.root.cert(), Purpose::TlsClient).unwrap_err();
    assert!(err.to_string().contains("permitted subtree"), "{err}");
    let mailbox = forged(&f.device_ca, "x", None, Some("x@scharni.org"), false);
    pki::verify(&mailbox, &[f.device_ca.cert()], f.root.cert(), Purpose::TlsClient).unwrap();
}

#[test]
fn test_validity_is_cut_at_the_issuer() {
    let f = fixture();
    let long =
        pki::device_cert(&f.device_ca, Uuid::new_v4(), "scharni.org", 3650, now() + Duration::days(3000)).unwrap();
    assert_eq!(long.not_after().unwrap(), f.device_ca.not_after().unwrap());
    let late = now() + Duration::days(3651);
    assert!(pki::device_cert(&f.device_ca, Uuid::new_v4(), "scharni.org", 30, late).is_err(), "expired CA");
    assert!(pki::device_cert(&f.device_ca, Uuid::new_v4(), "scharni.org", 0, now()).is_err(), "zero days");
}

#[test]
fn test_serials_are_unique() {
    let f = fixture();
    let serials: std::collections::BTreeSet<String> = (0..64)
        .map(|_| pki::device_cert(&f.device_ca, f.device_id, "scharni.org", 30, now()).unwrap().serial_hex().unwrap())
        .collect();
    assert_eq!(serials.len(), 64);
}

#[test]
fn test_issuer_start_checks() {
    let f = fixture();
    let other = fixture();
    let root_pem = f.root.cert_pem().unwrap();
    let ca_pem = f.device_ca.cert_pem().unwrap();
    let key_pem = f.device_ca.key_pem().unwrap();
    let config = |root: &'static [u8], ca: &'static [u8], key: &'static [u8], realm: &'static str| IssuerConfig {
        root_pem: root,
        device_ca_pem: ca,
        device_ca_key_pem: key,
        realm,
        ssid: "Scharni",
        radius_server_name: "radius.scharni.org",
        display_name: "Scharni",
        cert_days: 365,
        profile_signer: None,
    };
    let leak = |v: Vec<u8>| -> &'static [u8] { Box::leak(v.into_boxed_slice()) };
    let (root, ca, key) = (leak(root_pem), leak(ca_pem), leak(key_pem.to_vec()));
    Issuer::new(config(root, ca, key, "scharni.org")).unwrap();
    // the traditional EC key format (the Python version's old keys) loads too
    let ec = leak(f.device_ca.key().ec_key().unwrap().private_key_to_pem().unwrap());
    assert!(String::from_utf8_lossy(ec).starts_with("-----BEGIN EC PRIVATE KEY-----"));
    Issuer::new(config(root, ca, ec, "scharni.org")).unwrap();
    // a key of another CA
    let wrong_key = leak(other.device_ca.key_pem().unwrap().to_vec());
    let err = Issuer::new(config(root, ca, wrong_key, "scharni.org")).err().unwrap();
    assert!(err.to_string().contains("does not belong"), "{err}");
    // a device CA of another root
    let other_root = leak(other.root.cert_pem().unwrap());
    let err = Issuer::new(config(other_root, ca, key, "scharni.org")).err().unwrap();
    assert!(err.to_string().contains("not signed by the root"), "{err}");
    // a realm outside the device CA's name constraints
    let err = Issuer::new(config(root, ca, key, "house.example.net")).err().unwrap();
    assert!(err.to_string().contains("does not verify"), "{err}");
    // garbage
    assert!(Issuer::new(config(b"x", ca, key, "scharni.org")).is_err());
    assert!(
        Issuer::new(config(root, ca, b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n", "scharni.org"))
            .is_err()
    );
}

#[test]
fn test_a_device_ca_without_name_constraints_serves_every_realm() {
    // the contract suite's fixture PKI comes from the Python ceremony (no name constraints on the
    // root or the device CA) and serves instance B with realm house.example.net
    let legacy_root = {
        let key = pki::generate_key(pki::Curve::P384).unwrap();
        let mut name = openssl::x509::X509Name::builder().unwrap();
        name.append_entry_by_nid(Nid::COMMONNAME, "Legacy Network Root").unwrap();
        let name = name.build();
        let mut b = X509::builder().unwrap();
        b.set_version(2).unwrap();
        b.set_serial_number(&openssl::bn::BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap()).unwrap();
        b.set_subject_name(&name).unwrap();
        b.set_issuer_name(&name).unwrap();
        b.set_pubkey(&key).unwrap();
        b.set_not_before(&openssl::asn1::Asn1Time::days_from_now(0).unwrap()).unwrap();
        b.set_not_after(&openssl::asn1::Asn1Time::days_from_now(3650).unwrap()).unwrap();
        b.append_extension(BasicConstraints::new().critical().ca().pathlen(1).build().unwrap()).unwrap();
        b.append_extension(KeyUsage::new().critical().key_cert_sign().crl_sign().build().unwrap()).unwrap();
        let ski = openssl::x509::extension::SubjectKeyIdentifier::new().build(&b.x509v3_context(None, None)).unwrap();
        b.append_extension(ski).unwrap();
        b.sign(&key, MessageDigest::sha384()).unwrap();
        Issued::new(b.build(), key).unwrap()
    };
    let root = legacy_root;
    let mut b = X509::builder().unwrap();
    let key = pki::generate_key(pki::Curve::P384).unwrap();
    let mut name = openssl::x509::X509Name::builder().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, "Legacy Device CA").unwrap();
    let name = name.build();
    b.set_version(2).unwrap();
    let serial = openssl::bn::BigNum::from_u32(7).unwrap().to_asn1_integer().unwrap();
    b.set_serial_number(&serial).unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(root.cert().subject_name()).unwrap();
    b.set_pubkey(&key).unwrap();
    b.set_not_before(&openssl::asn1::Asn1Time::days_from_now(0).unwrap()).unwrap();
    b.set_not_after(&openssl::asn1::Asn1Time::days_from_now(365).unwrap()).unwrap();
    b.append_extension(BasicConstraints::new().critical().ca().pathlen(0).build().unwrap()).unwrap();
    b.append_extension(KeyUsage::new().critical().digital_signature().key_cert_sign().crl_sign().build().unwrap())
        .unwrap();
    let ski = openssl::x509::extension::SubjectKeyIdentifier::new().build(&b.x509v3_context(None, None)).unwrap();
    b.append_extension(ski).unwrap();
    b.sign(root.key(), MessageDigest::sha384()).unwrap();
    let legacy = b.build();
    let leak = |v: Vec<u8>| -> &'static [u8] { Box::leak(v.into_boxed_slice()) };
    let issuer = Issuer::new(IssuerConfig {
        root_pem: leak(root.cert_pem().unwrap()),
        device_ca_pem: leak(legacy.to_pem().unwrap()),
        device_ca_key_pem: leak(key.private_key_to_pem_pkcs8().unwrap()),
        realm: "house.example.net",
        ssid: "Haus",
        radius_server_name: "radius.house.example.net",
        display_name: "Haus",
        cert_days: 30,
        profile_signer: None,
    })
    .unwrap();
    let issued = issuer.issue(Uuid::new_v4(), now()).unwrap();
    assert_eq!((issued.not_after().unwrap() - issued.not_before().unwrap()).whole_days(), 30);
}
