//! The artefacts against the rules of the systems that read them (Python
//! `tests/test_profiles.py`, INVENTORY 6.3-6.7, the contract suite's `test_artefacts`).

mod common;

use base64::Engine;
use common::{El, aosp_parse, eap_metadata_xsd, fixture, have, now, openssl, parse_xml, run_tool};
use netportal_pki::enroll::{Format, Issuer, IssuerConfig};
use netportal_pki::pkcs12;
use netportal_pki::pki::{self, Purpose};
use netportal_pki::profiles::{self, Network, ProfileSigner};
use openssl::pkcs12::Pkcs12;
use openssl::x509::X509Ref;
use plist::Value;
use uuid::Uuid;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// (key matches, leaf DER, chain DERs) of a PKCS#12.
fn open_p12(der: &[u8], password: &str) -> (Vec<u8>, Vec<Vec<u8>>) {
    let parsed = Pkcs12::from_der(der).unwrap().parse2(password).expect("PKCS#12 opens");
    let key = parsed.pkey.expect("key");
    let cert = parsed.cert.expect("certificate");
    assert!(cert.public_key().unwrap().public_eq(&key), "the key belongs to the certificate");
    let chain = parsed.ca.map(|s| s.iter().map(|c| c.to_der().unwrap()).collect()).unwrap_or_default();
    (cert.to_der().unwrap(), chain)
}

fn der(cert: &X509Ref) -> Vec<u8> {
    cert.to_der().unwrap()
}

// --- PKCS#12 ---------------------------------------------------------------------------------

#[test]
fn test_apple_pkcs12_is_readable_by_apple() {
    let f = fixture();
    let p12 = pkcs12::legacy_3des(&f.issued, &[f.device_ca.cert()], "pa55-word_x", "Scharni Wi-Fi").unwrap();
    let (leaf, chain) = open_p12(&p12, "pa55-word_x");
    assert_eq!(leaf, der(f.issued.cert()));
    assert_eq!(chain, vec![der(f.device_ca.cert())]);
    assert!(Pkcs12::from_der(&p12).unwrap().parse2("wrong").is_err());
    if !have("openssl") {
        return;
    }
    // OpenSSL 3, default provider only (no -legacy): 3DES bags, SHA-1 MAC, 2048 iterations
    for legacy in [false, true] {
        let mut args = vec!["pkcs12", "-info", "-noout", "-in", "{p.p12}", "-passin", "pass:pa55-word_x"];
        if legacy {
            args.push("-legacy");
        }
        let (ok, out) = openssl(&args, &[("p.p12", &p12)]);
        assert!(ok, "{out}");
        assert!(out.contains("MAC: sha1, Iteration 2048"), "{out}");
        assert!(out.contains("PKCS7 Encrypted data: pbeWithSHA1And3-KeyTripleDES-CBC, Iteration 2048"), "{out}");
        assert!(out.contains("Shrouded Keybag: pbeWithSHA1And3-KeyTripleDES-CBC, Iteration 2048"), "{out}");
        assert!(!out.contains("PBES2") && !out.contains("RC2"), "{out}");
    }
    // the bag attributes: friendlyName and localKeyID on the leaf and the key
    let (ok, out) =
        openssl(&["pkcs12", "-info", "-nodes", "-in", "{p.p12}", "-passin", "pass:pa55-word_x"], &[("p.p12", &p12)]);
    assert!(ok, "{out}");
    assert_eq!(out.matches("friendlyName: Scharni Wi-Fi").count(), 2, "{out}");
    assert_eq!(out.matches("localKeyID:").count(), 2, "{out}");
    assert_eq!(out.matches("-----BEGIN CERTIFICATE-----").count(), 2, "{out}");
    let (ok, out) =
        openssl(&["pkcs12", "-info", "-noout", "-in", "{p.p12}", "-passin", "pass:nope"], &[("p.p12", &p12)]);
    assert!(!ok && out.contains("Mac verify error"), "{out}");
}

#[test]
fn test_passpoint_pkcs12_opens_with_an_empty_password() {
    let f = fixture();
    let p12 = pkcs12::clear(&f.issued, &[f.device_ca.cert()]).unwrap();
    let (leaf, chain) = open_p12(&p12, "");
    assert_eq!(leaf, der(f.issued.cert()));
    assert_eq!(chain, vec![der(f.device_ca.cert())]);
    if !have("openssl") {
        return;
    }
    let (ok, out) = openssl(&["pkcs12", "-info", "-noout", "-in", "{p.p12}", "-passin", "pass:"], &[("p.p12", &p12)]);
    assert!(ok, "{out}");
    assert!(out.contains("MAC: sha1, Iteration 1"), "{out}");
    assert!(!out.contains("Encrypted data") && !out.contains("Shrouded"), "{out}");
    assert_eq!(out.matches("PKCS7 Data").count(), 2, "{out}");
    assert!(out.contains("Key bag"), "{out}");
    // one key entry for AOSP's ks.size() == 1: localKeyID on leaf and key, no friendlyName
    let (ok, out) = openssl(&["pkcs12", "-info", "-nodes", "-in", "{p.p12}", "-passin", "pass:"], &[("p.p12", &p12)]);
    assert!(ok, "{out}");
    assert_eq!(out.matches("localKeyID:").count(), 2, "{out}");
    assert!(!out.contains("friendlyName"), "{out}");
    assert_eq!(out.matches("-----BEGIN PRIVATE KEY-----").count(), 1, "{out}");
    let (ok, _) =
        openssl(&["pkcs12", "-info", "-noout", "-legacy", "-in", "{p.p12}", "-passin", "pass:"], &[("p.p12", &p12)]);
    assert!(ok);
}

#[test]
fn test_pkcs12_input_checks() {
    let f = fixture();
    assert!(pkcs12::legacy_3des(&f.issued, &[], "", "x").is_err());
    assert!(pkcs12::legacy_3des(&f.issued, &[], "a\0b", "x").is_err());
    assert!(pkcs12::legacy_3des(&f.issued, &[], "secret", "a\0b").is_err());
}

// --- Apple ---------------------------------------------------------------------------------

fn plist_dict(body: &[u8]) -> plist::Dictionary {
    Value::from_reader_xml(body).expect("XML plist").into_dictionary().expect("dictionary")
}

fn payload<'a>(profile: &'a plist::Dictionary, kind: &str) -> Option<&'a plist::Dictionary> {
    profile["PayloadContent"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p.as_dictionary().unwrap())
        .find(|p| p["PayloadType"].as_string() == Some(kind))
}

fn string<'a>(d: &'a plist::Dictionary, key: &str) -> &'a str {
    d.get(key).and_then(Value::as_string).unwrap_or_else(|| panic!("{key}"))
}

fn is_upper_uuid(s: &str) -> bool {
    Uuid::parse_str(s).is_ok() && s == s.to_uppercase() && s.len() == 36
}

#[test]
fn test_profile_structure() {
    let f = fixture();
    for ethernet in [false, true] {
        let body =
            profiles::apple_mobileconfig(&f.net, &f.issued, &[f.device_ca.cert()], f.device_id, ethernet).unwrap();
        assert!(body.starts_with(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC"));
        let profile = plist_dict(&body);
        assert_eq!(string(&profile, "PayloadType"), "Configuration");
        assert_eq!(profile["PayloadVersion"].as_signed_integer(), Some(1));
        assert_eq!(profile["PayloadRemovalDisallowed"].as_boolean(), Some(false));
        assert_eq!(string(&profile, "PayloadDisplayName"), "Scharni");
        let top = string(&profile, "PayloadIdentifier");
        assert_eq!(top, format!("org.scharni.network.{}", f.device_id));
        let root = payload(&profile, "com.apple.security.root").unwrap();
        assert_eq!(root["PayloadContent"].as_data().unwrap(), der(f.root.cert()));
        let ident = payload(&profile, "com.apple.security.pkcs12").unwrap();
        let password = string(ident, "Password");
        assert_eq!(password.len(), 24);
        let (leaf, chain) = open_p12(ident["PayloadContent"].as_data().unwrap(), password);
        assert_eq!(leaf, der(f.issued.cert()));
        assert_eq!(chain, vec![der(f.device_ca.cert())]);
        let wifi = payload(&profile, "com.apple.wifi.managed").unwrap();
        assert_eq!(string(wifi, "SSID_STR"), "Scharni");
        assert_eq!(string(wifi, "EncryptionType"), "WPA2");
        assert_eq!(wifi["AutoJoin"].as_boolean(), Some(true));
        assert_eq!(wifi["HIDDEN_NETWORK"].as_boolean(), Some(false));
        let ethernet_payload = payload(&profile, "com.apple.firstactiveethernet.managed");
        assert_eq!(ethernet_payload.is_some(), ethernet, "iOS refuses an Ethernet payload");
        let mut refs = vec![wifi];
        if let Some(eth) = ethernet_payload {
            assert_eq!(string(eth, "Interface"), "FirstActiveEthernet");
            refs.push(eth);
        }
        for p in refs {
            assert_eq!(string(p, "PayloadCertificateUUID"), string(ident, "PayloadUUID"));
            assert!(!p.contains_key("PayloadCertificateAnchorUUID"), "Apple reads it inside EAPClientConfiguration");
            let eap = p["EAPClientConfiguration"].as_dictionary().unwrap();
            let types: Vec<i64> =
                eap["AcceptEAPTypes"].as_array().unwrap().iter().filter_map(Value::as_signed_integer).collect();
            assert_eq!(types, vec![13]);
            let names: Vec<&str> =
                eap["TLSTrustedServerNames"].as_array().unwrap().iter().filter_map(Value::as_string).collect();
            assert_eq!(names, vec!["radius.scharni.org"]);
            assert_eq!(string(eap, "UserName"), "anonymous@scharni.org");
            let anchors: Vec<&str> =
                eap["PayloadCertificateAnchorUUID"].as_array().unwrap().iter().filter_map(Value::as_string).collect();
            assert_eq!(anchors, vec![string(root, "PayloadUUID")]);
            assert_eq!(string(eap, "TLSMinimumVersion"), "1.2");
            assert_eq!(string(eap, "TLSMaximumVersion"), "1.3");
            assert!(!eap.contains_key("TLSAllowTrustExceptions"));
        }
        // every payload: version 1, unique upper-case UUID, identifier under the top one
        let payloads = profile["PayloadContent"].as_array().unwrap();
        let mut uuids = vec![string(&profile, "PayloadUUID").to_string()];
        let mut idents = vec![top.to_string()];
        for p in payloads {
            let p = p.as_dictionary().unwrap();
            assert_eq!(p["PayloadVersion"].as_signed_integer(), Some(1));
            uuids.push(string(p, "PayloadUUID").to_string());
            idents.push(string(p, "PayloadIdentifier").to_string());
        }
        assert!(uuids.iter().all(|u| is_upper_uuid(u)), "{uuids:?}");
        let unique: std::collections::BTreeSet<_> = uuids.iter().collect();
        assert_eq!(unique.len(), uuids.len());
        let mut expected = vec![top.to_string()];
        for suffix in ["root", "device", "wifi"].into_iter().chain(ethernet.then_some("ethernet")) {
            expected.push(format!("{top}.{suffix}"));
        }
        assert_eq!(idents, expected);
    }
}

#[test]
fn test_ios_profile_has_no_ethernet() {
    let f = fixture();
    let body = profiles::apple_mobileconfig(&f.net, &f.issued, &[f.device_ca.cert()], f.device_id, false).unwrap();
    assert!(payload(&plist_dict(&body), "com.apple.firstactiveethernet.managed").is_none());
}

#[test]
fn test_profile_identifier_stays_with_the_device() {
    let f = fixture();
    let ident = |device: Uuid| {
        let issued = pki::device_cert(&f.device_ca, device, "scharni.org", 30, now()).unwrap();
        let body = profiles::apple_mobileconfig(&f.net, &issued, &[f.device_ca.cert()], device, false).unwrap();
        string(&plist_dict(&body), "PayloadIdentifier").to_string()
    };
    let first = ident(f.device_id);
    assert_eq!(ident(f.device_id), first, "a renewal replaces the installed profile");
    assert_ne!(ident(Uuid::new_v4()), first, "another device gets its own profile");
    // reverse DNS of the realm, no doubled "org."
    assert!(first.starts_with("org.scharni.network."));
    let net = Network::new("house.example.net", "Haus", "radius.house.example.net", "Haus", f.root.cert()).unwrap();
    assert_eq!(net.apple_profile_identifier(f.device_id), format!("net.example.house.network.{}", f.device_id));
}

#[test]
fn test_profile_with_non_ascii_names() {
    let f = fixture();
    let net =
        Network::new("scharni.org", "Schärni 🏠", "radius.scharni.org", "Schärni & <Haus>", f.root.cert()).unwrap();
    let body = profiles::apple_mobileconfig(&net, &f.issued, &[f.device_ca.cert()], f.device_id, true).unwrap();
    let profile = plist_dict(&body);
    assert_eq!(string(&profile, "PayloadDisplayName"), "Schärni & <Haus>");
    assert_eq!(string(payload(&profile, "com.apple.wifi.managed").unwrap(), "SSID_STR"), "Schärni 🏠");
    if have("python3") {
        // an independent reader (CPython's plistlib, the Python version's writer)
        let (ok, out) = run_tool(
            "python3",
            &[
                "-I",
                "-c",
                "import plistlib,sys; p=plistlib.load(open(sys.argv[1],'rb')); print(p['PayloadContent'][2]['SSID_STR'])",
                "{p.plist}",
            ],
            &[("p.plist", &body)],
        );
        assert!(ok && out.trim() == "Schärni 🏠", "{out}");
    }
}

#[test]
fn test_signed_profile_verifies() {
    if !have("openssl") {
        return;
    }
    let f = fixture();
    // a stand-in signer: the RADIUS server certificate and key of the fixture
    let mut certs = f.server.cert_pem().unwrap();
    certs.extend(f.root.cert_pem().unwrap());
    let signer = ProfileSigner::from_pem(&certs, &f.server.key_pem().unwrap()).unwrap();
    let body = profiles::apple_mobileconfig(&f.net, &f.issued, &[f.device_ca.cert()], f.device_id, false).unwrap();
    let signed = profiles::sign_profile(&body, &signer).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let content = dir.path().join("content");
    let (ok, out) = openssl(
        &[
            "cms",
            "-verify",
            "-inform",
            "DER",
            "-in",
            "{s.der}",
            "-CAfile",
            "{root.pem}",
            "-purpose",
            "any",
            "-binary",
            "-out",
            content.to_str().unwrap(),
        ],
        &[("s.der", &signed), ("root.pem", &f.root.cert_pem().unwrap())],
    );
    assert!(ok && out.contains("Verification successful"), "{out}");
    assert_eq!(std::fs::read(content).unwrap(), body);
    // a key that does not belong to the signer certificate is refused
    assert!(ProfileSigner::from_pem(&certs, &f.issued.key_pem().unwrap()).is_err());
}

// --- Android Passpoint ---------------------------------------------------------------------

#[test]
fn test_android_installer_reads_it() {
    let f = fixture();
    let body = profiles::android_wifi_config(&f.net, &f.issued, &[f.device_ca.cert()]).unwrap();
    assert!(!body.contains(&b'\n') && !body.contains(&b'\r'), "one line of base64");
    let (outer, boundary, parts) = aosp_parse(&body);
    assert_eq!(outer[0].0, "Content-Type");
    assert!(boundary.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-'), "RFC 2046 boundary: {boundary}");
    let kinds: Vec<&str> = parts.iter().map(|p| p.0.as_str()).collect();
    assert_eq!(kinds, ["application/x-passpoint-profile", "application/x-x509-ca-cert", "application/x-pkcs12"]);
    assert!(parts.iter().all(|p| p.1 == "base64"));
    // CA part: one X.509 certificate, our root
    assert_eq!(parts[1].2, der(f.root.cert()));
    // PKCS#12: loads with an empty password (KeyStore.load(in, new char[0])), one key + chain
    let (leaf, chain) = open_p12(&parts[2].2, "");
    assert_eq!(leaf, der(f.issued.cert()));
    assert_eq!(chain, vec![der(f.device_ca.cert())]);
    // PPS MO: AOSP's XMLParser is a plain SAX parser (not namespace aware)
    let pps_xml = &parts[0].2;
    assert!(!pps_xml.starts_with(b"<?xml"));
    let tree = parse_xml(pps_xml);
    assert_eq!(tree.name, "MgmtTree");
    assert_eq!(tree.attr("xmlns"), Some("syncml:dmddf1.2"));
    assert_eq!(tree.child("VerDTD").unwrap().text, "1.2");
    let pps = tree.node("PerProviderSubscription");
    assert_eq!(pps.path("RTProperties/Type/DDFName").text, "urn:wfa:mo:hotspot2dot0-perprovidersubscription:1.0");
    let inst = pps.node("i001");
    let home = inst.node("HomeSP");
    assert_eq!(home.node("FriendlyName").value(), "Scharni");
    assert_eq!(home.node("FQDN").value(), "scharni.org");
    let cred = inst.node("Credential");
    assert_eq!(cred.node("Realm").value(), "scharni.org");
    let dc = cred.node("DigitalCertificate");
    assert_eq!(dc.node("CertificateType").value(), "x509v3");
    let fp = dc.node("CertSHA256Fingerprint").value();
    assert_eq!(fp, hex::encode(f.issued.cert().digest(openssl::hash::MessageDigest::sha256()).unwrap()));
    // Android 11+: the RADIUS server name pinned (domain suffix match)
    let trusted = inst.node("Extension").node("Android").node("AAAServerTrustedNames").node("FQDN").value();
    assert_eq!(trusted, "radius.scharni.org");
    // nothing else at the instance level (PpsMoParser refuses unknown nodes there)
    let names: Vec<&str> =
        inst.children.iter().filter(|c| c.name == "Node").map(|n| n.child("NodeName").unwrap().text.as_str()).collect();
    assert_eq!(names, ["HomeSP", "Credential", "Extension"]);
    if have("openssl") {
        let (ok, out) =
            openssl(&["pkcs12", "-info", "-noout", "-in", "{p.p12}", "-passin", "pass:"], &[("p.p12", &parts[2].2)]);
        assert!(ok && !out.contains("Encrypted data"), "{out}");
    }
}

#[test]
fn test_pps_mo_escapes_and_keeps_utf8() {
    let f = fixture();
    let net = Network::new("scharni.org", "Scharni", "radius.scharni.org", "Schärni & <Co>", f.root.cert()).unwrap();
    let xml = profiles::pps_mo(&net, &f.issued).unwrap();
    assert!(xml.contains("<Value>Schärni &amp; &lt;Co&gt;</Value>"), "{xml}");
    assert_eq!(
        parse_xml(xml.as_bytes())
            .node("PerProviderSubscription")
            .node("i001")
            .node("HomeSP")
            .node("FriendlyName")
            .value(),
        "Schärni & <Co>"
    );
}

// --- eap-config ------------------------------------------------------------------------------

fn eap_checks(tree: &El, net: &Network, issued_not_after: &str, root_der: &[u8], expected_leaf: &[u8]) {
    assert_eq!(tree.name, "EAPIdentityProviderList");
    let idp = tree.child("EAPIdentityProvider").unwrap();
    assert_eq!(idp.attr("ID"), Some(net.realm()));
    assert_eq!(idp.attr("namespace"), Some("urn:RFC4282:realm"));
    assert_eq!(idp.child("ValidUntil").unwrap().text, issued_not_after);
    let method = idp.path("AuthenticationMethods/AuthenticationMethod");
    assert_eq!(method.path("EAPMethod/Type").text, "13");
    let ca = method.path("ServerSideCredential/CA");
    assert_eq!((ca.attr("format"), ca.attr("encoding")), (Some("X.509"), Some("base64")));
    assert_eq!(B64.decode(&ca.text).unwrap(), root_der);
    assert_eq!(method.path("ServerSideCredential/ServerID").text, net.server_name());
    let client = method.child("ClientSideCredential").unwrap();
    assert_eq!(client.child("OuterIdentity").unwrap().text, net.outer_identity());
    let cc = client.child("ClientCertificate").unwrap();
    assert_eq!((cc.attr("format"), cc.attr("encoding")), (Some("PKCS12"), Some("base64")));
    let passphrase = &client.child("Passphrase").unwrap().text;
    assert_eq!(passphrase.len(), 20);
    let (leaf, _) = open_p12(&B64.decode(&cc.text).unwrap(), passphrase);
    assert_eq!(leaf, expected_leaf);
    assert_eq!(idp.path("CredentialApplicability/IEEE80211/SSID").text, net.ssid());
    assert_eq!(idp.path("CredentialApplicability/IEEE80211/MinRSNProto").text, "CCMP");
    assert_eq!(idp.path("ProviderInfo/DisplayName").text, net.display_name());
}

fn not_after_text(issued: &pki::Issued) -> String {
    issued
        .not_after()
        .unwrap()
        .format(time::macros::format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z"))
        .unwrap()
}

#[test]
fn test_valid_against_the_geant_schema() {
    let f = fixture();
    let odd = Network::new("scharni.org", "Schärni <&> \"'", "radius.scharni.org", "Ä & B", f.root.cert()).unwrap();
    for net in [&f.net, &odd] {
        let doc = profiles::eap_config(net, &f.issued, &[f.device_ca.cert()]).unwrap();
        assert!(doc.starts_with(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><EAPIdentityProviderList"));
        eap_checks(&parse_xml(&doc), net, &not_after_text(&f.issued), &der(f.root.cert()), &der(f.issued.cert()));
        if let Some(xsd) = eap_metadata_xsd()
            && have("xmllint")
        {
            let (ok, out) =
                run_tool("xmllint", &["--noout", "--schema", xsd.to_str().unwrap(), "{doc.xml}"], &[("doc.xml", &doc)]);
            assert!(ok && out.contains("validates"), "{out}");
        }
    }
}

// --- Issuer: issue + artefact per format ---------------------------------------------------

fn issuer(f: &common::Fixture, realm: &'static str) -> Issuer {
    let leak = |v: Vec<u8>| -> &'static [u8] { Box::leak(v.into_boxed_slice()) };
    Issuer::new(IssuerConfig {
        root_pem: leak(f.root.cert_pem().unwrap()),
        device_ca_pem: leak(f.device_ca.cert_pem().unwrap()),
        device_ca_key_pem: leak(f.device_ca.key_pem().unwrap().to_vec()),
        realm,
        ssid: "Scharni",
        radius_server_name: "radius.scharni.org",
        display_name: "Scharni",
        cert_days: 365,
        profile_signer: None,
    })
    .unwrap()
}

/// The certificate inside an artefact, the way the contract suite's `credentials_of` reads it.
fn leaf_of(format: Format, body: &[u8]) -> Vec<u8> {
    match format {
        Format::Apple | Format::AppleMac => {
            let profile = plist_dict(body);
            let ident = payload(&profile, "com.apple.security.pkcs12").unwrap();
            open_p12(ident["PayloadContent"].as_data().unwrap(), string(ident, "Password")).0
        }
        Format::Android => open_p12(&aosp_parse(body).2[2].2, "").0,
        Format::EapConfig | Format::LetsWifi => {
            let tree = parse_xml(body);
            let client =
                tree.path("EAPIdentityProvider/AuthenticationMethods/AuthenticationMethod/ClientSideCredential");
            open_p12(
                &B64.decode(&client.child("ClientCertificate").unwrap().text).unwrap(),
                &client.child("Passphrase").unwrap().text,
            )
            .0
        }
    }
}

#[test]
fn test_every_format_carries_a_certificate_that_verifies() {
    let f = fixture();
    let issuer = issuer(&f, "scharni.org");
    let mut serials = std::collections::BTreeSet::new();
    for format in [Format::Apple, Format::AppleMac, Format::Android, Format::EapConfig, Format::LetsWifi] {
        let device = Uuid::new_v4();
        let issued = issuer.issue(device, now()).unwrap();
        let artefact = issuer.artefact(&issued, device, format).unwrap();
        let leaf = openssl::x509::X509::from_der(&leaf_of(format, &artefact.body)).unwrap();
        assert_eq!(der(&leaf), der(issued.cert()), "{format:?}");
        assert_eq!(pki::subject_cn(&leaf).unwrap(), format!("{device}@scharni.org"));
        pki::verify(&leaf, &[issuer.device_ca()], issuer.root(), Purpose::TlsClient).unwrap();
        serials.insert(issued.serial_hex().unwrap());
        assert!(!format!("{artefact:?}").contains("PRIVATE"), "Debug never shows the body");
    }
    assert_eq!(serials.len(), 5);
}
