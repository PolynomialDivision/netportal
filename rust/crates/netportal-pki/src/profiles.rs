//! Onboarding artefacts for one device certificate (Python `netportal/profiles.py`).
//!
//! - Apple (iOS, iPadOS, macOS): a configuration profile with the PKCS#12 identity, the root as
//!   the only anchor, the RADIUS server name pinned, the Wi-Fi payload and (macOS) the wired
//!   802.1X payload. Keys as in Apple's schema
//!   (<https://github.com/apple/device-management>, `mdm/profiles/com.apple.wifi.managed.yaml`,
//!   `com.apple.firstactiveethernet.managed.yaml`, `com.apple.security.pkcs12.yaml`).
//! - Android Passpoint: `application/x-wifi-config` as AOSP's `ConfigParser` and
//!   `PpsMoParser` read it (packages/modules/Wifi, `framework/java/android/net/wifi/hotspot2/`).
//! - eap-config (geteduroam apps, Let's Wi-Fi API): GÉANT CAT `eap-metadata.xsd`.
//!
//! No personal data: the outer identity is `anonymous@<realm>` and the certificate subject a
//! random device ID.
//!
//! # Apple PayloadIdentifier
//!
//! iOS and macOS replace an installed profile that has the same top-level `PayloadIdentifier`
//! and add a new one otherwise. The identifier is reverse DNS of the realm plus the device id,
//! `<reversed realm>.network.<device uuid>` (`org.scharni.network.<uuid>` for `scharni.org`),
//! so a renewal of a device replaces its profile and two devices never collide. The payloads
//! inside are named under it (`.root`, `.device`, `.wifi`, `.ethernet`), so they are unique
//! across profiles too. The Python version wrote `org.org.scharni.network...` (an extra
//! `org.` in front of the reversed realm) and shared payload identifiers between profiles.
//!
//! # Profile signing: available, off by default
//!
//! [`sign_profile`] wraps a profile in CMS SignedData. A device shows a signed profile as
//! "Verified" only if the signer chains to a root it already trusts, i.e. a publicly trusted
//! certificate: our own root arrives inside the very profile, so a signature by our PKI shows
//! "Not Verified" and adds nothing. The only certificate the house has that devices trust is
//! the Let's Encrypt certificate of the portal's host name, and its key belongs to Caddy, not
//! to the portal; handing it over widens what a compromised portal leaks, and it rotates every
//! few weeks. Integrity of the download is already given by TLS, the login and the one-time
//! token. So profiles go out unsigned, as before; a deployment that wants the "Verified" badge
//! can configure a signer (certificate chain and key) and the web crate passes it here.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
use openssl::pkey::{PKey, Private};
use openssl::stack::Stack;
use openssl::x509::{X509, X509Ref};
use plist::{Dictionary, Value};
use quick_xml::Writer;
use quick_xml::events::{BytesDecl, BytesEnd, BytesStart, BytesText, Event};
use time::macros::format_description;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::Error;
use crate::pkcs12;
use crate::pki::{self, Issued};

/// EAP type number of EAP-TLS (RFC 5216).
pub const EAP_TLS: i64 = 13;

/// The network the artefacts configure (one per portal).
#[derive(Clone, Debug)]
pub struct Network {
    realm: String,
    ssid: String,
    server_name: String,
    display_name: String,
    root_der: Vec<u8>,
}

fn no_control(value: &str, what: &str) -> Result<(), Error> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(Error::Invalid(format!("{what} must be non-empty text without control characters")));
    }
    Ok(())
}

impl Network {
    /// `realm` (outer identity realm, certificate NAI realm, Passpoint FQDN), `ssid` (the
    /// 802.1X SSID, at most 32 octets), `server_name` (the RADIUS certificate name clients pin),
    /// `display_name` (what people see), `root` (the anchor, the offline root).
    pub fn new(realm: &str, ssid: &str, server_name: &str, display_name: &str, root: &X509Ref) -> Result<Self, Error> {
        pki::check_dns_name(realm, "realm")?;
        pki::check_dns_name(server_name, "RADIUS server name")?;
        no_control(ssid, "the SSID")?;
        if ssid.len() > 32 {
            return Err(Error::Invalid("an SSID has at most 32 octets".into()));
        }
        no_control(display_name, "the display name")?;
        Ok(Network {
            realm: realm.to_ascii_lowercase(),
            ssid: ssid.to_string(),
            server_name: server_name.to_ascii_lowercase(),
            display_name: display_name.to_string(),
            root_der: root.to_der()?,
        })
    }

    pub fn realm(&self) -> &str {
        &self.realm
    }

    pub fn ssid(&self) -> &str {
        &self.ssid
    }

    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    pub fn root_der(&self) -> &[u8] {
        &self.root_der
    }

    /// The outer EAP identity: anonymous, only the realm (routing).
    pub fn outer_identity(&self) -> String {
        format!("anonymous@{}", self.realm)
    }

    /// Reverse DNS of the realm: `scharni.org` -> `org.scharni`.
    pub fn reverse_realm(&self) -> String {
        self.realm.rsplit('.').collect::<Vec<_>>().join(".")
    }

    /// The top-level Apple PayloadIdentifier of a device's profile (see the module docs).
    pub fn apple_profile_identifier(&self, device_id: Uuid) -> String {
        format!("{}.network.{}", self.reverse_realm(), device_id.hyphenated())
    }
}

/// A random password of `bytes` CSPRNG bytes, base64url without padding.
fn random_password(bytes: usize) -> Result<Zeroizing<String>, Error> {
    let mut raw = Zeroizing::new(vec![0u8; bytes]);
    openssl::rand::rand_bytes(&mut raw)?;
    Ok(Zeroizing::new(URL_SAFE_NO_PAD.encode(&raw[..])))
}

fn upper_uuid() -> String {
    Uuid::new_v4().hyphenated().to_string().to_uppercase()
}

fn dict(entries: Vec<(&str, Value)>) -> Value {
    let mut d = Dictionary::new();
    for (key, value) in entries {
        d.insert(key.to_string(), value);
    }
    d.sort_keys();
    Value::Dictionary(d)
}

fn s(text: &str) -> Value {
    Value::String(text.to_string())
}

// --- Apple ---------------------------------------------------------------------------------

/// A configuration profile (XML plist). `ethernet` adds the macOS wired 802.1X payload (iOS
/// refuses a profile with that payload type, so only for the `apple-mac` format).
pub fn apple_mobileconfig(
    net: &Network,
    issued: &Issued,
    chain: &[&X509Ref],
    device_id: Uuid,
    ethernet: bool,
) -> Result<Vec<u8>, Error> {
    let password = random_password(18)?; // 24 characters
    let p12 = pkcs12::legacy_3des(issued, chain, &password, &net.display_name)?;
    let top = net.apple_profile_identifier(device_id);
    let (root_uuid, ident_uuid) = (upper_uuid(), upper_uuid());
    let eap = || {
        dict(vec![
            ("AcceptEAPTypes", Value::Array(vec![Value::Integer(EAP_TLS.into())])),
            ("UserName", s(&net.outer_identity())),
            ("TLSTrustedServerNames", Value::Array(vec![s(&net.server_name)])),
            // Apple's schema: a key of EAPClientConfiguration (the Python version put it next
            // to it, where it is ignored)
            ("PayloadCertificateAnchorUUID", Value::Array(vec![s(&root_uuid)])),
            ("TLSMinimumVersion", s("1.2")),
            ("TLSMaximumVersion", s("1.3")),
        ])
    };
    let mut payloads = vec![
        dict(vec![
            ("PayloadType", s("com.apple.security.root")),
            ("PayloadVersion", Value::Integer(1.into())),
            ("PayloadIdentifier", s(&format!("{top}.root"))),
            ("PayloadUUID", s(&root_uuid)),
            ("PayloadDisplayName", s(&format!("{} root CA", net.display_name))),
            ("PayloadContent", Value::Data(net.root_der.clone())),
        ]),
        dict(vec![
            ("PayloadType", s("com.apple.security.pkcs12")),
            ("PayloadVersion", Value::Integer(1.into())),
            ("PayloadIdentifier", s(&format!("{top}.device"))),
            ("PayloadUUID", s(&ident_uuid)),
            ("PayloadDisplayName", s(&format!("{} device", net.display_name))),
            ("PayloadContent", Value::Data(p12.to_vec())),
            ("Password", s(&password)),
        ]),
        dict(vec![
            ("PayloadType", s("com.apple.wifi.managed")),
            ("PayloadVersion", Value::Integer(1.into())),
            ("PayloadIdentifier", s(&format!("{top}.wifi"))),
            ("PayloadUUID", s(&upper_uuid())),
            ("PayloadDisplayName", s(&format!("{} Wi-Fi", net.display_name))),
            ("SSID_STR", s(&net.ssid)),
            // iOS 16+/macOS 13+: WPA2 joins WPA2 and WPA3; before, every WPA type was equivalent
            ("EncryptionType", s("WPA2")),
            ("AutoJoin", Value::Boolean(true)),
            ("HIDDEN_NETWORK", Value::Boolean(false)),
            ("EAPClientConfiguration", eap()),
            ("PayloadCertificateUUID", s(&ident_uuid)),
        ]),
    ];
    if ethernet {
        payloads.push(dict(vec![
            ("PayloadType", s("com.apple.firstactiveethernet.managed")),
            ("PayloadVersion", Value::Integer(1.into())),
            ("PayloadIdentifier", s(&format!("{top}.ethernet"))),
            ("PayloadUUID", s(&upper_uuid())),
            ("PayloadDisplayName", s(&format!("{} Ethernet", net.display_name))),
            ("Interface", s("FirstActiveEthernet")),
            ("EAPClientConfiguration", eap()),
            ("PayloadCertificateUUID", s(&ident_uuid)),
        ]));
    }
    let profile = dict(vec![
        ("PayloadType", s("Configuration")),
        ("PayloadVersion", Value::Integer(1.into())),
        ("PayloadIdentifier", s(&top)),
        ("PayloadUUID", s(&upper_uuid())),
        ("PayloadDisplayName", s(&net.display_name)),
        (
            "PayloadDescription",
            s(&format!(
                "Wi-Fi{} of {} with this device's own certificate.",
                if ethernet { " and Ethernet" } else { "" },
                net.display_name
            )),
        ),
        ("PayloadOrganization", s(&net.display_name)),
        ("PayloadRemovalDisallowed", Value::Boolean(false)),
        ("PayloadContent", Value::Array(payloads)),
    ]);
    let mut out = Vec::new();
    profile.to_writer_xml(&mut out)?;
    Ok(out)
}

/// A signer for configuration profiles (see the module docs: off by default).
pub struct ProfileSigner {
    cert: X509,
    key: PKey<Private>,
    chain: Vec<X509>,
}

impl ProfileSigner {
    /// The signer certificate followed by its intermediates (PEM), and its key (PEM).
    pub fn from_pem(certs_pem: &[u8], key_pem: &[u8]) -> Result<Self, Error> {
        let mut certs = X509::stack_from_pem(certs_pem)?.into_iter();
        let cert = certs.next().ok_or_else(|| Error::Invalid("no signer certificate".into()))?;
        let issued = Issued::new(cert, PKey::private_key_from_pem(key_pem)?)?;
        let (cert, key) = (issued.cert().to_owned(), issued.key().to_owned());
        Ok(ProfileSigner { cert, key, chain: certs.collect() })
    }
}

/// A signed profile: CMS SignedData (DER) with the profile as attached content, as Apple
/// devices and `security cms -D` read it. Content-Type stays `application/x-apple-aspen-config`.
pub fn sign_profile(profile: &[u8], signer: &ProfileSigner) -> Result<Vec<u8>, Error> {
    let mut chain = Stack::new()?;
    for cert in &signer.chain {
        chain.push(cert.clone())?;
    }
    Ok(Pkcs7::sign(&signer.cert, &signer.key, &chain, profile, Pkcs7Flags::BINARY)?.to_der()?)
}

// --- XML -------------------------------------------------------------------------------------

/// A small XML writer: elements with escaped text and attributes, no whitespace.
struct Xml(Writer<Vec<u8>>);

impl Xml {
    fn new() -> Self {
        Xml(Writer::new(Vec::new()))
    }

    fn event(&mut self, event: Event<'_>) -> Result<&mut Self, Error> {
        self.0.write_event(event).map_err(|e| Error::Xml(e.to_string()))?;
        Ok(self)
    }

    fn open(&mut self, name: &str, attrs: &[(&str, &str)]) -> Result<&mut Self, Error> {
        self.event(Event::Start(BytesStart::new(name).with_attributes(attrs.iter().copied())))
    }

    fn close(&mut self, name: &str) -> Result<&mut Self, Error> {
        self.event(Event::End(BytesEnd::new(name)))
    }

    fn leaf(&mut self, name: &str, attrs: &[(&str, &str)], text: &str) -> Result<&mut Self, Error> {
        self.open(name, attrs)?.event(Event::Text(BytesText::new(text)))?.close(name)
    }

    fn finish(self) -> Vec<u8> {
        self.0.into_inner()
    }
}

// --- Android Passpoint -----------------------------------------------------------------------

/// An OMA-DM `<Node>`: the name, then a value or child nodes written by `children`.
fn node(x: &mut Xml, name: &str, children: impl FnOnce(&mut Xml) -> Result<(), Error>) -> Result<(), Error> {
    x.open("Node", &[])?.leaf("NodeName", &[], name)?;
    children(x)?;
    x.close("Node")?;
    Ok(())
}

fn value_node(x: &mut Xml, name: &str, value: &str) -> Result<(), Error> {
    node(x, name, |x| x.leaf("Value", &[], value).map(|_| ()))
}

/// The PerProviderSubscription MO (Hotspot 2.0, OMA-DM XML) with an EAP-TLS certificate
/// credential. Android derives EAP-TLS from `DigitalCertificate`, trusts the CA part and checks
/// the server name: Android 8-10 against the HomeSP FQDN (the realm, as a domain suffix),
/// Android 11+ against `Extension/Android/AAAServerTrustedNames/FQDN` (the RADIUS server name;
/// `PpsMoParser.parseVendorAndroidExtension`, `PasspointProvider` sets it as the domain suffix
/// match; Android 8-10 skip the `Extension` node). UTF-8, no XML declaration.
pub fn pps_mo(net: &Network, issued: &Issued) -> Result<String, Error> {
    let fingerprint = pki::fingerprint_sha256(issued.cert())?;
    let mut x = Xml::new();
    x.open("MgmtTree", &[("xmlns", "syncml:dmddf1.2")])?.leaf("VerDTD", &[], "1.2")?;
    node(&mut x, "PerProviderSubscription", |x| {
        x.open("RTProperties", &[])?
            .open("Type", &[])?
            .leaf("DDFName", &[], "urn:wfa:mo:hotspot2dot0-perprovidersubscription:1.0")?
            .close("Type")?
            .close("RTProperties")?;
        node(x, "i001", |x| {
            node(x, "HomeSP", |x| {
                value_node(x, "FriendlyName", &net.display_name)?;
                value_node(x, "FQDN", &net.realm)
            })?;
            node(x, "Credential", |x| {
                value_node(x, "Realm", &net.realm)?;
                node(x, "DigitalCertificate", |x| {
                    value_node(x, "CertificateType", "x509v3")?;
                    value_node(x, "CertSHA256Fingerprint", &fingerprint)
                })
            })?;
            node(x, "Extension", |x| {
                node(x, "Android", |x| node(x, "AAAServerTrustedNames", |x| value_node(x, "FQDN", &net.server_name)))
            })
        })
    })?;
    x.close("MgmtTree")?;
    String::from_utf8(x.finish()).map_err(|e| Error::Xml(e.to_string()))
}

/// The MIME boundary: RFC 2046 characters only (the Python version used `{boundary-<hex>}`;
/// braces are not boundary characters).
fn boundary() -> String {
    format!("netportal-{}", Uuid::new_v4().simple())
}

/// One MIME part, base64 in 76-character lines (RFC 2045 6.8).
fn mime_part(out: &mut String, boundary: &str, content_type: &str, data: &[u8]) {
    let encoded = Zeroizing::new(STANDARD.encode(data));
    out.push_str(&format!("--{boundary}\r\nContent-Type: {content_type}\r\nContent-Transfer-Encoding: base64\r\n\r\n"));
    for (i, chunk) in encoded.as_bytes().chunks(76).enumerate() {
        if i > 0 {
            out.push_str("\r\n");
        }
        // base64 output is ASCII, so every chunk is valid UTF-8
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
    }
    out.push_str("\r\n");
}

/// `application/x-wifi-config`: one line of base64 of a CRLF MIME multipart with the PPS MO, the
/// root (CA) and the unencrypted PKCS#12, the layout AOSP's `ConfigParser` reads. Serve it with
/// the framing of [`crate::enroll::Format::Android`] (no Content-Disposition, from a user tap).
pub fn android_wifi_config(net: &Network, issued: &Issued, chain: &[&X509Ref]) -> Result<Vec<u8>, Error> {
    let p12 = pkcs12::clear(issued, chain)?;
    let b = boundary();
    let mut message = Zeroizing::new(format!(
        "Content-Type: multipart/mixed; boundary={b}\r\nContent-Transfer-Encoding: base64\r\n\r\n"
    ));
    mime_part(&mut message, &b, "application/x-passpoint-profile", pps_mo(net, issued)?.as_bytes());
    mime_part(&mut message, &b, "application/x-x509-ca-cert", &net.root_der);
    mime_part(&mut message, &b, "application/x-pkcs12", &p12);
    message.push_str(&format!("--{b}--\r\n"));
    Ok(STANDARD.encode(message.as_bytes()).into_bytes())
}

// --- eap-config (geteduroam / Let's Wi-Fi) ---------------------------------------------------

/// An `EAPIdentityProviderList` (GÉANT `eap-metadata.xsd`) with one EAP-TLS method; valid
/// until the certificate's notAfter. UTF-8 with the declaration (the Python version escaped
/// every non-ASCII character as a numeric reference; both are the same XML).
pub fn eap_config(net: &Network, issued: &Issued, chain: &[&X509Ref]) -> Result<Vec<u8>, Error> {
    let passphrase = random_password(15)?; // 20 characters
    let p12 = pkcs12::legacy_3des(issued, chain, &passphrase, &net.display_name)?;
    let p12_b64 = Zeroizing::new(STANDARD.encode(&p12[..]));
    let valid_until = issued
        .not_after()?
        .format(format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z"))
        .map_err(|e| Error::Invalid(format!("time: {e}")))?;
    let root_b64 = STANDARD.encode(&net.root_der);
    let mut x = Xml::new();
    x.event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))?
        .open(
            "EAPIdentityProviderList",
            &[
                ("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance"),
                ("xsi:noNamespaceSchemaLocation", "eap-metadata.xsd"),
            ],
        )?
        .open(
            "EAPIdentityProvider",
            &[("ID", &net.realm), ("namespace", "urn:RFC4282:realm"), ("lang", "en"), ("version", "1")],
        )?
        .leaf("ValidUntil", &[], &valid_until)?
        .open("AuthenticationMethods", &[])?
        .open("AuthenticationMethod", &[])?
        .open("EAPMethod", &[])?
        .leaf("Type", &[], &EAP_TLS.to_string())?
        .close("EAPMethod")?
        .open("ServerSideCredential", &[])?
        .leaf("CA", &[("format", "X.509"), ("encoding", "base64")], &root_b64)?
        .leaf("ServerID", &[], &net.server_name)?
        .close("ServerSideCredential")?
        .open("ClientSideCredential", &[])?
        .leaf("OuterIdentity", &[], &net.outer_identity())?
        .leaf("ClientCertificate", &[("format", "PKCS12"), ("encoding", "base64")], &p12_b64)?
        .leaf("Passphrase", &[], &passphrase)?
        .close("ClientSideCredential")?
        .close("AuthenticationMethod")?
        .close("AuthenticationMethods")?
        .open("CredentialApplicability", &[])?
        .open("IEEE80211", &[])?
        .leaf("SSID", &[], &net.ssid)?
        .leaf("MinRSNProto", &[], "CCMP")?
        .close("IEEE80211")?
        .close("CredentialApplicability")?
        .open("ProviderInfo", &[])?
        .leaf("DisplayName", &[], &net.display_name)?
        .close("ProviderInfo")?
        .close("EAPIdentityProvider")?
        .close("EAPIdentityProviderList")?;
    Ok(x.finish())
}
