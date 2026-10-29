//! The network access PKI (Python `netportal/pki.py`): an offline root, the device CA the
//! portal signs device certificates with, the RADIUS server certificate, and the device
//! certificates.
//!
//! # Design (decided for the Rust port, 2026-10-28)
//!
//! | Certificate | Key | Signature | Validity | Extensions |
//! |---|---|---|---|---|
//! | Root `CN=<name> Network Root` | EC P-384 | ecdsa-with-SHA384 | 7300 days | BasicConstraints CA pathlen 1 (critical); KeyUsage keyCertSign, cRLSign (critical); NameConstraints (critical): permitted dNSName `<server name>` and rfc822Name `<realm>`, excluded every IPv4/IPv6 address; SKI |
//! | Device CA `CN=<name> Device CA` | EC P-384 | ecdsa-with-SHA384 (root) | 3650 days, never beyond the root | BasicConstraints CA pathlen 0 (critical); KeyUsage keyCertSign, cRLSign (critical); EKU clientAuth; NameConstraints (critical): permitted rfc822Name `<realm>`, excluded every dNSName and every IPv4/IPv6 address; SKI; AKI |
//! | RADIUS server `CN=<server name>` | EC P-256 | ecdsa-with-SHA384 (root) | 825 days | BasicConstraints CA:FALSE (critical); KeyUsage digitalSignature (critical); EKU serverAuth; SAN dNSName; SKI; AKI |
//! | Device `CN=<device uuid>@<realm>` | EC P-256 | ecdsa-with-SHA384 (device CA) | `NETPORTAL_CERT_DAYS`, never beyond the device CA | BasicConstraints CA:FALSE (critical); KeyUsage digitalSignature (critical); EKU clientAuth; SAN rfc822Name `<device uuid>@<realm>`; SKI; AKI |
//!
//! Every validity starts 5 minutes in the past (clock skew of the supplicants) and lasts exactly
//! the stated number of days from there; one `now` per ceremony.
//!
//! * **Keys.** P-384 for the two long-lived CA keys (20 and 10 years; the same choice as
//!   Let's Encrypt's ISRG Root X2), P-256 for the leaves: every supplicant and every hardware
//!   key store (Secure Enclave, Android StrongBox) handles P-256. The signature hash follows the
//!   signer's curve (SHA-384 for P-384, as RFC 5480 4 recommends and as TLS 1.3's signature
//!   schemes pair them); the Python version signed with SHA-256 under a P-384 key.
//! * **Key usage.** CAs: keyCertSign and cRLSign only (no digitalSignature: they sign neither
//!   OCSP responses nor TLS handshakes). Leaves: digitalSignature only. The Python version also
//!   set keyAgreement, which only static-ECDH cipher suites use (gone in TLS 1.3, never used by
//!   ECDHE_ECDSA).
//! * **Identity (RFC 5216 5.2).** "Conforming implementations generating new certificates with
//!   Network Access Identifiers (NAIs) MUST use the rfc822Name in the subject alternative name
//!   field": the device certificate carries its NAI `<device uuid>@<realm>` both as CN (what
//!   FreeRADIUS and humans read) and as SAN rfc822Name. No personal data: under TLS 1.2 the
//!   client certificate is visible on the radio. FreeRADIUS identifies the credential by its
//!   serial in the registry, not by a name.
//! * **Serials.** 128 random bits from OpenSSL's CSPRNG with the top bit set: a positive
//!   integer of exactly 128 bits (17 DER octets), so the registry serial is always 32 lowercase
//!   hex digits, exactly what FreeRADIUS reports as `TLS-Client-Cert-Serial`.
//! * **The device CA cannot mint server certificates.** Its key is online (the portal holds
//!   it), and its certificates chain to the root that macOS and Windows install as a trust
//!   anchor. EKU clientAuth on the device CA (EKU chaining: Windows, NSS, Chrome, OpenSSL) and
//!   name constraints that exclude every DNS name and IP address (honoured by every current
//!   validator) keep a stolen device CA key from issuing a TLS server certificate the residents'
//!   machines would accept. The RADIUS server certificate comes from the offline root.
//! * **The root is a trust anchor for one name only** (security review 2026-10-29, L7). macOS
//!   (a profile's root becomes a system anchor) and the geteduroam apps install it; its own
//!   NameConstraints limit what anything under it can be: server certificates for the RADIUS
//!   server's name (and names under it), mailboxes of the realm (the devices' NAIs), no IP
//!   address. Enforced on the anchor by OpenSSL (FreeRADIUS, wpa_supplicant on Linux; "all
//!   certificates higher in chain including trust anchor", `x509_vfy.c`), BoringSSL (Android's
//!   wpa_supplicant) and Apple's trustd since iOS 13 / macOS 10.15 (older versions ignore an
//!   anchor's constraints, they do not refuse it); Windows' CryptoAPI checks name constraints but
//!   does not document whether it applies a self-signed anchor's own (to be checked on Windows
//!   10/11; the root is accepted either way, the device CA's constraints hold in any case). A
//!   new RADIUS server name needs a new ceremony.
//! * **No CRL, no AIA, no OCSP.** FreeRADIUS decides every authentication from the registry
//!   (`radius_cert`: revoked device, retired or expired credential), so revocation is immediate
//!   without CRLs (`radius/mods/eap`: `ocsp { enable = no }`, no `check_crl`); supplicants do
//!   not check revocation of EAP server certificates, and AIA would point at a URL nobody may
//!   fetch before being on the network.

use openssl::asn1::{Asn1Integer, Asn1Object, Asn1OctetString, Asn1Time, Asn1TimeRef};
use openssl::bn::BigNum;
use openssl::ec::{Asn1Flag, EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, PKeyRef, Private};
use openssl::stack::Stack;
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName, SubjectKeyIdentifier,
};
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::{X509, X509Builder, X509Extension, X509Name, X509PurposeId, X509Ref, X509StoreContext};
use time::macros::format_description;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::Error;

/// The `pki` command (see [`crate::ceremony::command`]).
pub use crate::ceremony::command as ceremony;

/// Root validity (20 years).
pub const ROOT_DAYS: u32 = 7300;
/// Device CA validity (10 years).
pub const DEVICE_CA_DAYS: u32 = 3650;
/// RADIUS server certificate validity: Apple's limit for TLS server certificates (iOS 13,
/// macOS 10.15: "must have a validity period of 825 days or fewer").
pub const SERVER_DAYS: u32 = 825;
/// Every certificate starts this much in the past (clock skew of the supplicants).
pub const BACKDATE: Duration = Duration::minutes(5);
/// The renewal hint shows when a certificate expires within this many days (`enroll.py`).
pub const RENEWAL_HINT_DAYS: i64 = 30;

/// Elliptic curves used by the PKI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Curve {
    P256,
    P384,
}

impl Curve {
    fn nid(self) -> Nid {
        match self {
            Curve::P256 => Nid::X9_62_PRIME256V1,
            Curve::P384 => Nid::SECP384R1,
        }
    }
}

/// A new EC key on a named curve (explicit curve parameters are refused by most TLS stacks).
pub fn generate_key(curve: Curve) -> Result<PKey<Private>, Error> {
    let mut group = EcGroup::from_curve_name(curve.nid())?;
    group.set_asn1_flag(Asn1Flag::NAMED_CURVE);
    Ok(PKey::from_ec_key(EcKey::generate(&group)?)?)
}

/// The signature hash for a signer key: SHA-384 for P-384, SHA-512 for P-521, else SHA-256.
fn digest_for(key: &PKeyRef<Private>) -> Result<MessageDigest, Error> {
    match key.id() {
        Id::EC => Ok(match key.ec_key()?.group().curve_name() {
            Some(Nid::SECP384R1) => MessageDigest::sha384(),
            Some(Nid::SECP521R1) => MessageDigest::sha512(),
            _ => MessageDigest::sha256(),
        }),
        Id::RSA => Ok(MessageDigest::sha256()),
        _ => Err(Error::Invalid("the CA key must be an EC or RSA key".into())),
    }
}

/// A certificate with its private key (a CA, the RADIUS server, or a device).
pub struct Issued {
    cert: X509,
    key: PKey<Private>,
}

impl std::fmt::Debug for Issued {
    /// Never prints the key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Issued")
            .field("subject", &subject_cn(&self.cert).unwrap_or_default())
            .field("serial", &serial_hex(&self.cert).unwrap_or_default())
            .finish_non_exhaustive()
    }
}

impl Issued {
    /// A certificate and its key; refuses a key that does not belong to the certificate.
    pub fn new(cert: X509, key: PKey<Private>) -> Result<Self, Error> {
        if !cert.public_key()?.public_eq(&key) {
            return Err(Error::Invalid(format!(
                "the key does not belong to the certificate {}",
                subject_cn(&cert).unwrap_or_default()
            )));
        }
        Ok(Issued { cert, key })
    }

    /// From a PEM certificate and a PEM private key (PKCS#8 or the traditional EC/RSA format,
    /// unencrypted), e.g. the device CA in the portal (Python `pki.load`).
    pub fn from_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<Self, Error> {
        let cert = X509::from_pem(cert_pem).map_err(|e| Error::Invalid(format!("certificate: {e}")))?;
        let key = PKey::private_key_from_pem(key_pem)
            .map_err(|_| Error::Invalid("the private key is not an unencrypted PEM key".into()))?;
        Self::new(cert, key)
    }

    pub fn cert(&self) -> &X509Ref {
        &self.cert
    }

    pub fn key(&self) -> &PKeyRef<Private> {
        &self.key
    }

    /// The registry serial (see [`serial_hex`]).
    pub fn serial_hex(&self) -> Result<String, Error> {
        serial_hex(&self.cert)
    }

    pub fn not_before(&self) -> Result<OffsetDateTime, Error> {
        to_offset(self.cert.not_before())
    }

    pub fn not_after(&self) -> Result<OffsetDateTime, Error> {
        to_offset(self.cert.not_after())
    }

    pub fn cert_pem(&self) -> Result<Vec<u8>, Error> {
        Ok(self.cert.to_pem()?)
    }

    pub fn cert_der(&self) -> Result<Vec<u8>, Error> {
        Ok(self.cert.to_der()?)
    }

    /// The private key as unencrypted PKCS#8 PEM, wiped from memory when dropped.
    pub fn key_pem(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        Ok(Zeroizing::new(self.key.private_key_to_pem_pkcs8()?))
    }
}

/// A PEM certificate (e.g. the root in the portal).
pub fn cert_from_pem(pem: &[u8]) -> Result<X509, Error> {
    X509::from_pem(pem).map_err(|e| Error::Invalid(format!("certificate: {e}")))
}

/// The serial as the registry stores it and FreeRADIUS reports it (`TLS-Client-Cert-Serial`,
/// lower-cased by `check-eap-tls`): lowercase hex of the big-endian magnitude, even length.
pub fn serial_hex(cert: &X509Ref) -> Result<String, Error> {
    let bytes = cert.serial_number().to_bn()?.to_vec();
    Ok(if bytes.is_empty() { "00".into() } else { hex::encode(bytes) })
}

/// The first CN of the subject.
pub fn subject_cn(cert: &X509Ref) -> Option<String> {
    let entry = cert.subject_name().entries_by_nid(Nid::COMMONNAME).next()?;
    entry.data().to_string().ok()
}

/// SHA-256 of the certificate's DER, lowercase hex (the Passpoint `CertSHA256Fingerprint`).
pub fn fingerprint_sha256(cert: &X509Ref) -> Result<String, Error> {
    Ok(hex::encode(cert.digest(MessageDigest::sha256())?))
}

/// A certificate time as `OffsetDateTime` (UTC).
pub fn to_offset(t: &Asn1TimeRef) -> Result<OffsetDateTime, Error> {
    let epoch = Asn1Time::from_unix(0)?;
    let diff = epoch.diff(t)?;
    Ok(OffsetDateTime::UNIX_EPOCH + Duration::days(diff.days.into()) + Duration::seconds(diff.secs.into()))
}

/// `OffsetDateTime` as a certificate time (UTCTime until 2049, GeneralizedTime after: RFC 5280
/// 4.1.2.5).
fn to_asn1(t: OffsetDateTime) -> Result<Asn1Time, Error> {
    let text = t
        .to_offset(time::UtcOffset::UTC)
        .format(format_description!("[year][month][day][hour][minute][second]Z"))
        .map_err(|e| Error::Invalid(format!("time: {e}")))?;
    Ok(Asn1Time::from_str_x509(&text)?)
}

/// 128 random bits, top bit set: positive, exactly 128 bits (RFC 5280 4.1.2.2: at most 20
/// octets; CA/B Forum: at least 64 bits of CSPRNG output).
fn random_serial() -> Result<Asn1Integer, Error> {
    let mut bytes = Zeroizing::new([0u8; 16]);
    openssl::rand::rand_bytes(&mut bytes[..])?;
    bytes[0] |= 0x80;
    Ok(BigNum::from_slice(&bytes[..])?.to_asn1_integer()?)
}

fn cn_name(cn: &str) -> Result<X509Name, Error> {
    let mut name = X509Name::builder()?;
    name.append_entry_by_nid(Nid::COMMONNAME, cn)?;
    Ok(name.build())
}

/// The common part of every certificate: version 3, random serial, names, key, validity.
fn builder(
    subject_cn: &str,
    key: &PKeyRef<Private>,
    issuer: Option<&X509Ref>,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
) -> Result<X509Builder, Error> {
    if subject_cn.is_empty() || subject_cn.chars().count() > 64 {
        return Err(Error::Invalid(format!("a common name has 1 to 64 characters: {subject_cn:?}")));
    }
    let subject = cn_name(subject_cn)?;
    let mut b = X509Builder::new()?;
    b.set_version(2)?;
    let serial = random_serial()?;
    b.set_serial_number(&serial)?;
    b.set_subject_name(&subject)?;
    match issuer {
        Some(issuer) => b.set_issuer_name(issuer.subject_name())?,
        None => b.set_issuer_name(&subject)?,
    }
    b.set_pubkey(key)?;
    let (not_before, not_after) = (to_asn1(not_before)?, to_asn1(not_after)?);
    b.set_not_before(&not_before)?;
    b.set_not_after(&not_after)?;
    Ok(b)
}

/// SKI and (for issued certificates) AKI with the issuer's key identifier.
fn key_identifiers(b: &mut X509Builder, issuer: Option<&X509Ref>) -> Result<(), Error> {
    let ski = SubjectKeyIdentifier::new().build(&b.x509v3_context(issuer, None))?;
    b.append_extension(ski)?;
    if let Some(issuer) = issuer {
        let aki = AuthorityKeyIdentifier::new().keyid(true).build(&b.x509v3_context(Some(issuer), None))?;
        b.append_extension(aki)?;
    }
    Ok(())
}

/// The validity window: from `now - BACKDATE`, `days` long, cut at the issuer's notAfter (a
/// certificate cannot be used past its issuer anyway; cutting it makes the date the devices
/// show true).
fn window(now: OffsetDateTime, days: u32, issuer: Option<&X509Ref>) -> Result<(OffsetDateTime, OffsetDateTime), Error> {
    let start = now - BACKDATE;
    let mut end = start + Duration::days(days.into());
    if let Some(issuer) = issuer {
        let limit = to_offset(issuer.not_after())?;
        if limit <= now {
            return Err(Error::Invalid(format!(
                "the issuing CA {} expired at {limit}",
                subject_cn(issuer).unwrap_or_default()
            )));
        }
        end = end.min(limit);
    }
    Ok((start, end))
}

/// DER of a TLV with a short or long length.
fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes: Vec<u8> = len.to_be_bytes().into_iter().skip_while(|b| *b == 0).collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend(bytes);
    }
    out.extend_from_slice(content);
    out
}

/// GeneralName tags (context-specific, primitive) used in name constraints.
const RFC822_NAME: u8 = 0x81;
const DNS_NAME: u8 = 0x82;
const IP_ADDRESS: u8 = 0x87;
/// Every IPv4 and every IPv6 address (address and mask all zero).
const ALL_IPV4: [u8; 8] = [0; 8];
const ALL_IPV6: [u8; 32] = [0; 32];

/// A critical NameConstraints extension (RFC 5280 4.2.1.10: "Conforming CAs MUST mark this
/// extension as critical") of these permitted and excluded GeneralNames `(tag, value)`.
fn name_constraints(permitted: &[(u8, &[u8])], excluded: &[(u8, &[u8])]) -> Result<X509Extension, Error> {
    let subtrees = |names: &[(u8, &[u8])]| -> Vec<u8> {
        names.iter().flat_map(|(tag, value)| der(0x30, &der(*tag, value))).collect()
    };
    let mut value = Vec::new();
    if !permitted.is_empty() {
        value.extend(der(0xA0, &subtrees(permitted)));
    }
    if !excluded.is_empty() {
        value.extend(der(0xA1, &subtrees(excluded)));
    }
    let oid = Asn1Object::from_str("2.5.29.30")?;
    let octets = Asn1OctetString::new_from_bytes(&der(0x30, &value))?;
    Ok(X509Extension::new_from_der(&oid, true, &octets)?)
}

/// NameConstraints for the device CA: mailboxes (rfc822Name) only under the realm, no DNS name
/// at all (a zero-length dNSName matches every name), no IPv4 or IPv6 address.
fn device_ca_name_constraints(realm: &str) -> Result<X509Extension, Error> {
    name_constraints(
        &[(RFC822_NAME, realm.as_bytes())],
        &[(DNS_NAME, b""), (IP_ADDRESS, &ALL_IPV4), (IP_ADDRESS, &ALL_IPV6)],
    )
}

/// NameConstraints for the root: DNS names only the RADIUS server's (and names under it, RFC
/// 5280), mailboxes only of the realm (`<device>@<realm>`; host form, so no subdomain), no IPv4
/// or IPv6 address.
fn root_name_constraints(server_name: &str, realm: &str) -> Result<X509Extension, Error> {
    name_constraints(
        &[(DNS_NAME, server_name.as_bytes()), (RFC822_NAME, realm.as_bytes())],
        &[(IP_ADDRESS, &ALL_IPV4), (IP_ADDRESS, &ALL_IPV6)],
    )
}

fn ca_key_usage() -> Result<X509Extension, Error> {
    Ok(KeyUsage::new().critical().key_cert_sign().crl_sign().build()?)
}

fn leaf_key_usage() -> Result<X509Extension, Error> {
    Ok(KeyUsage::new().critical().digital_signature().build()?)
}

/// The self-signed root (offline: the admin's password manager, never a server), a trust
/// anchor for the RADIUS server's name and the realm's mailboxes only ([`root_name_constraints`]).
pub fn make_root(cn: &str, server_name: &str, realm: &str, now: OffsetDateTime) -> Result<Issued, Error> {
    check_dns_name(server_name, "server name")?;
    check_dns_name(realm, "realm")?;
    let key = generate_key(Curve::P384)?;
    let (start, end) = window(now, ROOT_DAYS, None)?;
    let mut b = builder(cn, &key, None, start, end)?;
    b.append_extension(BasicConstraints::new().critical().ca().pathlen(1).build()?)?;
    b.append_extension(ca_key_usage()?)?;
    key_identifiers(&mut b, None)?;
    b.append_extension(root_name_constraints(&server_name.to_ascii_lowercase(), &realm.to_ascii_lowercase())?)?;
    b.sign(&key, digest_for(&key)?)?;
    Issued::new(b.build(), key)
}

/// The device CA under the root, restricted to client certificates for `realm`.
pub fn make_device_ca(root: &Issued, cn: &str, realm: &str, now: OffsetDateTime) -> Result<Issued, Error> {
    check_dns_name(realm, "realm")?;
    let key = generate_key(Curve::P384)?;
    let (start, end) = window(now, DEVICE_CA_DAYS, Some(root.cert()))?;
    let mut b = builder(cn, &key, Some(root.cert()), start, end)?;
    b.append_extension(BasicConstraints::new().critical().ca().pathlen(0).build()?)?;
    b.append_extension(ca_key_usage()?)?;
    b.append_extension(ExtendedKeyUsage::new().client_auth().build()?)?;
    key_identifiers(&mut b, Some(root.cert()))?;
    b.append_extension(device_ca_name_constraints(&realm.to_ascii_lowercase())?)?;
    b.sign(root.key(), digest_for(root.key())?)?;
    Issued::new(b.build(), key)
}

/// The RADIUS server certificate under the root (clients pin the root and this exact name).
pub fn make_server_cert(root: &Issued, dns_name: &str, days: u32, now: OffsetDateTime) -> Result<Issued, Error> {
    check_dns_name(dns_name, "server name")?;
    if days == 0 || days > SERVER_DAYS {
        return Err(Error::Invalid(format!("the server certificate lasts 1 to {SERVER_DAYS} days")));
    }
    let key = generate_key(Curve::P256)?;
    let (start, end) = window(now, days, Some(root.cert()))?;
    let mut b = builder(dns_name, &key, Some(root.cert()), start, end)?;
    b.append_extension(BasicConstraints::new().critical().build()?)?;
    b.append_extension(leaf_key_usage()?)?;
    b.append_extension(ExtendedKeyUsage::new().server_auth().build()?)?;
    key_identifiers(&mut b, Some(root.cert()))?;
    let san = SubjectAlternativeName::new().dns(dns_name).build(&b.x509v3_context(Some(root.cert()), None))?;
    b.append_extension(san)?;
    b.sign(root.key(), digest_for(root.key())?)?;
    Issued::new(b.build(), key)
}

/// The NAI of a device: `<device uuid>@<realm>` (no owner, no device name).
pub fn device_identity(device_id: Uuid, realm: &str) -> String {
    format!("{}@{}", device_id.hyphenated(), realm.to_ascii_lowercase())
}

/// A device certificate (Python `pki.device_cert`): a new P-256 key, `days` long but never past
/// the device CA.
pub fn device_cert(
    device_ca: &Issued,
    device_id: Uuid,
    realm: &str,
    days: u32,
    now: OffsetDateTime,
) -> Result<Issued, Error> {
    check_dns_name(realm, "realm")?;
    if days == 0 {
        return Err(Error::Invalid("a device certificate lasts at least one day".into()));
    }
    let nai = device_identity(device_id, realm);
    let key = generate_key(Curve::P256)?;
    let (start, end) = window(now, days, Some(device_ca.cert()))?;
    let mut b = builder(&nai, &key, Some(device_ca.cert()), start, end)?;
    b.append_extension(BasicConstraints::new().critical().build()?)?;
    b.append_extension(leaf_key_usage()?)?;
    b.append_extension(ExtendedKeyUsage::new().client_auth().build()?)?;
    key_identifiers(&mut b, Some(device_ca.cert()))?;
    let san = SubjectAlternativeName::new().email(&nai).build(&b.x509v3_context(Some(device_ca.cert()), None))?;
    b.append_extension(san)?;
    b.sign(device_ca.key(), digest_for(device_ca.key())?)?;
    Issued::new(b.build(), key)
}

/// The purpose a chain is verified for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    /// a device certificate (`openssl verify -purpose sslclient`)
    TlsClient,
    /// the RADIUS server certificate (`-purpose sslserver`)
    TlsServer,
}

/// Verifies `leaf` against the trust anchor `root` with `intermediates` as untrusted chain
/// certificates, the way FreeRADIUS (OpenSSL) and the supplicants do: signatures, validity at
/// the current time, CA flags and path lengths, key usage and EKU purpose (including the CA's
/// EKU), name constraints.
pub fn verify(leaf: &X509Ref, intermediates: &[&X509Ref], root: &X509Ref, purpose: Purpose) -> Result<(), Error> {
    let mut store = X509StoreBuilder::new()?;
    store.add_cert(root.to_owned())?;
    store.set_purpose(match purpose {
        Purpose::TlsClient => X509PurposeId::SSL_CLIENT,
        Purpose::TlsServer => X509PurposeId::SSL_SERVER,
    })?;
    let store = store.build();
    let mut chain = Stack::new()?;
    for cert in intermediates {
        chain.push((*cert).to_owned())?;
    }
    let mut ctx = X509StoreContext::new()?;
    let result = ctx.init(&store, leaf, &chain, |c| Ok(if c.verify_cert()? { Ok(()) } else { Err(c.error()) }))?;
    result.map_err(|e| Error::Verify(e.error_string().to_string()))
}

/// A DNS name (realm, server name): 1-253 characters, labels of letters, digits and inner
/// hyphens, at least two labels.
pub fn check_dns_name(name: &str, what: &str) -> Result<(), Error> {
    let label_ok = |l: &str| {
        !l.is_empty()
            && l.len() <= 63
            && l.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    };
    if name.len() > 253 || name.split('.').count() < 2 || !name.split('.').all(label_ok) {
        return Err(Error::Invalid(format!("the {what} {name:?} is not a DNS name with at least two labels")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_der_lengths() {
        assert_eq!(der(0x04, &[1, 2]), vec![0x04, 2, 1, 2]);
        let long = vec![0u8; 300];
        let out = der(0x04, &long);
        assert_eq!(&out[..4], &[0x04, 0x82, 0x01, 0x2c]);
        assert_eq!(out.len(), 304);
    }

    #[test]
    fn test_dns_names() {
        for ok in ["scharni.org", "radius.scharni.org", "house.example.net", "a-b.c1"] {
            check_dns_name(ok, "x").unwrap();
        }
        for bad in ["", "localhost", "-a.org", "a-.org", "a..org", "a.org.", "ä.org", "a b.org", "a@b.org"] {
            assert!(check_dns_name(bad, "x").is_err(), "{bad}");
        }
    }

    #[test]
    fn test_digest_follows_the_curve() {
        let p384 = generate_key(Curve::P384).unwrap();
        let p256 = generate_key(Curve::P256).unwrap();
        assert_eq!(digest_for(&p384).unwrap().type_(), MessageDigest::sha384().type_());
        assert_eq!(digest_for(&p256).unwrap().type_(), MessageDigest::sha256().type_());
    }

    #[test]
    fn test_time_round_trip() {
        let t = OffsetDateTime::from_unix_timestamp(1_800_000_123).unwrap();
        assert_eq!(to_offset(&to_asn1(t).unwrap()).unwrap(), t);
        let late = OffsetDateTime::from_unix_timestamp(2_600_000_000).unwrap(); // 2052: GeneralizedTime
        assert_eq!(to_offset(&to_asn1(late).unwrap()).unwrap(), late);
    }
}
