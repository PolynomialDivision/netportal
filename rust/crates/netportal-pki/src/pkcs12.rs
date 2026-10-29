//! PKCS#12 per platform (Python `profiles.pkcs12_apple`, `profiles.pkcs12_clear`), both made
//! with OpenSSL's `PKCS12_create` through the `openssl` crate (no CLI subprocess).
//!
//! Both variants hold exactly one private key, its certificate (with `localKeyID` on both) and
//! the device CA (the chain the device presents to FreeRADIUS).
//!
//! # Apple and eap-config: [`Variant::Legacy3Des`]
//!
//! Key bag (PKCS#8 ShroudedKeyBag) and certificate bag (PKCS#7 EncryptedData) with
//! `pbeWithSHA1And3-KeyTripleDES-CBC`, 2048 iterations; MAC HMAC-SHA1, 2048 iterations.
//! Readable by OpenSSL 3 without the legacy provider (3DES and the PKCS#12 KDF are in the
//! default provider; RC2 is not used).
//!
//! * Apple (`SecPKCS12Import`, used for the `com.apple.security.pkcs12` payload and by the
//!   geteduroam iOS app): the modern encoding OpenSSL 3 writes by default (PBES2 with
//!   AES-256-CBC, HMAC-SHA256 MAC) imports only from iOS 18 / macOS 15 on. Apple DTS: "macOS
//!   15 introduced support for a bunch of new algorithms that should allow you to import modern
//!   OpenSSL PKCS#12 files", the same for the aligned iOS 18
//!   (<https://developer.apple.com/forums/thread/779466>); macOS 14.8 still fails with "MAC
//!   verification failed" (<https://developer.apple.com/forums/thread/810723>), and Apple does
//!   not expect to backport it. Phones and iPads that stopped at iOS 16/17 and Macs on macOS 14
//!   are still in use, so the 3DES/SHA-1 encoding is required.
//! * geteduroam Android app (`KeyStore.getInstance("PKCS12")`, Android's trimmed Bouncy
//!   Castle): PBES2 key stores load only since AOSP commit `eba842c5` (January 2023, "support
//!   for PBES2-encrypted KeyStores", Android 14); before that, the BC aliases for an HMAC-SHA256
//!   MAC are commented out (`external/bouncycastle`, `SHA256.java` at android-13.0.0_r1), while
//!   `Alg.Alias.Mac.1.3.14.3.2.26` (HMAC-SHA1) and 3DES are present on every version.
//! * geteduroam Windows (.NET `X509Certificate2Collection.Import`, Windows CryptoAPI) and Linux
//!   (`software.sslmate.com/src/go-pkcs12` v0.7, `linux-app/go.mod`) read both encodings; 3DES
//!   is the common denominator.
//!
//! Safest versus most compatible: AES-256/PBKDF2 would be the safer cipher, but the password
//! travels in the same artefact (the `Password` key of the profile, the `Passphrase` element
//! next to the eap-config `ClientCertificate`), so the encryption is not a security boundary.
//! What protects the key is TLS, the login and the one-time download token. The compatible
//! encoding costs nothing here, so it is used. The password only stops the platform from
//! asking the resident for one.
//!
//! # Android Passpoint: [`Variant::Clear`]
//!
//! AOSP `ConfigParser.parsePkcs12` (packages/modules/Wifi, `hotspot2/ConfigParser.java`) does
//! `ks.load(in, new char[0])`, requires `ks.size() == 1` and reads the key with
//! `getKey(alias, null)`. So: no encryption (plain PKCS#8 KeyBag, certificates in plain PKCS#7
//! Data), no friendlyName (an alias on the certificate and none on the key would make two
//! entries), and a MAC over the empty password (Bouncy Castle verifies it with both
//! empty-password conventions, `PKCS12KeyStoreSpi.engineLoad`). The MAC is **HMAC-SHA1**, not
//! OpenSSL 3's default SHA-256 the Python version got from the openssl CLI: an SHA-256 MAC
//! fails to load on Android 13 (see above), an SHA-1 MAC loads on every version. Over an empty
//! password the MAC is an integrity check, not a secret, so SHA-1 costs nothing. MAC iteration
//! count 1 (the field left out), as `openssl pkcs12 -nomaciter` writes it.

use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkcs12::Pkcs12;
use openssl::stack::Stack;
use openssl::x509::X509Ref;
use zeroize::Zeroizing;

use crate::Error;
use crate::pki::Issued;

/// The PKCS#12 encodings (see the module docs for which platform needs which).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variant {
    /// Apple profiles and eap-config: 3DES-SHA1 bags and an HMAC-SHA1 MAC, with a password
    Legacy3Des,
    /// Android Passpoint: unencrypted, HMAC-SHA1 MAC over the empty password
    Clear,
}

/// PBE and MAC iteration count of the encrypted variant (OpenSSL's default).
pub const ITERATIONS: u32 = 2048;

/// `nid_key`/`nid_cert` value that makes `PKCS12_create` store the bag unencrypted.
const NO_ENCRYPTION: Nid = Nid::from_raw(-1);

/// The encrypted PKCS#12 for Apple and eap-config. `friendly_name` labels the key and
/// certificate in Keychain Access and the Windows certificate store.
pub fn legacy_3des(
    issued: &Issued,
    chain: &[&X509Ref],
    password: &str,
    friendly_name: &str,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if password.is_empty() || password.contains('\0') {
        return Err(Error::Invalid("the PKCS#12 password must be non-empty and without NUL".into()));
    }
    if friendly_name.is_empty() || friendly_name.contains('\0') {
        return Err(Error::Invalid("the PKCS#12 friendly name must be non-empty and without NUL".into()));
    }
    let mut b = Pkcs12::builder();
    b.name(friendly_name)
        .pkey(issued.key())
        .cert(issued.cert())
        .ca(stack(chain)?)
        .key_algorithm(Nid::PBE_WITHSHA1AND3_KEY_TRIPLEDES_CBC)
        .cert_algorithm(Nid::PBE_WITHSHA1AND3_KEY_TRIPLEDES_CBC)
        .key_iter(ITERATIONS)
        .mac_iter(ITERATIONS)
        .mac_md(MessageDigest::sha1());
    Ok(Zeroizing::new(b.build2(password)?.to_der()?))
}

/// The unencrypted PKCS#12 for Android's Passpoint installer.
pub fn clear(issued: &Issued, chain: &[&X509Ref]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut b = Pkcs12::builder();
    b.pkey(issued.key())
        .cert(issued.cert())
        .ca(stack(chain)?)
        .key_algorithm(NO_ENCRYPTION)
        .cert_algorithm(NO_ENCRYPTION)
        .mac_iter(1)
        .mac_md(MessageDigest::sha1());
    Ok(Zeroizing::new(b.build2("")?.to_der()?))
}

/// The PKCS#12 of one variant (`password` and `friendly_name` are ignored for [`Variant::Clear`]).
pub fn build(
    variant: Variant,
    issued: &Issued,
    chain: &[&X509Ref],
    password: &str,
    friendly_name: &str,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    match variant {
        Variant::Legacy3Des => legacy_3des(issued, chain, password, friendly_name),
        Variant::Clear => clear(issued, chain),
    }
}

fn stack(chain: &[&X509Ref]) -> Result<Stack<openssl::x509::X509>, Error> {
    let mut s = Stack::new()?;
    for cert in chain {
        s.push((*cert).to_owned())?;
    }
    Ok(s)
}
