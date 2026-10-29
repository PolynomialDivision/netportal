//! Issue a device certificate and wrap it in the artefact its platform installs (Python
//! `netportal/enroll.py`).
//!
//! The key is generated here, put into the artefact and forgotten: only the certificate's
//! serial and validity go into the registry. The web crate does, per download:
//!
//! ```text
//! let issued = issuer.issue(device_id, now)?;
//! registry.add_credential(device_id, issued.serial_hex()?, issued.not_after()?, overlap_days);
//! let artefact = issuer.artefact(&issued, device_id, format)?;   // body + framing
//! ```

use std::str::FromStr;

use openssl::x509::{X509, X509Ref};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::Error;
use crate::pki::{self, Issued, Purpose};
use crate::profiles::{self, Network, ProfileSigner};

/// The artefact formats.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Format {
    /// iOS/iPadOS (and macOS Wi-Fi only): `.mobileconfig`
    Apple,
    /// macOS: `.mobileconfig` with the wired 802.1X payload
    AppleMac,
    /// Android Passpoint: `application/x-wifi-config`
    Android,
    /// geteduroam apps, downloaded from the portal: `.eap-config`
    EapConfig,
    /// the Let's Wi-Fi API (`/api/eap-config/`): the eap-config document without a file name
    LetsWifi,
}

impl Format {
    /// The form/URL value (`letswifi` is the API's, never offered for download).
    pub fn as_str(self) -> &'static str {
        match self {
            Format::Apple => "apple",
            Format::AppleMac => "apple-mac",
            Format::Android => "android",
            Format::EapConfig => "eap-config",
            Format::LetsWifi => "letswifi",
        }
    }
}

impl FromStr for Format {
    type Err = Error;

    /// The downloadable formats of the enrol form (`letswifi` is not one of them).
    fn from_str(s: &str) -> Result<Self, Error> {
        match s {
            "apple" => Ok(Format::Apple),
            "apple-mac" => Ok(Format::AppleMac),
            "android" => Ok(Format::Android),
            "eap-config" => Ok(Format::EapConfig),
            _ => Err(Error::Invalid(format!("unknown format {s:?}"))),
        }
    }
}

/// How an artefact goes over HTTP (Python `enroll.CONTENT`, INVENTORY 6.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Framing {
    pub content_type: &'static str,
    /// `Content-Disposition: attachment; filename="<name>"` when set
    pub filename: Option<String>,
    /// extra response headers
    pub headers: &'static [(&'static str, &'static str)],
}

impl Framing {
    /// The `Content-Disposition` value, if the format has a file name.
    pub fn content_disposition(&self) -> Option<String> {
        self.filename.as_ref().map(|name| format!("attachment; filename=\"{name}\""))
    }
}

/// The file name base: the display name with every run of characters outside `[A-Za-z0-9._-]`
/// replaced by `-`, `-` and `.` trimmed at both ends, `wifi` if nothing is left (ASCII only:
/// the header is Latin-1; no leading dot, so the saved file is not hidden).
pub fn safe_file_base(display_name: &str) -> String {
    let mut out = String::new();
    let mut in_run = false;
    for c in display_name.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
            out.push(c);
            in_run = false;
        } else if !in_run {
            out.push('-');
            in_run = true;
        }
    }
    let trimmed = out.trim_matches(|c| c == '-' || c == '.');
    if trimmed.is_empty() { "wifi".into() } else { trimmed.to_string() }
}

/// The framing of a format.
pub fn framing(format: Format, display_name: &str) -> Framing {
    let base = safe_file_base(display_name);
    match format {
        Format::Apple | Format::AppleMac => Framing {
            content_type: "application/x-apple-aspen-config",
            filename: Some(format!("{base}.mobileconfig")),
            headers: &[],
        },
        // Android's installer takes the body only from a plain GET after a user tap, without
        // Content-Disposition; Chromium browsers hand it over only like this.
        Format::Android => Framing {
            content_type: "application/x-wifi-config",
            filename: None,
            headers: &[("Content-Transfer-Encoding", "base64")],
        },
        Format::EapConfig => Framing {
            content_type: "application/eap-config",
            filename: Some(format!("{base}.eap-config")),
            headers: &[],
        },
        Format::LetsWifi => Framing { content_type: "application/eap-config", filename: None, headers: &[] },
    }
}

/// One download: the body and how to frame it. The body holds a private key: send it, then
/// drop it; never log it.
pub struct Artefact {
    pub body: Vec<u8>,
    pub framing: Framing,
}

impl std::fmt::Debug for Artefact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Artefact").field("bytes", &self.body.len()).field("framing", &self.framing).finish()
    }
}

/// What the issuer is built from (the web crate fills it from the settings).
pub struct IssuerConfig<'a> {
    /// `NETPORTAL_ROOT_CERT` (PEM)
    pub root_pem: &'a [u8],
    /// `NETPORTAL_DEVICE_CA_CERT` (PEM)
    pub device_ca_pem: &'a [u8],
    /// the device CA key file `NETPORTAL_DEVICE_CA_KEY` (PEM, unencrypted; the caller wipes it)
    pub device_ca_key_pem: &'a [u8],
    pub realm: &'a str,
    pub ssid: &'a str,
    pub radius_server_name: &'a str,
    pub display_name: &'a str,
    /// `NETPORTAL_CERT_DAYS`
    pub cert_days: u32,
    /// optional profile signer (off by default, see [`crate::profiles`])
    pub profile_signer: Option<ProfileSigner>,
}

/// The device CA in the portal, with the network the artefacts configure (Python
/// `enroll.Issuer`).
pub struct Issuer {
    root: X509,
    device_ca: Issued,
    network: Network,
    cert_days: u32,
    signer: Option<ProfileSigner>,
}

impl Issuer {
    /// Loads the root and the device CA and checks at start, so that a bad configuration
    /// stops the portal instead of every download: the key belongs to the device CA, the device
    /// CA is signed by the root, and a test device certificate for the realm verifies against
    /// root + device CA as FreeRADIUS checks it (CA flags, path length, EKU, name constraints,
    /// validity).
    pub fn new(config: IssuerConfig<'_>) -> Result<Self, Error> {
        let root = pki::cert_from_pem(config.root_pem)?;
        let device_ca = Issued::from_pem(config.device_ca_pem, config.device_ca_key_pem)
            .map_err(|e| Error::Invalid(format!("device CA: {e}")))?;
        let root_key = root.public_key()?;
        if !device_ca.cert().verify(&root_key)? {
            return Err(Error::Invalid("the device CA is not signed by the root".into()));
        }
        if config.cert_days == 0 {
            return Err(Error::Invalid("NETPORTAL_CERT_DAYS must be at least 1".into()));
        }
        let network = Network::new(config.realm, config.ssid, config.radius_server_name, config.display_name, &root)?;
        let issuer = Issuer { root, device_ca, network, cert_days: config.cert_days, signer: config.profile_signer };
        let probe = issuer.issue(Uuid::nil(), OffsetDateTime::now_utc())?;
        pki::verify(probe.cert(), &[issuer.device_ca.cert()], &issuer.root, Purpose::TlsClient).map_err(|e| {
            Error::Invalid(format!("a device certificate for realm {} does not verify: {e}", config.realm))
        })?;
        Ok(issuer)
    }

    pub fn root(&self) -> &X509Ref {
        &self.root
    }

    pub fn device_ca(&self) -> &X509Ref {
        self.device_ca.cert()
    }

    pub fn network(&self) -> &Network {
        &self.network
    }

    /// When the device CA expires (devices must enrol again under a new one before that).
    pub fn device_ca_not_after(&self) -> Result<OffsetDateTime, Error> {
        self.device_ca.not_after()
    }

    /// A new certificate for an existing device (enrolment and renewal alike).
    pub fn issue(&self, device_id: Uuid, now: OffsetDateTime) -> Result<Issued, Error> {
        pki::device_cert(&self.device_ca, device_id, self.network.realm(), self.cert_days, now)
    }

    /// The artefact of `format` for a certificate from [`Issuer::issue`].
    pub fn artefact(&self, issued: &Issued, device_id: Uuid, format: Format) -> Result<Artefact, Error> {
        let chain = [self.device_ca.cert()];
        let body = match format {
            Format::Apple | Format::AppleMac => {
                let profile =
                    profiles::apple_mobileconfig(&self.network, issued, &chain, device_id, format == Format::AppleMac)?;
                match &self.signer {
                    Some(signer) => profiles::sign_profile(&profile, signer)?,
                    None => profile,
                }
            }
            Format::Android => profiles::android_wifi_config(&self.network, issued, &chain)?,
            Format::EapConfig | Format::LetsWifi => profiles::eap_config(&self.network, issued, &chain)?,
        };
        Ok(Artefact { body, framing: framing(format, self.network.display_name()) })
    }
}

/// The renewal hint (Python `enroll.expires_soon`): expires within `days`.
pub fn expires_soon(expires: Option<OffsetDateTime>, now: OffsetDateTime, days: i64) -> bool {
    expires.is_some_and(|e| e - now < Duration::days(days))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_file_base() {
        assert_eq!(safe_file_base("Wi-Fi"), "Wi-Fi");
        assert_eq!(safe_file_base("Schärni Haus"), "Sch-rni-Haus");
        assert_eq!(safe_file_base("\"Quotes\" & more"), "Quotes-more");
        assert_eq!(safe_file_base("..hidden."), "hidden");
        assert_eq!(safe_file_base("ÄÖÜ"), "wifi");
        assert_eq!(safe_file_base(""), "wifi");
    }

    #[test]
    fn test_formats() {
        for f in [Format::Apple, Format::AppleMac, Format::Android, Format::EapConfig] {
            assert_eq!(f.as_str().parse::<Format>().unwrap(), f);
        }
        assert!("letswifi".parse::<Format>().is_err());
        assert!("windows".parse::<Format>().is_err());
    }

    #[test]
    fn test_framing() {
        let apple = framing(Format::Apple, "Wi-Fi");
        assert_eq!(apple.content_type, "application/x-apple-aspen-config");
        assert_eq!(apple.content_disposition().as_deref(), Some("attachment; filename=\"Wi-Fi.mobileconfig\""));
        assert_eq!(framing(Format::AppleMac, "Scharni").filename.as_deref(), Some("Scharni.mobileconfig"));
        let android = framing(Format::Android, "Scharni");
        assert_eq!(android.content_type, "application/x-wifi-config");
        assert_eq!(android.content_disposition(), None);
        assert_eq!(android.headers, &[("Content-Transfer-Encoding", "base64")]);
        let eap = framing(Format::EapConfig, "Scharni");
        assert_eq!((eap.content_type, eap.filename.as_deref()), ("application/eap-config", Some("Scharni.eap-config")));
        let api = framing(Format::LetsWifi, "Scharni");
        assert_eq!((api.content_type, api.filename), ("application/eap-config", None));
    }

    #[test]
    fn test_expires_soon() {
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        assert!(expires_soon(Some(now + Duration::days(29)), now, 30));
        assert!(!expires_soon(Some(now + Duration::days(31)), now, 30));
        assert!(expires_soon(Some(now - Duration::days(1)), now, 30));
        assert!(!expires_soon(None, now, 30));
    }
}
