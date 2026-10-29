//! The network access PKI of netportal and what is built on it (Python `pki.py`, `enroll.py`,
//! `profiles.py`, `disconnect.py`, and the `pki` command of `__main__.py`):
//!
//! - [`pki`]: certificate profiles (root, device CA, RADIUS server, device), loading, checks;
//! - [`ceremony`]: the `pki` command (generate the CA files, refuse to overwrite them);
//! - [`pkcs12`]: the PKCS#12 encodings each platform reads;
//! - [`profiles`]: Apple configuration profiles, Android Passpoint files, eap-config;
//! - [`enroll`]: issuing per download, formats and HTTP framing;
//! - [`disconnect`]: RFC 5176 Disconnect-Requests to the access points.
//!
//! Everything takes explicit parameters (no settings, no database): `netportal-web` and
//! `netportal-offboard` wire them to the configuration and the registry. Design decisions and
//! their sources are in each module's documentation; the differences to the Python version are
//! listed in `docs/PARITY.md`. Private keys are never logged (the `Debug` impls leave them
//! out) and the buffers that hold them are wiped when dropped where the code owns them.

pub mod ceremony;
pub mod disconnect;
pub mod enroll;
pub mod pkcs12;
pub mod pki;
pub mod profiles;

use std::path::PathBuf;

/// Errors of the PKI and artefact functions.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("openssl: {0}")]
    Openssl(#[from] openssl::error::ErrorStack),
    #[error("{0}")]
    Invalid(String),
    #[error("{}: {source}", path.display())]
    Io { path: PathBuf, source: std::io::Error },
    #[error("refusing to overwrite existing files: {}", list(.0))]
    Exists(Vec<PathBuf>),
    #[error("certificate verification failed: {0}")]
    Verify(String),
    #[error("plist: {0}")]
    Plist(#[from] plist::Error),
    #[error("xml: {0}")]
    Xml(String),
}

fn list(paths: &[PathBuf]) -> String {
    paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", ")
}
