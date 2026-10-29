//! The CA ceremony (`netportal pki --out DIR --name NAME --server-name FQDN [--realm REALM]`,
//! Python `__main__.cmd_pki`). Run on an admin's machine, never on the server.
//!
//! It writes, into `--out` (created with mode 0700 if missing):
//!
//! | File | Mode | Content | Goes to |
//! |---|---|---|---|
//! | `root.pem` | 0644 | root certificate | every artefact (the anchor), house-infra `files/pki/root.pem.j2` |
//! | `root.key` | 0600 | root key (PKCS#8 PEM) | offline (password manager), never a server |
//! | `device-ca.pem` | 0644 | device CA certificate | portal (`NETPORTAL_DEVICE_CA_CERT`) |
//! | `device-ca.key` | 0600 | device CA key | vault -> portal only (a file, `NETPORTAL_DEVICE_CA_KEY`) |
//! | `device-ca-chain.pem` | 0644 | device CA + root, in this order | FreeRADIUS `ca_file` |
//! | `radius-server.pem` | 0644 | RADIUS server certificate | FreeRADIUS `certificate_file` |
//! | `radius-server.key` | 0600 | RADIUS server key | vault -> FreeRADIUS only |
//!
//! Re-run safety (the Python version overwrote everything, which silently replaced a CA that
//! every enrolled device depends on): nothing is written when any of these files exists; each
//! file is created exclusively (`O_EXCL`) with its final mode, so a key is never readable by
//! others, not even for a moment; on a failure halfway the files of this run are removed.
//!
//! The root carries name constraints too (the RADIUS server's name, the realm's mailboxes, no IP
//! address; `pki::make_root`), so a new server name needs a new ceremony; [`renew_server`]
//! refuses a name the root does not permit.
//!
//! The device CA's name constraints need the realm. `--realm` is optional: by default it is
//! the server name without its first label (`radius.scharni.org` -> `scharni.org`), because
//! the server name must lie under the realm anyway (Android's Passpoint validates the server
//! against the HomeSP FQDN = the realm). The portal checks at start that its realm is
//! permitted (`enroll::Issuer::new`).
//!
//! [`renew_server`] issues a new RADIUS server certificate from an existing root (needed every
//! 825 days) without touching the CAs, so the devices keep working.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use time::OffsetDateTime;

use crate::Error;
use crate::pki::{self, Issued, SERVER_DAYS};

/// The ceremony's output files and whether each is secret (0600).
pub const FILES: [(&str, bool); 7] = [
    ("root.pem", false),
    ("root.key", true),
    ("device-ca.pem", false),
    ("device-ca.key", true),
    ("device-ca-chain.pem", false),
    ("radius-server.pem", false),
    ("radius-server.key", true),
];

/// What the `pki` command was asked for.
#[derive(Clone, Debug)]
pub struct Request {
    /// `--name`: the house's name in the CA names (`<name> Network Root`, `<name> Device CA`)
    pub name: String,
    /// `--server-name`: the RADIUS server's DNS name (CN and SAN of its certificate)
    pub server_name: String,
    /// `--realm`: the realm the device CA may issue for (default: see the module docs)
    pub realm: Option<String>,
}

/// The three certificates of a new PKI.
#[derive(Debug)]
pub struct Ceremony {
    pub root: Issued,
    pub device_ca: Issued,
    pub server: Issued,
    pub realm: String,
}

/// What was written, for the command's output.
#[derive(Clone, Debug)]
pub struct Report {
    pub out: PathBuf,
    pub files: Vec<PathBuf>,
    /// FreeRADIUS `check_cert_issuer` (`DEVICE_CA_DN`), OpenSSL one-line format
    pub device_ca_dn: String,
    /// the realm in the device CA's name constraints
    pub realm: String,
    /// SHA-256 of the root certificate, for checking it out of band
    pub root_sha256: String,
}

impl Report {
    /// The line the command prints (the Python version printed the first part).
    pub fn summary(&self) -> String {
        format!(
            "PKI written to {}; device CA DN for FreeRADIUS check_cert_issuer: {}; device CA restricted to realm {}; root SHA-256 {}",
            self.out.display(),
            self.device_ca_dn,
            self.realm,
            self.root_sha256
        )
    }
}

/// The house name: printable ASCII without the characters that DN strings escape, so the
/// one-line DN FreeRADIUS compares is exactly `/CN=<name> Device CA`; at most 51 characters so
/// that `<name> Network Root` fits the 64-character CN limit.
fn check_name(name: &str) -> Result<(), Error> {
    let ok = !name.is_empty()
        && name.len() <= 51
        && name == name.trim()
        && name.bytes().all(|c| (c.is_ascii_graphic() || c == b' ') && !b"/\\=,+\"<>;#".contains(&c));
    if ok {
        Ok(())
    } else {
        Err(Error::Invalid(format!(
            "--name {name:?}: 1 to 51 printable ASCII characters without / \\ = , + \" < > ; #"
        )))
    }
}

/// The realm the device CA is restricted to.
pub fn realm_for(request: &Request) -> Result<String, Error> {
    let realm = match &request.realm {
        Some(realm) => realm.clone(),
        None => match request.server_name.split_once('.') {
            Some((_, parent)) => parent.to_string(),
            None => String::new(),
        },
    };
    pki::check_dns_name(&realm, "realm (give --realm)")?;
    Ok(realm.to_ascii_lowercase())
}

/// Generates root, device CA and server certificate (nothing written yet).
pub fn generate(request: &Request, now: OffsetDateTime) -> Result<Ceremony, Error> {
    check_name(&request.name)?;
    pki::check_dns_name(&request.server_name, "server name")?;
    let realm = realm_for(request)?;
    let server_name = request.server_name.to_ascii_lowercase();
    let root = pki::make_root(&format!("{} Network Root", request.name), &server_name, &realm, now)?;
    let device_ca = pki::make_device_ca(&root, &format!("{} Device CA", request.name), &realm, now)?;
    let server = pki::make_server_cert(&root, &server_name, SERVER_DAYS, now)?;
    Ok(Ceremony { root, device_ca, server, realm })
}

/// Runs the whole ceremony: generate, then write the files (see the module docs).
pub fn run(out: &Path, request: &Request, now: OffsetDateTime) -> Result<Report, Error> {
    let names: Vec<&str> = FILES.iter().map(|(name, _)| *name).collect();
    refuse_existing(out, &names)?;
    let c = generate(request, now)?;
    let mut chain = c.device_ca.cert_pem()?;
    chain.extend(c.root.cert_pem()?);
    let contents: Vec<(&str, Vec<u8>)> = vec![
        ("root.pem", c.root.cert_pem()?),
        ("root.key", c.root.key_pem()?.to_vec()),
        ("device-ca.pem", c.device_ca.cert_pem()?),
        ("device-ca.key", c.device_ca.key_pem()?.to_vec()),
        ("device-ca-chain.pem", chain),
        ("radius-server.pem", c.server.cert_pem()?),
        ("radius-server.key", c.server.key_pem()?.to_vec()),
    ];
    let files = write_all(out, contents)?;
    Ok(Report {
        out: out.to_path_buf(),
        files,
        device_ca_dn: format!("/CN={} Device CA", request.name),
        realm: c.realm,
        root_sha256: pki::fingerprint_sha256(c.root.cert())?,
    })
}

/// The `pki` command as the binary calls it (`netportal pki --out --name --server-name`): runs
/// [`run`] now with the realm derived from the server name, prints [`Report::summary`] and
/// returns the exit code 0. A `--realm` option would call [`run`] with `Request::realm` set.
pub fn command(out: &Path, name: &str, server_name: &str) -> Result<i32, Error> {
    let request = Request { name: name.to_string(), server_name: server_name.to_string(), realm: None };
    let report = run(out, &request, OffsetDateTime::now_utc())?;
    println!("{}", report.summary());
    Ok(0)
}

/// A new RADIUS server certificate from the root in `out` (`root.pem`, `root.key`), written as
/// `radius-server.pem` and `radius-server.key`; refuses when those exist (move them away
/// first). The CAs stay as they are, so no device has to enrol again.
pub fn renew_server(out: &Path, server_name: &str, now: OffsetDateTime) -> Result<Vec<PathBuf>, Error> {
    refuse_existing(out, &["radius-server.pem", "radius-server.key"])?;
    let read = |name: &str| {
        let path = out.join(name);
        fs::read(&path).map_err(|source| Error::Io { path, source })
    };
    let key = zeroize::Zeroizing::new(read("root.key")?);
    let root = Issued::from_pem(&read("root.pem")?, &key)?;
    let server = pki::make_server_cert(&root, &server_name.to_ascii_lowercase(), SERVER_DAYS, now)?;
    // a root with name constraints permits only its server name (a new name: a new ceremony)
    pki::verify(server.cert(), &[], root.cert(), pki::Purpose::TlsServer).map_err(|e| {
        Error::Invalid(format!(
            "the root does not permit the server name {server_name:?} ({e}): a new name needs a new ceremony"
        ))
    })?;
    write_all(out, vec![("radius-server.pem", server.cert_pem()?), ("radius-server.key", server.key_pem()?.to_vec())])
}

fn refuse_existing(out: &Path, names: &[&str]) -> Result<(), Error> {
    let existing: Vec<PathBuf> =
        names.iter().map(|name| out.join(name)).filter(|p| fs::symlink_metadata(p).is_ok()).collect();
    if existing.is_empty() { Ok(()) } else { Err(Error::Exists(existing)) }
}

/// Writes every file exclusively with its final mode; removes this run's files on a failure.
fn write_all(out: &Path, contents: Vec<(&str, Vec<u8>)>) -> Result<Vec<PathBuf>, Error> {
    if !out.exists() {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(out)
            .map_err(|source| Error::Io { path: out.to_path_buf(), source })?;
    }
    let mut written = Vec::new();
    for (name, data) in contents {
        let data = zeroize::Zeroizing::new(data);
        let secret = FILES.iter().any(|(n, s)| *n == name && *s);
        let path = out.join(name);
        if let Err(source) = write_one(&path, &data, secret) {
            if source.kind() != std::io::ErrorKind::AlreadyExists {
                let _ = fs::remove_file(&path); // our own partial file, never someone else's
            }
            for done in &written {
                let _ = fs::remove_file(done);
            }
            return Err(Error::Io { path, source });
        }
        written.push(path);
    }
    Ok(written)
}

fn write_one(path: &Path, data: &[u8], secret: bool) -> std::io::Result<()> {
    let mode = if secret { 0o600 } else { 0o644 };
    let mut file = OpenOptions::new().write(true).create_new(true).mode(mode).open(path)?;
    file.write_all(data)?;
    file.sync_all()?;
    if !secret {
        // the umask may have taken read rights away; FreeRADIUS and the portal must read these
        fs::set_permissions(path, fs::Permissions::from_mode(0o644))?;
    }
    Ok(())
}
