//! `radius-test-certs --pki DIR --out DIR --realm REALM NAME:ISSUER ...`
//!
//! For each NAME (`NAME:ISSUER`, or `NAME:ISSUER:EARLIER` for a renewal: the device of the
//! earlier NAME), a device certificate from the Rust PKI (`netportal_pki::pki::device_cert`,
//! exactly what the portal issues per download) is written as `NAME.key` (PKCS#8 PEM) and
//! `NAME.crt` (the certificate followed by its chain, as a supplicant presents it). ISSUER:
//!
//! - `device-ca`: the house's device CA (`DIR/device-ca.pem` + `.key`), chain = device CA;
//! - `root`: the root itself (`DIR/root.pem` + `.key`), chain = root (must be refused:
//!   `check_cert_issuer`);
//! - `foreign`: a second root and device CA with the SAME names as the house's, made here once
//!   (chain = foreign device CA + foreign root; must be refused: the chain does not verify).
//!
//! Prints one JSON object: `{"NAME": {"device_id", "serial", "not_after"}}` (serial: the
//! registry form, `pki::serial_hex`; not_after: Unix seconds). Test tooling only.
//!
//! `radius-test-certs pki OUT NAME SERVER_NAME` runs the CA ceremony
//! (`netportal_pki::ceremony::command`, what `netportal pki --out OUT --name NAME --server-name
//! SERVER_NAME` runs), for when the binary crate does not build.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use netportal_pki::pki::{self, Issued};
use time::OffsetDateTime;
use uuid::Uuid;

fn load(dir: &Path, name: &str) -> Result<Issued, String> {
    let cert = fs::read(dir.join(format!("{name}.pem"))).map_err(|e| format!("{name}.pem: {e}"))?;
    let key = fs::read(dir.join(format!("{name}.key"))).map_err(|e| format!("{name}.key: {e}"))?;
    Issued::from_pem(&cert, &key).map_err(|e| format!("{name}: {e}"))
}

fn json_str(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

fn run() -> Result<String, String> {
    let mut args = std::env::args().skip(1);
    let (mut pki_dir, mut out, mut realm, mut wanted) = (None, None, None, Vec::new());
    while let Some(a) = args.next() {
        match a.as_str() {
            "--pki" => pki_dir = args.next().map(PathBuf::from),
            "--out" => out = args.next().map(PathBuf::from),
            "--realm" => realm = args.next(),
            _ => wanted.push(a),
        }
    }
    let (pki_dir, out, realm) = match (pki_dir, out, realm) {
        (Some(p), Some(o), Some(r)) => (p, o, r),
        _ => return Err("usage: radius-test-certs --pki DIR --out DIR --realm REALM NAME:ISSUER ...".into()),
    };
    let now = OffsetDateTime::now_utc();
    let root = load(&pki_dir, "root")?;
    let device_ca = load(&pki_dir, "device-ca")?;
    let mut foreign: Option<(Issued, Issued)> = None;
    fs::create_dir_all(&out).map_err(|e| format!("{}: {e}", out.display()))?;
    let mut manifest = BTreeMap::new();
    let mut ids: BTreeMap<String, Uuid> = BTreeMap::new();
    for item in wanted {
        let parts: Vec<&str> = item.split(':').collect();
        let (name, issuer, same_as) = match parts.as_slice() {
            [name, issuer] => (*name, *issuer, None),
            [name, issuer, other] => (*name, *issuer, Some(*other)),
            _ => return Err(format!("{item}: NAME:ISSUER or NAME:ISSUER:SAME_DEVICE_AS")),
        };
        if name.is_empty() || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-') {
            return Err(format!("{name}: letters, digits and '-' only"));
        }
        // a renewal: a new certificate for the device of an earlier NAME
        let device_id = match same_as {
            Some(other) => *ids.get(other).ok_or_else(|| format!("{name}: {other} not issued before"))?,
            None => Uuid::new_v4(),
        };
        ids.insert(name.to_string(), device_id);
        let (leaf, chain): (Issued, Vec<Vec<u8>>) = match issuer {
            "device-ca" => (
                pki::device_cert(&device_ca, device_id, &realm, 365, now).map_err(|e| e.to_string())?,
                vec![device_ca.cert_pem().map_err(|e| e.to_string())?],
            ),
            "root" => (
                pki::device_cert(&root, device_id, &realm, 365, now).map_err(|e| e.to_string())?,
                vec![root.cert_pem().map_err(|e| e.to_string())?],
            ),
            "foreign" => {
                if foreign.is_none() {
                    // the same names as the house's CAs: only the keys differ
                    let root_cn = pki::subject_cn(root.cert()).ok_or("root without CN")?;
                    let ca_cn = pki::subject_cn(device_ca.cert()).ok_or("device CA without CN")?;
                    let other_root =
                        pki::make_root(&root_cn, "radius.scharni.org", &realm, now).map_err(|e| e.to_string())?;
                    let other_ca =
                        pki::make_device_ca(&other_root, &ca_cn, &realm, now).map_err(|e| e.to_string())?;
                    foreign = Some((other_root, other_ca));
                }
                let (other_root, other_ca) = foreign.as_ref().ok_or("foreign CA")?;
                (
                    pki::device_cert(other_ca, device_id, &realm, 365, now).map_err(|e| e.to_string())?,
                    vec![
                        other_ca.cert_pem().map_err(|e| e.to_string())?,
                        other_root.cert_pem().map_err(|e| e.to_string())?,
                    ],
                )
            }
            other => return Err(format!("{name}: unknown issuer {other} (device-ca, root, foreign)")),
        };
        let mut crt = leaf.cert_pem().map_err(|e| e.to_string())?;
        for c in chain {
            crt.extend(c);
        }
        fs::write(out.join(format!("{name}.crt")), crt).map_err(|e| e.to_string())?;
        fs::write(out.join(format!("{name}.key")), &*leaf.key_pem().map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        let serial = leaf.serial_hex().map_err(|e| e.to_string())?;
        let not_after = leaf.not_after().map_err(|e| e.to_string())?.unix_timestamp();
        manifest.insert(
            name.to_string(),
            format!(
                "{{\"device_id\": {}, \"serial\": {}, \"not_after\": {not_after}}}",
                json_str(&device_id.to_string()),
                json_str(&serial)
            ),
        );
    }
    let body: Vec<String> = manifest.iter().map(|(k, v)| format!("{}: {v}", json_str(k))).collect();
    Ok(format!("{{{}}}", body.join(", ")))
}

fn ceremony(args: &[String]) -> Result<String, String> {
    match args {
        [out, name, server] => netportal_pki::ceremony::command(Path::new(out), name, server)
            .map(|_| String::new())
            .map_err(|e| e.to_string()),
        _ => Err("usage: radius-test-certs pki OUT NAME SERVER_NAME".into()),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = if args.first().map(String::as_str) == Some("pki") { ceremony(&args[1..]) } else { run() };
    match result {
        Ok(json) => {
            if !json.is_empty() {
                println!("{json}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("radius-test-certs: {e}");
            ExitCode::FAILURE
        }
    }
}
