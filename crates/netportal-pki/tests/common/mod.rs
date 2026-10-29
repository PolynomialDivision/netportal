//! Shared fixtures for the integration tests: a PKI made by the ceremony, the network of the
//! Python tests (`tests/test_profiles.py:fixture`), and wrappers for the `openssl` and `xmllint`
//! command line tools (tests that need them are skipped with a message when they are missing).

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

use netportal_pki::ceremony::{self, Request};
use netportal_pki::pki::{self, Issued};
use netportal_pki::profiles::Network;
use time::OffsetDateTime;
use uuid::Uuid;

pub struct Fixture {
    pub root: Issued,
    pub device_ca: Issued,
    pub server: Issued,
    pub device_id: Uuid,
    pub issued: Issued,
    pub net: Network,
}

pub fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

/// Root, device CA and server certificate from the ceremony (realm scharni.org, derived from
/// the server name), one device certificate, the network `Scharni`.
pub fn fixture() -> Fixture {
    let request = Request { name: "Test".into(), server_name: "radius.scharni.org".into(), realm: None };
    let c = ceremony::generate(&request, now()).expect("ceremony");
    let device_id = Uuid::new_v4();
    let issued = pki::device_cert(&c.device_ca, device_id, "scharni.org", 365, now()).expect("device cert");
    let net = Network::new("scharni.org", "Scharni", "radius.scharni.org", "Scharni", c.root.cert()).expect("network");
    Fixture { root: c.root, device_ca: c.device_ca, server: c.server, device_id, issued, net }
}

pub fn have(tool: &str) -> bool {
    let ok = Command::new(tool).arg(if tool == "xmllint" { "--version" } else { "version" }).output().is_ok();
    if !ok {
        eprintln!("SKIPPED: `{tool}` is not installed");
    }
    ok
}

/// Runs `tool` with `args`, where `{name}` refers to a file written from `files`; returns
/// (success, stdout + stderr).
pub fn run_tool(tool: &str, args: &[&str], files: &[(&str, &[u8])]) -> (bool, String) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut paths: Vec<(String, PathBuf)> = Vec::new();
    for (name, data) in files {
        let path = dir.path().join(name);
        std::fs::write(&path, data).expect("write");
        paths.push((format!("{{{name}}}"), path));
    }
    let argv: Vec<String> = args
        .iter()
        .map(|a| {
            let mut a = a.to_string();
            for (placeholder, path) in &paths {
                a = a.replace(placeholder, &path.display().to_string());
            }
            a
        })
        .collect();
    let out = Command::new(tool).args(&argv).output().expect("run tool");
    let text = String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    (out.status.success(), text)
}

pub fn openssl(args: &[&str], files: &[(&str, &[u8])]) -> (bool, String) {
    run_tool("openssl", args, files)
}

/// `openssl x509 -text -noout` of a certificate.
pub fn x509_text(cert: &openssl::x509::X509Ref) -> String {
    let (ok, text) = openssl(&["x509", "-text", "-noout", "-in", "{c.pem}"], &[("c.pem", &cert.to_pem().unwrap())]);
    assert!(ok, "{text}");
    text
}

/// GÉANT CAT's eap-metadata.xsd, which `check.sh` downloads to `target/eap-metadata.xsd`.
pub fn eap_metadata_xsd() -> Option<PathBuf> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/eap-metadata.xsd");
    if path.exists() {
        Some(path)
    } else {
        eprintln!("SKIPPED: {} is missing (check.sh downloads it)", path.display());
        None
    }
}

/// A port of AOSP `ConfigParser.parseMimeMultipartMessage` (and of `aosp_parse` in
/// `tests/test_profiles.py`): base64 body, MIME multipart, base64 parts. Returns (outer
/// headers, boundary, [(content type, transfer encoding, decoded bytes)]).
pub type Headers = Vec<(String, String)>;
/// (content type, transfer encoding, decoded bytes)
pub type Part = (String, String, Vec<u8>);

pub fn aosp_parse(body: &[u8]) -> (Headers, String, Vec<Part>) {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;
    let message = String::from_utf8(b64.decode(body).expect("outer base64")).expect("ASCII message");
    assert!(message.contains("\r\n"), "CRLF line ends");
    let lines: Vec<&str> = message.split("\r\n").collect();
    let mut i = 0;
    let headers = |i: &mut usize| {
        let mut found = Vec::new();
        while !lines[*i].is_empty() {
            let (k, v) = lines[*i].split_once(':').expect("header line");
            assert!(!k.starts_with(char::is_whitespace), "no blank prefix");
            found.push((k.trim().to_string(), v.trim().to_string()));
            *i += 1;
        }
        *i += 1;
        found
    };
    let outer = headers(&mut i);
    let get = |h: &[(String, String)], k: &str| h.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    let ctype = get(&outer, "Content-Type").expect("Content-Type");
    let (kind, rest) = ctype.split_once(';').expect("boundary parameter");
    assert_eq!(kind.trim(), "multipart/mixed");
    let boundary = rest.trim().strip_prefix("boundary=").expect("boundary=").trim_matches('"').to_string();
    assert_eq!(get(&outer, "Content-Transfer-Encoding").as_deref(), Some("base64"));
    while lines[i] != format!("--{boundary}") {
        i += 1;
    }
    i += 1;
    let mut parts = Vec::new();
    loop {
        let h = headers(&mut i);
        let ctype = get(&h, "Content-Type").expect("part Content-Type");
        let cte = get(&h, "Content-Transfer-Encoding").expect("part CTE");
        let mut data = String::new();
        while !lines[i].starts_with(&format!("--{boundary}")) {
            data.push_str(lines[i]);
            i += 1;
        }
        let last = lines[i] == format!("--{boundary}--");
        i += 1;
        parts.push((ctype, cte, b64.decode(data.as_bytes()).expect("part base64")));
        if last {
            break;
        }
    }
    (outer, boundary, parts)
}

/// A minimal XML element tree (enough for the PPS MO and eap-config checks).
#[derive(Debug, Clone)]
pub struct El {
    pub name: String,
    pub attrs: Vec<(String, String)>,
    pub text: String,
    pub children: Vec<El>,
}

impl El {
    pub fn child(&self, name: &str) -> Option<&El> {
        self.children.iter().find(|c| c.name == name)
    }

    pub fn path(&self, path: &str) -> &El {
        path.split('/').fold(self, |el, name| el.child(name).unwrap_or_else(|| panic!("no {name} in {}", el.name)))
    }

    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    /// The OMA-DM child `<Node>` with this `NodeName` (exactly one).
    pub fn node(&self, name: &str) -> &El {
        let found: Vec<&El> = self
            .children
            .iter()
            .filter(|c| c.name == "Node" && c.child("NodeName").map(|n| n.text.as_str()) == Some(name))
            .collect();
        assert_eq!(found.len(), 1, "node {name}");
        found[0]
    }

    pub fn value(&self) -> &str {
        &self.child("Value").expect("Value").text
    }
}

pub fn parse_xml(xml: &[u8]) -> El {
    use quick_xml::XmlVersion;
    use quick_xml::events::Event;
    let mut reader = quick_xml::Reader::from_reader(xml);
    let mut stack: Vec<El> = vec![El { name: String::new(), attrs: vec![], text: String::new(), children: vec![] }];
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf).expect("well-formed XML") {
            Event::Start(e) => {
                let attrs = e
                    .attributes()
                    .map(|a| {
                        let a = a.expect("attribute");
                        let value = a.normalized_value(XmlVersion::Implicit1_0).expect("attribute value").to_string();
                        (AsRef::<str>::as_ref(&a.key).to_string(), value)
                    })
                    .collect();
                stack.push(El {
                    name: AsRef::<str>::as_ref(&e.name()).to_string(),
                    attrs,
                    text: String::new(),
                    children: vec![],
                });
            }
            Event::End(_) => {
                let el = stack.pop().unwrap();
                stack.last_mut().unwrap().children.push(el);
            }
            Event::Text(t) => {
                let text = t.xml_content(XmlVersion::Implicit1_0).to_string();
                stack.last_mut().unwrap().text.push_str(&text);
            }
            Event::GeneralRef(r) => {
                let name = AsRef::<str>::as_ref(&*r).to_string();
                let resolved = match name.as_str() {
                    "amp" => "&".to_string(),
                    "lt" => "<".to_string(),
                    "gt" => ">".to_string(),
                    "quot" => "\"".to_string(),
                    "apos" => "'".to_string(),
                    other => panic!("unexpected entity {other}"),
                };
                stack.last_mut().unwrap().text.push_str(&resolved);
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    stack.pop().unwrap().children.pop().expect("root element")
}
