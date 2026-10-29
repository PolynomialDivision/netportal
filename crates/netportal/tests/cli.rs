//! The binary's commands from the outside (Python: tests/test_units.py OffboardSidecarTests for
//! the exit codes; INVENTORY 1.1): exit codes, messages, and `init-db` against a real database
//! when `NETPORTAL_TEST_DATABASE_URL` is set (skipped with a message otherwise).

use std::process::{Command, Output};
use std::sync::LazyLock;

use sqlx::{Connection, Executor, PgConnection};

/// Run the binary with exactly these variables (and PATH).
fn netportal(args: &[&str], vars: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_netportal"));
    cmd.args(args).env_clear().env("PATH", std::env::var("PATH").unwrap_or_default());
    for (k, v) in vars {
        cmd.env(k, v);
    }
    cmd.output().expect("run netportal")
}

// arguments, variables, the command name in the message

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn test_usage_errors_exit_2() {
    assert_eq!(netportal(&[], &[]).status.code(), Some(2));
    assert_eq!(netportal(&["bogus"], &[]).status.code(), Some(2));
    assert_eq!(netportal(&["offboard", "--every", "x"], &[]).status.code(), Some(2));
    assert_eq!(netportal(&["pki", "--out", "/tmp/x"], &[]).status.code(), Some(2)); // --server-name required
    assert_eq!(netportal(&["job"], &[]).status.code(), Some(2));
    // --allow-mass is one round only (security review M1)
    assert_eq!(netportal(&["offboard", "--allow-mass", "--every", "900"], &[]).status.code(), Some(2));
    assert_eq!(netportal(&["--help"], &[]).status.code(), Some(0));
}

#[test]
fn test_missing_settings_exit_1_with_the_name() {
    let out = netportal(&["init-db"], &[]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(text(&out.stderr).trim(), "netportal: init-db: missing setting NETPORTAL_DATABASE_URL");
    let out = netportal(&["init-db"], &[("NETPORTAL_DATABASE_URL", "postgresql://x/y")]);
    assert_eq!(text(&out.stderr).trim(), "netportal: init-db: missing setting NETPORTAL_POLICIES");
    let out = netportal(&["collect", "--once"], &[("NETPORTAL_DATABASE_URL", "postgresql://x/y")]);
    assert_eq!(text(&out.stderr).trim(), "netportal: collect: missing setting NETPORTAL_SSID");
    let out = netportal(&["serve"], &[]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).starts_with("netportal: serve: missing setting"), "{}", text(&out.stderr));
}

#[test]
fn test_offboard_without_the_users_api_is_switched_off() {
    // No NETPORTAL_AUTHENTIK_API / _TOKEN: one round reads, changes and records nothing and
    // exits 0 (`--every` would loop forever, so only the single round is run here).
    let vars = [("NETPORTAL_DATABASE_URL", "postgresql://x/y"), ("NETPORTAL_POLICIES", "residents=30:residents")];
    let out = netportal(&["offboard"], &vars);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", text(&out.stderr));
}

#[tokio::test]
async fn test_init_db_creates_and_upgrades_the_schema() {
    let Some(admin) = std::env::var("NETPORTAL_TEST_DATABASE_URL").ok().filter(|u| !u.is_empty()) else {
        eprintln!("skipped: NETPORTAL_TEST_DATABASE_URL is not set (eval \"$(tools/test-db.sh)\")");
        return;
    };
    let mut url = url::Url::parse(&admin).expect("url");
    let name = format!("cli_{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let mut conn = PgConnection::connect(&admin).await.expect("connect");
    conn.execute(sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))).await.expect("create");
    url.set_path(&format!("/{name}"));
    let vars = [
        ("NETPORTAL_DATABASE_URL", url.as_str()),
        ("NETPORTAL_POLICIES", "residents=30:residents,it-admins;guests=50:former-residents"),
    ];
    let out = netportal(&["init-db"], &vars);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "schema ready (version 5)\n");
    let log = text(&out.stderr);
    assert!(log.contains(" netportal.registry INFO applying migration 0001 (registry)"), "{log}");
    assert!(log.contains(" netportal.registry INFO applying migration 0002 (radius contract)"), "{log}");
    assert!(log.contains(" netportal.registry INFO applying migration 0003 (session epoch)"), "{log}");
    assert!(log.contains(" netportal.registry INFO applying migration 0004 (security review)"), "{log}");
    assert!(log.contains(" netportal.registry INFO applying migration 0005 (sessions and rechecks)"), "{log}");
    // again: nothing to apply, the same answer
    let out = netportal(&["init-db"], &vars);
    assert_eq!((out.status.code(), text(&out.stdout).as_str()), (Some(0), "schema ready (version 5)\n"));
    assert!(!text(&out.stderr).contains("applying"), "{}", text(&out.stderr));
    let mut db = PgConnection::connect(url.as_str()).await.expect("connect");
    let policies: Vec<(String, i32)> =
        sqlx::query_as("SELECT name, vlan FROM policy ORDER BY name").fetch_all(&mut db).await.expect("policies");
    assert_eq!(policies, [("guests".to_string(), 50), ("residents".to_string(), 30)]);
    // a database that cannot be reached: exit 1, the URL (a secret) not in the message
    let bad = "postgresql://netportal:pw-secret@127.0.0.1:1/x";
    let out =
        netportal(&["init-db"], &[("NETPORTAL_DATABASE_URL", bad), ("NETPORTAL_POLICIES", "residents=30:residents")]);
    assert_eq!(out.status.code(), Some(1));
    assert!(!text(&out.stderr).contains("pw-secret"), "{}", text(&out.stderr));
}

/// A device CA key file (a PEM header is all the settings check).
static KEY_FILE: LazyLock<tempfile::NamedTempFile> = LazyLock::new(|| {
    let mut file = tempfile::NamedTempFile::new().expect("temp file");
    std::io::Write::write_all(&mut file, b"-----BEGIN PRIVATE KEY-----\n").expect("write");
    file
});

fn key_path() -> &'static str {
    static PATH: LazyLock<String> = LazyLock::new(|| KEY_FILE.path().to_string_lossy().into_owned());
    PATH.as_str()
}

/// The portal settings of a `serve` that gets as far as its own checks (no database needed).
fn serve_vars(extra: &[(&'static str, &'static str)]) -> Vec<(&'static str, &'static str)> {
    let mut vars = vec![
        ("NETPORTAL_BASE_URL", "http://wifi.test"),
        ("NETPORTAL_REALM", "scharni.org"),
        ("NETPORTAL_SSID", "Scharni"),
        ("NETPORTAL_RADIUS_SERVER_NAME", "radius.scharni.org"),
        ("NETPORTAL_DATABASE_URL", "postgresql://nobody:pw-secret@127.0.0.1:1/none"),
        ("NETPORTAL_SESSION_SECRET", "a-session-secret-of-at-least-32-bytes"),
        ("NETPORTAL_OIDC_ISSUER", "http://127.0.0.1:1/application/o/netportal/"),
        ("NETPORTAL_OIDC_CLIENT_ID", "netportal"),
        ("NETPORTAL_OIDC_CLIENT_SECRET", "s"),
        ("NETPORTAL_POLICIES", "residents=30:residents"),
        ("NETPORTAL_ROOT_CERT", "/nonexistent/root.pem"),
        ("NETPORTAL_DEVICE_CA_CERT", "/nonexistent/device-ca.pem"),
        ("NETPORTAL_DEVICE_CA_KEY", key_path()),
    ];
    vars.extend_from_slice(extra);
    vars
}

#[test]
fn test_serve_checks_its_address_and_registry() {
    // the address: --bind, else NETPORTAL_LISTEN
    let out = netportal(&["serve"], &serve_vars(&[("NETPORTAL_LISTEN", "not-an-address")]));
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("NETPORTAL_LISTEN: \"not-an-address\" is not host:port"),
        "{}",
        text(&out.stderr)
    );
    let out = netportal(&["serve", "--bind", "bogus"], &serve_vars(&[("NETPORTAL_LISTEN", "127.0.0.1:1")]));
    assert!(text(&out.stderr).contains("\"bogus\" is not host:port"), "{}", text(&out.stderr));
    // a registry that cannot be reached stops the start (the URL, a secret, is not in the message)
    let out = netportal(&["serve", "--bind", "127.0.0.1:0"], &serve_vars(&[]));
    assert_eq!(out.status.code(), Some(1));
    let stderr = text(&out.stderr);
    assert!(stderr.contains("netportal: serve: registry:"), "{stderr}");
    assert!(!stderr.contains("pw-secret"), "{stderr}");
    // a session secret shorter than 32 bytes
    let mut vars = serve_vars(&[]);
    vars.retain(|(k, _)| *k != "NETPORTAL_SESSION_SECRET");
    vars.push(("NETPORTAL_SESSION_SECRET", "short"));
    let out = netportal(&["serve"], &vars);
    assert_eq!(text(&out.stderr).trim(), "netportal: serve: NETPORTAL_SESSION_SECRET: at least 32 bytes");
    // the device CA key only from a file (security review L3)
    let out = netportal(
        &["serve"],
        &serve_vars(&[("NETPORTAL_DEVICE_CA_KEY_B64", "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCg==")]),
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("NETPORTAL_DEVICE_CA_KEY_B64 is not supported"), "{}", text(&out.stderr));
    // a metrics address that is not host:port
    let out = netportal(&["serve"], &serve_vars(&[("NETPORTAL_METRICS_LISTEN", "metrics")]));
    assert!(text(&out.stderr).contains("NETPORTAL_METRICS_LISTEN"), "{}", text(&out.stderr));
}

#[test]
fn test_health_commands_exit_0_or_1_with_the_reason() {
    let dir = tempfile::tempdir().unwrap();
    let beat = dir.path().join("netportal-offboard.heartbeat");
    let file = beat.to_str().unwrap();
    let out = netportal(&["health", "heartbeat", "--file", file, "--max-age", "1800"], &[]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).starts_with("netportal: health: heartbeat "), "{}", text(&out.stderr));
    std::fs::write(&beat, b"").unwrap();
    let out = netportal(&["health", "heartbeat", "--file", file, "--max-age", "1800"], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(out.stdout.is_empty() && out.stderr.is_empty());
    // --max-age is required; nothing listens on the port
    assert_eq!(netportal(&["health", "heartbeat", "--file", file], &[]).status.code(), Some(2));
    let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().to_string();
    let out = netportal(&["health", "web", "--timeout", "1"], &[("NETPORTAL_LISTEN", &free)]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).starts_with("netportal: health: connect 127.0.0.1:"), "{}", text(&out.stderr));
}
