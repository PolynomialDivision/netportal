//! The registry against a real PostgreSQL (Python: tests/test_registry_db.py, ported to the new
//! schema): migrations, the FreeRADIUS contract (schema radius, the role's rights), the functions
//! FreeRADIUS writes through, and every registry function.
//!
//! Needs `NETPORTAL_TEST_DATABASE_URL` (a superuser's URL, e.g. from `eval "$(tools/test-db.sh)"`);
//! without it every test is skipped with a message. Each test makes its own database `t_<random>`
//! (never dropped: DROP DATABASE checkpoints and costs more than the test; the container is
//! throwaway); the role radius (cluster-wide) is created by the first test.

use std::sync::LazyLock;
use std::time::Instant;

use netportal_core::Db;
use netportal_core::config::Policy;
use netportal_core::registry::{self, NewConnectionEvent, TokenUse};
use serde_json::json;
use sqlx::{Connection, Executor, PgConnection, Row};
use time::{Duration, OffsetDateTime, macros::datetime};
use tokio::sync::{Mutex, OnceCell, RwLock};
use uuid::Uuid;

const T0: OffsetDateTime = datetime!(2026-01-01 00:00 UTC);
const HOUR: Duration = Duration::hours(1);
const DAY: Duration = Duration::days(1);
const RADIUS_PASSWORD: &str = "radius-test-password";

/// Renaming the role radius (one test) must not run while others use it.
static RADIUS_ROLE: LazyLock<RwLock<()>> = LazyLock::new(|| RwLock::new(()));
/// Role-level statements (the grants' ALTER ROLE) of concurrent tests would collide.
static ROLE_DDL: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
static ROLE_READY: OnceCell<()> = OnceCell::const_new();

fn admin_url() -> Option<url::Url> {
    let url = std::env::var("NETPORTAL_TEST_DATABASE_URL").ok().filter(|u| !u.is_empty())?;
    url::Url::parse(&url).ok()
}

macro_rules! need_db {
    () => {
        match admin_url() {
            Some(url) => url,
            None => {
                eprintln!("skipped: NETPORTAL_TEST_DATABASE_URL is not set (eval \"$(rust/tools/test-db.sh)\")");
                return;
            }
        }
    };
}

fn url_for(admin: &url::Url, dbname: &str, user: Option<(&str, &str)>) -> String {
    let mut url = admin.clone();
    url.set_path(&format!("/{dbname}"));
    if let Some((user, password)) = user {
        let _ = url.set_username(user);
        let _ = url.set_password(Some(password));
    }
    url.to_string()
}

async fn admin_conn(admin: &url::Url) -> PgConnection {
    PgConnection::connect(admin.as_str()).await.expect("connect as admin")
}

async fn ensure_radius_role(admin: &url::Url) {
    ROLE_READY
        .get_or_init(|| async {
            let mut conn = admin_conn(admin).await;
            conn.execute(sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
                "DO $$ BEGIN
                     IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'radius') THEN
                         CREATE ROLE radius LOGIN PASSWORD '{RADIUS_PASSWORD}';
                     ELSE
                         ALTER ROLE radius LOGIN PASSWORD '{RADIUS_PASSWORD}';
                     END IF;
                 END $$"
            ))))
            .await
            .expect("role radius");
        })
        .await;
}

/// A fresh, empty database; returns its URL.
async fn fresh_database(admin: &url::Url) -> String {
    ensure_radius_role(admin).await;
    let name = format!("t_{}", &Uuid::new_v4().simple().to_string()[..12]);
    let mut conn = admin_conn(admin).await;
    conn.execute(sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))).await.expect("create database");
    url_for(admin, &name, None)
}

fn policies() -> Vec<Policy> {
    vec![
        Policy { name: "residents".into(), vlan: 30, groups: ["residents".to_string()].into() },
        Policy { name: "guests".into(), vlan: 50, groups: ["former-residents".to_string()].into() },
    ]
}

/// A fresh, initialised database (Python DbCase).
struct Case {
    url: String,
    db: Db,
}

impl Case {
    async fn new(admin: &url::Url) -> Case {
        let url = fresh_database(admin).await;
        let mut db = Db::connect(&url).await.expect("connect");
        {
            let _ddl = ROLE_DDL.lock().await;
            registry::init(&mut db, &policies()).await.expect("init");
        }
        Case { url, db }
    }

    async fn radius(&self) -> PgConnection {
        let url = url::Url::parse(&self.url).expect("url");
        let path = url.path().trim_start_matches('/').to_string();
        PgConnection::connect(&url_for(&url, &path, Some(("radius", RADIUS_PASSWORD))))
            .await
            .expect("connect as radius")
    }

    async fn other(&self) -> Db {
        Db::connect(&self.url).await.expect("connect")
    }

    async fn exec(&mut self, sql: &str) {
        self.db.tx().await.expect("tx").execute(sqlx::raw_sql(sqlx::AssertSqlSafe(sql.to_string()))).await.expect(sql);
    }

    async fn commit(&mut self) {
        self.db.commit().await.expect("commit");
    }

    async fn i64(&mut self, sql: &str) -> Option<i64> {
        sqlx::query_scalar::<_, Option<i64>>(sqlx::AssertSqlSafe(sql.to_string()))
            .fetch_one(self.db.tx().await.expect("tx"))
            .await
            .expect(sql)
    }

    async fn person(&mut self, sub: Option<&str>) -> String {
        let sub =
            sub.map(str::to_string).unwrap_or_else(|| format!("sub-{}", &Uuid::new_v4().simple().to_string()[..8]));
        let display = format!("{} Name", sub);
        registry::upsert_person(&mut self.db, &sub, &sub, &display, false).await.expect("person");
        sub
    }

    /// A device with one certificate (Python DbCase.device).
    async fn device(
        &mut self,
        owner: Option<&str>,
        not_after: Option<OffsetDateTime>,
        revoked: bool,
    ) -> (Uuid, String) {
        let owner = match owner {
            Some(o) => o.to_string(),
            None => self.person(None).await,
        };
        let id = registry::create_device(&mut self.db, &owner, "dev", "apple", "residents").await.expect("device");
        let serial = hex(8);
        let not_after = not_after.unwrap_or_else(|| OffsetDateTime::now_utc() + DAY);
        sqlx::query("INSERT INTO credential (serial, device_id, issued_at, not_after) VALUES ($1, $2, $3, $4)")
            .bind(&serial)
            .bind(id)
            .bind(not_after - DAY * 2)
            .bind(not_after)
            .execute(self.db.tx().await.expect("tx"))
            .await
            .expect("credential");
        if revoked {
            sqlx::query("UPDATE device SET revoked_at = now() WHERE id = $1")
                .bind(id)
                .execute(self.db.tx().await.expect("tx"))
                .await
                .expect("revoke");
        }
        self.commit().await;
        (id, serial)
    }

    async fn window(&mut self, id: Uuid, mac: &str, first: OffsetDateTime, last: OffsetDateTime) {
        sqlx::query(
            "INSERT INTO device_mac (device_id, mac, first_seen, last_seen, auth_count, randomized)
             VALUES ($1, $2::macaddr, $3, $4, 1, false)",
        )
        .bind(id)
        .bind(mac)
        .bind(first)
        .bind(last)
        .execute(self.db.tx().await.expect("tx"))
        .await
        .expect("window");
        self.commit().await;
    }

    async fn login(&mut self, dev: Uuid, serial: &str, mac: &str, nas: &str) -> Option<String> {
        login(self.db.tx().await.expect("tx"), &dev.to_string(), serial, mac, "AA-BB-CC-00-00-01:Scharni", nas, "")
            .await
    }

    async fn accounting(&mut self, a: Acct<'_>) {
        accounting(self.db.tx().await.expect("tx"), a).await;
    }

    async fn session(&mut self, sid: &str, nas: &str) -> Option<AcctRow> {
        sqlx::query_as(
            "SELECT device_id, link, mac::text AS mac, host(framed_ip) AS ip, ssid, started, updated, stopped,
                    session_time_s, input_octets, output_octets, terminate_cause, interim_s
             FROM radius_acct WHERE nas_ip = $1::inet AND acct_session_id = $2",
        )
        .bind(nas)
        .bind(sid)
        .fetch_optional(self.db.tx().await.expect("tx"))
        .await
        .expect("session")
    }
}

#[derive(Debug, sqlx::FromRow)]
struct AcctRow {
    device_id: Option<Uuid>,
    link: String,
    mac: Option<String>,
    ip: Option<String>,
    ssid: Option<String>,
    started: Option<OffsetDateTime>,
    updated: OffsetDateTime,
    stopped: Option<OffsetDateTime>,
    session_time_s: Option<i64>,
    input_octets: Option<i64>,
    output_octets: Option<i64>,
    terminate_cause: Option<String>,
    interim_s: Option<i32>,
}

async fn last_seen(db: &mut Db, dev: Uuid) -> OffsetDateTime {
    sqlx::query_scalar("SELECT last_seen FROM device_mac WHERE device_id = $1")
        .bind(dev)
        .fetch_one(db.tx().await.expect("tx"))
        .await
        .expect("last_seen")
}

async fn session_of(db: &mut Db, dev: Uuid) -> (String, String, String, OffsetDateTime) {
    sqlx::query_as(
        "SELECT host(nas_ip), calling_station, user_name, first_seen FROM radius_session WHERE device_id = $1",
    )
    .bind(dev)
    .fetch_one(db.tx().await.expect("tx"))
    .await
    .expect("session")
}

async fn nas_interim_at(db: &mut Db, nas: &str) -> Option<OffsetDateTime> {
    sqlx::query_scalar("SELECT interim_at FROM radius_nas WHERE nas_ip = $1::inet")
        .bind(nas)
        .fetch_one(db.tx().await.expect("tx"))
        .await
        .expect("interim_at")
}

fn hex(bytes: usize) -> String {
    Uuid::new_v4().simple().to_string()[..bytes * 2].to_string()
}

fn ts(t: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(t).expect("timestamp")
}

fn now_s() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

async fn login(
    conn: &mut PgConnection,
    dev: &str,
    serial: &str,
    mac: &str,
    called: &str,
    nas: &str,
    acct: &str,
) -> Option<String> {
    sqlx::query_scalar("SELECT radius.login($1, $2, $3, $4, $5, $6, 'anonymous@scharni.org')")
        .bind(dev)
        .bind(serial)
        .bind(mac)
        .bind(called)
        .bind(nas)
        .bind(acct)
        .fetch_one(conn)
        .await
        .expect("radius.login")
}

/// radius.accounting's 14 arguments (Python accounting()).
#[derive(Clone, Copy)]
struct Acct<'a> {
    status: &'a str,
    sid: &'a str,
    class: &'a str,
    mac: &'a str,
    nas: &'a str,
    called: &'a str,
    framed: &'a str,
    time: &'a str,
    input: &'a str,
    output: &'a str,
    in_gw: &'a str,
    out_gw: &'a str,
    cause: &'a str,
    event_ts: &'a str,
}

fn acct<'a>(status: &'a str, sid: &'a str) -> Acct<'a> {
    Acct {
        status,
        sid,
        class: "",
        mac: "AA-BB-CC-DD-EE-01",
        nas: "10.0.0.2",
        called: "AA-BB-CC-00-00-02:Scharni",
        framed: "",
        time: "",
        input: "",
        output: "",
        in_gw: "",
        out_gw: "",
        cause: "",
        event_ts: "",
    }
}

async fn accounting(conn: &mut PgConnection, a: Acct<'_>) {
    sqlx::query("SELECT radius.accounting($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)")
        .bind(a.status)
        .bind(a.sid)
        .bind(a.class)
        .bind(a.mac)
        .bind(a.called)
        .bind(a.nas)
        .bind(a.framed)
        .bind(a.time)
        .bind(a.input)
        .bind(a.output)
        .bind(a.in_gw)
        .bind(a.out_gw)
        .bind(a.cause)
        .bind(a.event_ts)
        .execute(conn)
        .await
        .expect("radius.accounting");
}

fn is_denied(e: &sqlx::Error) -> bool {
    e.as_database_error().and_then(|d| d.code()).as_deref() == Some("42501")
}

// --- migrations ----------------------------------------------------------------------------------

#[tokio::test]
async fn test_empty_database_then_idempotent() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let url = fresh_database(&admin).await;
    let mut db = Db::connect(&url).await.expect("connect");
    let _ddl = ROLE_DDL.lock().await;
    let first = registry::migrate(&mut db).await.expect("migrate");
    assert_eq!((first.applied.as_slice(), first.version, first.radius_role), (&[1, 2, 3, 4][..], Some(4), true));
    let second = registry::migrate(&mut db).await.expect("migrate");
    assert_eq!((second.applied.as_slice(), second.version, second.unknown.as_slice()), (&[][..], Some(4), &[][..]));
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT table_schema || '.' || table_name FROM information_schema.tables
         WHERE table_schema IN ('public', 'radius') ORDER BY 1",
    )
    .fetch_all(db.tx().await.expect("tx"))
    .await
    .expect("tables");
    for t in [
        "public.person",
        "public.policy",
        "public.device",
        "public.credential",
        "public.radius_session",
        "public.download",
        "public.oauth_grant",
        "public.oauth_token",
        "public.job",
        "public.audit",
        "public.device_mac",
        "public.radius_auth",
        "public.radius_acct",
        "public.radius_nas",
        "public.connection_event",
        "public.device_day",
        "public.ap_day",
        "public.incident",
        "public._sqlx_migrations",
        "public.device_mac_window",
        "radius.valid_cert",
    ] {
        assert!(tables.contains(&t.to_string()), "{t} missing in {tables:?}");
    }
    let rows: Vec<(i64, String, Vec<u8>)> =
        sqlx::query_as("SELECT version, description, checksum FROM _sqlx_migrations ORDER BY version")
            .fetch_all(db.tx().await.expect("tx"))
            .await
            .expect("ledger");
    let expected: Vec<(i64, String, Vec<u8>)> =
        registry::MIGRATOR.iter().map(|m| (m.version, m.description.to_string(), m.checksum.to_vec())).collect();
    assert_eq!(rows, expected);
}

#[tokio::test]
async fn test_init_seeds_policies_and_the_offboarding_job() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    let rows: Vec<(String, i32)> = sqlx::query_as("SELECT name, vlan FROM policy ORDER BY name")
        .fetch_all(case.db.tx().await.expect("tx"))
        .await
        .expect("policies");
    assert_eq!(rows, [("guests".to_string(), 50), ("residents".to_string(), 30)]);
    let jobs = registry::job_status(&mut case.db).await.expect("jobs");
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].name, "offboarding");
    assert!(jobs[0].last_success.is_some());
    // again with a changed VLAN: updated, nothing deleted
    let mut changed = policies();
    changed[1].vlan = 51;
    changed.truncate(1);
    changed.push(Policy { name: "guests".into(), vlan: 51, groups: Default::default() });
    let _ddl = ROLE_DDL.lock().await;
    registry::init(&mut case.db, &changed).await.expect("init");
    assert_eq!(case.i64("SELECT vlan::bigint FROM policy WHERE name = 'guests'").await, Some(51));
}

#[tokio::test]
async fn test_changed_migration_is_refused() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    case.exec("UPDATE _sqlx_migrations SET checksum = '\\x00' WHERE version = 2").await;
    case.commit().await;
    let result = {
        let _ddl = ROLE_DDL.lock().await;
        registry::migrate(&mut case.db).await
    };
    let message = result.err().map(|e| e.to_string()).unwrap_or_default();
    assert!(message.contains('2'), "{message}");
    // nothing half-done: the connection is usable, the record unchanged
    let checksum: Vec<u8> = sqlx::query_scalar("SELECT checksum FROM _sqlx_migrations WHERE version = 2")
        .fetch_one(case.db.tx().await.expect("tx"))
        .await
        .expect("checksum");
    assert_eq!(checksum, vec![0u8]);
}

#[tokio::test]
async fn test_newer_schema_is_left_alone() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    case.exec(
        "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time)
         VALUES (99, 'from the future', true, '\\x01', 1)",
    )
    .await;
    case.commit().await;
    let _ddl = ROLE_DDL.lock().await;
    let report = registry::migrate(&mut case.db).await.expect("migrate");
    assert_eq!((report.applied, report.unknown, report.version), (vec![], vec![99], Some(99)));
}

#[tokio::test]
async fn test_upgrade_from_an_older_release() {
    // the analogue of Python's test_upgrade_from_the_deployed_0002: a database at version 1
    // with data gets 2 and 3 and keeps the data
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let url = fresh_database(&admin).await;
    let mut db = Db::connect(&url).await.expect("connect");
    let older = sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(registry::MIGRATOR.iter().take(1).cloned().collect()),
        ..sqlx::migrate::Migrator::DEFAULT
    };
    older.run(db.autocommit().await.expect("conn")).await.expect("migrate 1");
    db.tx()
        .await
        .expect("tx")
        .execute("INSERT INTO policy VALUES ('residents', 30); INSERT INTO person (sub, username, display_name) VALUES ('a', 'a', 'A')")
        .await
        .expect("data");
    db.commit().await.expect("commit");
    let _ddl = ROLE_DDL.lock().await;
    let report = registry::migrate(&mut db).await.expect("migrate");
    assert_eq!((report.applied, report.version), (vec![2, 3, 4], Some(4)));
    let people = registry::people(&mut db).await.expect("people");
    assert_eq!(people.keys().collect::<Vec<_>>(), ["a"]);
}

#[tokio::test]
async fn test_missing_radius_role_warns() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.write().await;
    let url = fresh_database(&admin).await;
    let mut a = admin_conn(&admin).await;
    a.execute("ALTER ROLE radius RENAME TO radius_away").await.expect("rename");
    let result = async {
        let mut db = Db::connect(&url).await.expect("connect");
        let _ddl = ROLE_DDL.lock().await;
        let report = registry::migrate(&mut db).await.expect("migrate");
        let stats = registry::stats(&mut db).await.expect("stats");
        (report.radius_role, stats.radius_role)
    }
    .await;
    a.execute("ALTER ROLE radius_away RENAME TO radius").await.expect("rename back");
    a.execute(sqlx::raw_sql(sqlx::AssertSqlSafe(format!("ALTER ROLE radius PASSWORD '{RADIUS_PASSWORD}'"))))
        .await
        .expect("password"); // a rename clears an MD5 password
    assert_eq!(result, (false, false));
}

#[tokio::test]
async fn test_concurrent_migrate() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let url = fresh_database(&admin).await;
    let _ddl = ROLE_DDL.lock().await;
    let mut tasks = Vec::new();
    for _ in 0..3 {
        let url = url.clone();
        tasks.push(tokio::spawn(async move {
            let mut db = Db::connect(&url).await.expect("connect");
            registry::migrate(&mut db).await.map(|r| r.applied).map_err(|e| e.to_string())
        }));
    }
    let mut results = Vec::new();
    for t in tasks {
        results.push(t.await.expect("join").expect("migrate"));
    }
    results.sort();
    assert_eq!(results, [vec![], vec![], vec![1, 2, 3, 4]]);
}

// --- the FreeRADIUS contract -----------------------------------------------------------------------

#[tokio::test]
async fn test_radius_role_rights() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    let (dev, serial) = case.device(None, None, false).await;
    let mut r = case.radius().await;
    let vlan: Option<i32> = sqlx::query_scalar("SELECT vlan FROM radius.valid_cert WHERE serial = $1")
        .bind(&serial)
        .fetch_optional(&mut r)
        .await
        .expect("decision");
    assert_eq!(vlan, Some(30));
    let device_id: Option<String> = sqlx::query_scalar("SELECT device_id FROM radius.valid_cert WHERE serial = $1")
        .bind(&serial)
        .fetch_optional(&mut r)
        .await
        .expect("decision");
    assert_eq!(device_id, Some(dev.to_string()));
    for table in [
        "device",
        "person",
        "credential",
        "radius_session",
        "radius_auth",
        "radius_acct",
        "device_mac",
        "job",
        "audit",
        "oauth_token",
        "download",
        "device_mac_window",
    ] {
        let e = r.execute(sqlx::raw_sql(sqlx::AssertSqlSafe(format!("SELECT 1 FROM {table} LIMIT 1")))).await.err();
        assert!(e.as_ref().is_some_and(is_denied), "{table}: {e:?}");
    }
    let e = sqlx::query(
        "INSERT INTO radius_session (device_id, nas_ip, calling_station, user_name) VALUES ($1, '1.2.3.4', 'x', 'y')",
    )
    .bind(dev)
    .execute(&mut r)
    .await
    .err();
    assert!(e.as_ref().is_some_and(is_denied), "{e:?}");
    for call in ["SELECT np_device_for_mac('aa:bb:cc:dd:ee:ff', now())", "SELECT np_mac('AA-BB-CC-DD-EE-01')"] {
        let e = r.execute(call).await.err();
        assert!(e.as_ref().is_some_and(is_denied), "{call}: {e:?}");
    }
    let token =
        login(&mut r, &dev.to_string(), &serial, "AA-BB-CC-DD-EE-01", "AA-BB-CC-00-00-01:Scharni", "10.0.0.2", "")
            .await
            .unwrap_or_default();
    assert!(regex_token(&token), "{token}");
    r.execute("SELECT radius.reject('', 'AA-BB-CC-DD-EE-01', '', '10.0.0.2', 'no_cert')").await.expect("reject");
    accounting(&mut r, acct("Start", "s1")).await;
    let status: String =
        sqlx::query_scalar("SELECT radius.cert_status($1)").bind(&serial).fetch_one(&mut r).await.expect("status");
    assert_eq!(status, "valid");
    let timeout: String = sqlx::query_scalar("SHOW statement_timeout").fetch_one(&mut r).await.expect("show");
    assert_eq!(timeout, "2s");
    let lock: String = sqlx::query_scalar("SHOW lock_timeout").fetch_one(&mut r).await.expect("show");
    assert_eq!(lock, "1s");
}

fn regex_token(token: &str) -> bool {
    token.len() == 26
        && token.starts_with("np1:")
        && token[4..].bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[tokio::test]
async fn test_contract_objects() {
    // the contract is exactly: one view, four functions, in schema radius
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    let objects: Vec<String> = sqlx::query_scalar(
        "SELECT c.relname || ':' || c.relkind::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'radius'
         UNION ALL
         SELECT p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')'
         FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'radius'
         ORDER BY 1",
    )
    .fetch_all(case.db.tx().await.expect("tx"))
    .await
    .expect("objects");
    assert_eq!(
        objects,
        [
            "accounting(p_status text, p_acct_session_id text, p_class text, p_calling text, p_called text, \
             p_nas_ip text, p_framed_ip text, p_session_time text, p_in_octets text, p_out_octets text, \
             p_in_gigawords text, p_out_gigawords text, p_terminate_cause text, p_event_ts text)",
            "cert_status(p_serial text)",
            "login(p_device_id text, p_serial text, p_calling text, p_called text, p_nas_ip text, \
             p_acct_session_id text, p_user_name text)",
            "reject(p_serial text, p_calling text, p_called text, p_nas_ip text, p_reason_hint text)",
            "valid_cert:v",
        ]
    );
    let columns: Vec<(String, String)> = sqlx::query_as(
        "SELECT column_name::text, data_type::text FROM information_schema.columns
         WHERE table_schema = 'radius' AND table_name = 'valid_cert' ORDER BY ordinal_position",
    )
    .fetch_all(case.db.tx().await.expect("tx"))
    .await
    .expect("columns");
    let columns: Vec<(&str, &str)> = columns.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
    assert_eq!(columns, [("serial", "text"), ("device_id", "text"), ("vlan", "integer")]);
    // what the role may touch: the schema, the view, the functions, and nothing in public
    let public_rights = case
        .i64(
            "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = 'public' AND c.relkind IN ('r', 'v', 'S')
               AND (has_table_privilege('radius', c.oid, 'SELECT') OR has_table_privilege('radius', c.oid, 'INSERT')
                    OR has_table_privilege('radius', c.oid, 'UPDATE') OR has_table_privilege('radius', c.oid, 'DELETE'))",
        )
        .await;
    assert_eq!(public_rights, Some(0));
    let functions = case
        .i64(
            "SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
             WHERE n.nspname = 'radius' AND has_function_privilege('radius', p.oid, 'EXECUTE')",
        )
        .await;
    assert_eq!(functions, Some(4));
    let usage = case.i64("SELECT has_schema_privilege('radius', 'radius', 'USAGE')::int::bigint").await;
    assert_eq!(usage, Some(1));
    let create = case.i64("SELECT has_schema_privilege('radius', 'radius', 'CREATE')::int::bigint").await;
    assert_eq!(create, Some(0));
}

#[tokio::test]
async fn test_public_cannot_execute() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    let n = case
        .i64(
            "SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
             WHERE n.nspname IN ('public', 'radius') AND has_function_privilege('public', p.oid, 'EXECUTE')",
        )
        .await;
    assert_eq!(n, Some(0));
}

#[tokio::test]
async fn test_functions_are_definer_with_search_path() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    let rows: Vec<(String, bool, Option<Vec<String>>)> = sqlx::query_as(
        "SELECT n.nspname || '.' || p.proname, p.prosecdef, p.proconfig FROM pg_proc p
         JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname IN ('public', 'radius')",
    )
    .fetch_all(case.db.tx().await.expect("tx"))
    .await
    .expect("functions");
    for (name, definer, config) in &rows {
        if name.starts_with("radius.") {
            assert!(*definer, "{name}");
        } else {
            assert!(!*definer, "{name}"); // helpers run as their caller
        }
        assert!(config.iter().flatten().any(|c| c == "search_path=public, pg_temp"), "{name}: {config:?}");
    }
    assert_eq!(rows.iter().filter(|r| r.0.starts_with("radius.")).count(), 4);
}

// --- MACs ----------------------------------------------------------------------------------------

#[tokio::test]
async fn test_np_mac_matches_normalise_mac() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    for (raw, expected) in registry::MAC_CASES {
        assert_eq!(registry::normalise_mac(raw).as_deref(), *expected, "{raw:?}");
        let sql: Option<String> = sqlx::query_scalar("SELECT np_mac($1)::text")
            .bind(*raw)
            .fetch_one(case.db.tx().await.expect("tx"))
            .await
            .expect("np_mac");
        assert_eq!(sql.as_deref(), *expected, "{raw:?}");
    }
    let null: Option<String> = sqlx::query_scalar("SELECT np_mac(NULL)::text")
        .fetch_one(case.db.tx().await.expect("tx"))
        .await
        .expect("np_mac");
    assert_eq!(null, None);
}

#[tokio::test]
async fn test_called_station() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    let cases: &[(&str, Option<&str>, Option<&str>)] = &[
        ("AA-BB-CC-00-00-01:Scharni", Some("aa:bb:cc:00:00:01"), Some("Scharni")),
        ("aa:bb:cc:00:00:01:Scharni", Some("aa:bb:cc:00:00:01"), Some("Scharni")),
        ("AABBCC000001:Sch:arni", Some("aa:bb:cc:00:00:01"), Some("Sch:arni")),
        ("AA-BB-CC-00-00-01", Some("aa:bb:cc:00:00:01"), None),
        ("Scharni", None, None),
        ("", None, None),
    ];
    for (raw, bssid, ssid) in cases {
        let row: (Option<String>, Option<String>) =
            sqlx::query_as("SELECT bssid::text, ssid FROM np_called_station($1)")
                .bind(*raw)
                .fetch_one(case.db.tx().await.expect("tx"))
                .await
                .expect("called station");
        assert_eq!((row.0.as_deref(), row.1.as_deref()), (*bssid, *ssid), "{raw:?}");
    }
}

// --- radius.login --------------------------------------------------------------------------------

#[tokio::test]
async fn test_login_logs_and_returns_class() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    let (dev, serial) = case.device(None, None, false).await;
    let conn = case.db.tx().await.expect("tx");
    let token =
        login(conn, &dev.to_string(), &serial, "AA-BB-CC-DD-EE-01", "AA-BB-CC-00-00-01:Scharni", "10.0.0.2", "ACCT-1")
            .await
            .unwrap_or_default();
    assert!(regex_token(&token), "{token}");
    let row = sqlx::query(
        "SELECT result, reason, device_id, serial, mac::text AS mac, host(nas_ip) AS nas, bssid::text AS bssid, ssid,
                acct_session_id, tries FROM radius_auth WHERE class_token = $1",
    )
    .bind(&token)
    .fetch_one(case.db.tx().await.expect("tx"))
    .await
    .expect("row");
    let got: (String, String, Uuid, String, String, String, String, String, String, i32) = (
        row.get("result"),
        row.get("reason"),
        row.get("device_id"),
        row.get("serial"),
        row.get("mac"),
        row.get("nas"),
        row.get("bssid"),
        row.get("ssid"),
        row.get("acct_session_id"),
        row.get("tries"),
    );
    assert_eq!(
        got,
        (
            "accept".into(),
            "ok".into(),
            dev,
            serial.clone(),
            "aa:bb:cc:dd:ee:01".into(),
            "10.0.0.2".into(),
            "aa:bb:cc:00:00:01".into(),
            "Scharni".into(),
            "ACCT-1".into(),
            1
        )
    );
    let again = case.login(dev, &serial, "AA-BB-CC-DD-EE-01", "10.0.0.2").await;
    assert_ne!(again.as_deref(), Some(token.as_str())); // fresh per login
}

#[tokio::test]
async fn test_device_mac_and_session() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    let (dev, serial) = case.device(None, None, false).await;
    case.login(dev, &serial, "AA-BB-CC-DD-EE-01", "10.0.0.2").await;
    let s1 = session_of(&mut case.db, dev).await;
    assert_eq!(
        (s1.0.as_str(), s1.1.as_str(), s1.2.as_str()),
        ("10.0.0.2", "AA-BB-CC-DD-EE-01", "anonymous@scharni.org")
    );
    case.commit().await;
    case.login(dev, &serial, "AA-BB-CC-DD-EE-01", "10.0.0.3").await;
    let s2 = session_of(&mut case.db, dev).await;
    assert_eq!(s2.3, s1.3); // same MAC: first_seen kept
    assert_eq!(s2.0, "10.0.0.3");
    case.commit().await;
    case.login(dev, &serial, "DA-00-00-00-00-02", "10.0.0.2").await;
    case.login(dev, &serial, "A4-83-E7-00-00-02", "10.0.0.2").await;
    let s3 = session_of(&mut case.db, dev).await;
    assert!(s3.3 > s1.3); // another MAC: new
    let macs: Vec<(String, i32, bool)> =
        sqlx::query_as("SELECT mac::text, auth_count, randomized FROM device_mac WHERE device_id = $1 ORDER BY mac")
            .bind(dev)
            .fetch_all(case.db.tx().await.expect("tx"))
            .await
            .expect("macs");
    assert_eq!(
        macs,
        [
            ("a4:83:e7:00:00:02".to_string(), 1, false),
            ("aa:bb:cc:dd:ee:01".to_string(), 2, true), // 0xaa has the bit
            ("da:00:00:00:00:02".to_string(), 1, true),
        ]
    );
}

#[tokio::test]
async fn test_a_locked_row_does_not_hold_up_the_login() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    let (dev, serial) = case.device(None, None, false).await;
    let mut r = case.radius().await;
    let dev_text = dev.to_string();
    let called = "AA-BB-CC-00-00-01:Scharni";
    login(&mut r, &dev_text, &serial, "AA-BB-CC-DD-EE-01", called, "10.0.0.2", "").await;
    let mut other = case.other().await;
    sqlx::query("UPDATE device_mac SET last_seen = last_seen WHERE device_id = $1")
        .bind(dev)
        .execute(other.tx().await.expect("tx"))
        .await
        .expect("lock"); // row lock held
    let began = Instant::now();
    let token = login(&mut r, &dev_text, &serial, "AA-BB-CC-DD-EE-01", called, "10.0.0.2", "").await;
    let elapsed = began.elapsed().as_secs_f64();
    other.rollback().await.expect("rollback");
    assert!(token.as_deref().is_some_and(regex_token));
    assert!(0.4 < elapsed && elapsed < 0.9, "{elapsed}"); // 500 ms, not the role's 1 s
    let auth_count = case.i64(&format!("SELECT auth_count::bigint FROM device_mac WHERE device_id = '{dev}'")).await;
    assert_eq!(auth_count, Some(1)); // skipped
    let logged = case.i64(&format!("SELECT count(*) FROM radius_auth WHERE device_id = '{dev}'")).await;
    assert_eq!(logged, Some(2));
}

#[tokio::test]
async fn test_bad_input_never_raises() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    let (dev, serial) = case.device(None, None, false).await;
    let conn = case.db.tx().await.expect("tx");
    let none: Option<String> = sqlx::query_scalar("SELECT radius.login(NULL, NULL, NULL, NULL, NULL, NULL)")
        .fetch_one(&mut *conn)
        .await
        .expect("login");
    assert_eq!(none, None);
    let unknown = Uuid::new_v4().to_string();
    for args in [
        ["not-a-uuid", serial.as_str(), "x", "y", "z", ""],
        [unknown.as_str(), serial.as_str(), "", "", "", ""],
        ["'; DROP TABLE device; --", "", "", "", "", ""],
    ] {
        assert_eq!(login(&mut *conn, args[0], args[1], args[2], args[3], args[4], args[5]).await, None, "{args:?}");
    }
    // a login with junk attributes is still logged (the device is known)
    let long = "x".repeat(400);
    let token = login(&mut *conn, &dev.to_string(), "zz", "junk", "junk", "999.1.1.1", &long).await.unwrap_or_default();
    let row: (Option<String>, Option<String>, Option<String>, Option<String>, i32) = sqlx::query_as(
        "SELECT serial, mac::text, host(nas_ip), bssid::text, length(acct_session_id) FROM radius_auth WHERE class_token = $1",
    )
    .bind(&token)
    .fetch_one(&mut *conn)
    .await
    .expect("row");
    assert_eq!(row, (None, None, None, None, 253));
    conn.execute("SELECT radius.reject(NULL, NULL, NULL, NULL, NULL)").await.expect("reject");
    conn.execute(
        "SELECT radius.accounting(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)",
    )
    .await
    .expect("accounting");
    accounting(
        conn,
        Acct {
            class: "0xzz",
            mac: "junk",
            event_ts: "99999999999999999999",
            time: "-1",
            in_gw: "999999999999999999",
            ..acct("Start", "s")
        },
    )
    .await;
}

// --- radius.reject -------------------------------------------------------------------------------

async fn reject_rows(case: &mut Case, mac: &str) -> Vec<(i64, String, i32, OffsetDateTime, Option<OffsetDateTime>)> {
    sqlx::query_as("SELECT id, reason, tries, at, last_at FROM radius_auth WHERE mac = $1::macaddr ORDER BY id")
        .bind(mac)
        .fetch_all(case.db.tx().await.expect("tx"))
        .await
        .expect("rows")
}

#[tokio::test]
async fn test_repeats_are_one_row() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    let mut r = case.radius().await;
    let reject = |mac: &'static str| {
        format!("SELECT radius.reject('', '{mac}', 'AA-BB-CC-00-00-01:Scharni', '10.0.0.2', 'no_cert')")
    };
    for _ in 0..3 {
        r.execute(sqlx::raw_sql(sqlx::AssertSqlSafe(reject("AA-BB-CC-DD-EE-21")))).await.expect("reject");
    }
    let rows = reject_rows(&mut case, "aa:bb:cc:dd:ee:21").await;
    assert_eq!(rows.iter().map(|x| x.2).collect::<Vec<_>>(), [3]);
    assert!(rows[0].4.is_some_and(|last| last > rows[0].3));
    case.commit().await;
    r.execute(sqlx::raw_sql(sqlx::AssertSqlSafe(reject("AA-BB-CC-DD-EE-22")))).await.expect("reject");
    for sql in [
        "SELECT radius.reject('', 'AA-BB-CC-DD-EE-21', 'AA-BB-CC-00-00-01:Scharni', '10.0.0.2', 'not_eap')",
        "SELECT radius.reject('', 'AA-BB-CC-DD-EE-21', 'AA-BB-CC-00-00-02:Scharni', '10.0.0.2', 'no_cert')",
        "SELECT radius.reject('0123ab', 'AA-BB-CC-DD-EE-21', 'AA-BB-CC-00-00-01:Scharni', '10.0.0.2', '')",
    ] {
        r.execute(sql).await.expect("reject");
    }
    let got: Vec<(String, i32)> =
        reject_rows(&mut case, "aa:bb:cc:dd:ee:21").await.into_iter().map(|x| (x.1, x.2)).collect();
    assert_eq!(got, [("no_cert".into(), 3), ("not_eap".into(), 1), ("no_cert".into(), 1), ("unknown_cert".into(), 1)]);
    assert_eq!(reject_rows(&mut case, "aa:bb:cc:dd:ee:22").await.len(), 1);
    // more than 60 s after the latest try: a new row
    case.exec(&format!(
        "UPDATE radius_auth SET at = at - interval '2 minutes', last_at = last_at - interval '61 seconds' WHERE id = {}",
        rows[0].0
    ))
    .await;
    case.commit().await;
    r.execute(sqlx::raw_sql(sqlx::AssertSqlSafe(reject("AA-BB-CC-DD-EE-21")))).await.expect("reject");
    let no_cert = |rows: Vec<(i64, String, i32, OffsetDateTime, Option<OffsetDateTime>)>| {
        rows.into_iter().filter(|x| x.1 == "no_cert").map(|x| x.2).collect::<Vec<_>>()
    };
    assert_eq!(no_cert(reject_rows(&mut case, "aa:bb:cc:dd:ee:21").await), [3, 1, 1]);
    // a row spans at most an hour, however steady the flood
    let newest = reject_rows(&mut case, "aa:bb:cc:dd:ee:21").await.last().map(|x| x.0).unwrap_or_default();
    case.exec(&format!(
        "UPDATE radius_auth SET at = now() - interval '61 minutes', last_at = NULL WHERE id = {newest}"
    ))
    .await;
    case.commit().await;
    r.execute(sqlx::raw_sql(sqlx::AssertSqlSafe(reject("AA-BB-CC-DD-EE-21")))).await.expect("reject");
    assert_eq!(no_cert(reject_rows(&mut case, "aa:bb:cc:dd:ee:21").await), [3, 1, 1, 1]);
    // without a MAC (not from an access point) too
    for _ in 0..2 {
        r.execute("SELECT radius.reject('', '', '', '10.0.0.9', 'not_eap')").await.expect("reject");
    }
    let tries =
        case.i64("SELECT sum(tries)::bigint FROM radius_auth WHERE mac IS NULL AND host(nas_ip) = '10.0.0.9'").await;
    let rows = case.i64("SELECT count(*) FROM radius_auth WHERE mac IS NULL AND host(nas_ip) = '10.0.0.9'").await;
    assert_eq!((rows, tries), (Some(1), Some(2)));
}

#[tokio::test]
async fn test_a_row_being_updated_is_skipped_not_waited_for() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    let mut r = case.radius().await;
    let reject = "SELECT radius.reject('', 'AA-BB-CC-DD-EE-23', '', '10.0.0.2', 'no_cert')";
    r.execute(reject).await.expect("reject");
    let mut other = case.other().await;
    other
        .tx()
        .await
        .expect("tx")
        .execute("SELECT 1 FROM radius_auth WHERE mac = 'aa:bb:cc:dd:ee:23' FOR UPDATE")
        .await
        .expect("lock"); // held, not committed
    let began = Instant::now();
    r.execute(reject).await.expect("reject");
    assert!(began.elapsed().as_secs_f64() < 0.4);
    other.rollback().await.expect("rollback");
    let tries: Vec<i32> = reject_rows(&mut case, "aa:bb:cc:dd:ee:23").await.into_iter().map(|x| x.2).collect();
    assert_eq!(tries, [1, 1]);
}

#[tokio::test]
async fn test_reasons() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    let now = OffsetDateTime::now_utc();
    let (_, valid_serial) = case.device(None, None, false).await;
    let (revoked, revoked_serial) = case.device(None, None, true).await;
    let (_, expired_serial) = case.device(None, Some(now - HOUR), false).await;
    let (_, retired_serial) = case.device(None, None, false).await;
    case.exec(&format!(
        "UPDATE credential SET retired_at = now() - interval '1 minute' WHERE serial = '{retired_serial}'"
    ))
    .await;
    case.commit().await;
    async fn reason(
        case: &mut Case,
        serial: &str,
        hint: &str,
    ) -> (String, Option<Uuid>, Option<String>, Option<String>, Option<String>) {
        sqlx::query("SELECT radius.reject($1, 'AA-BB-CC-DD-EE-09', 'AA-BB-CC-00-00-01:Scharni', '10.0.0.2', $2)")
            .bind(serial)
            .bind(hint)
            .execute(case.db.tx().await.expect("tx"))
            .await
            .expect("reject");
        case.commit().await; // a transaction per reject, as FreeRADIUS calls it
        sqlx::query_as(
            "SELECT reason, device_id, serial, mac::text, ssid FROM radius_auth
             WHERE result = 'reject' ORDER BY coalesce(last_at, at) DESC, id DESC LIMIT 1",
        )
        .fetch_one(case.db.tx().await.expect("tx"))
        .await
        .expect("row")
    }
    let r = reason(&mut case, "0123abcd", "").await;
    assert_eq!((r.0.as_str(), r.1), ("unknown_cert", None));
    assert_eq!(reason(&mut case, &revoked_serial.to_uppercase(), "").await.0, "revoked");
    assert_eq!(reason(&mut case, &revoked_serial, "").await.1, Some(revoked));
    assert_eq!(reason(&mut case, &expired_serial, "").await.0, "expired");
    assert_eq!(reason(&mut case, &retired_serial, "").await.0, "retired");
    let r = reason(&mut case, &valid_serial, "").await; // the registry would accept: the TLS layer refused
    assert_eq!((r.0.as_str(), r.1, r.2.as_deref()), ("bad_chain", None, Some(valid_serial.as_str())));
    assert_eq!(reason(&mut case, "", "no_cert").await.0, "no_cert");
    assert_eq!(reason(&mut case, "", "not_eap").await.0, "not_eap");
    assert_eq!(reason(&mut case, "", "something").await.0, "other");
    let r = reason(&mut case, "not hex!", "no_cert").await;
    assert_eq!(
        (r.0.as_str(), r.2, r.3.as_deref(), r.4.as_deref()),
        ("no_cert", None, Some("aa:bb:cc:dd:ee:09"), Some("Scharni"))
    );
}

// --- radius.accounting ----------------------------------------------------------------------------

#[tokio::test]
async fn test_start_interim_stop_with_class() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    let (dev, serial) = case.device(None, None, false).await;
    let token = case.login(dev, &serial, "AA-BB-CC-DD-EE-01", "10.0.0.2").await.unwrap_or_default();
    let hex_class = format!("0x{}", token.bytes().map(|b| format!("{b:02x}")).collect::<String>());
    let t = now_s() - 900;
    let (t0, t300, t600) = (t.to_string(), (t + 300).to_string(), (t + 600).to_string());
    case.accounting(Acct { class: &hex_class, framed: "10.30.0.5", event_ts: &t0, ..acct("Start", "S1") }).await;
    let s = case.session("S1", "10.0.0.2").await.expect("session");
    assert_eq!(
        (s.device_id, s.link.as_str(), s.mac.as_deref(), s.ip.as_deref(), s.ssid.as_deref(), s.stopped),
        (Some(dev), "class", Some("aa:bb:cc:dd:ee:01"), Some("10.30.0.5"), Some("Scharni"), None)
    );
    assert_eq!(s.started, Some(ts(t)));
    case.accounting(Acct {
        class: &hex_class,
        time: "300",
        input: "1000",
        output: "5",
        in_gw: "1",
        out_gw: "2",
        event_ts: &t300,
        ..acct("Interim-Update", "S1")
    })
    .await;
    let s = case.session("S1", "10.0.0.2").await.expect("session");
    assert_eq!(
        (s.session_time_s, s.input_octets, s.output_octets),
        (Some(300), Some(1000 + (1 << 32)), Some(5 + 2 * (1 << 32)))
    );
    case.accounting(Acct {
        time: "600",
        input: "2000",
        output: "10",
        in_gw: "1",
        out_gw: "2",
        cause: "Lost-Carrier",
        event_ts: &t600,
        ..acct("Stop", "S1")
    })
    .await;
    let s = case.session("S1", "10.0.0.2").await.expect("session");
    assert_eq!(
        (s.link.as_str(), s.device_id, s.terminate_cause.as_deref(), s.session_time_s, s.input_octets),
        ("class", Some(dev), Some("Lost-Carrier"), Some(600), Some(2000 + (1 << 32)))
    );
    assert_eq!(s.stopped, Some(ts(t + 600)));
    // a late Interim (reordered) does not shrink counters or reopen the session
    case.accounting(Acct { time: "300", input: "1000", event_ts: &t300, ..acct("Interim-Update", "S1") }).await;
    let s = case.session("S1", "10.0.0.2").await.expect("session");
    assert_eq!((s.session_time_s, s.input_octets, s.stopped.is_some()), (Some(600), Some(2000 + (1 << 32)), true));
    // the plain token (not hex) works as well
    case.accounting(Acct { class: &token, ..acct("Start", "S1b") }).await;
    assert_eq!(case.session("S1b", "10.0.0.2").await.map(|s| s.link), Some("class".into()));
}

#[tokio::test]
async fn test_mac_window_and_none() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    let (dev, serial) = case.device(None, None, false).await;
    case.login(dev, &serial, "AA-BB-CC-DD-EE-21", "10.0.0.2").await;
    case.accounting(Acct { mac: "AA-BB-CC-DD-EE-21", ..acct("Start", "S2") }).await;
    let s = case.session("S2", "10.0.0.2").await.expect("session");
    assert_eq!((s.link.as_str(), s.device_id), ("mac_window", Some(dev)));
    case.accounting(Acct { mac: "AA-BB-CC-DD-EE-22", ..acct("Start", "S3") }).await;
    let s = case.session("S3", "10.0.0.2").await.expect("session");
    assert_eq!((s.link.as_str(), s.device_id), ("none", None));
    case.accounting(Acct { class: "np1:AAAAAAAAAAAAAAAAAAAAAA", mac: "AA-BB-CC-DD-EE-22", ..acct("Start", "S4") })
        .await;
    assert_eq!(case.session("S4", "10.0.0.2").await.map(|s| s.link), Some("none".into())); // unknown token, no window
    // the window grows with accounting
    let before = last_seen(&mut case.db, dev).await;
    case.commit().await;
    case.accounting(Acct { mac: "AA-BB-CC-DD-EE-21", ..acct("Interim-Update", "S2") }).await;
    assert!(last_seen(&mut case.db, dev).await > before);
}

#[tokio::test]
async fn test_class_link_kept() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    let (dev, serial) = case.device(None, None, false).await;
    let token = case.login(dev, &serial, "AA-BB-CC-DD-EE-31", "10.0.0.2").await.unwrap_or_default();
    case.accounting(Acct { class: &token, mac: "AA-BB-CC-DD-EE-31", ..acct("Start", "S5") }).await;
    case.accounting(Acct { mac: "AA-BB-CC-DD-EE-99", ..acct("Interim-Update", "S5") }).await;
    let s = case.session("S5", "10.0.0.2").await.expect("session");
    assert_eq!((s.link.as_str(), s.device_id, s.mac.as_deref()), ("class", Some(dev), Some("aa:bb:cc:dd:ee:99")));
}

#[tokio::test]
async fn test_accounting_on_closes_open_sessions_of_the_nas() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    case.accounting(Acct { nas: "10.0.0.7", ..acct("Start", "A1") }).await;
    case.accounting(Acct { nas: "10.0.0.7", ..acct("Start", "A2") }).await;
    case.accounting(Acct { nas: "10.0.0.8", ..acct("Start", "B1") }).await;
    case.accounting(Acct { mac: "", nas: "10.0.0.7", ..acct("Accounting-On", "") }).await;
    assert_eq!(case.session("A1", "10.0.0.7").await.and_then(|s| s.terminate_cause), Some("NAS-Reboot".into()));
    assert!(case.session("A2", "10.0.0.7").await.is_some_and(|s| s.stopped.is_some()));
    assert!(case.session("B1", "10.0.0.8").await.is_some_and(|s| s.stopped.is_none()));
    case.accounting(Acct { mac: "", nas: "10.0.0.8", ..acct("Accounting-Off", "") }).await;
    assert_eq!(case.session("B1", "10.0.0.8").await.and_then(|s| s.terminate_cause), Some("NAS-Request".into()));
}

#[tokio::test]
async fn test_the_measured_interval() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    let nas = "10.0.0.40";
    let t = now_s() - 1000;
    let at: Vec<String> = (0..=1000).map(|d| (t + d).to_string()).collect();
    let a = |status: &'static str, sid: &'static str, d: usize| Acct {
        nas: "10.0.0.40",
        event_ts: &at[d],
        ..acct(status, sid)
    };
    case.accounting(a("Start", "M1", 0)).await;
    assert_eq!(case.session("M1", nas).await.and_then(|s| s.interim_s), None);
    case.accounting(a("Interim-Update", "M1", 120)).await;
    assert_eq!(case.session("M1", nas).await.and_then(|s| s.interim_s), Some(120));
    case.accounting(a("Interim-Update", "M1", 120)).await; // duplicate
    case.accounting(a("Interim-Update", "M1", 60)).await; // reordered, older
    let s = case.session("M1", nas).await.expect("session");
    assert_eq!((s.interim_s, s.updated), (Some(120), ts(t + 120)));
    case.accounting(a("Interim-Update", "M1", 130)).await; // a retransmission
    assert_eq!(case.session("M1", nas).await.and_then(|s| s.interim_s), Some(120));
    case.accounting(a("Interim-Update", "M1", 360)).await; // one lost: 240
    case.accounting(a("Interim-Update", "M1", 960)).await; // an outage: 600
    assert_eq!(case.session("M1", nas).await.and_then(|s| s.interim_s), Some(120)); // the smallest gap
    assert_eq!(case.i64("SELECT interim_s::bigint FROM radius_nas WHERE nas_ip = '10.0.0.40'").await, Some(120));
    // another session's estimate within 10 % does not rewrite the NAS's; a different one does
    let nas_at = nas_interim_at(&mut case.db, nas).await;
    case.accounting(a("Start", "M2", 100)).await;
    case.accounting(a("Interim-Update", "M2", 230)).await; // 130
    assert_eq!(nas_interim_at(&mut case.db, nas).await, nas_at);
    case.accounting(a("Start", "M3", 100)).await;
    case.accounting(a("Interim-Update", "M3", 400)).await; // 300
    assert_eq!(case.i64("SELECT interim_s::bigint FROM radius_nas WHERE nas_ip = '10.0.0.40'").await, Some(300));
    // a Stop measures nothing
    case.accounting(a("Stop", "M1", 970)).await;
    assert_eq!(case.session("M1", nas).await.and_then(|s| s.interim_s), Some(120));
}

#[tokio::test]
async fn test_a_locked_radius_nas_row_does_not_lose_the_session_update() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    let t = now_s() - 1000;
    let (t0, t120) = (t.to_string(), (t + 120).to_string());
    case.accounting(Acct { nas: "10.0.0.44", event_ts: &t0, ..acct("Start", "LK") }).await;
    case.commit().await;
    let mut other = case.other().await;
    other
        .tx()
        .await
        .expect("tx")
        .execute("INSERT INTO radius_nas (nas_ip, interim_s) VALUES ('10.0.0.44', 999)")
        .await
        .expect("lock");
    case.accounting(Acct { nas: "10.0.0.44", event_ts: &t120, ..acct("Interim-Update", "LK") }).await;
    let s = case.session("LK", "10.0.0.44").await.expect("session");
    other.rollback().await.expect("rollback");
    assert_eq!((s.interim_s, s.updated), (Some(120), ts(t + 120)));
}

#[tokio::test]
async fn test_a_clock_ahead_is_taken_as_now() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    let ahead = (now_s() + 240).to_string();
    case.accounting(Acct { event_ts: &ahead, ..acct("Start", "FU") }).await;
    let started = case.session("FU", "10.0.0.2").await.and_then(|s| s.started).expect("started");
    assert!(started <= OffsetDateTime::now_utc());
}

#[tokio::test]
async fn test_a_reused_session_id_opens_again() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    let t = now_s() - 3000;
    let s = |d: i64| (t + d).to_string();
    let (s0, s100, s500, s600, s620, s1000) = (s(0), s(100), s(500), s(600), s(620), s(1000));
    case.accounting(Acct { event_ts: &s0, ..acct("Start", "RU") }).await;
    case.accounting(Acct { cause: "User-Request", event_ts: &s100, ..acct("Stop", "RU") }).await;
    case.accounting(Acct { event_ts: &s500, ..acct("Start", "RU") }).await;
    let row = case.session("RU", "10.0.0.2").await.expect("session");
    assert_eq!((row.started, row.stopped, row.terminate_cause), (Some(ts(t + 500)), None, None));
    case.accounting(Acct { event_ts: &s600, ..acct("Stop", "RU") }).await;
    case.accounting(Acct { time: "60", event_ts: &s620, ..acct("Interim-Update", "RU") }).await; // within an interval
    assert!(case.session("RU", "10.0.0.2").await.is_some_and(|r| r.stopped.is_some()));
    case.accounting(Acct { time: "60", event_ts: &s1000, ..acct("Interim-Update", "RU") }).await; // well after
    let row = case.session("RU", "10.0.0.2").await.expect("session");
    assert_eq!((row.stopped, row.started), (None, Some(ts(t + 940))));
}

#[tokio::test]
async fn test_reordered_stop_and_start() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    let t = now_s() - 1000;
    let (s0, s300, s600) = (t.to_string(), (t + 300).to_string(), (t + 600).to_string());
    // the Stop overtakes the Start (and an Interim): the session ends up stopped
    case.accounting(Acct { time: "600", cause: "User-Request", event_ts: &s600, ..acct("Stop", "R1") }).await;
    case.accounting(Acct { event_ts: &s0, ..acct("Start", "R1") }).await;
    case.accounting(Acct { time: "300", event_ts: &s300, ..acct("Interim-Update", "R1") }).await;
    let s = case.session("R1", "10.0.0.2").await.expect("session");
    assert_eq!(
        (s.started, s.updated, s.stopped, s.terminate_cause.as_deref()),
        (Some(ts(t)), ts(t + 600), Some(ts(t + 600)), Some("User-Request"))
    );
    // a retransmitted Stop (no Event-Timestamp: its arrival) keeps the first stop time
    case.accounting(Acct { time: "600", cause: "User-Request", ..acct("Stop", "R1") }).await;
    assert_eq!(case.session("R1", "10.0.0.2").await.and_then(|s| s.stopped), Some(ts(t + 600)));
    // a retransmitted Start (its Event-Timestamp) keeps the start and the Stop
    case.accounting(Acct { event_ts: &s0, ..acct("Start", "R1") }).await;
    let s = case.session("R1", "10.0.0.2").await.expect("session");
    assert_eq!((s.started, s.stopped), (Some(ts(t)), Some(ts(t + 600))));
}

#[tokio::test]
async fn test_a_stop_ends_only_its_own_session() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    let t = now_s() - 600;
    let s = |d: i64| (t + d).to_string();
    let (s0, s300, s310, s320) = (s(0), s(300), s(310), s(320));
    case.accounting(Acct { nas: "10.0.0.41", event_ts: &s0, ..acct("Start", "OLD") }).await;
    case.accounting(Acct { nas: "10.0.0.42", event_ts: &s300, ..acct("Start", "NEW") }).await; // the roam's new AP
    case.accounting(Acct { nas: "10.0.0.41", cause: "User-Request", event_ts: &s310, ..acct("Stop", "OLD") }).await;
    assert!(case.session("OLD", "10.0.0.41").await.is_some_and(|s| s.stopped.is_some()));
    assert!(case.session("NEW", "10.0.0.42").await.is_some_and(|s| s.stopped.is_none()));
    // the same session id at another AP is another session
    case.accounting(Acct { nas: "10.0.0.42", event_ts: &s320, ..acct("Start", "OLD") }).await;
    assert!(case.session("OLD", "10.0.0.42").await.is_some_and(|s| s.stopped.is_none()));
}

#[tokio::test]
async fn test_accounting_on_and_reordering() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    let nas = "10.0.0.43";
    let t = now_s() - 600;
    let s = |d: i64| (t + d).to_string();
    let (s50, s100, s200, s250, s280, s300, s400) = (s(50), s(100), s(200), s(250), s(280), s(300), s(400));
    case.accounting(Acct { nas, event_ts: &s200, ..acct("Start", "N1") }).await;
    case.accounting(Acct { mac: "", nas, event_ts: &s100, ..acct("Accounting-On", "") }).await; // older, arrives late
    assert!(case.session("N1", nas).await.is_some_and(|s| s.stopped.is_none()));
    // a Start from before the reboot that arrives after the Accounting-On: ended by it
    case.accounting(Acct { nas, event_ts: &s50, ..acct("Start", "N0") }).await;
    let row = case.session("N0", nas).await.expect("session");
    assert_eq!((row.stopped, row.terminate_cause.as_deref()), (Some(ts(t + 100)), Some("NAS-Reboot")));
    // a newer Accounting-Off closes N1; an older Off after it changes nothing
    case.accounting(Acct { mac: "", nas, event_ts: &s300, ..acct("Accounting-Off", "") }).await;
    case.accounting(Acct { mac: "", nas, event_ts: &s250, ..acct("Accounting-Off", "") }).await;
    let row = case.session("N1", nas).await.expect("session");
    assert_eq!((row.stopped, row.terminate_cause.as_deref()), (Some(ts(t + 300)), Some("NAS-Request")));
    let reset: Option<OffsetDateTime> = sqlx::query_scalar("SELECT reset_at FROM radius_nas WHERE nas_ip = $1::inet")
        .bind(nas)
        .fetch_one(case.db.tx().await.expect("tx"))
        .await
        .expect("reset_at");
    assert_eq!(reset, Some(ts(t + 300)));
    // a session updated after the reset is not ended by a late older packet
    case.accounting(Acct { nas, event_ts: &s400, ..acct("Start", "N2") }).await;
    case.accounting(Acct { nas, event_ts: &s280, ..acct("Interim-Update", "N2") }).await;
    assert!(case.session("N2", nas).await.is_some_and(|s| s.stopped.is_none()));
}

#[tokio::test]
async fn test_accounting_on_keeps_the_last_contact_of_abandoned_sessions() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    let nas = "10.0.0.45";
    let t = now_s() - 6 * 86400;
    let (old, live) = (t.to_string(), (now_s() - 100).to_string());
    case.accounting(Acct { nas, event_ts: &old, ..acct("Start", "AB") }).await;
    case.accounting(Acct { nas, event_ts: &live, ..acct("Start", "LIVE") }).await;
    case.accounting(Acct { mac: "", nas, ..acct("Accounting-On", "") }).await;
    let s = case.session("AB", nas).await.expect("session");
    assert_eq!((s.updated, s.stopped, s.terminate_cause.as_deref()), (ts(t), Some(ts(t + 660)), Some("NAS-Reboot")));
    let live = case.session("LIVE", nas).await.and_then(|s| s.stopped).expect("stopped");
    assert!((live - OffsetDateTime::now_utc()).abs() < Duration::seconds(60));
}

#[tokio::test]
async fn test_implausible_event_timestamp() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    case.accounting(Acct { event_ts: "1000", ..acct("Start", "T1") }).await; // 1970: the AP's clock is not set
    let started = case.session("T1", "10.0.0.2").await.and_then(|s| s.started).expect("started");
    assert!((started - OffsetDateTime::now_utc()).abs() < Duration::seconds(60));
}

#[tokio::test]
async fn test_ignored_packets() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    case.accounting(acct("Start", "")).await; // no session id
    case.accounting(Acct { nas: "", ..acct("Start", "X1") }).await; // no NAS
    case.accounting(acct("Weird", "X2")).await;
    assert_eq!(case.i64("SELECT count(*) FROM radius_acct").await, Some(0));
}

// --- windows -------------------------------------------------------------------------------------

const MAC: &str = "aa:bb:cc:dd:ee:51";

#[tokio::test]
async fn test_recycled_mac_at_different_times() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    let (a, _) = case.device(None, None, false).await;
    let (b, _) = case.device(None, None, false).await;
    case.window(a, MAC, T0, T0 + DAY).await;
    case.window(b, MAC, T0 + DAY * 2, T0 + DAY * 3).await;
    let db = &mut case.db;
    assert!(registry::window_conflicts(db, &[a, b], None, None).await.expect("conflicts").is_empty());
    assert_eq!(registry::device_for_mac(db, MAC, T0 + HOUR).await.expect("mac"), Some(a));
    assert_eq!(
        registry::device_for_mac(db, "AA-BB-CC-DD-EE-51", T0 + DAY + Duration::minutes(10)).await.expect("mac"),
        Some(a)
    );
    // a's only (current) window reaches 12 h 15 min past its last login; then nobody's
    assert_eq!(registry::device_for_mac(db, MAC, T0 + DAY + HOUR * 12).await.expect("mac"), Some(a));
    assert_eq!(registry::device_for_mac(db, MAC, T0 + DAY + HOUR * 13).await.expect("mac"), None);
    assert_eq!(registry::device_for_mac(db, MAC, T0 + DAY * 2 + HOUR).await.expect("mac"), Some(b));
    assert_eq!(registry::device_for_mac(db, "junk", T0).await.expect("mac"), None);
    let unknown = Uuid::new_v4();
    let windows = registry::device_windows(db, &[a, b, unknown], None, None).await.expect("windows");
    assert_eq!(windows.len(), 3);
    assert!(windows[&unknown].is_empty());
    let w: Vec<_> =
        windows[&a].iter().map(|w| (w.mac.as_str(), w.first_seen, w.last_seen, w.window_end, w.current)).collect();
    assert_eq!(w, [(MAC, T0, T0 + DAY, T0 + DAY + registry::CURRENT_WINDOW, true)]);
    assert!(registry::device_windows(db, &[a], Some(T0 + DAY * 2), None).await.expect("w")[&a].is_empty());
    assert_eq!(registry::device_windows(db, &[a], Some(T0 + DAY + HOUR * 12), None).await.expect("w")[&a].len(), 1);
    assert!(registry::device_windows(db, &[b], None, Some(T0 + DAY)).await.expect("w")[&b].is_empty());
    assert!(registry::device_windows(db, &[], None, None).await.expect("w").is_empty());
}

#[tokio::test]
async fn test_overlapping_owners_conflict() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    let mac = "aa:bb:cc:dd:ee:52";
    let (a, _) = case.device(None, None, false).await;
    let (b, _) = case.device(None, None, false).await;
    case.window(a, mac, T0, T0 + DAY * 4).await;
    case.window(b, mac, T0 + DAY, T0 + DAY * 2).await;
    let db = &mut case.db;
    let conflicts = registry::window_conflicts(db, &[a, b], None, None).await.expect("conflicts");
    let c = &conflicts[&a];
    assert_eq!(c.len(), 1);
    assert_eq!(
        (c[0].mac.as_str(), c[0].other_owners, c[0].from, c[0].to),
        (mac, 1, T0 + DAY, T0 + DAY * 2 + registry::CURRENT_WINDOW)
    );
    assert_eq!(conflicts[&b][0].other_owners, 1);
    assert_eq!(registry::device_for_mac(db, mac, T0 + DAY + HOUR).await.expect("mac"), None);
    assert_eq!(registry::device_for_mac(db, mac, T0 + DAY * 3).await.expect("mac"), Some(a));
    let clipped =
        registry::window_conflicts(db, &[a], Some(T0 + DAY + HOUR), Some(T0 + DAY + HOUR * 2)).await.expect("c");
    assert_eq!((clipped[&a][0].from, clipped[&a][0].to), (T0 + DAY + HOUR, T0 + DAY + HOUR * 2));
    assert!(registry::window_conflicts(db, &[a], Some(T0 + DAY * 3), None).await.expect("c").is_empty());
}

#[tokio::test]
async fn test_current_window() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    let now = OffsetDateTime::now_utc();
    let (a, _) = case.device(None, None, false).await;
    let (old, new, mac) = ("aa:bb:cc:dd:ee:55", "aa:bb:cc:dd:ee:56", "aa:bb:cc:dd:ee:57");
    case.window(a, old, T0, T0 + HOUR).await; // replaced by the newer MAC
    case.window(a, new, now - HOUR * 2, now - HOUR).await; // current, last login an hour ago
    let windows = registry::device_windows(&mut case.db, &[a], None, None).await.expect("windows");
    let w = |m: &str| windows[&a].iter().find(|w| w.mac == m).cloned().expect("window");
    assert_eq!((w(old).current, w(old).window_end), (false, T0 + HOUR + registry::WINDOW_GRACE));
    assert!(w(new).current);
    assert!((w(new).window_end - now).abs() < Duration::seconds(60)); // open up to now
    assert_eq!(registry::device_for_mac(&mut case.db, old, T0 + HOUR * 2).await.expect("mac"), None);
    assert_eq!(registry::device_for_mac(&mut case.db, new, now - Duration::minutes(5)).await.expect("mac"), Some(a));
    let (gone, _) = case.device(None, None, true).await;
    case.window(gone, "aa:bb:cc:dd:ee:58", T0, T0 + HOUR).await;
    let gw = registry::device_windows(&mut case.db, &[gone], None, None).await.expect("windows");
    assert_eq!(gw[&gone][0].window_end, T0 + HOUR + registry::WINDOW_GRACE);
    // someone else logs in with the MAC an hour after b's login, while b's window is current
    let (b, _) = case.device(None, None, false).await;
    let (c, _) = case.device(None, None, false).await;
    case.window(b, mac, T0, T0).await;
    case.window(c, mac, T0 + HOUR, T0 + HOUR).await;
    let conflicts = registry::window_conflicts(&mut case.db, &[b, c], None, None).await.expect("conflicts");
    assert_eq!(conflicts[&b][0].from, T0 + HOUR);
    assert_eq!(conflicts[&b][0].to, T0 + registry::CURRENT_WINDOW);
    let db = &mut case.db;
    assert_eq!(registry::device_for_mac(db, mac, T0 + HOUR * 2).await.expect("mac"), None);
    assert_eq!(registry::device_for_mac(db, mac, T0 + Duration::minutes(30)).await.expect("mac"), Some(b));
    assert_eq!(registry::device_for_mac(db, mac, T0 + HOUR * 13).await.expect("mac"), Some(c));
}

#[tokio::test]
async fn test_same_owner_is_no_conflict_a_revoked_device_still_is() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    let owner = case.person(None).await;
    let (a, _) = case.device(Some(&owner), None, false).await;
    let (a2, _) = case.device(Some(&owner), None, false).await;
    let mac = "aa:bb:cc:dd:ee:53";
    case.window(a, mac, T0, T0 + DAY * 2).await;
    case.window(a2, mac, T0 + DAY, T0 + DAY * 3).await; // re-enrolled: the newer one
    assert!(!registry::window_conflicts(&mut case.db, &[a], None, None).await.expect("c").contains_key(&a));
    assert_eq!(registry::device_for_mac(&mut case.db, mac, T0 + DAY * 2 + HOUR).await.expect("mac"), Some(a2));
    assert_eq!(registry::device_for_mac(&mut case.db, mac, T0 + HOUR * 36).await.expect("mac"), Some(a2));
    // someone else's device had it at the same time and was revoked since: that time stays
    // nobody's (np_device_for_mac) and withheld (window_conflicts), the same rule
    let (gone, _) = case.device(None, None, true).await;
    case.window(gone, mac, T0, T0 + DAY).await;
    let db = &mut case.db;
    assert_eq!(registry::device_for_mac(db, mac, T0 + HOUR).await.expect("mac"), None);
    let conflicts = registry::window_conflicts(db, &[a, a2], None, None).await.expect("c");
    let c = &conflicts[&a];
    assert_eq!((c.len(), c[0].other_owners, c[0].from, c[0].to), (1, 1, T0, T0 + DAY + registry::WINDOW_GRACE));
    assert_eq!(conflicts[&a2][0].from, T0 + DAY);
    assert!(registry::window_conflicts(db, &[a], Some(T0 + DAY * 2), None).await.expect("c").is_empty());
}

// --- the read and write interface -----------------------------------------------------------------

#[tokio::test]
async fn test_auth_events_and_failures() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    let owner = case.person(None).await;
    let (dev, serial) = case.device(Some(&owner), None, false).await;
    case.login(dev, &serial, "AA-BB-CC-DD-EE-61", "10.0.0.2").await;
    case.exec("SELECT radius.reject('', 'AA-BB-CC-DD-EE-61', '', '10.0.0.2', 'no_cert')").await;
    case.exec("SELECT radius.reject('', 'AA-BB-CC-DD-EE-62', '', '10.0.0.2', 'no_cert')").await; // not its MAC
    case.exec(&format!("UPDATE device SET revoked_at = now() WHERE id = '{dev}'")).await;
    case.exec(&format!("SELECT radius.reject('{serial}', 'AA-BB-CC-DD-EE-61', 'AA-BB-CC-00-00-01:S', '10.0.0.2', '')"))
        .await;
    let now = OffsetDateTime::now_utc();
    let db = &mut case.db;
    let events = registry::auth_events(db, dev, now - HOUR, now + HOUR, 1000).await.expect("events");
    let got: Vec<_> = events.iter().map(|e| (e.result.as_str(), e.reason.as_str(), e.matched.as_str())).collect();
    assert_eq!(got, [("accept", "ok", "device"), ("reject", "no_cert", "mac"), ("reject", "revoked", "device")]);
    assert!(events.iter().all(|e| e.tries == 1 && e.last_at.is_none()));
    assert_eq!((events[0].mac.as_deref(), events[0].nas_ip.as_deref()), (Some("aa:bb:cc:dd:ee:61"), Some("10.0.0.2")));
    assert_eq!(registry::auth_events(db, dev, now - HOUR, now + HOUR, 1).await.expect("events").len(), 1);
    assert!(registry::auth_events(db, dev, now + HOUR, now + HOUR * 2, 1000).await.expect("events").is_empty());
    let failures = registry::auth_failures(db, now - HOUR, None, 500).await.expect("failures");
    assert_eq!(failures[0].reason, "revoked");
    assert_eq!(
        (failures[0].device_id, failures[0].owner.as_deref(), failures[0].owner_name.as_deref()),
        (Some(dev), Some(owner.as_str()), Some(format!("{owner} Name").as_str()))
    );
    let reasons: std::collections::BTreeSet<_> = failures.iter().map(|f| f.reason.as_str()).collect();
    assert_eq!(reasons, ["no_cert", "revoked"].into());
    assert_eq!(registry::auth_failures(db, now - HOUR, None, 1).await.expect("failures").len(), 1);
    // repeats: one row with their count, in both lists
    case.commit().await;
    let mut r = case.radius().await;
    for _ in 0..4 {
        r.execute("SELECT radius.reject('', 'AA-BB-CC-DD-EE-61', '', '10.0.0.3', 'no_cert')").await.expect("reject");
    }
    let now = OffsetDateTime::now_utc();
    let db = &mut case.db;
    let repeated: Vec<_> = registry::auth_events(db, dev, now - HOUR, now + HOUR, 1000)
        .await
        .expect("events")
        .into_iter()
        .filter(|e| e.nas_ip.as_deref() == Some("10.0.0.3"))
        .collect();
    assert_eq!(repeated.iter().map(|e| (e.tries, e.matched.as_str())).collect::<Vec<_>>(), [(4, "mac")]);
    assert!(repeated[0].last_at.is_some_and(|l| l > repeated[0].at));
    let tries: Vec<i32> = registry::auth_failures(db, now - HOUR, None, 500)
        .await
        .expect("failures")
        .into_iter()
        .filter(|f| f.nas_ip.as_deref() == Some("10.0.0.3"))
        .map(|f| f.tries)
        .collect();
    assert_eq!(tries, [4]);
}

#[tokio::test]
async fn test_acct_sessions() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    let (dev, serial) = case.device(None, None, false).await;
    let token = case.login(dev, &serial, "AA-BB-CC-DD-EE-01", "10.0.0.2").await.unwrap_or_default();
    let t = now_s();
    let (a, b, c) = ((t - 1000).to_string(), (t - 500).to_string(), (t - 100).to_string());
    case.accounting(Acct { class: &token, event_ts: &a, ..acct("Start", "Q1") }).await;
    case.accounting(Acct { class: &token, event_ts: &b, time: "500", cause: "User-Request", ..acct("Stop", "Q1") })
        .await;
    case.accounting(Acct { class: &token, event_ts: &c, framed: "10.30.0.9", ..acct("Start", "Q2") }).await;
    let now = ts(t);
    let rows = registry::acct_sessions(&mut case.db, dev, now - HOUR, now, 1000).await.expect("sessions");
    assert_eq!(rows.iter().map(|r| r.acct_session_id.as_str()).collect::<Vec<_>>(), ["Q1", "Q2"]);
    assert_eq!(
        (rows[0].terminate_cause.as_deref(), rows[1].framed_ip.as_deref(), rows[1].nas_ip.as_str()),
        (Some("User-Request"), Some("10.30.0.9"), "10.0.0.2")
    );
    let recent = registry::acct_sessions(&mut case.db, dev, now - Duration::seconds(300), now, 1000).await.expect("s");
    assert_eq!(recent.iter().map(|r| r.acct_session_id.as_str()).collect::<Vec<_>>(), ["Q2"]);
}

#[tokio::test]
async fn test_latest_sessions_and_events_for_a_page() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    let (dev, serial) = case.device(None, None, false).await;
    let (dev2, serial2) = case.device(None, None, false).await;
    let token = case.login(dev, &serial, "AA-BB-CC-DD-EE-01", "10.0.0.2").await.unwrap_or_default();
    let token2 = case.login(dev2, &serial2, "AA-BB-CC-DD-EE-02", "10.0.0.2").await.unwrap_or_default();
    let t = now_s() - 3000;
    for i in 0..7 {
        let (sid, at) = (format!("L{i}"), (t + i * 100).to_string());
        case.accounting(Acct { class: &token, nas: "10.0.0.50", event_ts: &at, ..acct("Start", &sid) }).await;
    }
    let at = (t + 720).to_string();
    case.accounting(Acct { class: &token, nas: "10.0.0.50", event_ts: &at, ..acct("Interim-Update", "L6") }).await;
    let at = t.to_string();
    case.accounting(Acct {
        class: &token2,
        nas: "10.0.0.51",
        mac: "AA-BB-CC-DD-EE-02",
        event_ts: &at,
        ..acct("Start", "K1")
    })
    .await;
    case.commit().await;
    let unknown = Uuid::new_v4();
    let found = registry::latest_sessions(&mut case.db, &[dev, dev2, unknown], 5).await.expect("sessions");
    assert_eq!(found.len(), 3);
    let ids: Vec<_> = found[&dev].iter().map(|s| s.acct_session_id.as_str()).collect();
    assert_eq!(ids, ["L6", "L5", "L4", "L3", "L2"]);
    assert_eq!(
        (found[&dev][0].interim_s, found[&dev][0].nas_interim_s, found[&dev][1].nas_interim_s),
        (Some(120), Some(120), Some(120))
    );
    assert_eq!(found[&dev2].iter().map(|s| s.acct_session_id.as_str()).collect::<Vec<_>>(), ["K1"]);
    assert_eq!(found[&dev2][0].nas_interim_s, None);
    assert!(registry::latest_sessions(&mut case.db, &[], 5).await.expect("sessions").is_empty());
    let mac = "aa:bb:cc:dd:ee:72";
    case.window(dev, mac, T0, T0 + DAY).await;
    let rows: Vec<NewConnectionEvent> = [
        ("connected", Some("Scharni")),
        ("other", Some("Scharni")),
        ("disconnected", Some("Scharni")),
        ("connected", Some("Guests")),
        ("roamed", None),
    ]
    .iter()
    .enumerate()
    .map(|(i, (kind, ssid))| NewConnectionEvent {
        at: Some(T0 + HOUR * i as i32),
        kind: kind.to_string(),
        mac: mac.into(),
        ssid: ssid.map(str::to_string),
        dedup_key: format!("p{i}"),
        ..Default::default()
    })
    .collect();
    registry::insert_connection_events(&mut case.db, &rows).await.expect("insert");
    let db = &mut case.db;
    let events = registry::latest_connection_events(db, &[dev, dev2], 3, Some("Scharni")).await.expect("events");
    assert_eq!(
        events[&dev].iter().map(|e| e.kind.as_str()).collect::<Vec<_>>(),
        ["roamed", "disconnected", "connected"]
    );
    assert!(events[&dev2].is_empty());
    assert_eq!(registry::latest_connection_events(db, &[dev], 3, None).await.expect("e")[&dev].len(), 3);
    assert_eq!(registry::latest_connection_events(db, &[dev], 1, None).await.expect("e")[&dev][0].kind, "roamed");
    let conn = db.tx().await.expect("tx");
    conn.execute("SET LOCAL enable_seqscan = off").await.expect("set"); // a tiny table: show the index serves it
    let plan: Vec<String> =
        sqlx::query_scalar("EXPLAIN SELECT * FROM radius_acct WHERE device_id = $1 ORDER BY updated DESC LIMIT 5")
            .bind(dev)
            .fetch_all(&mut *conn)
            .await
            .expect("explain");
    assert!(plan.join("\n").contains("radius_acct_device"), "{plan:?}");
}

#[tokio::test]
async fn test_connection_events() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    let (dev, _) = case.device(None, None, false).await;
    let mac = "aa:bb:cc:dd:ee:71";
    case.window(dev, mac, T0, T0 + HOUR).await;
    let rows = vec![
        NewConnectionEvent {
            at: Some(T0 + Duration::minutes(30)),
            kind: "connected".into(),
            source: "unifi_syslog".into(),
            mac: "AA-BB-CC-DD-EE-71".into(),
            ap_mac: Some("AA:BB:CC:00:00:01".into()),
            ap_name: Some("AP Flur".into()),
            ssid: Some("Scharni".into()),
            radio: Some("na".into()),
            channel: Some(36),
            rssi: Some(-60),
            dedup_key: "k1".into(),
            detail: Some(json!({"raw": 1})),
            ..Default::default()
        },
        NewConnectionEvent {
            // outside the window: nobody's
            at: Some(T0 + HOUR * 14),
            kind: "roamed".into(),
            mac: mac.into(),
            from_ap_mac: Some("aa:bb:cc:00:00:01".into()),
            ap_mac: Some("aa:bb:cc:00:00:02".into()),
            dedup_key: "k2".into(),
            ..Default::default()
        },
        NewConnectionEvent {
            at: Some(T0 + HOUR + Duration::minutes(10)),
            kind: "weird".into(),
            mac: mac.into(),
            dedup_key: "k3".into(),
            ..Default::default()
        },
        NewConnectionEvent {
            at: Some(T0),
            kind: "connected".into(),
            mac: "junk".into(),
            dedup_key: "k4".into(),
            ..Default::default()
        },
        NewConnectionEvent { at: Some(T0), kind: "connected".into(), mac: mac.into(), ..Default::default() }, // no dedup key
        NewConnectionEvent {
            at: None,
            kind: "connected".into(),
            mac: mac.into(),
            dedup_key: "k6".into(),
            ..Default::default()
        },
    ];
    let db = &mut case.db;
    assert_eq!(registry::insert_connection_events(db, &rows).await.expect("insert"), 3);
    assert_eq!(registry::insert_connection_events(db, &rows).await.expect("insert"), 0); // idempotent
    let events = registry::connection_events(db, dev, T0, T0 + DAY, 2000).await.expect("events");
    let got: Vec<_> = events.iter().map(|e| (e.kind.as_str(), e.ap_mac.as_deref())).collect();
    assert_eq!(got, [("connected", Some("aa:bb:cc:00:00:01")), ("other", None)]);
    assert_eq!(
        (&events[0].detail.0, events[0].channel, events[0].source.as_str()),
        (&json!({"raw": 1}), Some(36), "unifi_syslog")
    );
    // the resolved events extended the window (the "other" one at +70 min)
    let last_seen: OffsetDateTime = sqlx::query_scalar("SELECT last_seen FROM device_mac WHERE device_id = $1")
        .bind(dev)
        .fetch_one(db.tx().await.expect("tx"))
        .await
        .expect("last_seen");
    assert_eq!(last_seen, T0 + HOUR + Duration::minutes(10));
    let k2: Option<Uuid> = sqlx::query_scalar("SELECT device_id FROM connection_event WHERE dedup_key = 'k2'")
        .fetch_one(db.tx().await.expect("tx"))
        .await
        .expect("k2");
    assert_eq!(k2, None);
    assert_eq!(registry::connection_events(db, dev, T0, T0 + DAY, 1).await.expect("events").len(), 1);
}

#[tokio::test]
async fn test_rollups() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    let (dev, _) = case.device(None, None, false).await;
    let day = time::macros::date!(2026 - 10 - 24);
    let row = registry::DeviceDay {
        device_id: dev,
        day,
        online_s: Some(100),
        stale_s: None,
        signal_avg_dbm: Some(-60.3),
        signal_p10_dbm: None,
        snr_avg_db: None,
        health_avg: None,
        health_min: None,
        retry_ratio_avg: None,
        rx_bytes: None,
        tx_bytes: None,
        link_rx_avg_bps: None,
        roams: None,
        reconnects: None,
        disconnects: None,
        aps: sqlx::types::Json(json!({"aa:bb": 100})),
        bands: sqlx::types::Json(json!({})),
        macs: None,
        auth_ok: None,
        auth_failed: None,
        computed_at: None,
    };
    let db = &mut case.db;
    registry::upsert_device_day(db, &row).await.expect("upsert");
    let second = registry::DeviceDay { online_s: Some(200), roams: Some(2), ..row.clone() };
    registry::upsert_device_day(db, &second).await.expect("upsert");
    let rows = registry::device_days(db, dev, day, day).await.expect("days");
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (rows[0].online_s, rows[0].roams, &rows[0].aps.0, rows[0].signal_avg_dbm),
        (Some(200), Some(2), &json!({"aa:bb": 100}), Some(-60.3)) // double precision: -60.3 exactly
    );
    assert!(rows[0].computed_at.is_some());
    let ap = registry::ApDay {
        ap_mac: "AA-BB-CC-00-00-01".into(),
        day,
        ap_name: Some("AP Flur".into()),
        clients_avg: None,
        clients_max: Some(7),
        channel_util_avg: sqlx::types::Json(json!({"ng": 0.4})),
        weak_client_share: None,
        restarts: None,
        down_s: None,
        computed_at: None,
    };
    registry::upsert_ap_day(db, &ap).await.expect("ap");
    let next = registry::ApDay { ap_mac: "aa:bb:cc:00:00:02".into(), day: day.next_day().expect("day"), ..ap.clone() };
    registry::upsert_ap_day(db, &next).await.expect("ap");
    let all = registry::ap_days(db, day, day.next_day().expect("day"), None).await.expect("days");
    assert_eq!(all.iter().map(|r| r.ap_mac.as_str()).collect::<Vec<_>>(), ["aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"]);
    let only = registry::ap_days(db, day, day + Duration::days(5), Some(&["AA:BB:CC:00:00:01"])).await.expect("days");
    let got: Vec<_> = only.iter().map(|r| (r.ap_mac.as_str(), r.clients_max, &r.channel_util_avg.0)).collect();
    assert_eq!(got, [("aa:bb:cc:00:00:01", Some(7), &json!({"ng": 0.4}))]);
    let bad = registry::ApDay { ap_mac: "junk".into(), ..ap };
    assert!(matches!(registry::upsert_ap_day(db, &bad).await, Err(registry::RegistryError::Invalid(_))));
}

#[tokio::test]
async fn test_incidents() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    let db = &mut case.db;
    let ap = "aa:bb:cc:00:00:01";
    let first = registry::open_incident(db, "ap_down", ap, Some("AP Flur"), T0, "measured", Some(&json!({"why": 1})))
        .await
        .expect("open");
    let again =
        registry::open_incident(db, "ap_down", ap, Some("AP Flur"), T0 + HOUR, "measured", None).await.expect("open");
    assert_eq!(first, again); // no second open incident
    let other = registry::open_incident(db, "internet_down", "", None, T0, "measured", None).await.expect("open");
    assert_ne!(other, first);
    assert_eq!(registry::close_incident(db, "ap_down", ap, T0 + HOUR * 2).await.expect("close"), 1);
    assert_eq!(registry::close_incident(db, "ap_down", ap, T0 + HOUR * 3).await.expect("close"), 0);
    // the same start again (a re-evaluation of the same window): the same incident, still closed
    assert_eq!(
        registry::open_incident(db, "ap_down", ap, Some("AP Flur"), T0, "measured", None).await.expect("open"),
        first
    );
    let later = registry::open_incident(db, "ap_down", ap, Some("AP Flur"), T0 + HOUR * 5, "inferred", None)
        .await
        .expect("open");
    assert_ne!(later, first);
    let rows = registry::incidents(db, T0, Some(T0 + DAY), None, None).await.expect("incidents");
    let aps: Vec<_> = rows.iter().filter(|r| r.kind == "ap_down").map(|r| (r.id, r.ended)).collect();
    assert_eq!(aps, [(first, Some(T0 + HOUR * 2)), (later, None)]);
    assert_eq!(rows[0].detail.0, json!({"why": 1}));
    let ids = |rows: Vec<registry::Incident>| rows.into_iter().map(|r| r.id).collect::<Vec<_>>();
    assert_eq!(ids(registry::incidents(db, T0 + HOUR * 3, Some(T0 + HOUR * 4), None, None).await.expect("i")), [other]);
    assert_eq!(ids(registry::incidents(db, T0, None, Some(&["internet_down"]), None).await.expect("i")), [other]);
    assert_eq!(ids(registry::incidents(db, T0, None, None, Some(&[ap])).await.expect("i")), [first, later]);
    assert!(ids(registry::incidents(db, T0, None, Some(&[]), None).await.expect("i")).is_empty()); // an empty list: none
    // a closing time before the start ends it at the start
    registry::close_incident(db, "ap_down", ap, T0).await.expect("close");
    let rows = registry::incidents(db, T0, None, None, Some(&[ap])).await.expect("i");
    assert_eq!(rows.last().and_then(|r| r.ended), Some(T0 + HOUR * 5));
}

#[tokio::test]
async fn test_jobs() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    let db = &mut case.db;
    let status = |rows: Vec<registry::JobStatus>, name: &str| rows.into_iter().find(|j| j.name == name).expect("job");
    registry::job_begin(db, "rollup").await.expect("begin");
    let s = status(registry::job_status(db).await.expect("status"), "rollup");
    assert!(s.last_success.is_none() && s.last_attempt.is_some());
    assert!(registry::job_status(db).await.expect("status").iter().any(|j| j.name == "offboarding"));
    registry::job_end(db, "rollup", false, Some("boom"), Some(1.5), None).await.expect("end");
    let s = status(registry::job_status(db).await.expect("status"), "rollup");
    assert_eq!((s.last_error.as_deref(), s.duration_s, s.last_success), (Some("boom"), Some(1.5), None));
    registry::job_end(db, "rollup", true, None, Some(2.0), Some(&json!({"day": "2026-10-24"}))).await.expect("end");
    let s = status(registry::job_status(db).await.expect("status"), "rollup");
    assert_eq!((s.last_error, s.cursor.0), (None, json!({"day": "2026-10-24"})));
    assert!(s.last_success.is_some());
    registry::job_end(db, "rollup", true, None, None, None).await.expect("end");
    assert_eq!(
        status(registry::job_status(db).await.expect("status"), "rollup").cursor.0,
        json!({"day": "2026-10-24"})
    );
    let long = "x".repeat(3000);
    registry::job_end(db, "rollup", false, Some(&long), None, None).await.expect("end");
    assert_eq!(
        status(registry::job_status(db).await.expect("status"), "rollup").last_error.map(|e| e.len()),
        Some(2000)
    );
    registry::job_end(db, "unifi_events", false, None, None, None).await.expect("end"); // a new job, failed
    assert_eq!(
        status(registry::job_status(db).await.expect("status"), "unifi_events").last_error.as_deref(),
        Some("failed")
    );
    registry::mark_job(db, "offboarding").await.expect("mark");
}

#[tokio::test]
async fn test_prune() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    let (dev, _) = case.device(None, None, false).await;
    let (revoked, _) = case.device(None, None, true).await;
    let now = OffsetDateTime::now_utc();
    let old = now - DAY * 401;
    let conn = case.db.tx().await.expect("tx");
    sqlx::query("INSERT INTO radius_auth (at, result, reason) VALUES ($1, 'reject', 'other'), ($2, 'reject', 'other')")
        .bind(old)
        .bind(now)
        .execute(&mut *conn)
        .await
        .expect("auth");
    sqlx::query("INSERT INTO radius_acct (nas_ip, acct_session_id, link, updated) VALUES ('10.0.0.2', 'old', 'none', $1), ('10.0.0.2', 'new', 'none', $2)")
        .bind(old)
        .bind(now)
        .execute(&mut *conn)
        .await
        .expect("acct");
    sqlx::query("INSERT INTO audit (at, actor, action) VALUES ($1, 'x', 'y')")
        .bind(now - DAY * 91)
        .execute(&mut *conn)
        .await
        .expect("audit");
    let event = NewConnectionEvent {
        at: Some(old),
        kind: "connected".into(),
        mac: "aa:bb:cc:dd:ee:81".into(),
        dedup_key: "p1".into(),
        ..Default::default()
    };
    registry::insert_connection_events(&mut case.db, &[event]).await.expect("events");
    case.commit().await;
    case.window(dev, "aa:bb:cc:dd:ee:82", old - DAY, old).await;
    case.window(revoked, "aa:bb:cc:dd:ee:83", old - DAY, old).await;
    case.window(revoked, "aa:bb:cc:dd:ee:84", now - DAY, now).await;
    let day = registry::DeviceDay {
        device_id: dev,
        day: old.date(),
        online_s: Some(1),
        stale_s: None,
        signal_avg_dbm: None,
        signal_p10_dbm: None,
        snr_avg_db: None,
        health_avg: None,
        health_min: None,
        retry_ratio_avg: None,
        rx_bytes: None,
        tx_bytes: None,
        link_rx_avg_bps: None,
        roams: None,
        reconnects: None,
        disconnects: None,
        aps: sqlx::types::Json(json!({})),
        bands: sqlx::types::Json(json!({})),
        macs: None,
        auth_ok: None,
        auth_failed: None,
        computed_at: None,
    };
    registry::upsert_device_day(&mut case.db, &day).await.expect("day");
    registry::open_incident(&mut case.db, "router_down", "", None, old, "measured", None).await.expect("incident");
    let deleted = registry::prune(&mut case.db, Some(now), registry::AUDIT_DAYS, registry::PRUNE_BATCH, false)
        .await
        .expect("prune");
    let got: Vec<_> = deleted.iter().map(|(k, v)| (*k, *v)).collect();
    assert_eq!(
        got,
        [
            ("radius_auth", 1),
            ("radius_acct", 1),
            ("connection_event", 1),
            ("device_mac", 1),
            ("audit", 1),
            ("download", 0),
            ("oauth_token", 0)
        ]
    );
    let left = case.i64(&format!("SELECT count(*) FROM device_mac WHERE device_id IN ('{dev}', '{revoked}')")).await;
    assert_eq!(left, Some(2)); // the active device's old row is kept
    assert_eq!(case.i64("SELECT count(*) FROM device_day").await, Some(1));
    assert_eq!(case.i64("SELECT count(*) FROM incident").await, Some(1));
}

#[tokio::test]
async fn test_prune_in_batches() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    let old = OffsetDateTime::now_utc() - DAY * 401;
    sqlx::query("INSERT INTO radius_auth (at, result, reason) SELECT $1, 'reject', 'other' FROM generate_series(1, 7)")
        .bind(old)
        .execute(case.db.tx().await.expect("tx"))
        .await
        .expect("rows");
    case.exec("INSERT INTO radius_auth (result, reason) VALUES ('reject', 'other')").await;
    case.commit().await;
    let commits = case.db.commits();
    let deleted = registry::prune(&mut case.db, None, registry::AUDIT_DAYS, 3, true).await.expect("prune");
    assert_eq!(deleted["radius_auth"], 7);
    assert_eq!(case.i64("SELECT count(*) FROM radius_auth").await, Some(1));
    // 3 + 3 + 1 for radius_auth, at least one for each of the 6 other tables
    assert!(case.db.commits() - commits >= 3 + 6, "{}", case.db.commits() - commits);
}

#[tokio::test]
async fn test_stats() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    let (_, _) = case.device(None, None, false).await;
    let (_, _) = case.device(None, None, true).await;
    let (_, _) = case.device(None, Some(OffsetDateTime::now_utc() + DAY * 10), false).await;
    let (_, _) = case.device(None, Some(OffsetDateTime::now_utc() - HOUR), false).await;
    let (d, _) = case.device(None, None, false).await;
    registry::audit(&mut case.db, "x", "disconnect:ack", Some(d)).await.expect("audit");
    registry::audit(&mut case.db, "x", "disconnect:timeout", Some(d)).await.expect("audit");
    registry::audit(&mut case.db, "x", "disconnect:timeout", Some(d)).await.expect("audit");
    let s = registry::stats(&mut case.db).await.expect("stats");
    assert_eq!((s.radius_role, s.schema_version), (true, Some(4)));
    assert_eq!((s.active, s.revoked, s.valid_certificates, s.expiring_30d, s.expired), (4, 1, 3, 3, 1));
    assert!(s.offboarding_last_success.is_some());
    assert_eq!(
        s.disconnects_1h,
        [("ack", 1), ("no-session", 0), ("skipped", 0), ("timeout", 2), ("nak", 0), ("error", 0)]
    );
}

// --- the portal's registry functions (mocked in the Python tests) ----------------------------------

#[tokio::test]
async fn test_people_admin_and_policy() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    let db = &mut case.db;
    registry::upsert_person(db, "a", "alice", "Alice", true).await.expect("person");
    assert_eq!(registry::person_state(db, "a").await.expect("state").map(|s| s.is_admin), Some(true));
    // losing the admin right ends the person's portal sessions (security review L2), once
    assert!(registry::set_admin(db, "a", false).await.expect("admin"));
    let state = registry::person_state(db, "a").await.expect("state");
    assert_eq!(state.map(|s| (s.is_admin, s.session_epoch)), Some((false, 1)));
    assert!(!registry::set_admin(db, "a", false).await.expect("admin"));
    assert!(!registry::set_admin(db, "a", true).await.expect("admin")); // gaining it ends nothing
    assert_eq!(registry::person_state(db, "a").await.expect("state").map(|s| s.session_epoch), Some(1));
    registry::set_admin(db, "a", false).await.expect("admin");
    db.tx().await.expect("tx").execute("UPDATE person SET session_epoch = 0 WHERE sub = 'a'").await.expect("reset");
    assert_eq!(registry::person_policy(db, "a").await.expect("policy"), None);
    assert_eq!(registry::person_policy(db, "nobody").await.expect("policy"), None);
    let d1 = registry::create_device(db, "a", "phone", "apple", "residents").await.expect("device");
    let d2 = registry::create_device(db, "a", "laptop", "apple-mac", "guests").await.expect("device");
    db.tx().await.expect("tx")
        .execute(sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "INSERT INTO radius_session (device_id, nas_ip, calling_station, user_name) VALUES ('{d1}', '10.0.0.2', 'AA-BB-CC-DD-EE-01', 'anonymous@x')"
        ))))
        .await
        .expect("session");
    let mut moved = registry::set_policy(db, "a", "guests").await.expect("policy");
    moved.sort_by_key(|m| m.0);
    assert_eq!(moved.len(), 1);
    assert_eq!(moved[0].0, d1);
    assert_eq!(
        moved[0].1.iter().map(|s| (s.nas_ip.as_str(), s.calling_station.as_str())).collect::<Vec<_>>(),
        [("10.0.0.2", "AA-BB-CC-DD-EE-01")]
    );
    assert_eq!(registry::person_policy(db, "a").await.expect("policy").as_deref(), Some("guests"));
    assert!(registry::set_policy(db, "a", "guests").await.expect("policy").is_empty());
    let people = registry::people(db).await.expect("people");
    assert_eq!(people["a"].display_name, "Alice");
    // offboarding: no session, no grants; the next login undoes it
    let grant = registry::create_grant(db, "a", "app.geteduroam.sh", "Laptop").await.expect("grant");
    registry::upsert_person(db, "b", "bob", "Bob", false).await.expect("person");
    let subjects = registry::subjects_to_check(db).await.expect("subjects");
    assert_eq!(subjects, ["a".to_string(), "b".to_string()].into());
    registry::offboard_person(db, "a").await.expect("offboard");
    assert_eq!(registry::person_state(db, "a").await.expect("state"), None);
    let revoked =
        case.i64(&format!("SELECT count(*) FROM oauth_grant WHERE id = '{grant}' AND revoked_at IS NOT NULL")).await;
    assert_eq!(revoked, Some(1));
    // still checked: the owner of active devices
    assert!(registry::subjects_to_check(&mut case.db).await.expect("subjects").contains("a"));
    registry::upsert_person(&mut case.db, "a", "alice", "Alice", false).await.expect("login");
    let state = registry::person_state(&mut case.db, "a").await.expect("state");
    // the sessions from before the offboarding stay ended after the new login; a logout ends the new ones
    assert_eq!(state.map(|s| s.session_epoch), Some(1));
    registry::end_sessions(&mut case.db, "a").await.expect("logout");
    assert_eq!(registry::person_state(&mut case.db, "a").await.expect("state").map(|s| s.session_epoch), Some(2));
    let _ = d2;
}

#[tokio::test]
async fn test_devices_credentials_and_revoke() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    let owner = case.person(None).await;
    let other = case.person(None).await;
    case.commit().await;
    let db = &mut case.db;
    let d = registry::create_device(db, &owner, "phone", "android", "residents").await.expect("device");
    let not_after = OffsetDateTime::now_utc() + DAY * 365;
    registry::add_credential(db, d, "0A1B", not_after, 2, None).await.expect("credential");
    let row = registry::device(db, d, Some(&owner)).await.expect("device").expect("found");
    assert_eq!((row.certificates, row.expires.map(|e| e.unix_timestamp())), (1, Some(not_after.unix_timestamp())));
    assert_eq!(registry::device(db, d, Some(&other)).await.expect("device"), None); // someone else's
    // a renewal: the old certificate is retired after the overlap (2 x 24 h)
    let later = not_after + DAY;
    registry::add_credential(db, d, "0c0d", later, 2, None).await.expect("credential");
    let retired: Vec<(String, Option<OffsetDateTime>)> =
        sqlx::query_as("SELECT serial, retired_at FROM credential WHERE device_id = $1 ORDER BY serial")
            .bind(d)
            .fetch_all(db.tx().await.expect("tx"))
            .await
            .expect("credentials");
    assert_eq!(retired[0].0, "0a1b"); // lower-cased
    let overlap: Duration = retired[0].1.map(|r| r - OffsetDateTime::now_utc()).unwrap_or_default();
    assert!((overlap - Duration::days(2)).abs() < Duration::minutes(1), "{overlap}");
    assert_eq!(retired[1], ("0c0d".into(), None));
    assert_eq!(
        registry::device(db, d, None)
            .await
            .expect("d")
            .map(|r| (r.certificates, r.expires.map(|e| e.unix_timestamp()))),
        Some((2, Some(later.unix_timestamp())))
    );
    // a re-issue within the window retires the ones issued within it at once, the older one
    // keeps its overlap (security review M2): at most one older certificate stays valid
    registry::add_credential(db, d, "0e0f", later, 2, Some(Duration::hours(1))).await.expect("credential");
    let valid: Vec<String> =
        sqlx::query_scalar("SELECT serial FROM credential WHERE device_id = $1 AND (retired_at IS NULL OR retired_at > now() + interval '1 second') ORDER BY serial")
            .bind(d)
            .fetch_all(db.tx().await.expect("tx"))
            .await
            .expect("credentials");
    assert_eq!(valid, ["0a1b", "0e0f"]); // 0c0d (issued just now) retired at once, 0a1b keeps its overlap
    // an odd serial is refused by the schema (FreeRADIUS compares even-length hex)
    assert!(registry::add_credential(db, d, "abc", later, 2, None).await.is_err());
    db.rollback().await.expect("rollback");
    let d = registry::create_device(db, &owner, "phone", "android", "residents").await.expect("device");
    registry::rename(db, d, "new name").await.expect("rename");
    let list = registry::devices(db, Some(&owner), false).await.expect("devices");
    assert_eq!(list.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(), ["new name"]);
    assert!(registry::revoke(db, d, &owner, "revoke").await.expect("revoke").is_empty()); // no session
    registry::rename(db, d, "after").await.expect("rename"); // a revoked device keeps its name
    assert!(registry::devices(db, Some(&owner), false).await.expect("devices").is_empty());
    let all = registry::devices(db, Some(&owner), true).await.expect("devices");
    assert_eq!((all.len(), all[0].name.as_str(), all[0].revoked_at.is_some()), (1, "new name", true));
    assert_eq!(registry::devices(db, None, true).await.expect("devices").len(), 1);
    let audit: Vec<(String, String)> = sqlx::query_as("SELECT actor, action FROM audit WHERE device_id = $1")
        .bind(d)
        .fetch_all(db.tx().await.expect("tx"))
        .await
        .expect("audit");
    assert_eq!(audit, [(owner.clone(), "revoke".to_string())]);
    // invalid names are refused by the schema
    assert!(registry::create_device(db, &owner, " ", "apple", "residents").await.is_err());
}

#[tokio::test]
async fn test_mac_claims() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    let owner = case.person(None).await;
    let (d, serial) = case.device(Some(&owner), None, false).await;
    case.login(d, &serial, "AA-BB-CC-DD-EE-91", "10.0.0.2").await;
    let claims =
        registry::mac_claims(&mut case.db, &["aa:bb:cc:dd:ee:91", "aa:bb:cc:dd:ee:92", "junk"]).await.expect("claims");
    assert_eq!(claims.len(), 1);
    assert_eq!(claims["aa:bb:cc:dd:ee:91"], [owner].into());
    assert!(registry::mac_claims(&mut case.db, &[]).await.expect("claims").is_empty());
}

#[tokio::test]
async fn test_downloads() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    let owner = case.person(None).await;
    let other = case.person(None).await;
    let (d, _) = case.device(Some(&owner), None, false).await;
    let db = &mut case.db;
    let token = registry::create_download(db, d, "apple", 10).await.expect("download");
    assert_eq!(registry::consume_download(db, &token, &other).await.expect("c"), None); // someone else's: left alone
    let (dev, format) = registry::consume_download(db, &token, &owner).await.expect("c").expect("found");
    assert_eq!((dev.id, format.as_str()), (d, "apple"));
    assert_eq!(registry::consume_download(db, &token, &owner).await.expect("c"), None); // once
    let expired = registry::create_download(db, d, "eap-config", 0).await.expect("download");
    assert_eq!(registry::consume_download(db, &expired, &owner).await.expect("c"), None);
    let revoked = registry::create_download(db, d, "android", 10).await.expect("download");
    registry::revoke(db, d, &owner, "revoke").await.expect("revoke");
    assert_eq!(registry::consume_download(db, &revoked, &owner).await.expect("c"), None);
    let stored = case
        .i64(&format!("SELECT count(*) FROM download WHERE token_hash = '{}'", registry::token_hash(&expired)))
        .await;
    assert_eq!(stored, Some(1)); // only the hash is stored
}

#[tokio::test]
async fn test_oauth_tokens() {
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    let owner = case.person(None).await;
    let db = &mut case.db;
    let grant = registry::create_grant(db, &owner, "app.geteduroam.sh", "Laptop").await.expect("grant");
    let code = registry::issue_token(db, grant, "code", 60, Some("challenge"), Some("http://127.0.0.1:1/"))
        .await
        .expect("code");
    assert_eq!(registry::use_token(db, &code, "access", true).await.expect("use"), TokenUse::Invalid); // wrong kind
    let row = registry::use_token(db, &code, "code", true).await.expect("use").valid().expect("grant");
    assert_eq!(
        (row.grant_id, row.client_id.as_str(), row.pkce_challenge.as_deref(), row.redirect_uri.as_deref()),
        (grant, "app.geteduroam.sh", Some("challenge"), Some("http://127.0.0.1:1/"))
    );
    let refresh = registry::issue_token(db, grant, "refresh", 400 * 86400, None, None).await.expect("refresh");
    let access = registry::issue_token(db, grant, "access", 3600, None, None).await.expect("access");
    db.commit().await.expect("commit");
    // a replayed code is reported (nothing changed); the web revokes the grant (and its device)
    let replay = registry::use_token(db, &code, "code", true).await.expect("use");
    assert!(matches!(&replay, TokenUse::Replayed(r) if r.grant_id == grant), "{replay:?}");
    assert!(registry::use_token(db, &access, "access", false).await.expect("use").valid().is_some());
    registry::revoke_grant(db, grant).await.expect("revoke grant");
    db.commit().await.expect("commit");
    assert_eq!(registry::use_token(db, &code, "code", true).await.expect("use"), TokenUse::Invalid);
    assert_eq!(registry::use_token(db, &refresh, "refresh", true).await.expect("use"), TokenUse::Invalid);
    assert_eq!(registry::use_token(db, &access, "access", false).await.expect("use"), TokenUse::Invalid);
    // a fresh grant: tokens stop when the person is offboarded
    let grant = registry::create_grant(db, &owner, "app.eduroam.geteduroam", "Phone").await.expect("grant");
    let access = registry::issue_token(db, grant, "access", 3600, None, None).await.expect("access");
    assert!(registry::use_token(db, &access, "access", false).await.expect("use").valid().is_some());
    assert!(registry::use_token(db, &access, "access", false).await.expect("use").valid().is_some()); // reusable
    let d = registry::create_device(db, &owner, "Phone", "letswifi", "residents").await.expect("device");
    registry::bind_grant(db, grant, d).await.expect("bind");
    assert_eq!(
        registry::use_token(db, &access, "access", false).await.expect("use").valid().and_then(|g| g.device_id),
        Some(d)
    );
    // single use (the eap-config): the second use is reported, not valid
    let once = registry::issue_token(db, grant, "access", 3600, None, None).await.expect("access");
    assert!(registry::use_token(db, &once, "access", true).await.expect("use").valid().is_some());
    assert!(matches!(registry::use_token(db, &once, "access", true).await.expect("use"), TokenUse::Replayed(_)));
    registry::offboard_person(db, &owner).await.expect("offboard");
    assert_eq!(registry::use_token(db, &access, "access", false).await.expect("use"), TokenUse::Invalid);
    let expired = registry::issue_token(db, grant, "access", 0, None, None).await.expect("access");
    assert_eq!(registry::use_token(db, &expired, "access", false).await.expect("use"), TokenUse::Invalid);
    // a code-only field on another kind is refused by the schema
    assert!(registry::issue_token(db, grant, "access", 60, Some("x"), None).await.is_err());
}

#[tokio::test]
async fn test_the_decision_view_is_a_security_barrier() {
    // security review 2026-10-29 I6: a condition of the radius role's own query must not see the
    // rows the view filters out (revoked, retired, expired): no oracle for which serials exist
    let admin = need_db!();
    let _role = RADIUS_ROLE.read().await;
    let mut case = Case::new(&admin).await;
    let (_, revoked) = case.device(None, None, true).await;
    let (_, valid) = case.device(None, None, false).await;
    case.commit().await;
    let options = case.i64("SELECT count(*) FROM pg_class WHERE oid = 'radius.valid_cert'::regclass AND reloptions @> '{security_barrier=true}'").await;
    assert_eq!(options, Some(1));
    let mut r = case.radius().await;
    let probe = "SELECT count(*) FROM radius.valid_cert
                 WHERE CASE WHEN serial = $1 THEN 1 / (length(serial) - length(serial)) ELSE 1 END = 1";
    // a filtered-out serial: the probe never reaches it (no division by zero)
    let n: i64 =
        sqlx::query_scalar(probe).bind(&revoked).fetch_one(&mut r).await.expect("no oracle for a revoked serial");
    assert!(n >= 1);
    // the probe itself works: on a row the view lets through it fails
    assert!(sqlx::query_scalar::<_, i64>(probe).bind(&valid).fetch_one(&mut r).await.is_err());
}
