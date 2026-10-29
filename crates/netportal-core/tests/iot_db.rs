//! The home (IoT) devices of the registry against a real PostgreSQL (migration 0006,
//! `netportal_core::iot`): registration and claims, the shares and the access view, the FreeRADIUS
//! MAC-authentication contract (`radius.iot_mac`, `radius.reject` with `unknown_mac`), the
//! controller's sync rows, the residents' MACs, and the discovery proxy's read-only role.
//!
//! Needs `NETPORTAL_TEST_DATABASE_URL` like tests/registry_db.rs (`eval "$(tools/test-db.sh)"`);
//! without it every test is skipped. Each test makes its own database; the cluster-wide roles
//! `radius` and `netportal_rust_discovery` are created once with known passwords.

use std::sync::LazyLock;

use netportal_core::Db;
use netportal_core::config::Policy;
use netportal_core::iot::{self, IotError, NewDevice};
use netportal_core::registry;
use sqlx::{Connection, Executor, PgConnection};
use time::OffsetDateTime;
use tokio::sync::{Mutex, OnceCell};
use uuid::Uuid;

const RADIUS_PASSWORD: &str = "radius-test-password";
const DISCOVERY_PASSWORD: &str = "discovery-test-password";
const IOT_CALLED: &str = "AA-BB-CC-00-00-07:Scharni-IoT";

/// Role-level statements of concurrent tests would collide (as in registry_db.rs).
static ROLE_DDL: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
static ROLES_READY: OnceCell<()> = OnceCell::const_new();

fn admin_url() -> Option<url::Url> {
    let url = std::env::var("NETPORTAL_TEST_DATABASE_URL").ok().filter(|u| !u.is_empty())?;
    url::Url::parse(&url).ok()
}

macro_rules! need_db {
    () => {
        match admin_url() {
            Some(url) => url,
            None => {
                eprintln!("skipped: NETPORTAL_TEST_DATABASE_URL is not set (eval \"$(tools/test-db.sh)\")");
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

async fn ensure_roles(admin: &url::Url) {
    ROLES_READY
        .get_or_init(|| async {
            let mut conn = PgConnection::connect(admin.as_str()).await.expect("connect as admin");
            for (role, password) in [("radius", RADIUS_PASSWORD), ("netportal_rust_discovery", DISCOVERY_PASSWORD)] {
                conn.execute(sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
                    "DO $$ BEGIN
                         IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN
                             CREATE ROLE {role} LOGIN PASSWORD '{password}';
                         ELSE
                             ALTER ROLE {role} LOGIN PASSWORD '{password}';
                         END IF;
                     END $$"
                ))))
                .await
                .expect("role");
            }
        })
        .await;
}

fn policies() -> Vec<Policy> {
    vec![
        Policy { name: "residents".into(), vlan: 30, groups: ["residents".to_string()].into() },
        Policy { name: "guests".into(), vlan: 50, groups: ["former-residents".to_string()].into() },
    ]
}

struct Case {
    url: String,
    db: Db,
}

impl Case {
    /// A fresh, initialised database with the policies `residents` and `guests`.
    async fn new(admin: &url::Url) -> Case {
        ensure_roles(admin).await;
        let name = format!("t_{}", &Uuid::new_v4().simple().to_string()[..12]);
        let mut conn = PgConnection::connect(admin.as_str()).await.expect("connect as admin");
        conn.execute(sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))).await.expect("create");
        let url = url_for(admin, &name, None);
        let mut db = Db::connect(&url).await.expect("connect");
        {
            let _ddl = ROLE_DDL.lock().await;
            registry::init(&mut db, &policies()).await.expect("init");
        }
        Case { url, db }
    }

    async fn as_role(&self, role: &str, password: &str) -> PgConnection {
        let url = url::Url::parse(&self.url).expect("url");
        let path = url.path().trim_start_matches('/').to_string();
        PgConnection::connect(&url_for(&url, &path, Some((role, password)))).await.expect("connect as role")
    }

    async fn commit(&mut self) {
        self.db.commit().await.expect("commit");
    }

    async fn rollback(&mut self) {
        self.db.rollback().await.expect("rollback");
    }

    /// A person with the policy `residents` (or none).
    async fn person(&mut self, sub: &str, policy: Option<&str>) -> String {
        registry::upsert_person(&mut self.db, sub, sub, &format!("{sub} Name"), false).await.expect("person");
        if let Some(p) = policy {
            registry::set_policy(&mut self.db, sub, p).await.expect("policy");
        }
        self.commit().await;
        sub.to_string()
    }

    async fn register(&mut self, owner: &str, name: &str, class: &str, mac: Option<&str>) -> (Uuid, String) {
        let out = iot::register(&mut self.db, NewDevice { owner, name, class, mac, policy: "residents" })
            .await
            .expect("register");
        self.commit().await;
        out
    }

    async fn exec(&mut self, sql: &str) {
        self.db.tx().await.expect("tx").execute(sqlx::raw_sql(sqlx::AssertSqlSafe(sql.to_string()))).await.expect(sql);
        self.commit().await;
    }

    async fn i64(&mut self, sql: &str) -> i64 {
        sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql.to_string()))
            .fetch_one(self.db.tx().await.expect("tx"))
            .await
            .expect(sql)
    }

    async fn audits(&mut self, action: &str) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM audit WHERE action = $1")
            .bind(action)
            .fetch_one(self.db.tx().await.expect("tx"))
            .await
            .expect("audit")
    }

    async fn access_of(&mut self, sub: &str, id: Uuid) -> Vec<String> {
        let mut rows: Vec<String> = iot::access(&mut self.db)
            .await
            .expect("access")
            .into_iter()
            .filter(|a| a.sub == sub && a.device_id == id)
            .map(|a| a.basis)
            .collect();
        rows.sort();
        rows
    }
}

// --- registration, shares, the access view --------------------------------------------------------

#[tokio::test]
async fn test_register_share_and_access() {
    let admin = need_db!();
    let mut case = Case::new(&admin).await;
    let a = case.person("a", Some("residents")).await;
    let b = case.person("b", Some("residents")).await;
    let c = case.person("c", None).await; // no policy: nothing of the house for them

    let (id, psk) = case.register(&a, "Living room TV", "cast", Some("AA-BB-CC-DD-EE-01")).await;
    assert_eq!(psk.len(), iot::PSK_LENGTH);
    let dev = iot::device(&mut case.db, id).await.expect("device").expect("exists");
    assert_eq!((dev.owner.as_str(), dev.owner_name.as_str(), dev.name.as_str()), ("a", "a Name", "Living room TV"));
    assert_eq!((dev.class.as_str(), dev.visibility.as_str(), dev.psk.as_str()), ("cast", "private", psk.as_str()));
    assert_eq!(dev.mac.as_deref(), Some("aa:bb:cc:dd:ee:01"));
    assert!(dev.mac_claimed_at.is_some() && dev.revoked_at.is_none());
    // the MAC window starts at registration, so presence treats it like a Wi-Fi device
    assert_eq!(case.i64(&format!("SELECT count(*) FROM device_mac WHERE device_id = '{id}'")).await, 1);
    assert_eq!(dev.last_seen, Some(dev.mac_claimed_at.expect("claimed")));
    // and the generic registry lists it with its platform
    let listed = registry::device(&mut case.db, id, Some("a")).await.expect("registry").expect("row");
    assert_eq!((listed.platform.as_str(), listed.certificates), ("iot", 0));

    assert_eq!(iot::devices_of(&mut case.db, &a, false).await.expect("own").len(), 1);
    assert!(iot::devices_of(&mut case.db, &b, false).await.expect("own").is_empty());
    assert!(iot::shared_with(&mut case.db, &b).await.expect("shared").is_empty());
    assert!(iot::may_reach(&mut case.db, &a, id).await.expect("owner"));
    assert!(!iot::may_reach(&mut case.db, &b, id).await.expect("stranger"));
    assert_eq!(case.access_of("a", id).await, ["owner"]);

    // a share, idempotent
    assert!(iot::share(&mut case.db, id, &b, &a).await.expect("share"));
    assert!(!iot::share(&mut case.db, id, &b, &a).await.expect("again"));
    case.commit().await;
    assert_eq!(case.audits("iot:share:b").await, 1);
    let shares = iot::shares_of(&mut case.db, id).await.expect("shares");
    assert_eq!(shares.len(), 1);
    assert_eq!(
        (shares[0].grantee.as_str(), shares[0].grantee_name.as_str(), shares[0].granted_by.as_str()),
        ("b", "b Name", "a")
    );
    assert!(iot::may_reach(&mut case.db, &b, id).await.expect("sharee"));
    assert_eq!(case.access_of("b", id).await, ["share"]);
    let shared = iot::shared_with(&mut case.db, &b).await.expect("shared");
    assert_eq!(shared.len(), 1);
    assert_eq!(shared[0].id, id);
    assert!(iot::shared_with(&mut case.db, &a).await.expect("own are not shared").is_empty());

    assert!(iot::unshare(&mut case.db, id, &b, &a).await.expect("unshare"));
    assert!(!iot::unshare(&mut case.db, id, &b, &a).await.expect("again"));
    case.commit().await;
    assert_eq!(case.audits("iot:unshare:b").await, 1);
    assert!(!iot::may_reach(&mut case.db, &b, id).await.expect("gone"));

    // visible to the house: everyone with a policy, nobody without
    iot::set_visibility(&mut case.db, id, "house", &a).await.expect("house");
    case.commit().await;
    assert_eq!(case.audits("iot:visibility:house").await, 1);
    assert!(iot::may_reach(&mut case.db, &b, id).await.expect("house"));
    assert!(!iot::may_reach(&mut case.db, &c, id).await.expect("no policy"));
    assert_eq!(case.access_of("b", id).await, ["house"]);
    assert_eq!(case.access_of("a", id).await, ["house", "owner"]);
    let by_device = iot::access_by_device(&mut case.db).await.expect("by device");
    assert_eq!(by_device.get(&id).map(|s| s.as_slice()), Some(["a".to_string(), "b".to_string()].as_slice()));
    assert_eq!(iot::shared_with(&mut case.db, &b).await.expect("shared").len(), 1);
    assert!(matches!(
        iot::set_visibility(&mut case.db, id, "public", &a).await,
        Err(IotError::BadVisibility(v)) if v == "public"
    ));
    case.rollback().await;

    // an offboarded grantee or owner has no access; a revoked device gives none to anyone
    iot::set_visibility(&mut case.db, id, "private", &a).await.expect("private");
    iot::share(&mut case.db, id, &b, &a).await.expect("share");
    case.commit().await;
    registry::offboard_person(&mut case.db, &b).await.expect("offboard b");
    case.commit().await;
    assert!(!iot::may_reach(&mut case.db, &b, id).await.expect("offboarded grantee"));
    assert_eq!(iot::drop_shares_of(&mut case.db, &b).await.expect("drop"), 1);
    case.commit().await;
    assert!(iot::shares_of(&mut case.db, id).await.expect("shares").is_empty());

    let d = case.person("d", Some("residents")).await;
    let (id2, _) = case.register(&d, "Printer", "printer", Some("AA-BB-CC-DD-EE-02")).await;
    iot::share(&mut case.db, id2, &a, &d).await.expect("share");
    case.commit().await;
    assert!(iot::may_reach(&mut case.db, &a, id2).await.expect("sharee"));
    registry::offboard_person(&mut case.db, &d).await.expect("offboard d");
    case.commit().await;
    assert!(!iot::may_reach(&mut case.db, &a, id2).await.expect("owner offboarded"));
    assert!(!iot::may_reach(&mut case.db, &d, id2).await.expect("owner offboarded"));
    assert!(
        iot::mac_devices(&mut case.db).await.expect("macs").iter().any(|m| m.device_id == id2),
        "revoked only by revoke"
    );

    assert!(registry::revoke(&mut case.db, id, &a, "iot:remove").await.expect("revoke").is_empty());
    case.commit().await;
    assert!(!iot::may_reach(&mut case.db, &a, id).await.expect("revoked"));
    assert!(iot::devices_of(&mut case.db, &a, false).await.expect("own").is_empty());
    assert_eq!(iot::devices_of(&mut case.db, &a, true).await.expect("own incl. revoked").len(), 1);
    assert!(!iot::mac_devices(&mut case.db).await.expect("macs").iter().any(|m| m.device_id == id));
    assert_eq!(iot::all_devices(&mut case.db, false).await.expect("all").len(), 1);
    assert_eq!(iot::all_devices(&mut case.db, true).await.expect("all").len(), 2);
}

#[tokio::test]
async fn test_register_validation_claim_and_rotation() {
    let admin = need_db!();
    let mut case = Case::new(&admin).await;
    let a = case.person("a", Some("residents")).await;
    let new = |class, mac| NewDevice { owner: "a", name: "x", class, mac, policy: "residents" };

    assert!(
        matches!(iot::register(&mut case.db, new("toaster", None)).await, Err(IotError::BadClass(c)) if c == "toaster")
    );
    case.rollback().await;
    assert!(
        matches!(iot::register(&mut case.db, new("other", Some("nope"))).await, Err(IotError::BadMac(m)) if m == "nope")
    );
    case.rollback().await;

    let (first, _) = case.register(&a, "first", "speaker", Some("aa:bb:cc:dd:ee:10")).await;
    // the same MAC in another spelling is the same MAC
    assert!(matches!(
        iot::register(&mut case.db, new("tv", Some("AA-BB-CC-DD-EE-10"))).await,
        Err(IotError::MacTaken(m)) if m == "aa:bb:cc:dd:ee:10"
    ));
    case.rollback().await;
    assert_eq!(case.audits("iot:register").await, 1);

    // registered without a MAC: no RADIUS access until claimed
    let (second, psk) = case.register(&a, "second", "airplay", None).await;
    let dev = iot::device(&mut case.db, second).await.expect("device").expect("exists");
    assert!(dev.mac.is_none() && dev.mac_claimed_at.is_none() && dev.last_seen.is_none());
    assert!(!iot::mac_devices(&mut case.db).await.expect("macs").iter().any(|m| m.device_id == second));
    assert!(matches!(iot::claim_mac(&mut case.db, second, "zz", "a").await, Err(IotError::BadMac(_))));
    case.rollback().await;
    assert!(matches!(
        iot::claim_mac(&mut case.db, second, "AA:BB:CC:DD:EE:10", "a").await,
        Err(IotError::MacTaken(m)) if m == "aa:bb:cc:dd:ee:10"
    ));
    case.rollback().await;
    iot::claim_mac(&mut case.db, second, "AA-BB-CC-DD-EE-11", "a").await.expect("claim");
    case.commit().await;
    let dev = iot::device(&mut case.db, second).await.expect("device").expect("exists");
    assert_eq!(dev.mac.as_deref(), Some("aa:bb:cc:dd:ee:11"));
    assert!(dev.mac_claimed_at.is_some());
    assert_eq!(case.i64(&format!("SELECT count(*) FROM device_mac WHERE device_id = '{second}'")).await, 1);
    assert_eq!(case.audits("iot:claim").await, 1);
    let macs = iot::mac_devices(&mut case.db).await.expect("macs");
    assert_eq!(macs.iter().map(|m| m.mac.as_str()).collect::<Vec<_>>(), ["aa:bb:cc:dd:ee:10", "aa:bb:cc:dd:ee:11"]);
    assert_eq!(macs[1].class, "airplay");

    // a replaced device: the MAC moves, the old window stays as history
    iot::claim_mac(&mut case.db, second, "AA-BB-CC-DD-EE-12", "a").await.expect("move");
    case.commit().await;
    assert_eq!(case.i64(&format!("SELECT count(*) FROM device_mac WHERE device_id = '{second}'")).await, 2);
    assert_eq!(
        iot::device(&mut case.db, second).await.expect("device").expect("exists").mac.as_deref(),
        Some("aa:bb:cc:dd:ee:12")
    );

    // a new key
    let rotated = iot::rotate_psk(&mut case.db, second, "a").await.expect("rotate");
    case.commit().await;
    assert_ne!(rotated, psk);
    assert_eq!(iot::device(&mut case.db, second).await.expect("device").expect("exists").psk, rotated);
    assert_eq!(case.audits("iot:rotate-key").await, 1);

    // a revoked device keeps its MAC and key but neither can change
    registry::revoke(&mut case.db, first, "a", "iot:remove").await.expect("revoke");
    case.commit().await;
    iot::claim_mac(&mut case.db, first, "AA-BB-CC-DD-EE-13", "a").await.expect("no-op");
    let _ = iot::rotate_psk(&mut case.db, first, "a").await.expect("no-op");
    case.commit().await;
    let dev = iot::device(&mut case.db, first).await.expect("device").expect("exists");
    assert_eq!(dev.mac.as_deref(), Some("aa:bb:cc:dd:ee:10"));
    assert!(dev.revoked_at.is_some());
    // a removed device's MAC is free again: the next registration or claim takes it over
    let (again, _) = case.register(&a, "first again", "speaker", Some("AA-BB-CC-DD-EE-10")).await;
    let old = iot::device(&mut case.db, first).await.expect("device").expect("exists");
    assert!(old.mac.is_none() && old.mac_claimed_at.is_none());
    assert_eq!(
        iot::device(&mut case.db, again).await.expect("device").expect("exists").mac.as_deref(),
        Some("aa:bb:cc:dd:ee:10")
    );
    assert_eq!(case.audits("iot:mac-released").await, 1);
    registry::revoke(&mut case.db, again, "a", "iot:remove").await.expect("revoke");
    case.commit().await;
    iot::claim_mac(&mut case.db, second, "aa:bb:cc:dd:ee:10", "a").await.expect("claim a removed device's MAC");
    case.commit().await;
    assert_eq!(
        iot::device(&mut case.db, second).await.expect("device").expect("exists").mac.as_deref(),
        Some("aa:bb:cc:dd:ee:10")
    );
    assert!(iot::device(&mut case.db, again).await.expect("device").expect("exists").mac.is_none());
    assert_eq!(case.audits("iot:mac-released").await, 2);
    // the renaming of the generic registry applies to home devices too
    registry::rename(&mut case.db, second, "AirPlay box").await.expect("rename");
    case.commit().await;
    assert_eq!(iot::device(&mut case.db, second).await.expect("device").expect("exists").name, "AirPlay box");
}

// --- the FreeRADIUS contract: MAC authentication ---------------------------------------------------

async fn iot_mac(r: &mut PgConnection, mac: &str) -> Option<String> {
    sqlx::query_scalar("SELECT device_id FROM radius.iot_mac WHERE mac = $1::macaddr")
        .bind(mac)
        .fetch_optional(&mut *r)
        .await
        .expect("radius.iot_mac")
}

async fn reject_unknown(r: &mut PgConnection, mac: &str) {
    sqlx::query("SELECT radius.reject('', $1, $2, '10.0.0.2', 'unknown_mac')")
        .bind(mac)
        .bind(IOT_CALLED)
        .execute(&mut *r)
        .await
        .expect("radius.reject");
}

#[tokio::test]
async fn test_radius_mac_authentication_contract() {
    let admin = need_db!();
    let mut case = Case::new(&admin).await;
    let a = case.person("a", Some("residents")).await;
    let (with_mac, _) = case.register(&a, "cast", "cast", Some("AA-BB-CC-DD-EE-20")).await;
    let (without, _) = case.register(&a, "later", "tv", None).await;
    let mut r = case.as_role("radius", RADIUS_PASSWORD).await;

    // the view: registered MACs of live devices only, as text device ids for Tmp-String-2
    assert_eq!(iot_mac(&mut r, "aa:bb:cc:dd:ee:20").await.as_deref(), Some(with_mac.to_string().as_str()));
    assert_eq!(iot_mac(&mut r, "aa:bb:cc:dd:ee:21").await, None);
    // the role sees the view, never the keys
    let direct: Result<Option<String>, _> =
        sqlx::query_scalar("SELECT psk FROM public.iot_device LIMIT 1").fetch_optional(&mut r).await;
    assert!(direct.is_err(), "the radius role must not read iot_device");
    let columns: Vec<String> = sqlx::query_scalar(
        "SELECT column_name::text FROM information_schema.columns WHERE table_schema = 'radius' AND table_name = 'iot_mac' ORDER BY 1",
    )
    .fetch_all(&mut r)
    .await
    .expect("columns");
    assert_eq!(columns, ["device_id", "mac"]);

    // an unknown MAC on the IoT SSID: logged once with tries, offered for a claim
    reject_unknown(&mut r, "AA-BB-CC-DD-EE-21").await;
    reject_unknown(&mut r, "AA-BB-CC-DD-EE-21").await;
    assert_eq!(
        case.i64("SELECT count(*) FROM radius_auth WHERE result = 'reject' AND reason = 'unknown_mac'").await,
        1
    );
    assert_eq!(case.i64("SELECT tries::bigint FROM radius_auth WHERE reason = 'unknown_mac'").await, 2);
    let attempts = iot::join_attempts(&mut case.db).await.expect("attempts");
    assert_eq!(attempts.len(), 1);
    assert_eq!(
        (attempts[0].mac.as_str(), attempts[0].tries, attempts[0].ssid.as_deref()),
        ("aa:bb:cc:dd:ee:21", 2, Some("Scharni-IoT"))
    );
    assert!(attempts[0].last_seen >= attempts[0].first_seen);

    // the claim consumes the attempt and the view accepts the MAC from then on
    iot::claim_mac(&mut case.db, without, "aa:bb:cc:dd:ee:21", "a").await.expect("claim");
    case.commit().await;
    assert!(iot::join_attempts(&mut case.db).await.expect("attempts").is_empty());
    assert_eq!(iot_mac(&mut r, "aa:bb:cc:dd:ee:21").await.as_deref(), Some(without.to_string().as_str()));
    // a MAC that a device holds is never offered even if it was refused meanwhile
    reject_unknown(&mut r, "AA-BB-CC-DD-EE-21").await;
    assert!(iot::join_attempts(&mut case.db).await.expect("attempts").is_empty());

    // the login of a MAC authentication: no serial, the device's MAC window advances
    let token: Option<String> = sqlx::query_scalar(
        "SELECT radius.login($1, '', 'AA-BB-CC-DD-EE-21', $2, '10.0.0.2', 'sid-1', 'aabbccddee21', NULL)",
    )
    .bind(without.to_string())
    .bind(IOT_CALLED)
    .fetch_one(&mut r)
    .await
    .expect("radius.login");
    assert!(token.is_some_and(|t| t.starts_with("np1:")));
    assert_eq!(
        case.i64(&format!(
            "SELECT auth_count::bigint FROM device_mac WHERE device_id = '{without}' AND mac = 'aa:bb:cc:dd:ee:21'"
        ))
        .await,
        1
    );
    assert_eq!(
        case.i64(
            "SELECT count(*) FROM radius_auth WHERE result = 'accept' AND serial IS NULL AND ssid = 'Scharni-IoT'"
        )
        .await,
        1
    );
    assert!(iot::device(&mut case.db, without).await.expect("device").expect("exists").last_seen.is_some());

    // revoked, or the owner gone: refused
    registry::revoke(&mut case.db, with_mac, "a", "iot:remove").await.expect("revoke");
    case.commit().await;
    assert_eq!(iot_mac(&mut r, "aa:bb:cc:dd:ee:20").await, None);
    registry::offboard_person(&mut case.db, &a).await.expect("offboard");
    case.commit().await;
    assert_eq!(iot_mac(&mut r, "aa:bb:cc:dd:ee:21").await, None);

    // the claim window and the pruning
    reject_unknown(&mut r, "AA-BB-CC-DD-EE-30").await;
    reject_unknown(&mut r, "AA-BB-CC-DD-EE-31").await;
    case.exec("UPDATE iot_join_attempt SET last_seen = now() - interval '20 minutes', first_seen = now() - interval '20 minutes' WHERE mac = 'aa:bb:cc:dd:ee:30'").await;
    let offered: Vec<String> =
        iot::join_attempts(&mut case.db).await.expect("attempts").into_iter().map(|j| j.mac).collect();
    assert_eq!(offered, ["aa:bb:cc:dd:ee:31"]);
    assert_eq!(iot::prune_join_attempts(&mut case.db).await.expect("prune"), 0);
    case.exec("UPDATE iot_join_attempt SET last_seen = now() - interval '2 days', first_seen = now() - interval '2 days' WHERE mac = 'aa:bb:cc:dd:ee:30'").await;
    assert_eq!(iot::prune_join_attempts(&mut case.db).await.expect("prune"), 1);
    case.commit().await;
    // left: ...:31 and the refused ...:21 (a claimed MAC's attempt is noted but never offered)
    assert_eq!(case.i64("SELECT count(*) FROM iot_join_attempt").await, 2);
    // an unparsable MAC leaves no attempt, the reject is still logged
    sqlx::query("SELECT radius.reject('', 'garbage', $1, '10.0.0.2', 'unknown_mac')")
        .bind(IOT_CALLED)
        .execute(&mut r)
        .await
        .expect("reject");
    assert_eq!(case.i64("SELECT count(*) FROM iot_join_attempt").await, 2);
    assert_eq!(case.i64("SELECT count(*) FROM radius_auth WHERE reason = 'unknown_mac' AND mac IS NULL").await, 1);
}

// --- the controller's rows and the residents' MACs --------------------------------------------------

#[tokio::test]
async fn test_sync_rows_and_resident_macs() {
    let admin = need_db!();
    let mut case = Case::new(&admin).await;
    let a = case.person("a", Some("residents")).await;
    let b = case.person("b", Some("residents")).await;
    let (id, _) = case.register(&a, "cast", "cast", Some("AA-BB-CC-DD-EE-40")).await;

    iot::set_sync(&mut case.db, "unifi_key", &id.to_string(), "pending", "").await.expect("set");
    iot::set_sync(&mut case.db, "opnsense_alias", "np_iot_dev_01234567", "failed", &"x".repeat(900))
        .await
        .expect("set");
    iot::set_sync(&mut case.db, "unifi_key", &id.to_string(), "applied", "round 2").await.expect("upsert");
    case.commit().await;
    let states = iot::sync_states(&mut case.db).await.expect("states");
    assert_eq!(states.len(), 2);
    assert_eq!(states[0].target, "opnsense_alias");
    assert_eq!(states[0].detail.len(), 500, "the detail is cut");
    let of_device = iot::sync_of_device(&mut case.db, id).await.expect("of device");
    assert_eq!(of_device.len(), 1);
    assert_eq!((of_device[0].status.as_str(), of_device[0].detail.as_str()), ("applied", "round 2"));
    let counts = iot::sync_counts(&mut case.db).await.expect("counts");
    assert_eq!((counts.get("applied"), counts.get("failed"), counts.get("pending")), (Some(&1), Some(&1), None));
    assert!(
        iot::set_sync(&mut case.db, "unifi_key", &id.to_string(), "done", "").await.is_err(),
        "the status is constrained"
    );
    case.rollback().await;
    iot::clear_sync(&mut case.db, "opnsense_alias", "np_iot_dev_01234567").await.expect("clear");
    case.commit().await;
    assert_eq!(iot::sync_states(&mut case.db).await.expect("states").len(), 1);

    // the residents' current MACs: certificate devices' current windows only, conflicts to nobody
    assert!(iot::current_resident_macs(&mut case.db).await.expect("none").is_empty());
    let phone_a = registry::create_device(&mut case.db, &a, "phone", "apple", "residents").await.expect("device");
    let laptop_b = registry::create_device(&mut case.db, &b, "laptop", "apple-mac", "residents").await.expect("device");
    let now = OffsetDateTime::now_utc();
    for (dev, mac, last) in [
        (phone_a, "aa:bb:cc:dd:ee:50", now),
        (phone_a, "aa:bb:cc:dd:ee:51", now - time::Duration::hours(2)), // an older MAC of the same device
        (laptop_b, "aa:bb:cc:dd:ee:52", now - time::Duration::days(2)), // current, but its window has ended
    ] {
        sqlx::query(
            "INSERT INTO device_mac (device_id, mac, first_seen, last_seen, auth_count, randomized)
             VALUES ($1, $2::macaddr, $3, $3, 1, false)",
        )
        .bind(dev)
        .bind(mac)
        .bind(last)
        .execute(case.db.tx().await.expect("tx"))
        .await
        .expect("window");
    }
    case.commit().await;
    let macs = iot::current_resident_macs(&mut case.db).await.expect("macs");
    assert_eq!(macs.iter().map(|(m, o)| (m.as_str(), o.as_str())).collect::<Vec<_>>(), [("aa:bb:cc:dd:ee:50", "a")]);
    // the same MAC current on two owners' devices belongs to nobody
    sqlx::query(
        "INSERT INTO device_mac (device_id, mac, first_seen, last_seen, auth_count, randomized)
         VALUES ($1, 'aa:bb:cc:dd:ee:50', now(), now(), 1, false)",
    )
    .bind(laptop_b)
    .execute(case.db.tx().await.expect("tx"))
    .await
    .expect("conflict");
    case.commit().await;
    assert!(iot::current_resident_macs(&mut case.db).await.expect("macs").is_empty());
    // a revoked device's windows are not current
    sqlx::query("DELETE FROM device_mac WHERE device_id = $1 AND mac = 'aa:bb:cc:dd:ee:50'")
        .bind(laptop_b)
        .execute(case.db.tx().await.expect("tx"))
        .await
        .expect("delete");
    registry::revoke(&mut case.db, phone_a, "a", "test").await.expect("revoke");
    case.commit().await;
    assert!(iot::current_resident_macs(&mut case.db).await.expect("macs").is_empty());
}

// --- the discovery proxy's role -----------------------------------------------------------------------

#[tokio::test]
async fn test_discovery_role_reads_access_only() {
    let admin = need_db!();
    let mut case = Case::new(&admin).await;
    let a = case.person("a", Some("residents")).await;
    let b = case.person("b", Some("residents")).await;
    let (id, _) = case.register(&a, "cast", "cast", Some("AA-BB-CC-DD-EE-60")).await;
    iot::share(&mut case.db, id, &b, &a).await.expect("share");
    case.commit().await;

    // the proxy reads the access view and the MAC map through the crate's functions
    let mut proxy = Db::connect(&url_for(
        &url::Url::parse(&case.url).expect("url"),
        url::Url::parse(&case.url).expect("url").path().trim_start_matches('/'),
        Some(("netportal_rust_discovery", DISCOVERY_PASSWORD)),
    ))
    .await
    .expect("connect as the proxy");
    let access = iot::access(&mut proxy).await.expect("access");
    assert_eq!(access.len(), 2);
    assert_eq!(iot::mac_devices(&mut proxy).await.expect("macs").len(), 1);
    assert!(iot::current_resident_macs(&mut proxy).await.expect("residents").is_empty());
    assert!(iot::may_reach(&mut proxy, "b", id).await.expect("reach"));
    proxy.rollback().await.expect("rollback");

    // and nothing else: no keys, no writes, no sessions, no RADIUS schema
    let mut r = case.as_role("netportal_rust_discovery", DISCOVERY_PASSWORD).await;
    for sql in [
        "SELECT psk FROM iot_device LIMIT 1",
        "INSERT INTO iot_share (device_id, grantee, granted_by) VALUES (gen_random_uuid(), 'a', 'a')",
        "UPDATE iot_device SET visibility = 'house'",
        "SELECT count(*) FROM session",
        "SELECT count(*) FROM radius_auth",
        "SELECT count(*) FROM audit",
        "SELECT count(*) FROM radius.iot_mac",
        "SELECT radius.reject('', '', '', '', 'unknown_mac')",
    ] {
        let mut tx = r.begin().await.expect("begin");
        let out = tx.execute(sqlx::raw_sql(sqlx::AssertSqlSafe(sql.to_string()))).await;
        tx.rollback().await.expect("rollback");
        assert!(out.is_err(), "allowed: {sql}");
    }
    let class: String = sqlx::query_scalar("SELECT class FROM iot_device WHERE device_id = $1")
        .bind(id)
        .fetch_one(&mut r)
        .await
        .expect("class");
    assert_eq!(class, "cast");
    // the grants survive a second init (they are reapplied each run)
    {
        let _ddl = ROLE_DDL.lock().await;
        registry::init(&mut case.db, &policies()).await.expect("init again");
    }
    let visibility: String = sqlx::query_scalar("SELECT visibility FROM iot_device WHERE device_id = $1")
        .bind(id)
        .fetch_one(&mut r)
        .await
        .expect("visibility");
    assert_eq!(visibility, "private");
}
