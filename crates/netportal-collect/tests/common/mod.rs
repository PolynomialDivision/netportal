//! The database side of the collector's tests: a fresh, initialised database per test on the
//! throwaway PostgreSQL of `tools/test-db.sh` (`NETPORTAL_TEST_DATABASE_URL`, a superuser's
//! URL). Without it the database tests are skipped with a message (`need_db!`).
#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use netportal_core::Db;
use netportal_core::config::{CollectSettings, DEFAULT_LOKI_SELECTOR, Policy, Secret};
use netportal_core::registry;
use sqlx::{Connection, Executor, PgConnection};
use time::OffsetDateTime;
use tokio::sync::Mutex;
use uuid::Uuid;

/// Concurrent initialisations would collide on role-level statements (the grants).
static INIT: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

pub fn admin_url() -> Option<url::Url> {
    let url = std::env::var("NETPORTAL_TEST_DATABASE_URL").ok().filter(|u| !u.is_empty())?;
    url::Url::parse(&url).ok()
}

#[macro_export]
macro_rules! need_db {
    () => {
        match common::admin_url() {
            Some(url) => url,
            None => {
                eprintln!("skipped: NETPORTAL_TEST_DATABASE_URL is not set (eval \"$(tools/test-db.sh)\")");
                return;
            }
        }
    };
}

/// A fresh, initialised database; returns its URL.
pub async fn fresh_database(admin: &url::Url) -> String {
    let name = format!("c_{}", &Uuid::new_v4().simple().to_string()[..12]);
    let mut conn = PgConnection::connect(admin.as_str()).await.expect("connect as admin");
    conn.execute(sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))).await.expect("create database");
    let mut url = admin.clone();
    url.set_path(&format!("/{name}"));
    let mut db = Db::connect(url.as_str()).await.expect("connect");
    let policies = [Policy { name: "residents".into(), vlan: 30, groups: ["residents".to_string()].into() }];
    {
        let _init = INIT.lock().await;
        registry::init(&mut db, &policies).await.expect("init");
    }
    db.close().await.expect("close");
    url.to_string()
}

/// A test's database, heartbeat directory and settings.
pub struct Case {
    pub url: String,
    pub db: Db,
    pub dir: tempfile::TempDir,
}

impl Case {
    pub async fn new(admin: &url::Url) -> Case {
        let url = fresh_database(admin).await;
        let db = Db::connect(&url).await.expect("connect");
        Case { url, db, dir: tempfile::tempdir().expect("tempdir") }
    }

    pub fn heartbeat(&self) -> PathBuf {
        self.dir.path().join("hb")
    }

    pub fn settings(&self, prometheus: Option<&str>, loki: Option<&str>) -> Arc<CollectSettings> {
        Arc::new(settings(&self.url, self.heartbeat(), prometheus, loki))
    }

    pub async fn person(&mut self, sub: &str) {
        registry::upsert_person(&mut self.db, sub, sub, sub, false).await.expect("person");
        self.db.commit().await.expect("commit");
    }

    /// A device of `owner` (created first if needed), revoked when asked (its last window then
    /// ends 15 minutes after its last_seen, like every non-current window).
    pub async fn device(&mut self, owner: &str, revoked: bool) -> Uuid {
        self.person(owner).await;
        let id = registry::create_device(&mut self.db, owner, "dev", "apple", "residents").await.expect("device");
        if revoked {
            sqlx::query("UPDATE device SET revoked_at = now() WHERE id = $1")
                .bind(id)
                .execute(self.db.tx().await.expect("tx"))
                .await
                .expect("revoke");
        }
        self.db.commit().await.expect("commit");
        id
    }

    pub async fn window(&mut self, device: Uuid, mac: &str, first: OffsetDateTime, last: OffsetDateTime) {
        sqlx::query(
            "INSERT INTO device_mac (device_id, mac, first_seen, last_seen, auth_count, randomized)
             VALUES ($1, $2::macaddr, $3, $4, 1, true)",
        )
        .bind(device)
        .bind(mac)
        .bind(first)
        .bind(last)
        .execute(self.db.tx().await.expect("tx"))
        .await
        .expect("window");
        self.db.commit().await.expect("commit");
    }

    pub async fn auth(&mut self, device: Uuid, at: OffsetDateTime, accept: bool, tries: i32) {
        sqlx::query("INSERT INTO radius_auth (at, tries, result, reason, device_id) VALUES ($1, $2, $3, $4, $5)")
            .bind(at)
            .bind(tries)
            .bind(if accept { "accept" } else { "reject" })
            .bind(if accept { "ok" } else { "expired" })
            .bind(device)
            .execute(self.db.tx().await.expect("tx"))
            .await
            .expect("auth");
        self.db.commit().await.expect("commit");
    }

    pub async fn exec(&mut self, sql: &str) {
        self.db.tx().await.expect("tx").execute(sqlx::raw_sql(sqlx::AssertSqlSafe(sql.to_string()))).await.expect(sql);
        self.db.commit().await.expect("commit");
    }

    pub async fn job(&mut self, name: &str) -> Option<registry::JobStatus> {
        let rows = registry::job_status(&mut self.db).await.expect("job_status");
        self.db.commit().await.expect("commit");
        rows.into_iter().find(|r| r.name == name)
    }

    pub async fn i64(&mut self, sql: &str) -> i64 {
        let n: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_string()))
            .fetch_one(self.db.tx().await.expect("tx"))
            .await
            .expect(sql);
        self.db.commit().await.expect("commit");
        n
    }
}

pub fn settings(
    database_url: &str,
    heartbeat: PathBuf,
    prometheus: Option<&str>,
    loki: Option<&str>,
) -> CollectSettings {
    CollectSettings {
        database_url: Secret::new(database_url.to_string()),
        ssid: "Scharni".into(),
        prometheus_url: prometheus.map(str::to_string),
        loki_url: loki.map(str::to_string),
        timezone: "Europe/Berlin".into(),
        heartbeat,
        query_timeout: Duration::from_secs(20),
        loki_selector: DEFAULT_LOKI_SELECTOR.into(),
        radius_container: "netaccess-radius".into(),
    }
}

pub fn ts(unix: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(unix).expect("timestamp")
}
