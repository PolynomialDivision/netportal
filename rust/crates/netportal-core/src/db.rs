//! A database connection with explicit commit points, the way the Python code used psycopg: the
//! first statement after a commit (or after connecting) opens a transaction, [`Db::commit`] and
//! [`Db::rollback`] end it. Registry functions that write leave the transaction open; the caller
//! commits, so the commit points of the Python code (revocation before the Disconnect, the
//! credential before the response, per-device commits in the offboarding, the collector's
//! batches) carry over one to one (INVENTORY 16, R8).
//!
//! A statement that fails inside a transaction leaves it aborted until [`Db::rollback`], as in
//! PostgreSQL itself.
//!
//! Two kinds of connection:
//!
//! - [`Db::connect`]: a connection of its own (the sidecars, `init-db`, the migration at the
//!   web's start). Dropping it closes it, which rolls back an open transaction on the server.
//! - [`Pool::acquire`]: a connection of the web's shared pool ([`Pool`], one per process). It
//!   goes back to the pool when dropped; one dropped inside a transaction is rolled back first
//!   (a task of its own, as sqlx returns connections), so the next request never inherits a
//!   transaction. Pooled connections must not change session state (`SET`, session advisory
//!   locks): [`Db::autocommit`] is refused on them.
//!
//! Connections are plain `sqlx` connections: sessions run in UTC (sqlx sets `TimeZone=UTC`),
//! statement logging is off (queries contain MACs, INVENTORY 4.9). Opening one takes at most
//! [`CONNECT_TIMEOUT`] (a pool: its acquire timeout).

use std::str::FromStr;
use std::time::Duration;

use sqlx::pool::PoolConnection;
use sqlx::postgres::{PgConnectOptions, PgConnection, PgPool, PgPoolOptions};
use sqlx::{ConnectOptions, Connection, Executor, Postgres};

/// Opening a connection of its own ([`Db::connect`]) takes at most this long.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

enum Conn {
    Own(PgConnection),
    Pooled(PoolConnection<Postgres>),
}

impl Conn {
    fn get(&mut self) -> &mut PgConnection {
        match self {
            Conn::Own(conn) => conn,
            Conn::Pooled(conn) => conn,
        }
    }
}

/// One database connection with lazily opened transactions.
pub struct Db {
    /// `None` only after [`Db::close`] took it
    conn: Option<Conn>,
    in_transaction: bool,
    commits: u64,
}

/// The connection options of a URL, without statement logging.
fn connect_options(url: &str) -> Result<PgConnectOptions, sqlx::Error> {
    Ok(PgConnectOptions::from_str(url)?
        .log_statements(log::LevelFilter::Off)
        .log_slow_statements(log::LevelFilter::Off, Duration::from_secs(3600)))
}

/// The error of a connection attempt that took too long.
fn timed_out() -> sqlx::Error {
    sqlx::Error::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, "connecting to the database timed out"))
}

impl Db {
    /// Connect with a PostgreSQL URL (`postgresql://user:password@host:port/dbname?sslmode=...`),
    /// within [`CONNECT_TIMEOUT`].
    pub async fn connect(url: &str) -> Result<Db, sqlx::Error> {
        let options = connect_options(url)?;
        match tokio::time::timeout(CONNECT_TIMEOUT, options.connect()).await {
            Ok(conn) => Ok(Db::from_connection(conn?)),
            Err(_) => Err(timed_out()),
        }
    }

    pub fn from_connection(conn: PgConnection) -> Db {
        Db { conn: Some(Conn::Own(conn)), in_transaction: false, commits: 0 }
    }

    fn conn(&mut self) -> Result<&mut PgConnection, sqlx::Error> {
        self.conn.as_mut().map(Conn::get).ok_or(sqlx::Error::PoolClosed)
    }

    /// The connection inside the current transaction (opened now if none is open). Every
    /// registry statement goes through this.
    pub async fn tx(&mut self) -> Result<&mut PgConnection, sqlx::Error> {
        if !self.in_transaction {
            self.conn()?.execute("BEGIN").await?;
            self.in_transaction = true;
        }
        self.conn()
    }

    /// The connection outside any transaction (autocommit statements such as `SET`, session
    /// advisory locks). Fails when a transaction is open, so nothing is committed by accident,
    /// and on a pooled connection, whose session state the next request would inherit.
    pub async fn autocommit(&mut self) -> Result<&mut PgConnection, sqlx::Error> {
        if self.in_transaction {
            return Err(sqlx::Error::Protocol("autocommit statement inside an open transaction".into()));
        }
        if matches!(self.conn, Some(Conn::Pooled(_))) {
            return Err(sqlx::Error::Protocol("session statement on a pooled connection".into()));
        }
        self.conn()
    }

    /// Commit the open transaction (nothing to do without one).
    pub async fn commit(&mut self) -> Result<(), sqlx::Error> {
        if self.in_transaction {
            self.in_transaction = false;
            self.conn()?.execute("COMMIT").await?;
            self.commits += 1;
        }
        Ok(())
    }

    /// Roll back the open transaction (nothing to do without one).
    pub async fn rollback(&mut self) -> Result<(), sqlx::Error> {
        if self.in_transaction {
            self.in_transaction = false;
            self.conn()?.execute("ROLLBACK").await?;
        }
        Ok(())
    }

    /// Roll back what is open and close the connection (a pooled one goes back to its pool).
    pub async fn close(mut self) -> Result<(), sqlx::Error> {
        self.rollback().await?;
        match self.conn.take() {
            Some(Conn::Own(conn)) => conn.close().await,
            Some(Conn::Pooled(conn)) => {
                drop(conn);
                Ok(())
            }
            None => Ok(()),
        }
    }

    pub fn in_transaction(&self) -> bool {
        self.in_transaction
    }

    /// Whether this connection belongs to a [`Pool`].
    pub fn is_pooled(&self) -> bool {
        matches!(self.conn, Some(Conn::Pooled(_)))
    }

    /// How many transactions this connection committed (tests, e.g. the prune batches).
    pub fn commits(&self) -> u64 {
        self.commits
    }
}

impl Drop for Db {
    /// A pooled connection left inside a transaction is rolled back before it goes back to the
    /// pool (in a task: drop cannot wait); without a runtime it is closed instead (the server
    /// rolls back). A connection of its own just closes.
    fn drop(&mut self) {
        if !self.in_transaction {
            return;
        }
        if let Some(Conn::Pooled(mut conn)) = self.conn.take() {
            match tokio::runtime::Handle::try_current() {
                Ok(runtime) => {
                    runtime.spawn(async move {
                        if conn.execute("ROLLBACK").await.is_err() {
                            conn.close_on_drop();
                        }
                    });
                }
                Err(_) => conn.close_on_drop(),
            }
        }
    }
}

/// What a [`Pool`] is made of (the web's: `NETPORTAL_DB_POOL_SIZE` and fixed timeouts, see
/// `netportal_web::web`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolSettings {
    /// connections at most (the database role's `CONNECTION LIMIT` must leave room for this)
    pub size: u32,
    /// waiting for a free connection (or for a new one to open) longer than this fails
    /// with `sqlx::Error::PoolTimedOut`
    pub acquire_timeout: Duration,
    /// the sessions' `statement_timeout`
    pub statement_timeout: Duration,
    /// the sessions' `lock_timeout`
    pub lock_timeout: Duration,
    /// the sessions' `idle_in_transaction_session_timeout`
    pub idle_in_transaction_timeout: Duration,
    /// the sessions' `application_name` (`pg_stat_activity`)
    pub application_name: String,
}

/// A shared, size-limited set of connections (the web process has one). Lazy: no connection
/// is opened before the first [`Pool::acquire`], so the portal starts without the registry
/// and recovers from an outage without a restart. Cheap to clone (shared).
#[derive(Clone)]
pub struct Pool {
    pool: PgPool,
}

impl std::fmt::Debug for Pool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pool").field("size", &self.pool.size()).field("idle", &self.pool.num_idle()).finish()
    }
}

fn postgres_ms(d: Duration) -> String {
    format!("{}ms", d.as_millis().max(1))
}

impl Pool {
    /// A pool for this URL (nothing is connected yet; an invalid URL is an error now).
    pub fn new(url: &str, settings: &PoolSettings) -> Result<Pool, sqlx::Error> {
        let options = connect_options(url)?.application_name(&settings.application_name).options([
            ("statement_timeout", postgres_ms(settings.statement_timeout)),
            ("lock_timeout", postgres_ms(settings.lock_timeout)),
            ("idle_in_transaction_session_timeout", postgres_ms(settings.idle_in_transaction_timeout)),
        ]);
        let pool = PgPoolOptions::new()
            .max_connections(settings.size.max(1))
            .min_connections(0)
            .acquire_timeout(settings.acquire_timeout)
            .idle_timeout(Some(Duration::from_secs(300)))
            .max_lifetime(Some(Duration::from_secs(1800)))
            .connect_lazy_with(options);
        Ok(Pool { pool })
    }

    /// A connection of the pool, waiting at most the acquire timeout (then
    /// `sqlx::Error::PoolTimedOut`: every connection is busy, or the database does not answer).
    pub async fn acquire(&self) -> Result<Db, sqlx::Error> {
        let conn = self.pool.acquire().await?;
        Ok(Db { conn: Some(Conn::Pooled(conn)), in_transaction: false, commits: 0 })
    }

    /// Connections open now (idle and in use).
    pub fn size(&self) -> u32 {
        self.pool.size()
    }

    /// Connections open and idle now.
    pub fn idle(&self) -> usize {
        self.pool.num_idle()
    }

    /// The most connections this pool opens.
    pub fn max_size(&self) -> u32 {
        self.pool.options().get_max_connections()
    }

    /// Close every connection (at the end of `serve`).
    pub async fn close(&self) {
        self.pool.close().await;
    }
}
