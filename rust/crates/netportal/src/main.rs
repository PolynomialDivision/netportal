//! `netportal <command>` (Python: `netportal/__main__.py`, `netportal/wsgi.py`; INVENTORY 1.1).
//!
//! - `serve [--bind ADDR]`   the portal (replaces gunicorn; migrates the registry at start;
//!   the address defaults to `NETPORTAL_LISTEN`, else `0.0.0.0:8080`)
//! - `init-db`               create or upgrade the schema and seed the policies
//! - `offboard [--every N] [--allow-mass]`  reconcile with Authentik once, or every N seconds
//!   (the sidecar); `--allow-mass`: one round past the mass-removal hold
//! - `collect [--once] [--jobs a,b]`  the collector, forever or every selected job once
//! - `job NAME`              one collector job once (unifi_events, incidents, rollup, prune)
//! - `pki --out DIR [--name NAME] --server-name FQDN`  the CA ceremony (on an admin's machine)
//! - `health web [--addr ADDR]`, `health heartbeat --file FILE --max-age SECONDS`  the
//!   containers' healthchecks (`health.rs`)
//!
//! Exit codes: 0 success, 1 failure (the message on stderr: `netportal: <command>: <error>`),
//! 2 usage errors. Each command loads only the settings it needs (`netportal_core::config`).

mod health;

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, SystemTime};

use clap::{Parser, Subcommand};
use netportal_core::config::{CollectSettings, InitDbSettings, OffboardSettings, PortalSettings};
use netportal_core::{Db, registry};

#[derive(Parser)]
#[command(name = "netportal", version, about = "The house's network access portal")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve the portal (migrates and seeds the registry first)
    Serve {
        /// address and port to listen on (default: NETPORTAL_LISTEN, else 0.0.0.0:8080)
        #[arg(long)]
        bind: Option<String>,
    },
    /// Create or upgrade the schema, apply the radius role's rights, seed the policies
    InitDb,
    /// Reconcile the registry with Authentik once, or forever
    Offboard {
        /// seconds between rounds; 0: one round
        #[arg(long, default_value_t = 0)]
        every: u64,
        /// one round that offboards everyone the directory no longer allows now: no hold on a
        /// mass removal, no second round (after checking the directory)
        #[arg(long, conflicts_with = "every")]
        allow_mass: bool,
    },
    /// The collector: every selected job forever, or once
    Collect {
        /// run every selected job once, then exit
        #[arg(long)]
        once: bool,
        /// comma-separated job names (default: all)
        #[arg(long, default_value = "")]
        jobs: String,
    },
    /// One collector job once (unifi_events, incidents, rollup, prune)
    Job { name: String },
    /// The PKI ceremony: root, device CA and RADIUS server certificate as PEM files
    Pki {
        /// directory for the files (created)
        #[arg(long)]
        out: PathBuf,
        /// the CA names' prefix ("<NAME> Network Root", "<NAME> Device CA")
        #[arg(long, default_value = "Scharni")]
        name: String,
        /// the RADIUS server's name (its certificate's subject)
        #[arg(long)]
        server_name: String,
    },
    /// Healthchecks for the containers (exit 0 healthy, 1 not)
    #[command(subcommand)]
    Health(Health),
}

#[derive(Subcommand)]
enum Health {
    /// GET /healthz of the portal must answer 200
    Web {
        /// address to ask (default: serve's, NETPORTAL_LISTEN or 0.0.0.0:8080, on the loopback)
        #[arg(long)]
        addr: Option<String>,
        /// seconds for the connection and the answer
        #[arg(long, default_value_t = 4)]
        timeout: u64,
    },
    /// A sidecar's heartbeat file must be younger than --max-age
    Heartbeat {
        /// the heartbeat file (the sidecar's NETPORTAL_HEARTBEAT)
        #[arg(long)]
        file: PathBuf,
        /// the largest healthy age in seconds
        #[arg(long)]
        max_age: u64,
    },
}

impl Command {
    fn name(&self) -> &'static str {
        match self {
            Command::Serve { .. } => "serve",
            Command::InitDb => "init-db",
            Command::Offboard { .. } => "offboard",
            Command::Collect { .. } => "collect",
            Command::Job { .. } => "job",
            Command::Pki { .. } => "pki",
            Command::Health(_) => "health",
        }
    }
}

async fn init_db() -> anyhow::Result<i32> {
    let settings = InitDbSettings::load()?;
    let mut db = Db::connect(settings.database_url.expose()).await?;
    let report = registry::init(&mut db, &settings.policies.list).await?;
    db.close().await?;
    match report.version {
        Some(version) => println!("schema ready (version {version})"),
        None => println!("schema ready"),
    }
    Ok(0)
}

async fn run(command: &Command) -> anyhow::Result<i32> {
    match command {
        Command::Serve { bind } => {
            let settings = PortalSettings::load()?;
            let bind = netportal_web::web::listen_address(bind.as_deref());
            netportal_web::web::serve(settings, &bind).await?;
            Ok(0)
        }
        Command::InitDb => init_db().await,
        Command::Offboard { every, allow_mass } => {
            let settings = OffboardSettings::load()?;
            Ok(netportal_offboard::offboarding::run(&settings, *every, *allow_mass).await?)
        }
        Command::Collect { once, jobs } => {
            let settings = CollectSettings::load()?;
            Ok(netportal_collect::scheduler::run(&settings, *once, jobs).await?)
        }
        Command::Job { name } => {
            let settings = CollectSettings::load()?;
            Ok(netportal_collect::scheduler::run_job(&settings, name).await?)
        }
        Command::Pki { out, name, server_name } => Ok(netportal_pki::pki::ceremony(out, name, server_name)?),
        Command::Health(Health::Web { addr, timeout }) => {
            let addr = health::web_address(&netportal_web::web::listen_address(addr.as_deref()))?;
            health::web(addr, Duration::from_secs(*timeout))?;
            Ok(0)
        }
        Command::Health(Health::Heartbeat { file, max_age }) => {
            health::heartbeat(file, Duration::from_secs(*max_age), SystemTime::now())?;
            Ok(0)
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    netportal_core::logging::init();
    match run(&cli.command).await {
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        Err(error) => {
            eprintln!("netportal: {}: {error:#}", cli.command.name());
            ExitCode::FAILURE
        }
    }
}
