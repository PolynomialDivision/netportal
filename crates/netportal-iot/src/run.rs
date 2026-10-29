//! `netportal iot [--every SECONDS]`: one round, or a round every `every` seconds until
//! SIGTERM/SIGINT (the pattern of `netportal-offboard/src/offboarding.rs` and the collector's
//! scheduler). The heartbeat file (`NETPORTAL_HEARTBEAT`) is touched after every round, also a
//! failed one: it says the sidecar is alive; whether rounds succeed is the job row `iot`.
//! Without UniFi or OPNsense configured the round skips that backend (said once at the start;
//! its `iot_sync` rows stay pending).

use std::future::Future;
use std::path::Path;
use std::time::{Duration, SystemTime};

use netportal_core::config::IotSettings;

use crate::opnsense::OpnsenseClient;
use crate::reconcile::{self, Backends, IotError, Memory, RoundReport};
use crate::unifi::UnifiClient;

const LOG: &str = "netportal.iot";

/// Create the heartbeat file or set its modification time to now.
pub fn touch(path: &Path) -> Result<(), IotError> {
    let error = |error| IotError::Heartbeat { path: path.display().to_string(), error };
    let file = std::fs::OpenOptions::new().create(true).append(true).open(path).map_err(error)?;
    file.set_modified(SystemTime::now()).map_err(error)
}

fn log_report(report: &RoundReport) {
    if report.wrote() || report.shares_dropped > 0 || report.devices_revoked > 0 {
        tracing::info!(
            target: LOG,
            "round: {} device(s), {} share(s); keys {}, blocked {}, kicked {}, unblocked {}, aliases {}, rules {}, \
             states killed {}; offboarding dropped {} share(s), revoked {} device(s); sync pending {}, failed {}; \
             address conflicts {}",
            report.devices,
            report.shares,
            if report.keys_written { "written" } else { "unchanged" },
            report.blocked,
            report.kicked,
            report.unblocked,
            report.aliases_changed,
            report.rules_changed,
            report.states_killed,
            report.shares_dropped,
            report.devices_revoked,
            report.sync_pending,
            report.sync_failed,
            report.address_conflicts
        );
    } else {
        tracing::debug!(target: LOG, "round: nothing to do ({} device(s), {} share(s))", report.devices, report.shares);
    }
}

/// One round (`every` 0, `Ok(0)` or its error) or the loop (`Ok(0)` at the first signal).
pub async fn run(settings: &IotSettings, every: u64) -> Result<i32, IotError> {
    let unifi = UnifiClient::new(settings)?;
    let opnsense = OpnsenseClient::new(settings)?;
    if unifi.is_none() {
        tracing::warn!(target: LOG, "UniFi is not configured (NETPORTAL_UNIFI_URL, _USER, _PASSWORD): keys, kicks and blocks are skipped");
    }
    if opnsense.is_none() {
        tracing::warn!(target: LOG, "OPNsense is not configured (NETPORTAL_OPNSENSE_URL, _API_KEY, _API_SECRET): aliases, rules and states are skipped");
    }
    let backends = Backends { unifi: unifi.as_ref(), opnsense: opnsense.as_ref() };
    let mut memory = Memory::default();
    if every == 0 {
        let result = reconcile::round(settings, &backends, &mut memory).await;
        let beat = touch(&settings.heartbeat);
        log_report(&result?);
        beat?;
        return Ok(0);
    }
    let signal = shutdown_signal().map_err(IotError::Signal)?;
    Ok(run_loop(settings, &backends, &mut memory, Duration::from_secs(every), signal).await)
}

/// Rounds every `every` until `stop` completes (checked between rounds: a round in progress
/// finishes). Returns the exit code 0.
pub async fn run_loop(
    settings: &IotSettings,
    backends: &Backends<'_>,
    memory: &mut Memory,
    every: Duration,
    stop: impl Future<Output = ()>,
) -> i32 {
    let mut stop = std::pin::pin!(stop);
    loop {
        match reconcile::round(settings, backends, memory).await {
            Ok(report) => log_report(&report),
            Err(e) => tracing::error!(target: LOG, "round failed: {e}"),
        }
        if let Err(e) = touch(&settings.heartbeat) {
            tracing::error!(target: LOG, "{e}");
        }
        tokio::select! {
            biased;
            () = &mut stop => {
                tracing::info!(target: LOG, "stopping");
                return 0;
            }
            () = tokio::time::sleep(every) => {}
        }
    }
}

/// Completes at the first SIGTERM or SIGINT (registered now, so a signal during a round is not
/// lost). The container's PID 1 has no default action for SIGTERM, so this is the clean stop.
fn shutdown_signal() -> std::io::Result<impl Future<Output = ()>> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    Ok(async move {
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
        }
    })
}
