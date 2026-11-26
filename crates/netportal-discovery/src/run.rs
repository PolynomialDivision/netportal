//! `netportal discovery [--probe]`: the main loop over both legs, the registry reader, the
//! heartbeat and the signals (the pattern of the collector's scheduler), or 30 s of listening
//! that prints everything seen with its source MAC (the owner's check of the macvlan legs on
//! Unraid, design 7.1).

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use netportal_core::config::DiscoverySettings;
use tokio::sync::{mpsc, watch};

use crate::LOG;
use crate::frame::Frame;
use crate::proxy::{BROWSE_EVERY, Proxy};
use crate::registry::{Reader, Snapshot};
use crate::sockets::{Leg, LegKind, MAX_DATAGRAM, RECV_ERROR_PAUSE};
use crate::wire;

/// `--probe` listens this long.
pub const PROBE_SECONDS: u64 = 30;
/// Expiry, re-queries, the heartbeat: every round of this length.
pub const HOUSEKEEPING: Duration = Duration::from_secs(5);
/// The summary line's period.
pub const SUMMARY: Duration = Duration::from_secs(60);

#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    #[error("{iface} ({leg} leg): {source}")]
    Leg { leg: &'static str, iface: String, source: io::Error },
    #[error("signal handlers: {0}")]
    Signals(io::Error),
}

// --- stop flag, heartbeat and signals ------------------------------------------------------------

/// The stop flag (SIGTERM/SIGINT): awaited by the loop instead of polled.
#[derive(Clone, Debug)]
pub struct Stop(Arc<watch::Sender<bool>>);

impl Default for Stop {
    fn default() -> Self {
        Stop(Arc::new(watch::channel(false).0))
    }
}

impl Stop {
    pub fn new() -> Stop {
        Stop::default()
    }

    pub fn set(&self) {
        self.0.send_replace(true);
    }

    pub fn is_set(&self) -> bool {
        *self.0.borrow()
    }

    /// Sleeps `duration` or until the flag is set; returns whether it is set.
    pub async fn wait(&self, duration: Duration) -> bool {
        let mut rx = self.0.subscribe();
        let _ = tokio::time::timeout(duration, rx.wait_for(|set| *set)).await;
        self.is_set()
    }

    /// Waits until the flag is set.
    pub async fn wait_set(&self) {
        let mut rx = self.0.subscribe();
        let _ = rx.wait_for(|set| *set).await;
    }
}

/// Creates the file or sets its modification time to now (a failure is logged).
pub fn touch(path: &Path) {
    let result = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .and_then(|f| f.set_modified(std::time::SystemTime::now()));
    if let Err(e) = result {
        tracing::warn!(target: LOG, "heartbeat {}: {e}", path.display());
    }
}

/// SIGTERM (docker stop) and SIGINT end the loop.
pub fn install_signal_handlers(stop: &Stop) -> io::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    let stop = stop.clone();
    tokio::spawn(async move {
        loop {
            let name = tokio::select! {
                _ = term.recv() => "SIGTERM",
                _ = int.recv() => "SIGINT",
            };
            tracing::info!(target: LOG, "{name}: stopping");
            stop.set();
        }
    });
    Ok(())
}

// --- the engine -----------------------------------------------------------------------------------

/// The reads of the registry, one per `refresh`, delivered to the loop.
pub type RegistryResults = mpsc::Receiver<Result<Snapshot, String>>;

/// Reads the registry every `refresh` until the stop flag is set.
pub fn spawn_registry_reader(url: String, refresh: Duration, extra: Vec<String>, stop: Stop) -> RegistryResults {
    let (tx, rx) = mpsc::channel(4);
    tokio::spawn(async move {
        let mut reader = Reader::new(&url);
        loop {
            let result = reader.read(&extra).await;
            if tx.send(result).await.is_err() {
                break;
            }
            if stop.wait(refresh).await {
                break;
            }
        }
    });
    rx
}

/// The proxy with its legs.
pub struct Engine {
    pub proxy: Proxy,
    pub residents: Leg,
    pub iot: Leg,
    pub registry: RegistryResults,
    pub stop: Stop,
    pub heartbeat: Option<PathBuf>,
}

impl Engine {
    fn beat(&self) {
        if let Some(path) = &self.heartbeat {
            touch(path);
        }
    }

    async fn browse(&self) {
        if let Some(query) = self.proxy.browse_query()
            && let Err(e) = self.iot.send_multicast(&query).await
        {
            tracing::warn!(target: LOG, "browse query not sent: {e}");
        }
    }

    /// The service: until the stop flag is set; returns the exit code 0.
    pub async fn serve(mut self) -> i32 {
        let mut residents_buf = vec![0u8; MAX_DATAGRAM];
        let mut iot_buf = vec![0u8; MAX_DATAGRAM];
        let mut browse = tokio::time::interval(BROWSE_EVERY);
        let mut housekeeping = tokio::time::interval(HOUSEKEEPING);
        let mut summary = tokio::time::interval_at(tokio::time::Instant::now() + SUMMARY, SUMMARY);
        loop {
            tokio::select! {
                received = self.residents.recv(&mut residents_buf) => match received {
                    Ok(Some(frame)) => {
                        for outgoing in self.proxy.on_resident(&frame, Instant::now()) {
                            if let Err(e) = self.residents.send(outgoing).await {
                                tracing::warn!(target: LOG, "answer to {} not sent: {e}", frame.src);
                            }
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        tracing::warn!(target: LOG, "{}: receive failed: {e}", self.residents.iface);
                        tokio::time::sleep(RECV_ERROR_PAUSE).await;
                    }
                },
                received = self.iot.recv(&mut iot_buf) => match received {
                    Ok(Some(frame)) => {
                        self.proxy.on_iot(&frame, Instant::now());
                    }
                    Ok(None) => {}
                    Err(e) => {
                        tracing::warn!(target: LOG, "{}: receive failed: {e}", self.iot.iface);
                        tokio::time::sleep(RECV_ERROR_PAUSE).await;
                    }
                },
                Some(result) = self.registry.recv() => self.proxy.update_registry(result, Instant::now()),
                _ = browse.tick() => self.browse().await,
                _ = housekeeping.tick() => {
                    let now = Instant::now();
                    self.proxy.housekeeping(now);
                    if let Some(query) = self.proxy.requery(now)
                        && let Err(e) = self.iot.send_multicast(&query).await
                    {
                        tracing::warn!(target: LOG, "re-query not sent: {e}");
                    }
                    self.beat();
                },
                _ = summary.tick() => tracing::info!(target: LOG, "{}", self.proxy.summary(Instant::now())),
                _ = self.stop.wait_set() => break,
            }
        }
        tracing::info!(target: LOG, "stopped");
        0
    }

    /// `--probe`: listens `duration` on both legs, prints every datagram with its source MAC
    /// (after one browse query on the IoT leg), the registry's device count and the cache; 0.
    pub async fn probe(mut self, duration: Duration) -> i32 {
        println!(
            "listening {} s: residents' leg {}, IoT leg {}",
            duration.as_secs(),
            self.residents.describe(),
            self.iot.describe()
        );
        self.browse().await;
        let mut residents_buf = vec![0u8; MAX_DATAGRAM];
        let mut iot_buf = vec![0u8; MAX_DATAGRAM];
        let deadline = tokio::time::sleep(duration);
        tokio::pin!(deadline);
        let mut registry_seen = false;
        loop {
            tokio::select! {
                received = self.residents.recv(&mut residents_buf) => if let Ok(Some(frame)) = received {
                    println!("{}", describe_frame(LegKind::Residents, &frame));
                },
                received = self.iot.recv(&mut iot_buf) => if let Ok(Some(frame)) = received {
                    println!("{}", describe_frame(LegKind::Iot, &frame));
                    self.proxy.on_iot(&frame, Instant::now());
                },
                Some(result) = self.registry.recv() => {
                    match &result {
                        Ok(snapshot) if !registry_seen => println!(
                            "registry: {} registered devices with a MAC, {} access rows, {} resident MACs",
                            snapshot.device_count(),
                            snapshot.access_count(),
                            snapshot.resident_mac_count()
                        ),
                        Ok(_) => {}
                        Err(e) => println!("registry: unreadable ({e})"),
                    }
                    registry_seen = registry_seen || result.is_ok();
                    self.proxy.update_registry(result, Instant::now());
                },
                _ = &mut deadline => break,
                _ = self.stop.wait_set() => break,
            }
        }
        if !registry_seen {
            println!("registry: not read within {} s", duration.as_secs());
        }
        let cache = self.proxy.cache();
        println!("cache: {} records from {} sources", cache.len(), cache.sources().count());
        let mut sources: Vec<_> = cache.sources().collect();
        sources.sort_by_key(|s| s.mac);
        for source in sources {
            let who = match self.proxy.registry().snapshot().and_then(|s| s.device_of(source.mac)) {
                Some(device) => format!("{} ({}, {}, {})", device.name, device.owner, device.class, device.visibility),
                None => "unclaimed".to_string(),
            };
            println!("  {} {} {who}: {} records", source.mac, source.addr, source.records.len());
            for cached in &source.records {
                println!("    {}", wire::describe_record(&cached.record));
            }
        }
        0
    }
}

fn describe_frame(leg: LegKind, frame: &Frame<'_>) -> String {
    let what = match wire::parse(frame.payload) {
        Some(message) => wire::describe(&message),
        None => format!("{} bytes, not mDNS", frame.payload.len()),
    };
    format!("{} {} {} -> {}: {what}", leg.name(), frame.src_mac, frame.src, frame.dst)
}

/// The entry point of `netportal discovery`.
pub async fn run(settings: &DiscoverySettings, probe: bool) -> Result<i32, DiscoveryError> {
    let open = |kind: LegKind, iface: &str| {
        Leg::open(kind, iface).map_err(|source| DiscoveryError::Leg {
            leg: kind.name(),
            iface: iface.to_string(),
            source,
        })
    };
    let residents = open(LegKind::Residents, &settings.residents_iface)?;
    let iot = open(LegKind::Iot, &settings.iot_iface)?;
    tracing::info!(target: LOG, "residents' leg {}; IoT leg {}", residents.describe(), iot.describe());
    let stop = Stop::new();
    install_signal_handlers(&stop).map_err(DiscoveryError::Signals)?;
    let registry = spawn_registry_reader(
        settings.database_url.expose().clone(),
        settings.refresh,
        settings.extra_services.clone(),
        stop.clone(),
    );
    let engine = Engine {
        proxy: Proxy::new(settings.ttl, settings.stale_after, &settings.extra_services),
        residents,
        iot,
        registry,
        stop,
        heartbeat: Some(settings.heartbeat.clone()),
    };
    if probe { Ok(engine.probe(Duration::from_secs(PROBE_SECONDS)).await) } else { Ok(engine.serve().await) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::testing::{CAST_MAC, cast_announcement, service};
    use crate::frame::Mac;
    use crate::registry::testing::{device, snapshot};
    use crate::wire::{Message, encode_query, ptr_question};
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket as StdUdpSocket};

    fn loopback_socket() -> StdUdpSocket {
        StdUdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("loopback socket")
    }

    fn v4(socket: &StdUdpSocket) -> SocketAddrV4 {
        match socket.local_addr().unwrap() {
            SocketAddr::V4(a) => a,
            SocketAddr::V6(_) => panic!("v4"),
        }
    }

    /// Real UDP sockets on loopback: the announcement goes to the IoT leg, a legacy query (the
    /// client's port is not 5353) to the residents' leg, and exactly one unicast answer comes
    /// back to the client, from the leg's port. Multicast on loopback is not relied on: the
    /// residents' leg's "multicast" is pointed at the client, where nothing must arrive for a
    /// legacy query.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn end_to_end_over_loopback() {
        let client = loopback_socket();
        client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let client_addr = v4(&client);
        let iot_socket = loopback_socket();
        let iot_addr = v4(&iot_socket);
        let residents_socket = loopback_socket();
        let residents_addr = v4(&residents_socket);
        // the IoT leg's browse queries loop back to itself (seen as queries, ignored), never to the LAN
        let iot = Leg::from_udp(LegKind::Iot, iot_socket, CAST_MAC, iot_addr).unwrap();
        let residents = Leg::from_udp(LegKind::Residents, residents_socket, Mac::ZERO, client_addr).unwrap();
        let (registry_tx, registry) = mpsc::channel(4);
        let stop = Stop::new();
        let engine = Engine {
            proxy: Proxy::new(120, Duration::from_secs(600), &[]),
            residents,
            iot,
            registry,
            stop: stop.clone(),
            heartbeat: None,
        };
        let served = tokio::spawn(engine.serve());
        registry_tx.send(Ok(snapshot(device(CAST_MAC, "alice", "cast", "house")))).await.unwrap();
        client.send_to(&cast_announcement(), iot_addr).unwrap();
        // the announcement must be in the cache before the query: a short wait
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut query = encode_query(vec![ptr_question(service())], vec![]).unwrap();
        query[0] = 0xab;
        query[1] = 0xcd;
        client.send_to(&query, residents_addr).unwrap();
        let mut buf = [0u8; 4096];
        let (n, from) = tokio::task::block_in_place(|| client.recv_from(&mut buf)).expect("an answer within 2 s");
        assert_eq!(from, SocketAddr::V4(residents_addr), "from the residents' leg's port");
        let answer = Message::from_vec(&buf[..n]).unwrap();
        assert_eq!(answer.id, 0xabcd, "the legacy answer carries the query id");
        assert_eq!(answer.queries.len(), 1, "and repeats the question");
        assert_eq!(answer.answers.len() + answer.additionals.len(), 4);
        assert!(answer.all_sections().all(|r| r.ttl == 10 && !r.mdns_cache_flush));
        // nothing else: a legacy query gets no multicast answer
        client.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        assert!(tokio::task::block_in_place(|| client.recv_from(&mut buf)).is_err());
        stop.set();
        assert_eq!(served.await.unwrap(), 0);
    }
}
