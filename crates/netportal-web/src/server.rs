//! The HTTP/1.1 server under both listeners (the portal's and `/metrics`'), through hyper's
//! connection builder instead of `axum::serve`, for the limits `axum::serve` does not offer
//! (owner's review 2026-10-29, the open point of the security review):
//!
//! - **Header read timeout** ([`Limits::header_read`], 10 s): a client must send a request's
//!   whole head within it, or the connection is closed (slowloris). hyper starts the same timer
//!   when a keep-alive connection goes idle, so it is also the **idle limit** between two
//!   requests on one connection;
//! - **request body** read within `web::BODY_READ_TIMEOUT` (10 s, 408) and at most
//!   `web::BODY_LIMIT` (64 KiB, 413): the router's [`crate::pipeline::read_body`];
//! - each request at most `web::REQUEST_TIMEOUT` (60 s, 503), load shedding
//!   (`NETPORTAL_MAX_REQUESTS`): the router's layers as before;
//! - **graceful shutdown**: at the stop signal the listener closes, idle connections close, and
//!   requests in progress finish (each at most `web::REQUEST_TIMEOUT`); after
//!   [`Limits::shutdown`] the rest are dropped.
//!
//! HTTP/1.1 only (Caddy and Prometheus speak it; no h2c), no upgrades.

use std::future::Future;
use std::time::Duration;

use axum::Router;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;

const LOG: &str = "netportal.web";

/// The connection limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// a request's head (request line and headers) must arrive within this; also the idle
    /// limit of a keep-alive connection
    pub header_read: Duration,
    /// how long requests in progress may finish after the stop signal
    pub shutdown: Duration,
}

/// The production limits: 10 s for a request's head (and keep-alive idle), 65 s to finish.
pub const LIMITS: Limits = Limits { header_read: Duration::from_secs(10), shutdown: Duration::from_secs(65) };

/// Serve `router` on `listener` until `stop` completes, then shut down gracefully.
pub async fn serve(
    listener: TcpListener,
    router: Router,
    limits: Limits,
    stop: impl Future<Output = ()>,
) -> std::io::Result<()> {
    let mut builder = http1::Builder::new();
    builder.timer(TokioTimer::new()).header_read_timeout(limits.header_read).keep_alive(true);
    let graceful = GracefulShutdown::new();
    let mut stop = std::pin::pin!(stop);
    loop {
        let accepted = tokio::select! {
            biased;
            () = &mut stop => break,
            accepted = listener.accept() => accepted,
        };
        let stream = match accepted {
            Ok((stream, _)) => stream,
            Err(e) => {
                // EMFILE and friends: wait a moment instead of spinning
                tracing::warn!(target: LOG, "accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let service = TowerToHyperService::new(router.clone());
        let connection = graceful.watch(builder.serve_connection(TokioIo::new(stream), service));
        tokio::spawn(async move {
            // a client that went away or a head that took too long: nothing to report
            if let Err(e) = connection.await {
                tracing::debug!(target: LOG, "connection ended: {e}");
            }
        });
    }
    drop(listener);
    tokio::select! {
        () = graceful.shutdown() => {}
        () = tokio::time::sleep(limits.shutdown) => {
            tracing::warn!(target: LOG, "requests still running after {} s: stopping anyway", limits.shutdown.as_secs());
        }
    }
    Ok(())
}
