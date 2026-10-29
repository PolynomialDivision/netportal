//! `/healthz` and `/metrics` (INVENTORY 3.2 rows 30-31).

use crate::web::App;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};

/// Headers a reverse proxy adds: a request carrying one came through Caddy, not from Prometheus
/// on the internal network.
const PROXY_HEADERS: [&str; 5] = ["x-forwarded-for", "forwarded", "x-forwarded-host", "x-forwarded-proto", "x-real-ip"];

fn text(status: StatusCode, body: &'static str) -> Response {
    (status, [(header::CONTENT_TYPE, "text/plain; charset=utf-8")], body).into_response()
}

/// `GET /healthz` (the container's healthcheck, `netportal health web`): `ok` while the process
/// serves and the registry answered its latest check, else 503 `unavailable`. The registry is
/// asked at most every 10 s (every 2 s after a failure), through the pool and within 2 s
/// ([`App::registry_ok`]); requests in between get that answer, so a flood of `/healthz` takes
/// at most one connection now and then, and the load shedding does not count it.
pub async fn healthz(State(app): State<App>) -> Response {
    if app.registry_ok().await {
        text(StatusCode::OK, "ok\n")
    } else {
        text(StatusCode::SERVICE_UNAVAILABLE, "unavailable\n")
    }
}

/// `GET /metrics` on the metrics listener (`NETPORTAL_METRICS_LISTEN`), for Prometheus on the
/// internal network only; a request that came through a reverse proxy is 404 all the same.
pub async fn metrics(State(app): State<App>, headers: HeaderMap) -> Response {
    let proxied = PROXY_HEADERS.iter().any(|h| headers.get(*h).is_some_and(|v| !v.as_bytes().is_empty()));
    if proxied {
        return StatusCode::NOT_FOUND.into_response();
    }
    let accept = headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()).unwrap_or("");
    let (content_type, body) = app.metrics.scrape(&app.pool, accept).await;
    (StatusCode::OK, [(header::CONTENT_TYPE, content_type)], body).into_response()
}
