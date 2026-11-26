//! `/healthz` and `/metrics` (INVENTORY 3.2 rows 30-31).

use crate::web::App;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

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

/// Whether `Authorization` carries `Bearer <token>` (the scheme in any case, RFC 9110 11.1).
/// Compared in constant time over SHA-256 digests, so neither the token nor its length leaks.
pub fn bearer_matches(headers: &HeaderMap, token: &str) -> bool {
    let sent = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).unwrap_or("");
    let Some((scheme, value)) = sent.split_once(' ') else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("bearer") {
        return false;
    }
    let sent = Sha256::digest(value.trim().as_bytes());
    let expected = Sha256::digest(token.as_bytes());
    !token.is_empty() && bool::from(sent.as_slice().ct_eq(expected.as_slice()))
}

/// `GET /metrics` on the metrics listener (`NETPORTAL_METRICS_LISTEN`), for Prometheus on the
/// internal network only; a request that came through a reverse proxy is 404 all the same. With
/// `NETPORTAL_METRICS_TOKEN` a request without `Authorization: Bearer <token>` is 401.
pub async fn metrics(State(app): State<App>, headers: HeaderMap) -> Response {
    let proxied = PROXY_HEADERS.iter().any(|h| headers.get(*h).is_some_and(|v| !v.as_bytes().is_empty()));
    if proxied {
        return StatusCode::NOT_FOUND.into_response();
    }
    if let Some(token) = &app.settings.metrics_token
        && !bearer_matches(&headers, token.expose())
    {
        let mut response = text(StatusCode::UNAUTHORIZED, "unauthorized\n");
        response.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer realm=\"metrics\""));
        return response;
    }
    let accept = headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()).unwrap_or("");
    let (content_type, body) = app.metrics.scrape(&app.pool, accept).await;
    (StatusCode::OK, [(header::CONTENT_TYPE, content_type)], body).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bearer_matches() {
        let token = "t".repeat(32);
        let with = |value: &str| {
            let mut h = HeaderMap::new();
            h.insert(header::AUTHORIZATION, HeaderValue::from_str(value).expect("header"));
            h
        };
        assert!(bearer_matches(&with(&format!("Bearer {token}")), &token));
        assert!(bearer_matches(&with(&format!("bearer  {token}")), &token));
        assert!(!bearer_matches(&with(&format!("Basic {token}")), &token));
        assert!(!bearer_matches(&with(&format!("Bearer {token}x")), &token));
        assert!(!bearer_matches(&with(&format!("Bearer {}", &token[1..])), &token));
        assert!(!bearer_matches(&with("Bearer"), &token));
        assert!(!bearer_matches(&HeaderMap::new(), &token));
        assert!(!bearer_matches(&with("Bearer "), ""));
    }
}
