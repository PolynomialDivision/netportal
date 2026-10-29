//! The collector's HTTP clients (security review 2026-10-29, I3): an answer larger than
//! `sources::MAX_ANSWER` fails the request instead of filling the memory. Redirects are not
//! followed (the process's client: `scheduler::http`, `redirect::Policy::none`): a 3xx is a
//! failed request. No database needed.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::http::{StatusCode, header};
use netportal_collect::sources::{Budget, MAX_ANSWER, Prometheus};

async fn serve(app: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("addr"));
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    url
}

fn client() -> reqwest::Client {
    reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().expect("client")
}

#[tokio::test]
async fn test_a_huge_answer_fails_the_request() {
    let body = format!(
        r#"{{"status":"success","data":{{"resultType":"vector","result":[]}},"pad":"{}"}}"#,
        "x".repeat(MAX_ANSWER)
    );
    let url = serve(Router::new().fallback(move || {
        let body = body.clone();
        async move { ([(header::CONTENT_TYPE, "application/json")], body) }
    }))
    .await;
    let prometheus =
        Prometheus::new(client(), &url, Duration::from_secs(20), Arc::new(Budget::new(Duration::from_secs(30))));
    let error = prometheus.vector("up", None).await.err().map(|e| e.to_string()).unwrap_or_default();
    assert!(error.contains("reply too large"), "{error}");
}

#[tokio::test]
async fn test_a_redirect_is_a_failure() {
    let url = serve(Router::new().fallback(|| async {
        (StatusCode::TEMPORARY_REDIRECT, [(header::LOCATION, "http://127.0.0.1:9/api/v1/query")])
    }))
    .await;
    let prometheus =
        Prometheus::new(client(), &url, Duration::from_secs(5), Arc::new(Budget::new(Duration::from_secs(10))));
    let error = prometheus.vector("up", None).await.err().map(|e| e.to_string()).unwrap_or_default();
    assert!(error.contains("HTTP 307"), "{error}");
}
