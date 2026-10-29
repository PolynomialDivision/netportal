//! The connections (`netportal_web::server`, owner's review 2026-10-29): a client sending its
//! request head slowly (slowloris) is cut off after the header read timeout, an idle keep-alive
//! connection too; normal requests and keep-alive work; a slow body is answered 408; at the stop
//! a request in progress finishes and new connections are refused. Real sockets on 127.0.0.1,
//! short limits; no registry needed.

use std::time::{Duration, Instant};

use axum::Router;
use axum::middleware;
use axum::routing::{get, post};
use netportal_web::server::{self, LIMITS, Limits};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const SHORT: Limits = Limits { header_read: Duration::from_millis(800), shutdown: Duration::from_secs(5) };

fn app() -> Router {
    Router::new()
        .route("/", get(|| async { "hello" }))
        .route(
            "/slow",
            get(|| async {
                tokio::time::sleep(Duration::from_millis(700)).await;
                "done"
            }),
        )
        .route("/echo", post(|body: axum::body::Bytes| async move { format!("{} bytes", body.len()) }))
        .layer(middleware::from_fn(|req, next| {
            netportal_web::pipeline::read_body_within(Duration::from_millis(600), req, next)
        }))
}

struct Running {
    addr: std::net::SocketAddr,
    stop: tokio::sync::oneshot::Sender<()>,
    done: tokio::task::JoinHandle<std::io::Result<()>>,
}

async fn start(limits: Limits) -> Running {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("address");
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let done = tokio::spawn(server::serve(listener, app(), limits, async move {
        let _ = stopped.await;
    }));
    Running { addr, stop, done }
}

/// Everything the server sends until it closes the connection (or `wait` passes).
async fn read_all(stream: &mut TcpStream, wait: Duration) -> (String, bool) {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    let deadline = Instant::now() + wait;
    loop {
        match tokio::time::timeout_at(deadline.into(), stream.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => return (String::from_utf8_lossy(&out).into_owned(), true),
            Ok(Ok(n)) => out.extend_from_slice(&buf[..n]),
            Err(_) => return (String::from_utf8_lossy(&out).into_owned(), false),
        }
    }
}

/// One response on a keep-alive connection (up to the end of its body "hello" / "done" / "N bytes").
async fn read_response(stream: &mut TcpStream) -> String {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n =
            tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await.expect("in time").expect("read");
        assert!(n > 0, "closed early: {}", String::from_utf8_lossy(&out));
        out.extend_from_slice(&buf[..n]);
        let text = String::from_utf8_lossy(&out).into_owned();
        if let Some((head, body)) = text.split_once("\r\n\r\n") {
            let length = head
                .lines()
                .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().to_string()))
                .and_then(|v| v.parse::<usize>().ok());
            if length.is_some_and(|n| body.len() >= n) {
                return text;
            }
        }
    }
}

#[tokio::test]
async fn test_the_production_limits() {
    assert_eq!(LIMITS.header_read, Duration::from_secs(10));
    assert!(LIMITS.shutdown > netportal_web::web::REQUEST_TIMEOUT);
    assert_eq!(netportal_web::web::BODY_READ_TIMEOUT, Duration::from_secs(10));
}

#[tokio::test]
async fn test_a_slow_request_head_is_cut_off() {
    let server = start(SHORT).await;
    let mut slow = TcpStream::connect(server.addr).await.expect("connect");
    let started = Instant::now();
    slow.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n").await.expect("write");
    // one more header byte now and then, never the end of the head
    let mut cut = false;
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if slow.write_all(b"X").await.is_err() {
            cut = true;
            break;
        }
        let mut probe = [0u8; 64];
        if let Ok(Ok(0)) = tokio::time::timeout(Duration::from_millis(1), slow.read(&mut probe)).await {
            cut = true;
            break;
        }
    }
    let (answer, closed) = read_all(&mut slow, Duration::from_secs(2)).await;
    assert!(cut || closed, "the connection stayed open");
    assert!(!answer.contains("hello"), "{answer}");
    assert!(started.elapsed() < Duration::from_secs(3), "{:?}", started.elapsed());
    // meanwhile a normal client is served
    let mut ok = TcpStream::connect(server.addr).await.expect("connect");
    ok.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await.expect("write");
    assert!(read_response(&mut ok).await.ends_with("hello"));
    let _ = server.stop.send(());
}

#[tokio::test]
async fn test_keep_alive_works_and_an_idle_connection_is_closed() {
    let server = start(SHORT).await;
    let mut conn = TcpStream::connect(server.addr).await.expect("connect");
    for _ in 0..3 {
        conn.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await.expect("write");
        let answer = read_response(&mut conn).await;
        assert!(answer.starts_with("HTTP/1.1 200") && answer.ends_with("hello"), "{answer}");
        tokio::time::sleep(Duration::from_millis(300)).await; // within the limit
    }
    // idle longer than the limit: closed by the server
    let started = Instant::now();
    let (rest, closed) = read_all(&mut conn, Duration::from_secs(3)).await;
    assert!(closed && rest.is_empty(), "{rest:?}");
    assert!(started.elapsed() < Duration::from_secs(2));
    let _ = server.stop.send(());
}

#[tokio::test]
async fn test_a_slow_body_is_answered_408() {
    let server = start(SHORT).await;
    let mut conn = TcpStream::connect(server.addr).await.expect("connect");
    conn.write_all(b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n0123456789").await.expect("write");
    let (answer, _) = read_all(&mut conn, Duration::from_secs(3)).await;
    assert!(answer.starts_with("HTTP/1.1 408"), "{answer}");
    // a whole body in time is served
    let mut conn = TcpStream::connect(server.addr).await.expect("connect");
    conn.write_all(b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nabcde").await.expect("write");
    assert!(read_response(&mut conn).await.ends_with("5 bytes"));
    let _ = server.stop.send(());
}

#[tokio::test]
async fn test_the_stop_lets_requests_in_progress_finish() {
    let server = start(SHORT).await;
    let mut busy = TcpStream::connect(server.addr).await.expect("connect");
    busy.write_all(b"GET /slow HTTP/1.1\r\nHost: x\r\n\r\n").await.expect("write");
    let mut idle = TcpStream::connect(server.addr).await.expect("connect");
    idle.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await.expect("write");
    assert!(read_response(&mut idle).await.ends_with("hello"));
    tokio::time::sleep(Duration::from_millis(100)).await;
    let _ = server.stop.send(());
    // the slow request still gets its answer; the idle keep-alive connection is closed
    assert!(read_response(&mut busy).await.ends_with("done"));
    let (_, closed) = read_all(&mut idle, Duration::from_secs(2)).await;
    assert!(closed);
    let finished = tokio::time::timeout(Duration::from_secs(3), server.done).await.expect("stopped");
    assert!(finished.expect("task").is_ok());
    // nothing listens any more
    assert!(TcpStream::connect(server.addr).await.is_err());
}
