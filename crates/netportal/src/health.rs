//! `netportal health …`: the containers' healthchecks, without a shell, curl or find in the image
//! (house-infra stacks/netaccess runs them as exec-form `CMD`s; Python: `curl -fsS /healthz` and
//! `find <heartbeat> -mmin -N | grep -q .`).
//!
//! - `health web [--addr HOST:PORT]`: `GET /healthz` must answer 200 within the timeout. The
//!   address defaults to what `serve` listens on (`NETPORTAL_LISTEN`, else `0.0.0.0:8080`), an
//!   unspecified address (`0.0.0.0`, `::`) asked on the loopback of its family.
//! - `health heartbeat --file FILE --max-age SECONDS`: the sidecar's heartbeat file
//!   (`NETPORTAL_HEARTBEAT`) was modified at most SECONDS ago; a time in the future (the clock
//!   went back) counts as fresh.
//!
//! Success prints nothing and exits 0; a failure is one line on stderr and exit 1 (Docker keeps
//! the output in the container's health log).

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::path::Path;
use std::time::{Duration, SystemTime};

use anyhow::{Context, bail};

/// The address `health web` asks: `serve`'s listen address with an unspecified IP replaced by the
/// loopback address of the same family.
pub fn web_address(listen: &str) -> anyhow::Result<SocketAddr> {
    let mut addr: SocketAddr =
        listen.parse().map_err(|_| anyhow::anyhow!("{listen:?} is not host:port (--addr / NETPORTAL_LISTEN)"))?;
    if addr.ip().is_unspecified() {
        addr.set_ip(match addr.ip() {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
        });
    }
    Ok(addr)
}

/// `GET /healthz` over plain HTTP/1.1; Ok when the status is 200.
pub fn web(addr: SocketAddr, timeout: Duration) -> anyhow::Result<()> {
    let mut stream = TcpStream::connect_timeout(&addr, timeout).with_context(|| format!("connect {addr}"))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let request =
        format!("GET /healthz HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nUser-Agent: netportal-health\r\n\r\n");
    stream.write_all(request.as_bytes()).with_context(|| format!("send to {addr}"))?;
    // The status line is all that counts; read until it is complete (or 1 KiB, or the end).
    let mut head = Vec::with_capacity(256);
    let mut buf = [0u8; 256];
    while !head.contains(&b'\n') && head.len() < 1024 {
        let n = stream.read(&mut buf).with_context(|| format!("read from {addr}"))?;
        if n == 0 {
            break;
        }
        head.extend_from_slice(&buf[..n]);
    }
    let line = String::from_utf8_lossy(&head);
    let line = line.lines().next().unwrap_or_default().trim();
    let status = line.strip_prefix("HTTP/1.1 ").or_else(|| line.strip_prefix("HTTP/1.0 "));
    match status.and_then(|rest| rest.split(' ').next()) {
        Some("200") => Ok(()),
        Some(code) => bail!("/healthz answered {code}"),
        None => bail!("/healthz: no HTTP answer"),
    }
}

/// The heartbeat file is at most `max_age` old.
pub fn heartbeat(file: &Path, max_age: Duration, now: SystemTime) -> anyhow::Result<()> {
    let modified =
        std::fs::metadata(file).and_then(|m| m.modified()).with_context(|| format!("heartbeat {}", file.display()))?;
    let age = now.duration_since(modified).unwrap_or(Duration::ZERO);
    if age > max_age {
        bail!("heartbeat {} is {} s old (at most {} s)", file.display(), age.as_secs(), max_age.as_secs());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn test_web_address() {
        assert_eq!(web_address("0.0.0.0:8080").unwrap(), "127.0.0.1:8080".parse().unwrap());
        assert_eq!(web_address("[::]:9000").unwrap(), "[::1]:9000".parse().unwrap());
        assert_eq!(web_address("10.0.0.5:8080").unwrap(), "10.0.0.5:8080".parse().unwrap());
        assert!(web_address("localhost").is_err());
    }

    /// One connection answered with `answer`, on a free loopback port.
    fn server(answer: &'static [u8]) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut conn, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let n = conn.read(&mut buf).unwrap_or(0);
                assert!(String::from_utf8_lossy(&buf[..n]).starts_with("GET /healthz HTTP/1.1\r\n"));
                let _ = conn.write_all(answer);
            }
        });
        addr
    }

    #[test]
    fn test_web() {
        let t = Duration::from_secs(2);
        assert!(web(server(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok"), t).is_ok());
        let err = web(server(b"HTTP/1.1 503 Service Unavailable\r\n\r\n"), t).unwrap_err();
        assert_eq!(err.to_string(), "/healthz answered 503");
        assert!(web(server(b"garbage"), t).is_err());
        assert!(web(server(b""), t).is_err());
        // nothing listening
        let free = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        assert!(web(free, t).is_err());
    }

    #[test]
    fn test_heartbeat() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("beat");
        let max = Duration::from_secs(600);
        assert!(heartbeat(&file, max, SystemTime::now()).is_err(), "missing file");
        std::fs::write(&file, b"").unwrap();
        let now = SystemTime::now();
        assert!(heartbeat(&file, max, now).is_ok());
        assert!(heartbeat(&file, max, now + Duration::from_secs(599)).is_ok());
        let err = heartbeat(&file, max, now + Duration::from_secs(700)).unwrap_err();
        assert!(err.to_string().contains("(at most 600 s)"), "{err}");
        // a modification time ahead of the clock is fresh
        assert!(heartbeat(&file, max, now - Duration::from_secs(3600)).is_ok());
    }
}
