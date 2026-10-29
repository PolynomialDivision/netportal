//! Small HTTP helpers: query and form parsing (first value per key, as Werkzeug's `.get`),
//! `Accept` negotiation, path parameters, local return paths, origins, masking for logs.

use indexmap::IndexMap;
use uuid::Uuid;

/// `key=value&...` (form or query), the first value of each key; `+` is a space.
pub fn parse_pairs(raw: &[u8]) -> IndexMap<String, String> {
    let mut out = IndexMap::new();
    for (k, v) in url::form_urlencoded::parse(raw) {
        out.entry(k.into_owned()).or_insert_with(|| v.into_owned());
    }
    out
}

/// The media range of `Accept` the client prefers: the highest q-value, then the most specific,
/// then the first (Werkzeug's `accept_mimetypes.best`); `None` without one.
pub fn best_accept(accept: &str) -> Option<String> {
    let mut best: Option<(f32, u8, String)> = None;
    for part in accept.split(',') {
        let mut pieces = part.split(';');
        let range = pieces.next().unwrap_or("").trim().to_ascii_lowercase();
        if range.is_empty() {
            continue;
        }
        let mut q = 1.0f32;
        for p in pieces {
            if let Some(v) = p.trim().strip_prefix("q=").or_else(|| p.trim().strip_prefix("Q=")) {
                q = v.trim().parse().unwrap_or(0.0);
            }
        }
        if q <= 0.0 {
            continue;
        }
        let specific = match range.as_str() {
            "*/*" => 0,
            r if r.ends_with("/*") => 1,
            _ => 2,
        };
        if best.as_ref().is_none_or(|(bq, bs, _)| q > *bq || (q == *bq && specific > *bs)) {
            best = Some((q, specific, range));
        }
    }
    best.map(|(_, _, r)| r)
}

/// A device id in a URL: the canonical 8-4-4-4-12 hex form in either case (Werkzeug's UUID
/// converter); anything else does not match the route (404).
pub fn device_id(text: &str) -> Option<Uuid> {
    let bytes = text.as_bytes();
    if bytes.len() != 36 || [8, 13, 18, 23].iter().any(|&i| bytes[i] != b'-') {
        return None;
    }
    Uuid::parse_str(text).ok()
}

/// A path the login may return to: local (one leading `/`, not `//` or `/\`, no backslash, no
/// control or space characters), at most 2 KiB. Anything else is no return target (no open
/// redirect).
pub fn safe_local_path(path: &str) -> Option<&str> {
    let b = path.as_bytes();
    let local = b.first() == Some(&b'/')
        && !matches!(b.get(1), Some(b'/') | Some(b'\\'))
        && !path.contains('\\')
        && path.len() <= 2048
        && !path.chars().any(|c| c.is_control() || c.is_whitespace());
    local.then_some(path)
}

/// `scheme://host[:port]` of an http(s) URL, `scheme:` of a custom scheme (the consent page's
/// CSP form-action source for the app's redirect, INVENTORY 3.4).
pub fn origin(uri: &str) -> Option<String> {
    let url = url::Url::parse(uri).ok()?;
    match url.scheme() {
        "http" | "https" => {
            let host = url.host_str()?;
            let host =
                if host.contains(':') && !host.starts_with('[') { format!("[{host}]") } else { host.to_string() };
            Some(match url.port() {
                Some(port) => format!("{}://{host}:{port}", url.scheme()),
                None => format!("{}://{host}", url.scheme()),
            })
        }
        scheme => Some(format!("{scheme}:")),
    }
}

/// A URI with these query parameters added (`&` when it has a query, else `?`), empty values
/// left out (Python `_with_query`).
pub fn with_query(uri: &str, params: &[(&str, &str)]) -> String {
    let mut ser = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in params {
        if !v.is_empty() {
            ser.append_pair(k, v);
        }
    }
    let query = ser.finish();
    if query.is_empty() {
        return uri.to_string();
    }
    let sep = if uri.contains('?') { '&' } else { '?' };
    format!("{uri}{sep}{query}")
}

/// A request path as it may appear in a log line: the one-time download token masked
/// (INVENTORY 4.9).
pub fn loggable_path(path: &str) -> String {
    match path.strip_prefix("/download/") {
        Some(_) => "/download/***".to_string(),
        None => path.chars().take(200).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_pairs() {
        let p = parse_pairs(b"a=1&b=x+y&a=2&c=%C3%A4&csrf=");
        assert_eq!(p["a"], "1");
        assert_eq!(p["b"], "x y");
        assert_eq!(p["c"], "ä");
        assert_eq!(p["csrf"], "");
    }

    #[test]
    fn test_best_accept() {
        assert_eq!(best_accept("application/json").as_deref(), Some("application/json"));
        assert_eq!(best_accept("text/html, application/json;q=0.5").as_deref(), Some("text/html"));
        assert_eq!(best_accept("application/json;q=0.9, text/html;q=0.8").as_deref(), Some("application/json"));
        assert_eq!(best_accept("*/*, application/json").as_deref(), Some("application/json"));
        assert_eq!(best_accept("*/*").as_deref(), Some("*/*"));
        assert_eq!(best_accept("application/json;q=0").as_deref(), None);
        assert_eq!(best_accept("").as_deref(), None);
    }

    #[test]
    fn test_device_id() {
        let id = "0f8e1c2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b";
        assert!(device_id(id).is_some());
        assert!(device_id(&id.to_uppercase()).is_some());
        assert!(device_id("0f8e1c2a3b4d4e5f8a9b0c1d2e3f4a5b").is_none());
        assert!(device_id("{0f8e1c2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b}").is_none());
        assert!(device_id("not-a-uuid").is_none());
        assert!(device_id("1234").is_none());
    }

    #[test]
    fn test_safe_local_path() {
        assert_eq!(safe_local_path("/admin?q=x"), Some("/admin?q=x"));
        assert_eq!(safe_local_path("/"), Some("/"));
        for bad in
            ["//evil.example/", "/\\evil.example", "https://evil.example/", "", "admin", "/a b", "/a\nb", "/x\\y"]
        {
            assert_eq!(safe_local_path(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn test_origin() {
        assert_eq!(origin("http://127.0.0.1:4711/callback").as_deref(), Some("http://127.0.0.1:4711"));
        assert_eq!(origin("http://[::1]:5555/").as_deref(), Some("http://[::1]:5555"));
        assert_eq!(origin("http://127.0.0.1/").as_deref(), Some("http://127.0.0.1"));
        assert_eq!(origin("app.eduroam.geteduroam:/").as_deref(), Some("app.eduroam.geteduroam:"));
    }

    #[test]
    fn test_with_query() {
        assert_eq!(with_query("app:/", &[("code", "c"), ("state", "")]), "app:/?code=c");
        assert_eq!(
            with_query("http://127.0.0.1:1/cb?x=1", &[("error", "invalid_request")]),
            "http://127.0.0.1:1/cb?x=1&error=invalid_request"
        );
        assert_eq!(with_query("app:/", &[("state", "a b&c")]), "app:/?state=a+b%26c");
    }

    #[test]
    fn test_loggable_path() {
        assert_eq!(loggable_path("/download/abc"), "/download/***");
        assert_eq!(loggable_path("/admin"), "/admin");
    }
}
