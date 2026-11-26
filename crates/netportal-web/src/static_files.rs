//! `/static/<file>` (INVENTORY 3.2 row 32, 12.3): the dashboard's ES modules and the stylesheet,
//! served from `crates/netportal-web/static/` (embedded at build time: the image needs no
//! files). A fixed list, so nothing else (no path traversal) can be served. `Cache-Control:
//! no-cache` with a strong `ETag` (SHA-256 of the content) and 304 for a matching
//! `If-None-Match`, as Flask did (there is no cache-busting in the URLs, so `no-cache` stays);
//! JavaScript as `text/javascript` (module scripts need a JavaScript MIME type under `nosniff`).

use std::sync::LazyLock;

use axum::extract::Path;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use sha2::{Digest, Sha256};

macro_rules! asset {
    ($name:literal) => {
        ($name, include_bytes!(concat!("../static/", $name)).as_slice())
    };
}

const FILES: [(&str, &[u8]); 8] = [
    asset!("style.css"),
    asset!("dashboard.js"),
    asset!("live.js"),
    asset!("format.js"),
    asset!("presence.js"),
    asset!("render.js"),
    asset!("admin.js"),
    asset!("charts.js"),
];

struct Asset {
    name: &'static str,
    body: &'static [u8],
    etag: String,
    content_type: &'static str,
}

static ASSETS: LazyLock<Vec<Asset>> = LazyLock::new(|| {
    FILES
        .iter()
        .map(|(name, body)| Asset {
            name,
            body,
            etag: format!("\"{}\"", &hex::encode(Sha256::digest(body))[..32]),
            content_type: if name.ends_with(".css") {
                "text/css; charset=utf-8"
            } else {
                "text/javascript; charset=utf-8"
            },
        })
        .collect()
});

fn not_modified(headers: &HeaderMap, etag: &str) -> bool {
    let Some(value) = headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    value.split(',').map(str::trim).any(|t| t == "*" || t == etag || t.strip_prefix("W/") == Some(etag))
}

/// `GET /static/<file>`.
pub async fn serve(Path(name): Path<String>, headers: HeaderMap) -> Response {
    let Some(asset) = ASSETS.iter().find(|a| a.name == name) else {
        // empty: the outer layer renders the 404 page
        return StatusCode::NOT_FOUND.into_response();
    };
    let etag = HeaderValue::from_str(&asset.etag).unwrap_or(HeaderValue::from_static("\"x\""));
    let mut response = if not_modified(&headers, &asset.etag) {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        ([(header::CONTENT_TYPE, asset.content_type)], asset.body).into_response()
    };
    response.headers_mut().insert(header::ETAG, etag);
    response.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_every_file_is_there() {
        assert_eq!(ASSETS.len(), 8);
        for a in ASSETS.iter() {
            assert!(!a.body.is_empty(), "{}", a.name);
            assert_eq!(a.etag.len(), 34);
        }
    }

    #[test]
    fn test_not_modified() {
        let mut headers = HeaderMap::new();
        headers.insert(header::IF_NONE_MATCH, HeaderValue::from_static("\"abc\", W/\"def\""));
        assert!(not_modified(&headers, "\"def\""));
        assert!(not_modified(&headers, "\"abc\""));
        assert!(!not_modified(&headers, "\"xyz\""));
    }
}
