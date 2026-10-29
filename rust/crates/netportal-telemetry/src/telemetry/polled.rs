//! The polled device APIs' ETag, 304 and poll hint (INVENTORY 3.3; Python `web.py` `etag`,
//! `if_none_match`, `polled`), as plain functions the web calls for `/api/devices`,
//! `/api/devices/<id>` and `/api/admin/devices`:
//!
//! ```text
//! let body = serde_json::to_value(&payload)?;
//! let tag = polled::etag(&body);
//! if polled::matches(request.headers().get("If-None-Match"), &tag) { 304, empty body } else { 200, body }
//! // both: ETag: <tag>, Cache-Control: polled::CACHE_CONTROL
//! ```
//!
//! The tag only has to be stable within this implementation (browsers send back what they got);
//! it leaves out the values that change with every request rather than with the data
//! ([`VOLATILE`], at any depth), or every poll would be a 200. The poll hint is the payload's
//! `poll_s` (`live::Dashboard::poll_s`, `live::OneDevice::poll_s`).

use std::collections::BTreeSet;

use serde_json::Value;
use sha2::{Digest, Sha256};

/// What the ETag leaves out: the request's time and ages counted to it; the absolute times stay
/// in (presence's confirmed_at, since; house.wifi_data_at).
pub const VOLATILE: [&str; 4] = ["generated_at", "wifi_data_age_s", "age_s", "associated_s"];

/// The polled answers' `Cache-Control`: nothing in a disk or shared cache (the payloads name
/// devices and MACs). The 304 flow does not need the browser's cache: the page's script
/// (`static/live.js`) keeps the last body and its ETag and sends `If-None-Match` itself
/// (`fetch(..., {cache: "no-store"})`). The login is checked first, every time.
pub const CACHE_CONTROL: &str = "private, no-store";

/// The payload in a canonical form: keys sorted, [`VOLATILE`] keys left out at any depth.
fn canonical(value: &Value, out: &mut String) {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().filter(|k| !VOLATILE.contains(&k.as_str())).collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String((*k).clone()).to_string());
                out.push(':');
                canonical(&map[k.as_str()], out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, v) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical(v, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

/// A weak ETag of a JSON payload: `W/"<first 32 hex digits of SHA-256>"` over its canonical form;
/// the same data, the same tag.
pub fn etag(payload: &Value) -> String {
    let mut body = String::new();
    canonical(payload, &mut body);
    let digest = hex::encode(Sha256::digest(body.as_bytes()));
    format!("W/\"{}\"", &digest[..32])
}

/// The tags of an `If-None-Match` header, each in its weak form (weak and strong compare alike
/// for a GET); `*` is kept as it is (it matches any).
pub fn if_none_match(header: Option<&str>) -> BTreeSet<String> {
    let mut tags = BTreeSet::new();
    for part in header.unwrap_or_default().split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if part == "*" {
            tags.insert("*".to_string());
            continue;
        }
        let strong = part.strip_prefix("W/").unwrap_or(part);
        tags.insert(format!("W/{strong}"));
    }
    tags
}

/// The browser has this tag: answer 304 (empty body, the same ETag and Cache-Control).
pub fn matches(header: Option<&str>, tag: &str) -> bool {
    let tags = if_none_match(header);
    tags.contains("*") || tags.contains(tag)
}
