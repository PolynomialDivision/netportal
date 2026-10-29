//! Error answers (INVENTORY 3.6, 4.7). A handler returns a [`Reject`]; it becomes an empty
//! response that carries the rejection, and the request pipeline (which knows the language, the
//! session and whether the request wants JSON) renders it: the message page or
//! `{"error": code}`. Nothing about the cause reaches the client; causes are logged by kind only
//! (never SQL text, values, tokens or URLs with tokens, INVENTORY 4.9).

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use axum::Json;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use netportal_core::registry::RegistryError;
use serde_json::json;

const LOG: &str = "netportal.web";

/// A warning a flood would repeat for every request (load shedding, a busy pool, a registry
/// outage): written at most once per [`Sparse::INTERVAL_MS`], with the number left out since, so
/// the log cannot be flooded (security review 2026-10-29, H1).
pub struct Sparse {
    next_at_ms: AtomicI64,
    left_out: AtomicU64,
}

impl Sparse {
    pub const INTERVAL_MS: i64 = 10_000;

    pub const fn new() -> Sparse {
        Sparse { next_at_ms: AtomicI64::new(0), left_out: AtomicU64::new(0) }
    }

    /// `Some(left out since the last line)` when a line is due at `now_ms` (Unix milliseconds),
    /// else `None` (counted).
    pub fn due_at(&self, now_ms: i64) -> Option<u64> {
        let next = self.next_at_ms.load(Ordering::Relaxed);
        if now_ms >= next
            && self
                .next_at_ms
                .compare_exchange(next, now_ms + Self::INTERVAL_MS, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            return Some(self.left_out.swap(0, Ordering::Relaxed));
        }
        self.left_out.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// [`Sparse::due_at`] now.
    pub fn due(&self) -> Option<u64> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
            .unwrap_or(0);
        self.due_at(now)
    }
}

impl Default for Sparse {
    fn default() -> Self {
        Sparse::new()
    }
}

/// " (N more like it not logged)" for a [`Sparse`] line.
pub fn left_out(n: u64) -> String {
    if n == 0 { String::new() } else { format!(" ({n} more like it not logged)") }
}

static UNREACHABLE: Sparse = Sparse::new();

/// Why a request is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reject {
    /// not logged in (a page): 302 `/login` (the return target is in the session already)
    Login,
    /// 400, 403, 404, 405, 413: the message page with `t.error`, or the JSON code of the status
    Status(StatusCode),
    /// a JSON error with its own code, whatever the request (`login_required`, `bad_range`, ...)
    Json(StatusCode, &'static str),
    /// the message page with this text key (`no_access`), JSON: the status's code
    Message(StatusCode, &'static str),
    /// the registry is unreachable: 503
    Unavailable,
    /// anything else: 500 (logged)
    Internal,
}

impl Reject {
    pub fn status(&self) -> StatusCode {
        match self {
            Reject::Login => StatusCode::FOUND,
            Reject::Status(s) | Reject::Json(s, _) | Reject::Message(s, _) => *s,
            Reject::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            Reject::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn not_found() -> Reject {
        Reject::Status(StatusCode::NOT_FOUND)
    }

    pub fn bad_request() -> Reject {
        Reject::Status(StatusCode::BAD_REQUEST)
    }

    pub fn forbidden() -> Reject {
        Reject::Status(StatusCode::FORBIDDEN)
    }
}

/// The JSON code of a status (3.6).
pub fn status_code_name(status: StatusCode) -> &'static str {
    match status.as_u16() {
        400 => "bad_request",
        401 => "login_required",
        403 => "forbidden",
        404 => "not_found",
        405 => "method_not_allowed",
        409 => "conflict",
        413 => "too_large",
        429 => "too_many_requests",
        503 => "unavailable",
        _ => "internal_error",
    }
}

/// `{"error": code}` with the status (also for the machine endpoints).
pub fn json_error(status: StatusCode, code: &str) -> Response {
    (status, Json(json!({ "error": code }))).into_response()
}

/// The marker a rejected response carries until the pipeline renders it.
#[derive(Debug, Clone)]
pub struct Rejected(pub Reject);

impl IntoResponse for Reject {
    fn into_response(self) -> Response {
        let mut response = self.status().into_response();
        response.headers_mut().remove(header::CONTENT_TYPE);
        response.extensions_mut().insert(Rejected(self));
        response
    }
}

impl From<RegistryError> for Reject {
    fn from(error: RegistryError) -> Self {
        match &error {
            RegistryError::Db(e) if is_connection_error(e) => {
                if let Some(n) = UNREACHABLE.due() {
                    tracing::error!(target: LOG, "registry unreachable: {}{}", db_kind(e), left_out(n));
                }
                Reject::Unavailable
            }
            RegistryError::Db(e) => {
                tracing::error!(target: LOG, "registry error: {}", db_kind(e));
                Reject::Internal
            }
            RegistryError::Migrate(_) => {
                tracing::error!(target: LOG, "registry error: migration");
                Reject::Internal
            }
            RegistryError::Invalid(_) | RegistryError::Conflict(_) => {
                tracing::error!(target: LOG, "registry error: {}", error);
                Reject::Internal
            }
        }
    }
}

impl From<sqlx::Error> for Reject {
    fn from(error: sqlx::Error) -> Self {
        Reject::from(RegistryError::Db(error))
    }
}

/// A connection that could not be made or was lost (the registry is down, not a bug).
pub fn is_connection_error(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Io(_) | sqlx::Error::Tls(_) | sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed)
        || matches!(e, sqlx::Error::Database(d) if d.code().is_some_and(|c| c.starts_with("08") || c.starts_with("57P")))
        || matches!(e, sqlx::Error::Protocol(_))
}

/// A database error by kind, for the log: SQLSTATE codes and variant names, never messages
/// (they can hold values).
pub fn db_kind(e: &sqlx::Error) -> String {
    match e {
        sqlx::Error::Database(d) => format!("database error {}", d.code().as_deref().unwrap_or("?")),
        sqlx::Error::Io(io) => format!("i/o: {}", io.kind()),
        sqlx::Error::Tls(_) => "tls".into(),
        sqlx::Error::Protocol(_) => "protocol".into(),
        sqlx::Error::RowNotFound => "row not found".into(),
        sqlx::Error::ColumnDecode { .. } | sqlx::Error::Decode(_) => "decode".into(),
        sqlx::Error::PoolTimedOut => "pool timed out".into(),
        sqlx::Error::Configuration(_) => "configuration".into(),
        _ => "other".into(),
    }
}

/// Log an unexpected failure by what failed (never with input values) and answer 500.
pub fn internal(what: &str) -> Reject {
    tracing::error!(target: LOG, "{what}");
    Reject::Internal
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sparse_logs_once_per_interval() {
        let s = Sparse::new();
        assert_eq!(s.due_at(1_000), Some(0));
        for t in [1_001, 5_000, 10_999] {
            assert_eq!(s.due_at(t), None);
        }
        assert_eq!(s.due_at(11_000), Some(3));
        assert_eq!(s.due_at(11_001), None);
        assert_eq!(left_out(0), "");
        assert_eq!(left_out(3), " (3 more like it not logged)");
    }

    #[test]
    fn test_codes() {
        assert_eq!(status_code_name(StatusCode::BAD_REQUEST), "bad_request");
        assert_eq!(status_code_name(StatusCode::METHOD_NOT_ALLOWED), "method_not_allowed");
        assert_eq!(status_code_name(StatusCode::INTERNAL_SERVER_ERROR), "internal_error");
        let r = Reject::not_found().into_response();
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
        assert!(r.extensions().get::<Rejected>().is_some());
    }
}
