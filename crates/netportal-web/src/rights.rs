//! The live check of admin rights (owner's review 2026-10-29). The registry's admin flag comes
//! from the login (the ID token's groups) and the offboarding round (every 15 min), so someone
//! removed from the admin group in Authentik would keep admin until the next round. Every
//! request that uses admin rights therefore asks Authentik's users API now (the offboarding's
//! client and its sub -> user mapping: `netportal_offboard::directory`, `uid` = the OIDC `sub`):
//!
//! - only for a person the registry lists as admin (anyone else has no admin right to check);
//! - a confirmation counts for [`CONFIRMED_FOR`] (30 s) per person: the window in which a right
//!   taken away in Authentik still works (docs/PARITY.md);
//! - fail closed: Authentik unreachable, answering an error, or a directory that names nobody
//!   (no users, nobody active in a policy's groups) is [`Verdict::Unknown`] and the admin
//!   request is refused (503); after a failure Authentik is not asked again for that person for
//!   [`FAILURE_PAUSE`] (one read at a time in any case; within [`OUTAGE_WINDOW`] of a failure
//!   a request does not wait for a running read but is refused at once). Resident pages never ask;
//! - the right gone ([`Verdict::NotAdmin`]: not in the directory, inactive, or out of the admin
//!   groups): the caller clears the registry's flag (which ends the person's portal sessions)
//!   and refuses ([`crate::ctx::Ctx::need_admin`]).
//!
//! Without `NETPORTAL_AUTHENTIK_API` and `NETPORTAL_AUTHENTIK_TOKEN` there is nothing to check
//! with: every admin request is refused (logged once at the start).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use netportal_core::config::{Policies, PortalSettings};
use netportal_offboard::directory::UsersApi;
use time::OffsetDateTime;

use crate::clock::Clock;
use crate::errors::{Sparse, left_out};

const LOG: &str = "netportal.rights";

/// A confirmed admin right counts this long without asking again.
pub const CONFIRMED_FOR: time::Duration = time::Duration::seconds(30);
/// After a failed read Authentik is not asked again for that person this long (their admin
/// requests meanwhile: 503).
pub const FAILURE_PAUSE: time::Duration = time::Duration::seconds(5);
/// One request to the users API waits at most this long (the whole read at most twice that).
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// After a failed read (of anyone), this long an admin request does not queue behind a read
/// that is already running: it is refused at once (503). Authentik hanging then holds one
/// request (and its registry connection) at a time, not every admin's polling page.
pub const OUTAGE_WINDOW: time::Duration = time::Duration::seconds(60);

static READ_FAILED: Sparse = Sparse::new();

/// What Authentik says about a person's admin right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// active, in a policy's groups and in `NETPORTAL_ADMIN_GROUPS`
    Admin,
    /// not (any more): unknown to the directory, inactive, or out of the groups
    NotAdmin,
    /// it cannot be told now (Authentik unreachable, an error, no API configured)
    Unknown,
}

#[derive(Default)]
struct Cache {
    /// sub -> when the right was last confirmed
    confirmed: HashMap<String, OffsetDateTime>,
    /// sub -> when the last read for them failed
    failed: HashMap<String, OffsetDateTime>,
    /// when the last read (of anyone) failed; cleared by a read that works
    last_failure: Option<OffsetDateTime>,
}

/// The checker (one per process).
pub struct AdminCheck {
    api: Option<UsersApi>,
    policies: Policies,
    clock: Clock,
    cache: Mutex<Cache>,
    /// one read of the directory at a time
    reading: tokio::sync::Mutex<()>,
}

impl AdminCheck {
    /// The checker for the portal's settings (off without API URL and token).
    pub fn new(settings: &PortalSettings, clock: Clock) -> anyhow::Result<AdminCheck> {
        let api = match (&settings.authentik_api, &settings.authentik_token) {
            (Some(api), Some(token)) => Some(
                UsersApi::new(api, token.clone(), REQUEST_TIMEOUT)
                    .map_err(|e| anyhow::anyhow!("NETPORTAL_AUTHENTIK_API: {e}"))?,
            ),
            _ => None,
        };
        Ok(AdminCheck {
            api,
            policies: settings.policies.clone(),
            clock,
            cache: Mutex::new(Cache::default()),
            reading: tokio::sync::Mutex::new(()),
        })
    }

    /// Whether admin rights can be checked at all.
    pub fn enabled(&self) -> bool {
        self.api.is_some()
    }

    fn cache(&self) -> std::sync::MutexGuard<'_, Cache> {
        self.cache.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// From the cache: a recent confirmation, or a recent failure.
    fn cached(&self, sub: &str, now: OffsetDateTime) -> Option<Verdict> {
        let cache = self.cache();
        if cache.confirmed.get(sub).is_some_and(|at| (time::Duration::ZERO..CONFIRMED_FOR).contains(&(now - *at))) {
            return Some(Verdict::Admin);
        }
        if cache.failed.get(sub).is_some_and(|at| (time::Duration::ZERO..FAILURE_PAUSE).contains(&(now - *at))) {
            return Some(Verdict::Unknown);
        }
        None
    }

    /// The person's admin right now (see the module documentation).
    pub async fn verify(&self, sub: &str) -> Verdict {
        let Some(api) = &self.api else {
            return Verdict::Unknown;
        };
        if let Some(verdict) = self.cached(sub, (self.clock)()) {
            return verdict;
        }
        let outage = {
            let now = (self.clock)();
            self.cache().last_failure.is_some_and(|at| (time::Duration::ZERO..OUTAGE_WINDOW).contains(&(now - at)))
        };
        let _one = if outage {
            match self.reading.try_lock() {
                Ok(one) => one,
                Err(_) => return Verdict::Unknown,
            }
        } else {
            self.reading.lock().await
        };
        // another request may have read it meanwhile
        if let Some(verdict) = self.cached(sub, (self.clock)()) {
            return verdict;
        }
        // a confirmation counts from before the read: the window is CONFIRMED_FOR at most
        let asked = (self.clock)();
        let read = tokio::time::timeout(REQUEST_TIMEOUT * 2, api.read()).await;
        let failed = |why: String| {
            if let Some(n) = READ_FAILED.due() {
                tracing::warn!(target: LOG, "admin rights cannot be checked: {why}{}", left_out(n));
            }
            let now = (self.clock)();
            let mut cache = self.cache();
            cache.failed.insert(sub.to_string(), now);
            cache.last_failure = Some(now);
            Verdict::Unknown
        };
        let directory = match read {
            Ok(Ok(directory)) => directory,
            Ok(Err(e)) => return failed(e.to_string()),
            Err(_) => return failed("the users API did not answer in time".into()),
        };
        let access = directory.access(&self.policies);
        if directory.is_empty() || access.allowed.is_empty() {
            return failed("the directory names nobody with Wi-Fi access".into());
        }
        let mut cache = self.cache();
        cache.failed.remove(sub);
        cache.last_failure = None;
        if access.admins.contains(sub) {
            cache.confirmed.insert(sub.to_string(), asked);
            Verdict::Admin
        } else {
            cache.confirmed.remove(sub);
            Verdict::NotAdmin
        }
    }
}
