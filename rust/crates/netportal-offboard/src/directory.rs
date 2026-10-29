//! Authentik's users API, read completely or not at all (Python `offboarding.read_directory`,
//! INVENTORY 8.1).
//!
//! `GET <api>/core/users/?include_groups=true&page_size=100&page=N` with the read-only bearer
//! token, page after page (Authentik's `pagination.next` is the next page NUMBER, 0 on the last
//! page). Inactive users are part of the list; `uid` is the OIDC `sub` (Authentik's default
//! subject mode "hashed user ID").
//!
//! A missing user would lose their Wi-Fi, so every page is checked before anything is believed
//! (stricter than Python, which took whatever the pages held; compare house-infra's vault-orgs
//! `idp_authentik.py`): the body must be Authentik's paged list; every user must carry a `uid`,
//! a boolean `is_active` and a `groups_obj` list (a missing field would otherwise read as
//! "inactive" or "in no group" and offboard everyone); the total (`pagination.count`) must be
//! the same on every page; each next page must be the following number; a page before the last
//! must not be empty; no `uid` may appear twice; at the end exactly `count` distinct users must
//! have been read. Users created or deleted while the pages are read shift between pages and
//! fail the read; the next round reads again. Any HTTP problem (status other than 200, a
//! redirect, a body that is not JSON or larger than [`MAX_PAGE_BYTES`], a timeout) fails it too.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use netportal_core::config::{Policies, Secret};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use serde_json::Value;

/// Users per page asked for (Authentik's own limit is higher; the read does not depend on it).
pub const PAGE_SIZE: u32 = 100;
/// Per request (Python: `requests.get(..., timeout=15)`).
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
/// A page larger than this is refused (100 users with their groups are a few hundred KiB).
pub const MAX_PAGE_BYTES: usize = 8 * 1024 * 1024;

/// Why the directory could not be read. Messages carry the page number and the URL without
/// credentials, never the token.
#[derive(Debug, thiserror::Error)]
pub enum DirectoryError {
    #[error("users API page {page}: {message}")]
    Http { page: u32, message: String },
    #[error("users API page {page}: HTTP status {status}")]
    Status { page: u32, status: u16 },
    #[error("users API page {page}: {message}")]
    Format { page: u32, message: String },
    #[error("the directory changed while it was read (page {page}: {seen} users, page 1: {first})")]
    Changed { page: u32, seen: u64, first: u64 },
    #[error("user {uid} is listed twice (the directory changed while it was read)")]
    Duplicate { uid: String },
    #[error("read {read} users, the directory has {count}")]
    Incomplete { read: usize, count: u64 },
}

/// One user as the offboarding sees them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryUser {
    /// Authentik's `uid` (the OIDC `sub`)
    pub uid: String,
    pub active: bool,
    /// the names of the user's (direct) groups, as in the OIDC `groups` claim
    pub groups: BTreeSet<String>,
}

/// Every user of the directory, by uid.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Directory {
    users: BTreeMap<String, DirectoryUser>,
}

/// Who may use Wi-Fi according to the directory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Access {
    /// uid -> policy name, for every active user whose groups give a policy
    pub allowed: BTreeMap<String, String>,
    /// the allowed users in one of `NETPORTAL_ADMIN_GROUPS`
    pub admins: BTreeSet<String>,
}

impl Directory {
    /// A directory of these users; a uid twice is refused.
    pub fn from_users(users: impl IntoIterator<Item = DirectoryUser>) -> Result<Directory, DirectoryError> {
        let mut map = BTreeMap::new();
        for user in users {
            if map.contains_key(&user.uid) {
                return Err(DirectoryError::Duplicate { uid: user.uid });
            }
            map.insert(user.uid.clone(), user);
        }
        Ok(Directory { users: map })
    }

    pub fn len(&self) -> usize {
        self.users.len()
    }

    pub fn is_empty(&self) -> bool {
        self.users.is_empty()
    }

    /// Whether the directory has this user at all (active or not, in any group or none).
    pub fn contains(&self, uid: &str) -> bool {
        self.users.contains_key(uid)
    }

    pub fn users(&self) -> impl Iterator<Item = &DirectoryUser> {
        self.users.values()
    }

    /// Active users whose groups give a policy (`Policies::policy_for`: the first policy sharing
    /// a group, an admin outside every policy gets the first), and the admins among them.
    pub fn access(&self, policies: &Policies) -> Access {
        let mut access = Access::default();
        for user in self.users.values().filter(|u| u.active) {
            let groups: Vec<&str> = user.groups.iter().map(String::as_str).collect();
            if let Some(policy) = policies.policy_for(&groups) {
                access.allowed.insert(user.uid.clone(), policy.to_string());
                if user.groups.iter().any(|g| policies.admin_groups.contains(g)) {
                    access.admins.insert(user.uid.clone());
                }
            }
        }
        access
    }
}

/// The users API of one Authentik (`NETPORTAL_AUTHENTIK_API`, e.g. `https://login.<domain>/api/v3`).
pub struct UsersApi {
    client: reqwest::Client,
    api: String,
    token: Secret<String>,
}

impl UsersApi {
    /// `api` without a trailing slash (as the settings give it); `timeout` per request.
    pub fn new(api: &str, token: Secret<String>, timeout: Duration) -> Result<UsersApi, DirectoryError> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(timeout)
            // a redirect is an error, not something to follow with the token
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("netportal-offboard/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| DirectoryError::Http { page: 0, message: format!("HTTP client: {e}") })?;
        Ok(UsersApi { client, api: api.trim_end_matches('/').to_string(), token })
    }

    /// Every user, all pages, checked as the module documentation says.
    pub async fn read(&self) -> Result<Directory, DirectoryError> {
        let mut users: BTreeMap<String, DirectoryUser> = BTreeMap::new();
        let mut number: u32 = 1;
        let mut count: Option<u64> = None;
        let mut total_pages: Option<u64> = None; // as page 1 says
        loop {
            let page = parse_page(number, &self.fetch(number).await?)?;
            match count {
                None => count = Some(page.count),
                Some(first) if first != page.count => {
                    return Err(DirectoryError::Changed { page: number, seen: page.count, first });
                }
                Some(_) => {}
            }
            if number == 1 {
                total_pages = page.total_pages;
            } else if page.total_pages != total_pages {
                return Err(format(number, "pagination.total_pages differs from page 1"));
            }
            if page.next != 0 && page.users.is_empty() {
                return Err(format(number, "an empty page before the last"));
            }
            for user in page.users {
                if users.contains_key(&user.uid) {
                    return Err(DirectoryError::Duplicate { uid: user.uid });
                }
                users.insert(user.uid.clone(), user);
            }
            if users.len() as u64 > page.count {
                return Err(DirectoryError::Incomplete { read: users.len(), count: page.count });
            }
            if page.next == 0 {
                if let Some(t) = total_pages
                    && t.max(1) != u64::from(number)
                {
                    return Err(format(number, &format!("the last page, but pagination.total_pages is {t}")));
                }
                break;
            }
            if page.next != u64::from(number) + 1 {
                return Err(format(number, &format!("points to page {} next", page.next)));
            }
            number += 1;
        }
        let count = count.unwrap_or(0);
        if users.len() as u64 != count {
            return Err(DirectoryError::Incomplete { read: users.len(), count });
        }
        Ok(Directory { users })
    }

    async fn fetch(&self, page: u32) -> Result<Value, DirectoryError> {
        let http = |e: reqwest::Error| DirectoryError::Http { page, message: e.without_url().to_string() };
        let url = format!("{}/core/users/", self.api);
        let mut response = self
            .client
            .get(&url)
            .query(&[
                ("include_groups", "true".to_string()),
                ("page_size", PAGE_SIZE.to_string()),
                ("page", page.to_string()),
            ])
            .header(AUTHORIZATION, format!("Bearer {}", self.token.expose()))
            .header(ACCEPT, "application/json")
            .send()
            .await
            .map_err(http)?;
        let status = response.status();
        if status != reqwest::StatusCode::OK {
            return Err(DirectoryError::Status { page, status: status.as_u16() });
        }
        let json_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.trim().to_ascii_lowercase().starts_with("application/json"));
        if !json_type {
            return Err(format(page, "the answer is not application/json"));
        }
        if response.content_length().is_some_and(|n| n > MAX_PAGE_BYTES as u64) {
            return Err(format(page, "the answer is too large"));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(http)? {
            if body.len() + chunk.len() > MAX_PAGE_BYTES {
                return Err(format(page, "the answer is too large"));
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).map_err(|_| format(page, "the answer is not JSON"))
    }
}

fn format(page: u32, message: &str) -> DirectoryError {
    DirectoryError::Format { page, message: message.to_string() }
}

/// One page of the list.
#[derive(Debug)]
struct Page {
    users: Vec<DirectoryUser>,
    count: u64,
    next: u64,
    total_pages: Option<u64>,
}

/// One page body: `{"pagination": {"count", "next", "current"?, "total_pages"?}, "results": [user]}`.
fn parse_page(number: u32, body: &Value) -> Result<Page, DirectoryError> {
    let not_list = || format(number, "not Authentik's paged list of users");
    let results = body.get("results").and_then(Value::as_array).ok_or_else(not_list)?;
    let pagination = body.get("pagination").and_then(Value::as_object).ok_or_else(not_list)?;
    let count = pagination.get("count").and_then(Value::as_u64).ok_or_else(not_list)?;
    let next = pagination.get("next").and_then(Value::as_u64).ok_or_else(not_list)?;
    if let Some(current) = pagination.get("current")
        && current.as_u64() != Some(u64::from(number))
    {
        return Err(format(number, &format!("the answer is page {current}")));
    }
    let total_pages = match pagination.get("total_pages") {
        None => None,
        Some(v) => Some(v.as_u64().ok_or_else(not_list)?),
    };
    let users = results.iter().map(|u| parse_user(number, u)).collect::<Result<Vec<_>, _>>()?;
    Ok(Page { users, count, next, total_pages })
}

fn parse_user(number: u32, user: &Value) -> Result<DirectoryUser, DirectoryError> {
    let uid = user.get("uid").and_then(Value::as_str).map(str::trim).filter(|u| !u.is_empty());
    let Some(uid) = uid else {
        return Err(format(number, "a user without a uid"));
    };
    let Some(active) = user.get("is_active").and_then(Value::as_bool) else {
        return Err(format(number, &format!("user {uid} without is_active")));
    };
    let Some(groups) = user.get("groups_obj").and_then(Value::as_array) else {
        return Err(format(number, &format!("user {uid} without groups_obj (include_groups ignored?)")));
    };
    let groups = groups
        .iter()
        .map(|g| g.get("name").and_then(Value::as_str).map(str::to_string))
        .collect::<Option<BTreeSet<String>>>()
        .ok_or_else(|| format(number, &format!("a group of user {uid} without a name")))?;
    Ok(DirectoryUser { uid: uid.to_string(), active, groups })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_parse_page_refuses_what_would_read_as_nobody() {
        let ok = json!({"pagination": {"count": 1, "next": 0, "current": 1, "total_pages": 1},
                        "results": [{"uid": "a", "is_active": true, "groups_obj": [{"name": "residents"}]}]});
        let page = parse_page(1, &ok).expect("page");
        assert_eq!(page.users[0].groups, BTreeSet::from(["residents".to_string()]));
        let user = |u: Value| json!({"pagination": {"count": 1, "next": 0}, "results": [u]});
        for (bad, why) in [
            (json!([]), "a list"),
            (json!({"results": []}), "no pagination"),
            (json!({"pagination": {"count": 0}, "results": []}), "no next"),
            (json!({"pagination": {"count": "1", "next": 0}, "results": []}), "count as text"),
            (json!({"pagination": {"count": 1, "next": null}, "results": []}), "next null"),
            (json!({"pagination": {"count": 1, "next": 0, "current": 2}, "results": []}), "another page"),
            (user(json!({"is_active": true, "groups_obj": []})), "no uid"),
            (user(json!({"uid": "", "is_active": true, "groups_obj": []})), "empty uid"),
            (user(json!({"uid": "a", "groups_obj": []})), "no is_active"),
            (user(json!({"uid": "a", "is_active": "yes", "groups_obj": []})), "is_active as text"),
            (user(json!({"uid": "a", "is_active": true})), "no groups_obj"),
            (user(json!({"uid": "a", "is_active": true, "groups_obj": [{"pk": 1}]})), "group without a name"),
        ] {
            assert!(parse_page(1, &bad).is_err(), "{why}");
        }
    }

    fn policies() -> Policies {
        Policies {
            list: netportal_core::config::parse_policies(
                "residents=30:residents,house-admins,it-admins; guests=50:former-residents",
            )
            .expect("policies"),
            admin_groups: BTreeSet::from(["it-admins".to_string()]),
        }
    }

    fn user(uid: &str, active: bool, groups: &[&str]) -> DirectoryUser {
        DirectoryUser { uid: uid.into(), active, groups: groups.iter().map(|g| g.to_string()).collect() }
    }

    #[test]
    fn test_offboarding_reads_the_policy_per_person() {
        let dir = Directory::from_users([
            user("a", true, &["residents"]),
            user("f", true, &["former-residents"]),
            user("x", false, &["residents"]),
            user("v", true, &["vpn-users"]),
        ])
        .expect("directory");
        let access = dir.access(&policies());
        assert_eq!(
            access.allowed,
            BTreeMap::from([("a".to_string(), "residents".to_string()), ("f".to_string(), "guests".to_string())])
        );
        assert!(dir.contains("x") && dir.contains("v") && !dir.contains("nobody"));
    }

    #[test]
    fn test_directory_reads_admins() {
        let mut p = policies();
        p.list = netportal_core::config::parse_policies("residents=30:residents").expect("policies");
        let dir = Directory::from_users([
            user("a", true, &["it-admins"]),
            user("r", true, &["residents"]),
            user("x", false, &["it-admins"]),
        ])
        .expect("directory");
        let access = dir.access(&p);
        assert_eq!(
            access.allowed,
            BTreeMap::from([("a".to_string(), "residents".to_string()), ("r".to_string(), "residents".to_string())])
        );
        assert_eq!(access.admins, BTreeSet::from(["a".to_string()]));
    }

    #[test]
    fn test_a_uid_twice_is_refused() {
        assert!(matches!(
            Directory::from_users([user("a", true, &[]), user("a", false, &[])]),
            Err(DirectoryError::Duplicate { .. })
        ));
    }
}
