//! Settings from the environment (Python: `netportal/config.py`, `netportal/collect/settings.py`;
//! INVENTORY 2). One loader per process, each reading only what that process uses:
//! [`PortalSettings`] (`serve`), [`OffboardSettings`] (`offboard`), [`InitDbSettings`]
//! (`init-db`), [`CollectSettings`] (`collect`, `job`).
//!
//! Reading rules (the same for every variable):
//! - A value is trimmed; an empty value counts as unset (so a default applies).
//! - A required value that is unset stops the process: `missing setting NAME`.
//! - A secret `NAME` may instead come from a file `NAME_FILE` (its content, trimmed); setting
//!   both is an error.
//! - Numbers, booleans, URLs and names are validated at start, with the variable's name in the
//!   message; nothing invalid is silently replaced by a default.
//!
//! Secrets are wrapped in [`Secret`], whose `Debug` output is `Secret(***)`.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::path::PathBuf;
use std::sync::LazyLock;
use std::time::Duration;

use regex::Regex;

/// A setting that failed to load; the message names the variable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ConfigError(pub String);

type Result<T> = std::result::Result<T, ConfigError>;

fn err<T>(message: impl Into<String>) -> Result<T> {
    Err(ConfigError(message.into()))
}

/// A secret value: never printed by `Debug`; [`Secret::expose`] gives it.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret<T>(T);

impl<T> Secret<T> {
    pub fn new(value: T) -> Self {
        Secret(value)
    }
    pub fn expose(&self) -> &T {
        &self.0
    }
}

impl<T> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(***)")
    }
}

// --- the environment ---------------------------------------------------------------------------

/// Where settings come from: the process environment ([`ProcessEnv`]) or, in tests, a map.
pub trait Env {
    /// The raw value of a variable, `None` when unset.
    fn var(&self, name: &str) -> Option<String>;
}

/// The process environment (values that are not UTF-8 are read lossily).
pub struct ProcessEnv;

impl Env for ProcessEnv {
    fn var(&self, name: &str) -> Option<String> {
        std::env::var_os(name).map(|v| v.to_string_lossy().into_owned())
    }
}

impl Env for HashMap<String, String> {
    fn var(&self, name: &str) -> Option<String> {
        self.get(name).cloned()
    }
}

impl Env for BTreeMap<&str, &str> {
    fn var(&self, name: &str) -> Option<String> {
        self.get(name).map(|v| v.to_string())
    }
}

/// A trimmed, non-empty value or `None`.
fn value(env: &dyn Env, name: &str) -> Option<String> {
    env.var(name).map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

fn required(env: &dyn Env, name: &str) -> Result<String> {
    value(env, name).ok_or_else(|| ConfigError(format!("missing setting {name}")))
}

fn or_default(env: &dyn Env, name: &str, default: &str) -> String {
    value(env, name).unwrap_or_else(|| default.to_string())
}

/// `NAME`, or the content of the file `NAME_FILE` (trimmed); both set is an error.
fn secret(env: &dyn Env, name: &str) -> Result<Option<Secret<String>>> {
    let file_var = format!("{name}_FILE");
    match (value(env, name), value(env, &file_var)) {
        (Some(_), Some(_)) => err(format!("{name} and {file_var} are both set: set one")),
        (Some(v), None) => Ok(Some(Secret(v))),
        (None, Some(path)) => {
            let text = std::fs::read_to_string(&path)
                .map_err(|e| ConfigError(format!("{file_var}: cannot read {path}: {e}")))?;
            let text = text.trim();
            if text.is_empty() {
                return err(format!("{file_var}: {path} is empty"));
            }
            Ok(Some(Secret(text.to_string())))
        }
        (None, None) => Ok(None),
    }
}

fn required_secret(env: &dyn Env, name: &str) -> Result<Secret<String>> {
    secret(env, name)?.ok_or_else(|| ConfigError(format!("missing setting {name}")))
}

fn integer<T>(env: &dyn Env, name: &str, default: T, range: std::ops::RangeInclusive<T>) -> Result<T>
where
    T: std::str::FromStr + PartialOrd + fmt::Display + Copy,
{
    let Some(text) = value(env, name) else {
        return Ok(default);
    };
    match text.parse::<T>() {
        Ok(v) if range.contains(&v) => Ok(v),
        _ => err(format!("{name}: {text:?} is not a whole number in {}..={}", range.start(), range.end())),
    }
}

fn seconds(env: &dyn Env, name: &str, default: f64, max: f64) -> Result<Duration> {
    let Some(text) = value(env, name) else {
        return Ok(Duration::from_secs_f64(default));
    };
    match text.parse::<f64>() {
        Ok(v) if v.is_finite() && v > 0.0 && v <= max => Ok(Duration::from_secs_f64(v)),
        _ => err(format!("{name}: {text:?} is not a number of seconds in (0, {max}]")),
    }
}

fn boolean(env: &dyn Env, name: &str, default: bool) -> Result<bool> {
    let Some(text) = value(env, name) else {
        return Ok(default);
    };
    match text.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => err(format!("{name}: {text:?} is not true or false")),
    }
}

static HTTP_URL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^https?://[^\s/?#]+(/[^\s?#]*)?$").expect("a valid regular expression"));

/// An http(s) base URL without a trailing slash, or `None` when unset.
fn http_url(env: &dyn Env, name: &str) -> Result<Option<String>> {
    let Some(url) = value(env, name) else {
        return Ok(None);
    };
    let url = url.trim_end_matches('/').to_string();
    if !HTTP_URL.is_match(&url) {
        return err(format!("{name}: {url:?} is not an http(s) URL"));
    }
    Ok(Some(url))
}

fn required_http_url(env: &dyn Env, name: &str) -> Result<String> {
    http_url(env, name)?.ok_or_else(|| ConfigError(format!("missing setting {name}")))
}

/// The house's time zone (`NETPORTAL_TIMEZONE`, default `Europe/Berlin`); must be known.
fn timezone(env: &dyn Env) -> Result<String> {
    let name = or_default(env, "NETPORTAL_TIMEZONE", "Europe/Berlin");
    if crate::conventions::zone(&name).is_none() {
        return err(format!("NETPORTAL_TIMEZONE: {name:?} is not a known time zone"));
    }
    Ok(name)
}

fn groups(env: &dyn Env, name: &str, default: &str) -> BTreeSet<String> {
    or_default(env, name, default).split(',').map(str::trim).filter(|g| !g.is_empty()).map(str::to_string).collect()
}

// --- policies ----------------------------------------------------------------------------------

/// Where a person's devices go: a name, the VLAN RADIUS assigns, the groups it is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub name: String,
    pub vlan: u16,
    pub groups: BTreeSet<String>,
}

/// The policies in order of precedence and the admin groups (`NETPORTAL_POLICIES`,
/// `NETPORTAL_ADMIN_GROUPS`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policies {
    pub list: Vec<Policy>,
    pub admin_groups: BTreeSet<String>,
}

impl Policies {
    /// The policy for someone in these groups: the first policy sharing a group; an admin in
    /// none of them gets the first policy; else `None` (no Wi-Fi).
    pub fn policy_for<S: AsRef<str>>(&self, groups: &[S]) -> Option<&str> {
        let has = |set: &BTreeSet<String>| groups.iter().any(|g| set.contains(g.as_ref()));
        if let Some(policy) = self.list.iter().find(|p| has(&p.groups)) {
            return Some(&policy.name);
        }
        if has(&self.admin_groups) {
            return self.list.first().map(|p| p.name.as_str());
        }
        None
    }

    /// May enrol devices: the groups of every policy.
    pub fn allowed_groups(&self) -> BTreeSet<String> {
        self.list.iter().flat_map(|p| p.groups.iter().cloned()).collect()
    }
}

static POLICY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([a-z0-9][a-z0-9-]*)=(\d+):(.+)$").expect("a valid regular expression"));

/// `NETPORTAL_POLICIES`: `name=vlan:group,group;name=vlan:group` in order of precedence (a
/// person in the groups of two policies gets the first). Names `[a-z0-9][a-z0-9-]*`, VLAN
/// 1-4094, names unique, every policy with groups no other policy has, at least one policy.
pub fn parse_policies(text: &str) -> Result<Vec<Policy>> {
    let mut policies: Vec<Policy> = Vec::new();
    let mut seen_groups = BTreeSet::new();
    for part in text.split(';').map(str::trim).filter(|p| !p.is_empty()) {
        let Some(m) = POLICY.captures(part) else {
            return err(format!("NETPORTAL_POLICIES: {part:?} is not name=vlan:group,group"));
        };
        let name = m[1].to_string();
        let vlan = match m[2].parse::<u16>() {
            Ok(v) if (1..=4094).contains(&v) => v,
            _ => return err(format!("NETPORTAL_POLICIES: VLAN {} of {name} is not 1-4094", &m[2])),
        };
        let groups: BTreeSet<String> =
            m[3].split(',').map(str::trim).filter(|g| !g.is_empty()).map(str::to_string).collect();
        if policies.iter().any(|p| p.name == name) {
            return err(format!("NETPORTAL_POLICIES: {name} twice"));
        }
        if groups.is_empty() || !groups.is_disjoint(&seen_groups) {
            return err(format!("NETPORTAL_POLICIES: {name} needs groups that no other policy has"));
        }
        seen_groups.extend(groups.iter().cloned());
        policies.push(Policy { name, vlan, groups });
    }
    if policies.is_empty() {
        return err("NETPORTAL_POLICIES: no policy");
    }
    Ok(policies)
}

fn policies(env: &dyn Env) -> Result<Policies> {
    let text = required(env, "NETPORTAL_POLICIES")?;
    Ok(Policies { list: parse_policies(&text)?, admin_groups: groups(env, "NETPORTAL_ADMIN_GROUPS", "it-admins") })
}

// --- shared pieces -------------------------------------------------------------------------------

/// RADIUS dynamic authorization (Disconnect-Request, RFC 5176).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaeSettings {
    /// `NETPORTAL_DAE_PORT` (3799)
    pub port: u16,
    /// `NETPORTAL_DAE_SECRET` / `_FILE`; `None`: Disconnects are skipped
    pub secret: Option<Secret<String>>,
    /// `NETPORTAL_DAE_REQUIRE_REPLY_MESSAGE_AUTHENTICATOR` (true): a Disconnect-ACK/NAK without
    /// Message-Authenticator is ignored (logged as a warning; the result is then `timeout`).
    /// hostapd signs its replies; turn it off only for an access point that does not.
    pub require_reply_message_authenticator: bool,
}

impl DaeSettings {
    /// Port and secret with the reply check on (the default).
    pub fn new(port: u16, secret: Option<Secret<String>>) -> DaeSettings {
        DaeSettings { port, secret, require_reply_message_authenticator: true }
    }
}

fn dae(env: &dyn Env) -> Result<DaeSettings> {
    Ok(DaeSettings {
        port: integer(env, "NETPORTAL_DAE_PORT", 3799u16, 1..=65535)?,
        secret: secret(env, "NETPORTAL_DAE_SECRET")?,
        require_reply_message_authenticator: boolean(env, "NETPORTAL_DAE_REQUIRE_REPLY_MESSAGE_AUTHENTICATOR", true)?,
    })
}

/// The device CA key file (`NETPORTAL_DEVICE_CA_KEY`, a path; PEM, unencrypted), read into a
/// buffer that is wiped when dropped. The key is accepted from a file only: a value in the
/// environment (the former `NETPORTAL_DEVICE_CA_KEY_B64`) is readable through the process's
/// environment by every process of the same user, `docker inspect` and every child process,
/// and cannot be wiped.
pub fn read_device_ca_key(path: &std::path::Path) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let key = zeroize::Zeroizing::new(
        std::fs::read(path)
            .map_err(|e| ConfigError(format!("NETPORTAL_DEVICE_CA_KEY: cannot read {}: {e}", path.display())))?,
    );
    if !key.windows(11).any(|w| w == b"-----BEGIN ") {
        return err("NETPORTAL_DEVICE_CA_KEY: not a PEM key");
    }
    Ok(key)
}

/// `NETPORTAL_DEVICE_CA_KEY`: the key file's path, checked now (read and wiped again; the
/// portal reads it once more when it builds its issuer, `netportal_web::web::App::new`).
fn device_ca_key(env: &dyn Env) -> Result<PathBuf> {
    if value(env, "NETPORTAL_DEVICE_CA_KEY_B64").is_some() {
        return err(
            "NETPORTAL_DEVICE_CA_KEY_B64 is not supported: put the key in a file and set NETPORTAL_DEVICE_CA_KEY to its path",
        );
    }
    let path = PathBuf::from(required(env, "NETPORTAL_DEVICE_CA_KEY")?);
    read_device_ca_key(&path)?;
    Ok(path)
}

/// A `host:port` socket address (`NETPORTAL_METRICS_LISTEN`), `None` when unset.
fn socket_address(env: &dyn Env, name: &str) -> Result<Option<String>> {
    let Some(text) = value(env, name) else {
        return Ok(None);
    };
    if text.parse::<std::net::SocketAddr>().is_err() {
        return err(format!("{name}: {text:?} is not host:port (an IP address and a port)"));
    }
    Ok(Some(text))
}

// --- the portal ----------------------------------------------------------------------------------

/// Everything `netportal serve` needs.
#[derive(Debug, Clone)]
pub struct PortalSettings {
    /// `NETPORTAL_BASE_URL` (no trailing slash): `https://wifi.scharni.org`
    pub base_url: String,
    /// `NETPORTAL_REALM`: outer identity realm, certificate CN suffix, Passpoint FQDN
    pub realm: String,
    /// `NETPORTAL_SSID`: the 802.1X network
    pub ssid: String,
    /// `NETPORTAL_RADIUS_SERVER_NAME`: the name every profile pins
    pub radius_server_name: String,
    /// `NETPORTAL_DISPLAY_NAME` (`Wi-Fi`): what residents see
    pub display_name: String,
    /// `NETPORTAL_IOT_SSID` (`<NETPORTAL_SSID>-IoT`): the home devices' PPSK network, as the key
    /// pages and the QR codes name it (the controller keys it: `NETPORTAL_UNIFI_IOT_SSID`)
    pub iot_ssid: String,
    /// `NETPORTAL_DATABASE_URL` / `_FILE`
    pub database_url: Secret<String>,
    /// `NETPORTAL_SESSION_SECRET` / `_FILE`: the cookie key material, at least 32 bytes
    pub session_secret: Secret<String>,
    /// `NETPORTAL_OIDC_ISSUER`, as given (Authentik's issuer ends with a slash)
    pub oidc_issuer: String,
    /// `NETPORTAL_OIDC_CLIENT_ID`
    pub oidc_client_id: String,
    /// `NETPORTAL_OIDC_CLIENT_SECRET` / `_FILE`
    pub oidc_client_secret: Secret<String>,
    /// `NETPORTAL_POLICIES`, `NETPORTAL_ADMIN_GROUPS`
    pub policies: Policies,
    /// `NETPORTAL_ROOT_CERT`: PEM of the offline root (the anchor in every profile)
    pub root_cert: PathBuf,
    /// `NETPORTAL_DEVICE_CA_CERT`: PEM of the device CA
    pub device_ca_cert: PathBuf,
    /// `NETPORTAL_DEVICE_CA_KEY`: the device CA key's file (only the path is kept here; see
    /// [`read_device_ca_key`])
    pub device_ca_key: PathBuf,
    /// `NETPORTAL_CERT_DAYS` (365, 1..=3650): device certificate validity
    pub cert_days: u32,
    /// `NETPORTAL_RENEW_OVERLAP_DAYS` (2, 0..=30): the previous certificate stays valid this long
    pub renew_overlap_days: u32,
    pub dae: DaeSettings,
    /// `NETPORTAL_PASSPOINT` (false): offer the Passpoint download on Android
    pub passpoint: bool,
    /// `NETPORTAL_LOGOUT_URL`: where "log out" goes; `None`: the portal's own page
    pub logout_url: Option<String>,
    /// `NETPORTAL_HOME_URL`, default `https://<realm>/`: the house bar's link home
    pub home_url: String,
    /// `NETPORTAL_PROMETHEUS_URL`; `None`: the dashboard shows the registry's data only
    pub prometheus_url: Option<String>,
    /// `NETPORTAL_PROMETHEUS_TIMEOUT` (4 s, at most 60): per query
    pub prometheus_timeout: Duration,
    /// `NETPORTAL_TIMEZONE` (`Europe/Berlin`): the house's days
    pub timezone: String,
    /// `NETPORTAL_ACCT_INTERIM_S` (300, 30..=86400): RADIUS accounting interval
    pub acct_interim_s: u32,
    /// `NETPORTAL_DB_POOL_SIZE` (10, 1..=100): registry connections of the web process at most
    /// (the database role's CONNECTION LIMIT must leave room for it and for `init-db`)
    pub db_pool_size: u32,
    /// `NETPORTAL_MAX_REQUESTS` (128, 1..=10000): requests handled at once; more are answered
    /// 503 with `Retry-After` at once (`/healthz` is not counted)
    pub max_requests: usize,
    /// `NETPORTAL_METRICS_LISTEN` (`host:port`; unset: no metrics): where `/metrics` is served,
    /// on a listener of its own (never on the public one)
    pub metrics_listen: Option<String>,
    /// `NETPORTAL_MAX_DEVICES` (20, 1..=1000): active devices per person
    pub max_devices: u32,
    /// `NETPORTAL_METRICS_TOKEN` / `_FILE` (at least 32 bytes; unset: none): `/metrics` answers
    /// 401 without `Authorization: Bearer <token>`
    pub metrics_token: Option<Secret<String>>,
    /// `NETPORTAL_AUTHENTIK_API` (`https://login.<domain>/api/v3`): where every request that uses
    /// admin rights checks them live; `None` (or no token): admin requests are refused
    pub authentik_api: Option<String>,
    /// `NETPORTAL_AUTHENTIK_TOKEN` / `_FILE`: the read-only users API token
    pub authentik_token: Option<Secret<String>>,
}

/// The shortest `NETPORTAL_METRICS_TOKEN` (bytes).
pub const METRICS_TOKEN_MIN: usize = 32;

fn metrics_token(env: &dyn Env) -> Result<Option<Secret<String>>> {
    let token = secret(env, "NETPORTAL_METRICS_TOKEN")?;
    if token.as_ref().is_some_and(|t| t.expose().len() < METRICS_TOKEN_MIN) {
        return err(format!("NETPORTAL_METRICS_TOKEN: at least {METRICS_TOKEN_MIN} bytes"));
    }
    Ok(token)
}

impl PortalSettings {
    pub fn load() -> Result<Self> {
        Self::from_env(&ProcessEnv)
    }

    pub fn from_env(env: &dyn Env) -> Result<Self> {
        let realm = required(env, "NETPORTAL_REALM")?;
        let session_secret = required_secret(env, "NETPORTAL_SESSION_SECRET")?;
        if session_secret.expose().len() < 32 {
            return err("NETPORTAL_SESSION_SECRET: at least 32 bytes");
        }
        let ssid = required(env, "NETPORTAL_SSID")?;
        Ok(PortalSettings {
            base_url: required_http_url(env, "NETPORTAL_BASE_URL")?,
            ssid: ssid.clone(),
            radius_server_name: required(env, "NETPORTAL_RADIUS_SERVER_NAME")?,
            display_name: or_default(env, "NETPORTAL_DISPLAY_NAME", "Wi-Fi"),
            iot_ssid: or_default(env, "NETPORTAL_IOT_SSID", &format!("{ssid}-IoT")),
            database_url: required_secret(env, "NETPORTAL_DATABASE_URL")?,
            session_secret,
            oidc_issuer: required(env, "NETPORTAL_OIDC_ISSUER")?,
            oidc_client_id: required(env, "NETPORTAL_OIDC_CLIENT_ID")?,
            oidc_client_secret: required_secret(env, "NETPORTAL_OIDC_CLIENT_SECRET")?,
            policies: policies(env)?,
            root_cert: PathBuf::from(required(env, "NETPORTAL_ROOT_CERT")?),
            device_ca_cert: PathBuf::from(required(env, "NETPORTAL_DEVICE_CA_CERT")?),
            device_ca_key: device_ca_key(env)?,
            cert_days: integer(env, "NETPORTAL_CERT_DAYS", 365, 1..=3650)?,
            renew_overlap_days: integer(env, "NETPORTAL_RENEW_OVERLAP_DAYS", 2, 0..=30)?,
            dae: dae(env)?,
            passpoint: boolean(env, "NETPORTAL_PASSPOINT", false)?,
            logout_url: value(env, "NETPORTAL_LOGOUT_URL"),
            home_url: value(env, "NETPORTAL_HOME_URL").unwrap_or_else(|| format!("https://{realm}/")),
            realm,
            prometheus_url: http_url(env, "NETPORTAL_PROMETHEUS_URL")?,
            prometheus_timeout: seconds(env, "NETPORTAL_PROMETHEUS_TIMEOUT", 4.0, 60.0)?,
            timezone: timezone(env)?,
            acct_interim_s: integer(env, "NETPORTAL_ACCT_INTERIM_S", 300, 30..=86400)?,
            db_pool_size: integer(env, "NETPORTAL_DB_POOL_SIZE", 10, 1..=100)?,
            max_requests: integer(env, "NETPORTAL_MAX_REQUESTS", 128, 1..=10000)?,
            metrics_listen: socket_address(env, "NETPORTAL_METRICS_LISTEN")?,
            max_devices: integer(env, "NETPORTAL_MAX_DEVICES", 20, 1..=1000)?,
            metrics_token: metrics_token(env)?,
            authentik_api: http_url(env, "NETPORTAL_AUTHENTIK_API")?,
            authentik_token: secret(env, "NETPORTAL_AUTHENTIK_TOKEN")?,
        })
    }

    /// The URL scheme decides the cookie: `https://` gives a `__Host-` cookie with `Secure`.
    pub fn is_https(&self) -> bool {
        self.base_url.starts_with("https://")
    }

    /// Whether admin rights can be checked live (API URL and token set).
    pub fn admin_check_enabled(&self) -> bool {
        self.authentik_api.is_some() && self.authentik_token.is_some()
    }
}

// --- the offboarding -----------------------------------------------------------------------------

/// Everything `netportal offboard` needs (no OIDC client, session or CA secrets).
#[derive(Debug, Clone)]
pub struct OffboardSettings {
    pub database_url: Secret<String>,
    /// `NETPORTAL_AUTHENTIK_API` (`https://login.<domain>/api/v3`); `None`: offboarding is off
    pub authentik_api: Option<String>,
    /// `NETPORTAL_AUTHENTIK_TOKEN` / `_FILE`; `None`: offboarding is off
    pub authentik_token: Option<Secret<String>>,
    pub policies: Policies,
    pub dae: DaeSettings,
    /// `NETPORTAL_HEARTBEAT` (`/tmp/netportal-offboard.heartbeat`): touched after every round
    pub heartbeat: PathBuf,
    /// When a round holds back (changes nothing, fails): see [`MassRemoval`]
    pub mass: MassRemoval,
    /// `NETPORTAL_ACCT_INTERIM_S` (300, 30..=86400): the accounting interval (a session without a
    /// Start or Interim-Update for two of them is no longer live)
    pub acct_interim_s: u32,
    /// `NETPORTAL_DISCONNECT_RECHECK_S` (30, 0..=3600; 0: off): with `--every`, how often the
    /// Disconnect reconciliation looks for live sessions of locked devices
    pub disconnect_recheck: Duration,
}

/// The offboarding's hold on mass removals (house-infra vault-orgs' rule, `MASS_REMOVAL_MIN`
/// and "more than half"): a round that would offboard at least `min` of the people with active
/// devices, and more than `percent` % of them, changes nothing and fails (HELD BACK), unless
/// `allow` is set (or the one round is run with `netportal offboard --allow-mass`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MassRemoval {
    /// `NETPORTAL_OFFBOARD_MASS_MIN` (3, 1..=100000)
    pub min: usize,
    /// `NETPORTAL_OFFBOARD_MASS_PERCENT` (50, 0..=100)
    pub percent: u32,
    /// `NETPORTAL_OFFBOARD_ALLOW_MASS` (false)
    pub allow: bool,
}

impl Default for MassRemoval {
    fn default() -> Self {
        MassRemoval { min: 3, percent: 50, allow: false }
    }
}

impl MassRemoval {
    /// Whether offboarding `removed` of `base` people with active devices is held back.
    pub fn holds(&self, removed: usize, base: usize) -> bool {
        !self.allow && removed >= self.min && removed * 100 > (self.percent as usize) * base
    }
}

impl OffboardSettings {
    pub fn load() -> Result<Self> {
        Self::from_env(&ProcessEnv)
    }

    pub fn from_env(env: &dyn Env) -> Result<Self> {
        Ok(OffboardSettings {
            database_url: required_secret(env, "NETPORTAL_DATABASE_URL")?,
            authentik_api: http_url(env, "NETPORTAL_AUTHENTIK_API")?,
            authentik_token: secret(env, "NETPORTAL_AUTHENTIK_TOKEN")?,
            policies: policies(env)?,
            dae: dae(env)?,
            heartbeat: PathBuf::from(or_default(env, "NETPORTAL_HEARTBEAT", "/tmp/netportal-offboard.heartbeat")),
            mass: MassRemoval {
                min: integer(env, "NETPORTAL_OFFBOARD_MASS_MIN", 3, 1..=100_000)?,
                percent: integer(env, "NETPORTAL_OFFBOARD_MASS_PERCENT", 50, 0..=100)?,
                allow: boolean(env, "NETPORTAL_OFFBOARD_ALLOW_MASS", false)?,
            },
            acct_interim_s: integer(env, "NETPORTAL_ACCT_INTERIM_S", 300, 30..=86400)?,
            disconnect_recheck: Duration::from_secs(integer(env, "NETPORTAL_DISCONNECT_RECHECK_S", 30u64, 0..=3600)?),
        })
    }

    /// Whether the directory can be read (API URL and token set).
    pub fn enabled(&self) -> bool {
        self.authentik_api.is_some() && self.authentik_token.is_some()
    }
}

// --- init-db -------------------------------------------------------------------------------------

/// Everything `netportal init-db` needs: the database and the policies to seed.
#[derive(Debug, Clone)]
pub struct InitDbSettings {
    pub database_url: Secret<String>,
    pub policies: Policies,
}

impl InitDbSettings {
    pub fn load() -> Result<Self> {
        Self::from_env(&ProcessEnv)
    }

    pub fn from_env(env: &dyn Env) -> Result<Self> {
        Ok(InitDbSettings { database_url: required_secret(env, "NETPORTAL_DATABASE_URL")?, policies: policies(env)? })
    }
}

// --- the collector -------------------------------------------------------------------------------

pub const DEFAULT_LOKI_SELECTOR: &str = r#"{application="unifi_system_log",category="CLIENT_DEVICES"}"#;

static LOKI_SELECTOR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\{[^{}]+\}$").expect("a valid regular expression"));
static CONTAINER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$").expect("a valid regular expression"));

/// Everything `netportal collect` and `netportal job` need (no web secrets).
#[derive(Debug, Clone)]
pub struct CollectSettings {
    pub database_url: Secret<String>,
    /// `NETPORTAL_SSID`: only its clients count
    pub ssid: String,
    /// `NETPORTAL_PROMETHEUS_URL`; `None`: the Prometheus jobs fail (recorded)
    pub prometheus_url: Option<String>,
    /// `NETPORTAL_LOKI_URL`; `None`: unifi_events fails (recorded)
    pub loki_url: Option<String>,
    /// `NETPORTAL_TIMEZONE` (`Europe/Berlin`): the rollups' days
    pub timezone: String,
    /// `NETPORTAL_HEARTBEAT` (`/tmp/netportal-collect.heartbeat`)
    pub heartbeat: PathBuf,
    /// `NETPORTAL_COLLECT_QUERY_TIMEOUT` (20 s, at most 300): per Prometheus/Loki request
    pub query_timeout: Duration,
    /// `NETPORTAL_LOKI_SELECTOR`: the LogQL stream selector of the UniFi client entries
    pub loki_selector: String,
    /// `NETPORTAL_RADIUS_CONTAINER` (`netaccess-radius`): FreeRADIUS's container in cAdvisor
    pub radius_container: String,
}

impl CollectSettings {
    pub fn load() -> Result<Self> {
        Self::from_env(&ProcessEnv)
    }

    pub fn from_env(env: &dyn Env) -> Result<Self> {
        let loki_selector = or_default(env, "NETPORTAL_LOKI_SELECTOR", DEFAULT_LOKI_SELECTOR);
        if !LOKI_SELECTOR.is_match(&loki_selector) {
            return err(format!("NETPORTAL_LOKI_SELECTOR: {loki_selector:?} is not a stream selector {{...}}"));
        }
        let radius_container = or_default(env, "NETPORTAL_RADIUS_CONTAINER", "netaccess-radius");
        if !CONTAINER.is_match(&radius_container) {
            return err(format!("NETPORTAL_RADIUS_CONTAINER: {radius_container:?} is not a container name"));
        }
        Ok(CollectSettings {
            database_url: required_secret(env, "NETPORTAL_DATABASE_URL")?,
            ssid: required(env, "NETPORTAL_SSID")?,
            prometheus_url: http_url(env, "NETPORTAL_PROMETHEUS_URL")?,
            loki_url: http_url(env, "NETPORTAL_LOKI_URL")?,
            timezone: timezone(env)?,
            heartbeat: PathBuf::from(or_default(env, "NETPORTAL_HEARTBEAT", "/tmp/netportal-collect.heartbeat")),
            query_timeout: seconds(env, "NETPORTAL_COLLECT_QUERY_TIMEOUT", 20.0, 300.0)?,
            loki_selector,
            radius_container,
        })
    }
}

// --- the IoT controller ----------------------------------------------------------------------------

/// Everything `netportal iot` needs (house-infra docs/IOT-ACCESS.md): the registry (the jobs'
/// role), UniFi's legacy API (the IoT SSID's keys, kicks and blocks, the client list) and
/// OPNsense's API (aliases, rules, states, DHCP leases). No web, OIDC, CA or DAE secrets.
#[derive(Debug, Clone)]
pub struct IotSettings {
    pub database_url: Secret<String>,
    /// `NETPORTAL_HEARTBEAT` (`/tmp/netportal-iot.heartbeat`): touched after every round
    pub heartbeat: PathBuf,
    /// `NETPORTAL_UNIFI_URL` (`https://unifi.<domain>`): the controller's web UI (its legacy API)
    pub unifi_url: Option<String>,
    /// `NETPORTAL_UNIFI_SITE` (`default`)
    pub unifi_site: String,
    /// `NETPORTAL_UNIFI_USER`, `NETPORTAL_UNIFI_PASSWORD` / `_FILE`: a site admin of its own
    pub unifi_user: Option<String>,
    pub unifi_password: Option<Secret<String>>,
    /// `NETPORTAL_UNIFI_VERIFY_TLS` (true)
    pub unifi_verify_tls: bool,
    /// `NETPORTAL_UNIFI_IOT_SSID`: the PPSK SSID whose keys the controller owns
    pub unifi_iot_ssid: String,
    /// `NETPORTAL_UNIFI_IOT_NETWORK`: the UniFi network (VLAN 40) every key maps to
    pub unifi_iot_network: String,
    /// `NETPORTAL_IOT_MAX_KEYS` (200, 1..=2000): keys the controller puts into the SSID at most
    pub max_keys: usize,
    /// `NETPORTAL_OPNSENSE_URL` (`https://opnsense.internal`)
    pub opnsense_url: Option<String>,
    /// `NETPORTAL_OPNSENSE_API_KEY`, `NETPORTAL_OPNSENSE_API_SECRET` / `_FILE`: the controller's own
    /// API user (aliases, the filter, diagnostics)
    pub opnsense_api_key: Option<String>,
    pub opnsense_api_secret: Option<Secret<String>>,
    /// `NETPORTAL_OPNSENSE_CA`: the PEM file of the API's certificate (its CA); unset: the system roots
    pub opnsense_ca: Option<PathBuf>,
    /// `NETPORTAL_RESIDENTS_CIDR` (`10.0.30.0/24`), `NETPORTAL_RESIDENTS_GATEWAY` (`10.0.30.1`): the
    /// residents' VLAN (the rules' interface is found by the gateway address)
    pub residents_cidr: String,
    pub residents_gateway: String,
    /// `NETPORTAL_IOT_CIDR` (`10.0.40.0/24`), `NETPORTAL_IOT_GATEWAY` (`10.0.40.1`)
    pub iot_cidr: String,
    pub iot_gateway: String,
    /// `NETPORTAL_IOT_PREFIX` (`np_iot`): the aliases' and rules' name prefix
    pub prefix: String,
    /// `NETPORTAL_IOT_REVERSE_RULES` (false): also a rule per person from their devices back to them
    pub reverse_rules: bool,
    /// `NETPORTAL_IOT_READBACK_S` (900, 60..=86400): how often UniFi and OPNsense are read back whole
    pub readback: Duration,
    /// `NETPORTAL_IOT_API_TIMEOUT` (15 s, at most 120): per UniFi or OPNsense request
    pub api_timeout: Duration,
}

impl IotSettings {
    pub fn load() -> Result<Self> {
        Self::from_env(&ProcessEnv)
    }

    pub fn from_env(env: &dyn Env) -> Result<Self> {
        let prefix = or_default(env, "NETPORTAL_IOT_PREFIX", "np_iot");
        if !prefix.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') || prefix.len() > 16 {
            return err(format!("NETPORTAL_IOT_PREFIX: {prefix:?} must be [a-z0-9_], at most 16 characters"));
        }
        Ok(IotSettings {
            database_url: required_secret(env, "NETPORTAL_DATABASE_URL")?,
            heartbeat: PathBuf::from(or_default(env, "NETPORTAL_HEARTBEAT", "/tmp/netportal-iot.heartbeat")),
            unifi_url: http_url(env, "NETPORTAL_UNIFI_URL")?,
            unifi_site: or_default(env, "NETPORTAL_UNIFI_SITE", "default"),
            unifi_user: value(env, "NETPORTAL_UNIFI_USER"),
            unifi_password: secret(env, "NETPORTAL_UNIFI_PASSWORD")?,
            unifi_verify_tls: boolean(env, "NETPORTAL_UNIFI_VERIFY_TLS", true)?,
            unifi_iot_ssid: or_default(env, "NETPORTAL_UNIFI_IOT_SSID", "Scharni-IoT"),
            unifi_iot_network: or_default(env, "NETPORTAL_UNIFI_IOT_NETWORK", "IoT"),
            max_keys: integer(env, "NETPORTAL_IOT_MAX_KEYS", 200usize, 1..=2000)?,
            opnsense_url: http_url(env, "NETPORTAL_OPNSENSE_URL")?,
            opnsense_api_key: value(env, "NETPORTAL_OPNSENSE_API_KEY"),
            opnsense_api_secret: secret(env, "NETPORTAL_OPNSENSE_API_SECRET")?,
            opnsense_ca: value(env, "NETPORTAL_OPNSENSE_CA").map(PathBuf::from),
            residents_cidr: cidr(env, "NETPORTAL_RESIDENTS_CIDR", "10.0.30.0/24")?,
            residents_gateway: ipv4(env, "NETPORTAL_RESIDENTS_GATEWAY", "10.0.30.1")?,
            iot_cidr: cidr(env, "NETPORTAL_IOT_CIDR", "10.0.40.0/24")?,
            iot_gateway: ipv4(env, "NETPORTAL_IOT_GATEWAY", "10.0.40.1")?,
            prefix,
            reverse_rules: boolean(env, "NETPORTAL_IOT_REVERSE_RULES", false)?,
            readback: Duration::from_secs(integer(env, "NETPORTAL_IOT_READBACK_S", 900u64, 60..=86400)?),
            api_timeout: seconds(env, "NETPORTAL_IOT_API_TIMEOUT", 15.0, 120.0)?,
        })
    }

    /// Whether UniFi can be driven (URL, user and password set).
    pub fn unifi_enabled(&self) -> bool {
        self.unifi_url.is_some() && self.unifi_user.is_some() && self.unifi_password.is_some()
    }

    /// Whether OPNsense can be driven (URL, key and secret set).
    pub fn opnsense_enabled(&self) -> bool {
        self.opnsense_url.is_some() && self.opnsense_api_key.is_some() && self.opnsense_api_secret.is_some()
    }
}

fn ipv4(env: &dyn Env, name: &str, default: &str) -> Result<String> {
    let text = or_default(env, name, default);
    if text.parse::<std::net::Ipv4Addr>().is_err() {
        return err(format!("{name}: {text:?} is not an IPv4 address"));
    }
    Ok(text)
}

fn cidr(env: &dyn Env, name: &str, default: &str) -> Result<String> {
    let text = or_default(env, name, default);
    let valid = text
        .split_once('/')
        .and_then(|(a, l)| Some((a.parse::<std::net::Ipv4Addr>().ok()?, l.parse::<u8>().ok()?)))
        .is_some_and(|(_, l)| l <= 32);
    if !valid {
        return err(format!("{name}: {text:?} is not an IPv4 network (a.b.c.d/len)"));
    }
    Ok(text)
}

// --- the discovery proxy -------------------------------------------------------------------------

/// Everything `netportal discovery` needs: the registry through the read-only role and the two
/// network legs. No credentials of any kind.
#[derive(Debug, Clone)]
pub struct DiscoverySettings {
    pub database_url: Secret<String>,
    /// `NETPORTAL_HEARTBEAT` (`/tmp/netportal-discovery.heartbeat`)
    pub heartbeat: PathBuf,
    /// `NETPORTAL_DISCOVERY_RESIDENTS_IFACE` (`eth1`): the leg in the residents' VLAN (queries arrive, answers leave)
    pub residents_iface: String,
    /// `NETPORTAL_DISCOVERY_IOT_IFACE` (`eth2`): the leg in the IoT VLAN (the devices' records are learned)
    pub iot_iface: String,
    /// `NETPORTAL_DISCOVERY_REFRESH_S` (10, 2..=300): how often the registry is read again
    pub refresh: Duration,
    /// `NETPORTAL_DISCOVERY_STALE_S` (600, 60..=86400): without the registry this long, only house-visible devices are answered
    pub stale_after: Duration,
    /// `NETPORTAL_DISCOVERY_TTL` (120, 10..=4500): the records' TTL in the answers
    pub ttl: u32,
    /// `NETPORTAL_DISCOVERY_SERVICES`: extra service types to browse (comma-separated, `_x._tcp`)
    pub extra_services: Vec<String>,
}

impl DiscoverySettings {
    pub fn load() -> Result<Self> {
        Self::from_env(&ProcessEnv)
    }

    pub fn from_env(env: &dyn Env) -> Result<Self> {
        let iface = |name: &str, default: &str| -> Result<String> {
            let text = or_default(env, name, default);
            let ok = !text.is_empty()
                && text.len() <= 15
                && text.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_');
            if !ok {
                return err(format!("{name}: {text:?} is not an interface name"));
            }
            Ok(text)
        };
        let extra_services: Vec<String> = or_default(env, "NETPORTAL_DISCOVERY_SERVICES", "")
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        for s in &extra_services {
            if !(s.starts_with('_') && (s.ends_with("._tcp") || s.ends_with("._udp"))) {
                return err(format!("NETPORTAL_DISCOVERY_SERVICES: {s:?} is not a service type (_name._tcp)"));
            }
        }
        Ok(DiscoverySettings {
            database_url: required_secret(env, "NETPORTAL_DATABASE_URL")?,
            heartbeat: PathBuf::from(or_default(env, "NETPORTAL_HEARTBEAT", "/tmp/netportal-discovery.heartbeat")),
            residents_iface: iface("NETPORTAL_DISCOVERY_RESIDENTS_IFACE", "eth1")?,
            iot_iface: iface("NETPORTAL_DISCOVERY_IOT_IFACE", "eth2")?,
            refresh: Duration::from_secs(integer(env, "NETPORTAL_DISCOVERY_REFRESH_S", 10u64, 2..=300)?),
            stale_after: Duration::from_secs(integer(env, "NETPORTAL_DISCOVERY_STALE_S", 600u64, 60..=86400)?),
            ttl: integer(env, "NETPORTAL_DISCOVERY_TTL", 120u32, 10..=4500)?,
            extra_services,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEA\n-----END PRIVATE KEY-----\n";
    const POLICIES: &str = "residents=30:residents,house-admins,it-admins; guests=50:former-residents";

    /// A device CA key file for every test of this module (kept until the process ends).
    static KEY_FILE: LazyLock<tempfile::NamedTempFile> = LazyLock::new(|| {
        let mut file = tempfile::NamedTempFile::new().expect("temp file");
        std::io::Write::write_all(&mut file, KEY_PEM.as_bytes()).expect("write");
        file
    });

    fn key_path() -> String {
        KEY_FILE.path().to_string_lossy().to_string()
    }

    fn portal_env() -> HashMap<String, String> {
        let key = key_path();
        [
            ("NETPORTAL_BASE_URL", "https://wifi.example.org/"),
            ("NETPORTAL_REALM", "example.org"),
            ("NETPORTAL_SSID", "Example"),
            ("NETPORTAL_RADIUS_SERVER_NAME", "radius.example.org"),
            ("NETPORTAL_DATABASE_URL", "postgresql://u:p@db/netportal"),
            ("NETPORTAL_SESSION_SECRET", "0123456789abcdef0123456789abcdef"),
            ("NETPORTAL_OIDC_ISSUER", "https://login.example.org/application/o/netportal/"),
            ("NETPORTAL_OIDC_CLIENT_ID", "netportal"),
            ("NETPORTAL_OIDC_CLIENT_SECRET", "oidc-secret"),
            ("NETPORTAL_POLICIES", POLICIES),
            ("NETPORTAL_ROOT_CERT", "/etc/netportal/root.pem"),
            ("NETPORTAL_DEVICE_CA_CERT", "/etc/netportal/device-ca.pem"),
            ("NETPORTAL_DEVICE_CA_KEY", key.as_str()),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
    }

    fn with(mut env: HashMap<String, String>, pairs: &[(&str, &str)]) -> HashMap<String, String> {
        for (k, v) in pairs {
            env.insert(k.to_string(), v.to_string());
        }
        env
    }

    fn portal_err(pairs: &[(&str, &str)]) -> String {
        match PortalSettings::from_env(&with(portal_env(), pairs)) {
            Ok(_) => String::new(),
            Err(e) => e.0,
        }
    }

    #[test]
    fn test_portal_defaults() {
        let s = PortalSettings::from_env(&portal_env()).expect("settings");
        assert_eq!(s.base_url, "https://wifi.example.org");
        assert!(s.is_https());
        assert_eq!(s.display_name, "Wi-Fi");
        assert_eq!(s.iot_ssid, "Example-IoT");
        assert_eq!(s.home_url, "https://example.org/");
        assert_eq!(s.cert_days, 365);
        assert_eq!(s.renew_overlap_days, 2);
        assert_eq!(s.dae, DaeSettings { port: 3799, secret: None, require_reply_message_authenticator: true });
        assert!(!s.passpoint);
        assert_eq!(s.logout_url, None);
        assert_eq!(s.prometheus_url, None);
        assert_eq!(s.prometheus_timeout, Duration::from_secs(4));
        assert_eq!(s.timezone, "Europe/Berlin");
        assert_eq!(s.acct_interim_s, 300);
        assert_eq!(s.device_ca_key, PathBuf::from(key_path()));
        assert_eq!(s.policies.admin_groups, BTreeSet::from(["it-admins".to_string()]));
        assert_eq!((s.db_pool_size, s.max_requests, s.max_devices), (10, 128, 20));
        assert_eq!(s.metrics_listen, None);
        assert!(s.metrics_token.is_none());
        assert_eq!((s.authentik_api.as_deref(), s.authentik_token.is_some()), (None, false));
        assert!(!s.admin_check_enabled());
        assert_eq!(s.oidc_issuer, "https://login.example.org/application/o/netportal/");
    }

    #[test]
    fn test_metrics_token_and_admin_check() {
        let token = "m".repeat(METRICS_TOKEN_MIN);
        let s = PortalSettings::from_env(&with(
            portal_env(),
            &[
                ("NETPORTAL_METRICS_TOKEN", &token),
                ("NETPORTAL_AUTHENTIK_API", "https://login.example.org/api/v3/"),
                ("NETPORTAL_AUTHENTIK_TOKEN", "reader"),
            ],
        ))
        .expect("settings");
        assert_eq!(s.metrics_token.as_ref().map(|t| t.expose().as_str()), Some(token.as_str()));
        assert_eq!(s.authentik_api.as_deref(), Some("https://login.example.org/api/v3"));
        assert!(s.admin_check_enabled());
        assert_eq!(
            portal_err(&[("NETPORTAL_METRICS_TOKEN", &"m".repeat(METRICS_TOKEN_MIN - 1))]),
            "NETPORTAL_METRICS_TOKEN: at least 32 bytes"
        );
        assert!(portal_err(&[("NETPORTAL_AUTHENTIK_API", "login:9000")]).starts_with("NETPORTAL_AUTHENTIK_API"));
        // from a file mounted read-only for the container's user (house-infra: mode 0400, uid 10001)
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("metrics-token");
        std::fs::write(&path, format!("{token}\n")).expect("write");
        let mut perms = std::fs::metadata(&path).expect("metadata").permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o400);
        std::fs::set_permissions(&path, perms).expect("chmod");
        let file = path.to_string_lossy().to_string();
        let s = PortalSettings::from_env(&with(portal_env(), &[("NETPORTAL_METRICS_TOKEN_FILE", &file)]))
            .expect("settings");
        assert_eq!(s.metrics_token.as_ref().map(|t| t.expose().as_str()), Some(token.as_str()));
        let e = portal_err(&[("NETPORTAL_METRICS_TOKEN", &token), ("NETPORTAL_METRICS_TOKEN_FILE", &file)]);
        assert!(e.contains("both set"), "{e}");
        let text = format!("{s:?}");
        assert!(!text.contains(&token), "{text}");
    }

    #[test]
    fn test_every_required_setting() {
        for name in [
            "NETPORTAL_BASE_URL",
            "NETPORTAL_REALM",
            "NETPORTAL_SSID",
            "NETPORTAL_RADIUS_SERVER_NAME",
            "NETPORTAL_DATABASE_URL",
            "NETPORTAL_SESSION_SECRET",
            "NETPORTAL_OIDC_ISSUER",
            "NETPORTAL_OIDC_CLIENT_ID",
            "NETPORTAL_OIDC_CLIENT_SECRET",
            "NETPORTAL_POLICIES",
            "NETPORTAL_ROOT_CERT",
            "NETPORTAL_DEVICE_CA_CERT",
            "NETPORTAL_DEVICE_CA_KEY",
        ] {
            let mut env = portal_env();
            env.remove(name);
            let e = PortalSettings::from_env(&env).err().map(|e| e.0);
            assert_eq!(e, Some(format!("missing setting {name}")), "{name}");
            // an empty (or blank) value is unset
            assert_eq!(portal_err(&[(name, "  ")]), format!("missing setting {name}"), "{name}");
        }
    }

    #[test]
    fn test_empty_means_default() {
        let s = PortalSettings::from_env(&with(
            portal_env(),
            &[
                ("NETPORTAL_DISPLAY_NAME", ""),
                ("NETPORTAL_PROMETHEUS_TIMEOUT", ""),
                ("NETPORTAL_TIMEZONE", ""),
                ("NETPORTAL_ACCT_INTERIM_S", " "),
            ],
        ))
        .expect("settings");
        assert_eq!(s.display_name, "Wi-Fi");
        assert_eq!(s.prometheus_timeout, Duration::from_secs(4));
        assert_eq!(s.timezone, "Europe/Berlin");
        assert_eq!(s.acct_interim_s, 300);
    }

    #[test]
    fn test_validation_messages() {
        assert_eq!(
            portal_err(&[("NETPORTAL_ACCT_INTERIM_S", "29")]),
            "NETPORTAL_ACCT_INTERIM_S: \"29\" is not a whole number in 30..=86400"
        );
        assert!(portal_err(&[("NETPORTAL_ACCT_INTERIM_S", "86401")]).starts_with("NETPORTAL_ACCT_INTERIM_S"));
        assert!(portal_err(&[("NETPORTAL_ACCT_INTERIM_S", "1e3")]).starts_with("NETPORTAL_ACCT_INTERIM_S"));
        assert!(portal_err(&[("NETPORTAL_CERT_DAYS", "0")]).starts_with("NETPORTAL_CERT_DAYS"));
        assert!(portal_err(&[("NETPORTAL_DAE_PORT", "70000")]).starts_with("NETPORTAL_DAE_PORT"));
        assert!(portal_err(&[("NETPORTAL_PROMETHEUS_TIMEOUT", "-1")]).starts_with("NETPORTAL_PROMETHEUS_TIMEOUT"));
        assert!(portal_err(&[("NETPORTAL_PROMETHEUS_TIMEOUT", "nan")]).starts_with("NETPORTAL_PROMETHEUS_TIMEOUT"));
        assert_eq!(
            portal_err(&[("NETPORTAL_TIMEZONE", "Mars/Olympus")]),
            "NETPORTAL_TIMEZONE: \"Mars/Olympus\" is not a known time zone"
        );
        assert_eq!(
            portal_err(&[("NETPORTAL_PROMETHEUS_URL", "prometheus:9090")]),
            "NETPORTAL_PROMETHEUS_URL: \"prometheus:9090\" is not an http(s) URL"
        );
        assert!(portal_err(&[("NETPORTAL_BASE_URL", "wifi.example.org")]).starts_with("NETPORTAL_BASE_URL"));
        assert_eq!(
            portal_err(&[("NETPORTAL_PASSPOINT", "maybe")]),
            "NETPORTAL_PASSPOINT: \"maybe\" is not true or false"
        );
        assert_eq!(portal_err(&[("NETPORTAL_SESSION_SECRET", "short")]), "NETPORTAL_SESSION_SECRET: at least 32 bytes");
    }

    #[test]
    fn test_values_are_normalised() {
        let s = PortalSettings::from_env(&with(
            portal_env(),
            &[
                ("NETPORTAL_PROMETHEUS_URL", " http://prometheus:9090/ "),
                ("NETPORTAL_PASSPOINT", "TRUE"),
                ("NETPORTAL_HOME_URL", "https://house.example.org/"),
                ("NETPORTAL_LOGOUT_URL", "https://login.example.org/if/flow/house-logout/"),
                ("NETPORTAL_PROMETHEUS_TIMEOUT", "2.5"),
                ("NETPORTAL_ADMIN_GROUPS", " it-admins, house-admins ,,"),
            ],
        ))
        .expect("settings");
        assert_eq!(s.prometheus_url.as_deref(), Some("http://prometheus:9090"));
        assert!(s.passpoint);
        assert_eq!(s.home_url, "https://house.example.org/");
        assert_eq!(s.logout_url.as_deref(), Some("https://login.example.org/if/flow/house-logout/"));
        assert_eq!(s.prometheus_timeout, Duration::from_millis(2500));
        assert_eq!(s.policies.admin_groups.len(), 2);
    }

    #[test]
    fn test_secret_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("db");
        std::fs::write(&path, "  postgresql://from-file/db\n").expect("write");
        let path = path.to_string_lossy().to_string();
        let mut env = portal_env();
        env.remove("NETPORTAL_DATABASE_URL");
        env.insert("NETPORTAL_DATABASE_URL_FILE".into(), path.clone());
        let s = PortalSettings::from_env(&env).expect("settings");
        assert_eq!(s.database_url.expose(), "postgresql://from-file/db");
        // both: refused
        env.insert("NETPORTAL_DATABASE_URL".into(), "postgresql://x/y".into());
        let e = PortalSettings::from_env(&env).err().map(|e| e.0).unwrap_or_default();
        assert!(e.contains("both set"), "{e}");
        // a missing file names the variable
        env.remove("NETPORTAL_DATABASE_URL");
        env.insert("NETPORTAL_DATABASE_URL_FILE".into(), format!("{path}.missing"));
        let e = PortalSettings::from_env(&env).err().map(|e| e.0).unwrap_or_default();
        assert!(e.starts_with("NETPORTAL_DATABASE_URL_FILE: cannot read"), "{e}");
        // optional secrets
        let s = PortalSettings::from_env(&with(portal_env(), &[("NETPORTAL_DAE_SECRET", "s3cret")])).expect("settings");
        assert_eq!(s.dae.secret.as_ref().map(|s| s.expose().as_str()), Some("s3cret"));
    }

    #[test]
    fn test_device_ca_key() {
        let s = PortalSettings::from_env(&portal_env()).expect("settings");
        assert_eq!(read_device_ca_key(&s.device_ca_key).expect("key").as_slice(), KEY_PEM.as_bytes());
        // only from a file: a key in the environment is refused, with what to do instead
        let b64 = "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCg==";
        let e = portal_err(&[("NETPORTAL_DEVICE_CA_KEY_B64", b64)]);
        assert!(e.starts_with("NETPORTAL_DEVICE_CA_KEY_B64 is not supported"), "{e}");
        let mut env = portal_env();
        env.remove("NETPORTAL_DEVICE_CA_KEY");
        env.insert("NETPORTAL_DEVICE_CA_KEY_B64".into(), b64.into());
        assert!(PortalSettings::from_env(&env).is_err());
        let dir = tempfile::tempdir().expect("tempdir");
        let not_pem = dir.path().join("key.der");
        std::fs::write(&not_pem, b"hello").expect("write");
        assert_eq!(
            portal_err(&[("NETPORTAL_DEVICE_CA_KEY", &not_pem.to_string_lossy())]),
            "NETPORTAL_DEVICE_CA_KEY: not a PEM key"
        );
        let missing = dir.path().join("missing.pem");
        assert!(
            portal_err(&[("NETPORTAL_DEVICE_CA_KEY", &missing.to_string_lossy())])
                .starts_with("NETPORTAL_DEVICE_CA_KEY: cannot read")
        );
    }

    #[test]
    fn test_capacity_and_metrics_settings() {
        let s = PortalSettings::from_env(&with(
            portal_env(),
            &[
                ("NETPORTAL_DB_POOL_SIZE", "4"),
                ("NETPORTAL_MAX_REQUESTS", "32"),
                ("NETPORTAL_METRICS_LISTEN", "0.0.0.0:9100"),
                ("NETPORTAL_MAX_DEVICES", "5"),
                ("NETPORTAL_DAE_REQUIRE_REPLY_MESSAGE_AUTHENTICATOR", "false"),
            ],
        ))
        .expect("settings");
        assert_eq!((s.db_pool_size, s.max_requests, s.max_devices), (4, 32, 5));
        assert_eq!(s.metrics_listen.as_deref(), Some("0.0.0.0:9100"));
        assert!(!s.dae.require_reply_message_authenticator);
        assert_eq!(
            portal_err(&[("NETPORTAL_METRICS_LISTEN", "localhost:9100")]),
            "NETPORTAL_METRICS_LISTEN: \"localhost:9100\" is not host:port (an IP address and a port)"
        );
        for (name, bad) in [
            ("NETPORTAL_DB_POOL_SIZE", "0"),
            ("NETPORTAL_DB_POOL_SIZE", "101"),
            ("NETPORTAL_MAX_REQUESTS", "0"),
            ("NETPORTAL_MAX_DEVICES", "0"),
            ("NETPORTAL_DAE_REQUIRE_REPLY_MESSAGE_AUTHENTICATOR", "perhaps"),
        ] {
            assert!(portal_err(&[(name, bad)]).starts_with(name), "{name}={bad}");
        }
    }

    #[test]
    fn test_mass_removal_settings() {
        let env: BTreeMap<&str, &str> =
            [("NETPORTAL_DATABASE_URL", "postgresql://u:p@db/n"), ("NETPORTAL_POLICIES", POLICIES)].into();
        let s = OffboardSettings::from_env(&env).expect("settings");
        assert_eq!(s.mass, MassRemoval { min: 3, percent: 50, allow: false });
        assert_eq!(s.dae, DaeSettings::new(3799, None));
        assert_eq!((s.acct_interim_s, s.disconnect_recheck), (300, Duration::from_secs(30)));
        // vault-orgs' rule: at least 3, and more than half
        assert!(!s.mass.holds(2, 2));
        assert!(!s.mass.holds(3, 6));
        assert!(s.mass.holds(3, 5));
        assert!(s.mass.holds(8, 9));
        assert!(!MassRemoval { allow: true, ..s.mass }.holds(8, 9));
        let mut env = env;
        env.insert("NETPORTAL_OFFBOARD_MASS_MIN", "1");
        env.insert("NETPORTAL_OFFBOARD_MASS_PERCENT", "0");
        env.insert("NETPORTAL_OFFBOARD_ALLOW_MASS", "yes");
        let s = OffboardSettings::from_env(&env).expect("settings");
        assert_eq!(s.mass, MassRemoval { min: 1, percent: 0, allow: true });
        env.insert("NETPORTAL_OFFBOARD_MASS_PERCENT", "101");
        assert!(OffboardSettings::from_env(&env).is_err());
        env.insert("NETPORTAL_OFFBOARD_MASS_PERCENT", "50");
        env.insert("NETPORTAL_DISCONNECT_RECHECK_S", "0");
        env.insert("NETPORTAL_ACCT_INTERIM_S", "120");
        let s = OffboardSettings::from_env(&env).expect("settings");
        assert_eq!((s.acct_interim_s, s.disconnect_recheck), (120, Duration::ZERO));
        for (name, bad) in [("NETPORTAL_DISCONNECT_RECHECK_S", "3601"), ("NETPORTAL_ACCT_INTERIM_S", "29")] {
            let mut e = env.clone();
            e.insert(name, bad);
            assert!(OffboardSettings::from_env(&e).err().is_some_and(|e| e.0.starts_with(name)), "{name}={bad}");
        }
    }

    #[test]
    fn test_secrets_are_not_in_debug_output() {
        let s = PortalSettings::from_env(&with(portal_env(), &[("NETPORTAL_DAE_SECRET", "dae-very-secret")]))
            .expect("settings");
        let text = format!("{s:?}");
        for secret in ["postgresql://u:p@db", "0123456789abcdef", "oidc-secret", "dae-very-secret", "BEGIN"] {
            assert!(!text.contains(secret), "{secret} in {text}");
        }
        assert!(text.contains("Secret(***)"));
    }

    // Python tests/test_units.py PolicyTests

    #[test]
    fn test_parse() {
        let policies = parse_policies(POLICIES).expect("policies");
        let pairs: Vec<_> = policies.iter().map(|p| (p.name.as_str(), p.vlan)).collect();
        assert_eq!(pairs, [("residents", 30), ("guests", 50)]);
        assert_eq!(policies[1].groups, BTreeSet::from(["former-residents".to_string()]));
        for bad in [
            "",
            "residents=30",
            "residents=0:residents",
            "residents=4095:residents",
            "residents=99999999999:residents",
            "Residents=30:residents",
            "residents=30:residents;residents=40:guests",
            "residents=30:residents;guests=50:residents",
            "residents=30: , ",
        ] {
            assert!(parse_policies(bad).is_err(), "{bad:?}");
        }
        assert_eq!(
            parse_policies("residents=30:residents;residents=40:guests").err().map(|e| e.0),
            Some("NETPORTAL_POLICIES: residents twice".to_string())
        );
    }

    #[test]
    fn test_policy_for() {
        let s = Policies {
            list: parse_policies(POLICIES).expect("policies"),
            admin_groups: BTreeSet::from(["it-admins".to_string()]),
        };
        assert_eq!(s.policy_for(&["residents"]), Some("residents"));
        assert_eq!(s.policy_for(&["former-residents"]), Some("guests"));
        assert_eq!(s.policy_for(&["former-residents", "residents"]), Some("residents")); // moving out: the first
        assert_eq!(s.policy_for(&["it-admins"]), Some("residents"));
        assert_eq!(s.policy_for(&["vpn-users"]), None);
        assert_eq!(s.policy_for::<&str>(&[]), None);
        let only_admin = Policies {
            list: parse_policies("guests=50:former-residents").expect("policies"),
            admin_groups: BTreeSet::from(["it-admins".to_string()]),
        };
        assert_eq!(only_admin.policy_for(&["it-admins"]), Some("guests"));
        let allowed: Vec<_> = s.allowed_groups().into_iter().collect();
        assert_eq!(allowed, ["former-residents", "house-admins", "it-admins", "residents"]);
    }

    #[test]
    fn test_the_old_single_policy_settings_are_gone() {
        let mut env = portal_env();
        env.remove("NETPORTAL_POLICIES");
        env.insert("NETPORTAL_DEFAULT_VLAN".into(), "30".into());
        env.insert("NETPORTAL_ALLOWED_GROUPS".into(), "residents".into());
        assert_eq!(
            PortalSettings::from_env(&env).err().map(|e| e.0),
            Some("missing setting NETPORTAL_POLICIES".to_string())
        );
    }

    #[test]
    fn test_offboard_needs_no_web_secrets() {
        let env: BTreeMap<&str, &str> =
            [("NETPORTAL_DATABASE_URL", "postgresql://u:p@db/n"), ("NETPORTAL_POLICIES", POLICIES)].into();
        let s = OffboardSettings::from_env(&env).expect("settings");
        assert!(!s.enabled());
        assert_eq!(s.heartbeat, PathBuf::from("/tmp/netportal-offboard.heartbeat"));
        let mut env = env;
        env.insert("NETPORTAL_AUTHENTIK_API", "https://login.example.org/api/v3/");
        env.insert("NETPORTAL_AUTHENTIK_TOKEN", "t");
        env.insert("NETPORTAL_HEARTBEAT", "/run/hb");
        let s = OffboardSettings::from_env(&env).expect("settings");
        assert!(s.enabled());
        assert_eq!(s.authentik_api.as_deref(), Some("https://login.example.org/api/v3"));
        assert_eq!(s.heartbeat, PathBuf::from("/run/hb"));
        let s = InitDbSettings::from_env(&env).expect("settings");
        assert_eq!(s.policies.list.len(), 2);
    }

    #[test]
    fn test_collect_settings() {
        let env: BTreeMap<&str, &str> =
            [("NETPORTAL_DATABASE_URL", "postgresql://u:p@db/n"), ("NETPORTAL_SSID", "Example")].into();
        let s = CollectSettings::from_env(&env).expect("settings");
        assert_eq!(s.loki_selector, DEFAULT_LOKI_SELECTOR);
        assert_eq!(s.radius_container, "netaccess-radius");
        assert_eq!(s.heartbeat, PathBuf::from("/tmp/netportal-collect.heartbeat"));
        assert_eq!(s.query_timeout, Duration::from_secs(20));
        assert_eq!((s.prometheus_url, s.loki_url), (None, None));
        let bad = |k, v| {
            let mut e = env.clone();
            e.insert(k, v);
            CollectSettings::from_env(&e).err().map(|e| e.0).unwrap_or_default()
        };
        assert!(bad("NETPORTAL_LOKI_SELECTOR", "application=x").starts_with("NETPORTAL_LOKI_SELECTOR"));
        assert!(bad("NETPORTAL_RADIUS_CONTAINER", "-x").starts_with("NETPORTAL_RADIUS_CONTAINER"));
        assert!(bad("NETPORTAL_TIMEZONE", "Nowhere/City").starts_with("NETPORTAL_TIMEZONE"));
        assert!(bad("NETPORTAL_LOKI_URL", "loki:3100").starts_with("NETPORTAL_LOKI_URL"));
        assert!(bad("NETPORTAL_COLLECT_QUERY_TIMEOUT", "0").starts_with("NETPORTAL_COLLECT_QUERY_TIMEOUT"));
        let mut e = env.clone();
        e.remove("NETPORTAL_SSID");
        assert_eq!(CollectSettings::from_env(&e).err().map(|e| e.0), Some("missing setting NETPORTAL_SSID".into()));
    }

    #[test]
    fn test_iot_settings() {
        let env: HashMap<String, String> = [("NETPORTAL_DATABASE_URL", "postgresql://u:p@db/netportal")]
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        let s = IotSettings::from_env(&env).unwrap();
        assert!(!s.unifi_enabled() && !s.opnsense_enabled());
        assert_eq!(
            (s.prefix.as_str(), s.residents_cidr.as_str(), s.iot_gateway.as_str()),
            ("np_iot", "10.0.30.0/24", "10.0.40.1")
        );
        let mut e = env.clone();
        e.insert("NETPORTAL_IOT_CIDR".into(), "10.0.40.0".into());
        assert!(IotSettings::from_env(&e).unwrap_err().0.starts_with("NETPORTAL_IOT_CIDR"));
        let mut e = env.clone();
        e.insert("NETPORTAL_IOT_PREFIX".into(), "Np-Iot".into());
        assert!(IotSettings::from_env(&e).unwrap_err().0.starts_with("NETPORTAL_IOT_PREFIX"));
        let mut e = env.clone();
        for (k, v) in [
            ("NETPORTAL_UNIFI_URL", "https://unifi.example"),
            ("NETPORTAL_UNIFI_USER", "netportal-iot"),
            ("NETPORTAL_UNIFI_PASSWORD", "x"),
            ("NETPORTAL_OPNSENSE_URL", "https://opnsense.internal"),
            ("NETPORTAL_OPNSENSE_API_KEY", "k"),
            ("NETPORTAL_OPNSENSE_API_SECRET", "s"),
        ] {
            e.insert(k.into(), v.into());
        }
        let s = IotSettings::from_env(&e).unwrap();
        assert!(s.unifi_enabled() && s.opnsense_enabled());
    }

    #[test]
    fn test_discovery_settings() {
        let env: HashMap<String, String> = [
            ("NETPORTAL_DATABASE_URL", "postgresql://u:p@db/netportal"),
            ("NETPORTAL_DISCOVERY_SERVICES", "_sonos._tcp, _hap._tcp"),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect();
        let s = DiscoverySettings::from_env(&env).unwrap();
        assert_eq!((s.residents_iface.as_str(), s.iot_iface.as_str(), s.ttl), ("eth1", "eth2", 120));
        assert_eq!(s.extra_services, vec!["_sonos._tcp", "_hap._tcp"]);
        let mut e = env.clone();
        e.insert("NETPORTAL_DISCOVERY_SERVICES".into(), "sonos".into());
        assert!(DiscoverySettings::from_env(&e).unwrap_err().0.starts_with("NETPORTAL_DISCOVERY_SERVICES"));
        let mut e = env.clone();
        e.insert("NETPORTAL_DISCOVERY_IOT_IFACE".into(), "eth 2".into());
        assert!(DiscoverySettings::from_env(&e).is_err());
    }
}
