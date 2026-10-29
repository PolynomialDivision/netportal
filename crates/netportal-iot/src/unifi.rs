//! The UniFi legacy API, as house-infra `roles/unifi` drives it: a session cookie from
//! `POST /api/login`, the `X-Csrf-Token` the controller hands out with it (sent on every
//! write), the site's collections under `/api/s/<site>/`, `POST /api/logout` at the end. What
//! the IoT controller needs of it: the IoT SSID's private pre-shared keys (`rest/wlanconf`), the
//! IoT network's id (`rest/networkconf`), the client list (`stat/sta`), the blocked clients
//! (`rest/user`), kick, block and unblock (`cmd/stamgr`).
//!
//! Nothing here logs a password or a key: errors name the method, the path and the status;
//! [`Ppsk`]'s `Debug` hides the password. The cookie jar is this module's own (the login
//! response's `Set-Cookie` headers, sent back as one `Cookie` header), so reqwest needs no
//! cookie store.
//!
//! Field names the controller is assumed to use (confirmed for `wlanconf`, `networkconf`,
//! `cmd/stamgr` by `roles/unifi` and the community documentation; the rest is what UniFi 8/9
//! answer and must be checked against the house's controller, docs/IOT-ACCESS.md 7.1):
//! `private_preshared_keys: [{password, networkconf_id}]`, `private_preshared_keys_enabled`;
//! `stat/sta` entries with `mac`, `ip`, `ap_mac`, `essid`, `hostname`, `name`, `last_seen`,
//! `signal`, `vlan`, and, when the controller tells which key a client used, one of
//! `ppsk_id`, `private_preshared_key_id` or `ppsk_key_id` (read as [`Client::ppsk_id`] when
//! present; unknown today); `rest/user` entries with `mac` and `blocked`.

use std::sync::Mutex;
use std::time::Duration;

use netportal_core::config::{IotSettings, Secret};
use reqwest::header::SET_COOKIE;
use serde_json::{Value, json};

const LOG: &str = "netportal.iot.unifi";

/// Where the controller reports which key a client used, if it does (any of these).
const PPSK_ID_FIELDS: [&str; 3] = ["ppsk_id", "private_preshared_key_id", "ppsk_key_id"];

#[derive(Debug, thiserror::Error)]
pub enum UnifiError {
    #[error("UniFi: {0}")]
    Client(String),
    #[error("UniFi {method} {path}: {reason}")]
    Request { method: &'static str, path: String, reason: &'static str },
    #[error("UniFi {method} {path}: HTTP {status}")]
    Status { method: &'static str, path: String, status: u16 },
    #[error("UniFi {method} {path}: refused ({rc}{msg})")]
    Refused { method: &'static str, path: String, rc: String, msg: String },
    #[error("UniFi: no network named {0:?}")]
    NoNetwork(String),
    #[error("UniFi: no SSID named {0:?}")]
    NoSsid(String),
}

/// A reqwest error's kind only: its text may carry the URL, never a body, but the kind is all
/// the log needs.
fn reason_of(e: &reqwest::Error) -> &'static str {
    if e.is_timeout() {
        "timed out"
    } else if e.is_connect() {
        "connection failed"
    } else if e.is_decode() || e.is_body() {
        "unreadable answer"
    } else {
        "request failed"
    }
}

/// A UniFi network (`rest/networkconf`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Network {
    pub id: String,
    pub name: String,
    pub vlan: Option<i64>,
}

/// One private pre-shared key of an SSID: the key and the network (VLAN) its clients land in.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub struct Ppsk {
    pub password: String,
    pub networkconf_id: String,
}

impl std::fmt::Debug for Ppsk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ppsk").field("password", &"***").field("networkconf_id", &self.networkconf_id).finish()
    }
}

/// An SSID (`rest/wlanconf`) with the part of it the controller owns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wlan {
    pub id: String,
    pub name: String,
    pub private_preshared_keys: Vec<Ppsk>,
    pub private_preshared_keys_enabled: bool,
}

/// A connected client (`stat/sta`); every field but the MAC is optional, controller versions
/// differ.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Client {
    /// `aa:bb:cc:dd:ee:ff`
    pub mac: String,
    pub ip: Option<String>,
    pub ap_mac: Option<String>,
    pub essid: Option<String>,
    pub hostname: Option<String>,
    pub name: Option<String>,
    /// epoch seconds
    pub last_seen: Option<i64>,
    pub signal: Option<i64>,
    pub vlan: Option<i64>,
    /// the key the client used, when the controller tells (see the module doc)
    pub ppsk_id: Option<String>,
}

#[derive(Default)]
struct Session {
    /// `name=value` pairs of the login response
    cookies: Vec<(String, String)>,
    csrf: Option<String>,
}

/// A client of one controller and site; `login` first, `logout` at the end of a round.
pub struct UnifiClient {
    http: reqwest::Client,
    /// `https://unifi.example`, no trailing slash
    base: String,
    site: String,
    user: String,
    password: Secret<String>,
    session: Mutex<Session>,
}

impl std::fmt::Debug for UnifiClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnifiClient").field("base", &self.base).field("site", &self.site).finish_non_exhaustive()
    }
}

fn str_of(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(Value::as_str).map(str::to_string).filter(|s| !s.is_empty())
}

/// An integer field, also when the controller sends it as a string.
fn int_of(v: &Value, key: &str) -> Option<i64> {
    match v.get(key)? {
        Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

fn bool_of(v: &Value, key: &str) -> bool {
    match v.get(key) {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s == "true" || s == "1",
        Some(Value::Number(n)) => n.as_i64() == Some(1),
        _ => false,
    }
}

impl UnifiClient {
    /// The client of the settings, `None` when UniFi is not configured (`unifi_enabled`).
    pub fn new(settings: &IotSettings) -> Result<Option<UnifiClient>, UnifiError> {
        let (Some(url), Some(user), Some(password)) =
            (&settings.unifi_url, &settings.unifi_user, &settings.unifi_password)
        else {
            return Ok(None);
        };
        Self::from_parts(
            url,
            &settings.unifi_site,
            user,
            password.clone(),
            settings.unifi_verify_tls,
            settings.api_timeout,
        )
        .map(Some)
    }

    /// `verify_tls` false accepts any certificate (the controller's self-signed one).
    pub fn from_parts(
        url: &str,
        site: &str,
        user: &str,
        password: Secret<String>,
        verify_tls: bool,
        timeout: Duration,
    ) -> Result<UnifiClient, UnifiError> {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(timeout)
            // a redirect is an error, not something to follow with the session
            .redirect(reqwest::redirect::Policy::none())
            .danger_accept_invalid_certs(!verify_tls)
            .user_agent(concat!("netportal-iot/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| UnifiError::Client("no HTTP client".into()))?;
        Ok(UnifiClient {
            http,
            base: url.trim_end_matches('/').to_string(),
            site: site.to_string(),
            user: user.to_string(),
            password,
            session: Mutex::new(Session::default()),
        })
    }

    fn cookie_header(&self) -> Option<String> {
        let session = self.session.lock().ok()?;
        if session.cookies.is_empty() {
            return None;
        }
        Some(session.cookies.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; "))
    }

    fn csrf(&self) -> Option<String> {
        self.session.lock().ok().and_then(|s| s.csrf.clone())
    }

    /// Keep the cookies and the CSRF token of an answer (the login's; a controller may renew
    /// them on any answer).
    fn remember(&self, headers: &reqwest::header::HeaderMap) {
        let Ok(mut session) = self.session.lock() else {
            return;
        };
        for value in headers.get_all(SET_COOKIE) {
            let Ok(text) = value.to_str() else {
                continue;
            };
            let Some((name, value)) = text.split(';').next().and_then(|pair| pair.split_once('=')) else {
                continue;
            };
            let (name, value) = (name.trim().to_string(), value.trim().to_string());
            session.cookies.retain(|(k, _)| *k != name);
            session.cookies.push((name, value));
        }
        if let Some(token) = headers.get("x-csrf-token").and_then(|v| v.to_str().ok()) {
            session.csrf = Some(token.to_string());
        } else if session.csrf.is_none() {
            // the software controller puts the token into a cookie as well
            session.csrf = session.cookies.iter().find(|(k, _)| k == "csrf_token").map(|(_, v)| v.clone());
        }
    }

    async fn send(
        &self,
        method: &'static str,
        path: String,
        body: Option<Value>,
    ) -> Result<(reqwest::StatusCode, Value), UnifiError> {
        let url = format!("{}{path}", self.base);
        let mut request = match method {
            "GET" => self.http.get(&url),
            "PUT" => self.http.put(&url),
            "DELETE" => self.http.delete(&url),
            _ => self.http.post(&url),
        };
        if let Some(cookie) = self.cookie_header() {
            request = request.header("Cookie", cookie);
        }
        if method != "GET"
            && let Some(token) = self.csrf()
        {
            request = request.header("X-Csrf-Token", token);
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        tracing::debug!(target: LOG, "{method} {path}");
        let response = request.send().await.map_err(|e| UnifiError::Request {
            method,
            path: path.clone(),
            reason: reason_of(&e),
        })?;
        let status = response.status();
        self.remember(response.headers());
        let bytes = response.bytes().await.map_err(|e| UnifiError::Request {
            method,
            path: path.clone(),
            reason: reason_of(&e),
        })?;
        let json: Value =
            if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).unwrap_or(Value::Null) };
        Ok((status, json))
    }

    /// The `data` of a site call (`{"meta": {"rc": "ok"}, "data": [...]}`); a refusal
    /// (`rc` not ok, or an HTTP error) is an error with UniFi's message.
    async fn call(&self, method: &'static str, path: &str, body: Option<Value>) -> Result<Vec<Value>, UnifiError> {
        let full = format!("/api/s/{}/{path}", self.site);
        let (status, json) = self.send(method, full.clone(), body).await?;
        let meta = json.get("meta").cloned().unwrap_or(Value::Null);
        let rc = str_of(&meta, "rc").unwrap_or_default();
        if status.is_success() && rc == "ok" {
            return Ok(json.get("data").and_then(Value::as_array).cloned().unwrap_or_default());
        }
        if rc.is_empty() || rc == "ok" {
            return Err(UnifiError::Status { method, path: full, status: status.as_u16() });
        }
        let msg = str_of(&meta, "msg").map(|m| format!(": {m}")).unwrap_or_default();
        Err(UnifiError::Refused { method, path: full, rc, msg })
    }

    /// `POST /api/login`: the session cookie and the CSRF token for the writes.
    pub async fn login(&self) -> Result<(), UnifiError> {
        let body = json!({"username": self.user, "password": self.password.expose(), "remember": false});
        let (status, json) = self.send("POST", "/api/login".into(), Some(body)).await?;
        let rc = json.get("meta").and_then(|m| str_of(m, "rc")).unwrap_or_default();
        if status.is_success() && (rc.is_empty() || rc == "ok") {
            if self.cookie_header().is_none() {
                return Err(UnifiError::Request {
                    method: "POST",
                    path: "/api/login".into(),
                    reason: "no session cookie",
                });
            }
            return Ok(());
        }
        if rc.is_empty() || rc == "ok" {
            return Err(UnifiError::Status { method: "POST", path: "/api/login".into(), status: status.as_u16() });
        }
        let msg = json.get("meta").and_then(|m| str_of(m, "msg")).map(|m| format!(": {m}")).unwrap_or_default();
        Err(UnifiError::Refused { method: "POST", path: "/api/login".into(), rc, msg })
    }

    /// `POST /api/logout`; the session is forgotten whatever the answer.
    pub async fn logout(&self) {
        let _ = self.send("POST", "/api/logout".into(), None).await;
        if let Ok(mut session) = self.session.lock() {
            *session = Session::default();
        }
    }

    /// Whether a login happened (a cookie is held).
    pub fn logged_in(&self) -> bool {
        self.cookie_header().is_some()
    }

    pub async fn networks(&self) -> Result<Vec<Network>, UnifiError> {
        Ok(self
            .call("GET", "rest/networkconf", None)
            .await?
            .iter()
            .filter_map(|n| Some(Network { id: str_of(n, "_id")?, name: str_of(n, "name")?, vlan: int_of(n, "vlan") }))
            .collect())
    }

    /// The `_id` of the network with this name.
    pub async fn network_id(&self, name: &str) -> Result<String, UnifiError> {
        self.networks()
            .await?
            .into_iter()
            .find(|n| n.name == name)
            .map(|n| n.id)
            .ok_or_else(|| UnifiError::NoNetwork(name.to_string()))
    }

    pub async fn wlans(&self) -> Result<Vec<Wlan>, UnifiError> {
        Ok(self.call("GET", "rest/wlanconf", None).await?.iter().filter_map(parse_wlan).collect())
    }

    /// The SSID with this name.
    pub async fn wlan(&self, ssid: &str) -> Result<Wlan, UnifiError> {
        self.wlans().await?.into_iter().find(|w| w.name == ssid).ok_or_else(|| UnifiError::NoSsid(ssid.to_string()))
    }

    /// Set the SSID's keys to exactly these (`PUT rest/wlanconf/<id>`, the two PPSK fields only:
    /// the controller merges a partial object, the other fields stay; confirmed against a real
    /// controller on 2026-10-29, house-infra tests/unifi). PPSK is switched on with the keys and
    /// off with the last one: the controller refuses an enabled PPSK list that is empty
    /// (`api.err.EmptyPrivatePreSharedKeys`, seen at the SSID's creation on 2026-10-29), so
    /// house-infra creates the SSID with PPSK off and the first key here turns it on. With PPSK
    /// on, UniFi itself moves the SSID's own `networkconf_id` to the default network and
    /// generates its own passphrase: the network is per key (`Ppsk::networkconf_id`) from then on.
    pub async fn set_ppsk(&self, wlan_id: &str, keys: &[Ppsk]) -> Result<(), UnifiError> {
        let body = json!({"private_preshared_keys": keys, "private_preshared_keys_enabled": !keys.is_empty()});
        self.call("PUT", &format!("rest/wlanconf/{wlan_id}"), Some(body)).await?;
        Ok(())
    }

    /// The connected clients of the site.
    pub async fn clients(&self) -> Result<Vec<Client>, UnifiError> {
        Ok(self.call("GET", "stat/sta", None).await?.iter().filter_map(parse_client).collect())
    }

    /// The MACs the site blocks (`rest/user` entries with `blocked`), lowercase.
    pub async fn blocked(&self) -> Result<Vec<String>, UnifiError> {
        Ok(self
            .call("GET", "rest/user", None)
            .await?
            .iter()
            .filter(|u| bool_of(u, "blocked"))
            .filter_map(|u| str_of(u, "mac"))
            .map(|m| m.to_ascii_lowercase())
            .collect())
    }

    async fn stamgr(&self, cmd: &str, mac: &str) -> Result<(), UnifiError> {
        self.call("POST", "cmd/stamgr", Some(json!({"cmd": cmd, "mac": mac.to_ascii_lowercase()}))).await?;
        Ok(())
    }

    /// Disconnect the client now (it may come back unless its key is gone or it is blocked).
    pub async fn kick(&self, mac: &str) -> Result<(), UnifiError> {
        self.stamgr("kick-sta", mac).await
    }

    /// Refuse the MAC on every SSID of the site until `unblock`.
    pub async fn block(&self, mac: &str) -> Result<(), UnifiError> {
        self.stamgr("block-sta", mac).await
    }

    pub async fn unblock(&self, mac: &str) -> Result<(), UnifiError> {
        self.stamgr("unblock-sta", mac).await
    }
}

fn parse_wlan(w: &Value) -> Option<Wlan> {
    let keys = w
        .get("private_preshared_keys")
        .and_then(Value::as_array)
        .map(|keys| {
            keys.iter()
                .filter_map(|k| {
                    Some(Ppsk { password: str_of(k, "password")?, networkconf_id: str_of(k, "networkconf_id")? })
                })
                .collect()
        })
        .unwrap_or_default();
    Some(Wlan {
        id: str_of(w, "_id")?,
        name: str_of(w, "name")?,
        private_preshared_keys: keys,
        private_preshared_keys_enabled: bool_of(w, "private_preshared_keys_enabled"),
    })
}

fn parse_client(c: &Value) -> Option<Client> {
    Some(Client {
        mac: str_of(c, "mac")?.to_ascii_lowercase(),
        ip: str_of(c, "ip"),
        ap_mac: str_of(c, "ap_mac").map(|m| m.to_ascii_lowercase()),
        essid: str_of(c, "essid"),
        hostname: str_of(c, "hostname"),
        name: str_of(c, "name"),
        last_seen: int_of(c, "last_seen"),
        signal: int_of(c, "signal"),
        vlan: int_of(c, "vlan"),
        ppsk_id: PPSK_ID_FIELDS.iter().find_map(|f| str_of(c, f)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parsing_tolerates_controller_variants() {
        let w = json!({"_id": "w1", "name": "Scharni-IoT", "private_preshared_keys_enabled": true,
            "private_preshared_keys": [{"password": "k1", "networkconf_id": "n1"}, {"password": "", "networkconf_id": "n1"}]});
        let wlan = parse_wlan(&w).expect("wlan");
        assert_eq!(wlan.private_preshared_keys, [Ppsk { password: "k1".into(), networkconf_id: "n1".into() }]);
        assert!(wlan.private_preshared_keys_enabled);
        assert_eq!(
            format!("{:?}", wlan.private_preshared_keys[0]),
            "Ppsk { password: \"***\", networkconf_id: \"n1\" }"
        );
        let c = json!({"mac": "AA:BB:CC:DD:EE:FF", "ip": "10.0.40.7", "last_seen": "1700000000", "vlan": 40,
            "signal": -61, "private_preshared_key_id": "k-7"});
        let client = parse_client(&c).expect("client");
        assert_eq!(client.mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!((client.last_seen, client.vlan, client.signal), (Some(1700000000), Some(40), Some(-61)));
        assert_eq!(client.ppsk_id.as_deref(), Some("k-7"));
        assert!(parse_client(&json!({"ip": "10.0.40.8"})).is_none());
        assert!(bool_of(&json!({"blocked": "true"}), "blocked"));
        assert!(!bool_of(&json!({"blocked": false}), "blocked"));
    }
}
