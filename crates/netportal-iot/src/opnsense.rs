//! The OPNsense API (HTTP Basic with the API key and secret; the API's CA from
//! `NETPORTAL_OPNSENSE_CA` as an extra root, else the system roots): the alias objects
//! (`firewall/alias`), their live content (`firewall/alias_util`: takes effect at once, no
//! reload), the MVC filter rules (`firewall/filter`, applied with `apply`), the states
//! (`diagnostics/firewall`) and the DHCP leases (`dnsmasq/leases`). The calls and their fields
//! are those house-infra's `roles/opnsense` and `plugins/filter/house.py` use for the kinds
//! `alias` and `filter`, and the exporter uses for the leases.
//!
//! Every object the controller makes carries a description starting with
//! [`DESCRIPTION_PREFIX`]; the reconciliation never touches an alias or rule without it.
//!
//! Field names assumed where house-infra has no precedent (to be checked against the house's
//! OPNsense, docs/IOT-ACCESS.md 7.1): `alias_util/list/<name>` rows with `ip`;
//! `query_states` rows with `id`, `creatorid`, `src_addr`, `dst_addr` (address, or
//! `address:port`); `del_state/<id>/<creatorid>` (a forum report says `delState` where
//! `del_state` is not routed: both are tried); `kill_states` with `{"filter": <address>}`
//! answering `dropped_states`; `interfacesInfo` rows with `identifier` and `addr4` or
//! `ipv4[].ipaddr` (`10.0.30.1/24`).

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Duration;

use netportal_core::config::{IotSettings, Secret};
use netportal_core::registry::normalise_mac;
use serde_json::{Value, json};

use crate::desired::Lease;

const LOG: &str = "netportal.iot.opnsense";

/// The description prefix of every alias and rule the controller owns.
pub const DESCRIPTION_PREFIX: &str = "netportal:";

#[derive(Debug, thiserror::Error)]
pub enum OpnsenseError {
    #[error("OPNsense: {0}")]
    Client(String),
    #[error("OPNsense {method} {path}: {reason}")]
    Request { method: &'static str, path: String, reason: &'static str },
    #[error("OPNsense {method} {path}: HTTP {status}")]
    Status { method: &'static str, path: String, status: u16 },
    /// The API answered, but not `saved`/`deleted`/`ok`/`done`: its message (validations).
    #[error("OPNsense {method} {path}: refused: {message}")]
    Refused { method: &'static str, path: String, message: String },
}

impl OpnsenseError {
    pub fn is_not_found(&self) -> bool {
        matches!(self, OpnsenseError::Status { status: 404, .. })
    }
}

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

/// An alias object as `searchItem` lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasRow {
    pub uuid: String,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub kind: String,
}

impl AliasRow {
    pub fn is_ours(&self) -> bool {
        self.description.starts_with(DESCRIPTION_PREFIX)
    }
}

/// A filter rule as `searchRule` lists it: the uuid and the fields the controller writes (as
/// strings, the API's own form).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleRow {
    pub uuid: String,
    pub fields: BTreeMap<String, String>,
}

impl RuleRow {
    pub fn description(&self) -> &str {
        self.fields.get("description").map(String::as_str).unwrap_or("")
    }

    pub fn is_ours(&self) -> bool {
        self.description().starts_with(DESCRIPTION_PREFIX)
    }
}

/// A state of the state table (`query_states`), addresses without ports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub id: String,
    pub creatorid: String,
    pub src: String,
    pub dst: String,
}

/// The fields of a filter rule the controller writes (house.py's kind `filter`).
pub const RULE_FIELDS: [&str; 15] = [
    "enabled",
    "sequence",
    "action",
    "quick",
    "interface",
    "direction",
    "ipprotocol",
    "protocol",
    "source_net",
    "source_not",
    "destination_net",
    "destination_not",
    "destination_port",
    "log",
    "description",
];

pub struct OpnsenseClient {
    http: reqwest::Client,
    /// `https://opnsense.internal`, no trailing slash
    base: String,
    key: String,
    secret: Secret<String>,
}

impl std::fmt::Debug for OpnsenseClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpnsenseClient").field("base", &self.base).finish_non_exhaustive()
    }
}

fn text_of(v: &Value, key: &str) -> String {
    match v.get(key) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => if *b { "1" } else { "0" }.to_string(),
        _ => String::new(),
    }
}

fn rows_of(v: &Value) -> Vec<Value> {
    match v.get("rows") {
        Some(Value::Array(rows)) => rows.clone(),
        _ => match v {
            Value::Array(rows) => rows.clone(),
            _ => Vec::new(),
        },
    }
}

/// Every string in a nested value (an interface row's `addr4` / `ipv4[].ipaddr`).
fn strings_in(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => out.push(s.clone()),
        Value::Array(items) => items.iter().for_each(|i| strings_in(i, out)),
        Value::Object(map) => map.values().for_each(|i| strings_in(i, out)),
        _ => {}
    }
}

/// `10.0.30.5:443` -> `10.0.30.5`; an address without a port stays; anything that is not IPv4
/// stays as it is.
pub fn without_port(address: &str) -> String {
    let address = address.trim();
    if address.parse::<Ipv4Addr>().is_ok() {
        return address.to_string();
    }
    if let Some((host, _port)) = address.rsplit_once(':')
        && host.parse::<Ipv4Addr>().is_ok()
    {
        return host.to_string();
    }
    address.to_string()
}

const SEARCH_ALL: &str = r#"{"current": 1, "rowCount": -1, "searchPhrase": ""}"#;

impl OpnsenseClient {
    /// The client of the settings, `None` when OPNsense is not configured (`opnsense_enabled`).
    pub fn new(settings: &IotSettings) -> Result<Option<OpnsenseClient>, OpnsenseError> {
        let (Some(url), Some(key), Some(secret)) =
            (&settings.opnsense_url, &settings.opnsense_api_key, &settings.opnsense_api_secret)
        else {
            return Ok(None);
        };
        let ca = match &settings.opnsense_ca {
            Some(path) => Some(read_ca(path)?),
            None => None,
        };
        Self::from_parts(url, key, secret.clone(), ca.as_deref(), settings.api_timeout).map(Some)
    }

    /// `ca_pem`: the API's certificate chain (PEM, one or more certificates) added to the roots.
    pub fn from_parts(
        url: &str,
        key: &str,
        secret: Secret<String>,
        ca_pem: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<OpnsenseClient, OpnsenseError> {
        let mut builder = reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("netportal-iot/", env!("CARGO_PKG_VERSION")));
        if let Some(pem) = ca_pem {
            let certs = reqwest::Certificate::from_pem_bundle(pem)
                .map_err(|_| OpnsenseError::Client("NETPORTAL_OPNSENSE_CA: not a PEM certificate bundle".into()))?;
            if certs.is_empty() {
                return Err(OpnsenseError::Client("NETPORTAL_OPNSENSE_CA: no certificate in the file".into()));
            }
            for cert in certs {
                builder = builder.add_root_certificate(cert);
            }
        }
        let http = builder.build().map_err(|_| OpnsenseError::Client("no HTTP client".into()))?;
        Ok(OpnsenseClient { http, base: url.trim_end_matches('/').to_string(), key: key.to_string(), secret })
    }

    async fn send(&self, method: &'static str, path: &str, body: Option<&Value>) -> Result<Value, OpnsenseError> {
        let url = format!("{}/api/{path}", self.base);
        let mut request = if method == "GET" { self.http.get(&url) } else { self.http.post(&url) };
        request = request.basic_auth(&self.key, Some(self.secret.expose())).header("Accept", "application/json");
        if let Some(body) = body {
            request = request.json(body);
        }
        tracing::debug!(target: LOG, "{method} {}", path.split('?').next().unwrap_or(path));
        let path_only = path.split('?').next().unwrap_or(path).to_string();
        let response = request.send().await.map_err(|e| OpnsenseError::Request {
            method,
            path: path_only.clone(),
            reason: reason_of(&e),
        })?;
        let status = response.status();
        if !status.is_success() {
            return Err(OpnsenseError::Status { method, path: path_only, status: status.as_u16() });
        }
        let bytes = response.bytes().await.map_err(|e| OpnsenseError::Request {
            method,
            path: path_only.clone(),
            reason: reason_of(&e),
        })?;
        if bytes.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_slice(&bytes).map_err(|_| OpnsenseError::Request {
            method,
            path: path_only,
            reason: "unreadable answer",
        })
    }

    async fn get(&self, path: &str) -> Result<Value, OpnsenseError> {
        self.send("GET", path, None).await
    }

    async fn post(&self, path: &str, body: &Value) -> Result<Value, OpnsenseError> {
        self.send("POST", path, Some(body)).await
    }

    /// A `result` answer (`saved`, `deleted`): anything else is a refusal with the validations.
    async fn post_result(&self, path: &str, body: &Value, expected: &str) -> Result<Value, OpnsenseError> {
        let answer = self.post(path, body).await?;
        if text_of(&answer, "result") == expected {
            return Ok(answer);
        }
        Err(OpnsenseError::Refused { method: "POST", path: path.to_string(), message: refusal(&answer) })
    }

    // --- aliases -----------------------------------------------------------------------------------

    pub async fn aliases(&self) -> Result<Vec<AliasRow>, OpnsenseError> {
        let body: Value = serde_json::from_str(SEARCH_ALL).unwrap_or(Value::Null);
        let answer = self.post("firewall/alias/searchItem", &body).await?;
        Ok(rows_of(&answer)
            .iter()
            .filter(|r| !text_of(r, "uuid").is_empty() && !text_of(r, "name").is_empty())
            .map(|r| AliasRow {
                uuid: text_of(r, "uuid"),
                name: text_of(r, "name"),
                description: text_of(r, "description"),
                enabled: text_of(r, "enabled") == "1",
                kind: text_of(r, "type"),
            })
            .collect())
    }

    /// A host alias with this name and description, empty; returns its uuid. The alias set
    /// needs `reconfigure_aliases` once afterwards.
    pub async fn add_alias(&self, name: &str, description: &str) -> Result<String, OpnsenseError> {
        let body =
            json!({"alias": {"enabled": "1", "name": name, "type": "host", "content": "", "description": description}});
        let answer = self.post_result("firewall/alias/addItem", &body, "saved").await?;
        Ok(text_of(&answer, "uuid"))
    }

    pub async fn del_alias(&self, uuid: &str) -> Result<(), OpnsenseError> {
        self.post_result(&format!("firewall/alias/delItem/{uuid}"), &json!({}), "deleted").await?;
        Ok(())
    }

    /// Activate the alias objects (`{"status": "ok"}`).
    pub async fn reconfigure_aliases(&self) -> Result<(), OpnsenseError> {
        let answer = self.post("firewall/alias/reconfigure", &json!({})).await?;
        if text_of(&answer, "status").trim().eq_ignore_ascii_case("ok") {
            return Ok(());
        }
        Err(OpnsenseError::Refused {
            method: "POST",
            path: "firewall/alias/reconfigure".into(),
            message: refusal(&answer),
        })
    }

    /// The live content of a host alias (the pf table).
    pub async fn alias_content(&self, name: &str) -> Result<Vec<String>, OpnsenseError> {
        let answer = self.get(&format!("firewall/alias_util/list/{name}")).await?;
        Ok(rows_of(&answer)
            .iter()
            .map(|r| {
                let ip = text_of(r, "ip");
                if ip.is_empty() { text_of(r, "address") } else { ip }
            })
            .map(|a| a.trim().to_string())
            .filter(|a| !a.is_empty())
            .collect())
    }

    async fn alias_util(&self, verb: &str, name: &str, address: &str) -> Result<(), OpnsenseError> {
        let path = format!("firewall/alias_util/{verb}/{name}");
        let answer = self.post(&path, &json!({"address": address})).await?;
        let status = text_of(&answer, "status");
        if status.is_empty() || status.eq_ignore_ascii_case("done") || status.eq_ignore_ascii_case("ok") {
            return Ok(());
        }
        Err(OpnsenseError::Refused { method: "POST", path, message: refusal(&answer) })
    }

    /// Put an address into the alias now (no reload).
    pub async fn alias_add(&self, name: &str, address: &str) -> Result<(), OpnsenseError> {
        self.alias_util("add", name, address).await
    }

    /// Take an address out of the alias now.
    pub async fn alias_delete(&self, name: &str, address: &str) -> Result<(), OpnsenseError> {
        self.alias_util("delete", name, address).await
    }

    // --- rules -------------------------------------------------------------------------------------

    pub async fn rules(&self) -> Result<Vec<RuleRow>, OpnsenseError> {
        let body: Value = serde_json::from_str(SEARCH_ALL).unwrap_or(Value::Null);
        let answer = self.post("firewall/filter/searchRule", &body).await?;
        Ok(rows_of(&answer)
            .iter()
            .filter(|r| !text_of(r, "uuid").is_empty())
            .map(|r| RuleRow {
                uuid: text_of(r, "uuid"),
                fields: RULE_FIELDS.iter().map(|f| (f.to_string(), text_of(r, f))).collect(),
            })
            .collect())
    }

    /// `{"rule": {...}}` of the fields (the API takes strings).
    fn rule_body(fields: &BTreeMap<&'static str, String>) -> Value {
        json!({"rule": fields})
    }

    /// Returns the new rule's uuid; `apply_rules` activates it.
    pub async fn add_rule(&self, fields: &BTreeMap<&'static str, String>) -> Result<String, OpnsenseError> {
        let answer = self.post_result("firewall/filter/addRule", &Self::rule_body(fields), "saved").await?;
        Ok(text_of(&answer, "uuid"))
    }

    pub async fn set_rule(&self, uuid: &str, fields: &BTreeMap<&'static str, String>) -> Result<(), OpnsenseError> {
        self.post_result(&format!("firewall/filter/setRule/{uuid}"), &Self::rule_body(fields), "saved").await?;
        Ok(())
    }

    pub async fn del_rule(&self, uuid: &str) -> Result<(), OpnsenseError> {
        self.post_result(&format!("firewall/filter/delRule/{uuid}"), &json!({}), "deleted").await?;
        Ok(())
    }

    /// Activate the rule set (`status` "OK", with configd's newlines).
    pub async fn apply_rules(&self) -> Result<(), OpnsenseError> {
        let answer = self.post("firewall/filter/apply", &json!({})).await?;
        if text_of(&answer, "status").trim().eq_ignore_ascii_case("ok") {
            return Ok(());
        }
        Err(OpnsenseError::Refused { method: "POST", path: "firewall/filter/apply".into(), message: refusal(&answer) })
    }

    // --- interfaces ----------------------------------------------------------------------------------

    /// The interface identifier (`lan`, `opt2`, ...) of the one interface whose IPv4 address is
    /// this gateway; `None` when none or several have it.
    pub async fn interface_by_gateway(&self, gateway: &str) -> Result<Option<String>, OpnsenseError> {
        let answer = self.get("interfaces/overview/interfacesInfo").await?;
        let mut found: Vec<String> = Vec::new();
        for row in rows_of(&answer) {
            let identifier = text_of(&row, "identifier");
            if identifier.is_empty() {
                continue;
            }
            let mut addresses = Vec::new();
            for field in ["addr4", "ipv4"] {
                if let Some(v) = row.get(field) {
                    strings_in(v, &mut addresses);
                }
            }
            let hit = addresses.iter().any(|a| a == gateway || a.starts_with(&format!("{gateway}/")));
            if hit && !found.contains(&identifier) {
                found.push(identifier);
            }
        }
        Ok(if found.len() == 1 { found.pop() } else { None })
    }

    // --- states ---------------------------------------------------------------------------------------

    /// The states that mention this address (`query_states` filtered by it).
    pub async fn states(&self, address: &str) -> Result<Vec<State>, OpnsenseError> {
        let body = json!({"current": 1, "rowCount": -1, "searchPhrase": address});
        let answer = self.post("diagnostics/firewall/query_states", &body).await?;
        Ok(rows_of(&answer)
            .iter()
            .filter(|r| !text_of(r, "id").is_empty())
            .map(|r| State {
                id: text_of(r, "id"),
                creatorid: text_of(r, "creatorid"),
                src: without_port(&text_of(r, "src_addr")),
                dst: without_port(&text_of(r, "dst_addr")),
            })
            .collect())
    }

    /// Remove one state: `del_state/<id>/<creatorid>`, else `delState/...` (the forum report).
    pub async fn del_state(&self, id: &str, creatorid: &str) -> Result<(), OpnsenseError> {
        let first = format!("diagnostics/firewall/del_state/{id}/{creatorid}");
        match self.post(&first, &json!({})).await {
            Ok(answer) if !text_of(&answer, "result").eq_ignore_ascii_case("failed") => return Ok(()),
            Ok(answer) => {
                return Err(OpnsenseError::Refused { method: "POST", path: first, message: refusal(&answer) });
            }
            Err(e) if e.is_not_found() => {}
            Err(e) => return Err(e),
        }
        let second = format!("diagnostics/firewall/delState/{id}/{creatorid}");
        let answer = self.post(&second, &json!({})).await?;
        if text_of(&answer, "result").eq_ignore_ascii_case("failed") {
            return Err(OpnsenseError::Refused { method: "POST", path: second, message: refusal(&answer) });
        }
        Ok(())
    }

    /// Kill every state from or to the address (`kill_states` with a filter); returns how many
    /// when the answer says. A 404 (the version has no such call) is `is_not_found`.
    pub async fn kill_states(&self, address: &str) -> Result<Option<u64>, OpnsenseError> {
        let answer = self.post("diagnostics/firewall/kill_states", &json!({"filter": address})).await?;
        if text_of(&answer, "result").eq_ignore_ascii_case("failed") {
            return Err(OpnsenseError::Refused {
                method: "POST",
                path: "diagnostics/firewall/kill_states".into(),
                message: refusal(&answer),
            });
        }
        Ok(answer.get("dropped_states").and_then(Value::as_u64))
    }

    // --- leases ----------------------------------------------------------------------------------------

    /// The Dnsmasq leases (MAC normalised, address, expiry as epoch seconds when given).
    pub async fn leases(&self) -> Result<Vec<Lease>, OpnsenseError> {
        let answer = self.get("dnsmasq/leases/search?rowCount=-1").await?;
        Ok(rows_of(&answer)
            .iter()
            .filter_map(|r| {
                let mac = normalise_mac(&text_of(r, "hwaddr"))?;
                let address = text_of(r, "address").trim().to_string();
                if address.is_empty() {
                    return None;
                }
                let expire = match r.get("expire") {
                    Some(Value::Number(n)) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)),
                    Some(Value::String(s)) => s.trim().parse::<f64>().ok().map(|f| f as i64),
                    _ => None,
                };
                Some(Lease { mac, address, expire, hostname: text_of(r, "hostname").trim().to_string() })
            })
            .collect())
    }
}

/// The API's message of a refusal: `validations` (field: text), `status_msg`, `message`, or
/// the whole answer when short.
fn refusal(answer: &Value) -> String {
    if let Some(Value::Object(v)) = answer.get("validations") {
        let parts: Vec<String> = v.iter().map(|(k, m)| format!("{k}: {}", m.as_str().unwrap_or("invalid"))).collect();
        return parts.join("; ");
    }
    for key in ["status_msg", "message", "errorMessage", "result", "status"] {
        let text = text_of(answer, key);
        if !text.is_empty() {
            return text.chars().take(300).collect();
        }
    }
    answer.to_string().chars().take(300).collect()
}

fn read_ca(path: &Path) -> Result<Vec<u8>, OpnsenseError> {
    std::fs::read(path).map_err(|e| OpnsenseError::Client(format!("NETPORTAL_OPNSENSE_CA {}: {e}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_without_port_and_rows() {
        assert_eq!(without_port("10.0.30.5:443"), "10.0.30.5");
        assert_eq!(without_port(" 10.0.40.7 "), "10.0.40.7");
        assert_eq!(without_port("fe80::1"), "fe80::1");
        assert_eq!(rows_of(&json!({"rows": [1, 2]})).len(), 2);
        assert_eq!(rows_of(&json!([1])).len(), 1);
        assert!(rows_of(&json!({"total": 0})).is_empty());
        assert_eq!(refusal(&json!({"result": "failed", "validations": {"alias.name": "taken"}})), "alias.name: taken");
        assert_eq!(text_of(&json!({"enabled": true}), "enabled"), "1");
    }
}
