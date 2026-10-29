//! The home devices (house-infra docs/IOT-ACCESS.md 6.6): a resident's Chromecasts, AirPlay
//! receivers, printers, TVs and speakers in the IoT VLAN, each with its own Wi-Fi key and
//! registered MAC (`netportal_core::iot`), shared with people or the whole house.
//!
//! Pages: `/home` (own devices, the ones shared with the person, the registration form, the
//! join attempts to claim), `/home/devices/<id>` (one device: the key with its QR code, the
//! sharing, rename, rotate, remove), `/admin/home` (every device, the sync state, the join
//! attempts); JSON: `/api/home/devices`, `/api/home/devices/<id>`, `/api/admin/home/devices`.
//!
//! Rights, in one place ([`reachable`]): the owner and an admin (the right checked live,
//! [`Ctx::admin_for`]) see everything and may change the device; a person the access view
//! `iot_access` lists (a share, or a house-visible device) sees the device, its owner and its
//! status, never the key, and may change nothing (403 for a crafted POST); everyone else gets
//! 404, as the Wi-Fi pages answer for a foreign device. The view decides who reaches a device;
//! nothing here derives that otherwise.
//!
//! Presence comes from the pipeline the Wi-Fi dashboard uses ([`dashboard_of`]): a registered
//! MAC is a `device_mac` row, so the windows, the accounting sessions and the UniFi client data
//! apply to a home device like to any other; a device without a MAC shows as never connected.
//!
//! Writes commit explicitly before the redirect; every one is audited by the registry
//! (`iot:register`, `iot:claim`, `iot:rotate-key`, `iot:share:<sub>`, `iot:unshare:<sub>`,
//! `iot:visibility:<value>`, `iot:remove`). A removal is a revocation of the device
//! (`registry::revoke`, reason `iot:remove`) without a Disconnect-Request: the controller kicks
//! the device from the access point on its next round (IOT-ACCESS 6.4).

use std::collections::{BTreeMap, BTreeSet};

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use indexmap::IndexMap;
use minijinja::context;
use netportal_core::Db;
use netportal_core::conventions::rfc3339;
use netportal_core::iot::{self, CLASSES, IotDevice, IotError, JoinAttempt, NewDevice, Share, SyncState, VISIBILITIES};
use netportal_core::registry::{self, Person};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::ctx::{Admin, Ctx, User, back_page};
use crate::dashboard::{dashboard_of, polled_response, serde, to_json};
use crate::devices::owner_policy;
use crate::errors::Reject;
use crate::http::device_id;
use crate::limits;
use crate::login::redirect;
use crate::platform::cut_name;
use crate::qr;
use crate::web::{App, Reg};

const LOG: &str = "netportal.web";

/// What a person is to a device.
pub enum Role {
    Owner,
    /// another person's device, the admin right confirmed now
    Admin(Admin),
    /// the access view lists the person: a share, or a house-visible device
    Shared,
}

impl Role {
    /// `owner`, `admin` or `shared` (the templates and the API).
    pub fn name(&self) -> &'static str {
        match self {
            Role::Owner => "owner",
            Role::Admin(_) => "admin",
            Role::Shared => "shared",
        }
    }

    /// Whether the key may be shown and the device changed.
    pub fn may_change(&self) -> bool {
        !matches!(self, Role::Shared)
    }

    /// Who acts (the audit's actor), or 403 for a person who may only look.
    fn actor<'a>(&'a self, user: &'a User) -> Result<&'a str, Reject> {
        match self {
            Role::Owner => Ok(&user.sub),
            Role::Admin(admin) => Ok(admin.sub()),
            Role::Shared => Err(Reject::forbidden()),
        }
    }
}

/// The home device of this URL and what this person is to it, else 404 (an unknown or revoked
/// device, a Wi-Fi device's id, a person the access view does not list). A listed admin's right
/// is checked live; it is required unless a share lets the person see the device anyway (then
/// Authentik being unreachable gives the sharee's view, not a 503).
async fn reachable(app: &App, ctx: &Ctx, db: &mut Db, id: &str, user: &User) -> Result<(IotDevice, Role), Reject> {
    let id = device_id(id).ok_or_else(Reject::not_found)?;
    let dev = match iot::device(db, id).await? {
        Some(dev) if dev.revoked_at.is_none() => dev,
        _ => return Err(Reject::not_found()),
    };
    if dev.owner == user.sub {
        return Ok((dev, Role::Owner));
    }
    let shared = iot::may_reach(db, &user.sub, id).await?;
    if user.listed_admin
        && let Some(admin) = ctx.admin_for(app, db, user, !shared).await?
    {
        return Ok((dev, Role::Admin(admin)));
    }
    if shared { Ok((dev, Role::Shared)) } else { Err(Reject::not_found()) }
}

/// The people a device may be shared with: everyone with a policy who is not offboarded (the
/// access view's condition for a grantee), by name. The registry's `people` lists everyone it
/// ever saw (the admin pages' names); this picker must not offer someone who left.
pub async fn share_candidates(db: &mut Db, owner: &str) -> Result<Vec<Person>, Reject> {
    Ok(sqlx::query_as::<_, Person>(
        "SELECT sub, username, display_name FROM person
         WHERE offboarded_at IS NULL AND policy IS NOT NULL AND sub <> $1 ORDER BY lower(display_name), sub",
    )
    .bind(owner)
    .fetch_all(db.tx().await?)
    .await?)
}

/// The sync rows by device id (every target whose key is a device id).
async fn sync_by_device(db: &mut Db) -> Result<BTreeMap<String, Vec<SyncState>>, Reject> {
    let mut out: BTreeMap<String, Vec<SyncState>> = BTreeMap::new();
    for row in iot::sync_states(db).await? {
        if Uuid::parse_str(&row.key).is_ok() {
            out.entry(row.key.clone()).or_default().push(row);
        }
    }
    Ok(out)
}

/// The one line the pages show of a device's sync rows: `failed` with the first failure's
/// detail when any target failed, else `pending` when any is pending or the controller has not
/// seen the device yet, else `applied`.
pub fn sync_json(rows: &[SyncState]) -> Value {
    if let Some(failed) = rows.iter().find(|r| r.status == "failed") {
        return json!({"status": "failed", "detail": failed.detail, "target": failed.target,
                      "updated_at": rfc3339(failed.updated_at)});
    }
    if rows.is_empty() || rows.iter().any(|r| r.status != "applied") {
        return json!({"status": "pending", "detail": "", "target": null,
                      "updated_at": rows.iter().map(|r| rfc3339(r.updated_at)).max()});
    }
    json!({"status": "applied", "detail": "", "target": null,
           "updated_at": rows.iter().map(|r| rfc3339(r.updated_at)).max()})
}

/// The join attempts as the pages read them.
fn attempts_json(attempts: &[JoinAttempt]) -> Vec<Value> {
    attempts
        .iter()
        .map(|a| {
            json!({"mac": a.mac, "first_seen": rfc3339(a.first_seen), "last_seen": rfc3339(a.last_seen),
                   "tries": a.tries, "ssid": a.ssid})
        })
        .collect()
}

fn shares_json(shares: &[Share]) -> Vec<Value> {
    shares
        .iter()
        .map(|s| json!({"sub": s.grantee, "display": s.grantee_name, "granted_at": rfc3339(s.granted_at)}))
        .collect()
}

fn people_json(people: &[Person]) -> Vec<Value> {
    people.iter().map(|p| json!({"sub": p.sub, "username": p.username, "display": p.display_name})).collect()
}

/// The presence of the pages' devices, by device id, from the Wi-Fi dashboard's pipeline (the
/// registry rows of these devices only), and the dashboard's own fields (`generated_at`,
/// `telemetry`, `stale`, `house`) for the banners.
struct Presence {
    devices: IndexMap<String, Value>,
    dashboard: Value,
}

async fn presence_of(
    app: &App,
    db: &mut Db,
    devices: &[&IotDevice],
    owners: Option<&IndexMap<String, Person>>,
) -> Result<Presence, Reject> {
    // one device: its row; a list: every row of the house once, filtered (the lists hold other
    // people's devices too, so the owner cannot narrow the query)
    let rows: Vec<registry::DeviceRow> = match devices {
        [one] => registry::device(db, one.id, None).await?.into_iter().collect(),
        _ => {
            let wanted: BTreeSet<Uuid> = devices.iter().map(|d| d.id).collect();
            registry::devices(db, None, false).await?.into_iter().filter(|r| wanted.contains(&r.id)).collect()
        }
    };
    let page = app.telemetry.page();
    let payload = dashboard_of(app, &page, db, &rows, owners, owners.is_some(), false).await?;
    let dashboard = json!({"generated_at": payload.generated_at, "telemetry": payload.telemetry, "stale": payload.stale,
                           "house": payload.house});
    let mut by_id = IndexMap::new();
    for device in payload.devices {
        let id = device.id.clone();
        by_id.insert(id, to_json(&device)?);
    }
    Ok(Presence { devices: by_id, dashboard })
}

/// What a sharee gets of the live data: the state and where, never the addresses.
const SHARED_LIVE: [&str; 7] = ["state", "since", "last_seen", "ap", "band", "channel", "proto"];
const SHARED_PRESENCE: [&str; 6] = ["state", "since", "confirmed_at", "confirmed_by", "basis", "derived"];
/// The live payload's registry fields the home device JSON has itself.
const NOT_LIVE: [&str; 9] =
    ["id", "name", "platform", "policy", "created", "expires", "expires_soon", "revoked", "owner"];

/// A home device as the pages and the API read it: the registry's fields, the live ones of
/// the presence pipeline when there are any, the sync line for the owner. `role` decides what
/// is left out: a sharee sees no MAC, no addresses and no key (the key is added by the caller
/// where it belongs).
pub fn device_json(d: &IotDevice, role: &str, live: Option<&Value>, sync: Option<&[SyncState]>) -> Value {
    let secret = role != "shared";
    let mut out = json!({
        "id": d.id.to_string(), "name": d.name, "class": d.class,
        "owner": {"sub": d.owner, "display": d.owner_name},
        "role": role, "claimed": d.mac.is_some(), "visibility": d.visibility,
        "created": rfc3339(d.created_at), "last_seen": d.last_seen.map(rfc3339),
        "state": if d.last_seen.is_some() { "unknown" } else { "never_connected" },
    });
    let Some(map) = out.as_object_mut() else {
        return out;
    };
    if secret {
        map.insert("mac".into(), json!(d.mac));
        map.insert("key_rotated".into(), json!(rfc3339(d.psk_rotated_at)));
    }
    if let Some(live) = live.and_then(Value::as_object) {
        for (key, value) in live {
            let keep = if secret { !NOT_LIVE.contains(&key.as_str()) } else { SHARED_LIVE.contains(&key.as_str()) };
            if keep {
                map.insert(key.clone(), value.clone());
            }
        }
        if !secret && let Some(p) = live.get("presence").and_then(Value::as_object) {
            let kept: serde_json::Map<String, Value> = p
                .iter()
                .filter(|(k, _)| SHARED_PRESENCE.contains(&k.as_str()))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            map.insert("presence".into(), Value::Object(kept));
        }
    }
    if let Some(sync) = sync {
        map.insert("sync".into(), sync_json(sync));
    }
    out
}

/// An `IotError` as the page says it: a MAC that is not one (400), one registered already
/// (409), the rest as the registry's errors.
fn refused(error: IotError) -> Reject {
    match error {
        IotError::BadMac(_) => Reject::Message(StatusCode::BAD_REQUEST, "bad_mac"),
        IotError::MacTaken(_) => Reject::Message(StatusCode::CONFLICT, "mac_taken"),
        IotError::BadClass(_) | IotError::BadVisibility(_) => Reject::bad_request(),
        IotError::Registry(e) => Reject::from(e),
    }
}

fn device_path(id: Uuid) -> String {
    format!("/home/devices/{id}")
}

/// Where a form goes afterwards: its `back` page ([`crate::ctx::BACK_PAGES`]), else `default`.
fn back_or(ctx: &Ctx, default: &str) -> Response {
    redirect(back_page(ctx.field("back")).unwrap_or(default))
}

/// A default name for a device registered without one: the class as the page calls it, and
/// the owner (as the Wi-Fi devices' `iPhone/iPad (resi)`).
fn default_name(lang: &str, class: &str, username: &str) -> String {
    let label = netportal_core::i18n::text(lang, &format!("cls_{class}")).unwrap_or(class);
    format!("{label} ({username})")
}

// --- pages ------------------------------------------------------------------------------------------

/// `GET /home`: the person's own devices and the ones shared with them, the registration form,
/// and (while they own a device) the join attempts of the last minutes to claim.
pub async fn page(State(app): State<App>, ctx: Ctx, mut reg: Reg) -> Result<Response, Reject> {
    let user = ctx.need_user(&mut reg).await?;
    let own = iot::devices_of(&mut reg, &user.sub, false).await?;
    let shared = iot::shared_with(&mut reg, &user.sub).await?;
    let all: Vec<&IotDevice> = own.iter().chain(shared.iter()).collect();
    let presence = presence_of(&app, &mut reg, &all, None).await?;
    let sync = sync_by_device(&mut reg).await?;
    let attempts = if own.is_empty() { Vec::new() } else { iot::join_attempts(&mut reg).await? };
    let mut own_json = Vec::with_capacity(own.len());
    for d in &own {
        let id = d.id.to_string();
        let mut row =
            device_json(d, "owner", presence.devices.get(&id), Some(sync.get(&id).map(Vec::as_slice).unwrap_or(&[])));
        if let Some(map) = row.as_object_mut() {
            map.insert("shares".into(), json!(shares_json(&iot::shares_of(&mut reg, d.id).await?)));
        }
        own_json.push(row);
    }
    let shared_json: Vec<Value> =
        shared.iter().map(|d| device_json(d, "shared", presence.devices.get(&d.id.to_string()), None)).collect();
    let unclaimed: Vec<Value> =
        own.iter().filter(|d| d.mac.is_none()).map(|d| json!({"id": d.id.to_string(), "name": d.name})).collect();
    app.page(
        &ctx,
        Some(&user),
        "home.html",
        context! {
            own => serde(&own_json), shared => serde(&shared_json), attempts => serde(&attempts_json(&attempts)),
            unclaimed => serde(&unclaimed), classes => CLASSES.to_vec(), dashboard => serde(&presence.dashboard),
        },
    )
}

/// `GET /home/devices/<id>`: one device. The owner and an admin get the key (`?key=1` opens
/// it, as after a registration or a rotation) with its QR code, the sharing list and the
/// actions; a sharee the device, its owner and its status.
pub async fn device_page(
    State(app): State<App>,
    ctx: Ctx,
    mut reg: Reg,
    Path(id): Path<String>,
) -> Result<Response, Reject> {
    let user = ctx.need_user(&mut reg).await?;
    let (dev, role) = reachable(&app, &ctx, &mut reg, &id, &user).await?;
    let people = match &role {
        Role::Admin(_) => Some(registry::people(&mut reg).await?),
        _ => None,
    };
    let presence = presence_of(&app, &mut reg, &[&dev], people.as_ref()).await?;
    let id = dev.id.to_string();
    let (shares, candidates, sync, attempts) = if role.may_change() {
        let shares = iot::shares_of(&mut reg, dev.id).await?;
        let granted: BTreeSet<&str> = shares.iter().map(|s| s.grantee.as_str()).collect();
        let candidates: Vec<Person> = share_candidates(&mut reg, &dev.owner)
            .await?
            .into_iter()
            .filter(|p| !granted.contains(p.sub.as_str()))
            .collect();
        let sync = iot::sync_of_device(&mut reg, dev.id).await?;
        let attempts = if dev.mac.is_none() { iot::join_attempts(&mut reg).await? } else { Vec::new() };
        (shares, candidates, Some(sync), attempts)
    } else {
        (Vec::new(), Vec::new(), None, Vec::new())
    };
    let mut device = device_json(&dev, role.name(), presence.devices.get(&id), sync.as_deref());
    if role.may_change()
        && let Some(map) = device.as_object_mut()
    {
        map.insert("psk".into(), json!(dev.psk));
        map.insert("qr".into(), json!(qr::svg(&qr::wifi_string(&app.iot_ssid, &dev.psk))));
        map.insert("shares".into(), json!(shares_json(&shares)));
    }
    app.page(
        &ctx,
        Some(&user),
        "home_device.html",
        context! {
            device => serde(&device), role => role.name(), shares => serde(&shares_json(&shares)),
            people => serde(&people_json(&candidates)), show_key => ctx.arg("key") == "1",
            attempts => serde(&attempts_json(&attempts)), dashboard => serde(&presence.dashboard),
            back => ctx.arg("from") == "admin",
        },
    )
}

/// `POST /home/register`: a new device (name, class, optional MAC) within the person's device
/// limit and rate, then its page with the key open.
pub async fn register(State(app): State<App>, ctx: Ctx, mut reg: Reg) -> Result<Response, Reject> {
    let user = ctx.need_user(&mut reg).await?;
    let class = ctx.field("class");
    if !CLASSES.contains(&class) {
        return Err(Reject::bad_request());
    }
    if let Some(over) = limits::new_device(&app, &mut reg, &user.sub).await? {
        return limits::page(&app, &ctx, &user, over);
    }
    let name = cut_name(ctx.field("name")).unwrap_or_else(|| default_name(ctx.lang, class, &user.username));
    let mac = ctx.field("mac").trim();
    let policy = owner_policy(&app, &mut reg, &user.sub).await?;
    let new =
        NewDevice { owner: &user.sub, name: &name, class, mac: (!mac.is_empty()).then_some(mac), policy: &policy };
    let (id, _) = iot::register(&mut reg, new).await.map_err(refused)?;
    reg.commit().await?;
    tracing::info!(target: LOG, "{} registered a home device ({class})", user.sub);
    Ok(redirect(&format!("{}?key=1", device_path(id))))
}

/// The device of this URL for a change: the owner or an admin, else 403 for a sharee and 404
/// for everyone else.
async fn changeable(app: &App, ctx: &Ctx, db: &mut Db, id: &str, user: &User) -> Result<(IotDevice, String), Reject> {
    let (dev, role) = reachable(app, ctx, db, id, user).await?;
    let actor = role.actor(user)?.to_string();
    Ok((dev, actor))
}

/// `POST /home/devices/<id>/claim`: the MAC of a join attempt (or typed in) becomes the
/// device's; back to the device page, or the list the form names.
pub async fn claim(State(app): State<App>, ctx: Ctx, mut reg: Reg, Path(id): Path<String>) -> Result<Response, Reject> {
    let user = ctx.need_user(&mut reg).await?;
    let (dev, actor) = changeable(&app, &ctx, &mut reg, &id, &user).await?;
    iot::claim_mac(&mut reg, dev.id, ctx.field("mac").trim(), &actor).await.map_err(refused)?;
    reg.commit().await?;
    Ok(back_or(&ctx, &device_path(dev.id)))
}

/// `POST /home/devices/<id>/rotate-key`: a new key, shown at once (the controller puts it into
/// the access points on its next round; the device must be told the new one).
pub async fn rotate_key(
    State(app): State<App>,
    ctx: Ctx,
    mut reg: Reg,
    Path(id): Path<String>,
) -> Result<Response, Reject> {
    let user = ctx.need_user(&mut reg).await?;
    let (dev, actor) = changeable(&app, &ctx, &mut reg, &id, &user).await?;
    iot::rotate_psk(&mut reg, dev.id, &actor).await?;
    reg.commit().await?;
    Ok(redirect(&format!("{}?key=1", device_path(dev.id))))
}

/// `POST /home/devices/<id>/share`: share with a person (`grantee`: one of the candidates;
/// anyone else, the owner included, is 400).
pub async fn share(State(app): State<App>, ctx: Ctx, mut reg: Reg, Path(id): Path<String>) -> Result<Response, Reject> {
    let user = ctx.need_user(&mut reg).await?;
    let (dev, actor) = changeable(&app, &ctx, &mut reg, &id, &user).await?;
    let grantee = ctx.field("grantee").trim();
    if !share_candidates(&mut reg, &dev.owner).await?.iter().any(|p| p.sub == grantee) {
        return Err(Reject::bad_request());
    }
    iot::share(&mut reg, dev.id, grantee, &actor).await?;
    reg.commit().await?;
    Ok(back_or(&ctx, &device_path(dev.id)))
}

/// `POST /home/devices/<id>/unshare`: take a share away (an unknown grantee changes nothing).
pub async fn unshare(
    State(app): State<App>,
    ctx: Ctx,
    mut reg: Reg,
    Path(id): Path<String>,
) -> Result<Response, Reject> {
    let user = ctx.need_user(&mut reg).await?;
    let (dev, actor) = changeable(&app, &ctx, &mut reg, &id, &user).await?;
    iot::unshare(&mut reg, dev.id, ctx.field("grantee").trim(), &actor).await?;
    reg.commit().await?;
    Ok(back_or(&ctx, &device_path(dev.id)))
}

/// `POST /home/devices/<id>/visibility`: `private` or `house`.
pub async fn visibility(
    State(app): State<App>,
    ctx: Ctx,
    mut reg: Reg,
    Path(id): Path<String>,
) -> Result<Response, Reject> {
    let user = ctx.need_user(&mut reg).await?;
    let (dev, actor) = changeable(&app, &ctx, &mut reg, &id, &user).await?;
    let value = ctx.field("visibility");
    if !VISIBILITIES.contains(&value) {
        return Err(Reject::bad_request());
    }
    iot::set_visibility(&mut reg, dev.id, value, &actor).await.map_err(refused)?;
    reg.commit().await?;
    Ok(back_or(&ctx, &device_path(dev.id)))
}

/// `POST /home/devices/<id>/rename`: the form (back to the device page; an empty name changes
/// nothing) or, for a script, `{"ok", "name"}` as the Wi-Fi rename answers.
pub async fn rename(
    State(app): State<App>,
    ctx: Ctx,
    mut reg: Reg,
    Path(id): Path<String>,
) -> Result<Response, Reject> {
    let as_json = ctx.wants_json();
    let user = if as_json { ctx.api_user(&mut reg).await? } else { ctx.need_user(&mut reg).await? };
    let (dev, _) = changeable(&app, &ctx, &mut reg, &id, &user).await?;
    let name = cut_name(ctx.field("name"));
    if let Some(name) = &name {
        registry::rename(&mut reg, dev.id, name).await?;
        reg.commit().await?;
    }
    if as_json {
        let status = if name.is_some() { StatusCode::OK } else { StatusCode::BAD_REQUEST };
        let body = json!({"ok": name.is_some(), "name": name.unwrap_or(dev.name)});
        return Ok((status, axum::Json(body)).into_response());
    }
    Ok(back_or(&ctx, &device_path(dev.id)))
}

/// `POST /home/devices/<id>/remove`: the device is revoked (`iot:remove`); its key stops
/// working and its shares end with the next controller round, which also kicks it. Back to
/// `/home`, or the list the form names.
pub async fn remove(
    State(app): State<App>,
    ctx: Ctx,
    mut reg: Reg,
    Path(id): Path<String>,
) -> Result<Response, Reject> {
    let user = ctx.need_user(&mut reg).await?;
    let (dev, actor) = changeable(&app, &ctx, &mut reg, &id, &user).await?;
    registry::revoke(&mut reg, dev.id, &actor, "iot:remove").await?;
    reg.commit().await?;
    tracing::info!(target: LOG, "{actor} removed the home device {}", dev.id);
    Ok(back_or(&ctx, "/home"))
}

// --- admin ------------------------------------------------------------------------------------------

/// Every home device with its shares and sync line, the attempts and the unclaimed devices
/// (the admin page and its API).
async fn admin_payload(app: &App, db: &mut Db) -> Result<Value, Reject> {
    let devices = iot::all_devices(db, false).await?;
    let people = registry::people(db).await?;
    let refs: Vec<&IotDevice> = devices.iter().collect();
    let presence = presence_of(app, db, &refs, Some(&people)).await?;
    let sync = sync_by_device(db).await?;
    let mut rows = Vec::with_capacity(devices.len());
    for d in &devices {
        let id = d.id.to_string();
        let mut row =
            device_json(d, "admin", presence.devices.get(&id), Some(sync.get(&id).map(Vec::as_slice).unwrap_or(&[])));
        if let Some(map) = row.as_object_mut() {
            let shares = iot::shares_of(db, d.id).await?;
            map.insert("shares".into(), json!(shares_json(&shares)));
            let targets: Vec<Value> = sync
                .get(&id)
                .map(Vec::as_slice)
                .unwrap_or(&[])
                .iter()
                .map(|s| json!({"target": s.target, "status": s.status, "detail": s.detail, "updated_at": rfc3339(s.updated_at)}))
                .collect();
            map.insert("sync_targets".into(), Value::Array(targets));
        }
        rows.push(row);
    }
    let attempts = iot::join_attempts(db).await?;
    let unclaimed: Vec<Value> = devices
        .iter()
        .filter(|d| d.mac.is_none())
        .map(|d| json!({"id": d.id.to_string(), "name": d.name, "owner": d.owner_name}))
        .collect();
    Ok(json!({"generated_at": presence.dashboard["generated_at"], "telemetry": presence.dashboard["telemetry"],
              "stale": presence.dashboard["stale"], "devices": rows, "attempts": attempts_json(&attempts),
              "unclaimed": unclaimed}))
}

/// `GET /admin/home`.
pub async fn admin_page(State(app): State<App>, ctx: Ctx, right: Admin, mut reg: Reg) -> Result<Response, Reject> {
    let payload = admin_payload(&app, &mut reg).await?;
    let dashboard =
        json!({"generated_at": payload["generated_at"], "telemetry": payload["telemetry"], "stale": payload["stale"]});
    app.page(
        &ctx,
        Some(right.user()),
        "admin_home.html",
        context! {
            devices => serde(&payload["devices"]), attempts => serde(&payload["attempts"]),
            unclaimed => serde(&payload["unclaimed"]), dashboard => serde(&dashboard),
        },
    )
}

/// `GET /api/admin/home/devices`.
pub async fn api_admin_devices(State(app): State<App>, _right: Admin, mut reg: Reg) -> Result<Response, Reject> {
    let payload = admin_payload(&app, &mut reg).await?;
    Ok(axum::Json(payload).into_response())
}

// --- the JSON API -----------------------------------------------------------------------------------

/// `GET /api/home/devices`: the person's own devices and the ones shared with them, with their
/// presence (polled like `/api/devices`); no key here.
pub async fn api_devices(
    State(app): State<App>,
    ctx: Ctx,
    mut reg: Reg,
    headers: HeaderMap,
) -> Result<Response, Reject> {
    let user = ctx.api_user(&mut reg).await?;
    let own = iot::devices_of(&mut reg, &user.sub, false).await?;
    let shared = iot::shared_with(&mut reg, &user.sub).await?;
    let all: Vec<&IotDevice> = own.iter().chain(shared.iter()).collect();
    let presence = presence_of(&app, &mut reg, &all, None).await?;
    let sync = sync_by_device(&mut reg).await?;
    let mut devices = Vec::with_capacity(own.len() + shared.len());
    for d in &own {
        let id = d.id.to_string();
        let mut row =
            device_json(d, "owner", presence.devices.get(&id), Some(sync.get(&id).map(Vec::as_slice).unwrap_or(&[])));
        if let Some(map) = row.as_object_mut() {
            map.insert("shares".into(), json!(shares_json(&iot::shares_of(&mut reg, d.id).await?)));
        }
        devices.push(row);
    }
    devices.extend(shared.iter().map(|d| device_json(d, "shared", presence.devices.get(&d.id.to_string()), None)));
    let payload = json!({"generated_at": presence.dashboard["generated_at"], "telemetry": presence.dashboard["telemetry"],
                         "stale": presence.dashboard["stale"], "devices": devices});
    Ok(polled_response(payload, &headers))
}

/// `GET /api/home/devices/<id>`: one device; the owner and an admin also get `psk`, the shares
/// and the sync line.
pub async fn api_device(
    State(app): State<App>,
    ctx: Ctx,
    mut reg: Reg,
    Path(id): Path<String>,
) -> Result<Response, Reject> {
    let user = ctx.api_user(&mut reg).await?;
    let (dev, role) = reachable(&app, &ctx, &mut reg, &id, &user).await?;
    let people = match &role {
        Role::Admin(_) => Some(registry::people(&mut reg).await?),
        _ => None,
    };
    let presence = presence_of(&app, &mut reg, &[&dev], people.as_ref()).await?;
    let sync = if role.may_change() { Some(iot::sync_of_device(&mut reg, dev.id).await?) } else { None };
    let mut device = device_json(&dev, role.name(), presence.devices.get(&dev.id.to_string()), sync.as_deref());
    if role.may_change()
        && let Some(map) = device.as_object_mut()
    {
        map.insert("psk".into(), json!(dev.psk));
        map.insert("shares".into(), json!(shares_json(&iot::shares_of(&mut reg, dev.id).await?)));
    }
    let payload = json!({"generated_at": presence.dashboard["generated_at"], "telemetry": presence.dashboard["telemetry"],
                         "stale": presence.dashboard["stale"], "device": device});
    Ok(axum::Json(payload).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::OffsetDateTime;

    fn device() -> IotDevice {
        IotDevice {
            id: Uuid::nil(),
            owner: "sub-o".into(),
            owner_name: "Owner".into(),
            name: "TV".into(),
            class: "tv".into(),
            mac: Some("aa:bb:cc:dd:ee:ff".into()),
            mac_claimed_at: Some(OffsetDateTime::UNIX_EPOCH),
            psk: "abcDEF0123456789wxYZ".into(),
            psk_rotated_at: OffsetDateTime::UNIX_EPOCH,
            visibility: "private".into(),
            created_at: OffsetDateTime::UNIX_EPOCH,
            revoked_at: None,
            last_seen: None,
        }
    }

    fn sync(target: &str, status: &str, detail: &str) -> SyncState {
        SyncState {
            target: target.into(),
            key: Uuid::nil().to_string(),
            status: status.into(),
            detail: detail.into(),
            updated_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn test_sync_line() {
        assert_eq!(sync_json(&[])["status"], "pending");
        assert_eq!(sync_json(&[sync("unifi_key", "applied", "")])["status"], "applied");
        assert_eq!(
            sync_json(&[sync("unifi_key", "applied", ""), sync("opnsense_alias", "pending", "")])["status"],
            "pending"
        );
        let failed = sync_json(&[sync("unifi_key", "applied", ""), sync("opnsense_alias", "failed", "timeout")]);
        assert_eq!(failed["status"], "failed");
        assert_eq!(failed["detail"], "timeout");
        assert_eq!(failed["target"], "opnsense_alias");
    }

    #[test]
    fn test_device_json_keeps_the_addresses_from_sharees() {
        let live = json!({"id": "x", "name": "live name", "state": "online", "since": "2026-10-29T10:00:00Z",
                          "mac": "aa:bb:cc:dd:ee:ff", "ip": "10.0.40.7", "ap": {"name": "ap-1"}, "band": "5",
                          "presence": {"state": "online", "since": "2026-10-29T10:00:00Z",
                                       "session": {"nas_ip": "10.0.10.2"}, "evidence": [{"source": "acct"}]}});
        let owner = device_json(&device(), "owner", Some(&live), Some(&[]));
        assert_eq!(owner["name"], "TV");
        assert_eq!(owner["mac"], "aa:bb:cc:dd:ee:ff");
        assert_eq!(owner["ip"], "10.0.40.7");
        assert_eq!(owner["state"], "online");
        assert_eq!(owner["sync"]["status"], "pending");
        assert!(owner.get("psk").is_none(), "the key is added only where it belongs");
        let shared = device_json(&device(), "shared", Some(&live), None);
        assert_eq!(shared["state"], "online");
        assert_eq!(shared["ap"]["name"], "ap-1");
        for hidden in ["mac", "ip", "sync", "key_rotated", "psk"] {
            assert!(shared.get(hidden).is_none(), "{hidden} shown to a sharee");
        }
        assert_eq!(shared["presence"]["state"], "online");
        assert!(shared["presence"].get("session").is_none());
        let bare = device_json(&device(), "shared", None, None);
        assert_eq!(bare["state"], "never_connected");
    }
}
