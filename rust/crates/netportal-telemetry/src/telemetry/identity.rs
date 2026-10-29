//! Telemetry: device identity across MAC rotation (`telemetry/identity.py`, INVENTORY 9.6).
//!
//! A device (its permanent id, the certificate subject) logs in with a MAC it sends itself. The
//! registry keeps one row per device and MAC (`device_mac`: first_seen, last_seen, auth_count,
//! randomized); a *window* is the time that MAC's data belongs to the device:
//! `[max(first_seen, enrolment), window_end]`. `window_end` and `current` are the registry's
//! (view `device_mac_window`): the current window (the MAC of the newest login) lasts until
//! last_seen + 12 h 15 min, capped at now; others end 15 min after their last_seen.
//!
//! **Whose data is it.** There are three rules in the system, deliberately different
//! (INVENTORY 9.14 #14); each is a named function:
//!
//! 1. [`Identity::segments`] (this module, the pages): a MAC's data is the device's inside its
//!    windows, from its enrolment on, minus what overlaps windows of other owners' devices on
//!    the same MAC (withheld from residents; admins see it marked).
//! 2. [`registry_device_for_mac`] (SQL `np_device_for_mac`, the accounting and the collector's
//!    UniFi events): the windows containing the moment; exactly one owner -> that owner's
//!    newest device, else nobody.
//! 3. [`rollup_owner_at`] (the collector's rollup): the minute belongs to a device only when
//!    exactly one device (any owner, also the same owner's re-enrolment) has a window holding it;
//!    no enrolment bound.

use indexmap::IndexMap;
use netportal_core::Db;
use netportal_core::registry::{self, DeviceRow, MacWindow, RegistryError, WindowConflict};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use time::OffsetDateTime;
use uuid::Uuid;

use super::common::{iso, moment, normalise_mac, unix};
use super::store::Store;

/// The registry's window rule, in seconds: 15 min grace.
pub const WINDOW_GRACE_S: f64 = registry::WINDOW_GRACE.whole_seconds() as f64;
/// The current window lasts up to 12 h 15 min after the last login.
pub const CURRENT_WINDOW_S: f64 = registry::CURRENT_WINDOW.whole_seconds() as f64;
/// A window end (or a conflict's end) this close to now was capped at the database's now (the
/// request's transaction): it is open.
pub const CAPPED_SLACK_S: f64 = 300.0;
/// Rotating: this many randomized MACs in this period (two can be a reset or a new phone OS).
pub const ROTATING_MIN_MACS: usize = 3;
pub const ROTATING_PERIOD_S: f64 = 30.0 * 86400.0;
/// The dashboard reads the windows of this period (current ones, the mode, the MACs shown).
pub const RECENT_S: f64 = 31.0 * 86400.0;
pub const MACS_SHOWN: usize = 50;

/// One window of a device on a MAC, in Unix seconds. `end` `None`: open (up to now).
#[derive(Debug, Clone, PartialEq)]
pub struct Window {
    pub mac: String,
    pub start: f64,
    pub end: Option<f64>,
    pub first_seen: f64,
    pub last_seen: f64,
    pub randomized: bool,
    pub auth_count: Option<i64>,
    pub current: bool,
}

/// Other owners' devices had overlapping windows on `mac` from `from` to `to` (`None`: open, up
/// to now).
#[derive(Debug, Clone, PartialEq)]
pub struct Conflict {
    pub mac: String,
    pub other_owners: i64,
    pub from: Option<f64>,
    pub to: Option<f64>,
}

/// A piece of a window where the MAC's data is the device's.
#[derive(Debug, Clone, PartialEq)]
pub struct Segment {
    pub mac: String,
    pub start: f64,
    pub end: f64,
}

/// `hardware` | `random_fixed` | `rotating`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MacMode {
    Hardware,
    RandomFixed,
    Rotating,
}

impl MacMode {
    pub fn as_str(self) -> &'static str {
        match self {
            MacMode::Hardware => "hardware",
            MacMode::RandomFixed => "random_fixed",
            MacMode::Rotating => "rotating",
        }
    }
}

/// DEVICE.macs (INVENTORY 9.12).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PublicMac {
    pub mac: String,
    pub randomized: bool,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub current: bool,
}

/// A conflict as the API shows it: admins `{mac, other_owners, from, to}` (`to` null: open),
/// residents the withheld span `{mac, from, to}`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PublicConflict {
    pub mac: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub other_owners: Option<i64>,
    pub from: Option<String>,
    pub to: Option<String>,
}

/// One device's windows and conflicts. `admin`: conflicts are marked, not withheld.
#[derive(Debug, Clone, PartialEq)]
pub struct Identity {
    pub device_id: String,
    /// sorted by (start, mac)
    pub windows: Vec<Window>,
    pub conflicts: Vec<Conflict>,
    pub admin: bool,
    pub now: f64,
}

impl Identity {
    pub fn new(device_id: &str, mut windows: Vec<Window>, conflicts: Vec<Conflict>, admin: bool, now: f64) -> Self {
        windows.sort_by(|a, b| a.start.total_cmp(&b.start).then_with(|| a.mac.cmp(&b.mac)));
        Identity { device_id: device_id.to_string(), windows, conflicts, admin, now }
    }

    // --- what the device is ----------------------------------------------------------------

    /// The current window (the MAC of the newest login).
    pub fn current(&self) -> Option<&Window> {
        self.windows.iter().find(|w| w.current)
    }

    pub fn current_mac(&self) -> Option<&str> {
        self.current().map(|w| w.mac.as_str())
    }

    /// The first window's start: no data of this device is older.
    pub fn data_from(&self) -> Option<f64> {
        self.windows.iter().map(|w| w.start).reduce(f64::min).filter(|t| t.is_finite())
    }

    /// The current MAC's kind and how many randomized MACs the device used in
    /// [`ROTATING_PERIOD_S`]; `None`: no login yet.
    pub fn mac_mode(&self) -> Option<MacMode> {
        let current = self.current().or(self.windows.last())?;
        if !current.randomized {
            return Some(MacMode::Hardware);
        }
        Some(if self.recent_randomized().len() >= ROTATING_MIN_MACS { MacMode::Rotating } else { MacMode::RandomFixed })
    }

    /// The randomized MACs used in [`ROTATING_PERIOD_S`], sorted.
    pub fn recent_randomized(&self) -> Vec<String> {
        let since = self.now - ROTATING_PERIOD_S;
        let macs: BTreeSet<&str> =
            self.windows.iter().filter(|w| w.randomized && w.last_seen >= since).map(|w| w.mac.as_str()).collect();
        macs.into_iter().map(str::to_string).collect()
    }

    /// DEVICE.macs: the newest [`MACS_SHOWN`], the current one first.
    pub fn public_macs(&self) -> Vec<PublicMac> {
        let mut rows: Vec<&Window> = self.windows.iter().collect();
        rows.sort_by(|a, b| (!a.current).cmp(&!b.current).then_with(|| b.last_seen.total_cmp(&a.last_seen)));
        rows.into_iter()
            .take(MACS_SHOWN)
            .map(|w| PublicMac {
                mac: w.mac.clone(),
                randomized: w.randomized,
                first_seen: iso(Some(w.first_seen)),
                last_seen: iso(Some(w.last_seen)),
                current: w.current,
            })
            .collect()
    }

    // --- conflicts -------------------------------------------------------------------------

    fn conflict_end(&self, c: &Conflict) -> f64 {
        c.to.unwrap_or(self.now)
    }

    /// The conflicts holding at `t`.
    pub fn conflicts_at(&self, t: f64) -> Vec<&Conflict> {
        self.conflicts.iter().filter(|c| c.from.is_none_or(|f| f <= t) && t <= self.conflict_end(c)).collect()
    }

    /// `[(mac, from, to)]` a resident does not see (nothing for an admin).
    pub fn withheld_spans(&self) -> Vec<(String, Option<f64>, f64)> {
        if self.admin {
            return Vec::new();
        }
        self.conflicts.iter().map(|c| (c.mac.clone(), c.from, self.conflict_end(c))).collect()
    }

    /// A resident's live data is withheld: the current MAC is in a conflict now.
    pub fn withheld_now(&self) -> bool {
        let Some(current) = self.current() else {
            return false;
        };
        !self.admin && self.conflicts_at(self.now).iter().any(|c| c.mac == current.mac)
    }

    /// The most other owners of any of the device's MACs now (an admin's `mac_conflict`).
    pub fn conflict_owners_now(&self) -> i64 {
        self.conflicts_at(self.now).iter().map(|c| c.other_owners).max().unwrap_or(0)
    }

    /// For admins every conflict with the other owners' count; residents get the spans only.
    pub fn public_conflicts(&self) -> Vec<PublicConflict> {
        if self.admin {
            return self
                .conflicts
                .iter()
                .map(|c| PublicConflict {
                    mac: c.mac.clone(),
                    other_owners: Some(c.other_owners),
                    from: iso(c.from),
                    to: iso(c.to),
                })
                .collect();
        }
        self.withheld_spans()
            .into_iter()
            .map(|(mac, from, to)| PublicConflict { mac, other_owners: None, from: iso(from), to: iso(Some(to)) })
            .collect()
    }

    // --- where the data is the device's ----------------------------------------------------

    /// **Whose data is it, rule 1 (the pages).** The windows clipped to `[start, end]`, minus what
    /// is withheld (a resident: the overlaps with other owners' windows on the same MAC, cut with
    /// 1 s granularity), sorted by (start, mac). An open window ends now. The windows' start is
    /// already bounded by the enrolment ([`from_registry`]).
    pub fn segments(&self, start: Option<f64>, end: Option<f64>) -> Vec<Segment> {
        let withheld = self.withheld_spans();
        let mut out = Vec::new();
        for w in &self.windows {
            let mut pieces = vec![(w.start, w.end.unwrap_or(self.now))];
            for (mac, from, to) in &withheld {
                if *mac == w.mac {
                    pieces = subtract(&pieces, from.unwrap_or(f64::NEG_INFINITY), *to);
                }
            }
            for (a, b) in pieces {
                let a = start.map_or(a, |s| a.max(s));
                let b = end.map_or(b, |e| b.min(e));
                if a <= b {
                    out.push(Segment { mac: w.mac.clone(), start: a, end: b });
                }
            }
        }
        out.sort_by(|a, b| a.start.total_cmp(&b.start).then_with(|| a.mac.cmp(&b.mac)));
        out
    }

    /// `{mac: data bound}` of the MACs whose (unwithheld) windows hold now: the bound is the start
    /// of that piece (data before it is not this device's).
    pub fn live_bounds(&self) -> BTreeMap<String, f64> {
        let mut bounds: BTreeMap<String, f64> = BTreeMap::new();
        for s in self.segments(None, None) {
            if s.start <= self.now && self.now <= s.end + 1.0 {
                let b = bounds.entry(s.mac.clone()).or_insert(s.start);
                *b = b.max(s.start);
            }
        }
        bounds
    }

    /// `mac`'s data at `t` is this device's (and not withheld).
    pub fn contains(&self, mac: &str, t: f64, segments: Option<&[Segment]>) -> bool {
        match segments {
            Some(segments) => segments.iter().any(|s| s.mac == mac && s.start <= t && t <= s.end),
            None => self.segments(None, None).iter().any(|s| s.mac == mac && s.start <= t && t <= s.end),
        }
    }
}

fn subtract(pieces: &[(f64, f64)], a: f64, b: f64) -> Vec<(f64, f64)> {
    let mut out = Vec::new();
    for &(x, y) in pieces {
        if b < x || a > y {
            out.push((x, y));
            continue;
        }
        if x < a {
            out.push((x, a - 1.0));
        }
        if b < y {
            out.push((b + 1.0, y));
        }
    }
    out
}

/// From when the registry row's data is the device's: the later of its enrolment and its latest
/// MAC's first login (Unix seconds).
pub fn data_bound(row: &DeviceRow) -> f64 {
    let created = unix(row.created_at);
    row.first_seen.map_or(created, |f| created.max(unix(f)))
}

// --- from the registry ----------------------------------------------------------------------------

/// `{device id: Identity}` for these registry rows, from `device_windows` and `window_conflicts`
/// (one query each for all of them). `since`: only windows and conflicts from then on (the
/// dashboard: [`RECENT_S`]; a device's history and raw rows: all).
pub async fn from_registry<S: Store>(
    store: &mut S,
    rows: &[DeviceRow],
    now: f64,
    admin: bool,
    since: Option<f64>,
) -> Result<IndexMap<Uuid, Identity>, RegistryError> {
    let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    if ids.is_empty() {
        return Ok(IndexMap::new());
    }
    let since_dt = since.map(moment);
    let windows = store.device_windows(&ids, since_dt, None).await?;
    let conflicts = store.window_conflicts(&ids, since_dt, None).await?;
    let mut out = IndexMap::new();
    for row in rows {
        let w = windows.get(&row.id).map(Vec::as_slice).unwrap_or_default();
        let c = conflicts.get(&row.id).map(Vec::as_slice).unwrap_or_default();
        out.insert(
            row.id,
            Identity::new(&row.id.to_string(), windows_of(row, w, now), conflicts_of(c, now), admin, now),
        );
    }
    Ok(out)
}

/// Identity windows from `device_windows` rows: the registry's window_end and current, the
/// start bounded by the enrolment. A current window whose end is capped at now (the
/// database's: not yet last_seen + [`CURRENT_WINDOW_S`], within [`CAPPED_SLACK_S`] of now) is
/// open: it ends whenever the page asks.
pub fn windows_of(row: &DeviceRow, rows: &[MacWindow], now: f64) -> Vec<Window> {
    let created = unix(row.created_at);
    let mut out: Vec<Window> = Vec::new();
    for w in rows {
        let Some(mac) = normalise_mac(&w.mac) else {
            continue;
        };
        let (first, last, mut end) = (unix(w.first_seen), unix(w.last_seen), Some(unix(w.window_end)));
        if w.current && end.is_some_and(|e| e < last + CURRENT_WINDOW_S && e >= now - CAPPED_SLACK_S) {
            end = None;
        }
        out.push(Window {
            mac,
            start: first.max(created),
            end,
            first_seen: first,
            last_seen: last,
            randomized: w.randomized,
            auth_count: Some(i64::from(w.auth_count)),
            current: w.current,
        });
    }
    // a tie on last_seen: one is the current MAC
    let keep = out
        .iter()
        .enumerate()
        .filter(|(_, w)| w.current)
        .max_by(|(_, a), (_, b)| {
            a.last_seen
                .total_cmp(&b.last_seen)
                .then_with(|| a.first_seen.total_cmp(&b.first_seen))
                .then_with(|| a.mac.cmp(&b.mac))
        })
        .map(|(i, _)| i);
    for (i, w) in out.iter_mut().enumerate() {
        w.current = w.current && Some(i) == keep;
    }
    out
}

/// Identity conflicts from `window_conflicts` rows. A conflict reaching (within
/// [`CAPPED_SLACK_S`]) now is open: its end is a current window's end, capped at the database's
/// now (the transaction's start, a moment before the request's `now`; compared as it is, the
/// overlap would look over and a resident would see the other owner's data).
pub fn conflicts_of(rows: &[WindowConflict], now: f64) -> Vec<Conflict> {
    rows.iter()
        .filter_map(|c| {
            let mac = normalise_mac(&c.mac)?;
            let to = unix(c.to);
            Some(Conflict {
                mac,
                other_owners: c.other_owners.max(1),
                from: Some(unix(c.from)),
                to: (to < now - CAPPED_SLACK_S).then_some(to),
            })
        })
        .collect()
}

// --- the other two rules ---------------------------------------------------------------------------

/// **Whose data is it, rule 2 (accounting, the collector's UniFi events).** The device whose
/// window on `mac` contains `at`: exactly one owner -> that owner's device seen last; none or
/// several owners -> `None` (SQL `np_device_for_mac`, `registry::device_for_mac`).
pub async fn registry_device_for_mac(
    db: &mut Db,
    mac: &str,
    at: OffsetDateTime,
) -> Result<Option<Uuid>, RegistryError> {
    registry::device_for_mac(db, mac, at).await
}

/// **Whose data is it, rule 3 (the collector's rollup).** The one device whose window
/// `[first_seen, window_end]` holds `t`; `None` when none or several devices (of any owner, also
/// the same owner's re-enrolment) do. No enrolment bound. `intervals`: `(device, from, to)` of one
/// MAC (Unix seconds).
pub fn rollup_owner_at<D: Copy + Eq>(intervals: &[(D, f64, f64)], t: f64) -> Option<D> {
    let mut owner = None;
    for (device, from, to) in intervals {
        if *from <= t && t <= *to {
            match owner {
                None => owner = Some(*device),
                Some(o) if o == *device => {}
                Some(_) => return None,
            }
        }
    }
    owner
}
