"""Whose data it is: a device's MAC identities over time (TELEMETRY.md, "One identity, many
identifiers").

A device (its permanent id, the certificate subject) logs in with a MAC it sends itself. The
registry keeps one row per device and MAC (device_mac: first_seen, last_seen, auth_count,
randomized); a *window* is the time that MAC's data belongs to the device:

    [max(first_seen, enrolment), window_end]

The rule is the registry's (SQL view device_mac_window, registry.device_windows' window_end and
current), the same one device_for_mac, window_conflicts and the accounting use: the current
window (the MAC of the newest login) lasts until last_seen + 12 h 15 min, capped at now (an
associated device logs in again at least every 12 h; accounting moves last_seen meanwhile).
Telemetry only bounds the start by the enrolment.

Prometheus data of a MAC outside its windows belongs to nobody and is never shown. Windows of
other people's devices on the same MAC that overlap (registry.window_conflicts; revoked devices
too, for the time they had it) are a conflict: residents see nothing of that MAC for the overlap
(withheld), admins see it marked.

Without a registry connection (unit tests of the v1 API, telemetry.dashboard(..., claims=))
the identity comes from the registry row as in v1: the latest login's MAC (calling_station) from
data_bound on, open-ended, withheld entirely while other people's devices claim the same MAC.
"""

import datetime

from .. import registry
from .common import UTC, iso, latest, normalise_mac, randomized, unix

# The registry's window rule (SQL view device_mac_window), in seconds: 15 min grace; the current
# window up to 12 h 15 min after the last login.
WINDOW_GRACE_S = registry.WINDOW_GRACE.total_seconds()
CURRENT_WINDOW_S = registry.CURRENT_WINDOW.total_seconds()
# a window_end this close to now was capped at the database's now() (the request's transaction)
CAPPED_SLACK_S = 300
SESSION_S = CURRENT_WINDOW_S                # the v2 name until 2026-10-25 (telemetry.SESSION_S)
# rotating: this many randomized MACs in this period (two can be a reset or a new phone OS;
# iOS "rotating" changes about every two weeks, Android "non-persistent" daily or per connection)
ROTATING_MIN_MACS, ROTATING_PERIOD_S = 3, 30 * 86400
# The dashboard reads the windows of this period (current ones, the mode, the MACs shown).
RECENT_S = 31 * 86400
MACS_SHOWN = 50


def data_bound(row):
    """From when Prometheus's data for this device's MAC is this device's: the later of its
    enrolment and the first login with that MAC (Unix seconds, None if neither is known). The
    v1 bound, from the registry row (radius_session.first_seen)."""
    known = [unix(row.get(k)) for k in ("created", "first_seen") if row.get(k) is not None]
    return max(known) if known else None


def other_owners(claims, mac, owner):
    """How many other people's active devices claim this MAC (v1: registry.mac_claims)."""
    return len(set((claims or {}).get(mac, ())) - {owner}) if mac else 0


class Identity:
    """One device's windows and conflicts, in Unix seconds.

    windows: [{"mac", "start", "end" (None: open, up to now), "first_seen", "last_seen",
    "randomized", "auth_count", "current"}] sorted by start; conflicts: [{"mac", "other_owners",
    "from", "to" (None: open)}]; admin: conflicts are marked, not withheld."""

    def __init__(self, device_id, windows, conflicts, admin, now):
        self.device_id, self.admin, self.now = device_id, admin, now
        self.windows = sorted(windows, key=lambda w: (w["start"], w["mac"]))
        self.conflicts = conflicts
        current = [w for w in self.windows if w["current"]]
        self.current = current[0] if current else None

    # --- what the device is ---------------------------------------------------------------

    @property
    def current_mac(self):
        return self.current["mac"] if self.current else None

    @property
    def data_from(self):
        """The first window's start: no data of this device is older."""
        first = min((w["start"] for w in self.windows), default=None)
        return None if first is None or first == float("-inf") else first

    def mac_mode(self):
        """hardware | random_fixed | rotating (None: no login yet). From the current MAC's kind
        and how many randomized MACs the device used in ROTATING_PERIOD_S."""
        if not self.windows:
            return None
        current = self.current or self.windows[-1]
        if not current["randomized"]:
            return "hardware"
        if len(self.recent_randomized()) >= ROTATING_MIN_MACS:
            return "rotating"
        return "random_fixed"

    def recent_randomized(self):
        since = self.now - ROTATING_PERIOD_S
        return sorted({w["mac"] for w in self.windows if w["randomized"] and (w["last_seen"] or 0) >= since})

    def public_macs(self):
        """DEVICE["macs"]: the newest MACS_SHOWN, the current one first."""
        rows = sorted(self.windows, key=lambda w: (not w["current"], -(w["last_seen"] or w["start"] or 0)))
        return [{"mac": w["mac"], "randomized": w["randomized"], "first_seen": iso(w["first_seen"]),
                 "last_seen": iso(w["last_seen"]), "current": w["current"]} for w in rows[:MACS_SHOWN]]

    # --- conflicts ------------------------------------------------------------------------

    def _conflict_end(self, c):
        return self.now if c["to"] is None else c["to"]

    def conflicts_at(self, t):
        return [c for c in self.conflicts if (c["from"] is None or c["from"] <= t) and t <= self._conflict_end(c)]

    def withheld_spans(self):
        """[(mac, from, to)] a resident does not see (nothing for an admin)."""
        if self.admin:
            return []
        return [(c["mac"], c["from"], self._conflict_end(c)) for c in self.conflicts]

    def withheld_now(self):
        """A resident's live data is withheld: the current MAC is in a conflict now."""
        return (not self.admin and self.current is not None
                and any(c["mac"] == self.current["mac"] for c in self.conflicts_at(self.now)))

    def conflict_owners_now(self):
        """The most other owners of any of the device's MACs now (an admin's mac_conflict)."""
        return max((c["other_owners"] for c in self.conflicts_at(self.now)), default=0)

    def public_conflicts(self):
        """For admins: every conflict with the other owners' count; residents get the spans only."""
        if self.admin:
            return [{"mac": c["mac"], "other_owners": c["other_owners"], "from": iso(c["from"]), "to": iso(c["to"])}
                    for c in self.conflicts]
        return [{"mac": mac, "from": iso(f), "to": iso(t)} for mac, f, t in self.withheld_spans()]

    # --- where the data is the device's -----------------------------------------------------

    def segments(self, start=None, end=None):
        """[{"mac", "start", "end"}]: the windows clipped to [start, end], minus what is withheld
        (residents), sorted by start. An open window ends now."""
        withheld = self.withheld_spans()
        out = []
        for w in self.windows:
            pieces = [(w["start"], self.now if w["end"] is None else w["end"])]
            for mac, f, t in withheld:
                if mac == w["mac"]:
                    pieces = _subtract(pieces, f if f is not None else float("-inf"), t)
            for a, b in pieces:
                a, b = max(a, start) if start is not None else a, min(b, end) if end is not None else b
                if a <= b:
                    out.append({"mac": w["mac"], "start": a, "end": b})
        return sorted(out, key=lambda s: (s["start"], s["mac"]))

    def live_bounds(self):
        """{mac: data bound} of the MACs whose (unwithheld) windows hold now: the bound is the
        start of that piece (data before it is not this device's)."""
        bounds = {}
        for s in self.segments():
            if s["start"] <= self.now <= s["end"] + 1:
                bounds[s["mac"]] = max(s["start"], bounds.get(s["mac"], s["start"]))
        return bounds

    def contains(self, mac, t, segments=None):
        """mac's data at t is this device's (and not withheld)."""
        return any(s["mac"] == mac and s["start"] <= t <= s["end"] for s in (segments or self.segments()))


def _subtract(pieces, a, b):
    out = []
    for x, y in pieces:
        if b < x or a > y:
            out.append((x, y))
            continue
        if x < a:
            out.append((x, a - 1))
        if b < y:
            out.append((b + 1, y))
    return out


# --- from the registry --------------------------------------------------------------------------

def from_registry(db, rows, now, admin, since=None):
    """{device id (str): Identity} for these registry rows (registry.DEVICE_LIST), from
    device_windows and window_conflicts (one query each for all of them). since: only windows
    and conflicts from then on (the dashboard: RECENT_S; a device's history: all)."""
    ids = [r["id"] for r in rows]
    if not ids:
        return {}
    since_dt = None if since is None else _dt(since)
    windows = registry.device_windows(db, ids, since=since_dt)
    conflicts = registry.window_conflicts(db, ids, since=since_dt)
    out = {}
    for r in rows:
        key = str(r["id"])
        rws = windows.get(r["id"], windows.get(key, []))
        out[key] = Identity(key, _windows(r, rws, now), _conflicts(conflicts.get(r["id"], conflicts.get(key, []))), admin, now)
    return out


def _dt(t):
    return datetime.datetime.fromtimestamp(t, UTC)


def _windows(row, rows, now):
    """Identity windows from registry.device_windows rows. The window rule is the registry's
    (SQL view device_mac_window): window_end and current come from there, telemetry only bounds
    the start by the enrolment. A current window whose end is capped at now (the database's: not
    yet last_seen + CURRENT_WINDOW, within CAPPED_SLACK_S of now) is open: it ends whenever the
    page asks."""
    created = unix(row.get("created"))
    out = []
    for w in rows:
        mac = normalise_mac(w.get("mac"))
        first, last, end = unix(w.get("first_seen")), unix(w.get("last_seen")), unix(w.get("window_end"))
        if mac is None or first is None or last is None or end is None:
            continue
        start = max(first, created) if created is not None else first
        current = bool(w.get("current"))
        if current and end < last + CURRENT_WINDOW_S and end >= now - CAPPED_SLACK_S:
            end = None
        out.append({"mac": mac, "start": start, "end": end, "first_seen": first, "last_seen": last,
                    "randomized": bool(w.get("randomized", randomized(mac))), "auth_count": w.get("auth_count"),
                    "current": current})
    flagged = [w for w in out if w["current"]]
    if len(flagged) > 1:                         # a tie on last_seen: one is the current MAC
        keep = max(flagged, key=lambda w: (w["last_seen"], w["first_seen"], w["mac"]))
        for w in flagged:
            w["current"] = w is keep
    return out


def _conflicts(rows):
    out = []
    for c in rows:
        mac = normalise_mac(c.get("mac"))
        if mac:
            out.append({"mac": mac, "other_owners": int(c.get("other_owners") or 1),
                        "from": unix(c.get("from")), "to": unix(c.get("to"))})
    return out


# --- v1: from the registry row -------------------------------------------------------------------

def from_rows(rows, claims, now, admin):
    """{device id (str): Identity} the v1 way: the latest login's MAC from data_bound on, open;
    a MAC other people's active devices claim too is a conflict for all time."""
    out = {}
    for r in rows:
        key, mac = str(r["id"]), normalise_mac(r.get("calling_station"))
        windows, conflicts = [], []
        if mac:
            bound = data_bound(r)
            last = latest(r.get("last_seen"))
            windows.append({"mac": mac, "start": bound if bound is not None else float("-inf"), "end": None,
                            "first_seen": unix(r.get("first_seen")), "last_seen": last, "randomized": randomized(mac),
                            "auth_count": None, "current": True})
            n = other_owners(claims, mac, r.get("owner"))
            if n:
                conflicts.append({"mac": mac, "other_owners": n, "from": None, "to": None})
        out[key] = Identity(key, windows, conflicts, admin, now)
    return out
