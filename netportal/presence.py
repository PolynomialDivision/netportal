"""Device presence: ONE state per device from every source (docs/TELEMETRY.md, "Presence").

Every place that says online/offline (DEVICE.state, last_seen and since, the diagnostics'
offline and stale_data findings, the admin device list and its counts) reads decide() here;
nothing else derives a state.

Sources (each item is evidence with a time; the newest authoritative one wins):
- association (Prometheus/unpoller): present or absent at the snapshot time Ts (scrape time -
  unpoller's cache age), with the association start. Fresh only while the snapshot is not
  older than diagnostics.STALE_AFTER_S; a frozen snapshot is no evidence at all.
- sessions (radius_acct, one per (nas_ip, acct_session_id), linked to the device by the login's
  Class or the MAC window, never by the MAC alone): started, updated (Start/Interim), stopped,
  cause. A Stop ends only its own session: on a roam the new AP's Start can come before the
  old AP's Stop. An open session is alive while now - updated <= stale_after = 2 x interval +
  STALE_GRACE_S, interval = the session's measured one (radius_acct.interim_s), else its NAS's
  (radius_nas.interim_s), else the configured NETPORTAL_ACCT_INTERIM_S. Older without an
  update or a Stop it is abandoned (the AP lost power, a Stop got lost). An open ap_down
  incident of its AP (no update since the incident began) makes it not count either.
- the latest login (radius_session.updated: the latest Access-Accept).
- UniFi's system log (connection_event): connected / disconnected / roamed, 2-10 min late.

Decision (decide):
1. Evidence newer than Ts decides (all of it when Ts is not fresh). The controller lists a new
   association, and drops a gone one, up to CONTROLLER_LAG_S after it happened, so a Start or a
   Stop counts as newer when it is within that before Ts; an Interim must be newer than Ts.
   a. an alive session whose Start or Interim is newer -> online (radius_acct, acct_start /
      acct_interim);
   b. a login less than CONNECTING_S old, newer than every session's start and stop, no alive
      session and no fresh association -> connecting (radius_auth, accept_pending); older
      without a Start: falls through;
   c. no alive session and the newest session stopped after Ts -> offline (radius_acct,
      acct_stop; ap_down when the AP itself ended it: Accounting-On/Off, NAS-Reboot/-Request);
   d. a UniFi disconnect newer than Ts and than every session's and login's time, no alive
      session -> offline (unifi_syslog, unifi_disconnect).
2. Otherwise a fresh snapshot: present -> online (prometheus, association); absent -> offline
   (prometheus, association_gone).
3. No fresh snapshot (Prometheus off, unavailable or frozen): 1 covers the alive session
   (online), the Stop (offline), the login and the disconnect; the newest session open on an AP
   with an open ap_down incident -> offline (inferred, ap_down); else unknown (session_stale when
   the newest session went silent, telemetry_unavailable otherwise). Missing evidence is never
   "offline".
4. A resident's device whose current MAC is in a conflict now -> unknown (mac_conflict), no
   evidence shown; admins get the decision. No MAC, no session and no login: never_connected.
Duplicates and reordered packets: only event times are compared, never arrival order (the SQL
function radius_accounting keeps updated monotonic and a Stop final).

Inputs are plain data (Unix seconds); load() reads the registry for all devices of a page in
two indexed queries.
"""

import datetime

from . import registry

ONLINE, CONNECTING, OFFLINE, UNKNOWN, NEVER = "online", "connecting", "offline", "unknown", "never_connected"
STATES = (ONLINE, CONNECTING, OFFLINE, UNKNOWN, NEVER)
MEASURED, INFERRED = "measured", "inferred"

# A login without an accounting Start yet is "connecting" this long (hostapd sends the Start
# right after the 4-way handshake; a login that is not followed by one within a minute did not
# end in an association, or the AP does not send accounting).
CONNECTING_S = 60
# The UniFi controller's own delay in listing a new association or dropping a gone one, beyond
# the snapshot time (unpoller's poll); RADIUS Starts and Stops this much before Ts still count as
# newer than the snapshot.
CONTROLLER_LAG_S = 60
# An open session is abandoned after 2 intervals without an update plus this.
STALE_GRACE_S = 60
# The configured accounting interval when nothing was measured (NETPORTAL_ACCT_INTERIM_S).
DEFAULT_INTERIM_S = 300
MIN_INTERIM_S, MAX_INTERIM_S = 30, 86400
# A Start this much before the login still is the login's (the AP's clock vs the database's),
# unless its session ended before the login.
CLOCK_SKEW_S = 5
# A measured interval counts up to this many configured ones (an outage's gap is no interval).
MAX_INTERVAL_FACTOR = 4
# A listed association that began this much before a Stop is the gone one, still listed (the
# association start moves by up to a minute between snapshots).
ASSOCIATION_SKEW_S = 60
# Sessions that overlap or follow each other within this are one stay (roams) for "since".
ROAM_S = 120
# The page's poll hint: fast while connecting or within RECENT_CHANGE_S of a change.
POLL_FAST_S, POLL_S, RECENT_CHANGE_S = 5, 30, 120
# Terminate causes that mean the access point ended the session itself (Accounting-On/Off).
AP_CAUSES = ("NAS-Reboot", "NAS-Request", "NAS-Error")
EVIDENCE_MAX = 12
SOURCES = ("prometheus", "radius_acct", "radius_auth", "unifi_syslog")


def stale_after(interim_s):
    """Seconds an open session stays alive without an update."""
    return 2 * int(interim_s) + STALE_GRACE_S


def _iso(t):
    return None if t is None else datetime.datetime.fromtimestamp(t, datetime.timezone.utc).isoformat(timespec="seconds")


def _unix(value):
    if isinstance(value, datetime.datetime):
        return (value if value.tzinfo else value.replace(tzinfo=datetime.timezone.utc)).timestamp()
    return value


# --- the inputs -----------------------------------------------------------------------------------

def association(status, telemetry, snapshot_at, stale):
    """The Prometheus evidence of one device: None unless Prometheus answered (telemetry "ok").
    status: live.device_status's entry of its MAC (None: no MAC asked: absent); snapshot_at: Ts."""
    if telemetry != "ok":
        return None
    status = status or {}
    return {"present": bool(status.get("present")), "at": snapshot_at,
            "fresh": not stale and snapshot_at is not None, "start": status.get("start"),
            "last_seen": status.get("last_seen")}


def session(row, aps=None):
    """A registry.latest_sessions row as plain data; ap from the ApMap (by BSSID, else NAS)."""
    name, ap_mac, _band = aps.by_bssid(row.get("bssid"), row.get("nas_ip")) if aps is not None else (None, None, None)
    started, updated = _unix(row.get("started")), _unix(row.get("updated"))
    return {"nas_ip": None if row.get("nas_ip") is None else str(row["nas_ip"]),
            "acct_session_id": row.get("acct_session_id"), "link": row.get("link"),
            "mac": registry.normalise_mac(str(row["mac"])) if row.get("mac") else None,
            "ap_name": name, "ap_mac": ap_mac, "started": started if started is not None else updated,
            "updated": updated, "stopped": _unix(row.get("stopped")), "cause": row.get("terminate_cause"),
            "interim_s": row.get("interim_s"), "nas_interim_s": row.get("nas_interim_s")}


def event(row):
    """A registry.latest_connection_events row as plain data."""
    return {"at": _unix(row["at"]), "kind": row.get("kind"),
            "mac": registry.normalise_mac(str(row["mac"])) if row.get("mac") else None,
            "ap_mac": registry.normalise_mac(str(row["ap_mac"])) if row.get("ap_mac") else None,
            "ap_name": row.get("ap_name")}


def ap_down(incidents):
    """{AP MAC or "name:<lower name>": start} of the open ap_down incidents (registry.incidents)."""
    out = {}
    for r in incidents or ():
        if r.get("kind") != "ap_down" or r.get("ended") is not None:
            continue
        started = _unix(r["started"])
        mac = registry.normalise_mac(r.get("subject") or "")
        if mac:
            out[mac] = started
        if r.get("subject_name"):
            out["name:" + r["subject_name"].lower()] = started
    return out


def own(rows, identity):
    """What of a device's sessions and events a resident may see (the timeline's rule,
    timeline.restrict): nothing of a MAC inside a withheld span except a session that is the
    device's by its certificate (link "class"). Admins and identity None: everything."""
    if identity is None or identity.admin or not identity.conflicts:
        return list(rows)
    out = []
    for r in rows:
        at = r.get("updated", r.get("at"))
        hit = r.get("mac") and any(c["mac"] == r["mac"] and (c["from"] is None or c["from"] <= at)
                                   and (c["to"] is None or at <= c["to"]) for c in identity.conflicts)
        if not hit or r.get("link") == "class":
            out.append(r)
    return out


def load(db, device_ids, ssid=None):
    """{device id (str): {"sessions": [rows], "events": [rows]}} for all devices of a page: two
    queries (registry.latest_sessions, registry.latest_connection_events), raw rows."""
    if not device_ids:
        return {}
    sessions = registry.latest_sessions(db, device_ids)
    events = registry.latest_connection_events(db, device_ids, ssid=ssid)
    return {str(i): {"sessions": sessions.get(str(i), []), "events": events.get(str(i), [])} for i in device_ids}


# --- the decision ---------------------------------------------------------------------------------

def _activity(s):
    """The session's last sign: its end (a Stop, or the last contact of one the AP closed after
    it had long gone silent), else its latest update."""
    return s["end"] if s.get("end") is not None else s["updated"]


def interval(measured, configured):
    """The interval a session's staleness counts with: the measured one, clamped to
    [configured, MAX_INTERVAL_FACTOR x configured] (a short extra Interim, an outage's gap or a
    lost packet cannot move it far); the configured one when nothing was measured."""
    configured = int(configured or DEFAULT_INTERIM_S)
    if not measured:
        return configured
    return min(max(int(measured), configured), MAX_INTERVAL_FACTOR * configured)


def _down_since(s, stopped, down):
    """The open ap_down incident's start when it ends this open session (no update since)."""
    if stopped is not None or not down:
        return None
    start = down.get(s["ap_mac"]) if s["ap_mac"] else None
    if start is None and s["ap_name"]:
        start = down.get("name:" + s["ap_name"].lower())
    return start if start is not None and s["updated"] <= start + CONTROLLER_LAG_S else None


def _view(now, sessions, down, interim_s):
    """The sessions with what the rules need: stale_after_s, stopped (None when the session was
    updated well after its Stop: the id was used again), end (the effective end), abandoned (an
    AP's Accounting-On/Off closed it long after its last contact: it ended at that contact),
    superseded, alive, down_since; newest activity first. A duplicate row counts once."""
    out, keys = [], []
    for s in sessions:
        key = (s.get("nas_ip"), s.get("acct_session_id"), s.get("started"), s.get("stopped"), s.get("updated"))
        if s.get("updated") is None or key in keys:
            continue
        keys.append(key)
        measured = s.get("interim_s") or s.get("nas_interim_s")
        every = interval(measured, interim_s)
        limit = stale_after(every)
        stopped = s["stopped"]
        if stopped is not None and s["updated"] > stopped + every:
            stopped = None
        end, abandoned = stopped, False
        if stopped is not None and s["cause"] in AP_CAUSES and stopped > s["updated"] + limit:
            end, abandoned = s["updated"], True
        out.append(dict(s, stopped=stopped, end=end, abandoned=abandoned, stale_after_s=limit,
                        interim_basis=MEASURED if measured else INFERRED, down_since=_down_since(s, stopped, down)))
    for v in out:
        # an open session last updated before another session of the device started: the device
        # moved on (a roam whose Stop got lost); not alive, however recent its last Interim
        v["superseded"] = v["stopped"] is None and any(
            o is not v and o["started"] is not None and v["updated"] < o["started"] for o in out)
        v["alive"] = (v["stopped"] is None and not v["superseded"] and now - v["updated"] <= v["stale_after_s"]
                      and v["down_since"] is None)
    return sorted(out, key=lambda v: (_activity(v), v["started"] or 0), reverse=True)


def _by_start(v):
    return (v["started"] if v["started"] is not None else v["updated"], v["updated"])


def _online_since(s, view, assoc, ts):
    """Since when the device is there: the association start of a fresh snapshot that already
    saw this session; else the start of the session, joined with the sessions before it that
    overlap it or end within ROAM_S of it (roams)."""
    if assoc and assoc["fresh"] and assoc["present"] and assoc["start"] is not None and (
            s is None or s["started"] is None or s["started"] <= ts):
        return assoc["start"]
    if s is None:
        return None
    since = s["started"]
    for _ in range(len(view)):
        earlier = [v["started"] for v in view if v["started"] is not None and v["started"] < since
                   and _activity(v) >= since - ROAM_S]
        if not earlier:
            break
        since = min(earlier)
    return since


def _last_present(assoc, view, accept, events):
    """The latest time any source saw the device there (None: never)."""
    times = [_activity(v) for v in view] + [e["at"] for e in events] + [accept]
    if assoc:
        times += [assoc["last_seen"], assoc["at"] if assoc["present"] else None]
    known = [t for t in times if t is not None]
    return max(known) if known else None


def _evidence(assoc, view, accept, events, down):
    items = []
    if assoc and assoc["at"] is not None:
        kind = "association" if assoc["present"] else "association_gone"
        items.append(("prometheus", assoc["at"], kind if assoc["fresh"] else kind + "_stale"))
    for v in view:
        if v["started"] is not None:
            items.append(("radius_acct", v["started"], "acct_start"))
        if v["updated"] != v["started"] and (v["stopped"] is None or v["updated"] < v["stopped"]):
            items.append(("radius_acct", v["updated"], "acct_interim"))
        if v["stopped"] is not None:
            items.append(("radius_acct", v["stopped"], "acct_stop"))
        if v["down_since"] is not None:
            items.append(("incident", v["down_since"], "ap_down"))
    if accept is not None:
        items.append(("radius_auth", accept, "accept"))
    for e in events:
        items.append(("unifi_syslog", e["at"], e["kind"]))
    items = sorted(set(items), key=lambda x: (x[1], x[0], x[2]), reverse=True)[:EVIDENCE_MAX]
    return [{"source": src, "at": at, "kind": kind} for src, at, kind in items]


def decide(now, assoc=None, sessions=(), accept=None, events=(), down=None, interim_s=DEFAULT_INTERIM_S,
           withheld=False, never=False):
    """The presence of one device (Unix times inside; public() makes the API's shape).

    assoc: association(); sessions: [session()]; accept: the latest login; events: [event()];
    down: ap_down(); interim_s: the configured interval; withheld: a resident's device in a MAC
    conflict now; never: the device has no MAC identity yet. Returns {"state", "since",
    "confirmed_at", "confirmed_by", "basis", "reason", "session", "stale_after_s", "poll_s",
    "evidence", "last_seen"}."""
    interim_s = interim_s or DEFAULT_INTERIM_S
    if withheld:
        return _result(now, UNKNOWN, None, None, None, INFERRED, "mac_conflict", None, stale_after(interim_s), [],
                       accept)
    view = _view(now, sessions or (), down or {}, interim_s)
    events = sorted((e for e in events or () if e.get("at") is not None), key=lambda e: e["at"], reverse=True)
    evidence = _evidence(assoc, view, accept, events, down)
    if never and not view and accept is None:
        return _result(now, NEVER, None, None, None, MEASURED, "no_data", None, stale_after(interim_s), evidence, None)
    fresh = bool(assoc and assoc["fresh"])
    ts = assoc["at"] if fresh else None
    absent = fresh and not assoc["present"]

    def newer(t, lag=0):
        return t is not None and (ts is None or t > ts - lag)

    alive = [v for v in view if v["alive"]]
    newest = view[0] if view else None
    current = max(alive, key=_by_start) if alive else None

    def done(state, since, at, by, basis, reason, s, last_seen):
        limit = s["stale_after_s"] if s else stale_after(interim_s)
        return _result(now, state, since, at, by, basis, reason, s, limit, evidence, last_seen)

    # 1a. an alive session newer than the snapshot (the newest started one). A fresh snapshot
    # that does not list a session it should long have seen (started well before Ts) while its
    # Interims go on: the sources disagree; online stays (the packets are the device's own,
    # and the session goes stale by itself once they stop), inferred, the session's since: no
    # flapping with every Interim.
    recent = [v for v in alive if newer(v["started"], CONTROLLER_LAG_S) or newer(v["updated"])]
    if recent or (absent and current):
        s = max(recent, key=_by_start) if recent else current
        since = _online_since(s, view, assoc, ts)
        if absent and s["started"] is not None and s["started"] <= ts - CONTROLLER_LAG_S:
            return done(ONLINE, since, s["updated"], "radius_acct", INFERRED, "sources_disagree", s, s["updated"])
        reason = "acct_interim" if s["updated"] > s["started"] else "acct_start"
        return done(ONLINE, since, s["updated"], "radius_acct", MEASURED, reason, s, s["updated"])
    # 1b. a fresh login without a Start yet
    if (accept is not None and 0 <= now - accept < CONNECTING_S and not alive and not (fresh and assoc["present"])
            # the login's own session (started at most CLOCK_SKEW_S before it) began, so the
            # login is answered, also when that session already ended: Event-Timestamps are
            # whole seconds of the AP's clock, a Stop can read up to a few seconds "before" the
            # login it belongs to; but one the AP itself closed before the login (Accounting-On:
            # it restarted) is no answer, the device logs in again after the restart
            and not any(v["started"] is not None and v["started"] >= accept - CLOCK_SKEW_S
                        and not (v["cause"] in AP_CAUSES and v["end"] is not None and v["end"] < accept)
                        for v in view)
            # an older session that ended clearly after the login: the login was a
            # re-authentication inside it; one that ended just before (a reconnect) is no reason
            and not any(v["end"] is not None and v["end"] >= accept + CLOCK_SKEW_S for v in view)):
        return done(CONNECTING, accept, accept, "radius_auth", MEASURED, "accept_pending", None, accept)
    # 1c. none alive and the newest session ended after the snapshot, or a present snapshot
    # lists an association from before that Stop (the controller still shows the gone client)
    if not alive and newest and newest["end"] is not None:
        listed_gone = (fresh and assoc["present"] and not newest["abandoned"] and assoc["start"] is not None
                       and assoc["start"] < newest["end"] - ASSOCIATION_SKEW_S)
        if newer(newest["end"], CONTROLLER_LAG_S) or listed_gone:
            reason = "ap_down" if newest["cause"] in AP_CAUSES else "acct_stop"
            return done(OFFLINE, newest["end"], newest["end"], "radius_acct", MEASURED, reason, newest, newest["end"])
    # 1d. a UniFi disconnect newer than everything else
    if events and not alive:
        e = events[0]
        others = [_activity(v) for v in view] + ([accept] if accept is not None else [])
        if e["kind"] == "disconnected" and newer(e["at"]) and all(e["at"] > t for t in others):
            return done(OFFLINE, e["at"], e["at"], "unifi_syslog", MEASURED, "unifi_disconnect", newest, e["at"])
    # 2. a fresh snapshot
    if fresh:
        if assoc["present"]:
            return done(ONLINE, _online_since(current, view, assoc, ts), ts, "prometheus", MEASURED, "association",
                        current, ts)
        seen = _last_present(assoc, view, accept, events)
        if seen is not None and seen > ts:
            # seen after the snapshot (a login that got no Start within CONNECTING_S): what
            # confirms it is the time since that sighting, not the older snapshot
            return done(OFFLINE, seen, seen, "prometheus", INFERRED, "association_gone", newest, seen)
        return done(OFFLINE, seen, ts, "prometheus", MEASURED, "association_gone", newest, seen)
    # 3. no fresh snapshot
    seen = _last_present(assoc, view, accept, events)
    if newest and newest["end"] is None and newest["down_since"] is not None:
        return done(OFFLINE, newest["down_since"], newest["down_since"], "prometheus", INFERRED, "ap_down", newest,
                    newest["updated"])
    if newest and newest["end"] is None:
        return done(UNKNOWN, None, None, None, INFERRED, "session_stale", newest, seen)
    return done(UNKNOWN, None, None, None, INFERRED, "telemetry_unavailable", newest, seen)


def _result(now, state, since, confirmed_at, confirmed_by, basis, reason, s, limit, evidence, last_seen):
    fast = state == CONNECTING or (since is not None and now - since < RECENT_CHANGE_S)
    return {"state": state, "since": since, "confirmed_at": confirmed_at, "confirmed_by": confirmed_by,
            "basis": basis, "reason": reason, "session": s, "stale_after_s": limit,
            "poll_s": POLL_FAST_S if fast else POLL_S, "evidence": evidence, "last_seen": last_seen}


def public(p):
    """DEVICE["presence"]: {state, since, confirmed_at, confirmed_by, basis, reason, session,
    stale_after_s, poll_s, evidence} with ISO times."""
    s = p["session"]
    session_out = None
    if s is not None:
        from .telemetry.common import ap_ref       # (the telemetry package imports this module)
        ap = ap_ref(s.get("ap_name"), s.get("ap_mac"))
        session_out = {"nas_ip": s["nas_ip"], "acct_session_id": s["acct_session_id"], "ap": ap,
                       "started": _iso(s["started"]), "updated": _iso(s["updated"]), "stopped": _iso(s["stopped"]),
                       "cause": s["cause"], "interim_s": s.get("interim_s") or s.get("nas_interim_s"),
                       "interim_basis": s.get("interim_basis")}
    return {"state": p["state"], "since": _iso(p["since"]), "confirmed_at": _iso(p["confirmed_at"]),
            "confirmed_by": p["confirmed_by"], "basis": p["basis"], "reason": p["reason"], "session": session_out,
            "stale_after_s": p["stale_after_s"], "poll_s": p["poll_s"],
            "evidence": [{"source": e["source"], "at": _iso(e["at"]), "kind": e["kind"]} for e in p["evidence"]]}


def counts(devices):
    """{state: n} over DEVICEs (every state a key)."""
    out = {s: 0 for s in STATES}
    for d in devices:
        out[d.get("state")] = out.get(d.get("state"), 0) + 1
    return out


def poll_s(devices):
    """The page's poll interval: the shortest of its devices' hints (POLL_S without devices)."""
    hints = [(d.get("presence") or {}).get("poll_s") for d in devices]
    hints = [h for h in hints if h]
    return min(hints) if hints else POLL_S
