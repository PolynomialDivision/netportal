"""The admins' views: the house's overview, the APs, incidents, RADIUS rejects, and all source
rows of one device. Admin-only (web.py checks); counts and lists from the registry, live AP
load from Prometheus under one page budget.

Shapes (JSON; times ISO 8601 UTC):

OVERVIEW (/api/admin/overview, the /admin page's "overview"):
    {"generated_at", "telemetry": ok|unavailable|off, "stale": bool, "house": HOUSE,
     "incidents": {"available": bool, "open": [INCIDENT], "recent": [INCIDENT] (ended in 7 days,
                   newest first, at most 50), "counts_7d": {kind: n}},
     "aps": [AP] (live; [] unless telemetry ok),
     "auth": {"available": bool, "since", "count" (tries: repeats included), "truncated" (rows),
              "by_reason": {reason: tries},
              "devices": n (distinct devices), "macs": n (distinct MACs), "recent": [AUTH_FAILURE] (20)},
     "jobs": [JOB], "jobs_available": bool (a list, not {"items": ...}: Jinja reads .items as the
     dict's method),
     "freshness": {"wifi_data_age_s", "prometheus": telemetry, "jobs_ok": bool|None,
                   "oldest_job_success_age_s": n|None}}
AP: {"name", "mac", "house", "floor", "spot", "ip", "model", "state": ok|down|unknown,
     "clients": n, "clients_house": n (on the house SSID), "weak_clients": n (signal <= -75 dBm),
     "signal_avg_dbm", "uptime_s", "uplink_mbps", "radios": [{"radio", "band", "channel",
     "clients", "channel_util"}], "open_incidents": [INCIDENT],
     "warnings": [code] (diagnostics.ap_warnings: down | overloaded | busy_channel |
                 poor_coverage | restarted | uplink, the worst first),
     "warning_details": [{"code", "severity", "params", "basis", "evidence"}] (the same, with values)}
APS (/api/admin/aps): {"generated_at", "telemetry", "aps": [AP + "days": [AP_DAY] (7 days)]}
INCIDENT: {"id", "kind", "subject", "subject_name", "started", "ended", "open", "duration_s",
           "basis", "detail", "devices": [{"id", "name", "owner": {"username", "display"}}] | None
           (None: not computed, older than DEVICES_SPAN_S before the newest one shown),
           "devices_truncated", "devices_basis": "inferred"}
           devices: the registered devices that dropped out (UniFi disconnect, accounting Stop,
           reconnect) from 2 min before the start to 2 min after the end (at most 15 min after the
           start: diagnostics.INCIDENT_*), of the incident's AP (by AP MAC or name) or, for the
           house-wide kinds, all of them; a switch's when its detail lists the AP MACs.
INCIDENTS (/api/admin/incidents): {"from", "to", "kind": str|None, "incidents": [INCIDENT],
           "truncated", "counts": {kind: n}}
AUTH_FAILURE: {"at", "reason", "serial", "device_id", "device_name", "owner": {"username",
              "display"} | None, "mac", "bssid", "ssid", "nas_ip", "ap": {"name", ..., "mac"} | None,
              "count" (the tries this row stands for: repeats within 60 s are one row,
              registry.REJECT_REPEAT), "last_at" (the latest of them; None: one)}
AUTH (/api/admin/auth): {"from", "to", "result": "reject", "events": [AUTH_FAILURE],
      "truncated", "by_reason": {reason: tries}}
JOB: {"name", "last_success", "last_attempt", "last_error", "duration_s", "ok", "age_s", "cursor"}
RAW (/api/admin/devices/<id>/raw): {"device": {"id", "name", "owner", "revoked"}, "from", "to",
     "windows": [{"mac", "first_seen", "last_seen", "randomized", "auth_count", "current",
                  "start", "end"}], "conflicts": [...], "auth": [rows], "acct": [rows],
     "events": [connection_event rows], "days": [device_day rows], "incidents": [INCIDENT],
     "limits": {source: n}, "truncated": {source: bool}}
"""

import datetime
import decimal
import ipaddress
import logging
import time
import uuid

from .. import diagnostics, registry
from . import live
from . import timeline as tl
from .client import SUMMARY_CACHE_SECONDS, Unavailable
from .common import BANDS, UTC, ap_info, ap_ref, iso, normalise_mac, promql_string, rounded, unix
from .house import empty_house, house_status

log = logging.getLogger("netportal.telemetry")

RECENT_INCIDENTS_S, RECENT_INCIDENTS_MAX = 7 * 86400, 50
AUTH_RECENT = 20
AUTH_LIMIT, AUTH_MAX_SPAN_S = 500, 31 * 86400
INCIDENT_LIMIT, INCIDENT_MAX_SPAN_S = 1000, 400 * 86400
RAW_LIMITS = {"auth": 1000, "acct": 1000, "events": 2000}
RAW_MAX_SPAN_S = 31 * 86400
AP_DAYS = 7
# incident devices: at most this many per incident, for the incidents of the newest
# DEVICES_SPAN_S of a list (each active device's events of that span: two registry queries per
# device, however many incidents), at most DEVICES_INCIDENTS incidents
INCIDENT_DEVICES_MAX, DEVICES_SPAN_S, DEVICES_INCIDENTS = 200, 7 * 86400, 100
DROPOUT_LIMITS = {"unifi": 2000, "acct": 1000}
WEAK_DBM = diagnostics.WEAK_SIGNAL_WARN_DBM


# --- serialising registry rows ----------------------------------------------------------------

def jsonable(value):
    """Registry values as JSON: datetimes ISO (UTC), dates ISO, addresses, UUIDs and decimals
    as strings/numbers, containers recursively."""
    if isinstance(value, datetime.datetime):
        return iso(value)
    if isinstance(value, datetime.date):
        return value.isoformat()
    if isinstance(value, (uuid.UUID, ipaddress.IPv4Address, ipaddress.IPv6Address, ipaddress.IPv4Network,
                          ipaddress.IPv6Network, ipaddress.IPv4Interface, ipaddress.IPv6Interface)):
        return str(value)
    if isinstance(value, decimal.Decimal):
        return float(value)
    if isinstance(value, dict):
        return {str(k): jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [jsonable(v) for v in value]
    return value


def public_incident(r, now=None):
    started, ended = unix(r["started"]), unix(r.get("ended"))
    end = ended if ended is not None else (time.time() if now is None else now)
    return {"id": r.get("id"), "kind": r.get("kind"), "subject": r.get("subject") or "",
            "subject_name": r.get("subject_name"), "started": iso(started), "ended": iso(ended),
            "open": ended is None, "duration_s": int(end - started), "basis": r.get("basis"),
            "detail": jsonable(r.get("detail") or {})}


def public_job(r, now):
    success, attempt = unix(r.get("last_success")), unix(r.get("last_attempt"))
    ok = r.get("last_error") is None and (attempt is None or (success is not None and success >= attempt))
    return {"name": r.get("name"), "last_success": iso(success), "last_attempt": iso(attempt),
            "last_error": r.get("last_error"), "duration_s": rounded(r.get("duration_s"), 2), "ok": ok,
            "age_s": None if success is None else int(now - success), "cursor": jsonable(r.get("cursor") or {})}


def _dt(t):
    return datetime.datetime.fromtimestamp(t, UTC)


def _section(db, name, fn, fallback):
    """One registry section of the overview: a failure (a table a migration has not made yet, a
    query error) leaves that section unavailable, not the whole page (logged, without rows)."""
    try:
        return fn()
    except Exception as e:  # noqa: BLE001
        log.warning("admin overview: %s failed (%s)", name, type(e).__name__)
        rollback = getattr(db, "rollback", None)
        if callable(rollback):
            try:
                rollback()          # a GET: nothing to keep; the next section gets a working transaction
            except Exception:  # noqa: BLE001
                pass
        return fallback


# --- the APs ------------------------------------------------------------------------------------

AP_QUERIES = {
    "info": live.AP_INFO,
    "clients": live.AP_CLIENTS,
    "radio_clients": 'sum by (name, radio) (unpoller_device_radio_stations{job="unifi"})',
    "radio_util": live.AP_RADIO_UTIL,
    "radio_channel": 'max by (name, radio) (unpoller_device_radio_channel{job="unifi"})',
    "uptime": 'max by (name) (unpoller_device_uptime_seconds{job="unifi",type="uap"})',
    "uplink": 'min by (name) (unpoller_device_uplink_speed_mbps{job="unifi"})',
    "signal": 'avg by (ap_name) (max by (ap_name, mac) (unpoller_client_radio_signal_db{job="unifi"}))',
    "weak": 'count by (ap_name) (max by (ap_name, mac) (unpoller_client_radio_signal_db{job="unifi"}) <= %d)' % WEAK_DBM,
}


def ap_status(client):
    """[AP] now, from unpoller (no incidents yet). One query per AP_QUERIES entry, plus the
    house SSID's clients per AP."""
    answers = {k: client.vector(q) for k, q in AP_QUERIES.items()}
    house = client.vector('count by (ap_name) (max by (ap_name, mac) (unpoller_client_uptime_seconds{job="unifi",'
                          'essid=%s}))' % promql_string(client.ssid or ""))
    aps = {}

    def ap(name):
        return aps.setdefault(name, dict(ap_info(name) or {"name": name}, mac=None, ip=None, model=None, state="unknown",
                                         clients=None, clients_house=0, weak_clients=0, signal_avg_dbm=None,
                                         uptime_s=None, uplink_mbps=None, radios={}, open_incidents=[]))
    for labels, _v in answers["info"]:
        if labels.get("name"):
            a = ap(labels["name"])
            a.update(mac=normalise_mac(labels.get("mac")), ip=labels.get("ip"), model=labels.get("model"), state="ok")
    for key, field, cast in (("clients", "clients", int), ("uptime", "uptime_s", int), ("uplink", "uplink_mbps", int)):
        for labels, value in answers[key]:
            if labels.get("name") and value is not None:
                ap(labels["name"])[field] = cast(value)
    for key, field in (("signal", "signal_avg_dbm"), ("weak", "weak_clients")):
        for labels, value in answers[key]:
            if labels.get("ap_name") and value is not None:
                ap(labels["ap_name"])[field] = round(value, 1) if field == "signal_avg_dbm" else int(value)
    for labels, value in house:
        if labels.get("ap_name") and value is not None:
            ap(labels["ap_name"])["clients_house"] = int(value)
    for key, field in (("radio_clients", "clients"), ("radio_util", "channel_util"), ("radio_channel", "channel")):
        for labels, value in answers[key]:
            name, radio = labels.get("name"), labels.get("radio")
            if name and radio:
                r = ap(name)["radios"].setdefault(radio, {"radio": radio, "band": BANDS.get(radio), "channel": None,
                                                          "clients": None, "channel_util": None})
                r[field] = None if value is None else (round(value, 3) if field == "channel_util" else int(value))
    out = []
    for a in aps.values():
        a["radios"] = sorted(a["radios"].values(), key=lambda r: r["radio"])
        out.append(a)
    return sorted(out, key=lambda a: (a.get("house") or "~", a.get("floor") if a.get("floor") is not None else 99,
                                      a["name"]))


def _with_incidents(aps, open_incidents, now):
    by_subject = {}
    for r in open_incidents:
        if (r.get("kind") or "").startswith("ap_"):
            by_subject.setdefault((r.get("subject") or "").lower(), []).append(r)
            by_subject.setdefault("name:" + (r.get("subject_name") or "").lower(), []).append(r)
    for a in aps:
        rows = by_subject.get((a.get("mac") or "").lower(), []) or by_subject.get("name:" + a["name"].lower(), [])
        a["open_incidents"] = [public_incident(r, now) for r in rows]
        if any(r.get("kind") == "ap_down" for r in rows):
            a["state"] = "down"
    return [with_warnings(a) for a in aps]


def with_warnings(a):
    details = diagnostics.ap_warnings(a)
    a["warnings"], a["warning_details"] = [w["code"] for w in details], details
    return a


# --- overview ---------------------------------------------------------------------------------

def overview(client, db, now=None):
    """OVERVIEW (see the module's docstring)."""
    now = time.time() if now is None else now
    telemetry, house, aps = ("off" if client is None else "ok"), empty_house(), []
    if client is not None:
        budget = client.within()
        try:
            house = house_status(budget)
            aps = ap_status(budget)
        except Unavailable:
            telemetry, house, aps = "unavailable", empty_house(), []
    incidents = _section(db, "incidents", lambda: _incidents_summary(db, now), {"available": False, "open": [],
                                                                               "recent": [], "counts_7d": {}})
    aps = _with_incidents(aps, [r for r in incidents.pop("_open_rows", [])], now)
    shown = incidents.pop("_shown_rows", [])
    if shown:
        _section(db, "incident devices", lambda: attach_devices(
            incidents["open"] + incidents["recent"], shown, db, now, live.ap_map(client.within()) if client else None),
            None)
    auth = _section(db, "auth", lambda: _auth_summary(db, now), {"available": False, "since": iso(now - 86400),
                                                                 "count": 0, "truncated": False, "by_reason": {},
                                                                 "devices": 0, "macs": 0, "recent": []})
    jobs = _section(db, "jobs", lambda: [public_job(r, now) for r in registry.job_status(db)], None)
    jobs_available, jobs = jobs is not None, jobs or []
    successes = [j["age_s"] for j in jobs if j["age_s"] is not None]
    return {"generated_at": iso(now), "telemetry": telemetry,
            "stale": telemetry == "ok" and diagnostics.is_stale(house["wifi_data_age_s"]), "house": house,
            "incidents": incidents, "aps": aps, "auth": auth, "jobs": jobs, "jobs_available": jobs_available,
            "freshness": {"wifi_data_age_s": house["wifi_data_age_s"], "prometheus": telemetry,
                          "jobs_ok": all(j["ok"] for j in jobs) if jobs else None,
                          "oldest_job_success_age_s": max(successes) if successes else None}}


def _incidents_summary(db, now):
    rows = registry.incidents(db, _dt(now - RECENT_INCIDENTS_S), _dt(now))
    open_rows = [r for r in rows if r.get("ended") is None]
    recent = sorted((r for r in rows if r.get("ended") is not None), key=lambda r: unix(r["started"]), reverse=True)
    counts = {}
    for r in rows:
        counts[r["kind"]] = counts.get(r["kind"], 0) + 1
    open_sorted = sorted(open_rows, key=lambda r: unix(r["started"]), reverse=True)
    recent = recent[:RECENT_INCIDENTS_MAX]
    return {"available": True, "open": [public_incident(r, now) for r in open_sorted],
            "recent": [public_incident(r, now) for r in recent], "counts_7d": counts,
            "_open_rows": open_rows, "_shown_rows": open_sorted + recent}


def _auth_summary(db, now):
    rows = registry.auth_failures(db, _dt(now - 86400), _dt(now), limit=AUTH_LIMIT)
    events = public_failures(rows, registry.people(db), {})
    return {"available": True, "since": iso(now - 86400), "count": tries(rows), "truncated": len(rows) >= AUTH_LIMIT,
            "by_reason": by_reason(rows), "devices": len({str(r["device_id"]) for r in rows if r.get("device_id")}),
            "macs": len({str(r["mac"]) for r in rows if r.get("mac")}), "recent": events[:AUTH_RECENT]}


def tries(rows):
    """The rejects these rows stand for: a row of repeated tries counts its "count"."""
    return sum(int(r.get("count") or 1) for r in rows)


def by_reason(rows):
    counts = {}
    for r in rows:
        counts[r.get("reason") or "other"] = counts.get(r.get("reason") or "other", 0) + int(r.get("count") or 1)
    return counts


def public_failures(rows, people, names, aps=None):
    """AUTH_FAILURE rows, newest first. people: registry.people; names: {device id: name}."""
    out = []
    for r in sorted(rows, key=lambda r: unix(r["at"]), reverse=True):
        owner = people.get(r.get("owner")) if r.get("owner") else None
        bssid = normalise_mac(str(r["bssid"])) if r.get("bssid") else None
        ap = None
        if aps is not None:
            name, ap_mac, _band = aps.by_bssid(bssid, r.get("nas_ip"))
            ap = ap_ref(name, ap_mac)
        out.append({"at": iso(r["at"]), "reason": r.get("reason"), "serial": r.get("serial"),
                    "device_id": None if r.get("device_id") is None else str(r["device_id"]),
                    "device_name": (r.get("device_name") or names.get(str(r.get("device_id"))))
                    if r.get("device_id") else None,
                    "owner": {"username": owner.get("username"), "display": owner.get("display")} if owner else None,
                    "mac": normalise_mac(str(r["mac"])) if r.get("mac") else None, "bssid": bssid,
                    "ssid": r.get("ssid"), "nas_ip": None if r.get("nas_ip") is None else str(r["nas_ip"]), "ap": ap,
                    "count": int(r.get("count") or 1), "last_at": iso(r.get("last_at"))})
    return out


# --- the other admin endpoints ------------------------------------------------------------------

def aps(client, db, now=None):
    """APS: the APs now (Prometheus, one budget) with their open incidents and 7 days of ap_day."""
    now = time.time() if now is None else now
    telemetry, items = ("off" if client is None else "ok"), []
    if client is not None:
        try:
            items = ap_status(client.within())
        except Unavailable:
            telemetry = "unavailable"
    open_rows = [r for r in registry.incidents(db, _dt(now - RECENT_INCIDENTS_S), _dt(now)) if r.get("ended") is None]
    items = _with_incidents(items, open_rows, now)
    today = datetime.datetime.fromtimestamp(now, UTC).date()
    days = registry.ap_days(db, today - datetime.timedelta(days=AP_DAYS - 1), today)
    by_ap = {}
    for d in days:
        by_ap.setdefault(normalise_mac(str(d["ap_mac"])), []).append(jsonable(d))
    known = {a["mac"] for a in items if a.get("mac")}
    for mac, rows in by_ap.items():              # APs that unpoller does not list now
        if mac not in known:
            name = rows[-1].get("ap_name") or mac
            items.append(dict(ap_info(name) or {"name": name}, mac=mac, ip=None, model=None, state="unknown",
                              clients=None, clients_house=None, weak_clients=None, signal_avg_dbm=None,
                              uptime_s=None, uplink_mbps=None, radios=[], open_incidents=[]))
    for a in items:
        a["days"] = sorted(by_ap.get(a.get("mac"), []), key=lambda d: d.get("day") or "")
        with_warnings(a)
    return {"generated_at": iso(now), "telemetry": telemetry, "aps": items}


def incidents(db, since, until, kind=None, now=None, client=None):
    """INCIDENTS between since and until (Unix), newest first, at most INCIDENT_LIMIT, with the
    devices that dropped out (client: the page's Prometheus budget, to place accounting rows at
    their AP by BSSID or NAS address; None: AP incidents match UniFi events only)."""
    now = time.time() if now is None else now
    rows = registry.incidents(db, _dt(since), _dt(until), kinds=[kind] if kind else None)
    rows = sorted(rows, key=lambda r: unix(r["started"]), reverse=True)[:INCIDENT_LIMIT + 1]
    counts = {}
    for r in rows:
        counts[r["kind"]] = counts.get(r["kind"], 0) + 1
    shown = rows[:INCIDENT_LIMIT]
    public = [public_incident(r, now) for r in shown]
    attach_devices(public, shown, db, now, live.ap_map(client.within()) if client else None)
    return {"from": iso(since), "to": iso(until), "kind": kind, "incidents": public,
            "truncated": len(rows) > INCIDENT_LIMIT, "counts": counts}


def incident_window(r, now):
    """(from, to) Unix in which a device's drop-out counts for the incident."""
    started = unix(r["started"])
    end = unix(r["ended"]) if r.get("ended") is not None else now
    end = min(end, started + diagnostics.INCIDENT_SPAN_MAX_S)
    return started - diagnostics.INCIDENT_MARGIN_S, end + diagnostics.INCIDENT_MARGIN_S


def dropouts(db, since, until, aps=None):
    """[{"at", "device", "ap_mac", "ap"}]: every active device's drop-outs in [since, until]
    (UniFi disconnects, accounting Stops and reconnects: timeline.DISCONNECT_KINDS), two
    registry queries per device. (A house-wide registry query would make this one.)"""
    s, u = _dt(since), _dt(until)
    out = []
    for d in registry.devices(db, include_revoked=False):
        events = (tl.from_unifi(registry.connection_events(db, d["id"], s, u, limit=DROPOUT_LIMITS["unifi"]), aps)
                  + tl.from_acct(registry.acct_sessions(db, d["id"], s, u, limit=DROPOUT_LIMITS["acct"]), aps))
        out += [{"at": e["at"], "device": d, "ap_mac": e["ap_mac"], "ap": e["ap"]} for e in events
                if e["kind"] in tl.DISCONNECT_KINDS and since <= e["at"] <= until]
    return out


def _concerns(r, drop):
    """A drop-out concerns the incident: house-wide kinds all, an AP's its own clients."""
    kind = r.get("kind") or ""
    subject, name = (r.get("subject") or "").lower(), (r.get("subject_name") or "").lower()
    if kind.startswith("ap_"):
        return bool((drop["ap_mac"] and drop["ap_mac"] == subject) or (name and drop["ap"] and drop["ap"].lower() == name))
    if kind.startswith("switch"):
        return drop["ap_mac"] in {normalise_mac(str(m)) for m in (r.get("detail") or {}).get("ap_macs") or ()}
    return not subject


def attach_devices(public, rows, db, now, aps=None):
    """INCIDENT["devices"] (in place) for the incidents of the newest DEVICES_SPAN_S (at most
    DEVICES_INCIDENTS of them); the older ones get None (not computed)."""
    if not rows:
        return
    windows = [incident_window(r, now) for r in rows]
    newest = max(w[1] for w in windows)
    chosen = [i for i, w in enumerate(windows) if w[1] >= newest - DEVICES_SPAN_S][:DEVICES_INCIDENTS]
    for pub in public:
        pub.update(devices=None, devices_truncated=False, devices_basis="inferred")
    if not chosen:
        return
    drops = dropouts(db, min(windows[i][0] for i in chosen), max(windows[i][1] for i in chosen), aps)
    people = registry.people(db)
    for i in chosen:
        a, b = windows[i]
        found = {}
        for x in drops:
            if a <= x["at"] <= b and _concerns(rows[i], x):
                found.setdefault(str(x["device"]["id"]), x["device"])
        devices = []
        for dev_id, d in sorted(found.items(), key=lambda kv: (kv[1].get("name") or "", kv[0])):
            owner = people.get(d.get("owner")) or {}
            devices.append({"id": dev_id, "name": d.get("name"),
                            "owner": {"username": owner.get("username"), "display": owner.get("display")}})
        public[i]["devices"] = devices[:INCIDENT_DEVICES_MAX]
        public[i]["devices_truncated"] = len(devices) > INCIDENT_DEVICES_MAX


def auth(db, since, until, limit=AUTH_LIMIT, client=None):
    """AUTH: the RADIUS rejects between since and until (Unix), newest first."""
    rows = registry.auth_failures(db, _dt(since), _dt(until), limit=limit)
    # registry.auth_failures names the device; older rows without it: the registry's list
    names = ({str(d["id"]): d["name"] for d in registry.devices(db, include_revoked=True)}
             if any(r.get("device_id") and not r.get("device_name") for r in rows) else {})
    aps = live.ap_map(client) if client is not None else None
    return {"from": iso(since), "to": iso(until), "result": "reject",
            "events": public_failures(rows, registry.people(db), names, aps), "truncated": len(rows) >= limit,
            "by_reason": by_reason(rows)}


def raw(db, row, identity, since, until, people=None):
    """RAW: every source row of one device in [since, until] (Unix), bounded per source."""
    people = people or {}
    owner = people.get(row.get("owner")) or {}
    s, u = _dt(since), _dt(until)
    auth_rows = registry.auth_events(db, row["id"], s, u, limit=RAW_LIMITS["auth"])
    acct_rows = registry.acct_sessions(db, row["id"], s, u, limit=RAW_LIMITS["acct"])
    event_rows = registry.connection_events(db, row["id"], s, u, limit=RAW_LIMITS["events"])
    first_day = datetime.datetime.fromtimestamp(since, UTC).date()
    last_day = datetime.datetime.fromtimestamp(until, UTC).date()
    days = registry.device_days(db, row["id"], first_day, last_day)
    windows = [{"mac": w["mac"], "first_seen": iso(w["first_seen"]), "last_seen": iso(w["last_seen"]),
                "randomized": w["randomized"], "auth_count": w["auth_count"], "current": w["current"],
                "start": iso(w["start"]) if w["start"] != float("-inf") else None,
                "end": iso(w["end"])} for w in identity.windows]
    return {"device": {"id": str(row["id"]), "name": row.get("name"), "revoked": bool(row.get("revoked")),
                       "owner": {"username": owner.get("username"), "display": owner.get("display")}},
            "from": iso(since), "to": iso(until), "windows": windows, "conflicts": identity.public_conflicts(),
            "auth": jsonable(auth_rows), "acct": jsonable(acct_rows), "events": jsonable(event_rows),
            "days": jsonable(days), "incidents": [public_incident(r) for r in registry.incidents(db, s, u)],
            "limits": dict(RAW_LIMITS),
            "truncated": {"auth": len(auth_rows) >= RAW_LIMITS["auth"], "acct": len(acct_rows) >= RAW_LIMITS["acct"],
                          "events": len(event_rows) >= RAW_LIMITS["events"]}}


__all__ = ["overview", "aps", "incidents", "auth", "raw", "jsonable", "ap_status", "SUMMARY_CACHE_SECONDS"]
