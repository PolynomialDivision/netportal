"""The detail page's history: charts and the connection timeline of one device.

Ranges (RANGES): 24h, 7d, 30d, 90d from Prometheus (step_s 300, 1800, 7200, 21600), stitched
over the device's MAC windows; 1y and all from the nightly rollups (registry.device_days, step
"day"). Every Prometheus client query is one `by (mac)` query for all the device's MACs of the
range (each a normalised MAC in the matcher, the house SSID on every client selector); a
sample counts only inside the window of its MAC (identity.Identity.segments: minus what is
withheld from a resident). A chart point (t - step, t] counts when it holds fresh Wi-Fi data
(unpoller's snapshot age <= STALE_AFTER_S) and lies, at least in part, in one of the MAC's
windows (a point that straddles a window's start averages up to one step of before: 5 minutes
at 24 h, 6 hours at 90 days, of a MAC that was nobody's or another owner's before the registry's
grace; windows of different owners that overlap are conflicts and withheld whole).

Payload (HISTORY): {"range", "step_s", "step": None | "day", "start", "end" (Unix), "telemetry":
ok|unavailable|off, "data_from" (Unix: the first window's start), "withheld": None |
"mac_conflict", "withheld_spans": [{"mac", "from", "to"}] (resident) or "conflicts": [{"mac",
"other_owners", "from", "to"}] (admin), "series": {name: [[t, value|null]]} (day ranges add
"signal_p10_dbm"), "timeline": [EVENT], "timeline_truncated", "timeline_days": None | days the
timeline covers when that is less than the charts (1y/all: the events' retention, or the
oldest event kept after truncation), "sources": [source with data]}.
"""

import datetime
import time
import zoneinfo

from .. import diagnostics, registry
from . import timeline as tl
from .client import LONG_CACHE_SECONDS, SUMMARY_CACHE_SECONDS, Unavailable
from .common import UTC, fit, iso, selectors, unix
from .identity import Identity, data_bound

STALE_AFTER_S = diagnostics.STALE_AFTER_S
CACHE_AGE = 'max(unpoller_prometheus_cache_age_seconds{job="unifi"})'

# range -> (seconds, chart step, timeline resolution). The timeline reads the association start
# at the resolution (one point per scrape for 24 h and 7 d); the charts average per step.
RANGES = {"24h": (86400, 300, 60), "7d": (7 * 86400, 1800, 60), "30d": (30 * 86400, 7200, 120),
          "90d": (90 * 86400, 21600, 300)}
# From the rollups: range -> days (None: since the first window, at most ALL_MAX_DAYS).
DAY_RANGES = {"1y": 365, "all": None}
ALL_MAX_DAYS = 3660
HISTORY_RANGES = tuple(RANGES) + tuple(DAY_RANGES)

CHARTS = {
    "signal_dbm": ('avg by (mac) (avg_over_time(unpoller_client_radio_signal_db{{job="unifi",{sel}}}[{step}s]))', 1),
    "health": ('avg by (mac) (avg_over_time(wifi_client_health_score{{{sel}}}[{step}s]))', 1),
    "rx_bps": (('sum by (mac) (rate(unpoller_client_transmit_bytes_total{{job="unifi",{mac}}}[{step}s]) '
               'and on (mac) max_over_time({u}[{step}s])) * 8'), "int"),
    "tx_bps": (('sum by (mac) (rate(unpoller_client_receive_bytes_total{{job="unifi",{mac}}}[{step}s]) '
               'and on (mac) max_over_time({u}[{step}s])) * 8'), "int"),
    "link_rx_bps": ('avg by (mac) (avg_over_time(unpoller_client_radio_transmit_rate_bps{{job="unifi",{sel}}}[{step}s]))',
                    "int"),
    "link_tx_bps": ('avg by (mac) (avg_over_time(unpoller_client_radio_receive_rate_bps{{job="unifi",{sel}}}[{step}s]))',
                    "int"),
    "snr_db": ('avg by (mac) (avg_over_time(wifi_client_snr_db{{{sel}}}[{step}s]))', 1),
    # the rule has no essid: only while the house network's uptime series is there
    "retry_ratio": ('avg by (mac) (avg_over_time(wifi_client_retry_ratio{{{mac}}}[{step}s])) '
                    'and on (mac) max by (mac) (max_over_time({u}[{step}s]))', 4),
}
# rates add up over MACs at one time (there is one at a time, rarely two during a change)
SUMMED = {"rx_bps", "tx_bps"}
SERIES = tuple(CHARTS) + ("online",)
# the rollup's columns per series (None: not in device_day)
DAY_SERIES = {"signal_dbm": "signal_avg_dbm", "health": "health_avg", "rx_bps": "rx_bytes", "tx_bps": "tx_bytes",
              "link_rx_bps": "link_rx_avg_bps", "link_tx_bps": None, "snr_db": "snr_avg_db",
              "retry_ratio": "retry_ratio_avg"}
# registry limits per source and range (the timeline is bounded, and cut to MAX_EVENTS after the merge)
EVENT_LIMITS = {"auth": 1000, "acct": 1000, "unifi": 2000}
# The registry keeps RADIUS, accounting and UniFi events this long (TELEMETRY.md, prune).
EVENT_RETENTION_DAYS = 400
# Day ranges only: the 10th percentile of the day's signal (device_day.signal_p10_dbm).
DAY_ONLY_SERIES = {"signal_p10_dbm": ("signal_p10_dbm", 1)}

TIMEZONE = "Europe/Berlin"


def zone(name=None):
    """The house's time zone for day boundaries (UTC if the image has no zone data)."""
    try:
        return zoneinfo.ZoneInfo(name or TIMEZONE)
    except (zoneinfo.ZoneInfoNotFoundError, ValueError):
        return UTC


def ttl_for(range_key):
    return {"24h": 15, "7d": SUMMARY_CACHE_SECONDS}.get(range_key, LONG_CACHE_SECONDS)


def empty_history(range_key, telemetry, now=None, since=None, withheld=None):
    now = time.time() if now is None else now
    end = int(now // 60 * 60)
    if range_key in RANGES:
        seconds, step, _res = RANGES[range_key]
        start, step_s, step_kind = end - seconds, step, None
    else:
        days = DAY_RANGES[range_key] or 1
        start, step_s, step_kind = end - days * 86400, 86400, "day"
    return {"range": range_key, "step_s": step_s, "step": step_kind, "start": start, "end": end,
            "telemetry": telemetry, "data_from": None if since is None else int(since), "withheld": withheld,
            "withheld_spans": [], "conflicts": [], "series": {name: [] for name in SERIES}, "timeline": [],
            "timeline_truncated": False, "timeline_days": None, "sources": []}


def _grid(start, end, step):
    return list(range(start, end + 1, step))


def history(client, mac, range_key, now=None, since=None, withheld=None, db=None, row=None, admin=False,
            identity=None, ap_map=None, tz=None):
    """The detail page's charts and connection timeline for one device.

    v1 call (no db): mac is its latest login's MAC, since its data bound, withheld
    "mac_conflict" asks nothing. With db and the registry row: the device's windows and conflicts
    (identity.from_registry, or `identity` when the caller has it), the registry's RADIUS,
    accounting and UniFi events, the incidents and (1y, all) the rollups. client None: telemetry
    "off" (the registry's events still come). Raises ValueError for an unknown range or a MAC
    that is not normalised."""
    if range_key not in HISTORY_RANGES:
        raise ValueError("unknown range")
    now = time.time() if now is None else now
    if db is None or row is None:
        if mac is not None:
            selectors("", [mac])                         # refuses anything but a normalised MAC
        if client is None or mac is None or withheld:
            return empty_history(range_key, "off" if client is None else "ok", now, since, withheld)
        identity = Identity("", [{"mac": mac, "start": since if since is not None else float("-inf"), "end": None,
                                  "first_seen": since, "last_seen": None, "randomized": False, "auth_count": None,
                                  "current": True}], [], admin, now)
    elif identity is None:
        from .identity import from_registry
        identity = from_registry(db, [row], now, admin)[str(row["id"])]
    data_from = identity.data_from
    if data_from is None and db is not None and row is not None and mac is None:
        data_from = data_bound(row)
    payload = empty_history(range_key, "off" if client is None else "ok", now, data_from)
    if not identity.admin and identity.windows and not identity.segments():
        payload["withheld"] = "mac_conflict"             # all of it is in a conflict: nothing at all
        return payload
    payload["conflicts" if identity.admin else "withheld_spans"] = identity.public_conflicts()
    events = []
    if range_key in RANGES:
        if client is not None:
            try:
                events += _prometheus(client, identity, range_key, payload)
            except Unavailable:
                fresh = empty_history(range_key, "unavailable", now, data_from)
                payload.update(telemetry="unavailable", series=fresh["series"])
        else:
            payload["series"] = {name: [] for name in SERIES}
    else:
        _days(db, row, identity, range_key, payload, tz or zone())
    if db is not None and row is not None:
        seen = {e["ap"].lower() for e in events if e["ap"]}
        if ap_map is None and client is not None and payload["telemetry"] == "ok":
            from .live import ap_map as current_aps      # (live imports this module)
            ap_map = current_aps(client.within())
        events += _registry_events(db, row, payload["start"], now, ap_map, payload, seen)
        events += tl.from_windows(identity, payload["start"], now)
    merged, truncated = tl.merge(tl.restrict(events, identity))
    payload["timeline"] = tl.public(merged)
    payload["timeline_truncated"] = payload["timeline_truncated"] or truncated
    if range_key in DAY_RANGES:
        payload["timeline_days"] = timeline_days(payload, merged, now)
    payload["sources"] = sorted(set(payload["sources"]) | {e["source"] for e in merged})
    return payload


def _prometheus(client, identity, range_key, payload):
    """Charts and presence events from Prometheus for the MACs whose windows meet the range."""
    seconds, step, res = RANGES[range_key]
    start, end = payload["start"], payload["end"]
    segments = identity.segments(start - step, end)
    macs = sorted({s["mac"] for s in segments})
    grid = _grid(start, end, step)
    if not macs:
        payload["series"] = {name: [[t, None] for t in grid] for name in SERIES}
        return []
    parts = selectors(client.ssid, macs)
    client = client.within()
    ttl = ttl_for(range_key)
    span = "[%ds:%ds]" % (seconds + step, res)
    ages = client.matrix(CACHE_AGE + span, at=end, ttl=ttl)
    assoc = client.matrix('(max by (mac, ap_name, radio) (timestamp({u}) - {u}) - on() group_left() ({age} or '
                          'vector(0))){span}'.format(u=parts["u"], age=CACHE_AGE, span=span), at=end, ttl=ttl)
    charts = {name: client.range(promql.format(step=step, **parts), start, end, step, ttl=ttl)
              for name, (promql, _digits) in CHARTS.items()}
    fresh = {t for t, age in (ages[0][1] if ages else []) if age is not None and age <= STALE_AFTER_S}
    by_mac = {}
    for s in segments:
        by_mac.setdefault(s["mac"], []).append((s["start"], s["end"]))
    mine = lambda m, t: any(a <= t <= b for a, b in by_mac.get(m, ()))           # noqa: E731
    overlaps = lambda m, t: any(a <= t and b > t - step for a, b in by_mac.get(m, ()))   # noqa: E731
    fresh_own = {t for t in fresh if any(mine(m, t) for m in macs)}
    by_t = {}
    for labels, values in assoc:
        m = labels.get("mac")
        for t, assoc_start in values:
            if t in fresh and assoc_start is not None and mine(m, t):
                by_t.setdefault(t, []).append((assoc_start, labels.get("ap_name"), labels.get("radio"), m))
    points = [(t, *max(v, key=lambda x: x[0])) for t, v in sorted(by_t.items())]   # the newest association
    first = min((s["start"] for s in segments), default=None)
    events, spans = tl.derive_timeline(points, res, max(fresh_own) if fresh_own else None, first)
    # a chart point (t - step, t] counts when it holds fresh data and meets one of the windows
    fresh_k = {-(-(f - start) // step) for f in fresh}
    fresh_window = {t: (t - start) // step in fresh_k for t in grid}
    own = {t: any(overlaps(m, t) for m in macs) for t in grid}
    for name, (_promql, digits) in CHARTS.items():
        values = {}
        for labels, pts in charts[name]:
            m = labels.get("mac")
            for t, v in pts:
                if v is not None and overlaps(m, t):
                    values.setdefault(t, []).append(v)
        payload["series"][name] = [[t, _combine(name, values.get(t), digits) if fresh_window[t] and own[t] else None]
                                   for t in grid]
    payload["series"]["online"] = [
        [t, (1 if any(a <= t and last > t - step for a, last in spans) else 0) if fresh_window[t] and own[t] else None]
        for t in grid]
    if fresh_own:
        payload["sources"].append("prometheus")
    return tl.from_presence(events)


def _combine(name, values, digits):
    if not values:
        return None
    return fit(sum(values) if name in SUMMED else sum(values) / len(values), digits)


# --- the rollups (1y, all) --------------------------------------------------------------------

def _days(db, row, identity, range_key, payload, tz):
    """Series from device_day, one point per day (the day's start in the house's zone)."""
    today = datetime.datetime.fromtimestamp(payload["end"], tz).date()
    days = DAY_RANGES[range_key]
    if days is None:
        first = identity.data_from or unix(row.get("created")) or payload["end"]
        first_day = datetime.datetime.fromtimestamp(first, tz).date()
        days = min(ALL_MAX_DAYS, (today - first_day).days + 1)
    first_day = today - datetime.timedelta(days=days - 1)
    rows = {r["day"]: r for r in registry.device_days(db, row["id"], first_day, today)} if db is not None else {}
    withheld = identity.withheld_spans()
    series = {name: [] for name in SERIES}
    for i in range(days):
        day = first_day + datetime.timedelta(days=i)
        t0 = int(datetime.datetime.combine(day, datetime.time(), tz).timestamp())
        t1 = int(datetime.datetime.combine(day + datetime.timedelta(days=1), datetime.time(), tz).timestamp())
        r = rows.get(day)
        if r is not None and any((f is None or f < t1) and t >= t0 for _mac, f, t in withheld):
            r = None                                  # a resident sees no day with a conflict in it
        for name, (column, digits) in DAY_ONLY_SERIES.items():
            value = None if r is None else r.get(column)
            series.setdefault(name, []).append([t0, None if value is None else fit(value, digits)])
        for name, column in DAY_SERIES.items():
            value = None if r is None or column is None else r.get(column)
            if value is not None and name in ("rx_bps", "tx_bps"):
                value = value * 8 / (t1 - t0)         # the day's average rate
            series[name].append([t0, None if value is None else fit(value, CHARTS[name][1])])
        online = None
        if r is not None and r.get("online_s") is not None:
            known = (t1 - t0) - (r.get("stale_s") or 0)
            online = round(min(1.0, r["online_s"] / known), 3) if known > 0 else None
        series["online"].append([t0, online])
    payload["series"], payload["start"] = series, series["online"][0][0] if days else payload["start"]
    if rows:
        payload["sources"].append("device_day")


def timeline_days(payload, merged, now):
    """How many days the timeline covers, when less than the charts: from the events' retention
    or, when it was cut, from its oldest event on; None when it covers all of the range."""
    start = max(payload["start"], now - EVENT_RETENTION_DAYS * 86400)
    if payload["timeline_truncated"] and merged:
        start = max(start, merged[0]["at"])
    if start <= payload["start"]:
        return None
    return max(1, -(-int(now - start) // 86400))


# --- the registry's events --------------------------------------------------------------------

def _registry_events(db, row, start, end, ap_map, payload, ap_names=()):
    """RADIUS logins and rejects, accounting sessions, UniFi events and the incidents of the
    device's APs and of the house, each bounded (EVENT_LIMITS)."""
    since, until = _dt(start), _dt(end)
    device_id = row["id"]
    auth = registry.auth_events(db, device_id, since, until, limit=EVENT_LIMITS["auth"])
    acct = registry.acct_sessions(db, device_id, since, until, limit=EVENT_LIMITS["acct"])
    unifi = registry.connection_events(db, device_id, since, until, limit=EVENT_LIMITS["unifi"])
    truncated = (len(auth) >= EVENT_LIMITS["auth"] or len(acct) >= EVENT_LIMITS["acct"]
                 or len(unifi) >= EVENT_LIMITS["unifi"])
    events = tl.from_auth(auth, ap_map) + tl.from_acct(acct, ap_map) + tl.from_unifi(unifi, ap_map)
    payload["sources"] += [name for name, rows in (("radius_auth", auth), ("radius_acct", acct),
                                                   ("unifi_syslog", unifi)) if rows]
    aps = {e["ap_mac"] for e in events if e["ap_mac"]}
    names = {e["ap"].lower() for e in events if e["ap"]} | set(ap_names)
    incidents = relevant_incidents(registry.incidents(db, since, until), aps, names)
    events += tl.from_incidents(incidents)
    if truncated:
        payload["timeline_truncated"] = True
    return events


HOUSE_INCIDENTS = ("internet_down", "internet_degraded", "router_down", "dns_down", "unifi_data_stale", "radius_down")


def relevant_incidents(rows, ap_macs, ap_names):
    """The incidents that concern a device: the house-wide ones and those of the APs it used
    (by MAC, or by name for rows without one); a switch's when its detail lists one of them."""
    out = []
    for r in rows:
        kind, subject = r.get("kind"), (r.get("subject") or "").lower()
        name = (r.get("subject_name") or "").lower()
        if kind in HOUSE_INCIDENTS and not subject:
            out.append(r)
        elif kind and kind.startswith("ap_") and (subject in ap_macs or (name and name in ap_names)):
            out.append(r)
        elif kind and kind.startswith("switch") and set((r.get("detail") or {}).get("ap_macs") or ()) & ap_macs:
            out.append(r)
    return out


def _dt(t):
    return datetime.datetime.fromtimestamp(t, UTC)


__all__ = ["RANGES", "DAY_RANGES", "HISTORY_RANGES", "CHARTS", "SERIES", "empty_history", "history", "iso",
           "relevant_incidents", "zone"]
