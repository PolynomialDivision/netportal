"""Job rollup: Prometheus -> device_day and ap_day (local days, NETPORTAL_TIMEZONE).

Every run (re)computes today (so far) and yesterday, then fills up to BACKFILL_DAYS_PER_RUN
missing older days, newest first, back to the Prometheus horizon (its lowest timestamp, at most
MAX_HISTORY_DAYS). Upserts per (device, day) and (AP MAC, day): rerunning a day replaces it.

Per device and day, from per-minute range queries (step 60 s) over [local midnight, next local
midnight), only minutes that are
- fresh: unpoller's snapshot at most STALE_AFTER_S old (stale minutes count as stale_s, never as
  online or in an average: a frozen snapshot shows clients that may have left);
- the house network's: every client selector has essid = NETPORTAL_SSID (byte counters and the
  retry ratio carry no essid and count only "and on (mac)" the house network's uptime series);
- the device's: the minute is inside exactly one device's window for that MAC ([first_seen,
  window_end] from registry.device_windows: the one window rule of the view device_mac_window,
  the same the pages use, so the current window reaches up to 12 h 15 min past the last login,
  capped at now); minutes in the windows of two devices belong to neither (a conflict, or a
  hand-over between an old and a new enrolment).
Values (TELEMETRY.md device_day): online_s and stale_s; averages over the online minutes
(signal also its 10th percentile); rx/tx bytes in the device's view (rx = what the AP transmits),
as rate()*60 per online minute summed (an approximation at the 60 s scrape); roams = AP changes
within one association, reconnects = new associations (association start = snapshot time -
uptime, as telemetry); aps {ap_mac: s} by the AP's MAC (unpoller_device_info maps the name at
that minute: APs were renamed); bands {"2.4"|"5"|"6": s}; macs = the device's MACs with a window
that day; auth_ok / auth_failed from radius_auth (a row of repeated rejects counts its tries); disconnects from connection_event (None when
the device has no event that day: unknown, not 0). A device gets a row for every day one of its
windows (or a RADIUS decision) touches, even with nothing online.

Per AP and day (only APs with data that day): name (the latest that day), clients avg/max
(unpoller_device_radio_stations, all networks), channel_util_avg {radio: ratio}, the share of
client-minutes below WEAK_DBM (all networks: it is about coverage), restarts (uptime resets) and
down_s (the incidents job's ap_down rule per minute, counted from the AP's first data that day).
Both use house-infra's records unifi_ap:up / unifi_ap:uptime:seconds where they exist (from the
2026-10-25 monitoring deploy) and the raw unpoller_device_* series otherwise, so older days
backfill the same way. Checked read-only against the live Prometheus for 2026-10-24: the 17 AP
restarts of that day (sum of resets()) come out the same.
"""

import datetime
import logging
import math

from .. import registry
from . import incidents
from .days import bounds, local_day
from .sources import mac_matcher, normalise_mac, promql_string

log = logging.getLogger("netportal.collect.rollup")

STEP = 60
CHUNK = 40                         # MACs per query
BACKFILL_DAYS_PER_RUN = 2
MAX_HISTORY_DAYS = 400
STALE_AFTER_S = incidents.STALE_AFTER_S
SAME_ASSOCIATION_S = 120
WEAK_DBM = -75
BANDS = {"ng": "2.4", "na": "5", "6e": "6"}
GRACE = getattr(registry, "WINDOW_GRACE", datetime.timedelta(minutes=15))

HORIZON = 'min(prometheus_tsdb_lowest_timestamp_seconds)'
AGE = 'max(unpoller_prometheus_cache_age_seconds{job="unifi"})'

# per chunk of MACs: {u} the house network's uptime series of these MACs, {sel} essid + mac
DEVICE_QUERIES = {
    "presence": 'min by (mac, ap_name, radio) ({u})',
    "signal": 'avg by (mac) (unpoller_client_radio_signal_db{{job="unifi",{sel}}})',
    "snr": 'avg by (mac) (wifi_client_snr_db{{{sel}}})',
    "health": 'min by (mac) (wifi_client_health_score{{{sel}}})',
    "retry": 'max by (mac) (wifi_client_retry_ratio{{{mac}}} and on (mac) {u})',
    "rx": 'sum by (mac) (rate(unpoller_client_transmit_bytes_total{{job="unifi",{mac}}}[3m]) and on (mac) {u}) * 60',
    "tx": 'sum by (mac) (rate(unpoller_client_receive_bytes_total{{job="unifi",{mac}}}[3m]) and on (mac) {u}) * 60',
    "link_rx": 'avg by (mac) (unpoller_client_radio_transmit_rate_bps{{job="unifi",{sel}}})',
}
AP_QUERIES = {
    "stations": 'sum by (mac) (unpoller_device_radio_stations{job="unifi"})',
    "util": 'max by (mac, radio) (unpoller_device_radio_channel_utilization_total_ratio{job="unifi"})',
    "weak": 'count by (ap_name) (unpoller_client_radio_signal_db{job="unifi"} < %d)' % WEAK_DBM,
    "signals": 'count by (ap_name) (unpoller_client_radio_signal_db{job="unifi"})',
}


def _ts(value):
    return value.timestamp() if isinstance(value, datetime.datetime) else float(value)


def _avg(values, digits=2):
    values = [v for v in values if v is not None]
    return round(sum(values) / len(values), digits) if values else None


def _p10(values):
    values = sorted(v for v in values if v is not None)
    return values[max(0, math.ceil(0.1 * len(values)) - 1)] if values else None


def _by_mac(rows):
    out = {}
    for labels, points in rows:
        mac = normalise_mac(labels.get("mac"))
        if mac:
            out.setdefault(mac, {}).update({t: v for t, v in points.items() if v is not None})
    return out


# --- windows ----------------------------------------------------------------------------------

def window_end(w):
    """The end of a device_windows row: its window_end (the registry's rule); last_seen + grace
    only for a row without one."""
    if w.get("window_end") is not None:
        return _ts(w["window_end"])
    return _ts(w["last_seen"]) + GRACE.total_seconds()


def mac_intervals(windows):
    """{mac: [(device_id, from, to)]} from device_windows (to = window_end)."""
    out = {}
    for device_id, rows in windows.items():
        for w in rows:
            mac = normalise_mac(w.get("mac"))
            if mac and w.get("first_seen") is not None and w.get("last_seen") is not None:
                out.setdefault(mac, []).append((device_id, _ts(w["first_seen"]), window_end(w)))
    return out


def owner_at(intervals, t):
    """The one device whose window holds t, else None (none or several)."""
    owners = {d for d, a, b in intervals if a <= t <= b}
    return next(iter(owners)) if len(owners) == 1 else None


# --- AP names -> MACs ---------------------------------------------------------------------------

class ApNames:
    """The AP MAC for an ap_name at a minute (unpoller_device_info's name then), else the only
    MAC that name had that day."""

    def __init__(self, info_rows):
        self.at, by_name, self.latest = {}, {}, {}
        for labels, points in info_rows:
            mac, name = normalise_mac(labels.get("mac")), labels.get("name")
            if not mac or not name:
                continue
            for t, v in points.items():
                if v is not None:
                    self.at[(name, t)] = mac
                    if t >= self.latest.get(mac, (0, None))[0]:
                        self.latest[mac] = (t, name)
            by_name.setdefault(name, set()).add(mac)
        self.only = {name: next(iter(macs)) for name, macs in by_name.items() if len(macs) == 1}

    def mac(self, name, t):
        return self.at.get((name, t)) or self.only.get(name)

    def name(self, mac):
        return self.latest.get(mac, (0, None))[1]


# --- one day ----------------------------------------------------------------------------------

def day_grid(day, tz, now):
    start, end = bounds(day, tz)
    last = (int(now) // STEP * STEP - STEP) if now < end else end - STEP     # today: up to a minute ago
    return start, end, list(range(start, last + 1, STEP))


def device_queries(ssid, macs):
    """{name: PromQL} of DEVICE_QUERIES for one chunk of normalised MACs on the house network."""
    mac = mac_matcher(macs)
    sel = "essid=%s,%s" % (promql_string(ssid), mac)
    u = 'unpoller_client_uptime_seconds{job="unifi",%s}' % sel
    return {name: template.format(u=u, sel=sel, mac=mac) for name, template in DEVICE_QUERIES.items()}


def device_series(prom, ssid, macs, start, last):
    """{query name: {mac: {t: value}}} (presence: {mac: {t: (uptime, ap_name, radio)}})."""
    out = {name: {} for name in DEVICE_QUERIES}
    macs = sorted(macs)
    for i in range(0, len(macs), CHUNK):
        for name, promql in device_queries(ssid, macs[i:i + CHUNK]).items():
            rows = prom.range(promql, start, last, STEP)
            if name == "presence":
                for labels, points in rows:
                    m = normalise_mac(labels.get("mac"))
                    for t, v in points.items():
                        if m and v is not None:
                            best = out[name].setdefault(m, {}).get(t)
                            if best is None or v < best[0]:          # the newest association
                                out[name][m][t] = (v, labels.get("ap_name"), labels.get("radio"))
            else:
                for m, points in _by_mac(rows).items():
                    out[name].setdefault(m, {}).update(points)
    return out


def device_row(device_id, day, grid, fresh, ages, intervals, macs, series, ap_names, auth, events):
    """The device_day row of one device (called for devices with a window or a RADIUS decision
    that day; minutes in two devices' windows count for neither)."""
    online, stale = [], 0
    for t in grid:
        mine = [m for m in macs if owner_at(intervals.get(m, ()), t) == device_id]
        if not mine:
            continue
        if t not in fresh:
            stale += 1
            continue
        here = [(series["presence"][m][t], m) for m in mine if t in series["presence"].get(m, {})]
        if here:
            (uptime, ap_name, radio), mac = min(here)
            online.append((t, mac, uptime, ap_name, radio))
    aps, bands = {}, {}
    roams = reconnects = 0
    prev = None
    for t, _mac, uptime, ap_name, radio in online:
        ap_mac = ap_names.mac(ap_name, t)
        if ap_mac:
            aps[ap_mac] = aps.get(ap_mac, 0) + STEP
        band = BANDS.get(radio)
        if band:
            bands[band] = bands.get(band, 0) + STEP
        start = t - (ages.get(t) or 0) - uptime
        if prev is not None:
            if start - prev[0] > SAME_ASSOCIATION_S:
                reconnects += 1
            elif ap_name != prev[1]:
                roams += 1
        prev = (start, ap_name)

    def values(name):
        return [series[name].get(mac, {}).get(t) for t, mac, *_ in online]

    rx, tx = [v for v in values("rx") if v is not None], [v for v in values("tx") if v is not None]
    health = [v for v in values("health") if v is not None]
    signal = values("signal")
    disconnects = None
    if events:
        disconnects = sum(1 for e in events if e.get("kind") == "disconnected")
    return {
        "device_id": device_id, "day": day,
        "online_s": len(online) * STEP, "stale_s": stale * STEP,
        "signal_avg_dbm": _avg(signal, 1), "signal_p10_dbm": _p10(signal),
        "snr_avg_db": _avg(values("snr"), 1),
        "health_avg": _avg(health, 1), "health_min": round(min(health), 1) if health else None,
        "retry_ratio_avg": _avg(values("retry"), 4),
        "rx_bytes": int(sum(rx)) if rx else None, "tx_bytes": int(sum(tx)) if tx else None,
        "link_rx_avg_bps": _avg(values("link_rx"), 0),
        "roams": roams if online else None, "reconnects": reconnects if online else None,
        "disconnects": disconnects,
        "aps": aps, "bands": bands,
        "macs": len(macs),
        "auth_ok": sum(int(a.get("count") or 1) for a in auth if a.get("result") == "accept"),
        "auth_failed": sum(int(a.get("count") or 1) for a in auth if a.get("result") == "reject"),
    }


def ap_rows(day, grid, fresh, s, ap_names, info_rows, aps):
    """The ap_day rows of the APs with data that day."""
    stations, util = _by_mac(aps["stations"]), {}
    for labels, points in aps["util"]:
        mac = normalise_mac(labels.get("mac"))
        if mac and labels.get("radio"):
            util.setdefault(mac, {}).setdefault(labels["radio"], {}).update(points)
    weak, total = {}, {}
    for key, rows in (("weak", weak), ("signals", total)):
        for labels, points in aps[key]:
            for t, v in points.items():
                mac = ap_names.mac(labels.get("ap_name"), t)
                if mac and t in fresh and v is not None:
                    rows[mac] = rows.get(mac, 0) + v
    known = [(labels, 1) for labels, _ in info_rows]
    states, _names, _details = incidents.ap_states(grid, s, info_rows, known)
    present = {}
    for labels, points in info_rows:
        mac = normalise_mac(labels.get("mac"))
        if mac:
            present.setdefault(mac, set()).update(t for t, v in points.items() if v is not None)
    restarts = {}
    for mac, _name, _boot, _back in incidents.ap_restarts(grid, s, {m: ap_names.name(m) for m in present},
                                                          info_rows):
        restarts[mac] = restarts.get(mac, 0) + 1
    rows = []
    for mac in sorted(present):
        first = min(present[mac])
        counts = [v for t, v in stations.get(mac, {}).items() if t in fresh]
        down = sum(1 for t, st in states.get(("ap_down", mac), {}).items() if st and t >= first)
        rows.append({
            "ap_mac": mac, "day": day, "ap_name": ap_names.name(mac),
            "clients_avg": _avg(counts, 2), "clients_max": int(max(counts)) if counts else None,
            "channel_util_avg": {radio: _avg([v for t, v in points.items() if t in fresh], 4)
                                 for radio, points in sorted(util.get(mac, {}).items())
                                 if any(t in fresh for t in points)},
            "weak_client_share": round(weak.get(mac, 0) / total[mac], 4) if total.get(mac) else None,
            "restarts": restarts.get(mac, 0), "down_s": down * STEP,
        })
    return rows


def compute_day(ctx, prom, day, devices, windows):
    """Upserts the day's device_day and ap_day rows. Returns (devices written, APs written)."""
    tz, now = ctx.settings.timezone, ctx.now.timestamp()
    start, end, grid = day_grid(day, tz, now)
    if not grid:
        return 0, 0
    last = grid[-1]
    first = start - incidents.FROZEN_S
    ages = _single(prom.range(AGE, first, last, STEP))
    fresh = {t for t in grid if ages.get(t) is not None and ages[t] <= STALE_AFTER_S}
    info_rows = prom.range(incidents.Q["ap_info"], first, last, STEP)
    ap_names = ApNames(info_rows)
    intervals = mac_intervals(windows)
    day_macs = {}
    for device_id, rows in windows.items():
        for w in rows:
            mac = normalise_mac(w.get("mac"))
            if mac and _ts(w["first_seen"]) < end and window_end(w) >= start:
                day_macs.setdefault(device_id, set()).add(mac)
    wanted = set().union(*day_macs.values()) if day_macs else set()
    series = device_series(prom, ctx.settings.ssid, wanted, start, last) if wanted else \
        {name: {} for name in DEVICE_QUERIES}
    since, until = datetime.datetime.fromtimestamp(start, datetime.timezone.utc), \
        datetime.datetime.fromtimestamp(end, datetime.timezone.utc)
    written = 0
    for dev in devices:
        key = str(dev["id"])                       # windows are keyed by the id as text
        auth = registry.auth_events(ctx.db, dev["id"], since, until) or []
        macs = day_macs.get(key, set())
        if not macs and not auth:
            continue
        events = registry.connection_events(ctx.db, dev["id"], since, until) or []
        row = device_row(key, day, grid, fresh, ages, intervals, macs, series, ap_names, auth, events)
        if row is not None:
            registry.upsert_device_day(ctx.db, dict(row, device_id=dev["id"]))
            written += 1
    s = {"age": ages, "unifi_up": {t: 1 for t in ages},   # an age sample means unpoller was scraped
         "site_disconnected": _single(prom.range(incidents.Q["site_disconnected"], first, last, STEP)),
         "ap_uptime_rows": prom.range(incidents.Q["ap_uptime"], first, last, STEP),
         "ap_up_rec_rows": prom.range(incidents.AP_UP_RECORD, first, last, STEP),
         "ap_uptime_rec_rows": prom.range(incidents.AP_UPTIME_RECORD, first, last, STEP)}
    aps = {name: prom.range(q, start, last, STEP) for name, q in AP_QUERIES.items()}
    ap_written = 0
    for row in ap_rows(day, grid, fresh, s, ap_names, info_rows, aps):
        registry.upsert_ap_day(ctx.db, row)
        ap_written += 1
    ctx.db.commit()
    return written, ap_written


def _single(rows):
    return {t: v for t, v in rows[0][1].items() if v is not None} if rows else {}


# --- which days -------------------------------------------------------------------------------

def horizon_day(prom, today, tz):
    rows = prom.vector(HORIZON)
    oldest = today - datetime.timedelta(days=MAX_HISTORY_DAYS)
    if rows and rows[0][1]:
        return max(oldest, local_day(rows[0][1], tz))
    return today - datetime.timedelta(days=1)


def _days(first, last):
    d = first
    while d <= last:
        yield d
        d += datetime.timedelta(days=1)


def missing_days(db, devices, windows, horizon, before, tz, empty):
    """Days in [horizon, before] that lack a device's row (one its windows touch) or any AP row
    (unless known to have no AP data: empty), newest first."""
    if before < horizon:
        return []
    need = set()
    for dev in devices:
        rows = windows.get(str(dev["id"])) or []
        days = set()
        for w in rows:
            a = max(local_day(_ts(w["first_seen"]), tz), horizon)
            b = min(local_day(window_end(w), tz), before)
            days.update(_days(a, b))
        if days:
            have = {r["day"] for r in registry.device_days(db, dev["id"], horizon, before) or []}
            need |= days - have
    have_ap = {r["day"] for r in registry.ap_days(db, horizon, before) or []}
    need |= {d for d in _days(horizon, before) if d not in have_ap and d.isoformat() not in empty}
    return sorted(need, reverse=True)


def run(ctx):
    prom, tz = ctx.prometheus, ctx.settings.timezone
    today = local_day(ctx.now.timestamp(), tz)
    devices = registry.devices(ctx.db, include_revoked=True)
    ids = [d["id"] for d in devices]
    windows = {str(k): v for k, v in (registry.device_windows(ctx.db, ids) if ids else {}).items()}
    horizon = horizon_day(prom, today, tz)
    empty = set(ctx.cursor.get("empty_days") or [])
    yesterday = today - datetime.timedelta(days=1)
    days = [today] + ([yesterday] if yesterday >= horizon else [])
    days += missing_days(ctx.db, devices, windows, horizon, today - datetime.timedelta(days=2), tz,
                         empty)[:BACKFILL_DAYS_PER_RUN]
    done = []
    for day in days:
        if ctx.stopping():
            break
        written, ap_written = compute_day(ctx, prom, day, devices, windows)
        if not ap_written and day < yesterday:
            empty.add(day.isoformat())
        done.append({"day": day.isoformat(), "devices": written, "aps": ap_written})
    empty = sorted(d for d in empty if d >= horizon.isoformat())
    return {"horizon": horizon.isoformat(), "empty_days": empty, "last_run": done}
