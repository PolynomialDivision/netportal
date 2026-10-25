"""DEVICE: a device's live state from Prometheus, its identity and login data from the registry,
and the findings (diagnostics.py) on both.

Live values come from the MACs whose windows hold now (identity.Identity.live_bounds), one
query per metric for all MACs of a page. Sources (checked against the live Prometheus on
2026-10-25):
- unpoller (job unifi, scraped every 60 s): one series per client and association, labels mac,
  ap_name, essid, radio (ng/na/6e), radio_proto, channel, ip, bssid ... A roam or a band change
  starts a new series (other ap_name/radio), so per-device values are aggregated by mac.
  unpoller answers from a snapshot; unpoller_prometheus_cache_age_seconds is its age. When the
  controller does not answer it keeps serving the old snapshot (for hours on 2026-10-24): the
  series go on with frozen values, so presence alone is no proof of being online.
- unpoller_client_uptime_seconds: present while associated; its value is the time since the
  association, which survives a roam and restarts with a new association. The association start
  (snapshot time - uptime) identifies a connection: a new start is a reconnect, with or without a
  gap in the data.
- Direction: unpoller's client counters are the AP's view (transmit = to the device). Every
  rx/tx here is the DEVICE's view: rx = what the device receives (download), tx = what it sends
  (upload). *_rate_bps are LINK rates (the radio's speed), not throughput (rate(bytes)*8).
- The house's rules (network-wifi-health.rules.yml): wifi_client_snr_db, wifi_client_retry_ratio
  (by mac only), wifi_client_channel_utilization_ratio, wifi_client_health_score (0-100).
- The APs: unpoller_device_info{type="uap"} (mac, name, ip, model), unpoller_device_stations
  (clients per AP and station type), unpoller_device_radio_channel_utilization_total_ratio and
  unpoller_device_radio_stations (per radio), unpoller_device_vap_* (bssid -> AP).

Only the house's EAP-TLS network counts (essid = NETPORTAL_SSID, on every client selector; the
byte counters and the retry ratio carry no essid and are joined to the uptime series that does).
"""

import time

from .. import diagnostics, registry
from . import identity as ident
from . import timeline as tl
from .client import SUMMARY_CACHE_SECONDS, Unavailable
from .common import (BANDS, ap_info, by_mac, fit, iso, latest, normalise_mac, rounded, selectors, small_int,
                     unix)
from .house import empty_house, house_status

STALE_AFTER_S = diagnostics.STALE_AFTER_S
SAME_ASSOCIATION_S = tl.SAME_ASSOCIATION_S
CACHE_AGE = 'max(unpoller_prometheus_cache_age_seconds{job="unifi"})'
# The association start per series: snapshot time (scrape time - snapshot age) - uptime.
ASSOCIATION_START = '(timestamp({u}) - {u}) - on() group_left() ({age} or vector(0))'

LIVE_FIELDS = ("ap", "ssid", "band", "channel", "proto", "ip", "signal_dbm", "noise_dbm", "snr_db", "health",
               "retry_ratio", "channel_util", "link_rx_bps", "link_tx_bps", "rx_bps", "tx_bps", "rx_24h_bytes",
               "tx_24h_bytes", "roams_1h")

# field -> (PromQL template with {sel}, {mac} and {u} (selectors()), rounding digits or "int").
# Metrics without an essid label (byte counters, the retry rule) only count "and on (mac)" the
# house network's uptime series.
GAUGES = {
    "signal_dbm": ('max by (mac) (unpoller_client_radio_signal_db{{job="unifi",{sel}}})', 1),
    "noise_dbm": ('max by (mac) (unpoller_client_noise_db{{job="unifi",{sel}}})', 1),
    "snr_db": ('max by (mac) (wifi_client_snr_db{{{sel}}})', 1),
    "health": ('min by (mac) (wifi_client_health_score{{{sel}}})', 1),
    "retry_ratio": ('max by (mac) (wifi_client_retry_ratio{{{mac}}} and on (mac) {u})', 4),
    "channel_util": ('max by (mac) (wifi_client_channel_utilization_ratio{{{sel}}})', 4),
    # the device's view: it receives what the AP transmits
    "link_rx_bps": ('max by (mac) (unpoller_client_radio_transmit_rate_bps{{job="unifi",{sel}}})', "int"),
    "link_tx_bps": ('max by (mac) (unpoller_client_radio_receive_rate_bps{{job="unifi",{sel}}})', "int"),
    "rx_bps": (('sum by (mac) (rate(unpoller_client_transmit_bytes_total{{job="unifi",{mac}}}[5m]) '
               'and on (mac) {u}) * 8'), "int"),
    "tx_bps": (('sum by (mac) (rate(unpoller_client_receive_bytes_total{{job="unifi",{mac}}}[5m]) '
               'and on (mac) {u}) * 8'), "int"),
}
# Over 24 h: only for devices whose data bound is older than that (else part is not theirs).
DAY_TOTALS = {
    "rx_24h_bytes": 'sum by (mac) (increase(unpoller_client_transmit_bytes_total{{job="unifi",{mac}}}[24h]) '
                    'and on (mac) last_over_time({u}[24h]))',
    "tx_24h_bytes": 'sum by (mac) (increase(unpoller_client_receive_bytes_total{{job="unifi",{mac}}}[24h]) '
                    'and on (mac) last_over_time({u}[24h]))',
}
# The device's signal per AP over 24 h (poor_coverage), same rule for the bound.
COVERAGE = {
    "signal_dbm": 'avg by (mac, ap_name) (avg_over_time(unpoller_client_radio_signal_db{{job="unifi",{sel}}}[24h]))',
    "samples": 'sum by (mac, ap_name) (count_over_time(unpoller_client_radio_signal_db{{job="unifi",{sel}}}[24h]))',
}
# The APs' load (ap_overloaded, the admin's AP list).
AP_CLIENTS = 'sum by (name) (unpoller_device_stations{job="unifi",type="uap"})'
AP_RADIO_UTIL = 'max by (name, radio) (unpoller_device_radio_channel_utilization_total_ratio{job="unifi"})'
AP_INFO = 'max by (mac, name, ip, model) (unpoller_device_info{job="unifi",type="uap"})'
AP_BSSIDS = 'max by (bssid, mac, name, radio) (unpoller_device_vap_transmit_power{job="unifi"})'
LAST_SEEN_LOOKBACK_S = 7 * 86400


def empty_status():
    return dict({f: None for f in LIVE_FIELDS}, present=False, start=None, last_seen=None)


def count_changes(points):
    """AP or band changes in [(t, ap_name, radio)] (sorted by t)."""
    changes, prev = 0, None
    for _t, ap, radio in points:
        if prev is not None and (ap, radio) != prev:
            changes += 1
        prev = (ap, radio)
    return changes


def reconnect_times(starts):
    """The new association starts in [(t, association start)]: a start later than the previous
    one by more than SAME_ASSOCIATION_S (whether or not the data has a gap in between)."""
    times, prev = [], None
    for _t, start in starts:
        if start is None:
            continue
        if prev is not None and start - prev > SAME_ASSOCIATION_S:
            times.append(start)
        prev = start
    return times


def count_reconnects(starts):
    return len(reconnect_times(starts))


def device_status(client, macs, bounds=None, now=None):
    """({mac: live values}, {mac: summary for the diagnostics}) for normalised MACs, one query
    per metric for all of them. bounds {mac: Unix time}: data before it is not the device's."""
    now = time.time() if now is None else now
    bounds = bounds or {}
    parts = selectors(client.ssid, macs)
    u = parts["u"]
    status = {mac: empty_status() for mac in macs}
    after = lambda mac, t: bounds.get(mac) is None or t >= bounds[mac]   # noqa: E731
    # where it is now: the series with the newest association start
    for labels, start in client.vector(ASSOCIATION_START.format(u=u, age=CACHE_AGE)):
        st = status.get(labels.get("mac"))
        if st is None or start is None or (st["start"] is not None and st["start"] >= start):
            continue
        st.update(present=True, start=start, ap=ap_info(labels.get("ap_name")), ssid=labels.get("essid"),
                  band=BANDS.get(labels.get("radio")), channel=small_int(labels.get("channel")),
                  proto=labels.get("radio_proto"), ip=labels.get("ip"))
    for mac, st in status.items():
        if st["start"] is not None and bounds.get(mac) is not None:
            st["start"] = max(st["start"], bounds[mac])
    for field, (promql, digits) in GAUGES.items():
        for mac, value in by_mac(client.vector(promql.format(**parts))).items():
            if mac in status:
                status[mac][field] = fit(value, digits)
    day = full_day(macs, bounds, now)
    if day:
        day_parts = selectors(client.ssid, day)
        for field, promql in DAY_TOTALS.items():
            for mac, value in by_mac(client.vector(promql.format(**day_parts))).items():
                if mac in status:
                    status[mac][field] = fit(value, "int")
    # AP/band changes in the last hour, from the per-minute AP of each device
    where = {}
    for labels, points in client.matrix('max by (mac, ap_name, radio) (%s)[1h:1m]' % u):
        mac = labels.get("mac")
        for t, uptime in points:
            if uptime is not None and after(mac, t):
                where.setdefault(mac, {}).setdefault(t, []).append((uptime, labels.get("ap_name"),
                                                                    labels.get("radio")))
    summary = {mac: {"reconnects_24h": None, "reconnect_times_24h": [], "bands_7d": [], "tx_attempts_per_s": None,
                     "aps_1h": []} for mac in macs}
    for mac, by_t in where.items():
        if mac in status:
            # two series at one minute (rare): the newer association (smaller uptime)
            newest = [(t, *min(v, key=lambda x: x[0])[1:]) for t, v in sorted(by_t.items())]
            status[mac]["roams_1h"] = count_changes(newest)
            summary[mac]["aps_1h"] = sorted({ap for _t, ap, _r in newest if ap})
    attempts = 'sum by (mac) (rate(unpoller_client_wifi_attempts_transmit_total{job="unifi",%s}[5m]))' % parts["sel"]
    for mac, value in by_mac(client.vector(attempts)).items():
        if mac in summary:
            summary[mac]["tx_attempts_per_s"] = rounded(value, 2)
    fresh_starts = ('((max by (mac) (timestamp({u}) - {u}) - on() group_left() {age}) '
                    'and on() ({age} <= {stale}))[24h:5m]').format(u=u, age=CACHE_AGE, stale=STALE_AFTER_S)
    for labels, points in client.matrix(fresh_starts, ttl=SUMMARY_CACHE_SECONDS):
        mac = labels.get("mac")
        if mac in summary:
            times = reconnect_times([(t, s) for t, s in points if after(mac, t)])
            summary[mac]["reconnects_24h"], summary[mac]["reconnect_times_24h"] = len(times), times
    # the bands seen in 7 days: when each was last seen, only from the device's own time
    bands = 'max by (mac, radio) (max_over_time(timestamp(%s)[7d:5m]))' % u
    for labels, t in client.vector(bands, ttl=SUMMARY_CACHE_SECONDS):
        mac, band = labels.get("mac"), BANDS.get(labels.get("radio"))
        if mac in summary and band and t is not None and after(mac, t) and band not in summary[mac]["bands_7d"]:
            summary[mac]["bands_7d"].append(band)
    # when the absent ones were last there (7 days, exact to the scrape; older: the registry)
    absent = [mac for mac, st in status.items() if not st["present"]]
    if absent:
        promql = 'max by (mac) (max_over_time(timestamp(%s)[7d:5m]))' % selectors(client.ssid, absent)["u"]
        for mac, t in by_mac(client.vector(promql, ttl=SUMMARY_CACHE_SECONDS)).items():
            if mac in status and t is not None and after(mac, t):
                status[mac]["last_seen"] = t
    return status, summary


def last_seen_until(client, mac, start, end):
    """When a MAC whose window has ended (start..end) was last there inside it, from the 7 days
    before the end (None if not then)."""
    lookback = int(min(LAST_SEEN_LOOKBACK_S, max(300, end - start)))
    promql = 'max by (mac) (max_over_time(timestamp(%s)[%ds:5m]))' % (selectors(client.ssid, [mac])["u"], lookback)
    seen = by_mac(client.vector(promql, at=int(end), ttl=SUMMARY_CACHE_SECONDS)).get(mac)
    return seen if seen is not None and start <= seen <= end else None


def ended_window(identity, now):
    """(mac, start, end) of the current MAC's last piece when it has ended (the device has not
    logged in for longer than a session) but less than LAST_SEEN_LOOKBACK_S ago."""
    if identity.current is None or identity.withheld_now() or identity.live_bounds():
        return None
    pieces = [s for s in identity.segments() if s["mac"] == identity.current["mac"]]
    if not pieces:
        return None
    last = max(pieces, key=lambda s: s["end"])
    if last["end"] < now - LAST_SEEN_LOOKBACK_S or last["start"] == float("-inf"):
        return None
    return last["mac"], last["start"], last["end"]


def full_day(macs, bounds, now):
    """The MACs whose data of the last 24 h is all the device's."""
    return [mac for mac in macs if bounds.get(mac) is None or bounds[mac] <= now - 86400]


def coverage(client, macs, bounds, now):
    """{mac: {ap name: {"signal_dbm", "samples"}}} over 24 h, for the MACs whose whole day is theirs."""
    day = full_day(macs, bounds, now)
    out = {}
    if not day:
        return out
    parts = selectors(client.ssid, day)
    for field, promql in COVERAGE.items():
        for labels, value in client.vector(promql.format(**parts), ttl=SUMMARY_CACHE_SECONDS):
            mac, ap = labels.get("mac"), labels.get("ap_name")
            if mac in day and ap and value is not None:
                out.setdefault(mac, {}).setdefault(ap, {"signal_dbm": None, "samples": 0})[field] = value
    return out


def ap_load(client):
    """{ap name: {"clients", "radios": {radio: channel utilisation}}} now."""
    out = {}
    for labels, value in client.vector(AP_CLIENTS):
        if labels.get("name") and value is not None:
            out.setdefault(labels["name"], {"clients": None, "radios": {}})["clients"] = int(value)
    for labels, value in client.vector(AP_RADIO_UTIL):
        if labels.get("name") and labels.get("radio"):
            out.setdefault(labels["name"], {"clients": None, "radios": {}})["radios"][labels["radio"]] = rounded(value, 3)
    return out


def ap_map(client):
    """timeline.ApMap from the APs' BSSIDs, addresses and MACs (cached a minute; empty when
    Prometheus does not answer)."""
    if client is None:
        return tl.ApMap()
    try:
        info = client.vector(AP_INFO, ttl=SUMMARY_CACHE_SECONDS)
        vaps = client.vector(AP_BSSIDS, ttl=SUMMARY_CACHE_SECONDS)
    except Unavailable:
        return tl.ApMap()
    names, nas, bssids = {}, {}, {}
    for labels, _v in info:
        mac = normalise_mac(labels.get("mac"))
        if mac and labels.get("name"):
            names[mac] = labels["name"]
            if labels.get("ip"):
                nas[labels["ip"]] = (labels["name"], mac)
    for labels, _v in vaps:
        bssid, mac = normalise_mac(labels.get("bssid")), normalise_mac(labels.get("mac"))
        if bssid:
            bssids[bssid] = (labels.get("name"), mac, BANDS.get(labels.get("radio")))
    return tl.ApMap(bssids, nas, names)


# --- DEVICE -----------------------------------------------------------------------------------

def device_entry(row, mac, status, telemetry, house, now, summary=None, conflict=0, admin=False, extra=None):
    """DEVICE from a registry row (registry.DEVICE_LIST) and its live status. conflict: the
    number of other people whose devices claim the same MAC now; residents then see no
    telemetry. extra (v2, live.dashboard): {"identity", "context", "last_auth"}."""
    extra = extra or {}
    stale = telemetry == "ok" and diagnostics.is_stale(house.get("wifi_data_age_s"))
    withheld = conflict and not admin
    if not mac:
        state = "never_connected"
    elif telemetry != "ok" or stale or withheld:
        state = "unknown"
    elif status and status["present"]:
        state = "online"
    else:
        state = "offline"
    status = empty_status() if withheld or not status else status
    if state == "online":
        last_seen = now - (house.get("wifi_data_age_s") or 0)
    elif state == "offline":
        last_seen = latest(status["last_seen"], row.get("last_seen"))
    else:
        last_seen = unix(row.get("last_seen"))   # RADIUS: the device's latest login
    device = {
        "id": str(row["id"]), "name": row["name"], "platform": row["platform"], "policy": row.get("policy"),
        "created": iso(row.get("created")), "expires": iso(row.get("expires")), "revoked": bool(row.get("revoked")),
        "mac": mac, "state": state, "last_seen": iso(last_seen),
        "since": iso(status["start"]) if state == "online" else None,
    }
    device.update({f: status[f] for f in LIVE_FIELDS})
    identity, context = extra.get("identity"), dict(extra.get("context") or {})
    _identity_fields(device, identity, extra.get("last_auth"), admin)
    if withheld:
        found = [diagnostics.finding("mac_conflict", "warn", evidence={})]
        found += diagnostics.auth_findings(context) + diagnostics.cert_findings(context)
        device["diagnostics"] = sorted(found, key=lambda f: diagnostics.SEVERITY_ORDER[f["severity"]])
    else:
        summary = dict(summary or {}, associated_s=now - status["start"] if state == "online" else None)
        device["diagnostics"] = diagnostics.findings(device, summary, house.get("wifi_data_age_s"), telemetry, context)
        if conflict:
            device["diagnostics"].insert(0, diagnostics.finding("mac_conflict", "warn", evidence={
                "owners": conflict, "macs": sorted({c["mac"] for c in identity.conflicts_at(now)}) if identity else [mac]},
                owners=conflict))
    device["findings"] = device["diagnostics"]
    device["facts"] = facts(device, house, telemetry, withheld)
    device["sources"] = sources(device, status, telemetry, extra)
    return device


def _identity_fields(device, identity, last_auth, admin):
    device["macs"] = identity.public_macs() if identity else []
    device["mac_mode"] = identity.mac_mode() if identity else None
    device["data_from"] = iso(identity.data_from) if identity else None
    device["last_auth"] = last_auth
    if admin:
        device["conflicts"] = identity.public_conflicts() if identity else []


FACT_SOURCES = {"expires": "registry", "mac_mode": "registry", "last_auth": "radius_auth"}


def facts(device, house, telemetry, withheld):
    """The measured values of a DEVICE with where each comes from: {key: {"value", "source",
    "basis"}} (only what is known)."""
    out = {}
    if not withheld and telemetry == "ok":
        for f in LIVE_FIELDS:
            if device.get(f) is not None:
                out[f] = {"value": device[f], "source": "prometheus", "basis": "measured"}
        if house.get("wifi_data_age_s") is not None:
            out["wifi_data_age_s"] = {"value": house["wifi_data_age_s"], "source": "prometheus", "basis": "measured"}
    for key, source in FACT_SOURCES.items():
        if device.get(key) is not None:
            out[key] = {"value": device[key], "source": source,
                        "basis": "inferred" if key == "mac_mode" else "measured"}
    return out


def sources(device, status, telemetry, extra):
    found = {"registry"}
    if device.get("last_auth"):
        found.add("radius_auth")
    if telemetry == "ok" and status and (status["present"] or status["last_seen"] is not None
                                         or any(status[f] is not None for f in LIVE_FIELDS)):
        found.add("prometheus")
    found |= set(extra.get("sources") or ())
    return sorted(found)


def last_auth(row, rejects):
    """{"at", "result", "reason"}: the newer of the last accept (radius_session.updated, the
    row's last_seen) and the last reject (registry.auth_failures; a row of repeats: its latest)."""
    accept = unix(row.get("last_seen"))
    reject = max(rejects, key=lambda r: r.get("last_at") or r["at"]) if rejects else None
    reject_at = (reject.get("last_at") or reject["at"]) if reject is not None else None
    if reject is not None and (accept is None or reject_at > accept):
        return {"at": iso(reject_at), "result": "reject", "reason": reject["reason"]}
    if accept is not None:
        return {"at": iso(accept), "result": "accept", "reason": "ok"}
    return None


def _rejects_of(row, identity, failures):
    """The house's rejects (24 h) that are this device's: by its certificate (device_id) or,
    without a certificate the registry knows (device_id None: no_cert, not_eap, unknown_cert,
    bad_chain), by one of its MACs inside its (unwithheld) windows; a reject of another device's
    certificate is that device's, whatever MAC it came from (as registry.auth_events). Each:
    {"at" (first), "last_at" (the latest repeat, None: one), "count", "reason", "mac"}."""
    segments = identity.segments() if identity else []
    out = []
    for r in failures:
        at, mac = unix(r.get("at")), normalise_mac(r.get("mac")) if r.get("mac") else None
        device = r.get("device_id")
        if (device is not None and str(device) == str(row["id"])) or (
                device is None and mac and identity is not None and identity.contains(mac, at, segments)):
            out.append({"at": at, "last_at": unix(r.get("last_at")), "count": int(r.get("count") or 1),
                        "reason": r.get("reason"), "mac": mac})
    return out


def _context(row, identity, summary, status, rejects, load, cover, incidents, now, detail_events=None):
    """The diagnostics' context (diagnostics.py) of one device."""
    context = {"now": now, "expires": unix(row.get("expires")), "rejects": rejects,
               "last_accept": unix(row.get("last_seen")), "mac_mode": identity.mac_mode() if identity else None,
               "randomized_macs_30d": identity.recent_randomized() if identity else [], "ap_load": None,
               "coverage": cover or {}, "disconnects": [], "roams_1h_measured": None, "incidents": []}
    if status and status.get("present") and status.get("ap") and load:
        name = status["ap"]["name"]
        ap = load.get(name) or {}
        radio = {v: k for k, v in BANDS.items()}.get(status.get("band"))
        context["ap_load"] = {"ap": name, "clients": ap.get("clients"), "band": status.get("band"),
                              "channel_util": (ap.get("radios") or {}).get(radio)}
    times = (summary or {}).get("reconnect_times_24h") or []
    context["disconnects"] = [{"at": t, "basis": "inferred", "source": "prometheus", "cause": None} for t in times]
    if detail_events is not None:
        merged = detail_events
        measured = tl.disconnects([e for e in merged if e["basis"] == "measured"], since=now - 86400)
        context["disconnects"] = measured + [d for d in context["disconnects"]
                                             if not any(abs(d["at"] - m["at"]) <= tl.MERGE_S for m in measured)]
        context["roams_1h_measured"] = sum(1 for e in merged if e["basis"] == "measured" and e["at"] >= now - 3600
                                           and e["kind"] in ("roamed", "band_changed")) or None
    names = set((summary or {}).get("aps_1h") or ())
    if status and status.get("ap"):
        names.add(status["ap"]["name"])
    if detail_events:
        names |= {e["ap"] for e in detail_events if e["ap"]}
    macs = {e["ap_mac"] for e in detail_events or () if e["ap_mac"]}
    from .history import relevant_incidents
    rows = relevant_incidents(incidents or [], macs, {n.lower() for n in names})
    context["incidents"] = [dict(r, started=unix(r["started"]), ended=unix(r.get("ended"))) for r in rows]
    return context


def _detail_events(db, row, identity, now, aps):
    """The last 24 h of the registry's measured events of one device (the detail page), merged."""
    since, until = ident._dt(now - 86400), ident._dt(now)
    acct = registry.acct_sessions(db, row["id"], since, until, limit=200)
    unifi = registry.connection_events(db, row["id"], since, until, limit=500)
    events, _ = tl.merge(tl.restrict(tl.from_acct(acct, aps) + tl.from_unifi(unifi, aps), identity), limit=None)
    found = [name for name, rows in (("radius_acct", acct), ("unifi_syslog", unifi)) if rows]
    return events, found


def dashboard(client, rows, owners=None, now=None, claims=None, admin=False, db=None, detail=False):
    """The /api/devices payload for these registry rows. client None: telemetry "off".
    owners ({sub: {"username", "display"}}) adds each device's owner.

    With db (v2): the devices' MAC windows and conflicts from the registry (identity.py), the
    house's RADIUS rejects and incidents of the last 24 h; detail (one device's page): its
    accounting sessions and UniFi events of 24 h too. A MAC in a conflict now is not asked for
    a resident (state "unknown", mac_conflict); an admin sees the data and the conflict.
    Without db (v1): the latest login's MAC (calling_station); claims ({mac: {owner sub}},
    registry.mac_claims) as the conflicts."""
    now = time.time() if now is None else now
    telemetry, house, statuses, summaries = ("off" if client is None else "ok"), empty_house(), {}, {}
    if db is not None:
        identities = ident.from_registry(db, rows, now, admin, since=now - ident.RECENT_S)
        failures = registry.auth_failures(db, ident._dt(now - 86400)) if rows else []
        incidents = registry.incidents(db, ident._dt(now - 86400)) if rows else []
    else:
        identities, failures, incidents = ident.from_rows(rows, claims, now, admin), [], []
    bounds = {}
    for row in rows:
        identity = identities[str(row["id"])]
        if identity.withheld_now():
            continue
        for mac, bound in identity.live_bounds().items():
            bounds[mac] = max(bound, bounds.get(mac, bound))      # several devices, one MAC: the latest
    wanted = sorted(bounds)
    ended = {}
    for row in rows:
        window = ended_window(identities[str(row["id"])], now)
        if window:
            ended[str(row["id"])] = window
    load, cover, ended_seen = {}, {}, {}
    if client is not None:
        client = client.within()
        try:
            house = house_status(client)
            if wanted:
                finite = {m: b for m, b in bounds.items() if b != float("-inf")}
                statuses, summaries = device_status(client, wanted, finite, now)
                cover = coverage(client, wanted, finite, now)
                if any(st["present"] for st in statuses.values()):
                    load = ap_load(client)
            for key, (mac, start, end) in ended.items():
                ended_seen[key] = last_seen_until(client, mac, start, end)
        except Unavailable:
            telemetry, statuses, summaries, load, cover, ended_seen = "unavailable", {}, {}, {}, {}, {}
    aps = ap_map(client) if (detail and db is not None and telemetry == "ok") else tl.ApMap()
    devices = []
    for row in rows:
        identity = identities[str(row["id"])]
        withheld = identity.withheld_now()
        macs = [] if withheld else sorted(identity.live_bounds())
        mac = _primary(macs, statuses, identity)
        conflict = identity.conflict_owners_now() if admin else (1 if withheld else 0)
        rejects = _rejects_of(row, identity, failures)
        events, found = (None, [])
        if detail and db is not None and not withheld:
            events, found = _detail_events(db, row, identity, now, aps)
        status, summary = statuses.get(mac), summaries.get(mac)
        if status is None and ended_seen.get(str(row["id"])) is not None:
            status = dict(empty_status(), last_seen=ended_seen[str(row["id"])])
        cov = {}
        for m in macs:
            for ap, c in (cover.get(m) or {}).items():
                if ap not in cov or (c.get("samples") or 0) > (cov[ap].get("samples") or 0):
                    cov[ap] = c
        context = _context(row, identity, summary, status, rejects, load, cov, incidents, now, events)
        extra = {"identity": identity, "context": context, "last_auth": last_auth(row, rejects), "sources": found}
        device = device_entry(row, mac or identity.current_mac, status, telemetry, house, now, summary, conflict, admin,
                              extra)
        if owners is not None:
            person = owners.get(row.get("owner")) or {}
            device["owner"] = {"username": person.get("username"), "display": person.get("display")}
        devices.append(device)
    return {"generated_at": iso(now), "telemetry": telemetry,
            "stale": telemetry == "ok" and diagnostics.is_stale(house["wifi_data_age_s"]),
            "house": house, "devices": devices}


def _primary(macs, statuses, identity):
    """The MAC a DEVICE shows: of its live MACs the one present with the newest association,
    else the current window's, else the latest seen."""
    present = [m for m in macs if statuses.get(m, {}).get("present")]
    if present:
        return max(present, key=lambda m: statuses[m]["start"])
    if identity.current_mac in macs:
        return identity.current_mac
    seen = [m for m in macs if statuses.get(m, {}).get("last_seen") is not None]
    return max(seen, key=lambda m: statuses[m]["last_seen"]) if seen else (macs[0] if macs else None)
