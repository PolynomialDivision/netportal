"""Job incidents: infrastructure problems from the house's monitoring -> incident rows.

Every run reads the signals below as per-minute range queries over the time since the last
evaluation (cursor "evaluated_until") plus OVERLAP_S (at least the last 15 minutes, at most
MAX_LOOKBACK_S after a long pause), turns them into a state per minute and subject (failing /
ok / unknown) and reconciles that with the stored incidents:

- a failing run of at least MIN_FOR[kind] with no stored incident overlapping it opens one
  (started = the run's first failing minute) and, when the run is over, closes it at the first
  ok minute after it;
- a stored open incident is closed at the first ok minute after its start;
- unknown minutes (no data, or a broader problem hides this one) neither open nor close.
Re-evaluating the same minutes finds the stored incident and changes nothing (idempotent).

Signals (names checked against the live Prometheus on 2026-10-25):
  router_down        max(probe_success{job="blackbox_icmp",role="gateway"}) == 0
  internet_down      max(probe_success{job="blackbox_icmp",role="internet"}) == 0, router answering
  internet_degraded  network_internet_packet_loss_ratio_5m > 5 % or network_internet_rtt_ms > 100,
                     internet and router up (as the house's InternetPacketLossHigh / telemetry)
  dns_down           max(probe_success{job="blackbox_dns",role="gateway"}) == 0, internet up
  unifi_data_stale   up{job="unifi"} == 0 or unpoller_prometheus_cache_age_seconds > 600
  ap_down            per AP MAC, only while the UniFi data is fresh: unifi_ap:up == 0 (house-infra's
                     record, where it exists), or its unpoller_device_info
                     series is missing (it was there within a day), or the site counts
                     disconnected APs (unpoller_site_disconnected{subsystem="wlan"} > 0) and this
                     AP's unpoller_device_uptime_seconds did not change for 3 minutes (unpoller
                     keeps exporting a disconnected but adopted AP with its last values)
  ap_restarted       per AP MAC: its uptime went down; started = boot time (snapshot - uptime),
                     ended = when it was seen running again
  switch_down        per switch: probe_success{job="switches_icmp"} == 0 for 3 min (router up), or
                     web_switch_up == 0 for 10 min (exporter up, login not blocked, reason
                     timeout/connection/loader per web_switch_down_reason)
  radius_down        the FreeRADIUS container (cadvisor container_last_seen{name=...}) is gone
                     while cadvisor answers. No RADIUS probe exists: this sees a stopped
                     container, not a hung server.
  switch_port_down   not evaluated: there is no mapping of switch ports to APs (no ifAlias, no
                     LLDP data in Prometheus).
All of them are direct signals: basis "measured".
"""

import datetime
import logging

from .. import registry
from .sources import normalise_mac

log = logging.getLogger("netportal.collect.incidents")

UTC = datetime.timezone.utc
STEP = 60
OVERLAP_S = 15 * 60
MAX_LOOKBACK_S = 6 * 3600
FROZEN_S = 180                    # an AP's uptime unchanged this long (with disconnected APs): down
STALE_AFTER_S = 600               # unpoller's snapshot older than this: stale (diagnostics.STALE_AFTER_S)
DEGRADED_LOSS_RATIO, DEGRADED_RTT_MS = 0.05, 100
SAME_RESTART_S = 120

MIN_FOR = {"router_down": 120, "internet_down": 180, "internet_degraded": 300, "dns_down": 300,
           "unifi_data_stale": 0, "ap_down": 180, "switch_down": 180, "radius_down": 120}
KINDS = tuple(MIN_FOR) + ("ap_restarted",)
# The small web switches are read over their slow web UIs: short timeouts are common (2026-10-25:
# runs of 1-4 minutes every hour), so like the house's WebSwitchDown alert only 10 minutes count,
# and only for reasons that mean unreachable (web_switch_down_reason), not "someone is logged in".
WEB_SWITCH_MIN_FOR = 600
WEB_SWITCH_DOWN_REASONS = {"timeout", "connection", "loader"}

Q = {
    "gateway": 'max(probe_success{job="blackbox_icmp",role="gateway"})',
    "internet": 'max(probe_success{job="blackbox_icmp",role="internet"})',
    "loss": 'max(network_internet_packet_loss_ratio_5m)',
    "rtt": 'max(network_internet_rtt_ms)',
    "dns": 'max(probe_success{job="blackbox_dns",role="gateway"})',
    "unifi_up": 'max(up{job="unifi"})',
    "age": 'max(unpoller_prometheus_cache_age_seconds{job="unifi"})',
    "site_disconnected": 'max(unpoller_site_disconnected{job="unifi",subsystem="wlan"})',
    "ap_info": 'max by (mac, name) (unpoller_device_info{job="unifi",type="uap"})',
    "ap_uptime": 'max by (name) (unpoller_device_uptime_seconds{job="unifi",type="uap"})',
    "switch_icmp": 'max by (switch) (probe_success{job="switches_icmp"})',
    "web_switch": 'max by (switch) (web_switch_up{job="web_switches"})',
    "web_switch_blocked": 'max by (switch) (web_switch_login_blocked{job="web_switches"})',
    "web_switch_reason": 'max by (switch, reason) (web_switch_down_reason{job="web_switches"})',
    "web_exporter": 'max(up{job="web_switches"})',
    "cadvisor": 'max(up{job="cadvisor"})',
}
AP_KNOWN = 'max by (mac, name) (last_over_time(unpoller_device_info{job="unifi",type="uap"}[1d]))'
# house-infra's records (wifi-aps rules, from the 2026-10-25 monitoring deploy; absent before it
# and while the UniFi data is stale): used where they exist, the raw series otherwise
AP_UP_RECORD = 'max by (ap_mac, ap_name) (unifi_ap:up)'
AP_UPTIME_RECORD = 'max by (ap_mac, ap_name) (unifi_ap:uptime:seconds)'
RADIUS = 'max(container_last_seen{{job="cadvisor",name="{name}"}})'


def _single(rows):
    """{t: value} of a range result with (at most) one series."""
    return rows[0][1] if rows else {}


def _by(rows, label):
    out = {}
    for labels, points in rows:
        key = labels.get(label)
        if key:
            out.setdefault(key, {}).update(points)
    return out


def _eq(value, target):
    return None if value is None else value == target


# --- states per minute ------------------------------------------------------------------------

def house_states(grid, s):
    """{(kind, subject): {t: True|False|None}} for the house-wide signals; s: name -> {t: v}."""
    states = {k: {} for k in ("router_down", "internet_down", "internet_degraded", "dns_down", "unifi_data_stale")}
    detail = {}
    for t in grid:
        gw, net, dns = s["gateway"].get(t), s["internet"].get(t), s["dns"].get(t)
        loss, rtt = s["loss"].get(t), s["rtt"].get(t)
        states["router_down"][t] = _eq(gw, 0)
        states["internet_down"][t] = (net == 0) if gw == 1 and net is not None else None
        if gw == 1 and net == 1:
            bad = (loss is not None and loss > DEGRADED_LOSS_RATIO) or (rtt is not None and rtt > DEGRADED_RTT_MS)
            states["internet_degraded"][t] = bad if (loss is not None or rtt is not None) else None
            if bad:
                d = detail.setdefault("internet_degraded", {})
                d["loss_ratio_max"] = max(d.get("loss_ratio_max") or 0, round(loss or 0, 4))
                d["rtt_ms_max"] = max(d.get("rtt_ms_max") or 0, round(rtt or 0, 1))
        elif gw == 0 or net == 0:
            states["internet_degraded"][t] = False      # a broader incident covers it
        else:
            states["internet_degraded"][t] = None
        states["dns_down"][t] = _eq(dns, 0) if gw == 1 and net == 1 else None
        up, age = s["unifi_up"].get(t), s["age"].get(t)
        if up is None:
            states["unifi_data_stale"][t] = None        # Prometheus itself has nothing then
        else:
            states["unifi_data_stale"][t] = up == 0 or age is None or age > STALE_AFTER_S
    return {(k, ""): v for k, v in states.items()}, {(k, ""): v for k, v in detail.items()}


def fresh_minutes(grid, s):
    return {t for t in grid if s["unifi_up"].get(t) == 1 and s["age"].get(t) is not None
            and s["age"][t] <= STALE_AFTER_S}


def ap_uptimes(s, info_rows):
    """{ap mac: {t: uptime}}: the raw unpoller_device_uptime_seconds (by name, mapped to the MAC
    the name had at that minute) and, where it exists, the record unifi_ap:uptime:seconds (by
    ap_mac; the same values, from house-infra's wifi-aps rules)."""
    at, macs_of = {}, {}
    for labels, points in info_rows:
        mac, name = normalise_mac(labels.get("mac")), labels.get("name")
        if mac and name:
            macs_of.setdefault(name, set()).add(mac)
            for t, v in points.items():
                if v is not None:
                    at[(name, t)] = mac
    only = {name: next(iter(m)) for name, m in macs_of.items() if len(m) == 1}
    out = {}
    for labels, points in s.get("ap_uptime_rows", []):
        name = labels.get("name")
        for t, v in points.items():
            mac = at.get((name, t)) or only.get(name)
            if mac and v is not None:
                out.setdefault(mac, {})[t] = v
    for labels, points in s.get("ap_uptime_rec_rows", []):
        mac = normalise_mac(labels.get("ap_mac"))
        if mac:
            out.setdefault(mac, {}).update({t: v for t, v in points.items() if v is not None})
    return out


def ap_states(grid, s, info_rows, known_rows):
    """({(ap_down, mac): {t: state}}, {mac: name}, {(ap_down, mac): detail}) per known AP.
    Where the record unifi_ap:up exists (house-infra, 2026-10-25) its 0 is down too; without it
    (older data, before that deploy) the raw rule alone decides."""
    names, present = {}, {}
    for labels, _value in known_rows:
        mac = normalise_mac(labels.get("mac"))
        if mac:
            names[mac] = labels.get("name") or names.get(mac)
    for labels, points in info_rows:
        mac = normalise_mac(labels.get("mac"))
        if not mac:
            continue
        names[mac] = labels.get("name") or names.get(mac)
        present.setdefault(mac, set()).update(t for t, v in points.items() if v is not None)
    record = {}
    for labels, points in s.get("ap_up_rec_rows", []):
        mac = normalise_mac(labels.get("ap_mac"))
        if mac:
            names.setdefault(mac, labels.get("ap_name"))
            record.setdefault(mac, {}).update({t: v for t, v in points.items() if v is not None})
    uptimes = ap_uptimes(s, info_rows)
    fresh = fresh_minutes(grid, s)
    states, details = {}, {}
    for mac in names:
        key = ("ap_down", mac)
        states[key], signals = {}, set()
        for t in grid:
            if t not in fresh:
                states[key][t] = None
                continue
            if record.get(mac, {}).get(t) == 0:
                states[key][t] = True
                signals.add("unifi_ap_up")
                continue
            if t not in present.get(mac, ()):
                states[key][t] = True
                signals.add("device_missing")
                continue
            disconnected = (s["site_disconnected"].get(t) or 0) > 0
            states[key][t] = bool(disconnected and _frozen(uptimes.get(mac, {}), t))
            if states[key][t]:
                signals.add("site_disconnected")
        if signals:
            details[key] = {"signal": sorted(signals)}
    return states, names, details


def _frozen(points, t):
    """The AP's uptime did not change over the last FROZEN_S (or is 0) at t; None: not known."""
    now = points.get(t)
    if now is None:
        return None
    if now == 0:
        return True
    before = [points.get(t - k * STEP) for k in range(1, FROZEN_S // STEP + 1)]
    if any(v is None for v in before):
        return None
    return all(v == now for v in before)


def ap_restarts(grid, s, names_by_mac, info_rows=()):
    """[(mac, name, boot, back)]: uptime resets (boot = snapshot time - uptime)."""
    out = []
    for mac, points in sorted(ap_uptimes(s, info_rows).items()):
        prev = None
        for t in grid:
            v = points.get(t)
            if v is None:
                continue
            if prev is not None and v + STEP < prev:
                snapshot = t - int(s["age"].get(t) or 0)
                out.append((mac, names_by_mac.get(mac), int(snapshot - v), int(snapshot)))
            prev = v
    return out


def switch_states(grid, s):
    states, details = {}, {}
    icmp, web = _by(s["switch_icmp_rows"], "switch"), _by(s["web_switch_rows"], "switch")
    blocked = _by(s["web_switch_blocked_rows"], "switch")
    reasons = {}
    for labels, points in s.get("web_switch_reason_rows", []):
        for t, v in points.items():
            if v is not None and labels.get("switch"):
                reasons[(labels["switch"], t)] = labels.get("reason")
    for name, points in icmp.items():
        key = ("switch_down", name)
        states[key] = {t: (_eq(points.get(t), 0) if s["gateway"].get(t) == 1 else None) for t in grid}
        details[key] = {"source": "switches_icmp"}
    for name, points in web.items():
        key = ("switch_down", name)
        mine = {}
        for t in grid:
            reason = reasons.get((name, t))
            if s["web_exporter"].get(t) != 1 or blocked.get(name, {}).get(t) == 1 or \
                    (points.get(t) == 0 and reason is not None and reason not in WEB_SWITCH_DOWN_REASONS):
                mine[t] = None                  # cannot be read (someone logged in ...): not down
            else:
                mine[t] = _eq(points.get(t), 0)
        if key in states:                       # in both: failing if either says so
            states[key] = {t: _or(states[key][t], mine[t]) for t in grid}
        else:
            states[key] = mine
            details[key] = {"source": "web_switches"}
    return states, details


def _or(a, b):
    if a is True or b is True:
        return True
    if a is None or b is None:
        return None
    return False


def radius_states(grid, s):
    rad = s["radius"]
    return {("radius_down", ""): {t: (t not in rad or rad[t] is None) if s["cadvisor"].get(t) == 1 else None
                                  for t in grid}}


# --- reconciliation ---------------------------------------------------------------------------

CLOSE_AFTER_S = 120   # an ok minute ends a problem only if nothing fails in the next 2 minutes


def _confirmed_ok(points, grid, t):
    """t is ok and stays so: no failing minute in (t, t + CLOSE_AFTER_S], and the window reaches
    that far (else the next run decides)."""
    if points.get(t) is not False or t + CLOSE_AFTER_S > grid[-1]:
        return False
    return not any(points.get(u) is True for u in grid if t < u <= t + CLOSE_AFTER_S)


def runs(points, grid):
    """[(start, end or None, last failing minute)]: failing runs; end = the confirmed ok minute
    after it (None: still failing, or not confirmed yet)."""
    out, start, last_fail = [], None, None
    for t in grid:
        state = points.get(t)
        if state is True:
            if start is None:
                start = t
            last_fail = t
        elif start is not None and _confirmed_ok(points, grid, t):
            out.append((start, t, last_fail))
            start = None
    if start is not None:
        out.append((start, None, last_fail))
    return out


def _ts(value):
    return value.timestamp() if isinstance(value, datetime.datetime) else value


def _dt(unix):
    return datetime.datetime.fromtimestamp(unix, UTC)


def reconcile(db, kind, subject, name, points, grid, stored, detail=None, min_for=None):
    """Open/close incidents of one kind and subject from its per-minute states. stored: this
    kind+subject's incidents overlapping the window (updated in place). Returns (opened, closed)."""
    opened = closed = 0
    for inc in [i for i in stored if i.get("ended") is None]:
        started = _ts(inc["started"])
        end = next((t for t in grid if t > started and _confirmed_ok(points, grid, t)), None)
        if end is not None:
            closed += registry.close_incident(db, kind, subject, _dt(end)) or 0
            inc["ended"] = _dt(end)
    for start, end, last_fail in runs(points, grid):
        length = (end if end is not None else last_fail + STEP) - start
        if length < max(MIN_FOR[kind] if min_for is None else min_for, STEP if end is None else 0):
            continue
        overlapping = [i for i in stored if _ts(i["started"]) <= last_fail
                       and (i.get("ended") is None or _ts(i["ended"]) >= start)]
        if overlapping:
            continue
        registry.open_incident(db, kind, subject, name, _dt(start), "measured", detail or {})
        opened += 1
        row = {"kind": kind, "subject": subject, "started": _dt(start), "ended": None}
        if end is not None:
            closed += registry.close_incident(db, kind, subject, _dt(end)) or 0
            row["ended"] = _dt(end)
        stored.append(row)
    return opened, closed


def _window(ctx):
    now = int(ctx.now.timestamp()) // STEP * STEP
    last = ctx.cursor.get("evaluated_until")
    start = now - OVERLAP_S
    if isinstance(last, (int, float)) and last > 0:
        start = min(start, int(last) // STEP * STEP - OVERLAP_S)
    return max(start, now - MAX_LOOKBACK_S), now


def gather(prom, start, end, radius_container):
    """All the signals over [start - FROZEN_S, end] at STEP."""
    first = start - FROZEN_S
    s = {}
    for name in ("gateway", "internet", "loss", "rtt", "dns", "unifi_up", "age", "site_disconnected",
                 "web_exporter", "cadvisor"):
        s[name] = _single(prom.range(Q[name], first, end, STEP))
    for name in ("ap_uptime", "switch_icmp", "web_switch", "web_switch_blocked", "web_switch_reason"):
        s[name + "_rows"] = prom.range(Q[name], first, end, STEP)
    s["ap_info_rows"] = prom.range(Q["ap_info"], first, end, STEP)
    s["ap_up_rec_rows"] = prom.range(AP_UP_RECORD, first, end, STEP)
    s["ap_uptime_rec_rows"] = prom.range(AP_UPTIME_RECORD, first, end, STEP)
    s["ap_known_rows"] = prom.vector(AP_KNOWN, at=end)
    s["radius"] = _single(prom.range(RADIUS.format(name=radius_container), first, end, STEP))
    return s


def evaluate(s, start, end):
    """({(kind, subject): states}, {(kind, subject): name}, {(kind, subject): detail}, restarts)."""
    grid = list(range(start, end + 1, STEP))
    states, details = house_states(grid, s)
    ap, ap_names, ap_details = ap_states(grid, s, s["ap_info_rows"], s["ap_known_rows"])
    states.update(ap)
    details.update(ap_details)
    sw, sw_details = switch_states(grid, s)
    states.update(sw)
    details.update(sw_details)
    states.update(radius_states(grid, s))
    names = {("ap_down", mac): name for mac, name in ap_names.items()}
    names.update({k: k[1] for k in sw})
    restarts = ap_restarts(list(range(start - FROZEN_S, end + 1, STEP)), s, ap_names, s["ap_info_rows"])
    return grid, states, names, details, restarts


def run(ctx):
    start, end = _window(ctx)
    s = gather(ctx.prometheus, start, end, ctx.settings.radius_container)
    grid, states, names, details, restarts = evaluate(s, start, end)
    stored = {}
    for inc in registry.incidents(ctx.db, _dt(start - MAX_LOOKBACK_S), kinds=list(KINDS)) or []:
        stored.setdefault((inc["kind"], inc["subject"]), []).append(dict(inc))
    opened = closed = 0
    for key, points in sorted(states.items()):
        detail = details.get(key)
        min_for = WEB_SWITCH_MIN_FOR if (detail or {}).get("source") == "web_switches" else None
        o, c = reconcile(ctx.db, key[0], key[1], names.get(key), points, grid, stored.get(key, []), detail, min_for)
        opened, closed = opened + o, closed + c
    for mac, name, boot, back in restarts:
        known = stored.get(("ap_restarted", mac), [])
        if any(abs(_ts(i["started"]) - boot) <= SAME_RESTART_S for i in known):
            continue
        registry.open_incident(ctx.db, "ap_restarted", mac, name, _dt(boot), "measured", {"seen_back": back})
        registry.close_incident(ctx.db, "ap_restarted", mac, _dt(max(back, boot)))
        known.append({"started": _dt(boot), "ended": _dt(back)})
        stored[("ap_restarted", mac)] = known
        opened += 1
    ctx.db.commit()
    if opened or closed:
        log.info("incidents: %d opened, %d closed", opened, closed)
    return {"evaluated_until": end, "last_run": {"opened": opened, "closed": closed}}
