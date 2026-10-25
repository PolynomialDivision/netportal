"""What the dashboard says about a device's Wi-Fi: findings from the data that is there.

A finding is {"code", "severity": info|warn|bad, "params", "basis", "evidence"}: params are what
the frontend's texts (i18n) fill in; basis is "measured" (it rests on samples, RADIUS packets,
UniFi events, registry rows) or "inferred" (on something derived: an association-start reset,
a change of the AP label, a correlation in time); evidence holds the values and events it rests
on, with the threshold that made it a finding. Each rule below names the data it reads and why
its threshold is where it is. A rule whose data is missing (null) says nothing: no data is not
a problem.

The inputs are a DEVICE (telemetry.dashboard), a summary (telemetry.device_status: reconnects
in 24 h and their times, the bands seen in 7 days, transmit attempts per second, seconds since
the association), the Wi-Fi data's age, and a context of the registry's and the house's data
(telemetry.live.context_for):

    {"now": Unix time, "expires": Unix time | None (the certificate),
     "rejects": [{"at", "reason", "mac"}] (RADIUS rejects of this device's serials or MACs, 24 h),
     "last_accept": Unix time | None, "mac_mode": hardware|random_fixed|rotating|None,
     "randomized_macs_30d": [mac], "ap_load": {"ap", "clients", "channel_util", "band"} | None,
     "coverage": {ap name: {"signal_dbm", "samples"}} (24 h), "disconnects": [{"at", "basis",
     "source", "cause"}] (24 h, merged), "roams_1h_measured": int | None,
     "incidents": [{"id", "kind", "subject", "subject_name", "started", "ended", "basis"}]}
"""

import datetime

SEVERITY_ORDER = {"bad": 0, "warn": 1, "info": 2}
MEASURED, INFERRED = "measured", "inferred"

# unpoller serves its last snapshot when the controller does not answer: older than this, the
# values are the past (the same limit as house-infra's UnifiMetricsStale alert).
STALE_AFTER_S = 600

# Signal (unpoller_client_radio_signal_db, dBm at the AP). -67 dBm is the usual target for calls
# and video; below -75 the rate drops and the device holds on to a far AP; below -80 the link
# itself becomes unreliable (retries, drop-outs). The house health score starts at -60.
WEAK_SIGNAL_WARN_DBM, WEAK_SIGNAL_BAD_DBM = -75, -80

# Signal-to-noise (wifi_client_snr_db = signal - noise). 25 dB and more is good (the health
# score's limit); below 20 dB only the slow rates work, below 15 dB hardly any. Only said when
# the signal itself is fine: then the noise (interference) is the cause, not the distance.
LOW_SNR_WARN_DB, LOW_SNR_BAD_DB = 20, 15

# Retries (wifi_client_retry_ratio: transmit retries / attempts over 5 min, by MAC). A few
# percent is normal; above 10 % latency is noticeable, above 25 % every fourth frame is sent
# again (the health score's retry penalty is full at 20 %). Only with at least
# RETRIES_MIN_ATTEMPTS transmit attempts per second: an idle device's ratio comes from a handful
# of frames (on 2026-10-25 17 of the 26 clients above 10 % sent fewer than 10 frames a second).
HIGH_RETRIES_WARN, HIGH_RETRIES_BAD, RETRIES_MIN_ATTEMPTS = 0.10, 0.25, 10

# Channel utilisation of the device's AP radio (wifi_client_channel_utilization_ratio). The
# health score penalises above 60 %; above 80 % the air is nearly always busy.
BUSY_CHANNEL_WARN, BUSY_CHANNEL_BAD = 0.60, 0.80

# AP or band changes in the last hour (roams_1h). A device that is carried around roams a few
# times; every 10 minutes or more often for a whole hour is ping-pong between two APs.
UNSTABLE_ROAMING_WARN, UNSTABLE_ROAMING_BAD = 6, 15

# New associations in 24 h (a reset of the association time, with or without a gap). Phones
# reconnect a few times a day (sleep, leaving the house); more than 5 is unusual, more than 20
# (about hourly) means the connection keeps dropping.
FREQUENT_DISCONNECTS_WARN, FREQUENT_DISCONNECTS_BAD = 6, 20

# Slow link: the device's receive link rate (the radio's rate, not internet speed) below this
# although the signal is good and the device is transferring data. At -65 dBm even a 2.4 GHz
# single-stream link runs at 50 Mbit/s or more; an idle device reports low rates, so it is only
# said while at least ACTIVE_BPS flow.
SLOW_LINK_BPS, SLOW_LINK_GOOD_SIGNAL_DBM, SLOW_LINK_ACTIVE_BPS = 20_000_000, -65, 1_000_000

# Stuck on 2.4 GHz: on 2.4 GHz for the whole last hour (no AP or band change, associated for an
# hour or more) with a signal good enough for 5 GHz (which reaches about 6-8 dB less far), and
# seen on 5 or 6 GHz in the last 7 days (so it can). Band steering moves most clients back and
# forth; only staying there an hour with a strong signal is worth a hint.
STUCK_2GHZ_MIN_SIGNAL_DBM, STUCK_2GHZ_MIN_S = -60, 3600

# RADIUS rejects of the device in 24 h (radius_auth, by its certificate's serial or its MACs).
# One or two happen when a profile is replaced or during a renewal; three and more mean the
# device keeps trying with something the server refuses, twenty (about hourly) that it tries all
# the time. A reject newer than the last accept is said at least as warn: the device cannot get
# in right now.
AUTH_FAILURES_WARN, AUTH_FAILURES_BAD = 3, 20

# The certificate (the newest one that is not retired): renewal hint from 30 days (as the
# dashboard's expires_soon), warn from 7 days, bad once expired (the device cannot log in).
CERT_EXPIRING_INFO_DAYS, CERT_EXPIRING_WARN_DAYS = 30, 7

# AP load while the device is on it (unpoller_device_stations of the AP, all SSIDs; the radio's
# channel utilisation, unpoller_device_radio_channel_utilization_total_ratio). The house's APs
# carried at most 8-24 clients each in the week to 2026-10-25; Wi-Fi 6 APs share the air well
# up to about 25 active clients per AP, beyond 40 every client waits. A busy channel with few
# clients is interference (busy_channel), not load: utilisation counts here only with at least
# AP_LOAD_MIN_CLIENTS clients.
AP_CLIENTS_WARN, AP_CLIENTS_BAD = 25, 40
AP_UTIL_WARN, AP_UTIL_BAD, AP_LOAD_MIN_CLIENTS = 0.80, 0.90, 10

# The APs' own warnings (ap_warnings; the admin pages' texts are ap_warn_<code>):
# - down: an open ap_down incident (then nothing else is said).
# - overloaded: as for a device on it (ap_load_level); else busy_channel: a radio's utilisation
#   at BUSY_CHANNEL_WARN or more (interference or neighbours, not the AP's own clients).
# - poor_coverage: a quarter or more of an AP's clients below WEAK_SIGNAL_WARN_DBM (-75): it
#   serves a place it does not cover well (or clients stick to it); only with at least
#   AP_WEAK_MIN_CLIENTS clients (one weak client of two is not a pattern).
# - restarted: up for less than a day (a restart drops every client; the incident says when).
# - uplink: the wired uplink below 1000 Mbit/s (a bad cable or port caps every client of the
#   AP; house-infra's ApUplinkDegraded alert uses the same limit).
AP_WEAK_SHARE_WARN, AP_WEAK_MIN_CLIENTS = 0.25, 4
AP_RESTARTED_S = 86400
AP_UPLINK_MIN_MBPS = 1000

# Poor coverage: the device's average signal over 24 h at every AP it used for at least
# COVERAGE_MIN_SAMPLES minutes is weak. Averages sit above the momentary values weak_signal
# looks at, so the limits are a few dB higher: -72 dBm on average means it is below -75 often.
POOR_COVERAGE_WARN_DBM, POOR_COVERAGE_BAD_DBM, COVERAGE_MIN_SAMPLES = -72, -78, 60

# Incident correlation: a disconnect from 2 minutes before an incident's start until 2 minutes
# after its end, at most INCIDENT_SPAN_MAX_S after the start (in a long outage a disconnect an
# hour later has other causes as likely).
INCIDENT_MARGIN_S, INCIDENT_SPAN_MAX_S = 120, 900

def finding(code, severity, basis=MEASURED, evidence=None, **params):
    """A finding; evidence defaults to the params (the values it rests on)."""
    return {"code": code, "severity": severity, "params": params, "basis": basis,
            "evidence": dict(params) if evidence is None else evidence}


def _below(value, warn, bad):
    """bad/warn/None for a value where lower is worse."""
    if value is None:
        return None
    if value <= bad:
        return "bad"
    if value <= warn:
        return "warn"
    return None


def _above(value, warn, bad):
    """bad/warn/None for a value where higher is worse."""
    if value is None:
        return None
    if value >= bad:
        return "bad"
    if value >= warn:
        return "warn"
    return None


def _worst(*levels):
    known = [lvl for lvl in levels if lvl]
    return min(known, key=lambda s: SEVERITY_ORDER[s]) if known else None


def _iso(t):
    return None if t is None else datetime.datetime.fromtimestamp(t, datetime.timezone.utc).isoformat(timespec="seconds")


def is_stale(wifi_data_age_s):
    """The Wi-Fi data is old or its age unknown (unpoller not scraped)."""
    return wifi_data_age_s is None or wifi_data_age_s > STALE_AFTER_S


def state_findings(device, wifi_data_age_s, telemetry="ok"):
    """never_connected, offline, stale_data: what is known about the device at all. The state is
    presence.py's (DEVICE.state, DEVICE.presence): offline only when presence says so (never
    for unknown or connecting), its evidence the presence's confirmation (confirmed_at,
    confirmed_by, reason, basis). stale_data only while Prometheus answers (telemetry "ok"): its
    Wi-Fi data is old, so what the page shows of the radio may be the past (an unreachable
    Prometheus is the page's telemetry state, not a finding): for an unknown state, and for one
    that RADIUS or UniFi's log decided while the snapshot is old."""
    state = device.get("state")
    if state == "never_connected":
        return [finding("never_connected", "info", evidence={"logins": 0})]
    out = []
    presence = device.get("presence") or {}
    from_radius = presence.get("confirmed_by") in ("radius_acct", "radius_auth", "unifi_syslog")
    if telemetry == "ok" and is_stale(wifi_data_age_s) and (state == "unknown" or from_radius):
        age = None if wifi_data_age_s is None else int(wifi_data_age_s)
        out.append(finding("stale_data", "warn", evidence={"age_s": age, "threshold_s": STALE_AFTER_S}, age_s=age))
    if state == "offline":
        out.append(finding("offline", "info", presence.get("basis") or MEASURED, evidence={
            "last_seen": device.get("last_seen"), "confirmed_at": presence.get("confirmed_at"),
            "confirmed_by": presence.get("confirmed_by"), "reason": presence.get("reason")},
            last_seen=device.get("last_seen")))
    return out


def radio_findings(device, summary=None):
    """weak_signal, low_snr, high_retries, busy_channel, slow_link: only while online."""
    if device.get("state") != "online":
        return []
    out = []
    signal = device.get("signal_dbm")
    weak = _below(signal, WEAK_SIGNAL_WARN_DBM, WEAK_SIGNAL_BAD_DBM)
    if weak:
        out.append(finding("weak_signal", weak, evidence={"signal_dbm": signal, "warn_dbm": WEAK_SIGNAL_WARN_DBM,
                                                          "bad_dbm": WEAK_SIGNAL_BAD_DBM}, signal_dbm=signal))
    snr = device.get("snr_db")
    low_snr = _below(snr, LOW_SNR_WARN_DB, LOW_SNR_BAD_DB)
    if low_snr and not weak:
        out.append(finding("low_snr", low_snr, evidence={"snr_db": snr, "noise_dbm": device.get("noise_dbm"),
                                                         "signal_dbm": signal, "warn_db": LOW_SNR_WARN_DB},
                           snr_db=snr, noise_dbm=device.get("noise_dbm")))
    retries = device.get("retry_ratio")
    attempts = (summary or {}).get("tx_attempts_per_s")
    high = _above(retries, HIGH_RETRIES_WARN, HIGH_RETRIES_BAD)
    if high and attempts is not None and attempts >= RETRIES_MIN_ATTEMPTS:
        out.append(finding("high_retries", high, evidence={"retry_ratio": retries, "tx_attempts_per_s": attempts,
                                                           "warn": HIGH_RETRIES_WARN}, retry_ratio=retries))
    util = device.get("channel_util")
    busy = _above(util, BUSY_CHANNEL_WARN, BUSY_CHANNEL_BAD)
    if busy:
        out.append(finding("busy_channel", busy, channel_util=util, channel=device.get("channel")))
    link, rx, tx = device.get("link_rx_bps"), device.get("rx_bps"), device.get("tx_bps")
    if (link is not None and signal is not None and rx is not None and tx is not None
            and link < SLOW_LINK_BPS and signal >= SLOW_LINK_GOOD_SIGNAL_DBM and rx + tx >= SLOW_LINK_ACTIVE_BPS):
        out.append(finding("slow_link", "warn", evidence={"link_rx_bps": link, "signal_dbm": signal,
                                                          "throughput_bps": rx + tx}, link_rx_bps=link, signal_dbm=signal))
    return out


def history_findings(device, summary, context=None):
    """unstable_roaming, frequent_disconnects, stuck_on_2ghz: from the recent history. The
    counts from Prometheus are inferred (AP label changes, association-start resets); measured
    roams and disconnects (UniFi events, accounting) count when they say more."""
    if device.get("state") not in ("online", "offline"):
        return []
    context = context or {}
    out = []
    roams = device.get("roams_1h")
    measured_roams = context.get("roams_1h_measured")
    level = _above(roams, UNSTABLE_ROAMING_WARN, UNSTABLE_ROAMING_BAD)
    measured_level = _above(measured_roams, UNSTABLE_ROAMING_WARN, UNSTABLE_ROAMING_BAD)
    if level or measured_level:
        basis = MEASURED if measured_level and (not level or (measured_roams or 0) >= (roams or 0)) else INFERRED
        count = measured_roams if basis == MEASURED else roams
        out.append(finding("unstable_roaming", _worst(level, measured_level), basis,
                           evidence={"roams_1h": roams, "roams_1h_measured": measured_roams,
                                     "warn": UNSTABLE_ROAMING_WARN}, roams_1h=count))
    reconnects = (summary or {}).get("reconnects_24h")
    measured = [d for d in context.get("disconnects") or () if d.get("basis") == MEASURED]
    level = _above(reconnects, FREQUENT_DISCONNECTS_WARN, FREQUENT_DISCONNECTS_BAD)
    measured_level = _above(len(measured) if measured else None, FREQUENT_DISCONNECTS_WARN, FREQUENT_DISCONNECTS_BAD)
    if level or measured_level:
        causes = {}
        for d in measured:
            if d.get("cause"):
                causes[d["cause"]] = causes.get(d["cause"], 0) + 1
        basis = MEASURED if measured_level and len(measured) >= (reconnects or 0) else INFERRED
        count = len(measured) if basis == MEASURED else reconnects
        out.append(finding("frequent_disconnects", _worst(level, measured_level), basis,
                           evidence={"reconnects_24h": reconnects, "disconnects_24h_measured": len(measured),
                                     "causes": causes, "warn": FREQUENT_DISCONNECTS_WARN},
                           reconnects_24h=count))
    bands = set((summary or {}).get("bands_7d") or ())
    signal, associated = device.get("signal_dbm"), (summary or {}).get("associated_s")
    if (device.get("state") == "online" and device.get("band") == "2.4" and bands & {"5", "6"}
            and roams == 0 and associated is not None and associated >= STUCK_2GHZ_MIN_S
            and signal is not None and signal >= STUCK_2GHZ_MIN_SIGNAL_DBM):
        out.append(finding("stuck_on_2ghz", "info", evidence={"bands_7d": sorted(bands), "signal_dbm": signal,
                                                              "associated_s": int(associated)},
                           bands_7d=sorted(bands)))
    return out


# --- the registry's and the house's data ------------------------------------------------------

def _reject_last(r):
    """A reject's latest try (a row of repeats: its last_at)."""
    return r.get("last_at") or r["at"]


def auth_findings(context):
    """auth_failures: RADIUS rejects of the device's certificate or MACs in 24 h. A reject row
    may stand for repeated tries ("count", the latest at "last_at"): counted as that many."""
    rejects = sorted(context.get("rejects") or (), key=_reject_last)
    if not rejects:
        return []
    count = sum(int(r.get("count") or 1) for r in rejects)
    last = rejects[-1]
    last_accept = context.get("last_accept")
    locked_out = last_accept is None or _reject_last(last) > last_accept
    level = _above(count, AUTH_FAILURES_WARN, AUTH_FAILURES_BAD)
    if locked_out:
        level = _worst(level, "warn")
    if not level:
        return []
    reasons = {}
    for r in rejects:
        reasons[r["reason"]] = reasons.get(r["reason"], 0) + int(r.get("count") or 1)
    return [finding("auth_failures", level, evidence={
        "count_24h": count, "reasons": reasons, "last_at": _iso(_reject_last(last)), "last_reason": last["reason"],
        "last_accept": _iso(last_accept), "locked_out": locked_out, "warn": AUTH_FAILURES_WARN},
        count=count, reason=last["reason"], last_at=_iso(_reject_last(last)))]


def cert_findings(context):
    """cert_expired, cert_expiring: the device's certificate (registry)."""
    expires, now = context.get("expires"), context.get("now")
    if expires is None or now is None:
        return []
    days_left = (expires - now) / 86400
    evidence = {"expires": _iso(expires), "days_left": int(days_left) if days_left >= 0 else -int(-days_left)}
    if expires <= now:
        return [finding("cert_expired", "bad", evidence=evidence, expires=_iso(expires))]
    if days_left <= CERT_EXPIRING_WARN_DAYS:
        return [finding("cert_expiring", "warn", evidence=evidence, expires=_iso(expires), days_left=int(days_left))]
    if days_left <= CERT_EXPIRING_INFO_DAYS:
        return [finding("cert_expiring", "info", evidence=evidence, expires=_iso(expires), days_left=int(days_left))]
    return []


def identity_findings(context):
    """rotating_mac: the device changes its private address (history only per address; a
    "fixed" private address keeps it whole and the diagnostics comparable)."""
    if context.get("mac_mode") != "rotating":
        return []
    macs = context.get("randomized_macs_30d") or []
    return [finding("rotating_mac", "info", evidence={"macs_30d": len(macs), "min_macs": 3}, macs_30d=len(macs))]


def ap_load_level(clients, util):
    """bad/warn/None of an AP's load: its clients, or its radio's utilisation with many clients."""
    if clients is None:
        return None
    level = _above(clients, AP_CLIENTS_WARN, AP_CLIENTS_BAD)
    if clients >= AP_LOAD_MIN_CLIENTS:
        level = _worst(level, _above(util, AP_UTIL_WARN, AP_UTIL_BAD))
    return level


def _ap_warning(code, severity, evidence, **params):
    return {"code": code, "severity": severity, "params": params, "basis": MEASURED, "evidence": evidence}


def ap_warnings(ap):
    """[{"code", "severity", "params", "basis", "evidence"}] of an AP (telemetry/admin.py's AP),
    codes down | overloaded | busy_channel | poor_coverage | restarted | uplink, the worst first."""
    if ap.get("state") == "down":
        return [_ap_warning("down", "bad", {"open_incidents": [i.get("id") for i in ap.get("open_incidents") or ()]})]
    out = []
    clients = ap.get("clients")
    utils = [r.get("channel_util") for r in ap.get("radios") or () if r.get("channel_util") is not None]
    util = max(utils) if utils else None
    level = ap_load_level(clients, util)
    if level:
        out.append(_ap_warning("overloaded", level, {"clients": clients, "channel_util": util,
                                                     "clients_warn": AP_CLIENTS_WARN, "util_warn": AP_UTIL_WARN},
                               clients=clients, channel_util=util))
    elif util is not None and util >= BUSY_CHANNEL_WARN:
        out.append(_ap_warning("busy_channel", "warn", {"channel_util": util, "threshold": BUSY_CHANNEL_WARN},
                               channel_util=util))
    weak = ap.get("weak_clients")
    if clients and weak is not None and clients >= AP_WEAK_MIN_CLIENTS and weak / clients >= AP_WEAK_SHARE_WARN:
        share = round(weak / clients, 3)
        out.append(_ap_warning("poor_coverage", "warn", {"weak_clients": weak, "clients": clients, "share": share,
                                                         "threshold": AP_WEAK_SHARE_WARN,
                                                         "signal_dbm": WEAK_SIGNAL_WARN_DBM},
                               share=share, weak_clients=weak, clients=clients))
    uptime = ap.get("uptime_s")
    if uptime is not None and uptime < AP_RESTARTED_S:
        out.append(_ap_warning("restarted", "info", {"uptime_s": uptime, "threshold_s": AP_RESTARTED_S},
                               uptime_s=uptime))
    uplink = ap.get("uplink_mbps")
    if uplink is not None and uplink < AP_UPLINK_MIN_MBPS:
        out.append(_ap_warning("uplink", "warn", {"uplink_mbps": uplink, "threshold_mbps": AP_UPLINK_MIN_MBPS},
                               uplink_mbps=uplink))
    return sorted(out, key=lambda f: SEVERITY_ORDER[f["severity"]])


def load_findings(device, context):
    """ap_overloaded: many clients on the device's AP (or a full channel with many clients)."""
    load = context.get("ap_load")
    if device.get("state") != "online" or not load or load.get("clients") is None:
        return []
    clients, util = load["clients"], load.get("channel_util")
    level = ap_load_level(clients, util)
    if not level:
        return []
    return [finding("ap_overloaded", level, evidence={"ap": load.get("ap"), "clients": clients, "channel_util": util,
                                                      "band": load.get("band"), "clients_warn": AP_CLIENTS_WARN,
                                                      "util_warn": AP_UTIL_WARN},
                    ap=load.get("ap"), clients=clients, channel_util=util)]


def coverage_findings(device, context):
    """poor_coverage: weak on average at every AP the device used in 24 h (a gap at its place)."""
    if device.get("state") not in ("online", "offline"):
        return []
    used = {ap: c for ap, c in (context.get("coverage") or {}).items()
            if c.get("signal_dbm") is not None and (c.get("samples") or 0) >= COVERAGE_MIN_SAMPLES}
    if not used:
        return []
    best = max(c["signal_dbm"] for c in used.values())
    level = _below(best, POOR_COVERAGE_WARN_DBM, POOR_COVERAGE_BAD_DBM)
    if not level:
        return []
    return [finding("poor_coverage", level, evidence={
        "aps": {ap: round(c["signal_dbm"], 1) for ap, c in sorted(used.items())},
        "minutes": {ap: int(c["samples"]) for ap, c in sorted(used.items())}, "warn_dbm": POOR_COVERAGE_WARN_DBM},
        best_signal_dbm=round(best, 1), aps=len(used))]


def incident_findings(context):
    """incident_correlated (inferred): disconnects of the device around an incident of its AP,
    the house's router or internet. One finding, about the latest such incident."""
    disconnects = sorted(d["at"] for d in context.get("disconnects") or ())
    now = context.get("now")
    hits = []
    for inc in context.get("incidents") or ():
        started = inc["started"]
        end = inc["ended"] if inc.get("ended") is not None else now if now is not None else started
        end = min(end, started + INCIDENT_SPAN_MAX_S)
        times = [t for t in disconnects if started - INCIDENT_MARGIN_S <= t <= end + INCIDENT_MARGIN_S]
        if times:
            hits.append((started, inc, times))
    if not hits:
        return []
    started, inc, times = max(hits, key=lambda h: h[0])
    incident = {"id": inc.get("id"), "kind": inc["kind"], "subject": inc.get("subject"),
                "subject_name": inc.get("subject_name"), "started": _iso(inc["started"]), "ended": _iso(inc.get("ended")),
                "basis": inc.get("basis")}
    return [finding("incident_correlated", "info", INFERRED,
                    evidence={"incident": incident, "disconnects": [_iso(t) for t in times],
                              "incidents_correlated": len(hits), "margin_s": INCIDENT_MARGIN_S},
                    kind=inc["kind"], subject_name=inc.get("subject_name"), started=_iso(inc["started"]),
                    disconnects=len(times))]


def findings(device, summary=None, wifi_data_age_s=None, telemetry="ok", context=None):
    """Every finding for a device, the worst first."""
    context = context or {}
    out = state_findings(device, wifi_data_age_s, telemetry)
    if device.get("state") != "never_connected":
        # the radio and the AP's load only from a fresh snapshot (a frozen one is the past)
        live = not (wifi_data_age_s is not None and is_stale(wifi_data_age_s))
        out += (radio_findings(device, summary) if live else []) + history_findings(device, summary, context)
        out += identity_findings(context) + (load_findings(device, context) if live else [])
        out += coverage_findings(device, context) + incident_findings(context)
    out += auth_findings(context) + cert_findings(context)
    return sorted(out, key=lambda f: SEVERITY_ORDER[f["severity"]])
