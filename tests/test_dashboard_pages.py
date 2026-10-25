"""The "My devices" pages (devices.html, device.html, admin.html) with Flask's test client:
registry mocked, the dashboard data built here in the shapes of the JSON API (/api/devices,
/api/devices/<id>/history, /api/admin/devices). The pages must be complete without JavaScript,
in every language, for every device state and telemetry state, and keep the strict CSP (no
inline code: the scripts' texts and data are JSON blocks). Example values only."""

import datetime as dt
import html
import json
import re
import sys
import unittest
import uuid
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from flask import render_template  # noqa: E402
from markupsafe import escape  # noqa: E402
from test_web import FakeDb, example_settings  # noqa: E402

from netportal import i18n, web  # noqa: E402

NOW = dt.datetime(2026, 10, 25, 12, 0, tzinfo=dt.UTC)
RESIDENT_SUB, ADMIN_SUB = "sub-resident", "sub-admin"
IDS = [str(uuid.UUID(int=i, version=4)) for i in range(1, 6)]


def iso(delta_s=0):
    return (NOW - dt.timedelta(seconds=delta_s)).isoformat()


def ap(name):
    """ap-<house>-<floor>-<spot> as the backend splits it (unknown names: house None)."""
    parts = name.split("-")
    if len(parts) == 4 and parts[0] == "ap":
        return {"name": name, "house": parts[1], "floor": int(parts[2]), "spot": parts[3]}
    return {"name": name, "house": None, "floor": None, "spot": None}


def device(i, name, state, **values):
    base = {"id": IDS[i], "name": name, "platform": "android", "policy": "residents", "created": iso(40 * 86400),
            "expires": iso(-300 * 86400), "expires_soon": False, "revoked": False,
            "mac": "02:00:00:00:00:%02x" % i, "state": state, "last_seen": None, "since": None, "ap": None,
            "ssid": None, "band": None, "channel": None, "proto": None, "ip": None, "signal_dbm": None,
            "noise_dbm": None, "snr_db": None, "health": None, "retry_ratio": None, "channel_util": None,
            "link_rx_bps": None, "link_tx_bps": None, "rx_bps": None, "tx_bps": None, "rx_24h_bytes": None,
            "tx_24h_bytes": None, "roams_1h": None, "diagnostics": []}
    base.update(values)
    return base


def sample_devices():
    return [
        device(0, "Pixel 8", "online", last_seen=iso(), since=iso(8130), ap=ap("ap-scharni-2-corner"),
               ssid="Example", band="5", channel=36, proto="ax", ip="10.30.0.23", signal_dbm=-58, noise_dbm=-95,
               snr_db=37, health=88, retry_ratio=0.03, channel_util=0.21, link_rx_bps=866_000_000,
               link_tx_bps=720_000_000, rx_bps=2_400_000, tx_bps=180_000, rx_24h_bytes=1_830_000_000,
               tx_24h_bytes=221_000_000, roams_1h=0),
        device(1, "MacBook Air", "online", platform="apple-mac", last_seen=iso(), since=iso(3 * 86400 + 4000),
               ap=ap("ap-colbe-0-far"), ssid="Example", band="2.4", channel=6, proto="n", ip="10.30.0.41",
               signal_dbm=-79, noise_dbm=-88, snr_db=9, health=41, retry_ratio=0.24, channel_util=0.72,
               link_rx_bps=52_000_000, link_tx_bps=26_000_000, rx_bps=310_000, tx_bps=41_000,
               rx_24h_bytes=640_000_000, tx_24h_bytes=95_000_000, roams_1h=7,
               diagnostics=[{"code": "weak_signal", "severity": "warn", "params": {"signal_dbm": -79}},
                            {"code": "high_retries", "severity": "bad", "params": {"retry_ratio": 0.24}},
                            {"code": "busy_channel", "severity": "warn", "params": {"channel_util": 0.72}},
                            {"code": "unstable_roaming", "severity": "warn", "params": {"roams_1h": 7}},
                            {"code": "stuck_on_2ghz", "severity": "info", "params": {}}]),
        device(2, "iPad", "offline", platform="apple", last_seen=iso(3 * 3600 + 600), ssid="Example",
               expires=iso(-12 * 86400), expires_soon=True,
               rx_24h_bytes=120_000_000, tx_24h_bytes=8_000_000,
               diagnostics=[{"code": "offline", "severity": "info", "params": {}},
                            {"code": "frequent_disconnects", "severity": "warn", "params": {"reconnects_24h": 6}}]),
        device(3, "Kindle", "never_connected", platform="eap-config", mac=None,
               diagnostics=[{"code": "never_connected", "severity": "info", "params": {}}]),
        device(4, "Sensor <&> \"Werkstatt\"", "online", platform="letswifi", last_seen=iso(), since=iso(30),
               ap=ap("ap-scharni-0-schlaglicht"), band="6", channel=37, proto="ax", signal_dbm=-66, health=72,
               diagnostics=[{"code": "slow_link", "severity": "warn", "params": {"link_rx_bps": 6_500_000, "signal_dbm": -66}},
                            {"code": "low_snr", "severity": "warn", "params": {"snr_db": 14}},
                            {"code": "stale_data", "severity": "info", "params": {"age_s": 900}}]),
    ]


def sample_house(**overrides):
    house = {"internet": "ok", "internet_loss_ratio": 0.0, "internet_rtt_ms": 11.4, "dns": "ok", "router": "ok",
             "speedtest": {"download_bps": 248_000_000, "upload_bps": 41_500_000, "ping_ms": 9.8, "at": iso(5400)},
             "wifi_data_age_s": 45}
    house.update(overrides)
    return house


def sample_dashboard(telemetry="ok", devices=None, admin=False, **overrides):
    payload = {"generated_at": iso(), "telemetry": telemetry, "stale": False, "house": sample_house(),
               "devices": sample_devices() if devices is None else devices}
    if telemetry != "ok":
        payload["house"] = sample_house(internet="unknown", dns="unknown", router="unknown", speedtest=None,
                                        internet_rtt_ms=None, internet_loss_ratio=None, wifi_data_age_s=None)
        for d in payload["devices"]:
            for key in ("signal_dbm", "health", "rx_bps", "tx_bps", "link_rx_bps", "link_tx_bps", "ap", "band",
                        "channel", "proto", "rx_24h_bytes", "tx_24h_bytes", "since"):
                d[key] = None
            if d["state"] == "online":
                d["state"] = "unknown"
            d["diagnostics"] = [f for f in d["diagnostics"] if f["code"] == "never_connected"]
    if admin:
        owners = [("Nick Example", "nick"), ("Fia Example", "fia")]
        for i, d in enumerate(payload["devices"]):
            d["owner"] = {"display": owners[i % 2][0], "username": owners[i % 2][1]}
    payload.update(overrides)
    return payload


def sample_history(range_="24h"):
    """A day (or more) of 5-minute samples: two connections, a roam, a band change and gaps."""
    import math
    span = {"24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400}[range_]
    step = {"24h": 300, "7d": 1800, "30d": 7200}[range_]
    end = int(NOW.timestamp())
    start = end - span
    series = {k: [] for k in ("signal_dbm", "health", "rx_bps", "tx_bps", "online", "link_rx_bps", "link_tx_bps")}
    off_from, off_to = end - int(span * 0.62), end - int(span * 0.55)       # a disconnect
    hole_from, hole_to = end - int(span * 0.30), end - int(span * 0.28)     # no data at all (scrape gap)
    for t in range(start, end + 1, step):
        if hole_from <= t < hole_to:
            continue
        online = not (off_from <= t < off_to)
        phase = (t - start) / span
        series["online"].append([t, 1 if online else 0])
        if not online:
            for k in ("signal_dbm", "health", "rx_bps", "tx_bps", "link_rx_bps", "link_tx_bps"):
                series[k].append([t, None])
            continue
        weak = phase > 0.8                                                   # moved to a far room
        sig = (-74 if weak else -58) + 4 * math.sin(phase * 40)
        series["signal_dbm"].append([t, round(sig, 1)])
        series["health"].append([t, round(max(0, min(100, 100 + (sig + 55) * 2.2)))])
        busy = 0.5 + 0.5 * math.sin(phase * 12)
        series["rx_bps"].append([t, round(busy * 4e6 + 1e5)])
        series["tx_bps"].append([t, round(busy * 6e5 + 2e4)])
        series["link_rx_bps"].append([t, 173_000_000 if weak else 866_000_000])
        series["link_tx_bps"].append([t, 144_000_000 if weak else 720_000_000])
    first = start - 3600
    timeline = [
        {"kind": "connected", "at": dt.datetime.fromtimestamp(first, dt.UTC).isoformat(),
         "ap": ap("ap-scharni-2-corner"), "band": "5", "from_ap": None, "from_band": None,
         "duration_s": off_from - first},
        {"kind": "disconnected", "at": dt.datetime.fromtimestamp(off_from, dt.UTC).isoformat(),
         "ap": ap("ap-scharni-2-corner"), "band": "5", "from_ap": None, "from_band": None, "duration_s": off_to - off_from},
        {"kind": "connected", "at": dt.datetime.fromtimestamp(off_to, dt.UTC).isoformat(),
         "ap": ap("ap-scharni-1-middle"), "band": "5", "from_ap": None, "from_band": None, "duration_s": None},
        {"kind": "roamed", "at": dt.datetime.fromtimestamp(end - int(span * 0.2), dt.UTC).isoformat(),
         "ap": ap("ap-colbe-0-far"), "band": "5", "from_ap": ap("ap-scharni-1-middle"), "from_band": "5",
         "duration_s": None},
        {"kind": "band_changed", "at": dt.datetime.fromtimestamp(end - int(span * 0.1), dt.UTC).isoformat(),
         "ap": ap("ap-colbe-0-far"), "band": "2.4", "from_ap": ap("ap-colbe-0-far"), "from_band": "5",
         "duration_s": None},
    ]
    return {"range": range_, "step_s": step, "start": start, "end": end, "telemetry": "ok", "series": series,
            "timeline": timeline, "timeline_truncated": False}


# --- telemetry v2 samples (docs/TELEMETRY.md; the shapes of telemetry/, diagnostics.py and the
# admin API as their docstrings describe them) -------------------------------------------------

def finding(code, severity, basis="measured", evidence=None, **params):
    """diagnostics.finding: evidence defaults to the params."""
    return {"code": code, "severity": severity, "params": params, "basis": basis,
            "evidence": dict(params) if evidence is None else evidence}


def v2_devices():
    """sample_devices with v2's identity, login, sources and evidence-based findings."""
    devices = sample_devices()
    pixel, mac, ipad, kindle, sensor = devices
    pixel.update(mac_mode="random_fixed", sources=["radius_auth", "radius_acct", "unifi_syslog", "prometheus"],
                 last_auth={"at": iso(1500), "result": "accept", "reason": "ok"},
                 macs=[{"mac": "02:00:00:00:00:00", "randomized": True, "first_seen": iso(40 * 86400),
                        "last_seen": iso(60), "current": True}])
    mac.update(mac_mode="hardware", sources=["radius_auth", "prometheus"],
               last_auth={"at": iso(4000), "result": "accept", "reason": "ok"},
               macs=[{"mac": "a4:83:e7:00:00:01", "randomized": False, "first_seen": iso(90 * 86400),
                      "last_seen": iso(30), "current": True}],
               diagnostics=[
                   finding("high_retries", "bad", evidence={"retry_ratio": 0.24, "tx_attempts_per_s": 41.5, "warn": 0.1},
                           retry_ratio=0.24),
                   finding("weak_signal", "warn", evidence={"signal_dbm": -79, "warn_dbm": -75, "bad_dbm": -80},
                           signal_dbm=-79),
                   finding("poor_coverage", "warn", evidence={"aps": {"ap-colbe-0-far": -77.4, "ap-colbe-1-middle": -80.2},
                                                              "minutes": {"ap-colbe-0-far": 900}, "warn_dbm": -72},
                           best_signal_dbm=-77.4, aps=2),
                   finding("ap_overloaded", "warn", evidence={"ap": "ap-colbe-0-far", "clients": 31, "channel_util": 0.84,
                                                              "band": "2.4", "clients_warn": 25, "util_warn": 0.8},
                           ap="ap-colbe-0-far", clients=31, channel_util=0.84),
                   finding("unstable_roaming", "warn", "inferred",
                           evidence={"roams_1h": 7, "roams_1h_measured": None, "warn": 6}, roams_1h=7),
                   finding("stuck_on_2ghz", "info", evidence={"bands_7d": ["2.4", "5"], "signal_dbm": -58,
                                                              "associated_s": 5400}, bands_7d=["2.4", "5"])])
    ipad.update(mac_mode="rotating", sources=["radius_auth", "radius_acct", "unifi_syslog", "prometheus", "device_mac"],
                last_auth={"at": iso(3 * 3600 + 900), "result": "accept", "reason": "ok"},
                macs=[{"mac": "06:11:22:33:44:%02x" % i, "randomized": True, "first_seen": iso((i + 1) * 7 * 86400),
                       "last_seen": iso(i * 7 * 86400 + 3 * 3600), "current": i == 0} for i in range(4)],
                diagnostics=[
                    finding("frequent_disconnects", "warn", evidence={
                        "reconnects_24h": 8, "disconnects_24h_measured": 7, "warn": 6,
                        "causes": {"Lost-Carrier": 5, "User-Request": 2}}, reconnects_24h=7),
                    finding("incident_correlated", "info", "inferred", evidence={
                        "incident": {"id": 7, "kind": "ap_restarted", "subject": "d0:21:f9:00:00:01",
                                     "subject_name": "ap-scharni-2-corner", "started": iso(5 * 3600), "ended": iso(5 * 3600 - 180),
                                     "basis": "measured"},
                        "disconnects": [iso(5 * 3600 - 40)], "incidents_correlated": 1, "margin_s": 120},
                        kind="ap_restarted", subject_name="ap-scharni-2-corner", started=iso(5 * 3600), disconnects=1),
                    finding("rotating_mac", "info", evidence={"macs_30d": 4, "min_macs": 3}, macs_30d=4),
                    finding("cert_expiring", "warn", evidence={"expires": iso(-6 * 86400), "days_left": 6},
                            expires=iso(-6 * 86400), days_left=6),
                    finding("offline", "info", last_seen=iso(3 * 3600 + 600))])
    kindle.update(mac_mode="hardware", sources=["radius_auth"],
                  last_auth={"at": iso(420), "result": "reject", "reason": "unknown_cert"},
                  macs=[{"mac": "f0:27:2d:00:00:03", "randomized": False, "first_seen": iso(2 * 86400),
                         "last_seen": iso(420), "current": True}],
                  diagnostics=[
                      finding("auth_failures", "bad", evidence={
                          "count_24h": 23, "reasons": {"unknown_cert": 23}, "last_at": iso(420),
                          "last_reason": "unknown_cert", "last_accept": None, "locked_out": True, "warn": 3},
                          count=23, reason="unknown_cert", last_at=iso(420)),
                      finding("never_connected", "info", evidence={"logins": 0})])
    return devices


def v2_timeline(start, end, admin=False):
    """Every event kind from every source, measured and inferred, in the API's EVENT shape."""
    span = end - start

    def at(fraction):
        return dt.datetime.fromtimestamp(int(start + span * fraction), dt.UTC).isoformat()

    def e(kind, fraction, source, basis="measured", ap_name=None, band=None, from_ap=None, from_band=None,
          duration_s=None, mac="02:00:00:00:00:00", sources=None, **detail):
        return {"kind": kind, "at": at(fraction), "source": source, "sources": sources or [source], "basis": basis,
                "ap": ap(ap_name) if ap_name else None, "band": band, "from_ap": ap(from_ap) if from_ap else None,
                "from_band": from_band, "mac": mac, "duration_s": duration_s, "detail": detail}

    return [
        e("authenticated", 0.02, "radius_auth", ap_name="ap-scharni-2-corner", band="5", reason="ok",
          bssid="d2:21:f9:00:00:11", ssid="Example"),
        e("connected", 0.021, "unifi_syslog", ap_name="ap-scharni-2-corner", band="5", sources=["unifi_syslog", "radius_acct"],
          rssi=-58, channel=36),
        e("roamed", 0.2, "radius_acct", ap_name="ap-scharni-1-middle", band="5", from_ap="ap-scharni-2-corner",
          from_band="5", from_cause="Lost-Service", gap_s=4),
        e("band_changed", 0.3, "prometheus", "inferred", ap_name="ap-scharni-1-middle", band="2.4",
          from_ap="ap-scharni-1-middle", from_band="5"),
        e("incident", 0.38, "incident", ap_name="ap-scharni-1-middle", duration_s=240,
          id=7, incident="ap_restarted", subject="d0:21:f9:00:00:01", subject_name="ap-scharni-1-middle", ended=at(0.385),
          open=False),
        e("session_ended", 0.381, "radius_acct", ap_name="ap-scharni-1-middle", band="2.4", duration_s=14_000,
          cause="NAS-Reboot", session_time_s=14_000, rx_bytes=812_000_000, tx_bytes=96_000_000),
        e("disconnected", 0.45, "prometheus", "inferred", ap_name="ap-scharni-1-middle", band="2.4", duration_s=3000),
        e("auth_rejected", 0.5, "radius_auth", reason="retired", bssid="d2:21:f9:00:00:12", ssid="Example"),
        e("reconnected", 0.55, "unifi_syslog", ap_name="ap-colbe-0-far", band="5", sources=["unifi_syslog", "prometheus"]),
        e("mac_changed", 0.7, "device_mac", "inferred", mac="06:11:22:33:44:01", from_mac="02:00:00:00:00:00",
          randomized=True),
        e("incident", 0.9, "incident", duration_s=None, id=9, incident="internet_degraded", subject="",
          subject_name=None, ended=None, open=True),
    ]


def v2_history(range_="24h", admin=False):
    """A /history payload of telemetry v2: ranges up to 90 days in steps, 1y and all in days."""
    if range_ in ("24h", "7d", "30d"):
        payload = sample_history(range_)
    else:
        payload = None
    end = int(NOW.timestamp())
    if payload is None and range_ == "90d":
        payload = sample_history("30d")
        payload.update(range="90d", step_s=21600, start=end - 90 * 86400)
    if payload is None:                                   # day steps from device_day
        import math
        days = 365 if range_ == "1y" else 420
        start = end - days * 86400
        series = {k: [] for k in ("signal_dbm", "health", "rx_bps", "tx_bps", "link_rx_bps", "link_tx_bps", "snr_db",
                                  "retry_ratio", "online")}
        for i in range(days):
            t = start + i * 86400
            gone = 150 <= i < 165 or (range_ == "all" and i < 40)          # away for two weeks; before the device
            for k in series:
                series[k].append([t, None])
            if gone:
                continue
            wave = math.sin(i / 9)
            series["signal_dbm"][-1][1] = round(-63 + 6 * wave, 1)
            series["health"][-1][1] = round(78 + 12 * wave, 1)
            series["rx_bps"][-1][1] = int((1.2e9 + 0.8e9 * (1 + math.sin(i / 3))) * 8 / 86400)
            series["tx_bps"][-1][1] = int((1.5e8 + 1e8 * (1 + math.cos(i / 4))) * 8 / 86400)
            series["link_rx_bps"][-1][1] = int(520e6 + 200e6 * wave)
            series["snr_db"][-1][1] = round(31 + 5 * wave, 1)
            series["retry_ratio"][-1][1] = round(0.05 + 0.03 * (1 - wave), 4)
            series["online"][-1][1] = round(min(1, 0.55 + 0.35 * (1 + math.sin(i / 5)) / 2), 3)
        payload = {"range": range_, "step_s": 86400, "step": "day", "start": start, "end": end, "telemetry": "ok",
                   "series": series, "timeline": [], "timeline_truncated": False, "sources": ["device_day"]}
    payload.setdefault("step", None)
    payload["timeline"] = v2_timeline(payload["start"], payload["end"], admin) if payload["step"] != "day" else \
        v2_timeline(payload["end"] - 90 * 86400, payload["end"], admin)
    payload["sources"] = ["radius_auth", "radius_acct", "unifi_syslog", "prometheus", "device_mac", "incident"]
    if payload["step"] != "day":
        import math
        grid = [p[0] for p in payload["series"]["online"]]
        payload["series"]["snr_db"] = [[t, None if v is None else round(v + 95, 1)] for t, v in payload["series"]["signal_dbm"]]
        payload["series"]["retry_ratio"] = [[t, round(0.04 + 0.03 * math.sin(i / 7), 4)] for i, t in enumerate(grid)]
    return payload


AP_MACS = {"ap-scharni-2-corner": "d0:21:f9:00:00:01", "ap-scharni-1-middle": "d0:21:f9:00:00:02",
           "ap-colbe-0-far": "d0:21:f9:00:00:03", "ap-scharni-0-schlaglicht": "d0:21:f9:00:00:04"}


def ap_days(name, days=30, seed=0):
    """ap_day rows of the last days (newest last)."""
    import math
    today = NOW.date()
    out = []
    for i in range(days):
        day = today - dt.timedelta(days=days - 1 - i)
        w = math.sin((i + seed) / 4)
        out.append({"ap_mac": AP_MACS[name], "day": day.isoformat(), "ap_name": name,
                    "clients_avg": round(9 + 5 * w + seed, 1), "clients_max": int(16 + 8 * w + seed * 2),
                    "channel_util_avg": {"ng": round(0.45 + 0.2 * w, 3), "na": round(0.18 + 0.1 * w, 3)},
                    "weak_client_share": round(max(0, 0.08 + 0.06 * w + seed * 0.05), 3),
                    "restarts": 1 if (i + seed) % 11 == 0 else 0, "down_s": 180 if (i + seed) % 11 == 0 else 0})
    return out


def sample_aps(with_days=True):
    """APs as telemetry/admin.py shows them (OVERVIEW "aps"; APS with "days")."""
    def one(name, state, clients, radios, weak, uptime, seed, uplink=2500, signal=-63.5, open_incidents=()):
        a = dict(ap(name), mac=AP_MACS[name], ip="10.10.0.%d" % (21 + seed), model="U7 Pro", state=state, clients=clients,
                 clients_house=None if clients is None else max(0, clients - 3), weak_clients=weak,
                 signal_avg_dbm=None if clients is None else signal, uptime_s=uptime, uplink_mbps=uplink,
                 radios=radios, open_incidents=list(open_incidents))
        if with_days:
            a["days"] = ap_days(name, days=7, seed=seed)
        return a
    down = {"id": 8, "kind": "ap_down", "subject": AP_MACS["ap-scharni-0-schlaglicht"], "subject_name": "ap-scharni-0-schlaglicht",
            "started": iso(2 * 3600), "ended": None, "open": True, "duration_s": 7200, "basis": "measured", "detail": {}}
    return [
        one("ap-scharni-2-corner", "ok", 14, [{"radio": "na", "band": "5", "channel": 36, "clients": 10, "channel_util": 0.21},
                                              {"radio": "ng", "band": "2.4", "channel": 1, "clients": 4, "channel_util": 0.52}],
            1, 9 * 86400, 0),
        one("ap-scharni-1-middle", "ok", 9, [{"radio": "na", "band": "5", "channel": 52, "clients": 7, "channel_util": 0.12},
                                             {"radio": "ng", "band": "2.4", "channel": 6, "clients": 2, "channel_util": 0.38}],
            0, 3 * 3600, 1, uplink=100),
        one("ap-colbe-0-far", "ok", 31, [{"radio": "na", "band": "5", "channel": 100, "clients": 12, "channel_util": 0.64},
                                         {"radio": "ng", "band": "2.4", "channel": 11, "clients": 19, "channel_util": 0.86}],
            10, 22 * 86400, 2, signal=-71.2),
        one("ap-scharni-0-schlaglicht", "down", None, [], None, None, 3, uplink=None, open_incidents=[down]),
    ]


def sample_incidents():
    """INCIDENT rows (telemetry/admin.py public_incident) plus "devices": the ones that dropped
    out at the time (asked of the backend; the pages show them when they are there)."""
    def inc(i, kind, subject, name, start_s, end_s, basis="measured", devices=(), **detail):
        return {"id": i, "kind": kind, "subject": subject, "subject_name": name, "started": iso(start_s),
                "ended": iso(end_s) if end_s is not None else None, "open": end_s is None,
                "duration_s": int(start_s - (end_s or 0)), "basis": basis, "detail": detail,
                "devices": [{"id": IDS[d], "name": sample_devices()[d]["name"],
                             "owner": {"display": "Resi Example", "username": "resi"}} for d in devices]}
    return [
        inc(9, "internet_degraded", "", None, 1800, None, loss_ratio=0.07, rtt_ms=84),
        inc(8, "ap_down", AP_MACS["ap-scharni-0-schlaglicht"], "ap-scharni-0-schlaglicht", 2 * 3600, None,
            devices=(4,), last_seen=iso(2 * 3600)),
        inc(7, "ap_restarted", AP_MACS["ap-scharni-2-corner"], "ap-scharni-2-corner", 5 * 3600, 5 * 3600 - 180,
            devices=(0, 2), uptime_before_s=812_000),
        inc(6, "switch_port_down", "sw-keller/7", "sw-keller port 7", 26 * 3600, 26 * 3600 - 600, "inferred"),
        inc(5, "dns_down", "", None, 3 * 86400, 3 * 86400 - 300),
        inc(4, "radius_down", "", None, 6 * 86400, 6 * 86400 - 120, devices=(1, 2, 3)),
    ]


def sample_overview():
    """OVERVIEW (telemetry/admin.py)."""
    incidents = sample_incidents()
    jobs = [{"name": "unifi_events", "last_success": iso(100), "last_attempt": iso(100), "last_error": None,
             "duration_s": 0.84, "ok": True, "age_s": 100, "cursor": {}},
            {"name": "incidents", "last_success": iso(5400), "last_attempt": iso(80),
             "last_error": "Prometheus: timeout after 4.0 s <query>", "duration_s": 4.02, "ok": False, "age_s": 5400, "cursor": {}},
            {"name": "rollup", "last_success": iso(1500), "last_attempt": iso(1500), "last_error": None,
             "duration_s": 12.7, "ok": True, "age_s": 1500, "cursor": {}},
            {"name": "prune", "last_success": None, "last_attempt": None, "last_error": None, "duration_s": None,
             "ok": True, "age_s": None, "cursor": {}}]
    return {"generated_at": iso(), "telemetry": "ok", "stale": False, "house": sample_house(),
            "incidents": {"available": True, "open": [i for i in incidents if i["open"]],
                          "recent": [i for i in incidents if not i["open"]], "counts_7d": {"ap_down": 1}},
            "aps": sample_aps(with_days=False),
            "auth": {"available": True, "since": iso(86400), "count": 27, "truncated": False, "devices": 2, "macs": 3,
                     "by_reason": {"unknown_cert": 23, "retired": 3, "not_eap": 1},
                     "recent": [
                         {"at": iso(420), "reason": "unknown_cert", "serial": "4f1c2a9b77e0", "device_id": IDS[3],
                          "device_name": "Kindle", "owner": {"display": "Resi Example", "username": "resi"},
                          "mac": "f0:27:2d:00:00:03", "bssid": "d2:21:f9:00:00:11", "ssid": "Example", "nas_ip": "10.10.0.21",
                          "ap": dict(ap("ap-scharni-2-corner"), mac=AP_MACS["ap-scharni-2-corner"]),
                          "count": 4, "last_at": iso(300)},
                         {"at": iso(5400), "reason": "retired", "serial": "77aa01", "device_id": IDS[2],
                          "device_name": "iPad", "owner": {"display": "Resi Example", "username": "resi"},
                          "mac": "06:11:22:33:44:00", "bssid": None, "ssid": "Example", "nas_ip": "10.10.0.22", "ap": None},
                         {"at": iso(20000), "reason": "not_eap", "serial": None, "device_id": None, "device_name": None,
                          "owner": None, "mac": "3c:22:fb:00:00:09", "bssid": "d2:21:f9:00:00:31", "ssid": "Example",
                          "nas_ip": "10.10.0.23", "ap": None}]},
            "jobs": jobs, "jobs_available": True,
            "freshness": {"wifi_data_age_s": 45, "prometheus": "ok", "jobs_ok": False, "oldest_job_success_age_s": 5400}}


def sample_raw(device_id=IDS[0]):
    """RAW (telemetry/admin.py): every source row of the device in a time span."""
    return {"device": {"id": device_id, "name": "Pixel 8", "revoked": False, "owner": {"username": "resi", "display": "Resi Example"}},
            "from": iso(86400), "to": iso(),
            "windows": [{"mac": "02:00:00:00:00:00", "first_seen": iso(40 * 86400), "last_seen": iso(60), "randomized": True,
                         "auth_count": 212, "current": True, "start": iso(40 * 86400), "end": None},
                        {"mac": "06:11:22:33:44:01", "first_seen": iso(60 * 86400), "last_seen": iso(41 * 86400),
                         "randomized": True, "auth_count": 31, "current": False, "start": iso(60 * 86400), "end": iso(41 * 86400 - 900)}],
            "conflicts": [{"mac": "06:11:22:33:44:01", "other_owners": 1, "from": iso(45 * 86400), "to": iso(41 * 86400)}],
            "auth": [{"at": iso(1500), "result": "accept", "reason": "ok", "mac": "02:00:00:00:00:00",
                      "bssid": "d2:21:f9:00:00:11", "ssid": "Example", "nas_ip": "10.10.0.21"},
                     {"at": iso(9000), "result": "reject", "reason": "retired", "mac": "02:00:00:00:00:00",
                      "bssid": "d2:21:f9:00:00:12", "ssid": "Example", "nas_ip": "10.10.0.22"}],
            "acct": [{"nas_ip": "10.10.0.21", "acct_session_id": "5F3A1C2B-00000042", "link": "class",
                      "mac": "02:00:00:00:00:00", "bssid": "d2:21:f9:00:00:11", "ssid": "Example", "framed_ip": "10.30.0.23",
                      "started": iso(1500), "updated": iso(60), "stopped": None, "session_time_s": None,
                      "input_octets": 12_400_000, "output_octets": 184_000_000, "terminate_cause": None},
                     {"nas_ip": "10.10.0.22", "acct_session_id": "5F3A1C2B-00000041", "link": "mac_window",
                      "mac": "02:00:00:00:00:00", "bssid": "d2:21:f9:00:00:12", "ssid": "Example", "framed_ip": None,
                      "started": iso(16000), "updated": iso(1600), "stopped": iso(1600), "session_time_s": 14400,
                      "input_octets": 96_000_000, "output_octets": 812_000_000, "terminate_cause": "Lost-Carrier"}],
            "events": [{"at": iso(1490), "kind": "connected", "source": "unifi_syslog", "mac": "02:00:00:00:00:00",
                        "ap_mac": AP_MACS["ap-scharni-2-corner"], "ap_name": "ap-scharni-2-corner", "from_ap_mac": None,
                        "from_ap_name": None, "ssid": "Example", "radio": "na", "channel": 36, "rssi": -58,
                        "duration_s": None, "rx_bytes": None, "tx_bytes": None},
                       {"at": iso(1610), "kind": "disconnected", "source": "unifi_syslog", "mac": "02:00:00:00:00:00",
                        "ap_mac": AP_MACS["ap-scharni-1-middle"], "ap_name": "ap-scharni-1-middle", "from_ap_mac": None,
                        "from_ap_name": None, "ssid": "Example", "radio": "ng", "channel": 6, "rssi": -71,
                        "duration_s": 14390, "rx_bytes": 812_000_000, "tx_bytes": 96_000_000}],
            "days": [{"device_id": device_id, "day": (NOW.date() - dt.timedelta(days=1)).isoformat(), "online_s": 61_200,
                      "stale_s": 0, "signal_avg_dbm": -61.2, "signal_p10_dbm": -70.5, "snr_avg_db": 33.1, "health_avg": 84.0,
                      "health_min": 52.0, "retry_ratio_avg": 0.05, "rx_bytes": 1_900_000_000, "tx_bytes": 240_000_000,
                      "link_rx_avg_bps": 610_000_000, "roams": 4, "reconnects": 2, "disconnects": 3, "aps": {}, "bands": {},
                      "macs": 1, "auth_ok": 9, "auth_failed": 1, "computed": iso(1500)}],
            "incidents": [sample_incidents()[2]],
            "limits": {"auth": 1000, "acct": 1000, "events": 2000},
            "truncated": {"auth": False, "acct": False, "events": True}}


def registry_rows(devices, owners=("sub-resident",)):
    """Registry rows (registry.DEVICE_LIST) for these DEVICEs."""
    return [{"id": uuid.UUID(d["id"]), "owner": owners[i % len(owners)], "name": d["name"], "platform": d["platform"],
             "policy": "residents", "created": NOW - dt.timedelta(days=40), "revoked": None,
             "expires": dt.datetime.fromisoformat(d["expires"]), "certificates": 1, "last_seen": NOW,
             "calling_station": d["mac"]} for i, d in enumerate(devices)]


def esc(text):
    return str(escape(text))


def visible(page):
    """The page without its JSON blocks (they hold every text)."""
    return re.sub(r"<script.*?</script>", "", page, flags=re.DOTALL)


SCRIPT = re.compile(r"<script\b([^>]*)>(.*?)</script>", re.DOTALL)


class DashboardPagesTestCase(unittest.TestCase):
    """The pages through web.py's routes; registry and telemetry mocked."""
    telemetry = "ok"
    template_globals = True

    def setUp(self):
        self.devices = sample_devices()
        self.overview = sample_overview()
        self.aps = {"generated_at": iso(), "telemetry": "ok", "aps": sample_aps()}
        self.incident_calls = []
        self.state = {RESIDENT_SUB: {"admin": False}, ADMIN_SUB: {"admin": True}}

        def fake_dashboard(client, rows, owners=None, now=None, **_kw):
            """telemetry.dashboard: the sample DEVICEs of these rows, in their order, with owners."""
            payload = sample_dashboard(self.telemetry, devices=[dict(d) for d in self.devices])
            by_id = {d["id"]: d for d in payload["devices"]}
            payload["devices"] = [by_id[str(r["id"])] for r in rows if str(r["id"]) in by_id]
            if owners is not None:
                for d, r in zip(payload["devices"], rows):
                    person = owners.get(r["owner"]) or {}
                    d["owner"] = {"username": person.get("username"), "display": person.get("display")}
            return payload

        # the resident owns the first four, the admin the sensor; one more row of somebody else
        rows = registry_rows(self.devices, owners=(RESIDENT_SUB,) * 4 + (ADMIN_SUB,))
        rows.append(dict(registry_rows([device(0, "Other", "offline")])[0], id=uuid.UUID(int=99, version=4),
                         owner="sub-other"))
        self.rows = rows
        patches = [
            mock.patch.object(web.enroll, "Issuer"),
            mock.patch.object(web.registry, "connect", return_value=FakeDb()),
            mock.patch.object(web.registry, "person_state", side_effect=lambda db, sub: self.state.get(sub)),
            mock.patch.object(web.registry, "devices", side_effect=lambda db, owner=None, include_revoked=False:
                              [r for r in rows if owner is None or r["owner"] == owner]),
            mock.patch.object(web.registry, "device", side_effect=lambda db, device_id, owner=None: next(
                (r for r in rows if str(r["id"]) == str(device_id) and (owner is None or r["owner"] == owner)), None)),
            mock.patch.object(web.registry, "people", return_value={
                RESIDENT_SUB: {"sub": RESIDENT_SUB, "username": "resi", "display": "Resi Example"},
                ADMIN_SUB: {"sub": ADMIN_SUB, "username": "admin", "display": "Admin Example"}}),
            mock.patch.object(web.telemetry, "dashboard", side_effect=fake_dashboard),
            mock.patch.object(web.telemetry, "history", side_effect=lambda client, mac, range_key, now=None, **kw:
                              self.history(range_key, kw)),
            mock.patch.object(web.telemetry, "admin_overview", side_effect=lambda *a, **k: self.overview),
            mock.patch.object(web.telemetry, "admin_aps", side_effect=lambda *a, **k: self.aps),
            mock.patch.object(web.telemetry, "admin_incidents", side_effect=self.fake_incidents),
            mock.patch.object(web.telemetry, "from_registry", side_effect=lambda db, devs, now, admin=False, **k: {
                str(d["id"]): None for d in devs}),
            mock.patch.object(web.telemetry, "admin_raw", side_effect=lambda db, row, identity, since, until, **k:
                              sample_raw(str(row["id"]))),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.app = web.create_app(example_settings(passpoint=True))
        if self.template_globals:
            self.app.jinja_env.globals.update(i18n.template_globals())     # as web.py should (idempotent)
        else:
            for name in i18n.template_globals():
                self.app.jinja_env.globals.pop(name, None)
        self.client = self.app.test_client()

    def history(self, range_key, kw):
        """telemetry.history: v1's sample for the v1 ranges, v2's for the others (and its admin flag)."""
        return sample_history(range_key) if range_key in ("24h", "7d", "30d") else v2_history(range_key, kw.get("admin"))

    def fake_incidents(self, db, since, until, kind=None, now=None, **_kw):
        self.incident_calls.append((since, until, kind))
        items = [i for i in sample_incidents() if not kind or i["kind"] == kind]
        return {"from": dt.datetime.fromtimestamp(since, dt.UTC).isoformat(), "to": dt.datetime.fromtimestamp(until, dt.UTC).isoformat(),
                "kind": kind, "incidents": items, "truncated": False, "counts": {}}

    def log_in(self, sub=RESIDENT_SUB):
        with self.client.session_transaction() as sess:
            sess["user"] = {"sub": sub, "username": sub, "name": sub}
            sess["login_at"] = int(dt.datetime.now().timestamp())
            sess["csrf"] = "example-csrf"

    def get(self, url, lang="en", sub=RESIDENT_SUB):
        self.log_in(sub)
        resp = self.client.get(url, headers={"Accept-Language": lang, "Accept": "text/html"})
        self.assertEqual(resp.status_code, 200, url)
        return resp, resp.get_data(as_text=True)

    def json_block(self, page, block_id):
        m = re.search(r'<script type="application/json" id="%s">(.*?)</script>' % block_id, page, re.DOTALL)
        self.assertIsNotNone(m, block_id)
        return json.loads(m.group(1))

    def assert_csp_safe(self, resp, page):
        """No inline code: scripts are static files (modules) or JSON data blocks; the CSP
        allows scripts from 'self' only; the CSRF token is in a meta tag for the rename."""
        for attrs, body in SCRIPT.findall(page):
            if "src=" in attrs:
                self.assertRegex(attrs, r'type="module" src="/static/[a-z]+\.js"')
                self.assertEqual(body.strip(), "")
            else:
                self.assertIn('type="application/json"', attrs)
                json.loads(body)                                # data, not code
        self.assertNotRegex(page, r"\son[a-z]+=")              # no inline event handlers
        self.assertNotIn("style=", page)                        # style-src 'self' forbids inline styles
        self.assertIn('<meta name="csrf" content="example-csrf">', page)
        csp = resp.headers["Content-Security-Policy"]
        self.assertIn("script-src 'self'", csp)
        self.assertIn("connect-src 'self'", csp)
        self.assertNotIn("unsafe", csp)


class DevicesPageTests(DashboardPagesTestCase):
    def test_every_language_renders_every_state(self):
        for lang in ("en", "de", "uk"):
            t = i18n.TEXT[lang]
            resp, page = self.get("/", lang)
            self.assert_csp_safe(resp, page)
            self.assertIn('<html lang="%s">' % lang, page)
            for state in ("online", "offline", "never_connected"):
                self.assertIn('class="dev-state state-%s"' % state, page)
                self.assertIn(t["state_" + state], page)
            self.assertIn(esc(t["house_title"]), page)
            self.assertIn(esc(t["house_speed_note"]), page)
            self.assertIn(esc(t["diag_weak_signal"]), page)
            self.assertIn(esc(t["diag_weak_signal_do"]), page)
            self.assertIn(esc(t["f_link_note"]), page)
            self.assertNotIn("{", visible(page))                                       # every placeholder filled

    def test_the_cards_are_complete_without_javascript(self):
        _resp, page = self.get("/", "de")
        self.assertIn("Scharni · 2. Stock · Ecke", page)                     # the room from the AP
        self.assertIn("5 GHz · Kanal 36 · Wi-Fi 6", page)
        self.assertIn("−58 dBm", page)
        self.assertIn("88 von 100", page)
        self.assertIn("2,4 Mbit/s", page)                                  # data now
        self.assertIn("1,8 GB", page)                                      # data in 24 hours
        self.assertIn("866 Mbit/s", page)                                  # the radio link rate
        self.assertIn("verbunden seit", page)
        self.assertIn("zuletzt gesehen", page)
        self.assertIn('href="/devices/%s"' % IDS[0], page)                  # the detail page
        self.assertIn('action="/devices/%s/rename"' % IDS[0], page)         # the rename form, also without JS
        self.assertIn(esc(i18n.TEXT["de"]["diag_never_connected_do"]), page)
        self.assertIn("Stand", page)                                       # "as of", replaced by the script
        self.assertIn(i18n.TEXT["de"]["expires_badge"], page)              # the iPad's key expires soon
        self.assertIn('action="/devices/%s/renew"' % IDS[2], page)
        self.assertIn('value="android"', page)                             # the enrolment stays
        self.assertIn('id="add"', page)

    def test_a_card_shows_two_findings_and_links_to_the_rest(self):
        _resp, page = self.get("/")
        card = page[page.index('id="device-%s"' % IDS[1]):page.index('id="device-%s"' % IDS[2])]
        self.assertEqual(card.count('class="finding sev-'), 2)
        self.assertIn(i18n.TEXT["en"]["diag_more"].format(n=3), card)

    def test_the_name_is_a_heading_with_an_edit_button(self):
        _resp, page = self.get("/")
        card = page[page.index('id="device-%s"' % IDS[0]):page.index('id="device-%s"' % IDS[1])]
        self.assertIn('<h2 class="dev-name-text" data-name>Pixel 8</h2>', card)
        self.assertIn('<summary class="edit-button" title="Rename">', card)
        self.assertIn('<span class="sr" data-name-label>Rename: Pixel 8</span>', card)
        # without the script: a plain POST form behind the button, with the CSRF token
        form = card[card.index('<form method="post" action="/devices/%s/rename"' % IDS[0]):]
        form = form[:form.index("</form>")]
        self.assertIn('name="csrf" value="example-csrf"', form)
        self.assertIn('name="name" value="Pixel 8"', form)
        self.assertIn('class="button small needs-js" data-cancel', form)     # Cancel only with the script
        self.assertNotIn('class="pill">Save', page)                             # no lone Save next to each name

    def test_a_conflicting_address_shows_the_finding_not_no_data(self):
        self.devices[0].update(state="unknown", signal_dbm=None, health=None, ap=None, rx_bps=None, tx_bps=None,
                               link_rx_bps=None, link_tx_bps=None, rx_24h_bytes=None, tx_24h_bytes=None, since=None,
                               last_seen=None, diagnostics=[{"code": "mac_conflict", "severity": "warn", "params": {"owners": 2}}])
        for lang in ("en", "de", "uk"):
            t = i18n.TEXT[lang]
            _resp, page = self.get("/", lang)
            card = page[page.index('id="device-%s"' % IDS[0]):page.index('id="device-%s"' % IDS[1])]
            self.assertIn(esc(t["diag_mac_conflict"]), card)
            self.assertIn(esc(t["diag_mac_conflict_do"]), card)
            self.assertNotIn(esc(t["unknown_line"]), card)
            self.assertNotIn(esc(t["diag_mac_conflict_admin_do"]), card)          # the residents' text
            _resp, page = self.get("/devices/%s" % IDS[0], lang)
            self.assertIn(esc(t["diag_mac_conflict_why"]), page)
            _resp, page = self.get("/admin", lang, sub=ADMIN_SUB)
            self.assertIn(esc(t["diag_mac_conflict_admin_why"].format(n=2)), page)
            self.assertIn(esc(t["diag_mac_conflict_admin_do"]), page)

    def test_names_are_escaped(self):
        _resp, page = self.get("/admin", sub=ADMIN_SUB)
        self.assertIn("Sensor &lt;&amp;&gt; &#34;Werkstatt&#34;", page)
        self.assertNotIn('Sensor <&> "Werkstatt"', page)
        data = self.json_block(page, "np-data")
        self.assertIn('Sensor <&> "Werkstatt"', [d["name"] for d in data["devices"]])

    def test_the_scripts_get_texts_config_and_data(self):
        _resp, page = self.get("/", "uk")
        self.assertEqual(self.json_block(page, "np-texts"), i18n.TEXT["uk"])
        config = self.json_block(page, "np-config")
        self.assertEqual(config["api"], "/api/devices")
        self.assertEqual(config["page"], "devices")
        self.assertEqual([d["id"] for d in self.json_block(page, "np-data")["devices"]], IDS[:4])

    def test_no_devices(self):
        self.devices = []
        _resp, page = self.get("/")
        self.assertIn(i18n.TEXT["en"]["no_devices"], page)
        self.assertLess(page.index('id="add"'), page.index('id="devices-h"'))   # enrolment first

    def test_without_the_formatting_global_the_page_still_renders(self):
        self.app.jinja_env.globals.pop("fmt", None)
        self.app.jinja_env.globals.pop("diagnoses", None)
        _resp, page = self.get("/")
        self.assertIn("-58 dBm", page)
        self.assertIn(i18n.TEXT["en"]["state_online"], page)


class TelemetryStatesTests(DashboardPagesTestCase):
    def test_off(self):
        self.telemetry = "off"
        for lang in ("en", "de", "uk"):
            _resp, page = self.get("/", lang)
            self.assertIn(esc(i18n.TEXT[lang]["telemetry_off"]), page)
            self.assertIn('data-part="house" hidden', page)                 # no house strip of unknowns
            self.assertIn("state-unknown", page)
            self.assertIn("state-never_connected", page)
            self.assertNotIn(esc(i18n.TEXT[lang]["all_good"]), visible(page))  # no "all good" without data

    def test_unavailable(self):
        self.telemetry = "unavailable"
        _resp, page = self.get("/", "de")
        self.assertIn(esc(i18n.TEXT["de"]["telemetry_unavailable"]), page)
        self.assertIn('data-part="house" hidden', page)                     # shown again by the script
        self.assertIn(i18n.TEXT["de"]["st_unknown"], page)
        self.assertIn(i18n.TEXT["de"]["house_speed_none"], page)

    def test_stale(self):
        _resp, page = self.render_devices(sample_dashboard(stale=True, house=sample_house(wifi_data_age_s=1500)))
        self.assertIn(esc(i18n.TEXT["en"]["live_stale"].split("{")[0]), page)
        self.assertIn(esc(i18n.TEXT["en"]["house_wifi_age"].format(age="25 min")), page)

    def render_devices(self, dashboard):
        with self.app.test_request_context("/", headers={"Accept-Language": "en"}):
            self.app.preprocess_request()
            return None, render_template("devices.html", dashboard=dashboard, devices=[], options=["apple"],
                                         expires_soon=lambda e: False)


class DevicePageTests(DashboardPagesTestCase):
    def test_every_language_and_state(self):
        for lang in ("en", "de", "uk"):
            t = i18n.TEXT[lang]
            for i in range(len(self.devices)):
                resp, page = self.get("/devices/%s" % IDS[i], lang, sub=ADMIN_SUB)   # admins may see any
                self.assert_csp_safe(resp, page)
                self.assertIn(esc(t["history_title"]), page)
                for key in ("signal", "quality", "traffic", "link", "online"):
                    self.assertIn('data-chart="%s"' % key, page)
                    self.assertIn(esc(t["ch_" + key]), page)
                self.assertIn(esc(t["ch_needs_js"]), page)               # in <noscript>: the list works without
                self.assertIn('class="chart-grid needs-js"', page)          # hidden without scripting
                self.assertIn('aria-current="true">%s<' % t["range_24h"], page)
                config = self.json_block(page, "np-config")
                self.assertEqual(config["device"], IDS[i])
                self.assertEqual(config["history"], "/api/devices/%s/history" % IDS[i])

    def test_details_and_full_findings(self):
        _resp, page = self.get("/devices/%s" % IDS[1])
        t = i18n.TEXT["en"]
        for code in ("weak_signal", "high_retries", "busy_channel", "unstable_roaming", "stuck_on_2ghz"):
            self.assertIn(esc(t["diag_%s_why" % code]), page)            # the explanation too
            self.assertIn(esc(t["diag_%s_do" % code]), page)
        self.assertIn("02:00:00:00:00:01", page)
        self.assertIn("10.30.0.41", page)
        self.assertIn("ap-colbe-0-far", page)
        self.assertIn("Colbe · ground floor · far end", page)
        self.assertIn("2.4 GHz · channel 6 · Wi-Fi 4", page)
        self.assertIn("7 per hour", page)
        self.assertIn("24%", page)

    def test_range_from_the_address(self):
        _resp, page = self.get("/devices/%s?range=7d" % IDS[0])
        self.assertIn('aria-current="true">7 days<', page)
        self.assertEqual(self.json_block(page, "np-config")["range"], "7d")
        _resp, page = self.get("/devices/%s?range=1y" % IDS[0])
        self.assertIn('aria-current="true">1 year<', page)                     # telemetry v2: up to "all"
        _resp, page = self.get("/devices/%s?range=2y" % IDS[0])
        self.assertIn('aria-current="true">24 hours<', page)

    def test_another_residents_device_is_not_found(self):
        self.log_in(RESIDENT_SUB)
        self.assertEqual(self.client.get("/devices/%s" % IDS[4]).status_code, 404)   # the admin's device
        self.assertEqual(self.client.get("/devices/%s" % uuid.UUID(int=99, version=4)).status_code, 404)

    def test_from_the_admin_page(self):
        _resp, page = self.get("/devices/%s?from=admin" % IDS[0], sub=ADMIN_SUB)
        self.assertIn('href="/admin"', page)
        self.assertIn('name="back" value="/admin"', page)
        self.assertTrue(self.json_block(page, "np-config")["admin"])
        self.assertIn("Resi Example", page)                                   # the owner

    def test_the_event_list_without_javascript(self):
        device = sample_dashboard()["devices"][0]
        with self.app.test_request_context("/devices/x", headers={"Accept-Language": "en"}):
            self.app.preprocess_request()
            page = render_template("device.html", device=device, dashboard=sample_dashboard(), history=sample_history())
        t = i18n.TEXT["en"]
        self.assertIn("Connected: Scharni · 2nd floor · corner (5 GHz)", page)
        self.assertIn("Moved from Scharni · 1st floor · middle to Colbe · ground floor · far end", page)
        self.assertIn("Switched from 5 GHz to 2.4 GHz", page)
        self.assertIn(t["tl_disconnected"], page)
        self.assertLess(page.index("Switched from"), page.index("Moved from"))   # newest first
        self.assertIn(esc(t["ch_needs_js"]), page)
        self.assertIn('class="card timeline-card"', page)                       # shown without scripting


class AdminPageTests(DashboardPagesTestCase):
    def test_every_language(self):
        for lang in ("en", "de", "uk"):
            resp, page = self.get("/admin", lang, sub=ADMIN_SUB)
            self.assert_csp_safe(resp, page)
            self.assertEqual(page.count('class="adm-item"'), len(self.rows) - 1)          # "Other" has no telemetry sample
            self.assertIn(esc(i18n.TEXT[lang]["adm_search_ph"]), page)
            self.assertEqual(page.count('action="/devices/'), len(self.rows) - 1)      # a revoke form per device
            self.assertIn('name="back" value="/admin"', page)
            for code in i18n.DIAGNOSES:
                self.assertIn('<option value="%s"' % code, page)

    def names(self, page):
        """(name, hidden) in page order."""
        return [(html.unescape(name), "hidden" in attrs)
                for attrs, name in re.findall(r'<li class="adm-item"([^>]*)>.*?class="adm-name" data-part="sum-name">(.*?)</strong>',
                                              page, re.DOTALL)]

    def test_search_filters_and_sorting_without_javascript(self):
        _resp, page = self.get("/admin?q=MAC", sub=ADMIN_SUB)
        self.assertEqual([n for n, hidden in self.names(page) if not hidden], ["MacBook Air"])
        _resp, page = self.get("/admin?q=02-00-00-00-00-02", sub=ADMIN_SUB)       # a MAC as the AP writes it
        self.assertEqual([n for n, hidden in self.names(page) if not hidden], ["iPad"])
        _resp, page = self.get("/admin?q=admin%20example", sub=ADMIN_SUB)         # the owner
        self.assertEqual([n for n, hidden in self.names(page) if not hidden], ['Sensor <&> "Werkstatt"'])
        _resp, page = self.get("/admin?state=offline", sub=ADMIN_SUB)
        self.assertEqual([n for n, hidden in self.names(page) if not hidden], ["iPad"])
        _resp, page = self.get("/admin?problem=with&sort=signal", sub=ADMIN_SUB)
        self.assertEqual([n for n, hidden in self.names(page) if not hidden], ["MacBook Air", 'Sensor <&> "Werkstatt"', "iPad"])
        _resp, page = self.get("/admin?problem=slow_link", sub=ADMIN_SUB)
        self.assertEqual([n for n, hidden in self.names(page) if not hidden], ['Sensor <&> "Werkstatt"'])
        self.assertIn("1 of 5 shown", page)
        _resp, page = self.get("/admin?sort=seen", sub=ADMIN_SUB)
        self.assertEqual([n for n, _h in self.names(page)][-1], "Kindle")          # never seen: last
        _resp, page = self.get("/admin?q=nothing-matches", sub=ADMIN_SUB)
        self.assertNotIn("data-none hidden", page)

    def test_problem_badges(self):
        _resp, page = self.get("/admin", sub=ADMIN_SUB)
        self.assertIn("problems: 4", page)          # MacBook: warn and bad only, not the info
        self.assertIn("badge sev-bad", page)


class TextTests(unittest.TestCase):
    def test_every_diagnosis_has_its_texts_in_every_language(self):
        source = (Path(__file__).resolve().parent.parent / "netportal" / "diagnostics.py").read_text()
        codes = set(re.findall(r'finding\("([a-z_0-9]+)"', source))
        self.assertLessEqual(codes, set(i18n.DIAGNOSES))                  # nothing reported without a text
        for lang, text in i18n.TEXT.items():
            for code in i18n.DIAGNOSES:
                for suffix in ("", "_why", "_do"):
                    self.assertTrue(text.get("diag_%s%s" % (code, suffix)), (lang, code, suffix))

    def test_rooms(self):
        F = i18n.Format
        ap_ = {"name": "ap-scharni-0-corner", "house": "scharni", "floor": 0, "spot": "corner"}
        self.assertEqual(F.room(ap_, "en"), "Scharni · ground floor · corner")
        self.assertEqual(F.room(ap_, "de"), "Scharni · Erdgeschoss · Ecke")
        self.assertEqual(F.room(ap_, "uk"), "Scharni · перший поверх · кут")
        self.assertEqual(F.room({"name": "2. stock scharni mitte", "house": None}, "de"), "2. stock scharni mitte")
        self.assertEqual(F.room({"name": "ap-x-9-y", "house": "x", "floor": 9, "spot": "y"}, "en"), "X · floor 9 · y")
        for lang in ("en", "de", "uk"):
            for spot in ("corner", "middle", "far"):
                self.assertIn("room_spot_" + spot, i18n.TEXT[lang])

    def test_formatting(self):
        F = i18n.Format
        self.assertEqual(F.bytes(1_830_000_000, "de"), "1,8 GB")
        self.assertEqual(F.bitrate(950, "en"), "950 bit/s")
        self.assertEqual(F.duration(8130, "uk"), "2 год 15 хв")
        self.assertEqual(F.ago(iso(3 * 3600), "en", iso()), "3 h ago")
        self.assertEqual(F.when(iso(), "en", iso()), "13:00")                  # the house's time (CET)
        self.assertEqual(F.number(12345.6, "uk", 1), "12 345,6")
        for name in ("bytes", "bitrate", "dbm", "percent", "duration", "date"):
            self.assertEqual(getattr(F, name)(None, "en"), "–")
        self.assertEqual(F.signal(-70), (2, "sig_fair", "warn"))
        self.assertEqual(F.health(None), None)


# --- telemetry v2 ---------------------------------------------------------------------------------

LANGS = ("en", "de", "uk")


def all_findings():
    """One finding of every code diagnostics.py can report, as it reports them."""
    by_code = {f["code"]: f for d in v2_devices() for f in d["diagnostics"]}
    by_code.update({
        "low_snr": finding("low_snr", "warn", evidence={"snr_db": 14, "noise_dbm": -88, "signal_dbm": -70, "warn_db": 20}),
        "busy_channel": finding("busy_channel", "warn", channel_util=0.72, channel=6),
        "slow_link": finding("slow_link", "warn", evidence={"link_rx_bps": 6_500_000, "signal_dbm": -62, "throughput_bps": 2e6}),
        "stale_data": finding("stale_data", "warn", evidence={"age_s": 900, "threshold_s": 600}, age_s=900),
        "cert_expired": finding("cert_expired", "bad", evidence={"expires": iso(86400), "days_left": -1}, expires=iso(86400)),
        "mac_conflict": finding("mac_conflict", "warn", evidence={"owners": 2, "macs": ["02:00:00:00:00:00"]}, owners=2),
    })
    return [by_code[c] for c in i18n.DIAGNOSES]


def events_of(page):
    start = page.index("data-events>")
    return page[start:page.index("</ol>", start)]


class V2DevicePagesTests(DashboardPagesTestCase):
    """How a device connects, its logins, findings with evidence, the merged timeline, ranges."""

    def setUp(self):
        super().setUp()
        self.devices = v2_devices()

    def card(self, page, i):
        start = page.index('id="device-%s"' % IDS[i])
        return page[start:page.index("</article>", start)]

    def test_how_each_device_connects_in_every_language(self):
        for lang in LANGS:
            t = i18n.TEXT[lang]
            resp, page = self.get("/", lang)
            self.assert_csp_safe(resp, page)
            self.assertNotIn("{", visible(page))
            for i, mode in ((0, "random_fixed"), (1, "hardware"), (2, "rotating"), (3, "hardware")):
                card = self.card(page, i)
                self.assertIn('class="conn-line mm-%s"' % mode, card)
                self.assertIn(esc(t["mm_" + mode]), card)
            ipad = self.card(page, 2)                                          # rotating: how to choose "fixed"
            self.assertIn(esc(t["mm_rotating_do"]), ipad)
            self.assertIn(esc(t["mm_how_apple"].format(ssid="Example")), ipad)
            self.assertNotIn(esc(t["mm_admin_rotating"]), ipad)                   # the admins' words stay theirs
            self.assertNotIn('class="advice"', self.card(page, 0))            # a fixed address needs no advice

    def test_the_advice_follows_the_platform(self):
        for platform, key in (("apple-mac", "mm_how_apple-mac"), ("android", "mm_how_android"), ("letswifi", "mm_how_other"),
                              ("eap-config", "mm_how_other")):
            self.devices[2]["platform"] = platform
            _resp, page = self.get("/", "de")
            self.assertIn(esc(i18n.TEXT["de"][key].format(ssid="Example")), self.card(page, 2), platform)

    def test_rejected_logins_say_why_and_what_to_do(self):
        for lang in LANGS:
            t = i18n.TEXT[lang]
            _resp, page = self.get("/", lang)
            kindle = self.card(page, 3)
            self.assertIn('class="alert tone-bad"', kindle)
            self.assertIn(esc(t["la_rejected_title"]), kindle)
            self.assertIn(esc(t["rr_unknown_cert"]), kindle)
            self.assertIn(esc(t["rr_unknown_cert_do"]), kindle)
            self.assertNotIn(esc(t["rr_unknown_cert_admin"]), kindle)
            self.assertIn('class="conn-line la-reject"', kindle)
            self.assertNotIn('class="alert', self.card(page, 0))             # an accepted login: a line, no alert
            self.assertIn('class="conn-line la-accept"', self.card(page, 0))
        for reason in i18n.REJECT_REASONS + ("something-unknown",):
            self.devices[3]["last_auth"] = {"at": iso(60), "result": "reject", "reason": reason}
            _resp, page = self.get("/devices/%s" % IDS[3], "uk")
            key = i18n.Format.reason_key(reason)
            self.assertIn(esc(i18n.TEXT["uk"]["rr_" + key]), page, reason)
            self.assertNotIn("{", visible(page))

    def test_cards_show_the_evidence_and_the_estimated_tag(self):
        _resp, page = self.get("/")
        t = i18n.TEXT["en"]
        self.assertIn('<span class="evidence">24%</span>', self.card(page, 1))
        ipad = self.card(page, 2)
        self.assertIn('<span class="evidence">8 times in 24 hours</span>', ipad)
        self.assertNotIn(esc(t["ev_based_on"]), ipad)                         # the full line only on the device page
        _resp, page = self.get("/devices/%s" % IDS[2])
        self.assertIn(esc(t["ev_based_on"]), page)
        self.assertIn("drop-outs reported by the access points <b>7</b>", page)
        self.assertIn(esc(t["cause_lost_carrier"]), page)
        self.assertIn('class="finding sev-info inferred"', page)
        self.assertIn('<span class="basis-tag" title="%s">%s' % (esc(t["basis_inferred_hint"]), t["basis_inferred"]), page)
        self.assertIn(esc(t["ev_last_24h"]), page)
        self.assertNotIn("reconnects_24h", visible(page))                     # no field names for residents
        self.assertNotIn("margin_s", visible(page))

    def test_every_finding_code_renders_in_every_language(self):
        self.devices[1]["diagnostics"] = all_findings()
        for lang in LANGS:
            t = i18n.TEXT[lang]
            for url, sub, admin in (("/devices/%s" % IDS[1], RESIDENT_SUB, False), ("/admin/devices/%s" % IDS[1], ADMIN_SUB, True)):
                resp, page = self.get(url, lang, sub=sub)
                self.assert_csp_safe(resp, page)
                shown = visible(page)
                self.assertNotIn("{", shown)
                for f in all_findings():
                    key = "diag_" + f["code"]
                    self.assertIn(esc(t[key]), shown, (lang, f["code"]))
                    todo = t[key + "_admin_do"] if admin and t.get(key + "_admin_do") else t[key + "_do"]
                    self.assertIn(esc(todo), shown, (lang, f["code"]))
                    for label, value in i18n.Format.evidence_items(f, lang, admin)[0]:
                        self.assertIn(esc(value), shown, (lang, f["code"], label))
                if not admin:
                    for word in ("count_24h", "tx_attempts_per_s", "min_macs", "locked_out", "threshold_s"):
                        self.assertNotIn(word, shown)

    def test_the_merged_timeline_without_javascript(self):
        for lang in LANGS:
            t = i18n.TEXT[lang]
            _resp, page = self.get("/devices/%s?range=90d" % IDS[0], lang)
            events = events_of(page)
            for kind in i18n.EVENT_KINDS:
                self.assertIn('class="ev ev-%s' % kind, events, (lang, kind))
            self.assertIn('class="ev ev-band_changed ev-inferred"', events)
            self.assertIn(esc(t["tl_auth_rejected"].format(reason=t["rr_retired"])), events)
            self.assertIn(esc(t["tl_session_ended"].format(cause=t["cause_nas_reboot"])), events)
            self.assertIn(esc(t["src_unifi_syslog"]), events)
            self.assertIn(esc(t["inc_internet_degraded"]), events)
            self.assertIn(esc(t["inc_open"]), events)
            self.assertNotIn("NAS-Reboot", events)                              # the raw cause is the admins'
            self.assertNotIn("{", visible(page))
        _resp, page = self.get("/admin/devices/%s?range=90d" % IDS[0], sub=ADMIN_SUB)
        events = events_of(page)
        self.assertIn("NAS-Reboot", events)
        self.assertIn(esc(i18n.TEXT["en"]["src_admin_unifi_syslog"]), events)
        self.assertIn(esc(i18n.TEXT["en"]["rr_retired_admin"]), events)
        self.assertIn("06:11:22:33:44:01", events)                             # the new MAC

    def test_every_range(self):
        for lang in LANGS:
            t = i18n.TEXT[lang]
            for r in i18n.RANGES:
                resp, page = self.get("/devices/%s?range=%s" % (IDS[0], r), lang)
                self.assert_csp_safe(resp, page)
                self.assertIn('aria-current="true">%s<' % t["range_" + r], page)
                self.assertEqual(self.json_block(page, "np-config")["range"], r)
                self.assertEqual(self.json_block(page, "np-data")["history"]["range"], r)
                days = r in ("1y", "all")
                self.assertEqual("data-days-note hidden" in page, not days, r)
                if days:
                    self.assertIn(esc(t["ch_signal_sub_day"]), page)
                for key in ("signal", "quality", "traffic", "link", "online", "retries", "snr"):
                    self.assertIn('data-chart="%s"' % key, page)

    def test_identity_details(self):
        _resp, page = self.get("/devices/%s" % IDS[2])
        t = i18n.TEXT["en"]
        details = visible(page)[visible(page).index('id="details-h"'):]
        self.assertIn(esc(t["dt_macs"]), details)
        for i in range(4):
            self.assertIn("06:11:22:33:44:%02x" % i, details)
        self.assertEqual(details.count('class="badge-plain on"'), 1)            # the one in use
        self.assertIn(esc(t["src_device_mac"]), details)
        self.assertNotIn(esc(t["src_admin_prometheus"]), details)
        self.assertNotIn("data-raw", page)                                      # raw data: admins only
        self.assertIsNone(self.json_block(page, "np-config")["raw"])

    def test_names_and_reasons_are_escaped(self):
        self.devices[3]["last_auth"] = {"at": iso(60), "result": "reject", "reason": "<script>alert(1)</script>"}
        self.devices[3]["name"] = "<img src=x onerror=alert(1)>"
        _resp, page = self.get("/admin/devices/%s" % IDS[3], sub=ADMIN_SUB)
        shown = visible(page)
        self.assertNotIn("<script>alert", shown)
        self.assertNotIn("<img src=x", shown)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", shown)         # the admin sees the raw value, escaped


class V2AdminPagesTests(DashboardPagesTestCase):
    """The overview, the access points, the incidents and the deep view: admins only."""

    def setUp(self):
        super().setUp()
        self.devices = v2_devices()

    def test_admin_pages_are_admin_only(self):
        for url in ("/admin", "/admin/aps", "/admin/incidents", "/admin/devices/%s" % IDS[0]):
            self.log_in(RESIDENT_SUB)
            resp = self.client.get(url, headers={"Accept": "text/html"})
            self.assertEqual(resp.status_code, 403, url)
            self.assertNotIn(b"ov-grid", resp.data)
        for url in ("/api/admin/overview", "/api/admin/aps", "/api/admin/incidents", "/api/admin/devices/%s/raw" % IDS[0]):
            self.log_in(RESIDENT_SUB)
            self.assertEqual(self.client.get(url, headers={"Accept": "application/json"}).status_code, 403, url)

    def test_the_overview_in_every_language(self):
        for lang in LANGS:
            t = i18n.TEXT[lang]
            resp, page = self.get("/admin", lang, sub=ADMIN_SUB)
            self.assert_csp_safe(resp, page)
            shown = visible(page)
            self.assertNotIn("{", shown)
            self.assertIn('<nav class="adm-tabs"', page)
            self.assertIn('href="/admin" aria-current="page"', page)
            for key in ("ov_title", "ov_incidents", "ov_open", "ov_recent", "ov_aps", "ov_auth", "ov_fresh", "inc_internet_degraded",
                        "inc_ap_down", "ap_warn_overloaded", "ap_warn_uplink", "ap_warn_restarted", "rr_unknown_cert_admin",
                        "fresh_wifi", "fresh_jobs_failed", "job_failed", "job_never", "job_ok", "ov_devices"):
                self.assertIn(esc(t[key]), shown, (lang, key))
            self.assertIn("Prometheus: timeout after 4.0 s &lt;query&gt;", shown)  # the job's error, escaped
            self.assertIn('href="/admin/devices/%s"' % IDS[3], shown)              # a rejected device: its deep view
            self.assertIn("Sensor &lt;&amp;&gt; &#34;Werkstatt&#34;", shown)      # dropped out in an incident
            self.assertEqual(page.count('class="adm-item"'), len(self.rows) - 1)     # v1's device list stays
            self.assertEqual(self.json_block(page, "np-data")["overview"]["auth"]["count"], 27)
            self.assertIn(">%s</span>" % esc(t["ov_auth_repeats"].format(n=4)), shown)   # a row of repeats
            self.assertEqual(self.json_block(page, "np-config")["overview"], "/api/admin/overview")

    def test_sections_that_are_not_available(self):
        self.overview = dict(sample_overview(), incidents={"available": False, "open": [], "recent": [], "counts_7d": {}},
                             auth={"available": False, "since": iso(), "count": 0, "truncated": False, "by_reason": {},
                                   "devices": 0, "macs": 0, "recent": []}, jobs=[], jobs_available=False, aps=[],
                             freshness={"wifi_data_age_s": None, "prometheus": "unavailable", "jobs_ok": None,
                                        "oldest_job_success_age_s": None})
        _resp, page = self.get("/admin", "de", sub=ADMIN_SUB)
        t = i18n.TEXT["de"]
        self.assertEqual(visible(page).count(esc(t["ov_unavailable"])), 3)
        self.assertIn(esc(t["aps_empty"]), page)
        self.assertIn(esc(t["fresh_state_unavailable"]), page)
        self.assertIn(esc(t["fresh_jobs_none"]), page)

    def test_the_access_points(self):
        for lang in LANGS:
            t = i18n.TEXT[lang]
            resp, page = self.get("/admin/aps", lang, sub=ADMIN_SUB)
            self.assert_csp_safe(resp, page)
            shown = visible(page)
            self.assertNotIn("{", shown)
            self.assertEqual(page.count('class="card ap-card'), 4)
            self.assertIn('href="/admin/aps" aria-current="page"', page)
            self.assertIn('id="ap-d021f9000003"', page)                          # the overview's links land here
            self.assertIn('class="card ap-card ap-down"', page)
            for key in ("ap_state_up", "ap_state_down", "ap_warn_poor_coverage", "ap_warn_overloaded", "ch_ap_util"):
                self.assertIn(esc(t[key]), shown, (lang, key))
            self.assertIn(esc(t["ap_clients_house"].format(n=28)), shown)
            self.assertIn("data-ap-chart", page)
            self.assertEqual(len(self.json_block(page, "np-data")["aps"]), 4)
        _resp, page = self.get("/admin/aps?q=colbe&sort=clients", sub=ADMIN_SUB)
        self.assertEqual(len(re.findall(r'<article class="card ap-card[^"]*"[^>]*hidden>', page)), 3)
        self.assertIn("1 of 4 shown", page)

    def test_the_incidents(self):
        for lang in LANGS:
            t = i18n.TEXT[lang]
            resp, page = self.get("/admin/incidents?range=30d", lang, sub=ADMIN_SUB)
            self.assert_csp_safe(resp, page)
            shown = visible(page)
            self.assertNotIn("{", shown)
            for kind in ("internet_degraded", "ap_down", "ap_restarted", "switch_port_down", "dns_down", "radius_down"):
                self.assertIn(esc(t["inc_" + kind]), shown)
            for kind in i18n.INCIDENT_KINDS:
                self.assertIn('<option value="%s"' % kind, page)
            self.assertIn('aria-current="true">%s<' % t["range_30d"], page)
            self.assertIn(esc(t["inc_affected_list"]), shown)
            self.assertIn('href="/admin/devices/%s"' % IDS[1], shown)
            self.assertIn('class="inc inc-closed inferred"', page)
            self.assertIn(esc(t["inc_lasted"].format(duration=i18n.Format.duration(600, lang))), shown)
        since, until, _kind = self.incident_calls[-1]
        self.assertAlmostEqual(until - since, 30 * 86400, delta=5)              # ?range=30d is the server's span
        _resp, page = self.get("/admin/incidents?kind=ap_down&state=open", sub=ADMIN_SUB)
        self.assertEqual(self.incident_calls[-1][2], "ap_down")
        self.assertIn('<option value="ap_down" selected>', page)
        self.assertIn("1 of 1 shown", page)
        self.assertEqual(self.json_block(page, "np-config")["kind"], "ap_down")

    def test_without_affected_devices_nothing_is_claimed(self):
        incidents = sample_incidents()
        for i in incidents:
            del i["devices"]
        payload = {"from": iso(86400), "to": iso(), "kind": None, "incidents": incidents}
        with mock.patch.object(web.telemetry, "admin_incidents", return_value=payload):
            _resp, page = self.get("/admin/incidents", sub=ADMIN_SUB)
        self.assertNotIn(esc(i18n.TEXT["en"]["inc_affected_none"]), visible(page))
        self.assertIn(esc(i18n.TEXT["en"]["inc_ap_down"]), page)

    def test_the_deep_view_with_raw_data(self):
        for lang in LANGS:
            t = i18n.TEXT[lang]
            resp, page = self.get("/admin/devices/%s" % IDS[0], lang, sub=ADMIN_SUB)
            self.assert_csp_safe(resp, page)
            shown = visible(page)
            self.assertNotIn("{", shown)
            self.assertIn('href="/admin#devices" aria-current="page"', page)
            for part in ("auth", "acct", "events", "macs", "days", "incidents"):
                self.assertIn('id="raw-%s"' % part, page)
                self.assertIn(esc(t["raw_tab_" + part]), shown)
            self.assertIn("5F3A1C2B-00000041", shown)                            # an accounting session
            self.assertIn("Lost-Carrier", shown)
            self.assertIn(esc(t["cause_lost_carrier"]), shown)
            self.assertIn('class="row-bad"', page)                               # the rejected login
            self.assertIn(esc(t["raw_conflict"].format(n=1)), shown)              # the MAC window's conflict
            self.assertIn(esc(t["raw_truncated"].format(n=2000)), shown)          # UniFi events cut at the limit
            self.assertIn(esc(t["mm_admin_random_fixed"]), shown)
            config = self.json_block(page, "np-config")
            self.assertTrue(config["admin"])
            self.assertEqual(config["raw"], "/api/admin/devices/%s/raw" % IDS[0])
            self.assertEqual(self.json_block(page, "np-data")["raw"]["acct"][1]["terminate_cause"], "Lost-Carrier")
        _resp, page = self.get("/devices/%s?from=admin" % IDS[0], sub=ADMIN_SUB)   # v1's link still works
        self.assertIn("data-raw", page)
        self.assertIn("data-raw-load", page)


class V2TextTests(unittest.TestCase):
    """Every code the backend sends has its texts, in every language."""

    def test_codes_have_texts(self):
        need = [("diag_%s" + s, i18n.DIAGNOSES) for s in ("", "_why", "_do")]
        need += [("tl_kind_%s", i18n.EVENT_KINDS), ("rr_%s", i18n.REJECT_REASONS), ("rr_%s_admin", i18n.REJECT_REASONS),
                 ("cause_%s", i18n.TERMINATE_CAUSES + ("unknown",)), ("mm_%s", i18n.MAC_MODES), ("mm_%s_sub", i18n.MAC_MODES),
                 ("mm_admin_%s", i18n.MAC_MODES), ("inc_%s", i18n.INCIDENT_KINDS), ("src_%s", i18n.SOURCES),
                 ("src_admin_%s", i18n.SOURCES), ("job_%s", i18n.JOBS), ("fresh_%s", i18n.FRESHNESS),
                 ("range_%s", i18n.RANGES), ("ap_warn_%s", i18n.AP_WARNINGS)]
        for lang, text in i18n.TEXT.items():
            for pattern, codes in need:
                for code in codes:
                    self.assertTrue(text.get(pattern % code), (lang, pattern % code))
            for code in i18n.REJECT_REASONS:
                self.assertIn("rr_%s_do" % code, text)                         # "" for ok: nothing to do
            for spec in i18n.EVIDENCE_SPEC.values():
                for key, kind in spec:
                    self.assertTrue(text.get("evk_limit" if kind.startswith("limit_") else "evk_" + key), (lang, key))
            for key in i18n.EVIDENCE_FORMAT:
                self.assertTrue(text.get("evk_" + key), (lang, key))

    def test_the_backends_codes_are_known(self):
        from netportal import diagnostics
        from netportal.telemetry import timeline
        source = (Path(__file__).resolve().parent.parent / "netportal" / "diagnostics.py").read_text()
        self.assertLessEqual(set(re.findall(r'finding\("([a-z_0-9]+)"', source)), set(i18n.DIAGNOSES))
        self.assertLessEqual(set(timeline.SOURCE_RANK), set(i18n.SOURCES))
        self.assertLessEqual(set(web.INCIDENT_KINDS), set(i18n.INCIDENT_KINDS))
        self.assertEqual(tuple(web.HISTORY_RANGES), i18n.RANGES)
        self.assertLessEqual(set(timeline.MERGE_KIND) | {"authenticated", "auth_rejected", "mac_changed", "incident"},
                             set(i18n.EVENT_KINDS))
        self.assertTrue(diagnostics.AP_CLIENTS_WARN and diagnostics.AP_UTIL_WARN)    # the AP warnings' limits

    def test_formatting(self):
        F = i18n.Format
        self.assertEqual(F.cause_key("Lost-Carrier"), "lost_carrier")
        self.assertEqual(F.cause_key("19"), "supplicant_restart")
        self.assertEqual(F.cause_key("99"), "unknown")
        self.assertEqual(F.cause_key("²"), "unknown")                    # isdigit, but no int
        self.assertEqual(F.reason_key("nope"), "other")
        self.assertEqual(F.incident_text({"kind": "ap_down", "subject_name": "ap-colbe-0-far"}, "de"),
                         "Access Point offline (Colbe · Erdgeschoss · hinten)")
        self.assertEqual(F.incident_text({"kind": "internet_down", "subject": ""}, "en"), "Internet down (whole house)")
        self.assertEqual(F.ap_warnings({"state": "down"}), ["down"])
        self.assertEqual(F.ap_warnings({"state": "ok", "clients": 31, "radios": [], "weak_clients": 10, "uptime_s": 60,
                                        "uplink_mbps": 100}), ["overloaded", "poor_coverage", "restarted", "uplink"])
        self.assertEqual(F.ap_warnings({"state": "ok", "clients": 5, "radios": [{"channel_util": 0.7}]}), ["busy_channel"])
        self.assertEqual(F.span_key(iso(30 * 86400), iso(), ("7d", "30d", "90d", "1y")), "30d")
        items, window = F.evidence_items(finding("unstable_roaming", "warn", "inferred",
                                                 evidence={"roams_1h": 7, "roams_1h_measured": None, "warn": 6}), "en")
        self.assertEqual(items, [("access point changes", "7 per hour"), ("limit", "6 per hour")])
        self.assertEqual(window, "in the last hour")
        self.assertEqual(F.evidence_short(finding("frequent_disconnects", "warn", evidence={"reconnects_24h": 8}), "de"),
                         "8-mal in 24 Stunden")
        self.assertEqual(F.evidence_short(finding("weak_signal", "warn", evidence={"signal_dbm": -79}), "en"), "−79 dBm")


if __name__ == "__main__":
    unittest.main()
