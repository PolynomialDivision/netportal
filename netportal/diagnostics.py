"""What the dashboard says about a device's Wi-Fi: findings from measured data only.

A finding is {"code", "severity": info|warn|bad, "params"}; the texts (what it means, what to do)
are the frontend's (i18n). Each rule below names the data it reads and why its threshold is
where it is. A rule whose data is missing (null) says nothing: no data is not a problem.

The inputs are a DEVICE (telemetry.dashboard), a summary (telemetry.device_status: reconnects
in 24 h, the bands seen in 7 days, transmit attempts per second, seconds since the association)
and the Wi-Fi data's age.
"""

SEVERITY_ORDER = {"bad": 0, "warn": 1, "info": 2}

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


def finding(code, severity, **params):
    return {"code": code, "severity": severity, "params": params}


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


def is_stale(wifi_data_age_s):
    """The Wi-Fi data is old or its age unknown (unpoller not scraped)."""
    return wifi_data_age_s is None or wifi_data_age_s > STALE_AFTER_S


def state_findings(device, wifi_data_age_s, telemetry="ok"):
    """never_connected, offline, stale_data: what is known about the device at all. stale_data
    only while Prometheus answers (telemetry "ok"): its Wi-Fi data is old, so the device's state
    is not known (an unreachable Prometheus is the page's telemetry state, not a finding)."""
    state = device.get("state")
    if state == "never_connected":
        return [finding("never_connected", "info")]
    out = []
    if telemetry == "ok" and state == "unknown" and is_stale(wifi_data_age_s):
        out.append(finding("stale_data", "warn", age_s=None if wifi_data_age_s is None else int(wifi_data_age_s)))
    if state == "offline":
        out.append(finding("offline", "info", last_seen=device.get("last_seen")))
    return out


def radio_findings(device, summary=None):
    """weak_signal, low_snr, high_retries, busy_channel, slow_link: only while online."""
    if device.get("state") != "online":
        return []
    out = []
    signal = device.get("signal_dbm")
    weak = _below(signal, WEAK_SIGNAL_WARN_DBM, WEAK_SIGNAL_BAD_DBM)
    if weak:
        out.append(finding("weak_signal", weak, signal_dbm=signal))
    snr = device.get("snr_db")
    low_snr = _below(snr, LOW_SNR_WARN_DB, LOW_SNR_BAD_DB)
    if low_snr and not weak:
        out.append(finding("low_snr", low_snr, snr_db=snr, noise_dbm=device.get("noise_dbm")))
    retries = device.get("retry_ratio")
    attempts = (summary or {}).get("tx_attempts_per_s")
    high = _above(retries, HIGH_RETRIES_WARN, HIGH_RETRIES_BAD)
    if high and attempts is not None and attempts >= RETRIES_MIN_ATTEMPTS:
        out.append(finding("high_retries", high, retry_ratio=retries))
    util = device.get("channel_util")
    busy = _above(util, BUSY_CHANNEL_WARN, BUSY_CHANNEL_BAD)
    if busy:
        out.append(finding("busy_channel", busy, channel_util=util, channel=device.get("channel")))
    link, rx, tx = device.get("link_rx_bps"), device.get("rx_bps"), device.get("tx_bps")
    if (link is not None and signal is not None and rx is not None and tx is not None
            and link < SLOW_LINK_BPS and signal >= SLOW_LINK_GOOD_SIGNAL_DBM and rx + tx >= SLOW_LINK_ACTIVE_BPS):
        out.append(finding("slow_link", "warn", link_rx_bps=link, signal_dbm=signal))
    return out


def history_findings(device, summary):
    """unstable_roaming, frequent_disconnects, stuck_on_2ghz: from the recent history."""
    if device.get("state") not in ("online", "offline"):
        return []
    out = []
    roams = device.get("roams_1h")
    level = _above(roams, UNSTABLE_ROAMING_WARN, UNSTABLE_ROAMING_BAD)
    if level:
        out.append(finding("unstable_roaming", level, roams_1h=roams))
    reconnects = (summary or {}).get("reconnects_24h")
    level = _above(reconnects, FREQUENT_DISCONNECTS_WARN, FREQUENT_DISCONNECTS_BAD)
    if level:
        out.append(finding("frequent_disconnects", level, reconnects_24h=reconnects))
    bands = set((summary or {}).get("bands_7d") or ())
    signal, associated = device.get("signal_dbm"), (summary or {}).get("associated_s")
    if (device.get("state") == "online" and device.get("band") == "2.4" and bands & {"5", "6"}
            and roams == 0 and associated is not None and associated >= STUCK_2GHZ_MIN_S
            and signal is not None and signal >= STUCK_2GHZ_MIN_SIGNAL_DBM):
        out.append(finding("stuck_on_2ghz", "info", bands_7d=sorted(bands)))
    return out


def findings(device, summary=None, wifi_data_age_s=None, telemetry="ok"):
    """Every finding for a device, the worst first."""
    out = state_findings(device, wifi_data_age_s, telemetry)
    if device.get("state") != "never_connected":
        out += radio_findings(device, summary) + history_findings(device, summary)
    return sorted(out, key=lambda f: SEVERITY_ORDER[f["severity"]])
