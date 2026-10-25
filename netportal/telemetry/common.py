"""What every part of the telemetry shares: MACs and PromQL selectors, times, AP names, rounding.

Only validated MACs (MAC_RE) ever go into a query: mac_selector refuses anything else, and the
SSID goes in as a PromQL string literal (promql_string).
"""

import datetime
import math
import re

from .. import registry

MAC_RE = re.compile(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}")
BANDS = {"ng": "2.4", "na": "5", "6e": "6"}
# ap-<house>-<floor>-<spot>, e.g. ap-scharni-2-corner, ap-scharni-0-schlaglicht
AP_NAME_RE = re.compile(r"ap-([a-z0-9]+)-(\d{1,2})-([a-z0-9][a-z0-9-]*)")
UTC = datetime.timezone.utc


# The one MAC normaliser (registry.py, the twin of SQL np_mac) and the locally administered bit:
# telemetry re-exports them (telemetry.normalise_mac, telemetry.randomized).
normalise_mac = registry.normalise_mac
randomized = registry.is_randomized


def mac_selector(macs):
    """The label matcher for these MACs. Each must already be normalised: nothing else (no
    quote, no regex character) can reach PromQL."""
    macs = sorted(set(macs))
    if not macs or not all(isinstance(m, str) and MAC_RE.fullmatch(m) for m in macs):
        raise ValueError("only normalised MACs go into a query")
    if len(macs) == 1:
        return 'mac="%s"' % macs[0]
    return 'mac=~"%s"' % "|".join(macs)


def promql_string(text):
    """A PromQL string literal (double quotes, Go escapes) of plain text; control characters are
    refused rather than escaped (no SSID has them)."""
    if not isinstance(text, str) or any(ord(c) < 32 or ord(c) == 127 for c in text):
        raise ValueError("not a plain string")
    return '"%s"' % text.replace("\\", "\\\\").replace('"', '\\"')


def selectors(ssid, macs):
    """{"sel": essid and mac matchers, "mac": the mac matcher alone, "u": the uptime series of
    the house network} for the query templates."""
    mac = mac_selector(macs)
    sel = "essid=%s,%s" % (promql_string(ssid), mac)
    return {"sel": sel, "mac": mac, "u": 'unpoller_client_uptime_seconds{job="unifi",%s}' % sel}


# --- times ------------------------------------------------------------------------------------

def iso(value):
    """ISO 8601 (UTC) of a Unix time or a datetime; None stays None."""
    if value is None:
        return None
    if isinstance(value, datetime.datetime):
        return value.astimezone(UTC).isoformat(timespec="seconds")
    return datetime.datetime.fromtimestamp(value, UTC).isoformat(timespec="seconds")


def unix(value):
    """Unix seconds of a datetime (aware; a naive one counts as UTC), a number as it is."""
    if isinstance(value, datetime.datetime):
        return (value if value.tzinfo else value.replace(tzinfo=UTC)).timestamp()
    return value


def latest(*times):
    known = [unix(t) for t in times if t is not None]
    return max(known) if known else None


# --- APs --------------------------------------------------------------------------------------

def ap_info(name):
    """{"name", "house", "floor", "spot"} of an AP; names not in the house scheme keep only
    their name (the frontend shows them as they are)."""
    if not name:
        return None
    m = AP_NAME_RE.fullmatch(name)
    if not m:
        return {"name": name, "house": None, "floor": None, "spot": None}
    return {"name": name, "house": m.group(1), "floor": int(m.group(2)), "spot": m.group(3)}


def ap_ref(name, mac=None):
    """ap_info plus the AP's MAC when known (its identity in long-term data: APs get renamed);
    None when neither is known."""
    info = ap_info(name)
    if mac is None:
        return info
    info = info or {"name": None, "house": None, "floor": None, "spot": None}
    return dict(info, mac=mac)


# --- numbers ----------------------------------------------------------------------------------

def number(text):
    """A sample value; NaN and infinities (no data) are None."""
    try:
        value = float(text)
    except (TypeError, ValueError):
        return None
    return value if math.isfinite(value) else None


def fit(value, digits):
    if value is None:
        return None
    return round(value) if digits == "int" else round(value, digits)


def rounded(value, digits):
    return None if value is None else round(value, digits)


def small_int(text):
    return int(text) if isinstance(text, str) and re.fullmatch(r"[0-9]{1,4}", text) else None


def by_mac(rows):
    return {labels.get("mac"): value for labels, value in rows if labels.get("mac")}
