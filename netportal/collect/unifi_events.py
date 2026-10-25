"""Job unifi_events: UniFi's client connect/disconnect/roam entries -> connection_event.

The source: UniFi Network 10.x has no event API any more; client events are in its system log
(/v2/api/site/<site>/system-log/...). unpoller (save_syslog = true) polls it and pushes every
entry to Loki as one line (github.com/unpoller/unifi system_log.go SystemLogEntry.MarshalJSON,
unpoller pkg/lokiunifi report_event.go SystemLogEvent):

  stream labels  application="unifi_system_log", job="unpoller", site_name, source, category,
                 severity
  timestamp      the entry's own time (timestamp ms)
  line (JSON)    category, event, id, key, message (rendered), parameters, severity,
                 show_on_dashboard, status, subcategory, target, timestamp (ms), title_raw, type,
                 site_name, source_name
  parameters     {NAME: {id, name, not_actionable, hostname, ip, model, model_name, version,
                 device_fingerprint_id, fingerprint_source, network_purpose, subnet, vlan_id}};
                 CLIENT.id is the client's MAC (unpoller hash_pii must stay off), DEVICE /
                 DEVICE_TO the AP (id = its MAC), WLAN the SSID (name). unpoller's struct keeps
                 only these fields: anything else the controller sends in a parameter is lost.

Not verified on our controller (10.6.109) yet, so everything is parsed defensively: the kind
comes from key/event (ROAM, DISCONNECT, CONNECT ...), the AP from DEVICE/DEVICE_TO (from-AP:
DEVICE_FROM), RSSI/channel/band from parameters or the rendered message when they are there,
and everything not mapped is kept in detail. An entry without a client MAC is skipped.

Whose data: only entries of the house SSID are kept, and entries without an SSID only when
their MAC is in a device's window (registry.device_for_mac); the registry resolves the device
at insert. dedup_key "unifi_syslog:id:<entry id>" (else the line's SHA-256) makes ingest
idempotent; every run reads from its cursor minus OVERLAP_NS, so late lines are not lost.

Late lines: Loki stores an entry under its own (the controller's) time, which may be well before
it arrives. unpoller pushes every 2 minutes what is newer than its previous push, and after an
outage (Loki or the controller away longer than 4 intervals) it resumes 4 intervals back (house-
infra stacks/monitoring/files/unpoller/up.conf): entries up to 8 minutes old arrive late, plus a
push interval and this job's own 2 minutes. OVERLAP_NS (15 minutes) covers that with room: the
cursor may stand at `now` after an empty read, the next run still reads the quarter hour before
it again (repeats are deduplicated, so the overlap only costs a re-read).

Rows are inserted and committed in batches of BATCH: resolving a device extends its window
(device_mac.last_seen), and FreeRADIUS's logging functions update the same rows on every login;
a small batch holds those row locks only briefly (the functions wait 500 ms at most, then skip).
"""

import datetime
import hashlib
import json
import logging
import re

from .. import registry
from .sources import normalise_mac

log = logging.getLogger("netportal.collect.unifi_events")

SOURCE = "unifi_syslog"
OVERLAP_NS = 15 * 60 * 10**9           # read again what may have arrived late (see the top)
FIRST_RUN_NS = 30 * 86400 * 10**9      # no cursor: from Loki's retention (30 days)
MAX_WINDOW_NS = 7 * 86400 * 10**9      # per run at most a week of log (catching up takes runs)
PAGE_LIMIT = 1000
SAME_TS_LIMIT = 5000                   # Loki's default max_entries_limit_per_query
MAX_PAGES = 50
BATCH = 100                            # rows per insert and commit (row locks held briefly)

# the radio as Prometheus/unpoller name it (ng/na/6e) from what a message or parameter says
BANDS = {"2.4": "ng", "2": "ng", "5": "na", "6": "6e"}
RADIO_CODES = {"ng", "na", "6e", "a", "g", "be"}

_RSSI_RE = re.compile(r"(-\d{2,3})\s*dBm", re.I)
_CHANNEL_RE = re.compile(r"\bCh(?:annel)?\.?\s*(\d{1,3})\b", re.I)
_BAND_RE = re.compile(r"\b(2\.4|5|6)\s*GHz\b", re.I)
_DURATION_RE = re.compile(r"(?:duration|connected for|for)\s*:?\s*((?:\d+\s*(?:d|h|hr|m|min|s|sec)\b\s*)+)", re.I)
_DURATION_PART = re.compile(r"(\d+)\s*(d|h|hr|m|min|s|sec)\b", re.I)
_UNIT_S = {"d": 86400, "h": 3600, "hr": 3600, "m": 60, "min": 60, "s": 1, "sec": 1}

# parameter names (upper case, substring match) -> what they carry
_AP_KEYS = ("DEVICE_TO", "DEVICE", "AP_TO", "AP")
_FROM_AP_KEYS = ("DEVICE_FROM", "AP_FROM", "FROM_DEVICE", "PREVIOUS_DEVICE")
_SSID_KEYS = ("WLAN", "SSID", "WLAN_NAME")


def classify(entry):
    """connected | disconnected | roamed | other, from the entry's key and event (then its title)."""
    for field in ("key", "event", "title_raw"):
        text = entry.get(field)
        if not isinstance(text, str) or not text:
            continue
        words = text.upper()
        if "ROAM" in words:
            return "roamed"
        if "DISCONNECT" in words or "DISASSOC" in words or re.search(r"(^|_)LEFT($|_)", words):
            return "disconnected"
        if "CONNECT" in words or "ASSOC" in words or re.search(r"(^|_)JOIN(ED)?($|_)", words):
            return "connected"
    return "other"


def _param(params, keys):
    for key in keys:
        value = params.get(key)
        if isinstance(value, dict):
            return value
    return None


def _text(value):
    return value.strip() if isinstance(value, str) and value.strip() else None


def _int(value, lo, hi):
    try:
        number = int(float(value))
    except (TypeError, ValueError):
        return None
    return number if lo <= number <= hi else None


def _param_value(params, *needles):
    """The id or name of the first parameter whose NAME contains one of the needles."""
    for name, value in params.items():
        if isinstance(value, dict) and any(n in name.upper() for n in needles):
            for field in ("id", "name"):
                if value.get(field) not in (None, ""):
                    return value[field]
    return None


def _radio(value):
    text = _text(str(value)) if value is not None else None
    if not text:
        return None
    low = text.lower()
    if low in RADIO_CODES:
        return low
    m = re.search(r"(2\.4|5|6)\s*(ghz|g)?", low)
    return BANDS.get(m.group(1)) if m else None


def _duration(text):
    m = _DURATION_RE.search(text or "")
    if not m:
        return None
    return sum(int(n) * _UNIT_S[u.lower()] for n, u in _DURATION_PART.findall(m.group(1)))


def entry_time(entry, ts_ns):
    """The entry's time (its own timestamp in ms when plausible, else Loki's)."""
    ms = entry.get("timestamp")
    if isinstance(ms, (int, float)) and 1e12 <= ms <= 1e13:
        return datetime.datetime.fromtimestamp(ms / 1000, datetime.timezone.utc)
    return datetime.datetime.fromtimestamp(ts_ns / 1e9, datetime.timezone.utc)


def dedup_key(entry, line):
    ident = entry.get("id")
    if isinstance(ident, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,100}", ident):
        return "%s:id:%s" % (SOURCE, ident)
    return "%s:sha256:%s" % (SOURCE, hashlib.sha256(line.encode()).hexdigest())


MAPPED = {"timestamp", "id"}


def map_entry(line, ts_ns):
    """(row, None) for a client entry, or (None, why) for one that is skipped."""
    try:
        entry = json.loads(line)
    except (TypeError, ValueError):
        return None, "malformed"
    if not isinstance(entry, dict):
        return None, "malformed"
    params = entry.get("parameters") if isinstance(entry.get("parameters"), dict) else {}
    client = params.get("CLIENT") if isinstance(params.get("CLIENT"), dict) else {}
    mac = normalise_mac(client.get("id"))
    if not mac:
        return None, "no_client_mac"
    ap = _param(params, _AP_KEYS) or {}
    from_ap = _param(params, _FROM_AP_KEYS) or {}
    wlan = _param(params, _SSID_KEYS) or {}
    message = entry.get("message") if isinstance(entry.get("message"), str) else ""
    kind = classify(entry)
    rssi = _int(_param_value(params, "RSSI", "SIGNAL"), -120, 0)
    if rssi is None:
        m = _RSSI_RE.search(message)
        rssi = _int(m.group(1), -120, 0) if m else None
    channel = _int(_param_value(params, "CHANNEL"), 1, 233)
    if channel is None:
        m = _CHANNEL_RE.search(message)
        channel = _int(m.group(1), 1, 233) if m else None
    radio = _radio(_param_value(params, "RADIO", "BAND"))
    if radio is None:
        m = _BAND_RE.search(message)
        radio = BANDS.get(m.group(1)) if m else None
    duration = _int(_param_value(params, "DURATION", "UPTIME"), 0, 10**9)
    if duration is None and kind == "disconnected":
        duration = _duration(message)
    row = {
        "at": entry_time(entry, ts_ns),
        "mac": mac,
        "kind": kind,
        "source": SOURCE,
        "ap_mac": normalise_mac(ap.get("id")),
        "ap_name": _text(ap.get("name")),
        "from_ap_mac": normalise_mac(from_ap.get("id")),
        "from_ap_name": _text(from_ap.get("name")),
        "ssid": _text(wlan.get("name")) or _text(wlan.get("id")),
        "radio": radio,
        "channel": channel,
        "rssi": rssi,
        "duration_s": duration,
        "rx_bytes": _int(_param_value(params, "RX_BYTES", "DOWNLOAD"), 0, 10**15),
        "tx_bytes": _int(_param_value(params, "TX_BYTES", "UPLOAD"), 0, 10**15),
        "dedup_key": dedup_key(entry, line),
        "detail": detail_of(entry, params),
    }
    return row, None


def detail_of(entry, params):
    """The entry without what was mapped and without the client's names (not needed, personal)."""
    detail = {k: v for k, v in entry.items() if k not in MAPPED and k != "parameters"}
    kept = {}
    for name, value in params.items():
        if name == "CLIENT" and isinstance(value, dict):
            value = {k: v for k, v in value.items() if k not in ("id", "name", "hostname")}
        kept[name] = value
    if kept:
        detail["parameters"] = kept
    return detail


def keep(db, row, ssid):
    """Whether the row is the house network's: its SSID, or (none known) a MAC in a window."""
    if row["ssid"] is not None:
        return row["ssid"] == ssid
    return registry.device_for_mac(db, row["mac"], row["at"]) is not None


def ingest(ctx, entries, counts):
    """Maps, filters and inserts one page; commits after every BATCH rows (and at the end)."""
    rows = []
    for ts, line, _labels in entries:
        counts["read"] += 1
        row, why = map_entry(line, ts)
        if row is not None and not keep(ctx.db, row, ctx.settings.ssid):
            row, why = None, "other_network"
        if row is None:
            counts["skipped"][why] = counts["skipped"].get(why, 0) + 1
            continue
        rows.append(row)
    for i in range(0, len(rows), BATCH):
        counts["inserted"] += registry.insert_connection_events(ctx.db, rows[i:i + BATCH]) or 0
        ctx.db.commit()
    ctx.db.commit()                        # also the reads of a page without rows


def run(ctx):
    loki = ctx.loki
    now_ns = int(ctx.now.timestamp() * 1e9)
    until = ctx.cursor.get("until_ns")
    if isinstance(until, int) and until > 0:
        # A run that stopped inside its range ("paging": the page limit, a stop, a failure) read
        # everything before until_ns and goes on exactly there, so paging always moves forward;
        # one that read its range to the end reads the overlap again for late lines.
        start = max(until if ctx.cursor.get("paging") else until - OVERLAP_NS, now_ns - FIRST_RUN_NS)
    else:
        start = now_ns - FIRST_RUN_NS
    end = min(now_ns, start + MAX_WINDOW_NS)
    counts = {"read": 0, "inserted": 0, "skipped": {}}
    page_start, pages, done = start, 0, False
    while pages < MAX_PAGES and not ctx.stopping():
        entries = loki.entries(ctx.settings.loki_selector, page_start, end, limit=PAGE_LIMIT)
        pages += 1
        if len(entries) >= PAGE_LIMIT and entries[-1][0] == page_start:
            # a full page of one timestamp: forward paging cannot get past it; that one
            # nanosecond with Loki's largest limit
            entries = loki.entries(ctx.settings.loki_selector, page_start, page_start + 1, limit=SAME_TS_LIMIT)
            ingest(ctx, entries, counts)
            page_start += 1
            ctx.save({"until_ns": page_start, "paging": True, "last_run": counts})
            continue
        ingest(ctx, entries, counts)
        if len(entries) < PAGE_LIMIT:
            done = True
            break
        # a full page: go on from its last timestamp (inclusive: the repeats are deduplicated)
        page_start = entries[-1][0]
        ctx.save({"until_ns": page_start, "paging": True, "last_run": counts})
    cursor = {"until_ns": end, "last_run": counts} if done else {"until_ns": page_start, "paging": True,
                                                                 "last_run": counts}
    if counts["read"]:
        log.info("unifi_events: %d read, %d new, skipped %s", counts["read"], counts["inserted"], counts["skipped"])
    return cursor
