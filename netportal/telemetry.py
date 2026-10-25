"""Wi-Fi telemetry for the "My devices" dashboard, read from the house's Prometheus.

Sources (checked against the live Prometheus on 2026-10-25):
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
- Direction: unpoller's client counters are the AP's view (transmit = to the device; the house's
  clients transmit 25 times more than they receive over an evening hour). Every rx/tx here is the
  DEVICE's view: rx = what the device receives (download), tx = what it sends (upload).
  *_rate_bps are LINK rates (the radio's speed), not throughput; throughput is rate(bytes)*8.
- The house's rules (network-wifi-health.rules.yml): wifi_client_snr_db, wifi_client_retry_ratio
  (by mac only), wifi_client_channel_utilization_ratio, wifi_client_health_score (0-100),
  network_internet_packet_loss_ratio_5m, network_internet_rtt_ms; blackbox probe_success with
  role gateway|internet (jobs blackbox_icmp, blackbox_dns); speedtest_tracker_* (job speedtest,
  the latest result only, as gauges).

Whose data it is: a device's key is the MAC of its latest RADIUS login, which the device itself
sends (and could fake). So only the house's EAP-TLS network counts (essid = NETPORTAL_SSID, on
every client selector; the byte counters and the retry ratio carry no essid and are joined to the
uptime series that does), nothing from before the device existed or before that MAC's first
login (radius_session.first_seen), and a MAC that devices of more than one person claim is
withheld from residents (web.py, registry.mac_claims).

Only validated MACs (MAC_RE) ever go into a query. One query per metric for all MACs of a page;
answers are cached 15 s (summaries of 24 h and 7 days: 60 s), one fetch per query at a time.
Each page's queries share a time budget (BUDGET_S); any failure or an exhausted budget makes the
telemetry "unavailable" (the page shows the registry's data), and for 15 s nothing is asked.
"""

import datetime
import logging
import math
import re
import threading
import time

import requests

from . import diagnostics, metrics

log = logging.getLogger("netportal.telemetry")

CACHE_SECONDS = 15
SUMMARY_CACHE_SECONDS = 60      # the 24 h and 7 day summaries change slowly
CACHE_MAX_ENTRIES = 512
# All of a page's queries together (a slow Prometheus must not hold the portal's threads); each
# query gets what is left, at most the configured timeout, and Prometheus is told to stop then too.
BUDGET_S = 5.0

MAC_RE = re.compile(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}")
_SEPARATED_MAC = re.compile(r"[0-9a-f]{2}([-:])[0-9a-f]{2}(?:\1[0-9a-f]{2}){4}")
BANDS = {"ng": "2.4", "na": "5", "6e": "6"}
# ap-<house>-<floor>-<spot>, e.g. ap-scharni-2-corner, ap-scharni-0-schlaglicht
AP_NAME_RE = re.compile(r"ap-([a-z0-9]+)-(\d{1,2})-([a-z0-9][a-z0-9-]*)")

# range -> (seconds, chart step, timeline resolution). The timeline reads the association start
# at the resolution (one point per scrape for 24 h and 7 d); the charts average per step.
RANGES = {"24h": (86400, 300, 60), "7d": (7 * 86400, 1800, 60), "30d": (30 * 86400, 7200, 120)}

STALE_AFTER_S = diagnostics.STALE_AFTER_S
# Association starts within this of each other are one connection: the snapshot time is
# exact, the uptime UniFi reports moves by up to a minute between snapshots.
SAME_ASSOCIATION_S = 120
MAX_EVENTS = 1000

CACHE_AGE = 'max(unpoller_prometheus_cache_age_seconds{job="unifi"})'
# The association start per series: snapshot time (scrape time - snapshot age) - uptime.
ASSOCIATION_START = '(timestamp({u}) - {u}) - on() group_left() ({age} or vector(0))'
_MISSING = object()


class Unavailable(Exception):
    """Prometheus did not answer usefully: down, slow, an error, an unexpected reply."""


# --- MACs and selectors -----------------------------------------------------------------------

def normalise_mac(raw):
    """aa:bb:cc:dd:ee:ff from what the AP sends as Calling-Station-Id (AA-BB-CC-DD-EE-FF),
    colon form or 12 bare hex digits; None for anything else."""
    if not isinstance(raw, str):
        return None
    mac = raw.strip().lower()
    if re.fullmatch(r"[0-9a-f]{12}", mac):
        mac = ":".join(mac[i:i + 2] for i in range(0, 12, 2))
    elif _SEPARATED_MAC.fullmatch(mac):
        mac = mac.replace("-", ":")
    else:
        return None
    return mac if MAC_RE.fullmatch(mac) else None


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


# --- the Prometheus client --------------------------------------------------------------------

def _number(text):
    """A sample value; NaN and infinities (no data) are None."""
    try:
        value = float(text)
    except (TypeError, ValueError):
        return None
    return value if math.isfinite(value) else None


def _labels(metric):
    if not isinstance(metric, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in metric.items()):
        raise ValueError("labels")
    return metric


def _parse_vector(data):
    if data["resultType"] != "vector":
        raise ValueError("not a vector")
    return [(_labels(r["metric"]), _number(r["value"][1])) for r in data["result"]]


def _parse_matrix(data):
    if data["resultType"] != "matrix":
        raise ValueError("not a matrix")
    return [(_labels(r["metric"]), [(round(float(t)), _number(v)) for t, v in r["values"]]) for r in data["result"]]


class Prometheus:
    """Instant and range queries over one HTTP session, cached, one fetch per query at a time."""

    def __init__(self, url, timeout=4.0, ssid="", session=None, clock=time.monotonic):
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.ssid = ssid                  # the house's EAP-TLS network: only its clients count
        self.session = session or requests.Session()
        self.clock = clock
        self._cache = {}
        self._inflight = {}
        self._down_until = 0.0
        self._lock = threading.Lock()

    def within(self, seconds=BUDGET_S):
        """This client with one time budget for all the queries made through it."""
        return Budget(self, self.clock() + seconds)

    def vector(self, promql, at=None, ttl=CACHE_SECONDS, deadline=None):
        """[(labels, value)] of an instant query."""
        return self._get("query", self._params(promql, time=at), _parse_vector, ttl, deadline)

    def matrix(self, promql, at=None, ttl=CACHE_SECONDS, deadline=None):
        """[(labels, [(t, value)])] of an instant query of a range (a subquery)."""
        return self._get("query", self._params(promql, time=at), _parse_matrix, ttl, deadline)

    def range(self, promql, start, end, step, ttl=CACHE_SECONDS, deadline=None):
        """[(labels, [(t, value)])] of a range query."""
        return self._get("query_range", self._params(promql, start=start, end=end, step=step), _parse_matrix,
                         ttl, deadline)

    @staticmethod
    def _params(promql, **extra):
        params = {"query": promql}
        params.update({k: "%d" % v for k, v in extra.items() if v is not None})
        return params

    def _lookup(self, key):
        hit = self._cache.get(key)
        return hit[1] if hit and hit[0] > self.clock() else _MISSING

    def _time_left(self, deadline):
        left = self.timeout if deadline is None else min(self.timeout, deadline - self.clock())
        return max(0.05, left)

    def _get(self, path, params, parse, ttl, deadline):
        key = (path, tuple(sorted(params.items())))
        refused = None
        with self._lock:
            hit = self._lookup(key)
            if hit is not _MISSING:
                return hit
            now = self.clock()
            if self._down_until > now:
                raise Unavailable("failed less than %d s ago" % CACHE_SECONDS)
            if deadline is not None and now >= deadline:
                refused = "time budget used up"
            else:
                flight = self._inflight.get(key)
                leader = flight is None
                if leader:
                    flight = self._inflight[key] = threading.Event()
        if refused:
            self._failed(refused, down=True)
            raise Unavailable(refused)
        if not leader:
            # the same query is on its way (another thread): wait for its answer, not a second fetch
            flight.wait(self._time_left(deadline))
            with self._lock:
                hit = self._lookup(key)
            if hit is not _MISSING:
                return hit
            raise Unavailable("the same query failed or did not finish")
        try:
            return self._fetch(key, path, params, parse, ttl, deadline)
        finally:
            with self._lock:
                self._inflight.pop(key, None)
            flight.set()

    def _fetch(self, key, path, params, parse, ttl, deadline):
        timeout = self._time_left(deadline)
        sent = dict(params, timeout="%ds" % max(1, math.ceil(timeout)))    # Prometheus stops evaluating too
        try:
            resp = self.session.get("%s/api/v1/%s" % (self.url, path), params=sent, timeout=timeout)
            status = resp.status_code
            body = resp.json()
        except (requests.RequestException, ValueError) as e:
            self._failed(type(e).__name__, down=True)
            raise Unavailable(type(e).__name__) from e
        if status != 200 or not isinstance(body, dict) or body.get("status") != "success":
            # 4xx: this query is wrong (a bug here), Prometheus itself works; 5xx: it does not
            self._failed("HTTP %s" % status, down=status >= 500)
            raise Unavailable("HTTP %s" % status)
        try:
            result = parse(body["data"])
        except (KeyError, TypeError, ValueError, IndexError, AttributeError) as e:
            self._failed("unexpected reply", down=False)
            raise Unavailable("unexpected reply") from e
        metrics.TELEMETRY_QUERIES.labels("ok").inc()
        with self._lock:
            now = self.clock()
            if len(self._cache) >= CACHE_MAX_ENTRIES:
                self._cache = {k: v for k, v in self._cache.items() if v[0] > now}
                if len(self._cache) >= CACHE_MAX_ENTRIES:
                    self._cache.clear()
            self._cache[key] = (now + ttl, result)
        return result

    def _failed(self, why, down):
        metrics.TELEMETRY_QUERIES.labels("error").inc()
        log.warning("Prometheus query failed: %s", why)        # never the query: it holds MACs
        if down:
            with self._lock:
                self._down_until = self.clock() + CACHE_SECONDS


class Budget:
    """A Prometheus client whose queries share one deadline (one page's worth)."""

    def __init__(self, client, deadline):
        self.client, self.deadline, self.ssid = client, deadline, client.ssid

    def within(self, seconds=BUDGET_S):
        return self                               # already counting

    def vector(self, promql, at=None, ttl=CACHE_SECONDS):
        return self.client.vector(promql, at, ttl, self.deadline)

    def matrix(self, promql, at=None, ttl=CACHE_SECONDS):
        return self.client.matrix(promql, at, ttl, self.deadline)

    def range(self, promql, start, end, step, ttl=CACHE_SECONDS):
        return self.client.range(promql, start, end, step, ttl, self.deadline)


# --- small helpers ----------------------------------------------------------------------------

def iso(value):
    """ISO 8601 (UTC) of a Unix time or a datetime; None stays None."""
    if value is None:
        return None
    if isinstance(value, datetime.datetime):
        return value.astimezone(datetime.timezone.utc).isoformat(timespec="seconds")
    return datetime.datetime.fromtimestamp(value, datetime.timezone.utc).isoformat(timespec="seconds")


def _unix(value):
    return value.timestamp() if isinstance(value, datetime.datetime) else value


def data_bound(row):
    """From when Prometheus's data for this device's MAC is this device's: the later of its
    enrolment and the first login with that MAC (Unix seconds, None if neither is known)."""
    known = [_unix(row.get(k)) for k in ("created", "first_seen") if row.get(k) is not None]
    return max(known) if known else None


def ap_info(name):
    """{"name", "house", "floor", "spot"} of an AP; names not in the house scheme keep only
    their name (the frontend shows them as they are)."""
    if not name:
        return None
    m = AP_NAME_RE.fullmatch(name)
    if not m:
        return {"name": name, "house": None, "floor": None, "spot": None}
    return {"name": name, "house": m.group(1), "floor": int(m.group(2)), "spot": m.group(3)}


def _int(text):
    return int(text) if isinstance(text, str) and re.fullmatch(r"[0-9]{1,4}", text) else None


def _round(value, digits):
    return None if value is None else round(value, digits)


def _by_mac(rows):
    return {labels.get("mac"): value for labels, value in rows if labels.get("mac")}


# --- the house --------------------------------------------------------------------------------

def empty_house():
    return {"internet": "unknown", "internet_loss_ratio": None, "internet_rtt_ms": None, "dns": "unknown",
            "router": "unknown", "speedtest": None, "wifi_data_age_s": None}


# The internet counts as degraded above these: the house's InternetPacketLossHigh alert fires at
# 5 % loss; the public resolvers normally answer in 5-20 ms, above 100 ms calls lag.
DEGRADED_LOSS_RATIO, DEGRADED_RTT_MS = 0.05, 100


def _up_state(value):
    return "unknown" if value is None else ("ok" if value >= 1 else "down")


def house_status(client):
    """HOUSE: the internet line, the router, the house's DNS, the latest speed test, and how old
    the Wi-Fi data is."""
    house = empty_house()
    probes = {(m.get("job"), m.get("role")): v for m, v in client.vector(
        'max by (job, role) (probe_success{job=~"blackbox_icmp|blackbox_dns",role=~"gateway|internet"})')}
    house["router"] = _up_state(probes.get(("blackbox_icmp", "gateway")))
    house["dns"] = _up_state(probes.get(("blackbox_dns", "gateway")))     # OPNsense Unbound
    line = {m.get("__name__"): v for m, v in client.vector(
        '{__name__=~"network_internet_packet_loss_ratio_5m|network_internet_rtt_ms"}')}
    loss, rtt = line.get("network_internet_packet_loss_ratio_5m"), line.get("network_internet_rtt_ms")
    house["internet_loss_ratio"], house["internet_rtt_ms"] = _round(loss, 4), _round(rtt, 1)
    internet = probes.get(("blackbox_icmp", "internet"))       # max: any public host answers
    if internet is None:
        house["internet"] = "unknown"
    elif internet < 1:
        house["internet"] = "down"
    elif (loss is not None and loss > DEGRADED_LOSS_RATIO) or (rtt is not None and rtt > DEGRADED_RTT_MS):
        house["internet"] = "degraded"
    else:
        house["internet"] = "ok"
    house["speedtest"] = speedtest(client)
    age = client.vector('max(unpoller_prometheus_cache_age_seconds{job="unifi"} + (time() - '
                        'timestamp(unpoller_prometheus_cache_age_seconds{job="unifi"})))')
    house["wifi_data_age_s"] = int(age[0][1]) if age and age[0][1] is not None else None
    return house


def speedtest(client):
    """The latest speed test of the internet line: {download_bps, upload_bps, ping_ms, at}, or
    None. speedtest-tracker shows only its latest result (as gauges with the server as labels);
    "at" is when its result id last changed (within a minute; None if not in the last 2 days)."""
    rows = client.vector('{job="speedtest",__name__=~"speedtest_tracker_(download_bits|upload_bits|ping_ms|result_id)"}')
    results = {}
    for labels, value in rows:
        key = tuple(sorted((k, v) for k, v in labels.items() if k != "__name__"))
        results.setdefault(key, {})[labels.get("__name__")] = value
    if not results:
        return None
    key, latest = max(results.items(), key=lambda kv: kv[1].get("speedtest_tracker_result_id") or -1)
    if dict(key).get("status", "completed") != "completed" or latest.get("speedtest_tracker_download_bits") is None:
        return None
    result_id = latest.get("speedtest_tracker_result_id")
    at = None
    history = client.matrix('max(speedtest_tracker_result_id{job="speedtest"})[2d:1m]', ttl=SUMMARY_CACHE_SECONDS)
    points = history[0][1] if history else []
    if result_id is not None and points and points[-1][1] == result_id:
        i = len(points) - 1
        while i > 0 and points[i - 1][1] == result_id:
            i -= 1
        at = iso(points[i][0]) if i > 0 else None      # the same id for 2 days: when is not known
    return {"download_bps": int(latest["speedtest_tracker_download_bits"]),
            "upload_bps": None if latest.get("speedtest_tracker_upload_bits") is None
            else int(latest["speedtest_tracker_upload_bits"]),
            "ping_ms": _round(latest.get("speedtest_tracker_ping_ms"), 2), "at": at}


# --- devices ----------------------------------------------------------------------------------

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


def _fit(value, digits):
    if value is None:
        return None
    return round(value) if digits == "int" else round(value, digits)


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


def count_reconnects(starts):
    """New associations in [(t, association start)]: a start later than the previous one by
    more than SAME_ASSOCIATION_S (whether or not the data has a gap in between)."""
    count, prev = 0, None
    for _t, start in starts:
        if start is None:
            continue
        if prev is not None and start - prev > SAME_ASSOCIATION_S:
            count += 1
        prev = start
    return count


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
                  band=BANDS.get(labels.get("radio")), channel=_int(labels.get("channel")),
                  proto=labels.get("radio_proto"), ip=labels.get("ip"))
    for mac, st in status.items():
        if st["start"] is not None and bounds.get(mac) is not None:
            st["start"] = max(st["start"], bounds[mac])
    for field, (promql, digits) in GAUGES.items():
        for mac, value in _by_mac(client.vector(promql.format(**parts))).items():
            if mac in status:
                status[mac][field] = _fit(value, digits)
    day = [mac for mac in macs if bounds.get(mac) is None or bounds[mac] <= now - 86400]
    if day:
        day_parts = selectors(client.ssid, day)
        for field, promql in DAY_TOTALS.items():
            for mac, value in _by_mac(client.vector(promql.format(**day_parts))).items():
                if mac in status:
                    status[mac][field] = _fit(value, "int")
    # AP/band changes in the last hour, from the per-minute AP of each device
    where = {}
    for labels, points in client.matrix('max by (mac, ap_name, radio) (%s)[1h:1m]' % u):
        mac = labels.get("mac")
        for t, uptime in points:
            if uptime is not None and after(mac, t):
                where.setdefault(mac, {}).setdefault(t, []).append((uptime, labels.get("ap_name"),
                                                                    labels.get("radio")))
    for mac, by_t in where.items():
        if mac in status:
            # two series at one minute (rare): the newer association (smaller uptime)
            newest = [(t, *min(v, key=lambda x: x[0])[1:]) for t, v in sorted(by_t.items())]
            status[mac]["roams_1h"] = count_changes(newest)
    summary = {mac: {"reconnects_24h": None, "bands_7d": [], "tx_attempts_per_s": None} for mac in macs}
    attempts = 'sum by (mac) (rate(unpoller_client_wifi_attempts_transmit_total{job="unifi",%s}[5m]))' % parts["sel"]
    for mac, value in _by_mac(client.vector(attempts)).items():
        if mac in summary:
            summary[mac]["tx_attempts_per_s"] = _round(value, 2)
    fresh_starts = ('((max by (mac) (timestamp({u}) - {u}) - on() group_left() {age}) '
                    'and on() ({age} <= {stale}))[24h:5m]').format(u=u, age=CACHE_AGE, stale=STALE_AFTER_S)
    for labels, points in client.matrix(fresh_starts, ttl=SUMMARY_CACHE_SECONDS):
        mac = labels.get("mac")
        if mac in summary:
            summary[mac]["reconnects_24h"] = count_reconnects([(t, s) for t, s in points if after(mac, t)])
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
        for mac, t in _by_mac(client.vector(promql, ttl=SUMMARY_CACHE_SECONDS)).items():
            if mac in status and t is not None and after(mac, t):
                status[mac]["last_seen"] = t
    return status, summary


def _latest(*times):
    known = [_unix(t) for t in times if t is not None]
    return max(known) if known else None


def other_owners(claims, mac, owner):
    """How many other people's active devices claim this MAC (registry.mac_claims)."""
    return len(set((claims or {}).get(mac, ())) - {owner}) if mac else 0


def device_entry(row, mac, status, telemetry, house, now, summary=None, conflict=0, admin=False):
    """DEVICE from a registry row (registry.DEVICE_LIST) and its live status. conflict: the
    number of other people whose devices claim the same MAC; residents then see no telemetry."""
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
        last_seen = _latest(status["last_seen"], row.get("last_seen"))
    else:
        last_seen = _unix(row.get("last_seen"))   # RADIUS: the device's latest login
    device = {
        "id": str(row["id"]), "name": row["name"], "platform": row["platform"], "policy": row.get("policy"),
        "created": iso(row.get("created")), "expires": iso(row.get("expires")), "revoked": bool(row.get("revoked")),
        "mac": mac, "state": state, "last_seen": iso(last_seen),
        "since": iso(status["start"]) if state == "online" else None,
    }
    device.update({f: status[f] for f in LIVE_FIELDS})
    if withheld:
        device["diagnostics"] = [diagnostics.finding("mac_conflict", "warn")]
        return device
    summary = dict(summary or {}, associated_s=now - status["start"] if state == "online" else None)
    device["diagnostics"] = diagnostics.findings(device, summary, house.get("wifi_data_age_s"), telemetry)
    if conflict:
        device["diagnostics"].insert(0, diagnostics.finding("mac_conflict", "warn", owners=conflict))
    return device


def dashboard(client, rows, owners=None, now=None, claims=None, admin=False):
    """The /api/devices payload for these registry rows. client None: telemetry "off".
    owners ({sub: {"username", "display"}}) adds each device's owner. claims ({mac: {owner sub}}
    of every active device, registry.mac_claims): a MAC claimed by other people's devices too is
    not asked for and shows as "unknown" with mac_conflict, unless admin (then with the count)."""
    now = time.time() if now is None else now
    telemetry, house, statuses, summaries = ("off" if client is None else "ok"), empty_house(), {}, {}
    macs = {row["id"]: normalise_mac(row.get("calling_station")) for row in rows}
    conflicts = {row["id"]: other_owners(claims, macs[row["id"]], row.get("owner")) for row in rows}
    bounds = {}
    for row in rows:
        mac, bound = macs[row["id"]], data_bound(row)
        if mac and (admin or not conflicts[row["id"]]) and bound is not None:
            bounds[mac] = max(bound, bounds.get(mac, bound))      # several devices, one MAC: the latest
    wanted = sorted({macs[row["id"]] for row in rows if macs[row["id"]] and (admin or not conflicts[row["id"]])})
    if client is not None:
        client = client.within()
        try:
            house = house_status(client)
            if wanted:
                statuses, summaries = device_status(client, wanted, bounds, now)
        except Unavailable:
            telemetry, statuses, summaries = "unavailable", {}, {}
    devices = []
    for row in rows:
        mac = macs[row["id"]]
        device = device_entry(row, mac, statuses.get(mac), telemetry, house, now, summaries.get(mac),
                              conflicts[row["id"]], admin)
        if owners is not None:
            person = owners.get(row.get("owner")) or {}
            device["owner"] = {"username": person.get("username"), "display": person.get("display")}
        devices.append(device)
    return {"generated_at": iso(now), "telemetry": telemetry,
            "stale": telemetry == "ok" and diagnostics.is_stale(house["wifi_data_age_s"]),
            "house": house, "devices": devices}


def house(client):
    """HOUSE alone (/api/house): unknown values when telemetry is off or unavailable."""
    if client is None:
        return empty_house()
    try:
        return house_status(client.within())
    except Unavailable:
        return empty_house()


# --- history ----------------------------------------------------------------------------------

def event(kind, at, ap=None, band=None, from_ap=None, from_band=None, duration_s=None):
    return {"kind": kind, "at": at, "ap": ap, "band": band, "from_ap": from_ap, "from_band": from_band,
            "duration_s": None if duration_s is None else int(duration_s)}


def derive_timeline(points, res, last_fresh=None, since=None):
    """(events, spans) from [(t, association start, ap_name, radio)] sorted by t, fresh data
    only. A connection is one association start: a later start (with or without a gap) is a
    disconnect plus a new connection; a gap with the same start is missing data, not a
    disconnect (the device stayed associated). AP changes are roams, band changes on the same AP
    band changes. A device not seen for 3 resolutions before the last fresh data is disconnected
    now. Nothing before since (the device's data bound). Times are Unix seconds (event "at"
    ISO); spans are (connected at, last seen)."""
    events, spans, cur = [], [], None

    def close(c):
        c["event"]["duration_s"] = int(c["last"] - c["at"])
        spans.append((c["at"], c["last"]))

    for t, start, ap_name, radio in points:
        if since is not None and t < since:
            continue
        start, band = min(start, t), BANDS.get(radio)
        if since is not None:
            start = max(start, since)
        if cur is not None and start - cur["start"] <= SAME_ASSOCIATION_S:
            if (ap_name, band) != (cur["ap"], cur["band"]):
                kind = "roamed" if ap_name != cur["ap"] else "band_changed"
                events.append(event(kind, t, ap_name, band, cur["ap"], cur["band"], t - cur["changed"]))
                cur.update(ap=ap_name, band=band, changed=t)
            cur.update(start=start, last=t)
            continue
        at = start if cur is None else max(start, cur["last"])
        if cur is not None:
            close(cur)
            events.append(event("disconnected", cur["last"], cur["ap"], cur["band"], duration_s=at - cur["last"]))
        new = event("connected", at, ap_name, band, duration_s=0)
        events.append(new)
        cur = {"start": start, "at": at, "last": t, "ap": ap_name, "band": band, "changed": at, "event": new}
    if cur is not None:
        close(cur)
        if last_fresh is not None and last_fresh - cur["last"] >= 3 * res:
            events.append(event("disconnected", cur["last"], cur["ap"], cur["band"],
                                duration_s=last_fresh - cur["last"]))
    return events, spans


def _public_events(events):
    """Events as the API shows them: ISO times, the AP as {"name", "house", "floor", "spot"}."""
    return [dict(e, at=iso(e["at"]), ap=ap_info(e["ap"]), from_ap=ap_info(e["from_ap"])) for e in events]


def _grid(start, end, step):
    return list(range(start, end + 1, step))


def _on_grid(grid, points, digits):
    values = dict(points)
    return [[t, _fit(values.get(t), digits)] for t in grid]


CHARTS = {
    "signal_dbm": ('avg(avg_over_time(unpoller_client_radio_signal_db{{job="unifi",{sel}}}[{step}s]))', 1),
    "health": ('avg(avg_over_time(wifi_client_health_score{{{sel}}}[{step}s]))', 1),
    "rx_bps": (('sum(rate(unpoller_client_transmit_bytes_total{{job="unifi",{mac}}}[{step}s]) '
               'and on (mac) max_over_time({u}[{step}s])) * 8'), "int"),
    "tx_bps": (('sum(rate(unpoller_client_receive_bytes_total{{job="unifi",{mac}}}[{step}s]) '
               'and on (mac) max_over_time({u}[{step}s])) * 8'), "int"),
    "link_rx_bps": ('avg(avg_over_time(unpoller_client_radio_transmit_rate_bps{{job="unifi",{sel}}}[{step}s]))', "int"),
    "link_tx_bps": ('avg(avg_over_time(unpoller_client_radio_receive_rate_bps{{job="unifi",{sel}}}[{step}s]))', "int"),
}


def empty_history(range_key, telemetry, now=None, since=None, withheld=None):
    seconds, step, _res = RANGES[range_key]
    end = int((time.time() if now is None else now) // 60 * 60)
    return {"range": range_key, "step_s": step, "start": end - seconds, "end": end, "telemetry": telemetry,
            "data_from": None if since is None else int(since), "withheld": withheld,
            "series": {name: [] for name in list(CHARTS) + ["online"]}, "timeline": [], "timeline_truncated": False}


def history(client, mac, range_key, now=None, since=None, withheld=None):
    """The detail page's charts and connection timeline for one device. since: its data bound
    (data_bound); points and events before it are left out (null). withheld ("mac_conflict"):
    nothing is asked, the payload says why. Raises ValueError for an unknown range or a MAC that
    is not normalised."""
    if range_key not in RANGES:
        raise ValueError("unknown range")
    if client is None or mac is None or withheld:
        return empty_history(range_key, "off" if client is None else "ok", now, since, withheld)
    parts = selectors(client.ssid, [mac])
    payload = empty_history(range_key, "ok", now, since)
    seconds, step, res = RANGES[range_key]
    start, end = payload["start"], payload["end"]
    client = client.within()
    try:
        span = "[%ds:%ds]" % (seconds + step, res)
        ages = client.matrix(CACHE_AGE + span, at=end)
        assoc = client.matrix('(max by (ap_name, radio) (timestamp({u}) - {u}) - on() group_left() ({age} or '
                              'vector(0))){span}'.format(u=parts["u"], age=CACHE_AGE, span=span), at=end)
        charts = {name: client.range(promql.format(step=step, **parts), start, end, step)
                  for name, (promql, _digits) in CHARTS.items()}
    except Unavailable:
        return empty_history(range_key, "unavailable", now, since)
    fresh = {t for t, age in (ages[0][1] if ages else []) if age is not None and age <= STALE_AFTER_S
             and (since is None or t >= since)}
    by_t = {}
    for labels, values in assoc:
        for t, assoc_start in values:
            if t in fresh and assoc_start is not None:
                by_t.setdefault(t, []).append((assoc_start, labels.get("ap_name"), labels.get("radio")))
    points = [(t, *max(v, key=lambda x: x[0])) for t, v in sorted(by_t.items())]   # the newest association
    events, spans = derive_timeline(points, res, max(fresh) if fresh else None, since)
    grid = _grid(start, end, step)
    # a chart point (t - step, t] counts when it holds fresh data of the device's own time
    fresh_k = {-(-(f - start) // step) for f in fresh}
    fresh_window = {t: (t - start) // step in fresh_k for t in grid}
    for name, (_promql, digits) in CHARTS.items():
        rows = charts[name]
        series = _on_grid(grid, rows[0][1] if rows else [], digits)
        payload["series"][name] = [[t, v if fresh_window[t] else None] for t, v in series]
    payload["series"]["online"] = [
        [t, (1 if any(a <= t and last > t - step for a, last in spans) else 0) if fresh_window[t] else None]
        for t in grid]
    payload["timeline_truncated"] = len(events) > MAX_EVENTS
    payload["timeline"] = _public_events(events[-MAX_EVENTS:])
    return payload
