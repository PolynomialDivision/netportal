"""HOUSE: the internet line, the router, the house's DNS, the latest speed test, and how old the
Wi-Fi data is (blackbox probes, the house's rules, speedtest-tracker, unpoller's snapshot age):
wifi_data_age_s (seconds, at the query) and wifi_data_at (ISO: the snapshot's time, unpoller's
poll of the controller; stable until the next snapshot)."""

from .client import SUMMARY_CACHE_SECONDS, Unavailable
from .common import iso, rounded

# The internet counts as degraded above these: the house's InternetPacketLossHigh alert fires at
# 5 % loss; the public resolvers normally answer in 5-20 ms, above 100 ms calls lag.
DEGRADED_LOSS_RATIO, DEGRADED_RTT_MS = 0.05, 100


def empty_house():
    return {"internet": "unknown", "internet_loss_ratio": None, "internet_rtt_ms": None, "dns": "unknown",
            "router": "unknown", "speedtest": None, "wifi_data_age_s": None, "wifi_data_at": None}


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
    house["internet_loss_ratio"], house["internet_rtt_ms"] = rounded(loss, 4), rounded(rtt, 1)
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
    # the age at the query's evaluation; the snapshot time (evaluation - age: unpoller's poll of
    # the controller) stays the same for every request until the next snapshot (presence's Ts)
    age = client.samples('max(unpoller_prometheus_cache_age_seconds{job="unifi"} + (time() - '
                         'timestamp(unpoller_prometheus_cache_age_seconds{job="unifi"})))')
    if age and age[0][1] is not None:
        house["wifi_data_age_s"] = int(age[0][1])
        house["wifi_data_at"] = iso(round(age[0][2] - age[0][1]))
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
            "ping_ms": rounded(latest.get("speedtest_tracker_ping_ms"), 2), "at": at}


def house(client):
    """HOUSE alone (/api/house): unknown values when telemetry is off or unavailable."""
    if client is None:
        return empty_house()
    try:
        return house_status(client.within())
    except Unavailable:
        return empty_house()
