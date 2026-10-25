"""The dashboard's Prometheus client and what it derives (netportal/telemetry.py), against a
fake Prometheus that answers canned JSON by query. Example MACs and values only."""

import logging
import re
import sys
import unittest
from pathlib import Path
from unittest import mock

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from netportal import metrics, telemetry  # noqa: E402

NOW = 1_800_000_000


def setUpModule():
    logging.getLogger("netportal.telemetry").setLevel(logging.CRITICAL)   # the failures are expected
MAC_A, MAC_B, MAC_C = "02:00:00:00:00:0a", "02:00:00:00:00:0b", "02:00:00:00:00:0c"


def vector(*rows):
    return {"resultType": "vector", "result": [{"metric": m, "value": [NOW, str(v)]} for m, v in rows]}


def matrix(*rows):
    return {"resultType": "matrix", "result": [{"metric": m, "values": [[t, str(v)] for t, v in vals]}
                                               for m, vals in rows]}


class FakeResponse:
    def __init__(self, data, status=200):
        self.status_code = status
        self._body = {"status": "success", "data": data} if status == 200 else {"status": "error", "errorType": "x"}

    def json(self):
        return self._body


class FakeSession:
    """Answers each query with the first handler whose text occurs in it ("^text": that it
    starts with), an empty result if none; remembers every query."""

    def __init__(self, handlers=(), fail=None):
        self.handlers = list(handlers)
        self.fail = fail
        self.calls = []

    def get(self, url, params=None, timeout=None):
        self.calls.append((url, dict(params)))
        if self.fail:
            raise self.fail
        query = params["query"]
        for needle, data in self.handlers:
            if "query_range" in url and data["resultType"] != "matrix":
                continue                       # a live value's handler, not a chart's
            if query.startswith(needle[1:]) if needle.startswith("^") else needle in query:
                return FakeResponse(data)
        kind = "matrix" if "query_range" in url or re.search(r":\d+[smhd]\]$", query) else "vector"
        return FakeResponse({"resultType": kind, "result": []})

    def queries(self, needle=""):
        return [p["query"] for _u, p in self.calls if needle in p["query"]]


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


SSID = "Example"


def client(handlers=(), fail=None, ssid=SSID):
    session = FakeSession(handlers, fail)
    return telemetry.Prometheus("http://prometheus.example:9090", 4, ssid=ssid, session=session, clock=Clock()), session


HOUSE_OK = [
    ("max by (job, role) (probe_success", vector(({"job": "blackbox_icmp", "role": "gateway"}, 1),
                                                 ({"job": "blackbox_icmp", "role": "internet"}, 1),
                                                 ({"job": "blackbox_dns", "role": "gateway"}, 1))),
    ("network_internet_packet_loss_ratio_5m|", vector(({"__name__": "network_internet_packet_loss_ratio_5m"}, 0),
                                                      ({"__name__": "network_internet_rtt_ms"}, 5.04))),
    ('{job="speedtest",__name__', vector(
        ({"__name__": "speedtest_tracker_download_bits", "server_id": "1", "status": "completed"}, 236752744),
        ({"__name__": "speedtest_tracker_upload_bits", "server_id": "1", "status": "completed"}, 86375664),
        ({"__name__": "speedtest_tracker_ping_ms", "server_id": "1", "status": "completed"}, 4.2),
        ({"__name__": "speedtest_tracker_result_id", "server_id": "1", "status": "completed"}, 126))),
    ("max(speedtest_tracker_result_id", matrix(({}, [(NOW - 180, 125), (NOW - 120, 126), (NOW - 60, 126)]))),
    ("time() - timestamp(unpoller_prometheus_cache_age_seconds", vector(({}, 42.5))),
]


class MacTests(unittest.TestCase):
    def test_normalise(self):
        for raw in ("02-00-00-00-00-0A", "02:00:00:00:00:0a", "0200000000 0A".replace(" ", ""), " 02-00-00-00-00-0a\n"):
            self.assertEqual(telemetry.normalise_mac(raw), MAC_A, raw)

    def test_refused(self):
        for raw in (None, "", "02-00-00-00-00", "02:00:00:00:00:0a:0b", "02-00:00-00-00-0a", "0200.0000.000a",
                    "02:00:00:00:00:0g", "zz:zz:zz:zz:zz:zz", '02:00:00:00:00:0a"} or vector(1) #',
                    "02:00:00:00:00:0a|.*", ".*", "02:00:00:00:00:0a\\", "０２:00:00:00:00:0a", 12345):
            self.assertIsNone(telemetry.normalise_mac(raw), raw)

    def test_selector_takes_only_normalised_macs(self):
        self.assertEqual(telemetry.mac_selector([MAC_A]), 'mac="%s"' % MAC_A)
        self.assertEqual(telemetry.mac_selector([MAC_B, MAC_A, MAC_B]), 'mac=~"%s|%s"' % (MAC_A, MAC_B))
        for bad in ([], ["02-00-00-00-00-0A"], [MAC_A, '.*"} or vector(1) #'], [MAC_A, ".*"], [None]):
            with self.assertRaises(ValueError):
                telemetry.mac_selector(bad)

    def test_history_refuses_a_raw_mac(self):
        prom, session = client()
        with self.assertRaises(ValueError):
            telemetry.history(prom, '.*"}', "24h", now=NOW)
        self.assertEqual(session.calls, [])

    def test_ap_names(self):
        self.assertEqual(telemetry.ap_info("ap-scharni-2-corner"),
                         {"name": "ap-scharni-2-corner", "house": "scharni", "floor": 2, "spot": "corner"})
        self.assertEqual(telemetry.ap_info("ap-scharni-0-schlaglicht")["spot"], "schlaglicht")
        self.assertEqual(telemetry.ap_info("2. stock scharni mitte"),
                         {"name": "2. stock scharni mitte", "house": None, "floor": None, "spot": None})
        self.assertIsNone(telemetry.ap_info(None))


class ClientTests(unittest.TestCase):
    def test_cached_for_15_seconds(self):
        prom, session = client([("up", vector(({}, 1)))])
        self.assertEqual(prom.vector("up"), [({}, 1.0)])
        prom.clock.t += 14
        prom.vector("up")
        self.assertEqual(len(session.calls), 1)
        prom.clock.t += 2
        prom.vector("up")
        self.assertEqual(len(session.calls), 2)

    def test_timeout_and_one_session(self):
        prom, session = client([("up", vector(({}, 1)))])
        with mock.patch.object(session, "get", wraps=session.get) as get:
            prom.vector("up")
        self.assertEqual(get.call_args.kwargs["timeout"], 4)
        self.assertEqual(get.call_args.args[0], "http://prometheus.example:9090/api/v1/query")

    def test_down_answers_unavailable_and_is_not_asked_again_for_15_seconds(self):
        before = metrics.TELEMETRY_QUERIES.labels("error")._value.get()
        prom, session = client(fail=requests.ConnectTimeout("slow"))
        with self.assertRaises(telemetry.Unavailable):
            prom.vector("up")
        with self.assertRaises(telemetry.Unavailable):
            prom.vector("other")
        self.assertEqual(len(session.calls), 1)
        self.assertEqual(metrics.TELEMETRY_QUERIES.labels("error")._value.get(), before + 1)
        prom.clock.t += 16
        session.fail = None
        prom.vector("up")
        self.assertEqual(len(session.calls), 2)

    def test_error_replies(self):
        prom, session = client()
        session.get = lambda *a, **k: FakeResponse(None, status=400)
        with self.assertRaises(telemetry.Unavailable):
            prom.vector("bad(")
        prom2, _ = client([("up", matrix(({}, [(1, 1)])))])       # a matrix where a vector belongs
        with self.assertRaises(telemetry.Unavailable):
            prom2.vector("up")
        prom3, session3 = client()
        session3.get = lambda *a, **k: mock.Mock(status_code=200, json=mock.Mock(side_effect=ValueError("html")))
        with self.assertRaises(telemetry.Unavailable):
            prom3.vector("up")

    def test_nan_and_inf_are_none(self):
        prom, _ = client([("x", vector(({"a": "1"}, "NaN"), ({"a": "2"}, "+Inf"), ({"a": "3"}, "1.5")))])
        self.assertEqual([v for _m, v in prom.vector("x")], [None, None, 1.5])

    def test_ok_counted(self):
        before = metrics.TELEMETRY_QUERIES.labels("ok")._value.get()
        prom, _ = client([("up", vector(({}, 1)))])
        prom.vector("up")
        prom.vector("up")                                  # cached: not a query
        self.assertEqual(metrics.TELEMETRY_QUERIES.labels("ok")._value.get(), before + 1)


def live(macs_present):
    """A fake Prometheus for the device queries: MAC_A online on ap-scharni-2-corner (5 GHz),
    MAC_B seen 2 hours ago, nothing about others."""
    start_a = NOW - 3600
    return HOUSE_OK + [
        ("^(timestamp(unpoller_client_uptime_seconds", vector(
            ({"mac": MAC_A, "ap_name": "ap-scharni-2-corner", "essid": "Scharni", "radio": "na", "channel": "56",
              "radio_proto": "ax", "ip": "10.0.30.5"}, start_a),) if MAC_A in macs_present else vector()),
        ("max by (mac) (unpoller_client_radio_signal_db", vector(({"mac": MAC_A}, -58),)),
        ("max by (mac) (unpoller_client_noise_db", vector(({"mac": MAC_A}, -96),)),
        ("max by (mac) (wifi_client_snr_db", vector(({"mac": MAC_A}, 38),)),
        ("min by (mac) (wifi_client_health_score", vector(({"mac": MAC_A}, 91.24),)),
        ("max by (mac) (wifi_client_retry_ratio", vector(({"mac": MAC_A}, 0.0312),)),
        ("max by (mac) (wifi_client_channel_utilization_ratio", vector(({"mac": MAC_A}, 0.2),)),
        ("max by (mac) (unpoller_client_radio_transmit_rate_bps", vector(({"mac": MAC_A}, 864000000),)),
        ("max by (mac) (unpoller_client_radio_receive_rate_bps", vector(({"mac": MAC_A}, 576000000),)),
        ("rate(unpoller_client_transmit_bytes_total", vector(({"mac": MAC_A}, 125000.4),)),
        ("rate(unpoller_client_receive_bytes_total", vector(({"mac": MAC_A}, 2500),)),
        ("increase(unpoller_client_transmit_bytes_total", vector(({"mac": MAC_A}, 9e9), ({"mac": MAC_B}, 1e6))),
        ("increase(unpoller_client_receive_bytes_total", vector(({"mac": MAC_A}, 3e8), ({"mac": MAC_B}, 2e5))),
        ("max by (mac, ap_name, radio)", matrix(
            ({"mac": MAC_A, "ap_name": "ap-scharni-1-corner", "radio": "na"}, [(NOW - 600, 3000)]),
            ({"mac": MAC_A, "ap_name": "ap-scharni-2-corner", "radio": "na"}, [(NOW - 540, 3060), (NOW - 60, 3540)]))),
        ("[24h:5m]", matrix(({"mac": MAC_A}, [(NOW - 7200, NOW - 9000), (NOW - 6900, NOW - 9010),
                                              (NOW - 3300, start_a)]),)),
        ("^max by (mac, radio)", vector(({"mac": MAC_A, "radio": "na"}, NOW - 60),
                                        ({"mac": MAC_A, "radio": "ng"}, NOW - 86400),
                                        ({"mac": MAC_B, "radio": "ng"}, NOW - 7200))),
        ("wifi_attempts_transmit_total", vector(({"mac": MAC_A}, 50),)),
        ("max_over_time(timestamp(", vector(({"mac": MAC_B}, NOW - 7200),)),
    ]


def brief(findings):
    """(code, severity, params) of each finding (basis and evidence are tested on their own)."""
    return [(f["code"], f["severity"], f["params"]) for f in findings]


def row(device_id, mac_raw, **extra):
    return dict({"id": device_id, "owner": "sub-resident", "name": "Phone " + device_id, "platform": "android",
                 "policy": "residents", "created": None, "revoked": None, "expires": None, "last_seen": None,
                 "calling_station": mac_raw}, **extra)


class DashboardTests(unittest.TestCase):
    def rows(self):
        return [row("a", MAC_A.upper().replace(":", "-")), row("b", MAC_B.upper().replace(":", "-")),
                row("c", None), row("d", "not a mac")]

    def test_one_query_per_metric_for_all_macs(self):
        prom, session = client(live({MAC_A}))
        telemetry.dashboard(prom, self.rows(), now=NOW)
        sel = 'mac=~"%s|%s"' % (MAC_A, MAC_B)
        for metric in ("max by (mac) (unpoller_client_radio_signal_db", "wifi_client_health_score",
                       "wifi_client_retry_ratio", "rate(unpoller_client_transmit_bytes_total", "max by (mac, radio)",
                       "avg by (mac, ap_name) (avg_over_time(unpoller_client_radio_signal_db"):
            queries = session.queries(metric)
            self.assertEqual(len(queries), 1, metric)
            self.assertIn(sel, queries[0])
        # only the absent device's last sighting is looked up
        self.assertIn('mac="%s"' % MAC_B, session.queries("max by (mac) (max_over_time(timestamp(")[0])
        # nothing but normalised MACs in any query
        for q in session.queries():
            self.assertNotIn("not a mac", q)
            self.assertNotIn("02-00", q)

    def test_online_offline_never(self):
        prom, _ = client(live({MAC_A}))
        payload = telemetry.dashboard(prom, self.rows(), now=NOW)
        self.assertEqual(payload["telemetry"], "ok")
        self.assertFalse(payload["stale"])
        a, b, c, d = payload["devices"]
        self.assertEqual(a["state"], "online")
        self.assertEqual(a["mac"], MAC_A)
        self.assertEqual(a["since"], telemetry.iso(NOW - 3600))
        self.assertEqual(a["last_seen"], telemetry.iso(NOW - 42))       # the snapshot's time
        self.assertEqual(a["ap"], {"name": "ap-scharni-2-corner", "house": "scharni", "floor": 2, "spot": "corner"})
        self.assertEqual((a["ssid"], a["band"], a["channel"], a["proto"]), ("Scharni", "5", 56, "ax"))
        self.assertEqual((a["signal_dbm"], a["snr_db"], a["health"], a["retry_ratio"]), (-58, 38, 91.2, 0.0312))
        self.assertEqual((a["link_rx_bps"], a["link_tx_bps"]), (864000000, 576000000))
        self.assertEqual((a["rx_bps"], a["tx_bps"]), (125000, 2500))
        self.assertEqual((a["rx_24h_bytes"], a["tx_24h_bytes"]), (9000000000, 300000000))
        self.assertEqual(a["roams_1h"], 1)
        self.assertEqual(a["diagnostics"], [])
        self.assertEqual(b["state"], "offline")
        self.assertEqual(b["last_seen"], telemetry.iso(NOW - 7200))
        self.assertIsNone(b["signal_dbm"])
        self.assertIsNone(b["roams_1h"])                                  # no data: unknown, not 0
        self.assertEqual([f["code"] for f in b["diagnostics"]], ["offline"])
        for never in (c, d):
            self.assertEqual(never["state"], "never_connected")
            self.assertIsNone(never["mac"])
            self.assertEqual([f["code"] for f in never["diagnostics"]], ["never_connected"])
        self.assertEqual(payload["house"]["speedtest"], {"download_bps": 236752744, "upload_bps": 86375664,
                                                         "ping_ms": 4.2, "at": telemetry.iso(NOW - 120)})

    def test_offline_last_seen_falls_back_to_the_registry(self):
        import datetime
        radius = datetime.datetime.fromtimestamp(NOW - 30 * 86400, datetime.timezone.utc)
        prom, _ = client([h for h in live(set()) if h[0] != "max_over_time(timestamp("])
        payload = telemetry.dashboard(prom, [row("a", MAC_A, last_seen=radius)], now=NOW)
        self.assertEqual(payload["devices"][0]["state"], "offline")
        self.assertEqual(payload["devices"][0]["last_seen"], telemetry.iso(radius))

    def test_unavailable_prometheus(self):
        prom, _ = client(fail=requests.ConnectionError("refused"))
        payload = telemetry.dashboard(prom, self.rows(), now=NOW)
        self.assertEqual(payload["telemetry"], "unavailable")
        self.assertFalse(payload["stale"])
        self.assertEqual(payload["house"], telemetry.empty_house())
        self.assertEqual([d["state"] for d in payload["devices"]], ["unknown", "unknown", "never_connected",
                                                                     "never_connected"])
        self.assertEqual(payload["devices"][0]["diagnostics"], [])
        self.assertEqual(telemetry.house(prom), telemetry.empty_house())

    def test_telemetry_off(self):
        payload = telemetry.dashboard(None, self.rows(), now=NOW)
        self.assertEqual(payload["telemetry"], "off")
        self.assertEqual(payload["devices"][0]["state"], "unknown")
        self.assertEqual(payload["devices"][2]["state"], "never_connected")

    def test_stale_wifi_data(self):
        handlers = [("time() - timestamp(unpoller_prometheus_cache_age_seconds", vector(({}, 4000),))] + live({MAC_A})
        prom, _ = client(handlers)
        payload = telemetry.dashboard(prom, self.rows(), now=NOW)
        self.assertTrue(payload["stale"])
        a = payload["devices"][0]
        self.assertEqual(a["state"], "unknown")                     # frozen presence is no proof
        self.assertEqual(brief(a["diagnostics"]), [("stale_data", "warn", {"age_s": 4000})])
        self.assertEqual(a["diagnostics"][0]["basis"], "measured")
        self.assertEqual(a["diagnostics"][0]["evidence"], {"age_s": 4000, "threshold_s": 600})

    def test_no_unpoller_data_is_stale_too(self):
        handlers = [h for h in live({MAC_A}) if "time() - timestamp" not in h[0]]
        payload = telemetry.dashboard(client(handlers)[0], self.rows(), now=NOW)
        self.assertTrue(payload["stale"])
        self.assertIsNone(payload["house"]["wifi_data_age_s"])
        self.assertEqual(payload["devices"][0]["state"], "unknown")

    def test_owners_for_admins(self):
        owners = {"sub-resident": {"sub": "sub-resident", "username": "res", "display": "Resident"}}
        payload = telemetry.dashboard(None, [row("a", MAC_A), row("b", None, owner="gone")], owners=owners, now=NOW)
        self.assertEqual(payload["devices"][0]["owner"], {"username": "res", "display": "Resident"})
        self.assertEqual(payload["devices"][1]["owner"], {"username": None, "display": None})
        self.assertNotIn("owner", telemetry.dashboard(None, [row("a", MAC_A)], now=NOW)["devices"][0])

    def test_reconnects_counted_from_association_starts(self):
        prom, _ = client(live({MAC_A}))
        _status, summary = telemetry.device_status(prom, [MAC_A])
        self.assertEqual(summary[MAC_A]["reconnects_24h"], 1)          # NOW-9000/-9010 one, then a new one
        self.assertEqual(sorted(summary[MAC_A]["bands_7d"]), ["2.4", "5"])


class HouseTests(unittest.TestCase):
    def test_states(self):
        prom, _ = client(HOUSE_OK)
        house = telemetry.house_status(prom)
        self.assertEqual((house["internet"], house["router"], house["dns"]), ("ok", "ok", "ok"))
        self.assertEqual((house["internet_loss_ratio"], house["internet_rtt_ms"], house["wifi_data_age_s"]), (0, 5.0, 42))

    def with_probes(self, internet, loss=0.0, rtt=5.0):
        probes = vector(({"job": "blackbox_icmp", "role": "gateway"}, 1), ({"job": "blackbox_icmp", "role": "internet"}, internet))
        line = vector(({"__name__": "network_internet_packet_loss_ratio_5m"}, loss), ({"__name__": "network_internet_rtt_ms"}, rtt))
        prom, _ = client([("probe_success", probes), ("network_internet_packet_loss_ratio_5m|", line)] + HOUSE_OK)
        return telemetry.house_status(prom)

    def test_internet_down_degraded(self):
        self.assertEqual(self.with_probes(0)["internet"], "down")
        self.assertEqual(self.with_probes(1, loss=0.2)["internet"], "degraded")
        self.assertEqual(self.with_probes(1, rtt=250)["internet"], "degraded")
        self.assertEqual(self.with_probes(1)["dns"], "unknown")                  # no DNS probe answer

    def test_nothing_known(self):
        house = telemetry.house_status(client()[0])
        self.assertEqual(house, telemetry.empty_house())

    def test_speedtest_result_older_than_the_window(self):
        prom, _ = client([("max(speedtest_tracker_result_id", matrix(({}, [(NOW - 120, 126), (NOW - 60, 126)])))]
                         + HOUSE_OK)
        self.assertIsNone(telemetry.house_status(prom)["speedtest"]["at"])


def P(t, start, ap="ap-scharni-2-corner", radio="na"):
    return (t, start, ap, radio)


class TimelineTests(unittest.TestCase):
    def kinds(self, events):
        return [e["kind"] for e in events]

    def test_one_connection(self):
        events, spans = telemetry.derive_timeline([P(1000 + 60 * i, 900 + (i % 2) * 30) for i in range(10)], 60, 1540)
        self.assertEqual(self.kinds(events), ["connected"])
        self.assertEqual((events[0]["at"], events[0]["duration_s"]), (900, 1540 - 900))
        self.assertEqual(spans, [(900, 1540)])

    def test_gap_with_a_new_association_is_a_disconnect(self):
        points = [P(1000, 900), P(1060, 900), P(2000, 1950), P(2060, 1950)]
        events, spans = telemetry.derive_timeline(points, 60, 2060)
        self.assertEqual(self.kinds(events), ["connected", "disconnected", "connected"])
        self.assertEqual((events[1]["at"], events[1]["duration_s"]), (1060, 1950 - 1060))
        self.assertEqual(events[0]["duration_s"], 160)
        self.assertEqual(spans, [(900, 1060), (1950, 2060)])

    def test_gap_with_the_same_association_is_missing_data(self):
        events, spans = telemetry.derive_timeline([P(1000, 900), P(1060, 900), P(3000, 920)], 60, 3000)
        self.assertEqual(self.kinds(events), ["connected"])
        self.assertEqual(spans, [(900, 3000)])

    def test_uptime_reset_without_a_gap_is_a_reconnect(self):
        events, _ = telemetry.derive_timeline([P(1000, 100), P(1060, 100), P(1120, 1100), P(1180, 1100)], 60, 1180)
        self.assertEqual(self.kinds(events), ["connected", "disconnected", "connected"])
        self.assertEqual(events[2]["at"], 1100)
        self.assertEqual(events[1]["duration_s"], 40)

    def test_roam_and_band_change(self):
        points = [P(1000, 900), P(1060, 900, ap="ap-colbe-2-far"), P(1120, 900, ap="ap-colbe-2-far", radio="ng"),
                  P(1180, 900, ap="ap-colbe-2-far", radio="ng")]
        events, _ = telemetry.derive_timeline(points, 60, 1180)
        self.assertEqual(self.kinds(events), ["connected", "roamed", "band_changed"])
        roam, band = events[1], events[2]
        self.assertEqual((roam["ap"], roam["from_ap"], roam["band"], roam["from_band"]),
                         ("ap-colbe-2-far", "ap-scharni-2-corner", "5", "5"))
        self.assertEqual(roam["duration_s"], 1060 - 900)       # time on the previous AP
        self.assertEqual((band["band"], band["from_band"]), ("2.4", "5"))

    def test_reconnect_on_another_ap_is_not_a_roam(self):
        events, _ = telemetry.derive_timeline([P(1000, 900), P(1060, 1050, ap="ap-colbe-2-far")], 60, 1060)
        self.assertEqual(self.kinds(events), ["connected", "disconnected", "connected"])
        self.assertEqual(events[2]["ap"], "ap-colbe-2-far")

    def test_gone_at_the_end(self):
        events, _ = telemetry.derive_timeline([P(1000, 900), P(1060, 900)], 60, 2000)
        self.assertEqual(self.kinds(events), ["connected", "disconnected"])
        self.assertEqual(events[1]["duration_s"], 940)
        events, _ = telemetry.derive_timeline([P(1000, 900), P(1060, 900)], 60, 1120)   # one scrape late
        self.assertEqual(self.kinds(events), ["connected"])

    def test_nothing(self):
        self.assertEqual(telemetry.derive_timeline([], 60, None), ([], []))


class HistoryTests(unittest.TestCase):
    END = NOW // 60 * 60

    def fake(self, stale_from=None):
        end, start = self.END, self.END - 86400
        grid = list(range(start - 300 + 60, end + 1, 60))
        ages = [(t, 5000 if stale_from and t >= stale_from else 30) for t in grid]
        # connected 2 h ago .. 1 h ago on corner, then (same association) on the 2.4 GHz radio until now
        assoc_a = [(t, end - 7200) for t in grid if end - 7200 <= t < end - 3600]
        assoc_b = [(t, end - 7200) for t in grid if t >= end - 3600]
        chart = [(t, -60) for t in range(start, end + 1, 300) if t >= end - 7200]
        return [
            ("max(unpoller_prometheus_cache_age_seconds{job=\"unifi\"})[", matrix(({}, ages),)),
            ("max by (mac, ap_name, radio) (timestamp(", matrix(
                ({"mac": MAC_A, "ap_name": "ap-scharni-2-corner", "radio": "na"}, assoc_a),
                ({"mac": MAC_A, "ap_name": "ap-scharni-2-corner", "radio": "ng"}, assoc_b))),
            ("unpoller_client_radio_signal_db", matrix(({"mac": MAC_A}, chart),)),
        ]

    def test_series_and_timeline(self):
        prom, session = client(self.fake())
        h = telemetry.history(prom, MAC_A, "24h", now=NOW)
        self.assertEqual((h["range"], h["step_s"], h["end"], h["start"]), ("24h", 300, self.END, self.END - 86400))
        self.assertEqual(h["telemetry"], "ok")
        signal = h["series"]["signal_dbm"]
        self.assertEqual(len(signal), 289)
        self.assertEqual(signal[-1], [self.END, -60])
        self.assertIsNone(signal[0][1])                             # no data: null, not zero
        online = dict(h["series"]["online"])
        self.assertEqual(online[self.END], 1)
        self.assertEqual(online[self.END - 3 * 3600], 0)
        self.assertEqual([e["kind"] for e in h["timeline"]], ["connected", "band_changed"])
        self.assertEqual(h["timeline"][0]["at"], telemetry.iso(self.END - 7200))
        self.assertEqual(h["timeline"][1]["ap"]["name"], "ap-scharni-2-corner")
        self.assertEqual(set(h["series"]), {"signal_dbm", "health", "rx_bps", "tx_bps", "online", "link_tx_bps",
                                            "link_rx_bps", "snr_db", "retry_ratio"})
        self.assertEqual((h["timeline"][0]["source"], h["timeline"][0]["basis"]), ("prometheus", "inferred"))
        self.assertEqual(h["timeline"][0]["mac"], MAC_A)
        # one MAC, exactly matched; every chart one range query with the range's step
        for q in session.queries("unpoller_client_"):
            self.assertIn('mac="%s"' % MAC_A, q)
        ranges = [p for u, p in session.calls if u.endswith("query_range")]
        self.assertEqual(len(ranges), 8)
        self.assertTrue(all(p["step"] == "300" for p in ranges))

    def test_stale_windows_are_null(self):
        prom, _ = client(self.fake(stale_from=self.END - 1800))
        h = telemetry.history(prom, MAC_A, "24h", now=NOW)
        self.assertIsNone(h["series"]["signal_dbm"][-1][1])
        self.assertIsNone(h["series"]["online"][-1][1])
        self.assertEqual(dict(h["series"]["online"])[self.END - 3600], 1)
        # no disconnect is made up for the time without fresh data
        self.assertNotIn("disconnected", [e["kind"] for e in h["timeline"]])

    def test_ranges(self):
        for key, step in (("7d", 1800), ("30d", 7200), ("90d", 21600)):
            h = telemetry.history(client()[0], MAC_A, key, now=NOW)
            self.assertEqual(h["step_s"], step)
            self.assertEqual(h["timeline"], [])
            self.assertTrue(all(v is None for _t, v in h["series"]["online"]))   # nothing known
        with self.assertRaises(ValueError):
            telemetry.history(None, MAC_A, "2y")

    def test_unavailable_off_and_never_connected(self):
        prom, _ = client(fail=requests.ReadTimeout("slow"))
        self.assertEqual(telemetry.history(prom, MAC_A, "24h", now=NOW)["telemetry"], "unavailable")
        self.assertEqual(telemetry.history(None, MAC_A, "24h", now=NOW)["telemetry"], "off")
        prom2, session2 = client()
        h = telemetry.history(prom2, None, "24h", now=NOW)
        self.assertEqual((h["telemetry"], h["timeline"]), ("ok", []))
        self.assertEqual(session2.calls, [])


class EssidTests(unittest.TestCase):
    """Only the house's EAP-TLS network counts: every client selector names it."""

    def client_queries(self, session):
        return [q for q in session.queries() if "unpoller_client_" in q or "wifi_client_" in q]

    def test_every_client_query_names_the_ssid(self):
        prom, session = client(live({MAC_A}))
        telemetry.dashboard(prom, DashboardTests().rows(), now=NOW)
        telemetry.history(client(HistoryTests().fake())[0], MAC_A, "24h", now=NOW)
        prom2, session2 = client(HistoryTests().fake())
        telemetry.history(prom2, MAC_A, "7d", now=NOW)
        queries = self.client_queries(session) + self.client_queries(session2)
        self.assertGreater(len(queries), 20)
        for q in queries:
            self.assertIn('essid="Example"', q, q)

    def test_metrics_without_essid_are_joined_to_the_uptime_series(self):
        prom, session = client(live({MAC_A}))
        telemetry.dashboard(prom, DashboardTests().rows(), now=NOW)
        for needle in ("wifi_client_retry_ratio", "unpoller_client_transmit_bytes_total",
                       "unpoller_client_receive_bytes_total"):
            for q in session.queries(needle):
                self.assertIn('and on (mac) ', q)
                self.assertIn('unpoller_client_uptime_seconds{job="unifi",essid="Example"', q.split("and on (mac)")[1])

    def test_string_literal(self):
        self.assertEqual(telemetry.promql_string("Scharni"), '"Scharni"')
        self.assertEqual(telemetry.promql_string('a"b\\c'), '"a\\"b\\\\c"')
        for bad in ("a\nb", "a\x00", None):
            with self.assertRaises(ValueError):
                telemetry.promql_string(bad)
        sel = telemetry.selectors('x",mac=~".*', [MAC_A])["sel"]
        self.assertEqual(sel, 'essid="x\\",mac=~\\".*",mac="%s"' % MAC_A)     # stays one literal


class ConflictTests(unittest.TestCase):
    """A MAC that other people's devices claim too (a device sends its own MAC, it can lie)."""

    def test_withheld_from_residents(self):
        prom, session = client(live({MAC_A}))
        claims = {MAC_A: {"sub-resident", "sub-other"}, MAC_B: {"sub-resident"}}
        a, b = telemetry.dashboard(prom, [row("a", MAC_A), row("b", MAC_B)], now=NOW, claims=claims)["devices"]
        self.assertEqual(a["state"], "unknown")
        self.assertEqual(brief(a["diagnostics"]), [("mac_conflict", "warn", {})])
        self.assertTrue(all(a[f] is None for f in telemetry.LIVE_FIELDS))
        self.assertEqual(b["state"], "offline")
        self.assertTrue(all(MAC_A not in q for q in session.queries()))      # not even asked

    def test_admins_see_the_data_and_the_conflict(self):
        prom, _ = client(live({MAC_A}))
        claims = {MAC_A: {"sub-resident", "sub-other", "sub-third"}}
        a = telemetry.dashboard(prom, [row("a", MAC_A)], now=NOW, claims=claims, admin=True)["devices"][0]
        self.assertEqual(a["state"], "online")
        self.assertEqual(brief(a["diagnostics"])[0], ("mac_conflict", "warn", {"owners": 2}))

    def test_the_same_persons_devices_are_no_conflict(self):
        prom, _ = client(live({MAC_A}))
        claims = {MAC_A: {"sub-resident"}}
        devices = telemetry.dashboard(prom, [row("a", MAC_A), row("a2", MAC_A)], now=NOW, claims=claims)["devices"]
        self.assertEqual([d["state"] for d in devices], ["online", "online"])

    def test_withheld_history(self):
        prom, session = client(HistoryTests().fake())
        h = telemetry.history(prom, MAC_A, "24h", now=NOW, withheld="mac_conflict")
        self.assertEqual((h["telemetry"], h["withheld"], h["timeline"]), ("ok", "mac_conflict", []))
        self.assertTrue(all(v == [] for v in h["series"].values()))
        self.assertEqual(session.calls, [])


class BoundTests(unittest.TestCase):
    """Nothing from before the device existed or before its MAC's first login."""

    def test_live_values_from_the_bound_on(self):
        import datetime
        first = datetime.datetime.fromtimestamp(NOW - 550, datetime.timezone.utc)
        prom, session = client(live({MAC_A}))
        a, b = telemetry.dashboard(prom, [row("a", MAC_A, first_seen=first),
                                          row("b", MAC_B, created=datetime.datetime.fromtimestamp(
                                              NOW - 3600, datetime.timezone.utc))], now=NOW)["devices"]
        self.assertIsNone(a["rx_24h_bytes"])                    # partly someone else's day: not shown
        self.assertEqual(a["roams_1h"], 0)                      # the roam at NOW-600 was before
        self.assertEqual(a["since"], telemetry.iso(NOW - 550))  # not before its first login
        self.assertEqual([f["code"] for f in a["diagnostics"]], [])
        self.assertIsNone(b["last_seen"])                       # seen at NOW-7200: before it existed
        self.assertTrue(all(MAC_A not in q and MAC_B not in q for q in session.queries("increase(")))

    def test_summary_bound(self):
        prom, _ = client(live({MAC_A}))
        _status, summary = telemetry.device_status(prom, [MAC_A], {MAC_A: NOW - 3600}, now=NOW)
        self.assertEqual(summary[MAC_A]["reconnects_24h"], 0)
        self.assertEqual(summary[MAC_A]["bands_7d"], ["5"])     # 2.4 GHz only before the bound

    def test_data_bound(self):
        import datetime
        utc = datetime.timezone.utc
        created, first = datetime.datetime(2026, 10, 1, tzinfo=utc), datetime.datetime(2026, 10, 20, tzinfo=utc)
        self.assertEqual(telemetry.data_bound({"created": created, "first_seen": first}), first.timestamp())
        self.assertEqual(telemetry.data_bound({"created": first, "first_seen": created}), first.timestamp())
        self.assertEqual(telemetry.data_bound({"created": created, "first_seen": None}), created.timestamp())
        self.assertIsNone(telemetry.data_bound({}))

    def test_history_from_the_bound_on(self):
        end = HistoryTests.END
        prom, _ = client(HistoryTests().fake())
        h = telemetry.history(prom, MAC_A, "24h", now=NOW, since=end - 1800)
        self.assertEqual(h["data_from"], end - 1800)
        self.assertEqual([e["kind"] for e in h["timeline"]], ["connected"])      # the band change was before
        self.assertEqual(h["timeline"][0]["at"], telemetry.iso(end - 1800))
        online = dict(h["series"]["online"])
        self.assertIsNone(online[end - 3600])                                     # before: not this device's
        self.assertEqual(online[end], 1)
        self.assertIsNone(dict(h["series"]["signal_dbm"])[end - 3600])


class SlowSession(FakeSession):
    """Each answer takes `delay` seconds of the client's clock."""

    def __init__(self, handlers, clock, delay):
        super().__init__(handlers)
        self.clock, self.delay = clock, delay

    def get(self, url, params=None, timeout=None):
        self.clock.t += self.delay
        self.timeouts = getattr(self, "timeouts", []) + [timeout]
        return super().get(url, params, timeout)


class BudgetTests(unittest.TestCase):
    def slow(self, delay):
        clock = Clock()
        session = SlowSession(live({MAC_A}), clock, delay)
        return telemetry.Prometheus("http://prometheus.example:9090", 4, ssid=SSID, session=session, clock=clock), session

    def test_a_slow_prometheus_uses_up_the_budget(self):
        prom, session = self.slow(2.0)
        payload = telemetry.dashboard(prom, [row("a", MAC_A)], now=NOW)
        self.assertEqual(payload["telemetry"], "unavailable")
        self.assertEqual(len(session.calls), 3)                  # 2 s each: the third ends after 5 s
        self.assertLessEqual(max(session.timeouts), 4)
        self.assertLessEqual(session.timeouts[-1], 1.0 + 1e-9)   # only what was left of the budget
        with self.assertRaises(telemetry.Unavailable):            # and the breaker is open now
            prom.vector("up")
        self.assertEqual(len(session.calls), 3)

    def test_prometheus_is_told_the_timeout(self):
        prom, session = client([("up", vector(({}, 1)))])
        prom.within().vector("up")
        self.assertEqual(session.calls[0][1]["timeout"], "4s")
        self.assertNotIn("timeout", dict(prom._cache.popitem()[0][1]))   # not part of the cache key

    def test_a_fast_prometheus_fits(self):
        prom, _ = self.slow(0.01)
        self.assertEqual(telemetry.dashboard(prom, [row("a", MAC_A)], now=NOW)["telemetry"], "ok")


class ReplyShapeTests(unittest.TestCase):
    def test_malformed_items_are_unavailable(self):
        for result in ([{"metric": {"a": 1}, "value": [1, "1"]}], [{"metric": {}, "value": "x"}],
                       [{"metric": {}}], ["x"], None):
            prom, _ = client([("up", {"resultType": "vector", "result": result})])
            with self.assertRaises(telemetry.Unavailable, msg=result):
                prom.vector("up")
        prom, _ = client([("up", {"resultType": "matrix", "result": [{"metric": {}, "values": [["t", "1"]]}]})])
        with self.assertRaises(telemetry.Unavailable):
            prom.matrix("up[5m:1m]")

    def test_not_json_or_not_a_dict(self):
        prom, session = client()
        session.get = lambda *a, **k: mock.Mock(status_code=200, json=mock.Mock(return_value=["x"]))
        with self.assertRaises(telemetry.Unavailable):
            prom.vector("up")


class CacheTests(unittest.TestCase):
    def test_one_fetch_per_query_at_a_time(self):
        import threading
        release, started = threading.Event(), threading.Event()
        session = FakeSession([("up", vector(({}, 1)))])
        inner = session.get

        def slow_get(*a, **k):
            started.set()
            release.wait(2)
            return inner(*a, **k)

        session.get = slow_get
        prom = telemetry.Prometheus("http://prometheus.example:9090", 4, ssid=SSID, session=session)
        results = []
        threads = [threading.Thread(target=lambda: results.append(prom.vector("up"))) for _ in range(5)]
        threads[0].start()
        started.wait(2)
        for t in threads[1:]:
            t.start()
        release.set()
        for t in threads:
            t.join(3)
        self.assertEqual(len(session.calls), 1)
        self.assertEqual(results, [[({}, 1.0)]] * 5)

    def test_summaries_live_a_minute(self):
        prom, session = client(live({MAC_A}))
        telemetry.device_status(prom, [MAC_A], now=NOW)
        prom.clock.t += 20
        telemetry.device_status(prom, [MAC_A], now=NOW)
        self.assertEqual(len(session.queries("[24h:5m]")), 1)
        self.assertEqual(len(session.queries("max by (mac, radio)")), 1)
        self.assertEqual(len(session.queries("unpoller_client_radio_signal_db")), 2)
        prom.clock.t += 41
        telemetry.device_status(prom, [MAC_A], now=NOW)
        self.assertEqual(len(session.queries("[24h:5m]")), 2)


if __name__ == "__main__":
    unittest.main()
