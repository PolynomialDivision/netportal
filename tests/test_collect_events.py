"""Job unifi_events: UniFi system log lines (as unpoller pushes them to Loki) -> connection_event.

The fixtures follow unpoller's source (github.com/unpoller/unifi system_log.go: the JSON of
SystemLogEntry.MarshalJSON; unpoller pkg/lokiunifi report_event.go: the stream labels). The key
and event names and the message texts are NOT verified on the house controller yet: they are
plausible UniFi 10.x values, and the mapping must not depend on them beyond ROAM / DISCONNECT /
CONNECT in key or event."""

import datetime
import json
import logging
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fakes import FakeLoki
from fakes.registry import FakeRegistry

from netportal.collect import jobs, scheduler, unifi_events
from netportal.collect.settings import CollectSettings

UTC = datetime.timezone.utc
logging.getLogger("netportal.collect").setLevel(logging.ERROR + 10)

NOW = datetime.datetime(2026, 10, 25, 12, 0, tzinfo=UTC)
PHONE, LAPTOP, STRANGER = "02:11:22:33:44:55", "a4:83:e7:00:00:01", "3c:22:fb:99:88:77"
AP_A, AP_B = ("60:22:32:37:48:00", "ap-scharni-2-corner"), ("68:d7:9a:1c:61:46", "ap-scharni-4-corner")
LABELS = {"application": "unifi_system_log", "job": "unpoller", "site_name": "Default (default)",
          "source": "https://unifi.scharni.org", "category": "CLIENT_DEVICES", "severity": "LOW"}


def ms(minutes_ago):
    return int((NOW - datetime.timedelta(minutes=minutes_ago)).timestamp() * 1000)


def entry(key, mac, minutes_ago, ident, ap=AP_A, from_ap=None, wlan="Scharni", message="", **extra):
    params = {"CLIENT": {"id": mac.upper().replace(":", "-") if mac == LAPTOP else mac, "name": "Nicks Phone",
                         "hostname": "nicks-phone", "ip": "10.0.30.140"}}
    if ap:
        params["DEVICE_TO" if from_ap else "DEVICE"] = {"id": ap[0], "name": ap[1], "model": "UAL6"}
    if from_ap:
        params["DEVICE_FROM"] = {"id": from_ap[0], "name": from_ap[1]}
    if wlan:
        params["WLAN"] = {"id": "65f0aa", "name": wlan}
    body = {"category": "CLIENT_DEVICES", "event": key.replace("WIRELESS_", ""), "id": ident, "key": key,
            "message": message, "parameters": params, "severity": "LOW", "show_on_dashboard": False,
            "status": "", "subcategory": "WIFI", "target": "", "timestamp": ms(minutes_ago),
            "title_raw": key.replace("_", " ").title(), "type": "CLIENT", "site_name": "Default (default)",
            "source_name": "https://unifi.scharni.org"}
    body.update(extra)
    return json.dumps(body)


CONNECT = entry("WIRELESS_CLIENT_CONNECTED", PHONE, 30, "6720aa01",
                message="Nicks Phone connected to Scharni on ap-scharni-2-corner. Connection Info: Ch. 36 "
                        "(5 GHz, 80 MHz), -61 dBm")
ROAM = entry("WIRELESS_CLIENT_ROAMED", PHONE, 20, "6720aa02", ap=AP_B, from_ap=AP_A,
             message="Nicks Phone roamed from ap-scharni-2-corner to ap-scharni-4-corner. Ch. 6 (2.4 GHz), -70 dBm")
DISCONNECT = entry("WIRELESS_CLIENT_DISCONNECTED", PHONE, 10, "6720aa03", ap=AP_B, wlan=None,
                   message="Nicks Phone disconnected from Scharni. Connected for 1h 2m 3s.")
UNKNOWN = entry("CLIENT_BLOCKED_BY_POLICY", PHONE, 9, "6720aa04", message="something new")
LAPTOP_CONNECT = entry("WIRELESS_CLIENT_CONNECTED", LAPTOP, 8, "6720aa05", ap=AP_B)
STRANGER_CONNECT = entry("WIRELESS_CLIENT_CONNECTED", STRANGER, 7, "6720aa06", wlan="Brantsovsky")
STRANGER_NO_WLAN = entry("WIRELESS_CLIENT_DISCONNECTED", STRANGER, 6, "6720aa07", wlan=None)
NO_CLIENT = json.dumps({"key": "WIRELESS_CLIENT_CONNECTED", "id": "6720aa08",
                        "parameters": {"WLAN": {"name": "Scharni"}},
                        "timestamp": ms(5)})


class MappingTests(unittest.TestCase):
    def setUp(self):
        patch = FakeRegistry().patched()
        patch.__enter__()
        self.addCleanup(patch.__exit__, None, None, None)

    def row(self, line, ts=None):
        row, why = unifi_events.map_entry(line, ts or int(NOW.timestamp() * 1e9))
        self.assertIsNone(why)
        return row

    def test_connect(self):
        row = self.row(CONNECT)
        self.assertEqual((row["kind"], row["mac"], row["ap_mac"], row["ap_name"], row["ssid"]),
                         ("connected", PHONE, AP_A[0], AP_A[1], "Scharni"))
        self.assertEqual((row["channel"], row["radio"], row["rssi"]), (36, "na", -61))
        self.assertEqual(row["at"], NOW - datetime.timedelta(minutes=30))     # the entry's own time
        self.assertEqual(row["source"], "unifi_syslog")
        self.assertEqual(row["dedup_key"], "unifi_syslog:id:6720aa01")
        # unmapped fields stay, the client's names do not
        self.assertEqual(row["detail"]["subcategory"], "WIFI")
        self.assertEqual(row["detail"]["parameters"]["CLIENT"], {"ip": "10.0.30.140"})
        self.assertEqual(row["detail"]["parameters"]["DEVICE"]["model"], "UAL6")
        self.assertNotIn("timestamp", row["detail"])

    def test_roam(self):
        row = self.row(ROAM)
        self.assertEqual((row["kind"], row["ap_mac"], row["ap_name"], row["from_ap_mac"], row["from_ap_name"]),
                         ("roamed", AP_B[0], AP_B[1], AP_A[0], AP_A[1]))
        self.assertEqual((row["channel"], row["radio"], row["rssi"]), (6, "ng", -70))

    def test_disconnect_without_wlan(self):
        row = self.row(DISCONNECT)
        self.assertEqual((row["kind"], row["ssid"], row["duration_s"]), ("disconnected", None, 3723))

    def test_unknown_shape_is_kept_as_other(self):
        row = self.row(UNKNOWN)
        self.assertEqual(row["kind"], "other")
        self.assertEqual(row["detail"]["key"], "CLIENT_BLOCKED_BY_POLICY")

    def test_dash_separated_mac(self):
        self.assertEqual(self.row(LAPTOP_CONNECT)["mac"], LAPTOP)

    def test_malformed(self):
        for line, why in (("not json", "malformed"), ("[1, 2]", "malformed"), (NO_CLIENT, "no_client_mac"),
                          (json.dumps({"parameters": {"CLIENT": {"id": "zz"}}}), "no_client_mac"),
                          (json.dumps({"parameters": "x"}), "no_client_mac")):
            self.assertEqual(unifi_events.map_entry(line, 1), (None, why), line)

    def test_missing_fields_do_not_break_it(self):
        row = self.row(json.dumps({"parameters": {"CLIENT": {"id": PHONE}}}), ts=1792931000 * 10**9)
        self.assertEqual((row["kind"], row["ap_mac"], row["ssid"], row["rssi"]), ("other", None, None, None))
        self.assertEqual(row["at"], datetime.datetime.fromtimestamp(1792931000, UTC))   # Loki's time
        self.assertTrue(row["dedup_key"].startswith("unifi_syslog:sha256:"))

    def test_weird_values(self):
        line = entry("WIRELESS_CLIENT_CONNECTED", PHONE, 1, "../../x", message="Ch. 999, +5 dBm",
                     timestamp="yesterday")
        row = self.row(line)
        self.assertEqual((row["channel"], row["rssi"]), (None, None))
        self.assertTrue(row["dedup_key"].startswith("unifi_syslog:sha256:"))   # an id that is no id

    def test_classify(self):
        for key, kind in (("CLIENT_ROAMED_RADIO", "roamed"), ("EVT_WU_Disconnected", "disconnected"),
                          ("CLIENT_DISASSOCIATED", "disconnected"), ("WIFI_CLIENT_JOINED", "connected"),
                          ("CLIENT_RECONNECTED", "connected"), ("CLIENT_BLOCKED", "other")):
            self.assertEqual(unifi_events.classify({"key": key}), kind, key)


class JobTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.reg = FakeRegistry()
        patch = self.reg.patched()
        patch.__enter__()
        self.addCleanup(patch.__exit__, None, None, None)
        first = mock.patch.object(unifi_events, "FIRST_RUN_NS", 86400 * 10**9)    # within one window
        first.start()
        self.addCleanup(first.stop)
        self.loki = FakeLoki().start()
        self.addCleanup(self.loki.stop)
        self.settings = CollectSettings(database_url="postgresql://fake", ssid="Scharni", loki_url=self.loki.url,
                                        heartbeat=str(Path(self.tmp.name) / "hb"))
        # the phone's device has a window (it logged in): its entries without WLAN count too
        self.reg.windows["dev-phone"] = [{"mac": PHONE, "first_seen": NOW - datetime.timedelta(hours=2),
                                          "last_seen": NOW, "randomized": True, "auth_count": 3}]
        for line in (CONNECT, ROAM, DISCONNECT, UNKNOWN, LAPTOP_CONNECT, STRANGER_CONNECT, STRANGER_NO_WLAN,
                     NO_CLIENT, "garbage"):
            ts = json.loads(line)["timestamp"] * 10**6 if line.startswith("{") else ms(4) * 10**6
            self.loki.push(LABELS, ts, line)
        self.loki.push(dict(LABELS, category="UNIFI_DEVICES"), ms(3) * 10**6,
                       entry("DEVICE_RESTARTED", PHONE, 3, "6720aa09"))

    def run_job(self, now=NOW):
        return scheduler.run_job(jobs.BY_NAME["unifi_events"], self.settings, now=now)

    def test_ingest(self):
        self.assertEqual(self.run_job(), scheduler.OK)
        events = sorted(self.reg.events.values(), key=lambda e: e["at"])
        self.assertEqual([(e["kind"], e["mac"]) for e in events],
                         [("connected", PHONE), ("roamed", PHONE), ("disconnected", PHONE), ("other", PHONE),
                          ("connected", LAPTOP)])
        self.assertEqual([e["device_id"] for e in events], ["dev-phone"] * 4 + [None])
        cursor = self.reg.jobs["unifi_events"]["cursor"]
        self.assertEqual(cursor["until_ns"], int(NOW.timestamp() * 1e9))
        self.assertEqual(cursor["last_run"]["inserted"], 5)
        self.assertEqual(cursor["last_run"]["skipped"], {"other_network": 2, "no_client_mac": 1, "malformed": 1})
        query = self.loki.requests[0][1]
        self.assertEqual(query["query"], '{application="unifi_system_log",category="CLIENT_DEVICES"}')
        self.assertEqual(query["direction"], "forward")
        # no cursor yet: from Loki's retention (here patched to a day)
        self.assertEqual(int(query["start"]), int(NOW.timestamp() * 1e9) - 86400 * 10**9)

    def test_overlapping_windows_do_not_duplicate(self):
        self.run_job()
        later = NOW + datetime.timedelta(minutes=2)
        self.loki.push(LABELS, ms(-1) * 10**6, entry("WIRELESS_CLIENT_CONNECTED", PHONE, -1, "6720aa10"))
        self.assertEqual(self.run_job(later), scheduler.OK)
        self.assertEqual(len(self.reg.events), 6)
        last = self.loki.requests[-1][1]
        self.assertEqual(int(last["start"]), int(NOW.timestamp() * 1e9) - unifi_events.OVERLAP_NS)
        self.assertEqual(self.reg.jobs["unifi_events"]["cursor"]["last_run"]["inserted"], 1)

    def test_paging_with_equal_timestamps(self):
        ts = ms(2) * 10**6
        for i in range(5):
            self.loki.push(LABELS, ts, entry("WIRELESS_CLIENT_CONNECTED", PHONE, 2, "same%02d" % i))
        with mock.patch.object(unifi_events, "PAGE_LIMIT", 2):
            self.assertEqual(self.run_job(), scheduler.OK)
        self.assertEqual(len(self.reg.events), 10)
        self.assertGreater(len(self.loki.requests), 5)

    def test_page_limit_per_run_continues_next_time(self):
        with mock.patch.object(unifi_events, "PAGE_LIMIT", 2), mock.patch.object(unifi_events, "MAX_PAGES", 2):
            self.run_job()
            cursor = self.reg.jobs["unifi_events"]["cursor"]
            self.assertLess(cursor["until_ns"], int(NOW.timestamp() * 1e9))
            self.assertTrue(cursor["paging"])
            asked = len(self.loki.requests)
            self.run_job()
            # stopped inside its range: the next run goes on exactly there (no overlap), so
            # paging moves forward however many entries the overlap would hold
            self.assertEqual(int(self.loki.requests[asked][1]["start"]), cursor["until_ns"])
            for _ in range(6):
                self.run_job()
            self.assertEqual(len(self.reg.events), 5)
            for _ in range(10):
                if "paging" not in self.reg.jobs["unifi_events"]["cursor"]:
                    break
                self.run_job()
        self.assertNotIn("paging", self.reg.jobs["unifi_events"]["cursor"])          # read to the end at last

    def test_a_line_arriving_late_is_read_by_the_next_run(self):
        """unpoller pushes up to 8 minutes back after an outage (and every 2 minutes): an entry
        10 minutes old that arrives after a run's end is still within the next run's overlap."""
        self.assertEqual(self.run_job(), scheduler.OK)
        self.assertEqual(self.reg.jobs["unifi_events"]["cursor"]["until_ns"], int(NOW.timestamp() * 1e9))
        self.loki.push(LABELS, ms(10) * 10**6, entry("WIRELESS_CLIENT_CONNECTED", PHONE, 10, "6720aa11"))
        self.assertEqual(self.run_job(NOW + datetime.timedelta(minutes=2)), scheduler.OK)
        self.assertEqual(self.reg.jobs["unifi_events"]["cursor"]["last_run"]["inserted"], 1)
        self.assertGreaterEqual(unifi_events.OVERLAP_NS, 15 * 60 * 10**9)

    def test_commits_in_small_batches(self):
        """Resolved events extend device_mac rows that every RADIUS login updates too: committed
        every BATCH rows, the row locks are held briefly."""
        with mock.patch.object(unifi_events, "BATCH", 2):
            self.assertEqual(self.run_job(), scheduler.OK)
        job_db = self.reg.connections[-1]
        self.assertEqual(len(self.reg.events), 5)
        self.assertGreaterEqual(job_db.commits, 3 + 1)            # 2 + 2 + 1 rows, then the page

    def test_long_pause_is_caught_up_a_week_per_run(self):
        self.reg.jobs["unifi_events"] = {"name": "unifi_events", "cursor": {"until_ns": int(
            (NOW - datetime.timedelta(days=10)).timestamp() * 1e9)}}
        with mock.patch.object(unifi_events, "FIRST_RUN_NS", 30 * 86400 * 10**9):
            self.run_job()
            until = self.reg.jobs["unifi_events"]["cursor"]["until_ns"]
            self.assertEqual(until, int((NOW - datetime.timedelta(days=3)).timestamp() * 1e9) - unifi_events.OVERLAP_NS)
            self.assertEqual(self.reg.events, {})
            self.run_job()
        self.assertEqual(len(self.reg.events), 5)

    def test_loki_down_is_recorded_and_the_cursor_kept(self):
        self.reg.jobs["unifi_events"] = {"name": "unifi_events", "cursor": {"until_ns": 5}}
        self.loki.fail(502)
        self.assertEqual(self.run_job(), scheduler.FAILED)
        row = self.reg.jobs["unifi_events"]
        self.assertIn("HTTP 502", row["last_error"])
        self.assertEqual(row["cursor"], {"until_ns": 5})
        self.assertEqual(self.reg.events, {})


if __name__ == "__main__":
    unittest.main()
