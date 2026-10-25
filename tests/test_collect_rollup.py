"""Job rollup: per-minute Prometheus data (fake) -> device_day / ap_day, on Europe/Berlin days."""

import datetime
import logging
import tempfile
import unittest
from pathlib import Path

from fakes import FakePrometheus
from fakes.registry import FakeRegistry

from netportal.collect import days, incidents, jobs, rollup, scheduler
from netportal.collect.settings import CollectSettings

UTC = datetime.timezone.utc
logging.getLogger("netportal.collect").setLevel(logging.ERROR + 10)

TZ = "Europe/Berlin"
DAY = datetime.date(2026, 10, 25)                 # the end of summer time: 25 hours
START, END = days.bounds(DAY, TZ)
T0 = START + 3 * 3600
M1 = "02:11:22:33:44:55"
AP_X, AP_Y = "60:22:32:37:48:00", "68:d7:9a:1c:61:46"
NOW = datetime.datetime.fromtimestamp(END + 11 * 3600, UTC)       # the next day, 10:00 local


def dt(unix):
    return datetime.datetime.fromtimestamp(unix, UTC)


class DayTests(unittest.TestCase):
    def test_dst_days(self):
        self.assertEqual(END - START, 25 * 3600)
        self.assertEqual(dt(START), datetime.datetime(2026, 10, 24, 22, 0, tzinfo=UTC))
        spring = days.bounds(datetime.date(2026, 3, 29), TZ)
        self.assertEqual(spring[1] - spring[0], 23 * 3600)
        normal = days.bounds(datetime.date(2026, 10, 24), TZ)
        self.assertEqual((normal[1] - normal[0], normal[1]), (24 * 3600, START))
        self.assertEqual(days.local_day(START, TZ), DAY)
        self.assertEqual(days.local_day(START - 1, TZ), datetime.date(2026, 10, 24))
        self.assertEqual(days.local_day(END - 1, TZ), DAY)


class World:
    """One device's phone M1 on the house network on DAY, two APs."""

    def __init__(self):
        self.first, self.last = START - incidents.FROZEN_S, END - 60
        self.grid = range(self.first, self.last + 1, 60)
        self.ages = {t: (900 if T0 + 600 <= t < T0 + 1200 else 30) for t in self.grid}
        self.presence = {}
        for t in range(T0, T0 + 7201, 60):
            uptime = t - T0 if t < T0 + 3000 else t - (T0 + 3000)
            self.presence[t] = (uptime, "ap-x" if t < T0 + 1800 else "ap-y")
        self.info = {AP_X: ("ap-x", set(self.grid)), AP_Y: ("ap-y", set(self.grid) - set(range(T0, T0 + 300, 60)))}
        self.ap_uptime = {"ap-x": {t: (50000 + t - START if t < T0 else t - T0 + 10) for t in self.grid},
                          "ap-y": {t: 90000 + t - START for t in self.grid}}

    def load(self, prom, ssid="Scharni"):
        prom.range_series(rollup.AGE, [({}, self.ages)])
        prom.range_series(incidents.Q["ap_info"], [({"mac": mac, "name": name}, {t: 1 for t in ts})
                                                   for mac, (name, ts) in self.info.items()])
        prom.range_series(incidents.Q["ap_uptime"], [({"name": n}, pts) for n, pts in self.ap_uptime.items()])
        prom.range_series(incidents.Q["site_disconnected"], [({}, {t: 0 for t in self.grid})])
        q = rollup.device_queries(ssid, [M1])
        prom.range_series(q["presence"], [
            ({"mac": M1, "ap_name": ap, "radio": "na"}, {t: up for t, (up, a) in self.presence.items() if a == ap})
            for ap in ("ap-x", "ap-y")])
        for name, value in (("signal", -60), ("snr", 30), ("health", 80), ("retry", 0.1), ("rx", 1000), ("tx", 10),
                            ("link_rx", 300e6)):
            prom.range_series(q[name], [({"mac": M1}, {t: value for t in self.presence})])
        day = range(START, END, 60)
        prom.range_series(rollup.AP_QUERIES["stations"], [({"mac": AP_X}, {t: 5 for t in day})])
        prom.range_series(rollup.AP_QUERIES["util"], [({"mac": AP_X, "radio": "ng"}, {t: 0.3 for t in day}),
                                                      ({"mac": AP_X, "radio": "na"}, {t: 0.1 for t in day})])
        prom.range_series(rollup.AP_QUERIES["weak"], [({"ap_name": "ap-x"}, {t: 1 for t in day})])
        prom.range_series(rollup.AP_QUERIES["signals"], [({"ap_name": "ap-x"}, {t: 4 for t in day})])
        prom.vector(rollup.HORIZON, [({}, START + 60)])


class RollupCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.reg = FakeRegistry()
        patch = self.reg.patched()
        patch.__enter__()
        self.addCleanup(patch.__exit__, None, None, None)
        self.prom = FakePrometheus().start()
        self.addCleanup(self.prom.stop)
        self.settings = CollectSettings(database_url="postgresql://fake", ssid="Scharni", prometheus_url=self.prom.url,
                                        timezone=TZ, heartbeat=str(Path(self.tmp.name) / "hb"))
        self.world = World()
        self.reg.device_rows = [{"id": "d1", "owner": "alice"}, {"id": "d2", "owner": "bob"}]
        self.reg.windows["d1"] = [{"mac": M1, "first_seen": dt(T0 - 600), "last_seen": dt(T0 + 3600),
                                   "randomized": True, "auth_count": 2}]
        self.reg.auth["d1"] = [{"at": dt(T0), "result": "accept"}, {"at": dt(START - 10), "result": "reject"}]

    def run_job(self, now=NOW):
        self.world.load(self.prom)
        result = scheduler.run_job(jobs.BY_NAME["rollup"], self.settings, now=now)
        self.assertEqual(result, scheduler.OK, self.reg.jobs.get("rollup"))
        return self.reg.jobs["rollup"]["cursor"]


class DeviceDayTests(RollupCase):
    def test_device_day(self):
        self.run_job()
        row = self.reg.device_day_rows[("d1", DAY)]
        # in the window T0-10 min .. T0+60 min + 15 min grace; present from T0; 10 stale minutes
        self.assertEqual((row["online_s"], row["stale_s"]), (66 * 60, 10 * 60))
        self.assertEqual(row["aps"], {AP_X: 20 * 60, AP_Y: 46 * 60})          # by MAC, not by name
        self.assertEqual(row["bands"], {"5": 66 * 60})
        self.assertEqual((row["roams"], row["reconnects"]), (1, 1))
        self.assertEqual((row["signal_avg_dbm"], row["signal_p10_dbm"], row["snr_avg_db"]), (-60, -60, 30))
        self.assertEqual((row["health_avg"], row["health_min"], row["retry_ratio_avg"]), (80, 80, 0.1))
        self.assertEqual((row["rx_bytes"], row["tx_bytes"], row["link_rx_avg_bps"]), (66000, 660, 300e6))
        self.assertEqual((row["macs"], row["auth_ok"], row["auth_failed"], row["disconnects"]), (1, 1, 0, None))
        self.assertNotIn(("d2", DAY), self.reg.device_day_rows)              # nothing of the day is d2's

    def test_disconnects_from_connection_events(self):
        self.reg.events["k1"] = {"device_id": "d1", "at": dt(T0 + 100), "kind": "disconnected"}
        self.reg.events["k2"] = {"device_id": "d1", "at": dt(T0 + 200), "kind": "connected"}
        self.run_job()
        self.assertEqual(self.reg.device_day_rows[("d1", DAY)]["disconnects"], 1)

    def test_the_window_end_is_the_registrys(self):
        """The current window reaches past last_seen + 15 min (device_windows' window_end, the rule
        the pages use): online_s counts it the same way; repeated rejects count their tries."""
        self.reg.windows["d1"][0]["window_end"] = dt(T0 + 3600 + 12 * 3600 + 900)
        self.reg.auth["d1"].append({"at": dt(T0 + 60), "result": "reject", "count": 5})
        self.run_job()
        row = self.reg.device_day_rows[("d1", DAY)]
        # present T0 .. T0+120 min, all in the window now; 10 of those minutes stale
        self.assertEqual((row["online_s"], row["stale_s"]), (111 * 60, 10 * 60))
        self.assertEqual((row["auth_ok"], row["auth_failed"]), (1, 5))
        self.assertEqual(rollup.window_end({"last_seen": dt(T0)}), T0 + 900)          # a row without one

    def test_overlapping_windows_belong_to_nobody(self):
        self.reg.windows["d2"] = [{"mac": M1, "first_seen": dt(T0 + 3000), "last_seen": dt(T0 + 3600),
                                   "randomized": True, "auth_count": 1}]
        self.run_job()
        self.assertEqual(self.reg.device_day_rows[("d1", DAY)]["online_s"], 40 * 60)
        d2 = self.reg.device_day_rows[("d2", DAY)]
        self.assertEqual((d2["online_s"], d2["stale_s"], d2["aps"], d2["roams"]), (0, 0, {}, None))

    def test_only_the_house_network(self):
        self.run_job()
        asked = [q for q in self.prom.queries("/api/v1/query_range") if M1 in q]
        self.assertEqual(len(asked), len(rollup.DEVICE_QUERIES))
        self.assertTrue(all('essid="Scharni"' in q for q in asked), asked)
        # another SSID's data (other query texts) is never read
        self.world.load(self.prom)
        self.settings = CollectSettings(**dict(self.settings.__dict__, ssid="Other"))
        scheduler.run_job(jobs.BY_NAME["rollup"], self.settings, now=NOW)
        self.assertEqual(self.reg.device_day_rows[("d1", DAY)]["online_s"], 0)

    def test_rerun_is_idempotent(self):
        self.run_job()
        first = dict(self.reg.device_day_rows[("d1", DAY)])
        self.run_job()
        self.assertEqual(self.reg.device_day_rows[("d1", DAY)], first)
        self.assertEqual(len(self.reg.device_day_rows), 1)

    def test_today_stops_at_now(self):
        now = dt(T0 + 1800 + 30)                     # during DAY
        self.run_job(now)
        row = self.reg.device_day_rows[("d1", DAY)]
        self.assertEqual(row["online_s"], (30 - 10) * 60)         # T0 .. T0+29 min, without the stale 10
        last = max(int(p["end"]) for path, p in self.prom.requests if path == "/api/v1/query_range")
        self.assertLessEqual(last, T0 + 1800 + 30 - 60)


class ApDayTests(RollupCase):
    def test_ap_day(self):
        self.run_job()
        x, y = self.reg.ap_day_rows[(AP_X, DAY)], self.reg.ap_day_rows[(AP_Y, DAY)]
        self.assertEqual((x["ap_name"], x["clients_avg"], x["clients_max"]), ("ap-x", 5, 5))
        self.assertEqual(x["channel_util_avg"], {"na": 0.1, "ng": 0.3})
        self.assertEqual(x["weak_client_share"], 0.25)
        self.assertEqual((x["restarts"], x["down_s"]), (1, 0))
        self.assertEqual((y["restarts"], y["down_s"], y["clients_avg"]), (0, 5 * 60, None))


class BackfillTests(RollupCase):
    def test_missing_days_back_to_the_horizon_bounded_per_run(self):
        horizon = START - 4 * 86400 + 3600                # 2026-10-21 local
        self.world.load(self.prom)
        self.prom.vector(rollup.HORIZON, [({}, horizon)])

        def run():
            scheduler.run_job(jobs.BY_NAME["rollup"], self.settings, now=NOW)
            return [d["day"] for d in self.reg.jobs["rollup"]["cursor"]["last_run"]]

        self.assertEqual(run(), ["2026-10-26", "2026-10-25", "2026-10-24", "2026-10-23"])
        self.assertEqual(run(), ["2026-10-26", "2026-10-25", "2026-10-22", "2026-10-21"])
        self.assertEqual(run(), ["2026-10-26", "2026-10-25"])
        cursor = self.reg.jobs["rollup"]["cursor"]
        self.assertEqual(cursor["horizon"], "2026-10-21")
        # the 24th has AP data in its last minutes (the world's series start 3 minutes before DAY)
        self.assertEqual(cursor["empty_days"], ["2026-10-21", "2026-10-22", "2026-10-23"])

    def test_a_device_day_lost_is_refilled(self):
        self.prom.vector(rollup.HORIZON, [({}, START - 86400)])
        self.run_job(NOW + datetime.timedelta(days=1))     # DAY is now the day before yesterday
        self.assertIn(("d1", DAY), self.reg.device_day_rows)
        del self.reg.device_day_rows[("d1", DAY)]
        cursor = self.run_job(NOW + datetime.timedelta(days=1))
        self.assertIn(DAY.isoformat(), [d["day"] for d in cursor["last_run"]])
        self.assertIn(("d1", DAY), self.reg.device_day_rows)

    def test_prometheus_down_fails_the_run(self):
        self.prom.fail()
        self.assertEqual(scheduler.run_job(jobs.BY_NAME["rollup"], self.settings, now=NOW), scheduler.FAILED)
        self.assertEqual(self.reg.device_day_rows, {})


if __name__ == "__main__":
    unittest.main()
