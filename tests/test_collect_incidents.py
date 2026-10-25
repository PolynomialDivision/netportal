"""Job incidents: per-minute monitoring signals (fake Prometheus) -> incident rows, opened and
closed idempotently."""

import datetime
import logging
import tempfile
import unittest
from pathlib import Path

from fakes import FakePrometheus
from fakes.registry import FakeRegistry

from netportal.collect import incidents, jobs, scheduler
from netportal.collect.settings import CollectSettings

UTC = datetime.timezone.utc
logging.getLogger("netportal.collect").setLevel(logging.ERROR + 10)

T0 = 1792929600                     # 2026-10-25 12:00 UTC (a minute boundary)
AP1 = {"mac": "60:22:32:37:48:00", "name": "ap-scharni-2-corner"}
AP2 = {"mac": "68:d7:9a:1c:61:46", "name": "ap-scharni-4-corner"}
Q = incidents.Q


def at(minute):
    return T0 + 60 * minute


def dt(unix):
    return datetime.datetime.fromtimestamp(unix, UTC)


class World:
    """The house's signals per minute from minute -60 to +60 around T0, all fine by default."""

    def __init__(self):
        self.minutes = range(-60, 61)
        self.values = {name: {m: v for m in self.minutes} for name, v in (
            ("gateway", 1), ("internet", 1), ("loss", 0.0), ("rtt", 5.0), ("dns", 1), ("unifi_up", 1), ("age", 12),
            ("site_disconnected", 0), ("web_exporter", 1), ("cadvisor", 1), ("radius", 1792900000))}
        self.aps = {AP1["mac"]: dict(AP1), AP2["mac"]: dict(AP2)}
        self.ap_present = {mac: set(self.minutes) for mac in self.aps}
        self.uptime = {mac: {m: 100000 + 60 * m for m in self.minutes} for mac in self.aps}
        self.switches_icmp = {"sw-cellar": {m: 1 for m in self.minutes}}
        self.web_switches = {"sw-colbe-2": {m: 1 for m in self.minutes}}

    def set(self, name, minutes, value):
        for m in minutes:
            if value is None:
                self.values[name].pop(m, None)
            else:
                self.values[name][m] = value

    def load(self, prom, radius="netaccess-radius"):
        def pts(d):
            return {at(m): v for m, v in d.items()}
        for name in ("gateway", "internet", "loss", "rtt", "dns", "unifi_up", "age", "site_disconnected",
                     "web_exporter", "cadvisor"):
            prom.range_series(Q[name], [({}, pts(self.values[name]))])
        prom.range_series(incidents.RADIUS.format(name=radius), [({}, pts(self.values["radius"]))])
        prom.range_series(Q["ap_info"], [({"mac": mac, "name": ap["name"]}, {at(m): 1 for m in self.ap_present[mac]})
                                         for mac, ap in self.aps.items()])
        prom.range_series(Q["ap_uptime"], [({"name": ap["name"]}, pts(self.uptime[mac]))
                                           for mac, ap in self.aps.items()])
        prom.vector(incidents.AP_KNOWN, [({"mac": mac, "name": ap["name"]}, 1) for mac, ap in self.aps.items()])
        prom.range_series(Q["switch_icmp"], [({"switch": k}, pts(v)) for k, v in self.switches_icmp.items()])
        prom.range_series(Q["web_switch"], [({"switch": k}, pts(v)) for k, v in self.web_switches.items()])
        prom.range_series(Q["web_switch_blocked"], [({"switch": k}, {at(m): 0 for m in v})
                                                    for k, v in self.web_switches.items()])


class IncidentsCase(unittest.TestCase):
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
                                        heartbeat=str(Path(self.tmp.name) / "hb"))
        self.world = World()

    def run_at(self, minute):
        self.world.load(self.prom)
        result = scheduler.run_job(jobs.BY_NAME["incidents"], self.settings, now=dt(at(minute) + 5))
        self.assertEqual(result, scheduler.OK, self.reg.jobs.get("incidents"))

    def rows(self, kind=None):
        return [(r["kind"], r["subject"], r["started"], r["ended"]) for r in self.reg.incident_rows
                if kind is None or r["kind"] == kind]


class HouseTests(IncidentsCase):
    def test_all_fine_opens_nothing(self):
        self.run_at(0)
        self.assertEqual(self.rows(), [])
        self.assertEqual(self.reg.jobs["incidents"]["cursor"]["evaluated_until"], at(0))

    def test_internet_down_opens_then_closes(self):
        self.world.set("internet", range(-6, 61), 0)
        self.run_at(0)
        self.assertEqual(self.rows(), [("internet_down", "", dt(at(-6)), None)])
        row = self.reg.incident_rows[0]
        self.assertEqual((row["basis"], row["subject_name"]), ("measured", None))
        # the same minutes again: nothing new (idempotent)
        self.run_at(0)
        self.run_at(1)
        self.assertEqual(len(self.reg.incident_rows), 1)
        # back at minute 5; closed once the next run sees it stay up
        self.world.set("internet", range(5, 61), 1)
        self.run_at(6)
        self.assertEqual(self.rows()[0][3], None)              # 1 minute ok: not confirmed yet
        self.run_at(8)
        self.assertEqual(self.rows(), [("internet_down", "", dt(at(-6)), dt(at(5)))])
        self.run_at(10)
        self.assertEqual(len(self.reg.incident_rows), 1)

    def test_short_blips_are_no_incident(self):
        self.world.set("internet", [-5], 0)
        self.world.set("gateway", [-3], 0)
        self.run_at(0)
        self.assertEqual(self.rows(), [])

    def test_a_one_minute_success_does_not_split_an_outage(self):
        self.world.set("internet", range(-12, 61), 0)
        self.world.set("internet", [-7], 1)
        self.run_at(0)
        self.assertEqual(self.rows(), [("internet_down", "", dt(at(-12)), None)])

    def test_router_down_hides_internet_and_dns(self):
        self.world.set("gateway", range(-8, 61), 0)
        self.world.set("internet", range(-8, 61), 0)
        self.world.set("dns", range(-8, 61), 0)
        self.run_at(0)
        self.assertEqual(self.rows(), [("router_down", "", dt(at(-8)), None)])

    def test_degraded_and_dns(self):
        self.world.set("loss", range(-10, 61), 0.2)
        self.world.set("dns", range(-9, 61), 0)
        self.run_at(0)
        kinds = {r[0]: r for r in self.rows()}
        self.assertEqual(kinds["internet_degraded"][2], dt(at(-10)))
        self.assertEqual(kinds["dns_down"][2], dt(at(-9)))
        detail = next(r["detail"] for r in self.reg.incident_rows if r["kind"] == "internet_degraded")
        self.assertEqual(detail["loss_ratio_max"], 0.2)

    def test_degraded_below_five_minutes_is_nothing(self):
        self.world.set("rtt", range(-3, 61), 250.0)            # 4 minutes up to now
        self.run_at(0)
        self.assertEqual(self.rows(), [])

    def test_stale_unifi_data(self):
        self.world.set("age", range(-5, 61), 900)
        self.world.set("unifi_up", range(-3, 61), 0)
        self.run_at(0)
        self.assertEqual(self.rows(), [("unifi_data_stale", "", dt(at(-5)), None)])

    def test_radius_container_gone(self):
        self.world.set("radius", range(-4, 61), None)
        self.run_at(0)
        self.assertEqual(self.rows(), [("radius_down", "", dt(at(-4)), None)])

    def test_cadvisor_down_says_nothing_about_radius(self):
        self.world.set("radius", range(-4, 61), None)
        self.world.set("cadvisor", range(-4, 61), 0)
        self.run_at(0)
        self.assertEqual(self.rows(), [])

    def test_prometheus_failing_is_recorded(self):
        self.prom.fail()
        self.world.load(self.prom)
        self.assertEqual(scheduler.run_job(jobs.BY_NAME["incidents"], self.settings, now=dt(at(0))), scheduler.FAILED)
        self.assertIn("HTTP 500", self.reg.jobs["incidents"]["last_error"])

    def test_a_long_pause_is_evaluated_from_the_cursor(self):
        self.run_at(-40)
        self.world.set("internet", range(-35, -25), 0)          # while the collector was away
        self.run_at(0)
        self.assertEqual(self.rows(), [("internet_down", "", dt(at(-35)), dt(at(-25)))])


class ApTests(IncidentsCase):
    def test_ap_missing_while_data_is_fresh(self):
        self.world.ap_present[AP1["mac"]] -= set(range(-5, 61))
        self.run_at(0)
        self.assertEqual(self.rows(), [("ap_down", AP1["mac"], dt(at(-5)), None)])
        row = self.reg.incident_rows[0]
        self.assertEqual((row["subject_name"], row["detail"]), (AP1["name"], {"signal": ["device_missing"]}))

    def test_ap_missing_while_unifi_is_stale_is_unifi_data_stale(self):
        self.world.ap_present[AP1["mac"]] -= set(range(-5, 61))
        self.world.set("age", range(-5, 61), 900)
        self.run_at(0)
        self.assertEqual([r[0] for r in self.rows()], ["unifi_data_stale"])

    def test_disconnected_ap_with_frozen_uptime(self):
        mac = AP2["mac"]
        frozen = self.world.uptime[mac][-8]
        for m in range(-8, 61):
            self.world.uptime[mac][m] = frozen
        self.world.set("site_disconnected", range(-6, 61), 1)
        self.run_at(0)
        # down once the uptime has not moved for 3 minutes (-8 .. -5) while the site counts one
        self.assertEqual(self.rows("ap_down"), [("ap_down", mac, dt(at(-5)), None)])
        self.assertEqual(self.reg.incident_rows[0]["detail"], {"signal": ["site_disconnected"]})

    def test_frozen_uptime_alone_is_not_down(self):
        mac = AP2["mac"]
        frozen = self.world.uptime[mac][-8]
        for m in range(-8, 61):
            self.world.uptime[mac][m] = frozen
        self.run_at(0)
        self.assertEqual(self.rows(), [])

    def test_restart(self):
        mac = AP1["mac"]
        for m in range(-4, 61):
            self.world.uptime[mac][m] = 30 + 60 * (m + 4)
        self.run_at(0)
        self.assertEqual(len(self.rows("ap_restarted")), 1)
        kind, subject, started, ended = self.rows("ap_restarted")[0]
        self.assertEqual(subject, mac)
        self.assertEqual(started, dt(at(-4) - 12 - 30))         # snapshot (minus its age) minus uptime
        self.assertEqual(ended, dt(at(-4) - 12))
        self.run_at(1)
        self.run_at(2)
        self.assertEqual(len(self.rows("ap_restarted")), 1)


class ApRecordTests(IncidentsCase):
    """house-infra's records unifi_ap:up / unifi_ap:uptime:seconds (by ap_mac), where they exist."""

    def test_record_zero_is_down(self):
        mac = AP2["mac"]
        self.world.load(self.prom)
        self.prom.range_series(incidents.AP_UP_RECORD, [
            ({"ap_mac": mac, "ap_name": AP2["name"]}, {at(m): (0 if m >= -5 else 1) for m in self.world.minutes})])
        scheduler.run_job(jobs.BY_NAME["incidents"], self.settings, now=dt(at(0) + 5))
        self.assertEqual(self.rows(), [("ap_down", mac, dt(at(-5)), None)])
        self.assertEqual(self.reg.incident_rows[0]["detail"], {"signal": ["unifi_ap_up"]})

    def test_restart_from_the_record_alone(self):
        mac = AP1["mac"]
        self.world.load(self.prom)
        self.prom.range_series(Q["ap_uptime"], [])                 # no raw series (only the record)
        self.prom.range_series(incidents.AP_UPTIME_RECORD, [
            ({"ap_mac": mac, "ap_name": AP1["name"]},
             {at(m): (500000 + 60 * m if m < -3 else 20 + 60 * (m + 3)) for m in self.world.minutes})])
        scheduler.run_job(jobs.BY_NAME["incidents"], self.settings, now=dt(at(0) + 5))
        self.assertEqual([(r[0], r[1], r[2]) for r in self.rows()], [("ap_restarted", mac, dt(at(-3) - 12 - 20))])
        self.assertEqual(self.reg.incident_rows[0]["subject_name"], AP1["name"])


class SwitchTests(IncidentsCase):
    def test_icmp_switch_down(self):
        for m in range(-4, 61):
            self.world.switches_icmp["sw-cellar"][m] = 0
        self.run_at(0)
        self.assertEqual(self.rows(), [("switch_down", "sw-cellar", dt(at(-4)), None)])
        self.assertEqual(self.reg.incident_rows[0]["detail"], {"source": "switches_icmp"})

    def test_web_switch_down_unless_the_exporter_is(self):
        for m in range(-10, 61):
            self.world.web_switches["sw-colbe-2"][m] = 0
        self.world.set("web_exporter", range(-60, 61), 0)
        self.run_at(0)
        self.assertEqual(self.rows(), [])
        self.world.set("web_exporter", range(-60, 61), 1)
        self.run_at(0)
        self.assertEqual(self.rows(), [("switch_down", "sw-colbe-2", dt(at(-10)), None)])

    def test_web_switch_short_timeouts_and_busy_sessions_are_no_incident(self):
        for m in range(-8, 61):
            self.world.web_switches["sw-colbe-2"][m] = 0          # 9 minutes: below the 10
        self.run_at(0)
        self.assertEqual(self.rows(), [])
        for m in range(-30, 61):
            self.world.web_switches["sw-colbe-2"][m] = 0
        self.world.load(self.prom)
        self.prom.range_series(Q["web_switch_reason"], [({"switch": "sw-colbe-2", "reason": "session_busy"},
                                                         {at(m): 1 for m in range(-30, 61)})])
        scheduler.run_job(jobs.BY_NAME["incidents"], self.settings, now=dt(at(0) + 5))
        self.assertEqual(self.rows(), [])


class ReconcileTests(unittest.TestCase):
    """reconcile() alone, on hand-made states."""

    def setUp(self):
        self.reg = FakeRegistry()
        patch = self.reg.patched()
        patch.__enter__()
        self.addCleanup(patch.__exit__, None, None, None)

    def states(self, text):
        """'.' ok, 'x' failing, '?' unknown, one per minute from T0."""
        grid = [T0 + 60 * i for i in range(len(text))]
        return grid, {t: {".": False, "x": True, "?": None}[c] for t, c in zip(grid, text, strict=True)}

    def test_unknown_neither_opens_nor_closes(self):
        grid, points = self.states("xxxx????????")
        incidents.reconcile(None, "router_down", "", None, points, grid, [])
        self.assertEqual(len(self.reg.incident_rows), 1)
        stored = [dict(r) for r in self.reg.incident_rows]
        grid, points = self.states("????????????")
        incidents.reconcile(None, "router_down", "", None, points, grid, stored)
        self.assertIsNone(self.reg.incident_rows[0]["ended"])

    def test_two_separate_outages(self):
        grid, points = self.states("xxxx.....xxxx.....")
        opened, closed = incidents.reconcile(None, "router_down", "", None, points, grid, [])
        self.assertEqual((opened, closed), (2, 2))
        self.assertEqual([(r["started"], r["ended"]) for r in self.reg.incident_rows],
                         [(dt(T0), dt(T0 + 240)), (dt(T0 + 540), dt(T0 + 780))])


if __name__ == "__main__":
    unittest.main()
