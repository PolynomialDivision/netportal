"""The dashboard's findings (netportal/diagnostics.py): each rule at its thresholds, and only on
data that is there. Example values only."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from netportal import diagnostics as dx  # noqa: E402


def online(**values):
    """A healthy online device; values override."""
    device = {"state": "online", "mac": "02:00:00:00:00:0a", "band": "5", "channel": 56, "signal_dbm": -55,
              "noise_dbm": -96, "snr_db": 41, "retry_ratio": 0.02, "channel_util": 0.2, "link_rx_bps": 600_000_000,
              "rx_bps": 50_000, "tx_bps": 10_000, "roams_1h": 0, "last_seen": "2026-10-25T10:00:00+00:00"}
    device.update(values)
    return device


BUSY = {"tx_attempts_per_s": 200}


def codes(device, summary=None, age=30, telemetry="ok"):
    return {f["code"]: f["severity"] for f in dx.findings(device, summary, age, telemetry)}


class StateTests(unittest.TestCase):
    def test_healthy_device_has_no_findings(self):
        self.assertEqual(dx.findings(online(), BUSY, 30), [])

    def test_never_connected(self):
        self.assertEqual(codes({"state": "never_connected", "mac": None}), {"never_connected": "info"})

    def test_offline(self):
        found = dx.findings({"state": "offline", "mac": "02:00:00:00:00:0a", "last_seen": "x"}, None, 30)
        self.assertEqual(found, [{"code": "offline", "severity": "info", "params": {"last_seen": "x"},
                                  "basis": "measured", "evidence": {"last_seen": "x", "confirmed_at": None,
                                                                    "confirmed_by": None, "reason": None}}])
        # presence's confirmation is what the finding rests on
        found = dx.findings({"state": "offline", "mac": "02:00:00:00:00:0a", "last_seen": "x", "presence": {
            "confirmed_at": "y", "confirmed_by": "radius_acct", "reason": "acct_stop", "basis": "measured"}}, None, 30)
        self.assertEqual(found[0]["evidence"], {"last_seen": "x", "confirmed_at": "y", "confirmed_by": "radius_acct",
                                                "reason": "acct_stop"})
        # connecting and unknown are never "not connected"
        for state in ("connecting", "unknown"):
            self.assertNotIn("offline", codes({"state": state, "mac": "02:00:00:00:00:0a"}))

    def test_stale_only_while_prometheus_answers(self):
        unknown = {"state": "unknown", "mac": "02:00:00:00:00:0a"}
        self.assertEqual(codes(unknown, age=601), {"stale_data": "warn"})
        self.assertEqual(codes(unknown, age=None), {"stale_data": "warn"})       # unpoller not scraped
        self.assertEqual(codes(unknown, age=None, telemetry="unavailable"), {})
        self.assertEqual(codes(unknown, age=None, telemetry="off"), {})
        self.assertFalse(dx.is_stale(600))
        self.assertTrue(dx.is_stale(601))

    def test_radio_rules_only_while_online(self):
        bad = online(signal_dbm=-90, snr_db=5, retry_ratio=0.9, channel_util=0.95)
        self.assertEqual(codes(dict(bad, state="offline"), BUSY), {"offline": "info"})
        self.assertEqual(codes(dict(bad, state="unknown"), BUSY, age=30), {})

    def test_worst_first(self):
        found = dx.findings(online(signal_dbm=-76, retry_ratio=0.3), BUSY, 30)
        self.assertEqual([f["severity"] for f in found], ["bad", "warn"])


class ThresholdTests(unittest.TestCase):
    def test_weak_signal(self):
        self.assertNotIn("weak_signal", codes(online(signal_dbm=-74)))
        self.assertEqual(codes(online(signal_dbm=-75))["weak_signal"], "warn")
        self.assertEqual(codes(online(signal_dbm=-80))["weak_signal"], "bad")
        self.assertEqual(dx.findings(online(signal_dbm=-80, snr_db=16))[0]["params"], {"signal_dbm": -80})

    def test_low_snr_only_with_a_good_signal(self):
        self.assertNotIn("low_snr", codes(online(snr_db=21)))
        self.assertEqual(codes(online(snr_db=20))["low_snr"], "warn")
        self.assertEqual(codes(online(snr_db=15))["low_snr"], "bad")
        self.assertNotIn("low_snr", codes(online(signal_dbm=-78, snr_db=15)))     # the distance, said already

    def test_high_retries_only_with_traffic(self):
        self.assertNotIn("high_retries", codes(online(retry_ratio=0.09), BUSY))
        self.assertEqual(codes(online(retry_ratio=0.10), BUSY)["high_retries"], "warn")
        self.assertEqual(codes(online(retry_ratio=0.25), BUSY)["high_retries"], "bad")
        self.assertNotIn("high_retries", codes(online(retry_ratio=0.5), {"tx_attempts_per_s": 9.9}))
        self.assertNotIn("high_retries", codes(online(retry_ratio=0.5), None))

    def test_busy_channel(self):
        self.assertNotIn("busy_channel", codes(online(channel_util=0.59)))
        self.assertEqual(codes(online(channel_util=0.6))["busy_channel"], "warn")
        self.assertEqual(codes(online(channel_util=0.8))["busy_channel"], "bad")

    def test_slow_link_needs_good_signal_and_traffic(self):
        slow = online(link_rx_bps=6_000_000, signal_dbm=-60, rx_bps=2_000_000)
        self.assertEqual(codes(slow)["slow_link"], "warn")
        self.assertNotIn("slow_link", codes(dict(slow, signal_dbm=-70)))
        self.assertNotIn("slow_link", codes(dict(slow, rx_bps=1000, tx_bps=1000)))       # idle: low rates are normal
        self.assertNotIn("slow_link", codes(dict(slow, link_rx_bps=20_000_000)))
        self.assertNotIn("slow_link", codes(dict(slow, link_rx_bps=None)))

    def test_unstable_roaming(self):
        self.assertNotIn("unstable_roaming", codes(online(roams_1h=5)))
        self.assertEqual(codes(online(roams_1h=6))["unstable_roaming"], "warn")
        self.assertEqual(codes(online(roams_1h=15))["unstable_roaming"], "bad")

    def test_frequent_disconnects(self):
        self.assertNotIn("frequent_disconnects", codes(online(), {"reconnects_24h": 5}))
        self.assertEqual(codes(online(), {"reconnects_24h": 6})["frequent_disconnects"], "warn")
        self.assertEqual(codes(online(), {"reconnects_24h": 20})["frequent_disconnects"], "bad")
        offline = {"state": "offline", "mac": "02:00:00:00:00:0a"}
        self.assertEqual(codes(offline, {"reconnects_24h": 30})["frequent_disconnects"], "bad")

    def test_stuck_on_2ghz(self):
        stuck = online(band="2.4", signal_dbm=-50, roams_1h=0)
        seen = {"bands_7d": ["2.4", "5"], "associated_s": 7200}
        self.assertEqual(codes(stuck, seen)["stuck_on_2ghz"], "info")
        self.assertNotIn("stuck_on_2ghz", codes(stuck, dict(seen, bands_7d=["2.4"])))       # cannot do better
        self.assertNotIn("stuck_on_2ghz", codes(stuck, dict(seen, associated_s=1800)))      # just arrived
        self.assertNotIn("stuck_on_2ghz", codes(dict(stuck, roams_1h=2), seen))             # band steering at work
        self.assertNotIn("stuck_on_2ghz", codes(dict(stuck, signal_dbm=-70), seen))         # 5 GHz would not reach
        self.assertNotIn("stuck_on_2ghz", codes(dict(stuck, band="5"), seen))

    def test_missing_values_say_nothing(self):
        empty = {"state": "online", "mac": "02:00:00:00:00:0a"}
        self.assertEqual(dx.findings(empty, None, 30), [])
        self.assertEqual(dx.findings(empty, {"reconnects_24h": None, "bands_7d": []}, 30), [])


NOW = 1_800_000_000


def ctx(**values):
    return dict({"now": NOW}, **values)


def find(device, context, code, summary=None):
    found = [f for f in dx.findings(device, summary, 30, "ok", context) if f["code"] == code]
    return found[0] if found else None


class BasisTests(unittest.TestCase):
    def test_every_finding_has_basis_and_evidence(self):
        device = online(signal_dbm=-81, snr_db=10, retry_ratio=0.5, channel_util=0.9, roams_1h=20)
        for f in dx.findings(device, dict(BUSY, reconnects_24h=30), 30):
            self.assertIn(f["basis"], ("measured", "inferred"), f["code"])
            self.assertIsInstance(f["evidence"], dict)
        found = {f["code"]: f for f in dx.findings(device, dict(BUSY, reconnects_24h=30), 30)}
        self.assertEqual(found["weak_signal"]["evidence"], {"signal_dbm": -81, "warn_dbm": -75, "bad_dbm": -80})
        self.assertEqual(found["weak_signal"]["basis"], "measured")
        self.assertEqual(found["unstable_roaming"]["basis"], "inferred")          # from AP label changes
        self.assertEqual(found["frequent_disconnects"]["basis"], "inferred")      # from association starts


class AuthFailureTests(unittest.TestCase):
    def rejects(self, n, reason="expired", last=NOW - 60):
        return [{"at": last - i * 60, "reason": reason, "mac": None} for i in range(n)]

    def test_thresholds(self):
        accepted = ctx(last_accept=NOW)                                           # logged in since
        self.assertIsNone(find(online(), dict(accepted, rejects=self.rejects(2)), "auth_failures"))
        self.assertEqual(find(online(), dict(accepted, rejects=self.rejects(3)), "auth_failures")["severity"], "warn")
        self.assertEqual(find(online(), dict(accepted, rejects=self.rejects(20)), "auth_failures")["severity"], "bad")

    def test_a_row_of_repeats_counts_its_tries(self):
        """Repeated rejects are one row (registry.REJECT_REPEAT): count tries, the latest at last_at."""
        rows = [{"at": NOW - 3000, "last_at": NOW - 100, "count": 25, "reason": "no_cert", "mac": None},
                {"at": NOW - 2000, "reason": "expired", "mac": None}]
        f = find(online(), ctx(last_accept=NOW - 1000, rejects=rows), "auth_failures")
        self.assertEqual((f["severity"], f["params"]["count"], f["evidence"]["count_24h"]), ("bad", 26, 26))
        self.assertEqual(f["evidence"]["reasons"], {"no_cert": 25, "expired": 1})
        self.assertEqual((f["params"]["reason"], f["evidence"]["last_at"]), ("no_cert", dx._iso(NOW - 100)))
        self.assertTrue(f["evidence"]["locked_out"])                    # its last try is after the login

    def test_rejected_since_the_last_login_is_a_warning_at_once(self):
        f = find({"state": "never_connected"}, ctx(last_accept=None, rejects=self.rejects(1, "revoked")),
                 "auth_failures")
        self.assertEqual((f["severity"], f["basis"], f["params"]["reason"]), ("warn", "measured", "revoked"))
        self.assertEqual(f["evidence"]["reasons"], {"revoked": 1})
        self.assertTrue(f["evidence"]["locked_out"])


class CertTests(unittest.TestCase):
    def test_expiring_and_expired(self):
        self.assertIsNone(find(online(), ctx(expires=NOW + 31 * 86400), "cert_expiring"))
        self.assertEqual(find(online(), ctx(expires=NOW + 30 * 86400), "cert_expiring")["severity"], "info")
        f = find(online(), ctx(expires=NOW + 7 * 86400), "cert_expiring")
        self.assertEqual((f["severity"], f["params"]["days_left"], f["evidence"]["days_left"]), ("warn", 7, 7))
        f = find({"state": "never_connected"}, ctx(expires=NOW - 86400), "cert_expired")
        self.assertEqual((f["severity"], f["evidence"]["days_left"]), ("bad", -1))


class IdentityFindingTests(unittest.TestCase):
    def test_rotating_mac(self):
        macs = ["02:00:00:00:00:%02x" % i for i in range(4)]
        f = find(online(), ctx(mac_mode="rotating", randomized_macs_30d=macs), "rotating_mac")
        self.assertEqual((f["severity"], f["params"], f["basis"]), ("info", {"macs_30d": 4}, "measured"))
        self.assertIsNone(find(online(), ctx(mac_mode="random_fixed"), "rotating_mac"))


class LoadTests(unittest.TestCase):
    def load(self, clients, util=None):
        return ctx(ap_load={"ap": "ap-scharni-2-corner", "clients": clients, "channel_util": util, "band": "5"})

    def test_clients(self):
        self.assertIsNone(find(online(), self.load(24), "ap_overloaded"))
        self.assertEqual(find(online(), self.load(25), "ap_overloaded")["severity"], "warn")
        self.assertEqual(find(online(), self.load(40), "ap_overloaded")["severity"], "bad")

    def test_utilisation_counts_only_with_many_clients(self):
        self.assertIsNone(find(online(), self.load(9, 0.95), "ap_overloaded"))
        self.assertEqual(find(online(), self.load(10, 0.80), "ap_overloaded")["severity"], "warn")
        f = find(online(), self.load(10, 0.90), "ap_overloaded")
        self.assertEqual((f["severity"], f["evidence"]["ap"], f["evidence"]["clients"]), ("bad", "ap-scharni-2-corner", 10))
        self.assertIsNone(find(dict(online(), state="offline"), self.load(60), "ap_overloaded"))


class CoverageTests(unittest.TestCase):
    def cover(self, *signals, samples=120):
        return ctx(coverage={"ap-%d" % i: {"signal_dbm": s, "samples": samples} for i, s in enumerate(signals)})

    def test_weak_at_every_ap(self):
        self.assertIsNone(find(online(), self.cover(-71.9, -80), "poor_coverage"))     # one AP is fine
        self.assertEqual(find(online(), self.cover(-72, -80), "poor_coverage")["severity"], "warn")
        f = find(dict(online(), state="offline"), self.cover(-78, -85), "poor_coverage")
        self.assertEqual((f["severity"], f["params"]["aps"], f["evidence"]["aps"]["ap-0"]), ("bad", 2, -78))

    def test_short_visits_do_not_count(self):
        self.assertIsNone(find(online(), self.cover(-85, samples=59), "poor_coverage"))


class IncidentFindingTests(unittest.TestCase):
    INCIDENT = {"id": 9, "kind": "ap_restarted", "subject": "60:22:32:37:48:00", "subject_name": "ap-scharni-2-corner",
                "started": NOW - 3600, "ended": NOW - 3500, "basis": "measured"}

    def test_a_disconnect_near_an_incident(self):
        context = ctx(incidents=[self.INCIDENT], disconnects=[{"at": NOW - 3590, "basis": "measured"},
                                                              {"at": NOW - 600, "basis": "inferred"}])
        f = find(online(), context, "incident_correlated")
        self.assertEqual((f["basis"], f["severity"], f["params"]["kind"]), ("inferred", "info", "ap_restarted"))
        self.assertEqual(f["evidence"]["incident"]["id"], 9)
        self.assertEqual(len(f["evidence"]["disconnects"]), 1)

    def test_the_margins(self):
        for at, hit in ((NOW - 3600 - 120, True), (NOW - 3600 - 121, False), (NOW - 3500 + 120, True),
                        (NOW - 3500 + 121, False)):
            context = ctx(incidents=[self.INCIDENT], disconnects=[{"at": at, "basis": "inferred"}])
            self.assertEqual(find(online(), context, "incident_correlated") is not None, hit, at)

    def test_a_long_incident_counts_only_its_first_15_minutes(self):
        long = dict(self.INCIDENT, ended=None)
        late = ctx(incidents=[long], disconnects=[{"at": NOW - 3600 + 900 + 121, "basis": "inferred"}])
        self.assertIsNone(find(online(), late, "incident_correlated"))


class MeasuredHistoryTests(unittest.TestCase):
    def test_measured_disconnects_with_causes(self):
        disconnects = [{"at": NOW - i * 600, "basis": "measured", "cause": "Lost-Carrier" if i % 2 else "User-Request"}
                       for i in range(6)]
        f = find(online(), ctx(disconnects=disconnects), "frequent_disconnects", {"reconnects_24h": 2})
        self.assertEqual((f["basis"], f["severity"], f["params"]["reconnects_24h"]), ("measured", "warn", 6))
        self.assertEqual(f["evidence"]["causes"], {"User-Request": 3, "Lost-Carrier": 3})

    def test_measured_roams(self):
        f = find(online(roams_1h=2), ctx(roams_1h_measured=15), "unstable_roaming")
        self.assertEqual((f["basis"], f["severity"], f["params"]["roams_1h"]), ("measured", "bad", 15))



class ApWarningTests(unittest.TestCase):
    def ap(self, **values):
        base = {"name": "ap-scharni-2-corner", "state": "ok", "clients": 10, "weak_clients": 0, "uptime_s": 5 * 86400,
                "uplink_mbps": 1000, "radios": [{"radio": "na", "channel_util": 0.3}]}
        return dict(base, **values)

    def codes(self, **values):
        return {f["code"]: f["severity"] for f in dx.ap_warnings(self.ap(**values))}

    def test_a_healthy_ap_has_none(self):
        self.assertEqual(dx.ap_warnings(self.ap()), [])

    def test_down_says_it_all(self):
        self.assertEqual(self.codes(state="down", clients=60, uptime_s=10), {"down": "bad"})

    def test_poor_coverage(self):
        self.assertNotIn("poor_coverage", self.codes(clients=8, weak_clients=1))
        self.assertEqual(self.codes(clients=8, weak_clients=2)["poor_coverage"], "warn")          # 25 %
        self.assertNotIn("poor_coverage", self.codes(clients=3, weak_clients=3))                  # too few
        f = dx.ap_warnings(self.ap(clients=4, weak_clients=1))[0]
        self.assertEqual((f["params"]["share"], f["basis"], f["evidence"]["threshold"]), (0.25, "measured", 0.25))

    def test_restarted_and_uplink(self):
        self.assertEqual(self.codes(uptime_s=86399)["restarted"], "info")
        self.assertNotIn("restarted", self.codes(uptime_s=86400))
        self.assertEqual(self.codes(uplink_mbps=100)["uplink"], "warn")
        self.assertNotIn("uplink", self.codes(uplink_mbps=None))
        self.assertNotIn("uplink", self.codes(uplink_mbps=2500))

    def test_overloaded_as_for_a_device_else_busy(self):
        self.assertEqual(self.codes(clients=25)["overloaded"], "warn")
        self.assertEqual(self.codes(clients=40)["overloaded"], "bad")
        self.assertEqual(self.codes(clients=10, radios=[{"radio": "ng", "channel_util": 0.91}])["overloaded"], "bad")
        self.assertEqual(self.codes(clients=9, radios=[{"radio": "ng", "channel_util": 0.95}]),
                         {"busy_channel": "warn"})
        self.assertEqual(self.codes(radios=[{"channel_util": 0.6}]), {"busy_channel": "warn"})
        for clients, util in ((24, 0.5), (25, 0.5), (12, 0.85)):
            device = find(online(), ctx(ap_load={"ap": "x", "clients": clients, "channel_util": util}), "ap_overloaded")
            ap = [f for f in dx.ap_warnings(self.ap(clients=clients, radios=[{"channel_util": util}]))
                  if f["code"] == "overloaded"]
            self.assertEqual(device["severity"] if device else None, ap[0]["severity"] if ap else None)

if __name__ == "__main__":
    unittest.main()
