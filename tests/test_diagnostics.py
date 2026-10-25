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
        self.assertEqual(found, [{"code": "offline", "severity": "info", "params": {"last_seen": "x"}}])

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


if __name__ == "__main__":
    unittest.main()
