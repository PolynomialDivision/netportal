"""Telemetry v2 (netportal/telemetry/): the timeline merge across sources, the history stitched
over MAC windows (Prometheus faked, registry faked), the day ranges from the rollups, and the
DEVICE additions of the dashboard. Example MACs and values only."""

import datetime
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_telemetry import HOUSE_OK, SSID, client, live, matrix, vector  # noqa: E402
from test_telemetry_registry import NOW, FakeRegistry, dt, row, window  # noqa: E402

from netportal import telemetry  # noqa: E402
from netportal.telemetry import identity as ident  # noqa: E402
from netportal.telemetry import timeline as tl  # noqa: E402

AP1, AP2 = "ap-scharni-2-corner", "ap-colbe-2-far"
AP1_MAC, AP2_MAC = "60:22:32:37:48:00", "68:d7:9a:1c:61:46"
M1, M2, M3 = "02:00:00:00:00:0a", "02:00:00:00:00:0b", "02:00:00:00:00:0c"
END = NOW // 60 * 60


def kinds(events):
    return [e["kind"] for e in events]


def unifi(at, kind, ap=AP1, ap_mac=AP1_MAC, from_ap=None, from_ap_mac=None, mac=M1, radio="na", **extra):
    return dict({"at": dt(at), "kind": kind, "source": "unifi_syslog", "mac": mac, "ap_mac": ap_mac, "ap_name": ap,
                 "from_ap_mac": from_ap_mac, "from_ap_name": from_ap, "ssid": SSID, "radio": radio, "channel": 36,
                 "rssi": -60, "duration_s": None, "rx_bytes": None, "tx_bytes": None}, **extra)


def acct(started, stopped=None, bssid="60:22:32:38:48:00", cause=None, sid="s1", link="class", mac=M1):
    return {"nas_ip": "10.0.10.27", "acct_session_id": sid, "link": link, "mac": mac, "bssid": bssid, "ssid": SSID,
            "framed_ip": "10.30.0.5", "started": None if started is None else dt(started),
            "updated": dt(stopped or started), "stopped": None if stopped is None else dt(stopped),
            "session_time_s": None if stopped is None or started is None else stopped - started,
            "input_octets": 1000, "output_octets": 9000, "terminate_cause": cause}


APS = tl.ApMap(bssids={"60:22:32:38:48:00": (AP1, AP1_MAC, "5"), "68:d7:9a:1d:61:46": (AP2, AP2_MAC, "5")},
               nas={"10.0.10.27": (AP1, AP1_MAC)}, names={AP1_MAC: AP1, AP2_MAC: AP2})


class MergeTests(unittest.TestCase):
    def test_the_same_connection_from_three_sources_is_one_event(self):
        t = NOW - 3600
        events = (tl.from_presence([tl.event("connected", t + 50, AP1, "5", mac=M1)])
                  + tl.from_acct([acct(t + 5)], APS) + tl.from_unifi([unifi(t, "connected")], APS))
        merged, truncated = tl.merge(events)
        self.assertFalse(truncated)
        self.assertEqual(kinds(merged), ["connected"])
        e = merged[0]
        self.assertEqual(e["sources"], ["unifi_syslog", "radius_acct", "prometheus"])
        self.assertEqual((e["source"], e["basis"], e["at"]), ("unifi_syslog", "measured", t))   # measured wins
        self.assertEqual(e["detail"]["rssi"], -60)
        self.assertEqual(e["detail"]["framed_ip"], "10.30.0.5")                                # filled in

    def test_events_further_apart_or_on_other_aps_stay_apart(self):
        t = NOW - 3600
        merged, _ = tl.merge(tl.from_unifi([unifi(t, "connected")], APS)
                             + tl.from_acct([acct(t + 300)], APS)
                             + tl.from_presence([tl.event("roamed", t + 10, AP2, "5", AP1, "5", mac=M1)]))
        self.assertEqual(kinds(merged), ["connected", "roamed", "connected"])

    def test_measured_beats_inferred(self):
        t = NOW - 7200
        inferred = tl.from_presence([tl.event("disconnected", t + 30, AP1, "5", duration_s=600, mac=M1)])
        merged, _ = tl.merge(inferred + tl.from_unifi([unifi(t, "disconnected")], APS))
        self.assertEqual(len(merged), 1)
        self.assertEqual((merged[0]["basis"], merged[0]["source"]), ("measured", "unifi_syslog"))
        self.assertEqual(merged[0]["duration_s"], 600)                 # what the measured one lacked
        # an inferred disconnect covered by an accounting Stop is dropped (its source noted)
        merged, _ = tl.merge(inferred + tl.from_acct([acct(t - 3600, t, cause="User-Request")], APS))
        self.assertEqual(kinds(merged), ["connected", "session_ended"])
        self.assertEqual(merged[1]["detail"]["cause"], "User-Request")
        self.assertIn("prometheus", merged[1]["sources"])

    def test_accounting_stop_causes_and_roams(self):
        t = NOW - 7200
        sessions = [acct(t, t + 600, cause="Lost-Carrier", sid="a"),
                    acct(t + 630, t + 1200, bssid="68:d7:9a:1d:61:46", cause="User-Request", sid="b"),
                    acct(t + 1260, t + 2000, bssid="68:d7:9a:1d:61:46", cause="Idle-Timeout", sid="c"),
                    acct(t + 5000, t + 6000, cause="NAS-Reboot", sid="d")]
        events = tl.from_acct(sessions, APS)
        self.assertEqual(kinds(events), ["connected", "roamed", "reconnected", "session_ended", "connected",
                                         "session_ended"])
        roam = events[1]
        self.assertEqual((roam["ap"], roam["from_ap"], roam["detail"]["from_cause"]), (AP2, AP1, "Lost-Carrier"))
        self.assertEqual(events[2]["detail"]["gap_s"], 60)
        self.assertEqual(events[3]["detail"]["cause"], "Idle-Timeout")
        self.assertEqual((events[3]["detail"]["rx_bytes"], events[3]["detail"]["tx_bytes"]), (9000, 1000))
        self.assertEqual(events[5]["detail"]["cause"], "NAS-Reboot")
        self.assertEqual(tl.disconnects(events), [
            {"at": t + 1260, "basis": "measured", "source": "radius_acct", "cause": "User-Request"},
            {"at": t + 2000, "basis": "measured", "source": "radius_acct", "cause": "Idle-Timeout"},
            {"at": t + 6000, "basis": "measured", "source": "radius_acct", "cause": "NAS-Reboot"}])

    def test_a_unifi_roam_between_radios_is_a_band_change(self):
        events = tl.from_unifi([unifi(NOW - 60, "roamed", from_ap=AP1, from_ap_mac=AP1_MAC, radio="ng")], APS)
        self.assertEqual((events[0]["kind"], events[0]["band"]), ("band_changed", "2.4"))

    def test_a_disconnect_and_a_connection_close_together_are_a_reconnect(self):
        t = NOW - 600
        merged, _ = tl.merge(tl.from_unifi([unifi(t, "disconnected"), unifi(t + 40, "connected", ap=AP2,
                                                                             ap_mac=AP2_MAC, mac=M2)], APS))
        self.assertEqual(kinds(merged), ["reconnected"])
        r = merged[0]
        self.assertEqual((r["from_ap"], r["ap"], r["detail"]["gap_s"], r["detail"]["from_mac"]), (AP1, AP2, 40, M1))
        self.assertEqual(r["basis"], "measured")

    def test_authentication_and_rejects(self):
        rows = [{"at": dt(NOW - 100), "result": "accept", "reason": "ok", "mac": M1, "bssid": "60:22:32:38:48:00",
                 "ssid": SSID, "nas_ip": "10.0.10.27"},
                {"at": dt(NOW - 50), "result": "reject", "reason": "expired", "mac": M1, "bssid": None, "ssid": SSID,
                 "nas_ip": "10.0.10.27"}]
        events = tl.from_auth(rows, APS)
        self.assertEqual(kinds(events), ["authenticated", "auth_rejected"])
        self.assertEqual((events[0]["ap"], events[0]["ap_mac"], events[0]["band"]), (AP1, AP1_MAC, "5"))
        self.assertEqual(events[1]["ap"], AP1)                           # from the NAS when no BSSID
        self.assertEqual(events[1]["detail"]["reason"], "expired")

    def test_mac_changes(self):
        identity = ident.Identity("a", [], [], False, NOW)
        identity.windows = [_w(M1, NOW - 5 * 86400, NOW - 4 * 86400), _w(M2, NOW - 3 * 86400, NOW - 2 * 86400),
                            _w(M3, NOW - 3600, NOW)]
        events = tl.from_windows(identity, NOW - 4 * 86400, NOW)
        self.assertEqual([(e["kind"], e["mac"], e["detail"]["from_mac"], e["basis"]) for e in events],
                         [("mac_changed", M2, M1, "inferred"), ("mac_changed", M3, M2, "inferred")])

    def test_bounded_sorted_and_flagged(self):
        events = tl.from_unifi([unifi(NOW - 10000 + i * 300, "connected" if i % 2 else "roamed", from_ap=AP2,
                                      from_ap_mac=AP2_MAC) for i in range(30)][::-1], APS)
        merged, truncated = tl.merge(events, limit=10)
        self.assertTrue(truncated)
        self.assertEqual(len(merged), 10)
        self.assertEqual([e["at"] for e in merged], sorted(e["at"] for e in merged))
        self.assertEqual(merged[-1]["at"], NOW - 10000 + 29 * 300)          # the latest kept

    def test_conflicts_withhold_mac_events_from_residents_and_mark_them_for_admins(self):
        conflicts = [{"mac": M1, "other_owners": 2, "from": NOW - 7200, "to": NOW - 3600}]
        events = (tl.from_unifi([unifi(NOW - 5000, "connected"), unifi(NOW - 100, "disconnected")], APS)
                  + tl.from_auth([{"at": dt(NOW - 5000), "result": "accept", "reason": "ok", "mac": M1,
                                   "match": "device"}])
                  + tl.from_acct([acct(NOW - 4000, link="mac_window"), acct(NOW - 4100, link="class", sid="x")], APS))
        resident = tl.restrict(events, ident.Identity("a", [], conflicts, False, NOW))
        self.assertEqual(sorted((e["kind"], e["source"]) for e in resident),
                         [("authenticated", "radius_auth"), ("connected", "radius_acct"), ("disconnected", "unifi_syslog")])
        admin = tl.restrict(events, ident.Identity("a", [], conflicts, True, NOW))
        self.assertEqual(len(admin), len(events))
        self.assertEqual(admin[0]["detail"]["conflict"], 2)

    def test_a_reject_found_by_the_mac_alone_is_withheld_in_a_conflict(self):
        """A reject without a certificate (match "mac") is whoever sent the MAC: during a conflict
        it may be the other owner's, so a resident does not see it; one of the device's own
        certificate (match "device") stays. Admins see both, marked."""
        conflicts = [{"mac": M1, "other_owners": 1, "from": NOW - 7200, "to": NOW - 3600}]
        rows = [{"at": dt(NOW - 5000), "result": "reject", "reason": "no_cert", "mac": M1, "match": "mac", "count": 7,
                 "last_at": dt(NOW - 4900)},
                {"at": dt(NOW - 4800), "result": "reject", "reason": "revoked", "mac": M1, "match": "device"},
                {"at": dt(NOW - 600), "result": "reject", "reason": "no_cert", "mac": M1, "match": "mac"}]
        events = tl.from_auth(rows)
        self.assertEqual([(e["detail"]["match"], e["detail"]["count"]) for e in events],
                         [("mac", 7), ("device", 1), ("mac", 1)])
        self.assertEqual(events[0]["detail"]["last_at"], telemetry.iso(NOW - 4900))
        self.assertNotIn("last_at", events[1]["detail"])
        resident = tl.restrict(events, ident.Identity("a", [], conflicts, False, NOW))
        self.assertEqual([e["detail"]["reason"] for e in resident], ["revoked", "no_cert"])   # outside: kept
        admin = tl.restrict(events, ident.Identity("a", [], conflicts, True, NOW))
        self.assertEqual([e["detail"].get("conflict") for e in admin], [1, 1, None])
        # a row without match (an older caller) is not taken as the device's own
        bare = tl.from_auth([{"at": dt(NOW - 5000), "result": "accept", "reason": "ok", "mac": M1}])
        self.assertEqual(tl.restrict(bare, ident.Identity("a", [], conflicts, False, NOW)), [])

    def test_public_shape(self):
        e = tl.public(tl.from_unifi([unifi(NOW - 60, "connected")], APS))[0]
        self.assertEqual(set(e), {"kind", "at", "source", "sources", "basis", "ap", "band", "from_ap", "from_band",
                                  "mac", "duration_s", "detail"})
        self.assertEqual(e["ap"], {"name": AP1, "house": "scharni", "floor": 2, "spot": "corner", "mac": AP1_MAC})
        self.assertEqual(e["at"], telemetry.iso(NOW - 60))


def _w(mac, first, last):
    return {"mac": mac, "start": first, "end": last, "first_seen": first, "last_seen": last, "randomized": True,
            "auth_count": 1, "current": False}


class IncidentTests(unittest.TestCase):
    def test_relevant_incidents(self):
        rows = [{"id": 1, "kind": "internet_down", "subject": "", "subject_name": None},
                {"id": 2, "kind": "ap_restarted", "subject": AP1_MAC, "subject_name": AP1},
                {"id": 3, "kind": "ap_down", "subject": AP2_MAC, "subject_name": AP2},
                {"id": 4, "kind": "ap_down", "subject": "aa:aa:aa:aa:aa:aa", "subject_name": AP2},
                {"id": 5, "kind": "switch_port_down", "subject": "sw1:3", "detail": {"ap_macs": [AP1_MAC]}}]
        self.assertEqual([r["id"] for r in telemetry.relevant_incidents(rows, {AP1_MAC}, set())], [1, 2, 5])
        self.assertEqual([r["id"] for r in telemetry.relevant_incidents(rows, set(), {AP2.lower()})], [1, 3, 4])


class HistoryCase(unittest.TestCase):
    """A device with two (rotating) MACs: M1 until 12 h ago, M2 since 10 h ago; the fake
    Prometheus has data for both MACs for the whole day (M1's after its window is someone
    else's, M2's before its window was nobody's)."""

    def setUp(self):
        self.windows = [window(M1, NOW - 30 * 86400, END - 12 * 3600 - ident.WINDOW_GRACE_S, randomized=True),
                        window(M2, END - 10 * 3600, NOW - 60, randomized=True)]
        self.fake = FakeRegistry(windows={"a": self.windows}).patch(self)

    def prometheus(self, extra=()):
        start = END - 86400
        grid = list(range(start - 300 + 60, END + 1, 60))
        ages = [(t, 30) for t in grid]
        chart = lambda v: [(t, v) for t in range(start, END + 1, 300)]  # noqa: E731
        return list(extra) + [
            ('max(unpoller_prometheus_cache_age_seconds{job="unifi"})[', matrix(({}, ages),)),
            ("max by (mac, ap_name, radio) (timestamp(", matrix(
                ({"mac": M1, "ap_name": AP1, "radio": "na"}, [(t, start - 3600) for t in grid]),
                ({"mac": M2, "ap_name": AP2, "radio": "na"}, [(t, start - 7200) for t in grid]))),
            ("unpoller_client_radio_signal_db", matrix(({"mac": M1}, chart(-50)), ({"mac": M2}, chart(-70)))),
            ("rate(unpoller_client_transmit_bytes_total", matrix(({"mac": M1}, chart(1000)), ({"mac": M2}, chart(2000)))),
        ]

    def history(self, range_key="24h", admin=False, extra=(), client_=True, **kw):
        prom, session = client(self.prometheus(extra))
        h = telemetry.history(prom if client_ else None, None, range_key, now=NOW, db=object(),
                              row=row("a", created=NOW - 400 * 86400), admin=admin, **kw)
        return h, session


class StitchingTests(HistoryCase):
    def test_one_by_mac_query_per_chart_for_both_macs(self):
        h, session = self.history()
        sel = 'mac=~"%s|%s"' % (M1, M2)
        ranges = [p for u, p in session.calls if u.endswith("query_range")]
        self.assertEqual(len(ranges), len(telemetry.CHARTS))
        for p in ranges:
            self.assertIn(sel, p["query"])
            self.assertIn("by (mac)", p["query"])
        for q in session.queries("unpoller_client_"):
            self.assertIn('essid="Example"', q)

    def test_each_macs_data_only_in_its_window(self):
        h, _ = self.history()
        signal = dict(h["series"]["signal_dbm"])
        self.assertEqual(signal[END - 13 * 3600], -50)                      # M1's time
        self.assertIsNone(signal[END - 11 * 3600])                          # between the windows: nobody's
        self.assertEqual(signal[END - 3600], -70)                           # M2's time
        self.assertEqual(dict(h["series"]["rx_bps"])[END - 3600], 2000 * 8 // 8 * 1)   # not summed with M1
        self.assertIsNone(dict(h["series"]["online"])[END - 11 * 3600])
        self.assertEqual(dict(h["series"]["online"])[END - 3600], 1)
        self.assertEqual(h["data_from"], NOW - 30 * 86400)
        timeline = [(e["kind"], e["mac"]) for e in h["timeline"]]
        self.assertIn(("mac_changed", M2), timeline)
        self.assertEqual([e["source"] for e in h["timeline"] if e["kind"] == "mac_changed"], ["device_mac"])
        self.assertTrue(all(e["mac"] in (M1, M2, None) for e in h["timeline"]))

    def test_a_recycled_mac_before_its_owners_window_is_not_shown(self):
        # M2 belonged to someone else until 10 h ago: the history reads only from its window
        h, _ = self.history()
        self.assertTrue(all(v in (None, -50) for t, v in h["series"]["signal_dbm"] if t < END - 10 * 3600 - 300))

    def test_withheld_spans_for_residents_marked_for_admins(self):
        self.fake.conflicts = {"a": [{"mac": M2, "other_owners": 1, "from": dt(END - 4 * 3600), "to": dt(END - 2 * 3600)}]}
        h, _ = self.history()
        self.assertIsNone(dict(h["series"]["signal_dbm"])[END - 3 * 3600])
        self.assertEqual(dict(h["series"]["signal_dbm"])[END - 3600], -70)
        self.assertEqual(h["withheld_spans"], [{"mac": M2, "from": telemetry.iso(END - 4 * 3600),
                                                "to": telemetry.iso(END - 2 * 3600)}])
        self.assertEqual(h["conflicts"], [])
        h, _ = self.history(admin=True)
        self.assertEqual(dict(h["series"]["signal_dbm"])[END - 3 * 3600], -70)
        self.assertEqual(h["conflicts"][0]["other_owners"], 1)

    def test_all_withheld_asks_nothing(self):
        self.fake.windows = {"a": [window(M2, NOW - 86400, NOW - 60)]}
        self.fake.conflicts = {"a": [{"mac": M2, "other_owners": 1, "from": dt(NOW - 2 * 86400), "to": None}]}
        h, session = self.history()
        self.assertEqual(h["withheld"], "mac_conflict")
        self.assertEqual((h["timeline"], session.calls), ([], []))
        self.assertTrue(all(v == [] for v in h["series"].values()))

    def test_registry_events_and_incidents_join_the_timeline(self):
        self.fake.events = {"a": [unifi(END - 1800, "disconnected", ap=AP2, ap_mac=AP2_MAC, mac=M2)]}
        self.fake.incident_rows = [
            {"id": 7, "kind": "ap_restarted", "subject": AP2_MAC, "subject_name": AP2, "started": dt(END - 1850),
             "ended": dt(END - 1700), "basis": "measured", "detail": {}},
            {"id": 8, "kind": "ap_restarted", "subject": "aa:aa:aa:aa:aa:aa", "subject_name": "ap-x-1-y",
             "started": dt(END - 1850), "ended": dt(END - 1700), "basis": "measured", "detail": {}}]
        h, _ = self.history()
        incidents = [e for e in h["timeline"] if e["kind"] == "incident"]
        self.assertEqual([e["detail"]["id"] for e in incidents], [7])
        self.assertIn("unifi_syslog", h["sources"])
        self.assertIn("incident", h["sources"])
        self.assertEqual(len(self.fake.called("auth_events")), 1)
        self.assertEqual(self.fake.called("connection_events")[0][4], 2000)          # bounded

    def test_logins_are_placed_at_their_ap_by_bssid(self):
        self.fake.auth = {"a": [{"at": dt(END - 600), "result": "accept", "reason": "ok", "mac": M2,
                                 "bssid": "68:d7:9a:1d:61:46", "ssid": SSID, "nas_ip": "10.0.10.47"}]}
        vaps = ("max by (bssid, mac, name, radio) (unpoller_device_vap_transmit_power",
                vector(({"bssid": "68:d7:9a:1d:61:46", "mac": AP2_MAC, "name": AP2, "radio": "na"}, 17),))
        h, _ = self.history(extra=[vaps])
        login = [e for e in h["timeline"] if e["kind"] == "authenticated"][0]
        self.assertEqual((login["ap"]["name"], login["ap"]["mac"], login["band"]), (AP2, AP2_MAC, "5"))
        self.assertEqual(login["detail"]["bssid"], "68:d7:9a:1d:61:46")

    def test_prometheus_down_keeps_the_registrys_events(self):
        import requests
        self.fake.events = {"a": [unifi(END - 1800, "connected", mac=M2)]}
        prom, session = client(fail=requests.ConnectionError("refused"))
        h = telemetry.history(prom, None, "24h", now=NOW, db=object(), row=row("a"))
        self.assertEqual(h["telemetry"], "unavailable")
        self.assertEqual([e["kind"] for e in h["timeline"]], ["mac_changed", "connected"])

    def test_90_days(self):
        h, session = self.history("90d")
        self.assertEqual((h["step_s"], h["step"], len(h["series"]["online"])), (21600, None, 361))
        self.assertTrue(all(p["step"] == "21600" for u, p in session.calls if u.endswith("query_range")))


class DayRangeTests(HistoryCase):
    def days(self):
        tz = telemetry.zone("Europe/Berlin")
        today = datetime.datetime.fromtimestamp(END, tz).date()
        return tz, today, [
            {"day": today - datetime.timedelta(days=1), "online_s": 43200, "stale_s": 0, "signal_avg_dbm": -61.26,
             "signal_p10_dbm": -70.04,
             "snr_avg_db": 35.0, "health_avg": 90.0, "retry_ratio_avg": 0.031, "rx_bytes": 8_640_000_000,
             "tx_bytes": 864_000_000, "link_rx_avg_bps": 400e6},
            {"day": today - datetime.timedelta(days=3), "online_s": 3600, "stale_s": 82800, "signal_avg_dbm": -70.0,
             "snr_avg_db": None, "health_avg": None, "retry_ratio_avg": None, "rx_bytes": None, "tx_bytes": None,
             "link_rx_avg_bps": None}]

    def test_a_year_from_the_rollups(self):
        tz, today, days = self.days()
        self.fake.days = {"a": days}
        h, session = self.history("1y", tz=tz)
        self.assertEqual((h["range"], h["step"], h["step_s"]), ("1y", "day", 86400))
        self.assertEqual([u for u, p in session.calls if u.endswith("query_range")], [])     # no Prometheus charts
        self.assertEqual(len(h["series"]["online"]), 365)
        t_yesterday = int(datetime.datetime.combine(today - datetime.timedelta(days=1), datetime.time(), tz).timestamp())
        signal, online, rx = (dict(h["series"][k]) for k in ("signal_dbm", "online", "rx_bps"))
        self.assertEqual(signal[t_yesterday], -61.3)
        self.assertEqual(dict(h["series"]["signal_p10_dbm"])[t_yesterday], -70.0)
        self.assertIsNone(h["timeline_days"])                             # a year: all of it
        self.assertEqual(online[t_yesterday], 0.5)
        self.assertEqual(rx[t_yesterday], 800_000)                        # 8.64 GB a day: 0.8 Mbit/s
        t3 = int(datetime.datetime.combine(today - datetime.timedelta(days=3), datetime.time(), tz).timestamp())
        self.assertEqual(online[t3], 1.0)                                 # an hour of the hour with fresh data
        self.assertIsNone(signal[t3 - 86400])
        self.assertEqual(h["start"], h["series"]["online"][0][0])
        self.assertIn("device_day", h["sources"])
        self.assertEqual(self.fake.called("device_days")[0][2], today - datetime.timedelta(days=364))

    def test_all_since_the_first_window(self):
        tz, today, days = self.days()
        self.fake.days = {"a": days}
        h, _ = self.history("all", tz=tz)
        self.assertEqual(len(h["series"]["online"]), 31)                 # the first window is 30 days old

    def test_timeline_days(self):
        self.fake.windows = {"a": [window(M1, NOW - 600 * 86400, NOW - 60)]}
        h, _ = self.history("all")
        # enrolled 400 days ago (HistoryCase): 401 day points, the events of 400 days
        self.assertEqual((len(h["series"]["online"]), h["timeline_days"]), (401, 400))
        h, _ = self.history("24h")
        self.assertIsNone(h["timeline_days"])
        self.assertNotIn("signal_p10_dbm", h["series"])
        # cut to the newest events: from the oldest one kept
        self.fake.events = {"a": [unifi(NOW - 100 * 86400 + i * 3600, "connected" if i % 2 else "disconnected", mac=M1)
                                  for i in range(2100)]}
        h, _ = self.history("1y")
        self.assertTrue(h["timeline_truncated"])
        self.assertLess(h["timeline_days"], 100)

    def test_a_resident_sees_no_day_with_a_conflict(self):
        tz, today, days = self.days()
        self.fake.days = {"a": days}
        t0 = datetime.datetime.combine(today - datetime.timedelta(days=1), datetime.time(), tz).timestamp()
        self.fake.conflicts = {"a": [{"mac": M2, "other_owners": 1, "from": dt(t0 + 3600), "to": dt(t0 + 7200)}]}
        h, _ = self.history("1y", tz=tz)
        self.assertIsNone(dict(h["series"]["signal_dbm"])[int(t0)])
        h, _ = self.history("1y", tz=tz, admin=True)
        self.assertEqual(dict(h["series"]["signal_dbm"])[int(t0)], -61.3)


class DashboardV2Tests(unittest.TestCase):
    """telemetry.dashboard with the registry (db): DEVICE's additions and the new findings."""
    MAC = "02:00:00:00:00:0a"                       # live({MAC_A}) of test_telemetry

    def setUp(self):
        self.fake = FakeRegistry(windows={"a": [window(self.MAC, NOW - 20 * 86400, NOW - 600)]}).patch(self)

    def dashboard(self, handlers=None, rows=None, admin=False, **kw):
        prom, session = client(handlers if handlers is not None else live({self.MAC}))
        payload = telemetry.dashboard(prom, rows or [row("a", last_seen=dt(NOW - 600))], now=NOW, db=object(),
                                      admin=admin, **kw)
        return payload["devices"][0], session

    def test_device_additions(self):
        d, _ = self.dashboard()
        self.assertEqual((d["state"], d["mac"], d["mac_mode"]), ("online", self.MAC, "random_fixed"))
        self.assertEqual(d["macs"], [{"mac": self.MAC, "randomized": True, "first_seen": telemetry.iso(NOW - 20 * 86400),
                                      "last_seen": telemetry.iso(NOW - 600), "current": True}])
        self.assertEqual(d["last_auth"], {"at": telemetry.iso(NOW - 600), "result": "accept", "reason": "ok"})
        self.assertEqual(d["facts"]["signal_dbm"], {"value": -58, "source": "prometheus", "basis": "measured"})
        self.assertEqual(d["facts"]["last_auth"]["source"], "radius_auth")
        self.assertEqual(d["sources"], ["prometheus", "radius_auth", "registry"])
        self.assertIs(d["findings"], d["diagnostics"])
        self.assertEqual(d["data_from"], telemetry.iso(NOW - 20 * 86400))
        self.assertNotIn("conflicts", d)
        self.assertEqual(len(self.fake.called("device_windows")), 1)
        self.assertEqual(len(self.fake.called("auth_failures")), 1)            # one for the page

    def test_auth_failures_by_certificate_or_mac(self):
        self.fake.failures = [{"at": dt(NOW - 300 + i), "reason": "expired", "serial": "ab", "device_id": "a",
                               "owner": "sub-resident", "mac": None, "bssid": None, "ssid": SSID, "nas_ip": None}
                              for i in range(2)]
        self.fake.failures.append({"at": dt(NOW - 200), "reason": "no_cert", "serial": None, "device_id": None,
                                   "owner": None, "mac": self.MAC, "bssid": None, "ssid": SSID, "nas_ip": None})
        self.fake.failures.append({"at": dt(NOW - 100), "reason": "no_cert", "serial": None, "device_id": None,
                                   "owner": None, "mac": "02:00:00:00:00:99", "bssid": None, "ssid": SSID, "nas_ip": None})
        d, _ = self.dashboard()
        f = [f for f in d["diagnostics"] if f["code"] == "auth_failures"][0]
        self.assertEqual((f["severity"], f["basis"], f["params"]["count"]), ("warn", "measured", 3))
        self.assertEqual(f["evidence"]["reasons"], {"expired": 2, "no_cert": 1})
        self.assertTrue(f["evidence"]["locked_out"])                       # rejected after the last login
        self.assertEqual(d["last_auth"], {"at": telemetry.iso(NOW - 200), "result": "reject", "reason": "no_cert"})

    def test_rejects_of_another_certificate_are_not_this_devices(self):
        """A reject logged with another device (its revoked certificate) is that device's even
        when it came from this device's MAC inside its window; repeats count as their tries."""
        self.fake.failures = [{"at": dt(NOW - 300), "reason": "revoked", "serial": "cd", "device_id": "other",
                               "owner": "sub-other", "mac": self.MAC, "bssid": None, "ssid": SSID, "nas_ip": None,
                               "count": 40, "last_at": dt(NOW - 100)},
                              {"at": dt(NOW - 900), "reason": "no_cert", "serial": None, "device_id": None,
                               "owner": None, "mac": self.MAC, "bssid": None, "ssid": SSID, "nas_ip": None,
                               "count": 4, "last_at": dt(NOW - 120)}]
        d, _ = self.dashboard()
        f = [f for f in d["diagnostics"] if f["code"] == "auth_failures"][0]
        self.assertEqual((f["params"]["count"], f["evidence"]["reasons"]), (4, {"no_cert": 4}))
        self.assertEqual(f["evidence"]["last_at"], telemetry.iso(NOW - 120))
        # the latest try of the repeats is after the last login (NOW - 600)
        self.assertEqual(d["last_auth"], {"at": telemetry.iso(NOW - 120), "result": "reject", "reason": "no_cert"})

    def test_incident_correlated_with_a_reconnect(self):
        self.fake.incident_rows = [{"id": 3, "kind": "ap_restarted", "subject": AP1_MAC, "subject_name": AP1,
                                    "started": dt(NOW - 3550), "ended": dt(NOW - 3200), "basis": "measured",
                                    "detail": {}}]
        d, _ = self.dashboard()                                            # reconnect at NOW-3600 (live())
        f = [f for f in d["diagnostics"] if f["code"] == "incident_correlated"][0]
        self.assertEqual((f["basis"], f["evidence"]["incident"]["id"]), ("inferred", 3))
        self.assertEqual(f["evidence"]["disconnects"], [telemetry.iso(NOW - 3600)])

    def test_ap_overloaded(self):
        handlers = [("sum by (name) (unpoller_device_stations", vector(({"name": AP1}, 41),)),
                    ("unpoller_device_radio_channel_utilization_total_ratio",
                     vector(({"name": AP1, "radio": "na"}, 0.5),))] + live({self.MAC})
        d, _ = self.dashboard(handlers)
        f = [f for f in d["diagnostics"] if f["code"] == "ap_overloaded"][0]
        self.assertEqual((f["severity"], f["evidence"]["clients"], f["evidence"]["channel_util"]), ("bad", 41, 0.5))

    def test_poor_coverage_needs_a_whole_day(self):
        handlers = [("avg by (mac, ap_name) (avg_over_time", vector(({"mac": self.MAC, "ap_name": AP1}, -79),
                                                                    ({"mac": self.MAC, "ap_name": AP2}, -74))),
                    ("sum by (mac, ap_name) (count_over_time", vector(({"mac": self.MAC, "ap_name": AP1}, 600),
                                                                      ({"mac": self.MAC, "ap_name": AP2}, 120)))]
        d, _ = self.dashboard(handlers + live({self.MAC}))
        f = [f for f in d["diagnostics"] if f["code"] == "poor_coverage"][0]
        self.assertEqual((f["severity"], f["params"]["best_signal_dbm"]), ("warn", -74))
        self.fake.windows = {"a": [window(self.MAC, NOW - 3600, NOW - 600)]}       # not a whole day its own
        d, session = self.dashboard(handlers + live({self.MAC}))
        self.assertNotIn("poor_coverage", [f["code"] for f in d["diagnostics"]])
        self.assertEqual(session.queries("count_over_time"), [])

    def test_conflict_now_withholds_for_residents(self):
        self.fake.conflicts = {"a": [{"mac": self.MAC, "other_owners": 1, "from": dt(NOW - 3600), "to": None}]}
        d, session = self.dashboard()
        self.assertEqual((d["state"], [f["code"] for f in d["diagnostics"]]), ("unknown", ["mac_conflict"]))
        self.assertTrue(all(self.MAC not in q for q in session.queries()))
        self.assertEqual(d["facts"].get("signal_dbm"), None)
        d, _ = self.dashboard(admin=True)
        self.assertEqual((d["state"], d["diagnostics"][0]["params"]), ("online", {"owners": 1}))
        self.assertEqual(d["conflicts"][0]["other_owners"], 1)

    def test_an_ended_window_asks_when_it_was_last_there_inside_it(self):
        self.fake.windows = {"a": [window(self.MAC, NOW - 20 * 86400, NOW - 3 * 86400)]}
        handlers = [("max by (mac) (max_over_time(timestamp(", vector(({"mac": self.MAC}, NOW - 3 * 86400 + 3600),))]
        d, session = self.dashboard(handlers + HOUSE_OK, rows=[row("a", last_seen=dt(NOW - 3 * 86400))])
        self.assertEqual((d["state"], d["last_seen"]), ("offline", telemetry.iso(NOW - 3 * 86400 + 3600)))
        asked = [p for _u, p in session.calls if "max_over_time(timestamp(" in p["query"]]
        self.assertEqual(asked[0]["time"], "%d" % (NOW - 3 * 86400 + ident.CURRENT_WINDOW_S))   # at the window's end

    def test_detail_reads_a_day_of_events(self):
        self.fake.events = {"a": [unifi(NOW - 1000 + i * 60, "roamed", ap=AP2 if i % 2 else AP1,
                                        ap_mac=AP2_MAC if i % 2 else AP1_MAC, from_ap=AP1 if i % 2 else AP2,
                                        from_ap_mac=AP1_MAC if i % 2 else AP2_MAC, mac=self.MAC) for i in range(8)]}
        d, _ = self.dashboard(detail=True)
        f = [f for f in d["diagnostics"] if f["code"] == "unstable_roaming"][0]
        self.assertEqual((f["basis"], f["params"]["roams_1h"]), ("measured", 8))
        self.assertIn("unifi_syslog", d["sources"])


if __name__ == "__main__":
    unittest.main()
