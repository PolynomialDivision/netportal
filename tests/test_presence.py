"""Device presence (netportal/presence.py): the one decision over Prometheus, RADIUS accounting,
logins, UniFi events and incidents; the dashboard's DEVICE.presence, state, last_seen and the
offline finding built on it; the device API's ETag and poll hint. Registry and Prometheus faked.
Example MACs, addresses and times only."""

import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_dashboard_api import MINE, DashboardApiCase  # noqa: E402
from test_telemetry import MAC_A, client, live, vector  # noqa: E402
from test_web import ADMIN_SUB, RESIDENT_SUB  # noqa: E402
from test_telemetry_registry import NOW, FakeRegistry, dt, row, window  # noqa: E402

from netportal import presence, telemetry, web  # noqa: E402
from netportal.telemetry import timeline as tl  # noqa: E402

AP1_MAC, AP2_MAC = "60:22:32:37:48:00", "68:d7:9a:1c:61:46"
NAS1, NAS2 = "10.0.10.27", "10.0.10.28"
TS = NOW - 60                                   # the snapshot's time in most cases


def assoc(present, at=TS, fresh=True, start=None, last_seen=None):
    return {"present": present, "at": at, "fresh": fresh, "start": start, "last_seen": last_seen}


def sess(started, updated=None, stopped=None, sid="s1", nas=NAS1, ap_mac=AP1_MAC, cause=None, interim=None,
         nas_interim=None, link="class", mac=MAC_A):
    return {"nas_ip": nas, "acct_session_id": sid, "link": link, "mac": mac, "ap_name": None, "ap_mac": ap_mac,
            "started": started, "updated": updated if updated is not None else (stopped or started),
            "stopped": stopped, "cause": cause, "interim_s": interim, "nas_interim_s": nas_interim}


def decide(**kw):
    return presence.decide(NOW, **kw)


class DecisionTests(unittest.TestCase):
    def test_a_fresh_login_is_connecting_then_its_start_makes_it_online(self):
        # the login 10 s ago; the snapshot (40 s old) does not show the device yet
        p = decide(assoc=assoc(False, at=NOW - 40), accept=NOW - 10)
        self.assertEqual((p["state"], p["confirmed_by"], p["reason"], p["since"], p["poll_s"]),
                         ("connecting", "radius_auth", "accept_pending", NOW - 10, 5))
        # also when the snapshot is a little newer than the login (the controller lists it late)
        self.assertEqual(decide(assoc=assoc(False, at=NOW - 20), accept=NOW - 50)["state"], "connecting")
        # the accounting Start: online at once, from RADIUS, before Prometheus sees it
        p = decide(assoc=assoc(False, at=NOW - 40), accept=NOW - 10, sessions=[sess(NOW - 5)])
        self.assertEqual((p["state"], p["confirmed_by"], p["reason"], p["since"], p["confirmed_at"], p["poll_s"]),
                         ("online", "radius_acct", "acct_start", NOW - 5, NOW - 5, 5))
        self.assertEqual(p["session"]["acct_session_id"], "s1")
        # later the snapshot shows it: the association's start, the slow poll
        later = presence.decide(NOW + 300, assoc=assoc(True, at=NOW + 250, start=NOW - 6), accept=NOW - 10,
                                sessions=[sess(NOW - 5, updated=NOW + 115, interim=120)])
        self.assertEqual((later["state"], later["confirmed_by"], later["since"], later["poll_s"]),
                         ("online", "prometheus", NOW - 6, 30))

    def test_a_login_without_a_start_falls_through_after_a_minute(self):
        p = decide(assoc=assoc(False, at=NOW - 20), accept=NOW - 70)
        self.assertEqual((p["state"], p["confirmed_by"], p["reason"]), ("offline", "prometheus", "association_gone"))
        self.assertEqual(p["last_seen"], NOW - 70)
        # without Prometheus: not known (never offline on missing evidence)
        self.assertEqual(decide(accept=NOW - 70)["state"], "unknown")

    def test_a_login_after_a_stop_is_connecting(self):
        # the AP's Accounting-On ended the session a moment before the device logged in again
        p = decide(sessions=[sess(NOW - 900, stopped=NOW - 10.2, cause="NAS-Reboot")], accept=NOW - 10)
        self.assertEqual((p["state"], p["reason"]), ("connecting", "accept_pending"))
        # ... also when that session had only just started (a Start within the clock skew)
        p = decide(sessions=[sess(NOW - 10.6, stopped=NOW - 10.2, cause="NAS-Reboot")], accept=NOW - 10)
        self.assertEqual(p["state"], "connecting")
        # a Start a moment before the login (the AP's clock behind) is the login's
        self.assertEqual(decide(sessions=[sess(NOW - 12)], accept=NOW - 10)["state"], "online")
        # a Stop after the login (the association failed or ended): offline
        p = decide(sessions=[sess(NOW - 900, stopped=NOW - 5)], accept=NOW - 10)
        self.assertEqual((p["state"], p["reason"]), ("offline", "acct_stop"))

    def test_whole_second_timestamps_do_not_reopen_connecting(self):
        # Event-Timestamps are whole seconds: the login's own session (Start and Stop read 0.6 s
        # "before" the login) ended, the device left: offline, not connecting again (E2E
        # against the house's Prometheus, 2026-10-25)
        p = decide(sessions=[sess(NOW - 10.6, stopped=NOW - 10.6)], accept=NOW - 10)
        self.assertEqual((p["state"], p["reason"]), ("offline", "acct_stop"))

    def test_a_reconnect_is_connecting_also_with_the_aps_clock_ahead(self):
        # the old session's Stop reads 3 s after the new login (the AP's clock ahead)
        p = decide(sessions=[sess(NOW - 900, stopped=NOW - 7)], accept=NOW - 10)
        self.assertEqual((p["state"], p["reason"]), ("connecting", "accept_pending"))

    def test_an_access_points_clock_a_little_ahead_still_polls_fast(self):
        p = decide(sessions=[sess(NOW - 900, stopped=NOW + 3)])
        self.assertEqual((p["state"], p["poll_s"]), ("offline", 5))

    def test_reauthentication_while_connected_is_not_connecting(self):
        # 12 h re-authentication: a login inside a running session, no new Start
        p = decide(assoc=assoc(True, start=NOW - 43000), accept=NOW - 5,
                   sessions=[sess(NOW - 43000, updated=NOW - 100, interim=120)])
        self.assertEqual(p["state"], "online")
        # nor without accounting, while the snapshot shows the device
        self.assertEqual(decide(assoc=assoc(True, start=NOW - 43000), accept=NOW - 5)["state"], "online")

    def test_the_stop_of_the_current_session_is_offline_at_once(self):
        p = decide(assoc=assoc(True, start=NOW - 3600),
                   sessions=[sess(NOW - 3600, stopped=NOW - 10, cause="User-Request")])
        self.assertEqual((p["state"], p["confirmed_by"], p["reason"], p["since"], p["last_seen"]),
                         ("offline", "radius_acct", "acct_stop", NOW - 10, NOW - 10))
        self.assertEqual((p["session"]["cause"], p["poll_s"]), ("User-Request", 5))
        # a Stop from long before the snapshot: the snapshot decides
        p = decide(assoc=assoc(True, start=NOW - 30), sessions=[sess(NOW - 3600, stopped=NOW - 600)])
        self.assertEqual((p["state"], p["confirmed_by"]), ("online", "prometheus"))

    def test_the_old_sessions_stop_after_a_roam_does_not_end_the_new_one(self):
        old = sess(NOW - 3600, updated=NOW - 100, stopped=NOW - 20, sid="old", nas=NAS1, cause="User-Request")
        new = sess(NOW - 30, sid="new", nas=NAS2, ap_mac=AP2_MAC)
        for snapshot in (assoc(True, at=NOW - 60, start=NOW - 3600), None, assoc(True, fresh=False)):
            p = decide(assoc=snapshot, sessions=[old, new])
            self.assertEqual((p["state"], p["session"]["acct_session_id"]), ("online", "new"), snapshot)
            self.assertEqual(p["since"], NOW - 3600)            # one stay across the roam
        # and once the snapshot has caught up, it says the same
        p = presence.decide(NOW + 120, assoc=assoc(True, at=NOW + 60, start=NOW - 3600), sessions=[old, new])
        self.assertEqual((p["state"], p["confirmed_by"], p["since"]), ("online", "prometheus", NOW - 3600))

    def test_a_disconnect_without_a_stop(self):
        # interval 300 (configured): alive for 660 s after the last update
        quiet = sess(NOW - 3000, updated=NOW - 600)
        self.assertEqual(decide(sessions=[quiet])["state"], "online")                    # Prometheus down
        self.assertEqual(decide(sessions=[quiet])["stale_after_s"], 660)
        gone = sess(NOW - 3000, updated=NOW - 700)
        p = decide(assoc=assoc(False, last_seen=NOW - 720), sessions=[gone])
        self.assertEqual((p["state"], p["confirmed_by"], p["reason"], p["since"]),
                         ("offline", "prometheus", "association_gone", NOW - 700))
        for snapshot in (None, assoc(True, fresh=False)):                             # down / frozen
            p = decide(assoc=snapshot, sessions=[gone])
            self.assertEqual((p["state"], p["reason"], p["confirmed_at"]), ("unknown", "session_stale", None), snapshot)
            self.assertEqual(p["session"]["acct_session_id"], "s1")

    def test_the_measured_interval_sets_the_staleness(self):
        s = sess(NOW - 3000, updated=NOW - 400, interim=120)
        p = decide(sessions=[s], interim_s=120)
        self.assertEqual((p["state"], p["stale_after_s"], p["session"]["interim_basis"]), ("unknown", 300, "measured"))
        # the NAS's measured interval for a session that has only its Start
        p = decide(sessions=[sess(NOW - 400, nas_interim=120)], interim_s=120)
        self.assertEqual((p["state"], p["stale_after_s"]), ("unknown", 300))
        # nothing measured: the configured interval
        p = decide(sessions=[sess(NOW - 400)], interim_s=300)
        self.assertEqual((p["state"], p["stale_after_s"], p["session"]["interim_basis"]), ("online", 660, "inferred"))
        p = decide(sessions=[sess(NOW - 400)], interim_s=120)
        self.assertEqual((p["state"], p["stale_after_s"]), ("unknown", 300))
        self.assertEqual(presence.public(decide(sessions=[s]))["session"]["interim_s"], 120)
        # a longer measured interval (the AP's own setting) counts
        p = decide(sessions=[sess(NOW - 3000, updated=NOW - 700, interim=400)], interim_s=120)
        self.assertEqual((p["state"], p["stale_after_s"]), ("online", 860))

    def test_a_distorted_measurement_is_clamped(self):
        # review 6: an outage's gap (1 h) as the NAS's interval would keep a gone device online
        # for two hours; at most 4 configured intervals count
        p = decide(sessions=[sess(NOW - 7200, updated=NOW - 1800, interim=3600)], interim_s=120)
        self.assertEqual((p["state"], p["reason"], p["stale_after_s"]), ("unknown", "session_stale", 1020))
        # one short extra Interim (40 s) does not make a fresh session stale before Prometheus lists it
        p = decide(assoc=assoc(False, at=NOW - 100), sessions=[sess(NOW - 150, nas_interim=40)])
        self.assertEqual((p["state"], p["stale_after_s"]), ("online", 660))
        p = decide(sessions=[sess(NOW - 200, nas_interim=40)])
        self.assertEqual(p["state"], "online")
        self.assertEqual([presence.interval(m, 120) for m in (None, 40, 120, 300, 480, 3600)],
                         [120, 120, 120, 300, 480, 480])

    def test_an_ap_outage(self):
        down = presence.ap_down([{"kind": "ap_down", "subject": AP1_MAC, "subject_name": "ap-scharni-2-corner",
                                  "started": dt(NOW - 200), "ended": None},
                                 {"kind": "ap_down", "subject": AP2_MAC, "started": dt(NOW - 900), "ended": dt(NOW - 800)}])
        self.assertEqual(down, {AP1_MAC: NOW - 200, "name:ap-scharni-2-corner": NOW - 200})
        on_it = sess(NOW - 3000, updated=NOW - 250)
        p = decide(sessions=[on_it], down=down)                                     # Prometheus down too
        self.assertEqual((p["state"], p["reason"], p["basis"], p["since"], p["last_seen"]),
                         ("offline", "ap_down", "inferred", NOW - 200, NOW - 250))
        self.assertIn({"source": "incident", "at": NOW - 200, "kind": "ap_down"}, p["evidence"])
        # an update after the outage began: the AP is not down for this session
        self.assertEqual(decide(sessions=[sess(NOW - 3000, updated=NOW - 100)], down=down)["state"], "online")
        # a session on another AP is not affected
        self.assertEqual(decide(sessions=[sess(NOW - 3000, updated=NOW - 250, ap_mac=AP2_MAC)], down=down)["state"],
                         "online")
        # the AP's own Accounting-Off closed the session (cause NAS-Request): offline, measured
        p = decide(assoc=assoc(True, start=NOW - 3000),
                   sessions=[sess(NOW - 3000, stopped=NOW - 100, cause="NAS-Request")])
        self.assertEqual((p["state"], p["reason"], p["basis"], p["confirmed_by"]),
                         ("offline", "ap_down", "measured", "radius_acct"))

    def test_an_ap_reboot_closing_a_long_abandoned_session(self):
        # review 1: the session went silent 3 days ago; the AP's Accounting-On closes it now
        old = sess(NOW - 3 * 86400, updated=NOW - 3 * 86400 + 600, stopped=NOW - 30, cause="NAS-Reboot")
        for snapshot in (assoc(False, NOW - 60), None):
            p = decide(assoc=snapshot, sessions=[old])
            self.assertEqual((p["state"], p["since"], p["last_seen"]),
                             ("offline", NOW - 3 * 86400 + 600, NOW - 3 * 86400 + 600), snapshot)
            self.assertEqual(p["poll_s"], 30)
        # a present snapshot is not overruled by that old close
        p = decide(assoc=assoc(True, NOW - 60, start=NOW - 3600), sessions=[old])
        self.assertEqual((p["state"], p["confirmed_by"]), ("online", "prometheus"))
        # a session the reboot ended while it was alive: offline at the reboot
        p = decide(sessions=[sess(NOW - 3000, updated=NOW - 100, stopped=NOW - 30, cause="NAS-Reboot")])
        self.assertEqual((p["state"], p["reason"], p["since"]), ("offline", "ap_down", NOW - 30))

    def test_a_roam_whose_old_stop_got_lost(self):
        # review 2: AP1's session is superseded by AP2's Start; AP2's Stop ends the stay
        ap1 = sess(NOW - 3000, updated=NOW - 420, sid="a1")
        ap2 = sess(NOW - 400, stopped=NOW - 100, sid="a2", nas=NAS2, ap_mac=AP2_MAC)
        for snapshot in (None, assoc(True, NOW - 150, start=NOW - 3000), assoc(True, fresh=False)):
            p = decide(assoc=snapshot, sessions=[ap1, ap2])
            self.assertEqual((p["state"], p["reason"], p["since"]), ("offline", "acct_stop", NOW - 100), snapshot)
        # while AP2's session runs, a late Interim of AP1 does not make AP1 the current session
        ap1_late = sess(NOW - 3000, updated=NOW - 390, sid="a1")
        ap2_open = sess(NOW - 400, updated=NOW - 280, sid="a2", nas=NAS2, ap_mac=AP2_MAC)
        p = decide(sessions=[ap1_late, ap2_open])
        self.assertEqual((p["state"], p["session"]["acct_session_id"]), ("online", "a2"))

    def test_a_gone_client_the_controller_still_lists(self):
        # review 3: the listing's association began before the Stop: it is the gone one
        s = sess(NOW - 3600, updated=NOW - 100, stopped=NOW - 100)
        for at in (NOW - 60, NOW - 20):
            p = decide(assoc=assoc(True, at, start=NOW - 3600), sessions=[s])
            self.assertEqual((p["state"], p["reason"], p["since"]), ("offline", "acct_stop", NOW - 100), at)
        # a new association after the Stop (no accounting for it): the listing wins
        p = decide(assoc=assoc(True, NOW - 20, start=NOW - 50), sessions=[s])
        self.assertEqual((p["state"], p["confirmed_by"]), ("online", "prometheus"))

    def test_absent_in_prometheus_while_interims_go_on_does_not_flap(self):
        # review 4: a stable state, a stable since, the slow poll
        seen = set()
        for t in range(0, 600, 60):
            now = NOW + t
            last = NOW + (t // 300) * 300
            p = presence.decide(now, assoc=assoc(False, now - 30), sessions=[sess(NOW - 3600, updated=last, interim=300)])
            seen.add((p["state"], p["reason"], p["since"], p["poll_s"]))
        self.assertEqual(seen, {("online", "sources_disagree", NOW - 3600, 30)})
        # a new session the snapshot cannot have seen yet is plain acct_start, measured
        p = decide(assoc=assoc(False, NOW - 60), sessions=[sess(NOW - 90)])
        self.assertEqual((p["state"], p["reason"], p["basis"]), ("online", "acct_start", "measured"))

    def test_a_reused_session_id(self):
        # review 9: updated long after its Stop (the SQL reopens it; older rows: presence too)
        p = decide(sessions=[sess(NOW - 1000, updated=NOW - 10, stopped=NOW - 500)])
        self.assertEqual((p["state"], p["session"]["stopped"]), ("online", None))

    def test_since_is_never_after_the_confirmation(self):
        # review 10: a login 61 s ago without a Start, an older absent snapshot
        p = decide(assoc=assoc(False, NOW - 100), accept=NOW - 61)
        self.assertEqual((p["state"], p["since"], p["confirmed_at"], p["basis"]),
                         ("offline", NOW - 61, NOW - 61, "inferred"))
        p = decide(assoc=assoc(False, NOW - 100), accept=NOW - 900)
        self.assertEqual((p["since"], p["confirmed_at"], p["basis"]), (NOW - 900, NOW - 100, "measured"))

    def test_duplicates_and_order_do_not_matter(self):
        sessions = [sess(NOW - 3600, updated=NOW - 100, stopped=NOW - 20, sid="old"),
                    sess(NOW - 30, sid="new", nas=NAS2, ap_mac=AP2_MAC),
                    sess(NOW - 7200, stopped=NOW - 3700, sid="older")]
        events = [{"at": NOW - 5000, "kind": "connected", "mac": MAC_A, "ap_mac": AP1_MAC, "ap_name": None},
                  {"at": NOW - 3700, "kind": "disconnected", "mac": MAC_A, "ap_mac": AP1_MAC, "ap_name": None}]
        first = decide(assoc=assoc(False), sessions=sessions, events=events, accept=NOW - 35)
        rng = random.Random(7)
        for _ in range(10):
            shuffled = sessions + [dict(rng.choice(sessions))]
            rng.shuffle(shuffled)
            again = decide(assoc=assoc(False), sessions=shuffled, events=list(reversed(events)) * 2, accept=NOW - 35)
            self.assertEqual({k: again[k] for k in ("state", "since", "confirmed_at", "reason")},
                             {k: first[k] for k in ("state", "since", "confirmed_at", "reason")})
            self.assertEqual(again["evidence"], first["evidence"])
        self.assertEqual(first["state"], "online")

    def test_conflicting_telemetry(self):
        # Prometheus still lists it, a newer Stop says it left
        p = decide(assoc=assoc(True, start=NOW - 900), sessions=[sess(NOW - 900, stopped=NOW - 30)])
        self.assertEqual((p["state"], p["confirmed_by"]), ("offline", "radius_acct"))
        # Prometheus does not list it, a newer Interim says it is there: online (the sources
        # disagree: the session is older than the snapshot)
        p = decide(assoc=assoc(False), sessions=[sess(NOW - 900, updated=NOW - 20)])
        self.assertEqual((p["state"], p["reason"], p["confirmed_at"]), ("online", "sources_disagree", NOW - 20))
        # with a fresh present snapshot and a newer Interim: online, measured
        p = decide(assoc=assoc(True, start=NOW - 900), sessions=[sess(NOW - 900, updated=NOW - 20)])
        self.assertEqual((p["state"], p["reason"], p["basis"]), ("online", "acct_interim", "measured"))
        # ... and when the snapshot keeps not listing a session it has long had to see, while
        # its Interims go on, the sources disagree: online stays, inferred
        p = decide(assoc=assoc(False), sessions=[sess(NOW - 900, updated=NOW - 90)])
        self.assertEqual((p["state"], p["confirmed_by"], p["reason"], p["basis"]),
                         ("online", "radius_acct", "sources_disagree", "inferred"))
        # a frozen snapshot is no evidence: RADIUS alone
        frozen = assoc(True, at=NOW - 4000, fresh=False, start=NOW - 9000)
        p = decide(assoc=frozen, sessions=[sess(NOW - 900, updated=NOW - 200)])
        self.assertEqual((p["state"], p["confirmed_by"]), ("online", "radius_acct"))
        self.assertEqual(decide(assoc=frozen)["state"], "unknown")
        self.assertIn({"source": "prometheus", "at": NOW - 4000, "kind": "association_stale"},
                      decide(assoc=frozen)["evidence"])

    def test_a_unifi_disconnect_newer_than_the_snapshot(self):
        events = [{"at": NOW - 30, "kind": "disconnected", "mac": MAC_A, "ap_mac": AP1_MAC, "ap_name": None}]
        p = decide(assoc=assoc(True, start=NOW - 900), events=events, sessions=[sess(NOW - 900, updated=NOW - 300)],
                   interim_s=600)
        # the session is alive (an Interim from before the snapshot): Prometheus and the session agree
        self.assertEqual(p["state"], "online")
        p = decide(assoc=assoc(True, start=NOW - 900), events=events, accept=NOW - 900)
        self.assertEqual((p["state"], p["confirmed_by"], p["reason"]), ("offline", "unifi_syslog", "unifi_disconnect"))
        # older than the snapshot: the snapshot decides
        events[0]["at"] = NOW - 90
        self.assertEqual(decide(assoc=assoc(True, start=NOW - 900), events=events)["state"], "online")

    def test_never_connected_and_withheld(self):
        p = decide(never=True)
        self.assertEqual((p["state"], p["reason"], p["last_seen"]), ("never_connected", "no_data", None))
        self.assertEqual(decide(never=True, accept=NOW - 10)["state"], "connecting")
        p = decide(assoc=assoc(True), sessions=[sess(NOW - 10)], accept=NOW - 20, withheld=True)
        self.assertEqual((p["state"], p["reason"], p["evidence"], p["session"], p["last_seen"]),
                         ("unknown", "mac_conflict", [], None, NOW - 20))

    def test_public_shape(self):
        p = presence.public(decide(assoc=assoc(False), accept=NOW - 35, sessions=[sess(NOW - 30, nas=NAS2)]))
        self.assertEqual(sorted(p), ["basis", "confirmed_at", "confirmed_by", "evidence", "poll_s", "reason", "session",
                                     "since", "stale_after_s", "state"])
        self.assertEqual(sorted(p["session"]), ["acct_session_id", "ap", "cause", "interim_basis", "interim_s", "nas_ip",
                                                "started", "stopped", "updated"])
        self.assertEqual((p["since"], p["session"]["nas_ip"], p["session"]["ap"]["mac"]),
                         (telemetry.iso(NOW - 30), NAS2, AP1_MAC))
        self.assertEqual(p["evidence"][0], {"source": "radius_acct", "at": telemetry.iso(NOW - 30), "kind": "acct_start"})
        self.assertTrue(all(sorted(e) == ["at", "kind", "source"] for e in p["evidence"]))

    def test_own_data_only_for_residents(self):
        identity = telemetry.Identity("a", [], [{"mac": MAC_A, "other_owners": 1, "from": NOW - 1000, "to": NOW - 500}],
                                      False, NOW)
        rows = [sess(NOW - 900, sid="mine", link="class"), sess(NOW - 800, sid="by-mac", link="mac_window"),
                sess(NOW - 100, sid="later", link="mac_window")]
        self.assertEqual([r["acct_session_id"] for r in presence.own(rows, identity)], ["mine", "later"])
        identity.admin = True
        self.assertEqual(len(presence.own(rows, identity)), 3)

    def test_counts_and_poll(self):
        devices = [{"state": "online", "presence": {"poll_s": 30}}, {"state": "connecting", "presence": {"poll_s": 5}},
                   {"state": "offline", "presence": {"poll_s": 30}}]
        self.assertEqual(presence.counts(devices), {"online": 1, "connecting": 1, "offline": 1, "unknown": 0,
                                                    "never_connected": 0})
        self.assertEqual((presence.poll_s(devices), presence.poll_s([])), (5, 30))


# --- the dashboard: DEVICE built on the decision -----------------------------------------------------------

def acct_row(started, updated=None, stopped=None, sid="s1", nas=NAS1, bssid="60:22:32:38:48:00", cause=None,
             interim=None, nas_interim=None, link="class", mac=MAC_A):
    return {"nas_ip": nas, "acct_session_id": sid, "link": link, "mac": mac, "bssid": bssid, "ssid": "Scharni",
            "started": dt(started), "updated": dt(updated or stopped or started),
            "stopped": None if stopped is None else dt(stopped), "terminate_cause": cause, "session_time_s": None,
            "interim_s": interim, "nas_interim_s": nas_interim}


def absent_age(age):
    """live() without MAC_A, with this snapshot age."""
    return [("time() - timestamp(unpoller_prometheus_cache_age_seconds", vector(({}, age),))] + live(set())


class DashboardPresenceTests(unittest.TestCase):
    def setUp(self):
        self.fake = FakeRegistry(windows={"a": [window(MAC_A, NOW - 20 * 86400, NOW - 600)]}).patch(self)

    def dashboard(self, handlers=None, rows=None, admin=False, **kw):
        prom, _session = client(handlers if handlers is not None else live({MAC_A}))
        payload = telemetry.dashboard(prom, rows or [row("a", last_seen=dt(NOW - 600))], now=NOW, db=object(),
                                      admin=admin, **kw)
        return payload, payload["devices"][0]

    def test_online_from_prometheus(self):
        payload, d = self.dashboard()
        p = d["presence"]
        self.assertEqual((d["state"], p["state"], p["confirmed_by"], p["reason"], p["basis"]),
                         ("online", "online", "prometheus", "association", "measured"))
        self.assertEqual((p["confirmed_at"], d["last_seen"], d["since"], p["since"]),
                         (telemetry.iso(NOW - 42), telemetry.iso(NOW - 42), telemetry.iso(NOW - 3600),
                          telemetry.iso(NOW - 3600)))
        self.assertEqual((payload["poll_s"], payload["counts"]["online"], payload["house"]["wifi_data_at"]),
                         (30, 1, telemetry.iso(NOW - 42)))
        self.assertEqual(len(self.fake.called("latest_sessions")), 1)             # one query for the page
        self.assertEqual(len(self.fake.called("latest_connection_events")), 1)

    def test_a_start_before_prometheus_sees_it_and_no_contradiction(self):
        self.fake.acct = {"a": [acct_row(NOW - 20)]}
        _payload, d = self.dashboard(absent_age(42), rows=[row("a", last_seen=dt(NOW - 25))])
        self.assertEqual((d["state"], d["presence"]["confirmed_by"], d["presence"]["reason"]),
                         ("online", "radius_acct", "acct_start"))
        self.assertEqual((d["since"], d["last_seen"]), (telemetry.iso(NOW - 20), telemetry.iso(NOW - 20)))
        codes = [f["code"] for f in d["diagnostics"]]
        self.assertNotIn("offline", codes)
        self.assertEqual(d["presence"]["session"]["ap"]["mac"] if d["presence"]["session"]["ap"] else None, None)
        self.assertIn("radius_acct", d["sources"])
        # the login alone (no Start yet): connecting, still no "not connected"
        self.fake.acct = {}
        payload, d = self.dashboard(absent_age(42), rows=[row("a", last_seen=dt(NOW - 25))])
        self.assertEqual((d["state"], payload["poll_s"], payload["counts"]["connecting"]), ("connecting", 5, 1))
        self.assertNotIn("offline", [f["code"] for f in d["diagnostics"]])

    def test_the_offline_finding_rests_on_the_confirmation(self):
        self.fake.acct = {"a": [acct_row(NOW - 900, stopped=NOW - 30, cause="User-Request")]}
        _payload, d = self.dashboard()                                            # Prometheus still lists it
        self.assertEqual(d["state"], "offline")
        offline = next(f for f in d["diagnostics"] if f["code"] == "offline")
        self.assertEqual(offline["evidence"], {"last_seen": telemetry.iso(NOW - 30),
                                               "confirmed_at": telemetry.iso(NOW - 30),
                                               "confirmed_by": "radius_acct", "reason": "acct_stop"})
        self.assertIsNone(d["since"])
        # no radio findings or values about an offline device's last snapshot... the live values stay
        self.assertNotIn("weak_signal", [f["code"] for f in d["diagnostics"]])

    def test_a_frozen_snapshot_and_radius(self):
        self.fake.acct = {"a": [acct_row(NOW - 900, updated=NOW - 120)]}
        handlers = [("time() - timestamp(unpoller_prometheus_cache_age_seconds", vector(({}, 4000),))] + live({MAC_A})
        payload, d = self.dashboard(handlers)
        self.assertEqual((payload["stale"], d["state"], d["presence"]["confirmed_by"]), (True, "online", "radius_acct"))
        codes = {f["code"] for f in d["diagnostics"]}
        self.assertIn("stale_data", codes)                    # the radio values are the past
        self.assertFalse(codes & {"weak_signal", "high_retries", "busy_channel", "ap_overloaded"})
        # the session silent for too long as well: unknown, not offline
        self.fake.acct = {"a": [acct_row(NOW - 3000, updated=NOW - 1000)]}
        _payload, d = self.dashboard(handlers)
        self.assertEqual((d["state"], d["presence"]["reason"]), ("unknown", "session_stale"))
        self.assertNotIn("offline", {f["code"] for f in d["diagnostics"]})

    def test_prometheus_unavailable(self):
        self.fake.acct = {"a": [acct_row(NOW - 3000, updated=NOW - 1000)]}
        prom, _ = client(fail=telemetry.Unavailable("down"))
        prom._down_until = 1e12
        d = telemetry.dashboard(prom, [row("a", last_seen=dt(NOW - 600))], now=NOW, db=object())["devices"][0]
        self.assertEqual((d["state"], d["presence"]["reason"]), ("unknown", "session_stale"))
        self.fake.acct = {"a": [acct_row(NOW - 3000, stopped=NOW - 1000, cause="Idle-Timeout")]}
        d = telemetry.dashboard(None, [row("a", last_seen=dt(NOW - 600))], now=NOW, db=object())["devices"][0]
        self.assertEqual((d["state"], d["presence"]["confirmed_by"], d["last_seen"]),
                         ("offline", "radius_acct", telemetry.iso(NOW - 1000)))

    def test_mac_rotation_same_device_by_class(self):
        new_mac = "02:00:00:00:00:5e"
        self.fake.windows = {"a": [window(MAC_A, NOW - 20 * 86400, NOW - 7200), window(new_mac, NOW - 40, NOW - 40)]}
        self.fake.acct = {"a": [acct_row(NOW - 3 * 86400, stopped=NOW - 7200, sid="old"),
                                acct_row(NOW - 30, sid="new", mac=new_mac, link="class")]}
        _payload, d = self.dashboard(absent_age(42), rows=[row("a", last_seen=dt(NOW - 40))])
        self.assertEqual((d["state"], d["mac"], d["presence"]["session"]["acct_session_id"]), ("online", new_mac, "new"))

    def test_measured_interval_from_the_registry(self):
        self.fake.acct = {"a": [acct_row(NOW - 3000, updated=NOW - 400, interim=120)]}
        prom, _ = client(fail=telemetry.Unavailable("down"))
        prom._down_until = 1e12
        d = telemetry.dashboard(prom, [row("a", last_seen=dt(NOW - 3000))], now=NOW, db=object(),
                                interim_s=120)["devices"][0]
        self.assertEqual((d["state"], d["presence"]["stale_after_s"]), ("unknown", 300))
        self.fake.acct = {"a": [acct_row(NOW - 3000, updated=NOW - 400)]}
        d = telemetry.dashboard(prom, [row("a", last_seen=dt(NOW - 3000))], now=NOW, db=object(),
                                interim_s=300)["devices"][0]
        self.assertEqual((d["state"], d["presence"]["stale_after_s"]), ("online", 660))

    def test_mac_conflict_withholds_for_residents_only(self):
        self.fake.conflicts = {"a": [{"mac": MAC_A, "other_owners": 1, "from": dt(NOW - 3600), "to": None}]}
        self.fake.acct = {"a": [acct_row(NOW - 20)]}
        _payload, d = self.dashboard()
        self.assertEqual((d["state"], d["presence"]["reason"], d["presence"]["evidence"], d["presence"]["session"]),
                         ("unknown", "mac_conflict", [], None))
        _payload, d = self.dashboard(admin=True)
        self.assertEqual((d["state"], d["presence"]["confirmed_by"]), ("online", "radius_acct"))
        self.assertTrue(d["presence"]["evidence"])

    def test_an_ap_down_incident_maps_the_session_by_its_bssid(self):
        self.fake.acct = {"a": [acct_row(NOW - 3000, updated=NOW - 250)]}
        self.fake.incident_rows = [{"id": 1, "kind": "ap_down", "subject": AP1_MAC, "subject_name": "ap-scharni-2-corner",
                                    "started": dt(NOW - 200), "ended": None, "basis": "measured", "detail": {}}]
        aps = [('max by (bssid, mac, name, radio) (unpoller_device_vap_transmit_power', vector(
            ({"bssid": "60:22:32:38:48:00", "mac": AP1_MAC, "name": "ap-scharni-2-corner", "radio": "na"}, 1),))]
        stale = [("time() - timestamp(unpoller_prometheus_cache_age_seconds", vector(({}, 4000),))]
        _payload, d = self.dashboard(stale + aps + live(set()))
        self.assertEqual((d["state"], d["presence"]["reason"]), ("offline", "ap_down"))
        self.assertEqual(d["presence"]["session"]["ap"]["name"], "ap-scharni-2-corner")

    def test_ap_down_while_prometheus_is_down_uses_the_last_ap_map(self):
        # review 10: the AP map from the last answer places the session while Prometheus is down
        from netportal.telemetry import live
        aps = [('max by (bssid, mac, name, radio) (unpoller_device_vap_transmit_power', vector(
            ({"bssid": "60:22:32:38:48:00", "mac": AP1_MAC, "name": "ap-scharni-2-corner", "radio": "na"}, 1),))]
        prom, _ = client(aps)
        self.addCleanup(live._LAST_APS.__setitem__, slice(None), [0.0, None])
        live.ap_map(prom.within())
        self.fake.acct = {"a": [acct_row(NOW - 3000, updated=NOW - 250)]}
        self.fake.incident_rows = [{"id": 1, "kind": "ap_down", "subject": AP1_MAC, "subject_name": "ap-scharni-2-corner",
                                    "started": dt(NOW - 200), "ended": None, "basis": "measured", "detail": {}}]
        down, _ = client(fail=telemetry.Unavailable("down"))
        down._down_until = 1e12
        d = telemetry.dashboard(down, [row("a", last_seen=dt(NOW - 3000))], now=NOW, db=object())["devices"][0]
        self.assertEqual((d["state"], d["presence"]["reason"]), ("offline", "ap_down"))

    def test_house_wide_reads_are_shared_between_polls(self):
        self.dashboard()
        self.dashboard()
        self.assertEqual((len(self.fake.called("auth_failures")), len(self.fake.called("incidents"))), (1, 1))
        self.assertEqual(len(self.fake.called("latest_sessions")), 2)     # per device: every time

    def test_v1_rows_without_the_registry(self):
        prom, _ = client(live({MAC_A}))
        d = telemetry.dashboard(prom, [row("a", calling_station=MAC_A, last_seen=dt(NOW - 600))], now=NOW)["devices"][0]
        self.assertEqual((d["state"], d["presence"]["confirmed_by"]), ("online", "prometheus"))


class TimelineDisconnectsTests(unittest.TestCase):
    def test_the_merge_is_unchanged_by_presence(self):
        self.assertEqual(tl.DISCONNECT_KINDS, ("disconnected", "session_ended", "reconnected"))


# --- the API: ETag, 304 and the poll hint ----------------------------------------------------------------

class SettingTests(unittest.TestCase):
    def test_the_accounting_interval(self):
        from netportal import config
        self.assertEqual(config._interim("120"), 120)
        for bad in ("", "abc", "10", "86401", "-5", "1e3"):
            with self.assertRaises(RuntimeError, msg=bad):
                config._interim(bad)
        self.assertEqual(config.Settings.__dataclass_fields__["acct_interim_s"].default, 300)


class EtagTests(unittest.TestCase):
    def test_stable_without_the_volatile_values(self):
        a = {"generated_at": "x", "house": {"wifi_data_age_s": 40, "wifi_data_at": "t"}, "devices": [
            {"state": "online", "facts": {"wifi_data_age_s": {"value": 40}}, "diagnostics": [{"evidence": {"age_s": 1}}]}]}
        b = {"generated_at": "y", "house": {"wifi_data_age_s": 55, "wifi_data_at": "t"}, "devices": [
            {"state": "online", "facts": {"wifi_data_age_s": {"value": 55}}, "diagnostics": [{"evidence": {"age_s": 9}}]}]}
        self.assertEqual(web.etag(a), web.etag(b))
        b["devices"][0]["state"] = "offline"
        self.assertNotEqual(web.etag(a), web.etag(b))
        b["devices"][0]["state"], b["house"]["wifi_data_at"] = "online", "t2"
        self.assertNotEqual(web.etag(a), web.etag(b))
        self.assertRegex(web.etag(a), r'^W/"[0-9a-f]{32}"$')

    def test_if_none_match(self):
        self.assertEqual(web.if_none_match('W/"a", "b"'), {'W/"a"', 'W/"b"'})
        self.assertIn('W/"z"', web.if_none_match("*"))
        self.assertEqual(web.if_none_match(None), set())


class PolledApiTests(DashboardApiCase):
    """GET /api/devices and /api/devices/<id> with the browser's revalidation."""

    def test_etag_304_and_poll_hint(self):
        self.log_in(RESIDENT_SUB)
        for url in ("/api/devices", "/api/devices/%s" % MINE):
            first = self.client.get(url)
            self.assertEqual(first.status_code, 200, url)
            tag = first.headers["ETag"]
            self.assertRegex(tag, r'^W/"[0-9a-f]{32}"$')
            self.assertEqual(first.headers["Cache-Control"], "private, no-cache")
            self.assertIn(first.get_json()["poll_s"], (5, 30))
            again = self.client.get(url, headers={"If-None-Match": tag})
            self.assertEqual((again.status_code, again.get_data(), again.headers["ETag"]), (304, b"", tag), url)
            self.assertIn("default-src 'none'", again.headers["Content-Security-Policy"])
            other = self.client.get(url, headers={"If-None-Match": 'W/"0000"'})
            self.assertEqual(other.status_code, 200)
        self.assertIn("presence", first.get_json()["device"])

    def test_a_changed_payload_gets_a_new_tag(self):
        self.log_in(RESIDENT_SUB)
        tag = self.client.get("/api/devices").headers["ETag"]
        self.session.handlers = [h for h in self.session.handlers if "timestamp(unpoller_client_uptime" not in h[0]]
        self.app.extensions["netportal"]["telemetry"]._cache.clear()
        resp = self.client.get("/api/devices", headers={"If-None-Match": tag})
        self.assertEqual(resp.status_code, 200)
        self.assertNotEqual(resp.headers["ETag"], tag)
        self.assertEqual(resp.get_json()["devices"][0]["state"], "offline")

    def test_no_login_no_304(self):
        resp = self.client.get("/api/devices", headers={"If-None-Match": "*"})
        self.assertEqual(resp.status_code, 401)

    def test_the_admin_list_filters_by_connecting(self):
        self.assertIn("connecting", web.DEVICE_STATES)
        self.log_in(ADMIN_SUB)
        body = self.client.get("/api/admin/devices?state=connecting").get_json()
        self.assertEqual((body["devices"], body["counts"]["online"], body["counts"]["offline"]), ([], 1, 1))
        self.assertEqual(body["poll_s"], 30)                  # of the devices shown


if __name__ == "__main__":
    unittest.main()
