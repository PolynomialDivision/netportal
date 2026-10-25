"""A fake of the registry's telemetry interface (the contract's registry functions: windows,
conflicts, RADIUS, accounting, UniFi events, rollups, incidents, jobs) for the telemetry and API
tests, and the tests of the identity rules on it (netportal/telemetry/identity.py): windows,
rotating MACs, a MAC recycled across owners, conflicts for residents and admins. Example values
only."""

import datetime
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from netportal import registry, telemetry  # noqa: E402
from netportal.telemetry import identity  # noqa: E402

UTC = datetime.timezone.utc
NOW = 1_800_000_000
FUNCTIONS = ("device_windows", "window_conflicts", "device_for_mac", "auth_events", "auth_failures", "acct_sessions",
             "connection_events", "device_days", "ap_days", "incidents", "job_status")


def dt(t):
    return datetime.datetime.fromtimestamp(t, UTC)


def _t(value):
    return value.timestamp() if isinstance(value, datetime.datetime) else value


def _within(row, key, since, until):
    t = _t(row[key])
    return (since is None or t >= _t(since)) and (until is None or t <= _t(until))


class FakeRegistry:
    """The registry's telemetry functions over in-memory rows (keyed by device id as str).
    windows: {id: [device_mac rows]}; conflicts: {id: [{"mac", "other_owners", "from", "to"}]};
    holders: {mac: device id} (device_for_mac); auth/acct/events/days: {id: [rows]};
    failures, incidents, jobs, ap_days: [rows]. Every call is remembered in calls."""

    def __init__(self, windows=None, conflicts=None, holders=None, auth=None, acct=None, events=None, days=None,
                 failures=None, incidents=None, jobs=None, ap_days=None, now=NOW):
        self.windows, self.conflicts, self.holders = windows or {}, conflicts or {}, holders or {}
        self.now = now
        self.auth, self.acct, self.events, self.days = auth or {}, acct or {}, events or {}, days or {}
        self.failures, self.incident_rows, self.jobs, self.ap_rows = failures or [], incidents or [], jobs or [], ap_days or []
        self.calls = []

    def patch(self, case, target=registry):
        """Patch these functions into the registry module for the test (they need not exist yet)."""
        for name in FUNCTIONS:
            p = mock.patch.object(target, name, getattr(self, name), create=True)
            p.start()
            case.addCleanup(p.stop)
        return self

    def called(self, name):
        return [c for c in self.calls if c[0] == name]

    def device_windows(self, db, device_ids, since=None, until=None):
        """As registry.device_windows: each row with window_end and current by the rule of the SQL
        view device_mac_window (rows that bring their own window_end keep it)."""
        self.calls.append(("device_windows", tuple(str(i) for i in device_ids), since, until))
        out = {}
        for i in device_ids:
            rows = with_window_end(self.windows.get(str(i), []), self.now)
            out[i] = [w for w in rows if (since is None or _t(w["window_end"]) >= _t(since))
                      and (until is None or _t(w["first_seen"]) <= _t(until))]
        return out

    def window_conflicts(self, db, device_ids, since=None, until=None):
        self.calls.append(("window_conflicts", tuple(str(i) for i in device_ids), since, until))
        return {i: list(self.conflicts.get(str(i), [])) for i in device_ids}

    def device_for_mac(self, db, mac, at):
        self.calls.append(("device_for_mac", mac, at))
        return self.holders.get(mac)

    def _rows(self, name, store, device_id, since, until, limit, key="at"):
        self.calls.append((name, str(device_id), since, until, limit))
        rows = [r for r in store.get(str(device_id), []) if _within(r, key, since, until)]
        return rows[:limit]

    def auth_events(self, db, device_id, since, until, limit=1000):
        return self._rows("auth_events", self.auth, device_id, since, until, limit)

    def acct_sessions(self, db, device_id, since, until, limit=1000):
        return self._rows("acct_sessions", self.acct, device_id, since, until, limit, key="updated")

    def connection_events(self, db, device_id, since, until, limit=2000):
        return self._rows("connection_events", self.events, device_id, since, until, limit)

    def device_days(self, db, device_id, since_day, until_day):
        self.calls.append(("device_days", str(device_id), since_day, until_day))
        return [r for r in self.days.get(str(device_id), []) if since_day <= r["day"] <= until_day]

    def ap_days(self, db, since_day, until_day, ap_macs=None):
        self.calls.append(("ap_days", since_day, until_day))
        return [r for r in self.ap_rows if since_day <= r["day"] <= until_day]

    def auth_failures(self, db, since, until=None, limit=500):
        self.calls.append(("auth_failures", since, until, limit))
        return [r for r in self.failures if _within(r, "at", since, until)][:limit]

    def incidents(self, db, since, until=None, kinds=None, subjects=None):
        self.calls.append(("incidents", since, until, kinds))
        out = []
        for r in self.incident_rows:
            end = _t(r["ended"]) if r.get("ended") is not None else None
            if (until is None or _t(r["started"]) <= _t(until)) and (end is None or end >= _t(since)) and (
                    not kinds or r["kind"] in kinds):
                out.append(r)
        return out

    def job_status(self, db):
        self.calls.append(("job_status",))
        return list(self.jobs)


def with_window_end(rows, now):
    """The SQL view's rule (migrations/0002_telemetry.sql, device_mac_window): the device's MAC
    with the newest last_seen is current; its window ends at last_seen + CURRENT_WINDOW, capped at
    now (but not before last_seen + WINDOW_GRACE); every other one at last_seen + WINDOW_GRACE."""
    if not rows:
        return []
    newest = max(_t(w["last_seen"]) for w in rows)
    grace, current = registry.WINDOW_GRACE.total_seconds(), registry.CURRENT_WINDOW.total_seconds()
    out = []
    for w in rows:
        last = _t(w["last_seen"])
        is_current = w.get("current", last == newest)
        end = min(last + current, max(now, last + grace)) if is_current else last + grace
        out.append(dict(w, current=is_current, window_end=w.get("window_end") or dt(end)))
    return out


def window(mac, first, last, randomized=None, auth_count=1):
    return {"mac": mac, "first_seen": dt(first), "last_seen": dt(last),
            "randomized": telemetry.randomized(mac) if randomized is None else randomized, "auth_count": auth_count}


def row(device_id, owner="sub-resident", created=NOW - 400 * 86400, **extra):
    return dict({"id": device_id, "owner": owner, "name": "Phone " + device_id, "platform": "android",
                 "policy": "residents", "created": dt(created), "revoked": None, "expires": dt(NOW + 200 * 86400),
                 "last_seen": None, "calling_station": None, "first_seen": None}, **extra)


R1, R2, R3, R4 = "02:00:00:00:01:01", "02:00:00:00:01:02", "02:00:00:00:01:03", "02:00:00:00:01:04"
HW = "00:11:22:33:44:55"


class IdentityTests(unittest.TestCase):
    def identity(self, windows, conflicts=(), admin=False, holders=None, device="a", **row_extra):
        fake = FakeRegistry(windows={device: windows}, conflicts={device: list(conflicts)}, holders=holders).patch(self)
        return identity.from_registry(None, [row(device, **row_extra)], NOW, admin)[device], fake

    def test_the_current_window_stays_open_for_a_session(self):
        ident, fake = self.identity([window(HW, NOW - 10 * 86400, NOW - 3600)])
        self.assertEqual(ident.current_mac, HW)
        self.assertIsNone(ident.windows[0]["end"])                     # capped at now: open
        self.assertEqual(ident.live_bounds(), {HW: NOW - 10 * 86400})
        self.assertEqual(ident.mac_mode(), "hardware")
        self.assertEqual(fake.called("device_for_mac"), [])            # the rule is the registry's

    def test_a_window_ends_a_session_after_the_last_login(self):
        ident, _ = self.identity([window(HW, NOW - 10 * 86400, NOW - 2 * 86400)])
        self.assertEqual(ident.windows[0]["end"], NOW - 2 * 86400 + identity.CURRENT_WINDOW_S)
        self.assertEqual(ident.live_bounds(), {})                        # nothing of now is its own

    def test_the_registrys_window_end_is_used_as_it_is(self):
        # e.g. the registry ends a current window early (another owner's device holds the MAC)
        w = dict(window(HW, NOW - 86400, NOW - 3 * 3600), current=True, window_end=dt(NOW - 3 * 3600 + 900))
        ident, _ = self.identity([w])
        self.assertEqual(ident.windows[0]["end"], NOW - 3 * 3600 + 900)
        self.assertEqual(ident.live_bounds(), {})
        revoked = dict(window(HW, NOW - 86400, NOW - 60), current=False)      # a revoked device: none current
        ident, _ = self.identity([revoked])
        self.assertIsNone(ident.current_mac)
        self.assertEqual(ident.windows[0]["end"], NOW - 60 + identity.WINDOW_GRACE_S)

    def test_the_constants_are_the_registrys(self):
        self.assertEqual(identity.WINDOW_GRACE_S, registry.WINDOW_GRACE.total_seconds())
        self.assertEqual(identity.CURRENT_WINDOW_S, registry.CURRENT_WINDOW.total_seconds())
        self.assertIs(telemetry.normalise_mac, registry.normalise_mac)

    def test_rotating_macs(self):
        windows = [window(R1, NOW - 20 * 86400, NOW - 19 * 86400), window(R2, NOW - 10 * 86400, NOW - 9 * 86400),
                   window(R3, NOW - 3600, NOW - 600)]
        ident, _ = self.identity(windows)
        self.assertEqual(ident.mac_mode(), "rotating")
        self.assertEqual(ident.current_mac, R3)
        self.assertEqual([m["mac"] for m in ident.public_macs()], [R3, R2, R1])
        self.assertTrue(ident.public_macs()[0]["current"])
        self.assertEqual(ident.data_from, NOW - 20 * 86400)
        # old MACs' windows end with their grace: their data later is nobody's
        r1 = [w for w in ident.windows if w["mac"] == R1][0]
        self.assertEqual(r1["end"], NOW - 19 * 86400 + identity.WINDOW_GRACE_S)
        self.assertEqual(set(ident.live_bounds()), {R3})

    def test_two_randomized_macs_are_a_fixed_private_address(self):
        ident, _ = self.identity([window(R1, NOW - 20 * 86400, NOW - 19 * 86400), window(R2, NOW - 86400, NOW)])
        self.assertEqual(ident.mac_mode(), "random_fixed")
        self.assertIsNone(self.identity([])[0].mac_mode())

    def test_the_enrolment_bounds_the_first_window(self):
        ident, _ = self.identity([window(HW, NOW - 90 * 86400, NOW)], created=NOW - 30 * 86400)
        self.assertEqual(ident.data_from, NOW - 30 * 86400)

    def test_a_recycled_mac_belongs_to_each_owner_in_their_time(self):
        # the same MAC: device a (one person) in October, device b (someone else) since
        fake = FakeRegistry(windows={"a": [window(R1, NOW - 60 * 86400, NOW - 40 * 86400)],
                                     "b": [window(R1, NOW - 10 * 86400, NOW - 60)]}).patch(self)
        ids = identity.from_registry(None, [row("a"), row("b", owner="sub-other")], NOW, admin=False)
        a, b = ids["a"], ids["b"]
        self.assertTrue(a.contains(R1, NOW - 50 * 86400))
        self.assertFalse(a.contains(R1, NOW - 5 * 86400))                # b's time: not a's
        self.assertFalse(b.contains(R1, NOW - 50 * 86400))               # a's time: not b's
        self.assertTrue(b.contains(R1, NOW - 5 * 86400))
        self.assertEqual(a.live_bounds(), {})
        self.assertEqual(b.live_bounds(), {R1: NOW - 10 * 86400})
        self.assertFalse(b.withheld_now())
        self.assertEqual(len(fake.called("device_windows")), 1)          # one query for every device

    def test_an_overlap_is_withheld_from_residents_and_marked_for_admins(self):
        windows = [window(R1, NOW - 10 * 86400, NOW - 60)]
        conflicts = [{"mac": R1, "other_owners": 1, "from": dt(NOW - 5 * 86400), "to": dt(NOW - 4 * 86400)}]
        resident, _ = self.identity(windows, conflicts)
        self.assertFalse(resident.contains(R1, NOW - 4.5 * 86400))
        self.assertTrue(resident.contains(R1, NOW - 6 * 86400))
        self.assertTrue(resident.contains(R1, NOW - 3 * 86400))
        self.assertFalse(resident.withheld_now())                         # the overlap is past
        self.assertEqual(resident.public_conflicts(), [{"mac": R1, "from": telemetry.iso(NOW - 5 * 86400),
                                                        "to": telemetry.iso(NOW - 4 * 86400)}])
        admin, _ = self.identity(windows, conflicts, admin=True)
        self.assertTrue(admin.contains(R1, NOW - 4.5 * 86400))
        self.assertEqual(admin.public_conflicts()[0]["other_owners"], 1)

    def test_an_open_overlap_withholds_the_live_data(self):
        conflicts = [{"mac": R1, "other_owners": 2, "from": dt(NOW - 3600), "to": None}]
        resident, _ = self.identity([window(R1, NOW - 86400, NOW - 60)], conflicts)
        self.assertTrue(resident.withheld_now())
        self.assertEqual(resident.live_bounds(), {})
        admin, _ = self.identity([window(R1, NOW - 86400, NOW - 60)], conflicts, admin=True)
        self.assertFalse(admin.withheld_now())
        self.assertEqual(admin.conflict_owners_now(), 2)

    def test_the_dashboard_reads_a_month_of_windows(self):
        _ident, fake = self.identity([window(HW, NOW - 86400, NOW)])
        identity.from_registry(None, [row("a")], NOW, False, since=NOW - identity.RECENT_S)
        self.assertEqual(fake.called("device_windows")[-1][2], dt(NOW - identity.RECENT_S))


if __name__ == "__main__":
    unittest.main()
