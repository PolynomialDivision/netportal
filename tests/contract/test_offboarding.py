"""Offboarding black-box (INVENTORY 8): `netportal offboard` against the mock Authentik users API,
observed over HTTP (sessions, app tokens), at the fake access point (Disconnect-Requests) and
through the registry adapter (people, devices, audit).

The mock's directory is every person any test logged in with, as last posted, so a round here
leaves the other tests' people alone; each test changes only its own people."""

import os
import time

from harness import (A, RUN, ContractCase, Person, download, idp_api_requests, idp_directory, resident)
from test_letswifi import WINDOWS, Flow


class OffboardingTests(ContractCase):
    """INVENTORY 8.1 (users API, safety guard), 8.2 (reconciliation), 8.3 (heartbeat), 7.1 (Disconnect)."""

    def setUp(self):
        idp_directory(reset=True)
        A.nas.reset("ack")
        self.heartbeat = RUN / ("heartbeat-%s" % self.id().rsplit(".", 1)[-1])
        if self.heartbeat.exists():
            self.heartbeat.unlink()

    def tearDown(self):
        idp_directory(reset=True)

    def offboard(self, *args, **settings):
        settings.setdefault("NETPORTAL_HEARTBEAT", str(self.heartbeat))
        return A.command("offboard", *args, env=settings, timeout=90)

    def offboard_twice(self):
        """Two rounds: only someone two rounds in a row found without access is offboarded
        (test_two_rounds_before_a_removal)."""
        first = self.offboard()
        self.assertEqual(first.returncode, 0, first.stderr[-2000:])
        return self.offboard()

    def resident_with_device(self, prefix, session=True):
        p = resident(prefix)
        b = A.browser().logged_in(p)
        _, cert, dev = download(b, "apple")
        if session:
            A.reg.radius_session(dev, cert, calling="02:00:00:00:cc:%02x" % (len(prefix) % 256))
        return p, b, cert, dev

    def assertOffboarded(self, person, browser, devices):
        state = A.reg.person(person.sub)
        self.assertTrue(state["offboarded"])
        self.assertFalse(state["admin"])
        for dev in devices:
            self.assertTrue(A.reg.device(dev)["revoked"], dev)
            self.assertIn(("offboarding", "revoke"), A.reg.audit(dev))
        self.assertToLogin(browser.get("/"))                       # the portal session ends
        self.assertJsonError(browser.get("/api/devices"), 401, "login_required")

    def assertUntouched(self, person, browser, devices):
        self.assertFalse(A.reg.person(person.sub)["offboarded"])
        for dev in devices:
            self.assertFalse(A.reg.device(dev)["revoked"], dev)
        self.assertEqual(browser.get("/").status_code, 200)

    def test_lost_access_is_offboarded(self):
        """8.2: deactivated, out of every Wi-Fi group, or deleted in Authentik -> person
        offboarded, every device revoked with a Disconnect-Request, app grants revoked, the portal
        session ends at the next request."""
        inactive, b1, cert1, dev1 = self.resident_with_device("off-inactive")
        nogroup, b2, _, dev2 = self.resident_with_device("off-nogroup", session=False)
        deleted, b3, _, dev3 = self.resident_with_device("off-deleted", session=False)
        app = Flow(WINDOWS, person=deleted)
        app.browser = b3
        tokens = app.tokens()
        self.assertEqual(app.eap(tokens["access_token"]).status_code, 200)
        keeper, b4, _, dev4 = self.resident_with_device("off-keeper", session=False)
        before = A.reg.offboarding_last_success()
        time.sleep(1.1)
        idp_directory(override={inactive.sub: inactive.json(active=False),
                                nogroup.sub: nogroup.json(groups=["vpn-users"]),
                                deleted.sub: None})
        out = self.offboard_twice()
        self.assertEqual(out.returncode, 0, out.stderr[-2000:])
        self.assertOffboarded(inactive, b1, [dev1])
        self.assertOffboarded(nogroup, b2, [dev2])
        self.assertOffboarded(deleted, b3, [dev3] + [d["id"] for d in A.reg.devices(deleted.sub)])
        self.assertUntouched(keeper, b4, [dev4])
        # the app's tokens stop at once
        self.assertJsonError(app.eap(tokens["access_token"]), 401, "invalid_token")
        self.assertJsonError(app.refresh(tokens["refresh_token"]), 400, "invalid_grant")
        # the access point got a valid Disconnect-Request for the device with a session
        packets = A.nas.wait(1)
        self.assertEqual(len(packets), 1, packets)
        self.assertTrue(packets[0]["valid"])
        self.assertIn(("offboarding", "disconnect:ack"), A.reg.audit(dev1))
        self.assertIn(("offboarding", "disconnect:no-session"), A.reg.audit(dev2))
        # the round counts as a success
        self.assertGreater(A.reg.offboarding_last_success(), before)
        self.assertTrue(self.heartbeat.exists())

    def test_moved_out_keeps_the_devices_in_the_guests_vlan(self):
        """8.2: someone whose groups now give another policy keeps their devices; they move to
        that policy (Disconnect: authenticate again into its VLAN)."""
        p, b, _, dev = self.resident_with_device("off-moved")
        idp_directory(override={p.sub: p.json(groups=["former-residents"])})
        out = self.offboard()
        self.assertEqual(out.returncode, 0, out.stderr[-2000:])
        self.assertEqual(A.reg.person(p.sub)["policy"], "guests")
        self.assertEqual(A.reg.device(dev)["policy"], "guests")
        self.assertFalse(A.reg.device(dev)["revoked"])
        self.assertIn(("offboarding", "policy:guests"), A.reg.audit(dev))
        packets = A.nas.wait(1)
        self.assertEqual(len(packets), 1)
        self.assertTrue(packets[0]["valid"])
        self.assertEqual(b.get("/").status_code, 200)

    def test_admin_rights_follow_the_groups(self):
        """8.2/4.3: the round sets admin from NETPORTAL_ADMIN_GROUPS; an open session follows at
        the next request."""
        adm = Person(["it-admins"], "off-adm")
        ab = A.browser().logged_in(adm)
        res = resident("off-adm2")
        rb = A.browser().logged_in(res)
        self.assertEqual(ab.get("/admin").status_code, 200)
        self.assertEqual(rb.get("/admin").status_code, 403)
        idp_directory(override={adm.sub: adm.json(groups=["residents"]),
                                res.sub: res.json(groups=["residents", "it-admins"])})
        out = self.offboard()
        self.assertEqual(out.returncode, 0, out.stderr[-2000:])
        self.assertToLogin(ab.get("/admin"))         # no admin page any more: the session ended (L2)
        self.assertPage(rb.get("/admin"), 200)

    def test_losing_admin_ends_the_portal_sessions(self):
        """Security review 2026-10-29 L2: a round that takes the admin right away ends the
        person's portal sessions (the next page logs in again, with Authentik's groups)."""
        adm = Person(["it-admins"], "off-adm3")
        ab = A.browser().logged_in(adm)
        self.assertEqual(ab.get("/admin").status_code, 200)
        idp_directory(override={adm.sub: adm.json(groups=["residents"])})
        out = self.offboard()
        self.assertEqual(out.returncode, 0, out.stderr[-2000:])
        self.assertToLogin(ab.get("/"))
        self.assertFalse(A.reg.person(adm.sub)["admin"])

    def test_two_rounds_before_a_removal(self):
        """Security review 2026-10-29 M1: the first round that finds someone without access only
        notes it; the next round (still without access) offboards them."""
        p, b, _, dev = self.resident_with_device("off-tworounds", session=False)
        idp_directory(override={p.sub: None})
        out = self.offboard()
        self.assertEqual(out.returncode, 0, out.stderr[-2000:])
        self.assertUntouched(p, b, [dev])
        out = self.offboard()
        self.assertEqual(out.returncode, 0, out.stderr[-2000:])
        self.assertOffboarded(p, b, [dev])

    def test_a_mass_removal_is_held_back(self):
        """Security review 2026-10-29 M1 (house-infra vault-orgs' rule): a directory that would
        take the devices of at least 3 and more than half of the people who have devices (an API
        token with narrowed rights, a renamed group, members moved into subgroups) changes
        nothing; the round fails (HELD BACK), so the staleness alert fires."""
        p, b, _, dev = self.resident_with_device("off-mass", session=False)
        for i in range(2):                              # at least 3 with devices, however the suite runs
            self.resident_with_device("off-mass%d" % i, session=False)
        keeper = resident("off-mass-keeper")
        A.browser().logged_in(keeper)                   # in the registry: the "another directory" guard passes
        idp_directory(only=[keeper.json()])
        before = A.reg.offboarding_last_success()
        out = self.offboard()
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("HELD BACK", out.stderr)
        self.assertUntouched(p, b, [dev])
        self.assertEqual(A.reg.offboarding_last_success(), before)
        self.assertEqual(A.nas.received(), [])
        self.assertTrue(self.heartbeat.exists())

    def test_all_pages_are_read(self):
        """8.1: the users API is paged (Authentik: pagination.next = next page number); people on
        later pages are not offboarded; groups are asked for (include_groups=true)."""
        last = resident("off-page")
        lb = A.browser().logged_in(last)
        idp_directory(page_size=3)
        out = self.offboard()
        self.assertEqual(out.returncode, 0, out.stderr[-2000:])
        self.assertUntouched(last, lb, [])
        calls = idp_api_requests()
        self.assertGreaterEqual(len(calls), 2)
        pages = []
        for call in calls:
            self.assertTrue(call["authorized"], call)
            q = dict(p.split("=", 1) for p in call["query"].split("&") if "=" in p)
            self.assertEqual(q.get("include_groups"), "true", call)
            pages.append(int(q.get("page", "1")))
        self.assertEqual(pages, list(range(1, len(pages) + 1)))

    def test_people_only_in_authentik_are_ignored(self):
        stranger = Person(["residents"], "off-stranger")
        idp_directory(override={stranger.sub: stranger.json()})
        out = self.offboard()
        self.assertEqual(out.returncode, 0, out.stderr[-2000:])
        self.assertIsNone(A.reg.person(stranger.sub))

    def check_nothing_changes(self, expect_exit_nonzero=True, **settings):
        p, b, _, dev = self.resident_with_device("off-safe", session=False)
        idp_directory(override={p.sub: None})          # would be offboarded by a working round
        before = A.reg.offboarding_last_success()
        out = self.offboard(**settings)
        if expect_exit_nonzero:
            self.assertNotEqual(out.returncode, 0)
        else:
            self.assertEqual(out.returncode, 0, out.stderr[-2000:])
        self.assertUntouched(p, b, [dev])
        self.assertEqual(A.reg.offboarding_last_success(), before)
        self.assertEqual(A.nas.received(), [])
        self.assertTrue(self.heartbeat.exists(), "the heartbeat is touched after a failed round too")

    def test_api_failure_changes_nothing(self):
        """8.1 safety: an HTTP error of the users API -> the round fails (exit 1), nothing revoked."""
        idp_directory(fail=500)
        self.check_nothing_changes()

    def test_wrong_token_changes_nothing(self):
        self.check_nothing_changes(NETPORTAL_AUTHENTIK_TOKEN="not-the-reader-token")

    def test_empty_directory_changes_nothing(self):
        """8.1 safety: zero users -> refuse to offboard everyone."""
        idp_directory(only=[])
        self.check_nothing_changes()

    def test_unreachable_api_changes_nothing(self):
        self.check_nothing_changes(NETPORTAL_AUTHENTIK_API="http://127.0.0.1:9/api/v3")

    def test_switched_off_without_api(self):
        """8.1 off switch: no NETPORTAL_AUTHENTIK_API -> nothing is done, and the round is not
        counted as a success (the staleness alert fires)."""
        self.check_nothing_changes(expect_exit_nonzero=False, NETPORTAL_AUTHENTIK_API="")

    def test_every_n_seconds(self):
        """1.1/8.3: offboard --every N runs rounds forever and touches the heartbeat after each."""
        proc = A.command("offboard", "--every", "1", env={"NETPORTAL_HEARTBEAT": str(self.heartbeat)},
                         background=True)
        try:
            seen = set()
            end = time.time() + 20
            while time.time() < end and len(seen) < 3:
                if self.heartbeat.exists():
                    seen.add(os.stat(self.heartbeat).st_mtime_ns)
                time.sleep(0.1)
            self.assertIsNone(proc.poll(), "the loop must keep running")
            self.assertGreaterEqual(len(seen), 3, "the heartbeat must be touched after every round")
        finally:
            proc.terminate()
            proc.communicate(timeout=10)
