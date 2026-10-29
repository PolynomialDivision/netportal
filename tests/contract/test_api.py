"""The dashboard's JSON API (INVENTORY 3.2 rows 16-25): the polled device APIs with ETag, 304
and the poll hint (3.3), field names, types and semantics (9.12; times RFC 3339, numbers not
pinned to one rounding), the admin API's parameter checks (3.2 rows 20-25)."""

import time
import uuid

from harness import (A, ContractCase, admin_person, download, enrol, is_rfc3339, newest_device, resident)


def polled_cache_control(r):
    """The polled answers' Cache-Control: private, not stored at all (test_polled_answers_are_not_stored)."""
    return {p.strip() for p in r.headers["Cache-Control"].split(",")} == {"private", "no-store"}

STATES = {"online", "connecting", "offline", "never_connected", "unknown"}
TELEMETRY = {"ok", "unavailable", "off"}


class PolledApiTests(ContractCase):
    """INVENTORY 3.3."""

    @classmethod
    def setUpClass(cls):
        cls.person = resident("poll")
        cls.b = A.browser().logged_in(cls.person)
        _, cls.cert, cls.dev = download(cls.b, "apple", "poll phone")

    def get(self, path="/api/devices", **headers):
        return self.b.get(path, headers=headers)

    def test_etag_and_cache_control(self):
        r = self.get()
        self.assertJson(r, 200)
        tag = r.headers["ETag"]
        self.assertRegex(tag, r'^W/"[^"]+"$')
        self.assertTrue(polled_cache_control(r), r.headers["Cache-Control"])

    def test_same_data_same_etag(self):
        """The ETag leaves out what changes with every request (generated_at, ages)."""
        first = self.get().headers["ETag"]
        time.sleep(1.1)
        self.assertEqual(self.get().headers["ETag"], first)

    def test_304(self):
        r = self.get()
        tag = r.headers["ETag"]
        strong = tag[2:]
        for header in [tag, strong, "*", '"nope", ' + tag, 'W/"x", W/"y" ,%s' % tag]:
            with self.subTest(header=header):
                r = self.get(**{"If-None-Match": header})
                self.assertEqual(r.status_code, 304)
                self.assertEqual(r.content, b"")
                self.assertEqual(r.headers["ETag"], tag)
                self.assertTrue(polled_cache_control(r), r.headers["Cache-Control"])
                self.assertEqual(r.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(self.get(**{"If-None-Match": 'W/"something else"'}).status_code, 200)

    def test_polled_answers_are_not_stored(self):
        """Security review 2026-10-29 I7: the device lists name MACs and owners; nothing keeps
        them (private, no-store). The 304 flow does not need the browser's cache: the page's script
        keeps the body and its ETag and sends If-None-Match itself (static/live.js)."""
        r = self.get()
        tag = r.headers["ETag"]
        for resp in (r, self.get(**{"If-None-Match": tag})):
            self.assertEqual({p.strip() for p in resp.headers["Cache-Control"].split(",")}, {"private", "no-store"})
        self.assertEqual(self.get(**{"If-None-Match": tag}).status_code, 304)

    def test_etag_changes_with_the_data(self):
        before = self.get().headers["ETag"]
        self.b.post("/devices/%s/rename" % self.dev, data={"csrf": self.b.csrf(), "name": "renamed for etag"})
        r = self.get(**{"If-None-Match": before})
        self.assertEqual(r.status_code, 200)
        self.assertNotEqual(r.headers["ETag"], before)
        self.b.post("/devices/%s/rename" % self.dev, data={"csrf": self.b.csrf(), "name": "poll phone"})

    def test_login_is_checked_before_the_304(self):
        tag = self.get().headers["ETag"]
        anon = A.browser()
        self.assertJsonError(anon.get("/api/devices", headers={"If-None-Match": tag}), 401, "login_required")

    def test_single_device_api(self):
        r = self.get("/api/devices/" + self.dev)
        body = self.assertJson(r, 200)
        self.assertIn("device", body)
        self.assertNotIn("devices", body)
        self.assertNotIn("counts", body)
        self.assertEqual(body["device"]["id"], self.dev)
        self.assertIsInstance(body["poll_s"], int)
        tag = r.headers["ETag"]
        self.assertEqual(self.get("/api/devices/" + self.dev, **{"If-None-Match": tag}).status_code, 304)


class PayloadTests(ContractCase):
    """INVENTORY 9.12 DASHBOARD, DEVICE, HOUSE, HISTORY: field names, types, semantics."""

    @classmethod
    def setUpClass(cls):
        cls.person = resident("pay")
        cls.b = A.browser().logged_in(cls.person)
        _, cls.cert, cls.dev = download(cls.b, "eap-config", "payload phone")
        enrol(cls.b, "apple", "never downloaded")
        A.reg.radius_session(cls.dev, cls.cert, calling="02:00:00:00:bb:01")

    def check_house(self, house):
        self.assertIn(house["internet"], {"ok", "degraded", "down", "unknown"})
        for key in ("dns", "router"):
            self.assertIn(house[key], {"ok", "down", "unknown"})
        for key in ("internet_loss_ratio", "internet_rtt_ms", "speedtest", "wifi_data_age_s", "wifi_data_at"):
            self.assertIn(key, house)
        self.assertTrue(house["wifi_data_at"] is None or is_rfc3339(house["wifi_data_at"]))

    def check_device(self, d):
        self.assertIsInstance(d["id"], str)
        uuid.UUID(d["id"])
        for key in ("name", "platform", "policy"):
            self.assertIsInstance(d[key], str)
        self.assertTrue(is_rfc3339(d["created"]), d["created"])
        self.assertTrue(d["expires"] is None or is_rfc3339(d["expires"]), d["expires"])
        self.assertIs(d["revoked"], False)
        self.assertIn(d["state"], STATES)
        self.assertTrue(d["last_seen"] is None or is_rfc3339(d["last_seen"]))
        self.assertIsInstance(d["expires_soon"], bool)
        self.assertIsInstance(d["presence"], dict)
        self.assertEqual(d["presence"]["state"], d["state"])
        self.assertIsInstance(d["presence"]["poll_s"], int)
        self.assertIsInstance(d["findings"], list)
        self.assertIsInstance(d["macs"], list)
        self.assertIn("registry", d["sources"])
        self.assertEqual(d["sources"], sorted(d["sources"]))

    def test_dashboard_payload(self):
        body = self.assertJson(self.b.get("/api/devices"), 200)
        self.assertTrue(is_rfc3339(body["generated_at"]), body["generated_at"])
        self.assertEqual(body["telemetry"], "off")             # no NETPORTAL_PROMETHEUS_URL here
        self.assertIsInstance(body["stale"], bool)
        self.assertIsInstance(body["poll_s"], int)
        self.assertGreater(body["poll_s"], 0)
        self.assertTrue(STATES <= set(body["counts"]), body["counts"])
        self.assertTrue(all(isinstance(v, int) for v in body["counts"].values()))
        self.assertEqual(sum(body["counts"].values()), len(body["devices"]))
        self.check_house(body["house"])
        names = [d["name"] for d in body["devices"]]
        self.assertEqual(names, ["never downloaded", "payload phone"])          # newest first
        for d in body["devices"]:
            self.check_device(d)
            self.assertNotIn("owner", d)                       # residents see no owner block
            self.assertNotIn("conflicts", d)
        downloaded = [d for d in body["devices"] if d["id"] == self.dev][0]
        self.assertIsNotNone(downloaded["expires"])
        self.assertEqual(downloaded["mac"], "02:00:00:00:bb:01")
        self.assertIsNotNone(downloaded["last_seen"])
        never = [d for d in body["devices"] if d["id"] != self.dev][0]
        self.assertEqual(never["state"], "never_connected")
        self.assertIsNone(never["expires"])

    def test_house(self):
        self.check_house(self.assertJson(self.b.get("/api/house"), 200))

    def test_history(self):
        for range_key in ("24h", "7d", "30d", "90d", "1y", "all"):
            with self.subTest(range=range_key):
                r = self.b.get("/api/devices/%s/history?range=%s" % (self.dev, range_key))
                body = self.assertJson(r, 200)
                self.assertNotIn("ETag", r.headers)
                self.assertIn("no-store", r.headers["Cache-Control"])
                self.assertEqual(body["range"], range_key)
                self.assertIsInstance(body["start"], int)
                self.assertIsInstance(body["end"], int)
                self.assertLess(body["start"], body["end"])
                self.assertIn(body["telemetry"], TELEMETRY)
                self.assertIsInstance(body["series"], dict)
                self.assertIsInstance(body["timeline"], list)
                for event in body["timeline"]:
                    self.assertTrue(is_rfc3339(event["at"]), event)
        for bad in ("", "2h", "24H", "1d"):
            with self.subTest(bad=bad):
                self.assertJsonError(self.b.get("/api/devices/%s/history?range=%s" % (self.dev, bad)), 400,
                                     "bad_range")


class AdminApiTests(ContractCase):
    """INVENTORY 3.2 rows 20-25."""

    @classmethod
    def setUpClass(cls):
        cls.owner = resident("aap")
        ob = A.browser().logged_in(cls.owner)
        enrol(ob, "apple", "Zebra-Tablet-%s" % cls.owner.username)
        cls.dev = newest_device(A, cls.owner.sub)["id"]
        enrol(ob, "apple", "revoked one")
        cls.revoked = newest_device(A, cls.owner.sub)["id"]
        ob.post("/devices/%s/revoke" % cls.revoked, data={"csrf": ob.csrf()})
        cls.ab = A.browser().logged_in(admin_person("aap"))

    def test_admin_devices_with_owner_and_filters(self):
        body = self.assertJson(self.ab.get("/api/admin/devices"), 200)
        mine = [d for d in body["devices"] if d["id"] == self.dev]
        self.assertEqual(len(mine), 1)
        self.assertEqual(mine[0]["owner"]["username"], self.owner.username)
        self.assertIn("display", mine[0]["owner"])
        self.assertNotIn(self.revoked, [d["id"] for d in body["devices"]])
        total = sum(body["counts"].values())
        for q in ["zebra-tablet-" + self.owner.username, self.owner.username.upper()]:
            with self.subTest(q=q):
                found = self.assertJson(self.ab.get("/api/admin/devices", params={"q": q}), 200)
                self.assertEqual([d["id"] for d in found["devices"]], [self.dev])
                self.assertEqual(sum(found["counts"].values()), total)          # counts: of all devices
        found = self.ab.get("/api/admin/devices", params={"state": "never_connected"}).json()
        self.assertTrue(all(d["state"] == "never_connected" for d in found["devices"]))
        self.assertIn(self.dev, [d["id"] for d in found["devices"]])
        found = self.ab.get("/api/admin/devices", params={"state": "online", "q": self.owner.username}).json()
        self.assertEqual(found["devices"], [])

    def test_overview_and_aps(self):
        for path in ("/api/admin/overview", "/api/admin/aps"):
            with self.subTest(path=path):
                self.assertIsInstance(self.assertJson(self.ab.get(path), 200), dict)

    def test_incidents_parameters(self):
        ok = ["", "?range=7d", "?range=30d", "?range=1y", "?kind=ap_down", "?from=2026-10-01&to=2026-10-20",
              "?from=%d" % (time.time() - 3600), "?from=2026-10-01T00:00:00Z"]
        for q in ok:
            with self.subTest(q=q):
                body = self.assertJson(self.ab.get("/api/admin/incidents" + q), 200)
                self.assertIsInstance(body, dict)
        for q, code in [("?kind=AP_DOWN", "bad_kind"), ("?kind=" + "a" * 41, "bad_kind"), ("?kind=1x", "bad_kind"),
                        ("?from=2026-10-20&to=2026-10-01", "bad_range"), ("?from=2020-01-01&to=2026-01-01", "bad_range"),
                        ("?from=yesterday", "bad_range")]:
            with self.subTest(q=q):
                self.assertJsonError(self.ab.get("/api/admin/incidents" + q), 400, code)

    def test_auth_parameters(self):
        self.assertIsInstance(self.assertJson(self.ab.get("/api/admin/auth?limit=10"), 200), dict)
        self.assertJsonError(self.ab.get("/api/admin/auth?result=accept"), 400, "bad_result")
        for limit in ["0", "501", "abc", "²", "٣", "-1", "1.5"]:
            with self.subTest(limit=limit):
                self.assertJsonError(self.ab.get("/api/admin/auth", params={"limit": limit}), 400, "bad_limit")
        self.assertJsonError(self.ab.get("/api/admin/auth?from=2026-01-01&to=2026-03-01"), 400, "bad_range")

    def test_raw_shows_revoked_devices(self):
        for dev in (self.dev, self.revoked):
            with self.subTest(dev=dev):
                self.assertIsInstance(self.assertJson(self.ab.get("/api/admin/devices/%s/raw" % dev), 200), dict)
        self.assertJsonError(self.ab.get("/api/admin/devices/%s/raw" % uuid.uuid4()), 404, "not_found")
        self.assertJsonError(self.ab.get("/api/admin/devices/%s/raw?from=2026-01-01&to=2026-03-01" % self.dev),
                             400, "bad_range")
        self.assertPage(self.ab.get("/admin/devices/" + self.revoked), 404)
