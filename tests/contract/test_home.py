"""The home devices (house-infra docs/IOT-ACCESS.md 6.6): registration with the key and its QR
code, the claim of a join attempt, sharing and visibility, the rights of the owner, a sharee, a
stranger and an admin, the JSON API, the admin page, and the Wi-Fi area's move under /wifi."""

import uuid

from harness import A, ContractCase, admin_person, enrol, newest_device, register_home, resident

UNKNOWN = str(uuid.uuid4())


def fresh_mac(tag):
    return "3c:22:fb:%02x:%02x:%02x" % (tag % 256, (tag // 256) % 256, (tag // 65536) % 256)


class HomeDeviceTests(ContractCase):
    """IOT-ACCESS 6.6: the owner's pages and actions."""

    @classmethod
    def setUpClass(cls):
        cls.person = resident("hom")
        cls.b = A.browser().logged_in(cls.person)

    def test_register_without_an_address_then_claim(self):
        dev = register_home(self.b, "Living room TV", "tv")
        row = A.reg.home_device(dev)
        self.assertRegex(row["psk"], r"^[A-Za-z0-9]{20}$")
        self.assertIsNone(row["mac"])
        self.assertEqual((row["class"], row["visibility"]), ("tv", "private"))
        self.assertEqual(A.reg.device(dev)["platform"], "iot")
        self.assertEqual(A.reg.audit(dev), [(self.person.sub, "iot:register")])
        page = self.b.get("/home/devices/%s?key=1" % dev)
        self.assertPage(page, 200, '<code class="psk">%s</code>' % row["psk"])
        self.assertIn('<svg class="qr" aria-hidden="true"', page.text)
        self.assertIn('<details class="key-box" open>', page.text)
        self.assertIn("Scharni-IoT", page.text)
        # a join attempt is offered for the claim; the claim binds the address and consumes it
        mac = fresh_mac(1)
        A.reg.join_attempt(mac, tries=2)
        page = self.b.get("/home")
        self.assertPage(page, 200, mac)
        self.assertIn('action="/home/devices/%s/claim"' % dev, page.text)
        r = self.b.post("/home/devices/%s/claim" % dev, data={"csrf": self.b.csrf(), "mac": mac, "back": "/home"})
        self.assertRedirect(r, "/home")
        self.assertEqual(A.reg.home_device(dev)["mac"], mac)
        self.assertEqual(A.reg.audit(dev)[-1], (self.person.sub, "iot:claim"))
        self.assertNotIn("A device tried to join", self.b.get("/home").text)      # consumed

    def test_register_with_an_address_and_the_refusals(self):
        mac = fresh_mac(2)
        dev = register_home(self.b, "printer", "printer", "3C-22-FB-00-02-00")
        self.assertEqual(A.reg.home_device(dev)["mac"], "3c:22:fb:00:02:00")
        b = self.b
        r = b.post("/home/register", data={"csrf": b.csrf(), "name": "x", "class": "printer", "mac": "not-a-mac"})
        self.assertPage(r, 400, "That is not a hardware address")
        r = b.post("/home/register", data={"csrf": b.csrf(), "name": "x", "class": "printer", "mac": "3c:22:fb:00:02:00"})
        self.assertPage(r, 409, "registered for another device already")
        r = b.post("/home/register", data={"csrf": b.csrf(), "name": "x", "class": "toaster", "mac": mac})
        self.assertPage(r, 400, "Something went wrong.")
        self.assertPage(b.post("/home/register", data={"name": "x", "class": "cast"}), 400)   # no CSRF token
        dev = register_home(self.b, "", "speaker")
        self.assertEqual(A.reg.device(dev)["name"], "Speaker (%s)" % self.person.username)

    def test_rotate_rename_and_remove(self):
        dev = register_home(self.b, "speaker", "speaker", fresh_mac(3))
        before = A.reg.home_device(dev)["psk"]
        r = self.b.post("/home/devices/%s/rotate-key" % dev, data={"csrf": self.b.csrf()})
        self.assertRedirect(r, "/home/devices/%s?key=1" % dev)
        after = A.reg.home_device(dev)["psk"]
        self.assertNotEqual(before, after)
        self.assertIn(after, self.b.get("/home/devices/%s" % dev).text)
        r = self.b.post("/home/devices/%s/rename" % dev, data={"csrf": self.b.csrf(), "name": "  hall  "})
        self.assertRedirect(r, "/home/devices/%s" % dev)
        self.assertEqual(A.reg.device(dev)["name"], "hall")
        r = self.b.post("/home/devices/%s/rename" % dev, data={"csrf": self.b.csrf(), "name": "x"},
                        headers={"Accept": "application/json"})
        self.assertEqual(self.assertJson(r, 200), {"ok": True, "name": "x"})
        r = self.b.post("/home/devices/%s/remove" % dev, data={"csrf": self.b.csrf(), "back": "/home"})
        self.assertRedirect(r, "/home")
        self.assertTrue(A.reg.device(dev)["revoked"])
        self.assertEqual(A.reg.audit(dev)[-1], (self.person.sub, "iot:remove"))
        self.assertNotIn("disconnect:", " ".join(a for _, a in A.reg.audit(dev)))
        self.assertPage(self.b.get("/home/devices/%s" % dev), 404)
        self.assertJsonError(self.b.get("/api/home/devices/%s" % dev), 404, "not_found")


class SharingAndRightsTests(ContractCase):
    """IOT-ACCESS 6.6: the sharee's view (no key, no changes), the stranger's 404, the admin."""

    @classmethod
    def setUpClass(cls):
        cls.owner, cls.friend, cls.stranger, cls.adm = resident("sho"), resident("shf"), resident("shs"), admin_person("sha")
        cls.ob = A.browser().logged_in(cls.owner)
        cls.fb = A.browser().logged_in(cls.friend)
        cls.sb = A.browser().logged_in(cls.stranger)
        cls.ab = A.browser().logged_in(cls.adm)
        cls.dev = register_home(cls.ob, "kitchen cast", "cast", fresh_mac(10))
        r = cls.ob.post("/home/devices/%s/share" % cls.dev, data={"csrf": cls.ob.csrf(), "grantee": cls.friend.sub})
        assert r.status_code == 302, r.text[:200]

    def test_sharee_sees_the_device_without_the_key(self):
        psk = A.reg.home_device(self.dev)["psk"]
        page = self.fb.get("/home/devices/" + self.dev)
        self.assertPage(page, 200, "kitchen cast")
        self.assertIn(self.owner.name, page.text)
        self.assertNotIn(psk, page.text)
        self.assertNotIn('class="psk"', page.text)
        self.assertNotIn('<svg class="qr"', page.text)
        self.assertNotIn("/home/devices/%s/" % self.dev, page.text)
        self.assertIn("kitchen cast", self.fb.get("/home").text)
        one = self.assertJson(self.fb.get("/api/home/devices/" + self.dev), 200)
        self.assertEqual(one["device"]["role"], "shared")
        self.assertNotIn("psk", one["device"])
        self.assertNotIn("mac", one["device"])
        listed = self.assertJson(self.fb.get("/api/home/devices"), 200)
        self.assertEqual([d["id"] for d in listed["devices"]], [self.dev])
        self.assertNotIn(psk, self.fb.get("/api/home/devices").text)
        for action in ["claim", "rotate-key", "share", "unshare", "visibility", "rename", "remove"]:
            with self.subTest(action=action):
                data = {"csrf": self.fb.csrf(), "name": "x", "mac": fresh_mac(11), "visibility": "house",
                        "grantee": self.friend.sub}
                self.assertPage(self.fb.post("/home/devices/%s/%s" % (self.dev, action), data=data), 403)
        self.assertEqual(A.reg.device(self.dev)["name"], "kitchen cast")

    def test_stranger_gets_404(self):
        self.assertPage(self.sb.get("/home/devices/" + self.dev), 404)
        self.assertJsonError(self.sb.get("/api/home/devices/" + self.dev), 404, "not_found")
        self.assertNotIn("kitchen cast", self.sb.get("/home").text)
        data = {"csrf": self.sb.csrf(), "name": "x"}
        self.assertPage(self.sb.post("/home/devices/%s/rename" % self.dev, data=data), 404)
        # visible to the house: everyone with a policy reaches it
        r = self.ob.post("/home/devices/%s/visibility" % self.dev, data={"csrf": self.ob.csrf(), "visibility": "house"})
        self.assertRedirect(r, "/home/devices/" + self.dev)
        self.assertPage(self.sb.get("/home/devices/" + self.dev), 200, "kitchen cast")
        r = self.ob.post("/home/devices/%s/visibility" % self.dev, data={"csrf": self.ob.csrf(), "visibility": "private"})
        self.assertRedirect(r, "/home/devices/" + self.dev)
        self.assertPage(self.sb.get("/home/devices/" + self.dev), 404)

    def test_owner_api_and_shares(self):
        one = self.assertJson(self.ob.get("/api/home/devices/" + self.dev), 200)
        self.assertEqual(one["device"]["psk"], A.reg.home_device(self.dev)["psk"])
        self.assertEqual([s["sub"] for s in one["device"]["shares"]], [self.friend.sub])
        listed = self.assertJson(self.ob.get("/api/home/devices"), 200)
        own = [d for d in listed["devices"] if d["id"] == self.dev][0]
        self.assertEqual(own["role"], "owner")
        self.assertIn(own["sync"]["status"], ("pending", "failed"))     # the admin test may have run first
        self.assertNotIn("psk", own)
        self.assertEqual(self.ob.get("/api/home/devices").headers["Cache-Control"], "private, no-store")
        r = self.ob.post("/home/devices/%s/share" % self.dev, data={"csrf": self.ob.csrf(), "grantee": self.owner.sub})
        self.assertPage(r, 400)

    def test_admin_sees_everything_and_may_change_anything(self):
        A.reg.set_sync("unifi_key", self.dev, "applied")
        A.reg.set_sync("opnsense_alias", self.dev, "failed", "alias_util: 502")
        page = self.ab.get("/admin/home")
        self.assertPage(page, 200, "kitchen cast")
        self.assertIn(self.owner.name, page.text)
        self.assertIn("failed: alias_util: 502", page.text)
        self.assertIn('href="/admin/home" aria-current="page"', page.text)
        self.assertIn('href="/admin/home"', self.ab.get("/admin").text)
        body = self.assertJson(self.ab.get("/api/admin/home/devices"), 200)
        d = [d for d in body["devices"] if d["id"] == self.dev][0]
        self.assertEqual((d["owner"]["sub"], d["class"], d["sync"]["status"]), (self.owner.sub, "cast", "failed"))
        self.assertEqual(len(d["sync_targets"]), 2)
        self.assertNotIn("psk", d)
        self.assertIn("Firewall and Wi-Fi: failed: alias_util: 502", self.ob.get("/home").text)
        page = self.ab.get("/home/devices/%s?from=admin" % self.dev)
        self.assertPage(page, 200, A.reg.home_device(self.dev)["psk"])
        r = self.ab.post("/home/devices/%s/rename" % self.dev, data={"csrf": self.ab.csrf(), "name": "the cast"})
        self.assertRedirect(r, "/home/devices/" + self.dev)
        self.assertEqual(A.reg.device(self.dev)["name"], "the cast")
        r = self.ab.post("/home/devices/%s/rename" % self.dev, data={"csrf": self.ab.csrf(), "name": "kitchen cast"})
        self.assertRedirect(r, "/home/devices/" + self.dev)
        self.assertPage(self.ob.get("/admin/home"), 403)
        self.assertJsonError(self.ob.get("/api/admin/home/devices"), 403, "forbidden")


class AreasTests(ContractCase):
    """IOT-ACCESS 6.1: the overview, the Wi-Fi area under /wifi, the old device path's 308."""

    @classmethod
    def setUpClass(cls):
        cls.person = resident("are")
        cls.b = A.browser().logged_in(cls.person)
        enrol(cls.b, "apple", "old phone")
        cls.wifi = str(newest_device(A, cls.person.sub)["id"])
        cls.home = register_home(cls.b, "my cast", "cast", fresh_mac(20))

    def test_overview(self):
        page = self.b.get("/")
        self.assertPage(page, 200, "Network")
        self.assertIn('<nav class="main-nav"', page.text)
        self.assertIn("1 devices in the house Wi-Fi", page.text)
        self.assertIn("1 of your own", page.text)
        self.assertIn('href="/wifi#add"', page.text)
        self.assertIn('href="/home#add"', page.text)

    def test_wifi_area_keeps_its_flow(self):
        page = self.b.get("/wifi")
        self.assertPage(page, 200, 'action="/wifi/enroll"')
        self.assertIn("old phone", page.text)
        self.assertNotIn("my cast", page.text)
        self.assertIn('href="/wifi/devices/%s"' % self.wifi, page.text)
        ids = [d["id"] for d in self.assertJson(self.b.get("/api/devices"), 200)["devices"]]
        self.assertEqual(ids, [self.wifi])
        self.assertPage(self.b.get("/wifi/devices/" + self.home), 404)
        self.assertNotIn("old phone", self.b.get("/home").text)

    def test_old_device_path_redirects(self):
        for b in [A.browser(), self.b]:
            self.assertRedirect(b.get("/devices/" + self.wifi), "/wifi/devices/" + self.wifi, status=308)
        self.assertPage(A.browser().get("/devices/x"), 404)
        self.assertEqual(self.b.get("/devices/" + self.wifi, follow=True).status_code, 200)

    def test_metrics_have_the_home_families(self):
        m = A.metrics()[1]
        for family in ["netportal_iot_devices", "netportal_iot_shares", "netportal_iot_sync",
                       "netportal_iot_address_conflicts", "netportal_iot_backend_ok", "netportal_iot_join_attempts"]:
            with self.subTest(family=family):
                self.assertEqual(m["types"].get(family), "gauge")
