"""The resident's devices: enrolment (INVENTORY 3.2 row 7), one-time downloads (4.6, 6.4),
renewal (row 8, 6.2), rename (row 10), revocation with a Disconnect-Request to the access point
(row 11, 7.1)."""

import re
import time
import urllib.parse

from harness import (A, ANDROID_UA, B, FIREFOX_ANDROID_UA, IPHONE_UA, MAC_UA, ContractCase, admin_person, credentials_of, download, enrol,
                     newest_device, python_known_deviation, resident, sample, serial_hex)

FORMATS = {
    # format: (Content-Type, file extension or None, default name prefix)
    "apple": ("application/x-apple-aspen-config", ".mobileconfig", "iPhone/iPad"),
    "apple-mac": ("application/x-apple-aspen-config", ".mobileconfig", "Mac"),
    "android": ("application/x-wifi-config", None, "Android"),
    "eap-config": ("application/eap-config", ".eap-config", "Android"),
}


def api_device(browser, device_id):
    r = browser.get("/api/devices/" + device_id)
    return r.json()["device"] if r.status_code == 200 else None


class EnrolTests(ContractCase):
    """INVENTORY 3.2 row 7, 4.6."""

    @classmethod
    def setUpClass(cls):
        cls.person = resident("enr")
        cls.b = A.browser().logged_in(cls.person)

    def test_enrol_each_format(self):
        """POST /enroll: the install page with a one-time /download/<token> link (>= 256 bits,
        URL-safe), valid for 10 minutes; the device is listed under its default name."""
        for fmt, (_, _, prefix) in FORMATS.items():
            with self.subTest(fmt=fmt):
                r, token = enrol(self.b, fmt)
                self.assertPage(r, 200)
                self.assertRegex(token or "", r"^[A-Za-z0-9_-]{43,}$")
                expires_in = A.reg.download_expires_in(token)
                self.assertTrue(540 <= expires_in <= 600, expires_in)
                dev = newest_device(A, self.person.sub)
                self.assertEqual(dev["name"], "%s (%s)" % (prefix, self.person.username))
                listed = api_device(self.b, dev["id"])
                self.assertEqual(listed["name"], dev["name"])
                self.assertIn(("%s" % self.person.sub, "enrol:" + fmt), A.reg.audit(dev["id"]))

    def test_name_is_stripped_and_cut_to_60(self):
        enrol(self.b, "apple", "  " + "x" * 70 + "  ")
        self.assertEqual(newest_device(A, self.person.sub)["name"], "x" * 60)
        enrol(self.b, "apple", "  Küchen-iPad  ")
        self.assertEqual(newest_device(A, self.person.sub)["name"], "Küchen-iPad")

    def test_unknown_format_is_400(self):
        before = len(A.reg.devices(self.person.sub))
        for fmt in ["", "windows", "android-app", "letswifi", "APPLE"]:
            with self.subTest(fmt=fmt):
                r = self.b.post("/enroll", data={"csrf": self.b.csrf(), "format": fmt})
                self.assertPage(r, 400)
        self.assertEqual(len(A.reg.devices(self.person.sub)), before)

    def test_android_needs_passpoint(self):
        """NETPORTAL_PASSPOINT off (instance B): no Passpoint download, the option is not offered."""
        b = B.browser().logged_in(resident("np"))
        r = b.post("/enroll", data={"csrf": b.csrf(), "format": "android"})
        self.assertPage(r, 400)
        self.assertNotIn('value="android"', b.get("/").text)
        self.assertIn('value="android"', self.b.get("/").text)

    def test_recommended_format_per_platform(self):
        """3.2 enrolment options: the first (recommended) enrolment form fits the browser's platform;
        a Firefox on Android gets the app's eap-config first (it saves a Passpoint file instead of
        installing it)."""
        for ua, fmt in [(IPHONE_UA, "apple"), (MAC_UA, "apple-mac"), (ANDROID_UA, "android"),
                        (FIREFOX_ANDROID_UA, "eap-config")]:
            with self.subTest(fmt=fmt):
                page = A.browser(ua=ua).logged_in(resident("ua")).get("/").text
                first = re.search(r'name="format" value="([^"]+)"', page)
                self.assertEqual(first.group(1) if first else None, fmt)


class DownloadTests(ContractCase):
    """INVENTORY 4.6 (one-time tokens) and 6.4 (HTTP framing)."""

    @classmethod
    def setUpClass(cls):
        cls.person = resident("dl")
        cls.b = A.browser().logged_in(cls.person)

    def test_framing_per_format(self):
        """6.4: Content-Type per format; a file name (ASCII, from the display name) for the
        downloads saved as files; the Passpoint file without Content-Disposition and with a
        base64 body (Android's installer); never cached (it holds a private key)."""
        for fmt, (ctype, ext, _) in FORMATS.items():
            with self.subTest(fmt=fmt):
                r, cert, _ = download(self.b, fmt)
                self.assertEqual(r.headers["Content-Type"].split(";")[0].strip(), ctype)
                self.assertIn("no-store", r.headers.get("Cache-Control", ""))
                disposition = r.headers.get("Content-Disposition")
                if ext is None:
                    self.assertIsNone(disposition)
                    self.assertEqual(r.headers.get("Content-Transfer-Encoding"), "base64")
                    self.assertRegex(r.content, rb"^[A-Za-z0-9+/]+=*$")
                else:
                    self.assertEqual(disposition, 'attachment; filename="Scharni%s"' % ext)

    def test_file_name_from_the_default_display_name(self):
        """2.2 NETPORTAL_DISPLAY_NAME default Wi-Fi (instance B), ASCII file name."""
        b = B.browser().logged_in(resident("fn"))
        r, _, _ = download(b, "apple")
        self.assertEqual(r.headers["Content-Disposition"], 'attachment; filename="Wi-Fi.mobileconfig"')

    def test_token_works_once(self):
        _, token = enrol(self.b, "eap-config")
        self.assertEqual(self.b.get("/download/" + token).status_code, 200)
        self.assertPage(self.b.get("/download/" + token), 404)

    def test_someone_elses_token_is_refused_and_not_used_up(self):
        _, token = enrol(self.b, "apple")
        other = A.browser().logged_in(resident("dl2"))
        self.assertPage(other.get("/download/" + token), 404)
        self.assertEqual(self.b.get("/download/" + token).status_code, 200)

    def test_expired_token(self):
        _, token = enrol(self.b, "apple")
        A.reg.expire_download(token)
        self.assertPage(self.b.get("/download/" + token), 404)

    def test_unknown_token(self):
        self.assertPage(self.b.get("/download/" + "A" * 43), 404)

    def test_revoked_device_gives_no_artefact(self):
        _, token = enrol(self.b, "apple")
        dev = newest_device(A, self.person.sub)["id"]
        self.b.post("/devices/%s/revoke" % dev, data={"csrf": self.b.csrf()})
        self.assertPage(self.b.get("/download/" + token), 404)
        self.assertEqual(A.reg.credential_count(dev), 0)

    def test_every_download_is_a_new_certificate(self):
        """4.6/6.2: the key and certificate are made when the link is opened, recorded before
        the response; the registry knows the certificate as valid for that device."""
        r, cert, device_id = download(self.b, "apple")
        cred = A.reg.credential(cert)
        self.assertEqual(cred["device_id"], device_id)
        self.assertEqual(cred["status"], "valid")
        self.assertEqual(newest_device(A, self.person.sub)["id"], device_id)


class RenewTests(ContractCase):
    """INVENTORY 3.2 row 8, 6.2."""

    def renew(self, instance, overlap_days):
        person = resident("ren")
        b = instance.browser().logged_in(person)
        _, first, device_id = download(b, "apple")
        r = b.post("/devices/%s/renew" % device_id, data={"csrf": b.csrf()})
        self.assertPage(r, 200)
        token = re.search(r'href="/download/([^"]+)"', r.text).group(1)
        r = b.get("/download/" + token)
        second = credentials_of("apple", r.content)[1]
        self.assertNotEqual(serial_hex(first), serial_hex(second))
        self.assertEqual(second.subject, first.subject)                         # same device identity
        old, new = instance.reg.credential(first), instance.reg.credential(second)
        self.assertEqual((old["status"], new["status"]), ("valid", "valid"))    # overlap: both work for now
        self.assertAbout(old["retires_in_s"], overlap_days * 86400, 120)
        self.assertIsNone(new["retires_in_s"])
        self.assertIn((person.sub, "renew"), instance.reg.audit(device_id))
        self.assertEqual(len(instance.reg.devices(person.sub)), 1)

    def test_renew_keeps_the_device_and_overlaps(self):
        """NETPORTAL_RENEW_OVERLAP_DAYS default 2 (A) and 5 (B)."""
        self.renew(A, 2)
        self.renew(B, 5)

    def test_renew_revoked_or_foreign_is_404(self):
        person = resident("ren2")
        b = A.browser().logged_in(person)
        enrol(b, "apple")
        dev = newest_device(A, person.sub)["id"]
        other = A.browser().logged_in(resident("ren3"))
        self.assertPage(other.post("/devices/%s/renew" % dev, data={"csrf": other.csrf()}), 404)
        b.post("/devices/%s/revoke" % dev, data={"csrf": b.csrf()})
        self.assertPage(b.post("/devices/%s/renew" % dev, data={"csrf": b.csrf()}), 404)


class RenameTests(ContractCase):
    """INVENTORY 3.2 row 10."""

    @classmethod
    def setUpClass(cls):
        cls.person = resident("rn")
        cls.b = A.browser().logged_in(cls.person)
        enrol(cls.b, "apple", "before")
        cls.dev = newest_device(A, cls.person.sub)["id"]

    def rename(self, name, as_json=False):
        return self.b.post("/devices/%s/rename" % self.dev, data={"csrf": self.b.csrf(), "name": name},
                           headers={"Accept": "application/json"} if as_json else None)

    def test_form_rename(self):
        self.assertRedirect(self.rename("  phone  "), "/")
        self.assertEqual(api_device(self.b, self.dev)["name"], "phone")
        self.assertRedirect(self.rename("   "), "/")                    # empty: nothing changes
        self.assertEqual(api_device(self.b, self.dev)["name"], "phone")

    def test_json_rename(self):
        """The inline rename: {"ok", "name"} as stored; an empty name is 400 with the old name."""
        r = self.rename("y" * 65, as_json=True)
        self.assertEqual(self.assertJson(r, 200), {"ok": True, "name": "y" * 60})
        r = self.rename("", as_json=True)
        self.assertEqual(self.assertJson(r, 400), {"ok": False, "name": "y" * 60})
        self.assertEqual(api_device(self.b, self.dev)["name"], "y" * 60)


class RevokeTests(ContractCase):
    """INVENTORY 3.2 row 11, 7.1: revoked in the registry (every new authentication fails) and
    the running session cut with a Disconnect-Request the access point verifies."""

    def setUp(self):
        A.nas.reset("ack")
        self.person = resident("rv")
        self.b = A.browser().logged_in(self.person)
        _, self.cert, self.dev = download(self.b, "apple")

    def revoke(self, browser=None, **data):
        browser = browser or self.b
        return browser.post("/devices/%s/revoke" % self.dev, data=dict(data, csrf=browser.csrf()))

    def test_revoke_with_a_session_disconnects_it(self):
        A.reg.radius_session(self.dev, self.cert, calling="02:00:00:00:aa:42", user_name="anonymous@scharni.org")
        _, before = A.metrics()
        started = time.time()
        r = self.revoke()
        self.assertRedirect(r, "/")
        packets = A.nas.wait(1)
        self.assertEqual(len(packets), 1, packets)
        p = packets[0]
        self.assertTrue(p["valid"], p)                         # Request Authenticator and Message-Authenticator
        self.assertEqual(p["code"], 40)                        # Disconnect-Request
        attrs = {}
        for t, v in p["attrs"]:
            attrs.setdefault(t, []).append(v)
        self.assertEqual(attrs[1], [b"anonymous@scharni.org"])          # User-Name as recorded
        self.assertEqual(attrs[31], [b"02:00:00:00:aa:42"])             # Calling-Station-Id as the AP sent it
        self.assertEqual(attrs[4], [bytes([127, 0, 0, 1])])             # NAS-IP-Address
        event = int.from_bytes(attrs[55][0], "big")                     # Event-Timestamp (hostapd needs it)
        self.assertAbout(event, started, 60)
        self.assertEqual(len(attrs[80]), 1)                             # Message-Authenticator
        self.assertEqual(A.reg.credential(self.cert)["status"], "revoked")
        self.assertEqual(A.reg.audit(self.dev)[-2:], [(self.person.sub, "revoke"), (self.person.sub, "disconnect:ack")])
        _, after = A.metrics()
        self.assertEqual((sample(after, "netportal_disconnects_total", result="ack") or 0)
                         - (sample(before, "netportal_disconnects_total", result="ack") or 0), 1)
        self.assertEqual(self.b.get("/api/devices").json()["devices"], [])
        self.assertPage(self.b.get("/devices/" + self.dev), 404)

    def test_revoke_without_a_session(self):
        self.assertRedirect(self.revoke(), "/")
        self.assertEqual(A.nas.wait(1, timeout=1), [])
        self.assertEqual(A.reg.audit(self.dev)[-1], (self.person.sub, "disconnect:no-session"))
        self.assertEqual(A.reg.credential(self.cert)["status"], "revoked")

    def test_nak(self):
        A.nas.reset("nak")
        A.reg.radius_session(self.dev, self.cert)
        self.revoke()
        self.assertEqual(A.reg.audit(self.dev)[-1], (self.person.sub, "disconnect:nak"))

    def test_timeout_retries_with_the_same_identifier(self):
        """7.1: no answer -> retransmissions with the same Identifier (RFC 5080 2.2.1), then
        timeout; the revocation stands."""
        A.nas.reset("silent")
        A.reg.radius_session(self.dev, self.cert)
        self.revoke()
        packets = A.nas.received()
        self.assertGreaterEqual(len(packets), 2)
        self.assertEqual(len({p["identifier"] for p in packets}), 1)
        self.assertEqual(A.reg.audit(self.dev)[-1], (self.person.sub, "disconnect:timeout"))
        self.assertEqual(A.reg.credential(self.cert)["status"], "revoked")

    def test_twice_is_404(self):
        self.revoke()
        self.assertPage(self.revoke(), 404)

    def test_back_is_only_honoured_for_admin(self):
        r = self.revoke(back="https://evil.example/")
        self.assertRedirect(r, "/")
        self.assertFalse(urllib.parse.urlsplit(r.headers["Location"]).netloc not in ("", "127.0.0.1:28080"))

    def test_admin_revokes_someone_elses_device(self):
        A.reg.radius_session(self.dev, self.cert)
        adm = admin_person("rva")
        ab = A.browser().logged_in(adm)
        self.assertRedirect(self.revoke(ab, back="/admin"), "/admin")
        self.assertEqual(A.reg.audit(self.dev)[-2:], [(adm.sub, "revoke"), (adm.sub, "disconnect:ack")])


class LimitTests(ContractCase):
    """Security review 2026-10-29 L5: per-person limits (NETPORTAL_MAX_DEVICES active devices,
    10 new devices an hour, 30 certificates a day)."""

    @python_known_deviation("no limit: one person can create any number of devices and certificates")
    def test_enrolment_rate(self):
        b = A.browser().logged_in(resident("rate"))
        for i in range(10):
            r, token = enrol(b, "apple", "d%d" % i)
            self.assertEqual(r.status_code, 200, i)
            self.assertIsNotNone(token)
        r, token = enrol(b, "apple", "one too many")
        self.assertPage(r, 429, "Too many new devices or downloads in a short time.")
        self.assertIsNotNone(r.headers.get("Retry-After"))
        self.assertIsNone(token)
