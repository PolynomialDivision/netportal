"""Unit tests of the security-relevant pieces (no database, no network)."""

import base64
import hashlib
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from netportal import config, disconnect, i18n, offboarding, web  # noqa: E402


class RedirectTests(unittest.TestCase):
    sh = web.LETSWIFI_CLIENTS["app.geteduroam.sh"]
    android = web.LETSWIFI_CLIENTS["app.eduroam.geteduroam"]

    def test_loopback_any_port(self):
        self.assertTrue(web.redirect_allowed(self.sh, "http://127.0.0.1:43210/"))
        self.assertTrue(web.redirect_allowed(self.sh, "http://[::1]:5000/callback"))

    def test_refused(self):
        for uri in ("https://evil.example/", "http://127.0.0.1.evil.example/", "http://localhost:80/",
                    "http://10.0.0.1/", "app.eduroam.geteduroam:/", "javascript:alert(1)"):
            self.assertFalse(web.redirect_allowed(self.sh, uri), uri)

    def test_custom_scheme_exact(self):
        self.assertTrue(web.redirect_allowed(self.android, "app.eduroam.geteduroam:/"))
        self.assertFalse(web.redirect_allowed(self.android, "app.eduroam.geteduroam:/x"))
        self.assertFalse(web.redirect_allowed(self.android, "http://127.0.0.1/"))


class PkceTests(unittest.TestCase):
    def test_rfc7636_example(self):
        self.assertTrue(web.pkce_ok("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                                    "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"))

    def test_refused(self):
        self.assertFalse(web.pkce_ok("x" * 43, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"))
        self.assertFalse(web.pkce_ok("short", base64.urlsafe_b64encode(hashlib.sha256(b"short").digest())
                                     .rstrip(b"=").decode()))
        self.assertFalse(web.pkce_ok("", ""))


class PlatformTests(unittest.TestCase):
    def test_detection(self):
        cases = {
            "Mozilla/5.0 (iPhone; CPU iPhone OS 19_0 like Mac OS X)": ["apple"],
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_6)": ["apple-mac", "apple"],
            "Mozilla/5.0 (Linux; Android 16; Pixel 9)": ["android", "android-app"],
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)": ["windows"],
            "Mozilla/5.0 (X11; Linux x86_64)": ["linux"],
        }
        for ua, expected in cases.items():
            self.assertEqual(web.platform_of(ua), expected, ua)
        self.assertEqual(len(web.platform_of("curl/8")), 6)

    def test_passpoint_off_puts_the_app_first(self):
        android = "Mozilla/5.0 (Linux; Android 16; Pixel 9)"
        self.assertEqual(web.enrol_options(android, passpoint=False), ["android-app"])
        self.assertEqual(web.enrol_options(android, passpoint=True), ["android", "android-app"])
        self.assertNotIn("android", web.enrol_options("curl/8", passpoint=False))


class LanguageTests(unittest.TestCase):
    def test_pick(self):
        self.assertEqual(i18n.pick("de-DE,de;q=0.9,en;q=0.8"), "de")
        self.assertEqual(i18n.pick("uk"), "uk")
        self.assertEqual(i18n.pick("ru-RU"), "uk")
        self.assertEqual(i18n.pick("fr"), "en")
        self.assertEqual(i18n.pick(None), "en")

    def test_every_language_has_every_text(self):
        keys = set(i18n.TEXT["en"])
        for lang, text in i18n.TEXT.items():
            self.assertEqual(set(text), keys, lang)


class TextTests(unittest.TestCase):
    """Every text exists in every language with the same placeholders; the platform labels exist."""

    def test_same_keys_and_placeholders(self):
        import re
        self.assertEqual(sorted(i18n.TEXT["de"]), sorted(i18n.TEXT["en"]))
        self.assertEqual(sorted(i18n.TEXT["uk"]), sorted(i18n.TEXT["en"]))
        for key, value in i18n.TEXT["en"].items():
            for lang in ("de", "uk"):
                other = i18n.TEXT[lang][key]
                self.assertIs(type(other), type(value), key)
                if isinstance(value, list):
                    self.assertEqual(len(other), len(value), key)
                    value_text, other_text = " ".join(value), " ".join(other)
                else:
                    value_text, other_text = value, other
                self.assertEqual(sorted(re.findall(r"{\w+}", other_text)), sorted(re.findall(r"{\w+}", value_text)), (lang, key))
        for label in i18n.PLATFORM_LABEL.values():
            self.assertIn(label, i18n.TEXT["en"])


class DisconnectTests(unittest.TestCase):
    def test_packet(self):
        secret = b"s3cret"
        pkt = disconnect.build(7, secret, "anonymous@scharni.org", "02-00-00-00-00-01", "10.0.10.21")
        code, ident, length = struct.unpack("!BBH", pkt[:4])
        self.assertEqual((code, ident, length), (40, 7, len(pkt)))
        # Request Authenticator (RFC 5176 2.3) over the attributes as sent.
        self.assertEqual(pkt[4:20], hashlib.md5(pkt[:4] + b"\x00" * 16 + pkt[20:] + secret).digest())
        self.assertIn(b"anonymous@scharni.org", pkt)
        # Event-Timestamp (55), 4 octets, for access points that require it.
        stamped = disconnect.build(7, secret, "u", "02-00-00-00-00-01", "10.0.10.21", now=1760000000)
        self.assertIn(struct.pack("!BBI", 55, 6, 1760000000), stamped)

    def test_reply_check(self):
        secret = b"s3cret"
        req = disconnect.build(9, secret, "u", "02-00-00-00-00-01", "10.0.10.21")
        body = b""
        head = struct.pack("!BBH", 41, 9, 20)
        good = head + hashlib.md5(head + req[4:20] + body + secret).digest()
        self.assertTrue(disconnect.verify_reply(good, req, secret))
        self.assertFalse(disconnect.verify_reply(good, req, b"other"))
        self.assertFalse(disconnect.verify_reply(struct.pack("!BBH", 41, 8, 20) + good[4:], req, secret))

    def test_nothing_to_do(self):
        self.assertEqual(disconnect.disconnect(None, "x"), "skipped")
        self.assertEqual(disconnect.disconnect({"nas_ip": "1"}, ""), "skipped")

    def test_unusable_address_is_an_error_not_a_crash(self):
        # A session without NAS-IP-Address (or an IPv6 one) must not break the revocation.
        for nas_ip in ("", "fe80::1"):
            sess = {"nas_ip": nas_ip, "calling_station": "02-00-00-00-00-01", "user_name": "u"}
            self.assertEqual(disconnect.disconnect(sess, "x", timeout=0.1, retries=0), "error", nas_ip)


class OffboardSidecarTests(unittest.TestCase):
    """python -m netportal offboard touches its heartbeat after every round (the healthcheck)."""

    def run_once(self, run):
        import tempfile
        from unittest import mock
        from netportal import __main__ as cli
        with tempfile.TemporaryDirectory() as tmp:
            beat = Path(tmp) / "beat"
            with mock.patch.object(cli, "HEARTBEAT", str(beat)), \
                    mock.patch("netportal.config.load", return_value=object()), \
                    mock.patch("netportal.offboarding.run", side_effect=run) as mocked:
                rc = cli.main(["offboard"])
                return rc, beat.exists(), mocked.call_count

    def test_heartbeat_after_a_round(self):
        self.assertEqual(self.run_once(lambda settings: None), (0, True, 1))

    def test_heartbeat_even_when_the_round_fails(self):
        def boom(settings):
            raise RuntimeError("authentik down")
        self.assertEqual(self.run_once(boom), (1, True, 1))


class PolicyTests(unittest.TestCase):
    """NETPORTAL_POLICIES: which VLAN a person's devices go to (2026-10-22: guests)."""

    TEXT = "residents=30:residents,house-admins,it-admins; guests=50:former-residents"

    def settings(self, text=TEXT):
        import dataclasses
        fields = {f.name: None for f in dataclasses.fields(config.Settings) if f.default is dataclasses.MISSING}
        return config.Settings(**dict(fields, policies=config.parse_policies(text), admin_groups=frozenset({"it-admins"})))

    def test_parse(self):
        policies = config.parse_policies(self.TEXT)
        self.assertEqual([(p.name, p.vlan) for p in policies], [("residents", 30), ("guests", 50)])
        self.assertEqual(policies[1].groups, frozenset({"former-residents"}))
        for bad in ("", "residents=30", "residents=0:residents", "residents=4095:residents", "Residents=30:residents",
                    "residents=30:residents;residents=40:guests", "residents=30:residents;guests=50:residents",
                    "residents=30: , "):
            with self.assertRaises(RuntimeError, msg=bad):
                config.parse_policies(bad)

    def test_policy_for(self):
        s = self.settings()
        self.assertEqual(s.policy_for({"residents"}), "residents")
        self.assertEqual(s.policy_for({"former-residents"}), "guests")
        self.assertEqual(s.policy_for({"former-residents", "residents"}), "residents")   # moving out: the first
        self.assertEqual(s.policy_for({"it-admins"}), "residents")
        self.assertIsNone(s.policy_for({"vpn-users"}))
        self.assertIsNone(s.policy_for(set()))
        self.assertEqual(s.allowed_groups, {"residents", "house-admins", "it-admins", "former-residents"})

    def test_the_old_settings_give_one_policy(self):
        from unittest import mock
        env = {"NETPORTAL_DEFAULT_VLAN": "30", "NETPORTAL_ALLOWED_GROUPS": "residents,house-admins"}
        with mock.patch.dict("os.environ", env, clear=True), \
                mock.patch.object(config, "_env", side_effect=lambda name, default=None: env.get(name, default or "x")), \
                mock.patch.object(config, "_secret", return_value="x"), \
                mock.patch.object(config, "_device_ca_key", return_value=b"x"):
            policies = config.load().policies
        self.assertEqual(policies, (config.Policy("residents", 30, frozenset({"residents", "house-admins"})),))

    def test_offboarding_reads_the_policy_per_person(self):
        from unittest import mock
        users = [{"uid": "a", "is_active": True, "groups_obj": [{"name": "residents"}]},
                 {"uid": "f", "is_active": True, "groups_obj": [{"name": "former-residents"}]},
                 {"uid": "x", "is_active": False, "groups_obj": [{"name": "residents"}]},
                 {"uid": "v", "is_active": True, "groups_obj": [{"name": "vpn-users"}]}]
        reply = mock.Mock(**{"json.return_value": {"results": users, "pagination": {"next": 0}}})
        with mock.patch("netportal.offboarding.requests.get", return_value=reply):
            self.assertEqual(offboarding.allowed_subjects("http://ak/api/v3", "t", self.settings()),
                             {"a": "residents", "f": "guests"})


if __name__ == "__main__":
    unittest.main()
