"""The portal's session rules with Flask's test client (registry and PKI mocked, no database):
admin rights from the registry on every request, an absolute session age, the house language
cookie, the house bar. Example values only."""

import dataclasses
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from netportal import config, i18n, offboarding, web  # noqa: E402

ADMIN_SUB, RESIDENT_SUB = "sub-admin", "sub-resident"


def example_settings(**overrides):
    fields = {f.name: None for f in dataclasses.fields(config.Settings) if f.default is dataclasses.MISSING}
    fields.update(base_url="http://wifi.example.org", realm="example.org", ssid="Example", display_name="Example",
                  database_url="postgresql://example", session_secret="example-session-secret-0123456789",
                  oidc_issuer="http://login.example.org/application/o/netportal/", oidc_client_id="netportal",
                  oidc_client_secret="example", policies=config.parse_policies("residents=30:residents"),
                  admin_groups=frozenset({"it-admins"}))
    fields.update(overrides)
    return config.Settings(**fields)


class FakeDb:
    def execute(self, *a, **k):
        return mock.Mock(fetchone=lambda: None)

    def commit(self):
        pass

    def close(self):
        pass


class PortalTestCase(unittest.TestCase):
    def setUp(self):
        self.state = {}                    # sub -> {"admin": bool}; missing = offboarded / unknown
        patches = [
            mock.patch.object(web.enroll, "Issuer"),
            mock.patch.object(web.registry, "connect", return_value=FakeDb()),
            mock.patch.object(web.registry, "person_state", side_effect=lambda db, sub: self.state.get(sub)),
            mock.patch.object(web.registry, "devices", return_value=[]),
            mock.patch.object(web.registry, "people", return_value={}),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.settings = example_settings()
        self.app = web.create_app(self.settings)
        self.client = self.app.test_client()

    def log_in(self, sub, login_at=None, **extra):
        with self.client.session_transaction() as sess:
            sess["user"] = {"sub": sub, "username": sub, "name": sub, **extra}
            sess["login_at"] = int(time.time()) if login_at is None else login_at
            sess["csrf"] = "example-csrf"
            sess.permanent = True


class AdminRightsTests(PortalTestCase):
    def test_admin_from_the_registry(self):
        self.state[ADMIN_SUB] = {"admin": True}
        self.log_in(ADMIN_SUB)
        self.assertEqual(self.client.get("/admin").status_code, 200)

    def test_removed_from_the_admin_group_loses_admin_at_once(self):
        self.state[ADMIN_SUB] = {"admin": True}
        self.log_in(ADMIN_SUB)
        self.assertEqual(self.client.get("/admin").status_code, 200)
        self.state[ADMIN_SUB] = {"admin": False}           # the offboarding round saw the change
        self.assertEqual(self.client.get("/admin").status_code, 403)
        page = self.client.get("/").get_data(as_text=True)
        self.assertNotIn('href="/admin"', page)

    def test_the_cookie_cannot_claim_admin(self):
        self.state[RESIDENT_SUB] = {"admin": False}
        self.log_in(RESIDENT_SUB, admin=True)               # an old cookie still saying admin
        self.assertEqual(self.client.get("/admin").status_code, 403)

    def test_admin_can_revoke_others_only_while_admin(self):
        self.state[ADMIN_SUB] = {"admin": False}
        self.log_in(ADMIN_SUB)
        with mock.patch.object(web.registry, "device", return_value=None) as device:
            self.client.post("/devices/00000000-0000-4000-8000-000000000001/revoke", data={"csrf": "example-csrf"})
        self.assertEqual(device.call_args.kwargs["owner"], ADMIN_SUB)  # only their own devices

    def test_offboarded_goes_to_the_login(self):
        self.log_in(ADMIN_SUB)                              # not in the registry (offboarded)
        resp = self.client.get("/admin")
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/login", resp.headers["Location"])


class SessionAgeTests(PortalTestCase):
    def test_fresh(self):
        now = 1_800_000_000
        self.assertTrue(web.session_fresh(now - 60, now))
        self.assertTrue(web.session_fresh(now - web.SESSION_MAX_SECONDS + 1, now))
        self.assertFalse(web.session_fresh(now - web.SESSION_MAX_SECONDS, now))
        self.assertFalse(web.session_fresh(now + 60, now))   # from the future
        self.assertFalse(web.session_fresh(None, now))       # from before the limit existed
        self.assertFalse(web.session_fresh("1", now))

    def test_an_old_login_ends_however_busy(self):
        self.state[ADMIN_SUB] = {"admin": True}
        self.log_in(ADMIN_SUB, login_at=int(time.time()) - web.SESSION_MAX_SECONDS - 5)
        resp = self.client.get("/admin")
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/login", resp.headers["Location"])

    def test_a_form_sent_after_the_limit_goes_to_the_login(self):
        self.state[RESIDENT_SUB] = {"admin": False}
        self.log_in(RESIDENT_SUB, login_at=int(time.time()) - web.SESSION_MAX_SECONDS - 5)
        resp = self.client.post("/enroll", data={"csrf": "example-csrf", "format": "apple"})
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/login", resp.headers["Location"])

    def test_the_login_records_its_time_and_the_rights_go_to_the_registry(self):
        claims = {"sub": ADMIN_SUB, "preferred_username": "admin", "name": "Admin", "groups": ["it-admins"]}
        with mock.patch("authlib.integrations.flask_client.apps.FlaskOAuth2App.authorize_access_token",
                        return_value={"userinfo": claims}), \
                mock.patch.object(web.registry, "upsert_person") as upsert, \
                mock.patch.object(web.registry, "set_policy", return_value=[]):
            resp = self.client.get("/auth/callback")
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(upsert.call_args.kwargs["admin"])
        with self.client.session_transaction() as sess:
            self.assertNotIn("admin", sess["user"])
            self.assertLessEqual(abs(sess["login_at"] - time.time()), 5)


class HouseLookTests(PortalTestCase):
    def test_house_lang_cookie_wins_over_the_browser(self):
        self.client.set_cookie("house_lang", "uk")
        page = self.client.get("/welcome", headers={"Accept-Language": "de"}).get_data(as_text=True)
        self.assertIn('<html lang="uk">', page)

    def test_unknown_cookie_falls_back_to_the_browser(self):
        self.client.set_cookie("house_lang", "xx")
        page = self.client.get("/welcome", headers={"Accept-Language": "de"}).get_data(as_text=True)
        self.assertIn('<html lang="de">', page)

    def test_kit_and_house_bar(self):
        page = self.client.get("/welcome").get_data(as_text=True)
        self.assertIn('href="/_house/ui.css"', page)
        self.assertLess(page.index("/_house/ui.css"), page.index("style.css"))
        self.assertIn('<nav class="h-bar"', page)
        self.assertIn('href="https://example.org/"', page)

    def test_home_url_setting(self):
        self.assertEqual(example_settings(home_url="https://home.example.org/").home, "https://home.example.org/")
        self.assertEqual(example_settings().home, "https://example.org/")

    def test_pick(self):
        self.assertEqual(i18n.pick("de", "en"), "en")
        self.assertEqual(i18n.pick("de", "uk"), "uk")
        self.assertEqual(i18n.pick("de", ""), "de")
        self.assertEqual(i18n.pick("de", "ru"), "de")       # only the house's own codes


class OffboardingAdminTests(unittest.TestCase):
    """The offboarding round keeps the stored admin flag in line with the directory."""

    def test_directory_reads_admins(self):
        users = [{"uid": "a", "is_active": True, "groups_obj": [{"name": "it-admins"}]},
                 {"uid": "r", "is_active": True, "groups_obj": [{"name": "residents"}]},
                 {"uid": "x", "is_active": False, "groups_obj": [{"name": "it-admins"}]}]
        reply = mock.Mock(**{"json.return_value": {"results": users, "pagination": {"next": 0}}})
        settings = example_settings(policies=config.parse_policies("residents=30:residents"))
        with mock.patch("netportal.offboarding.requests.get", return_value=reply):
            allowed, admins = offboarding.read_directory("http://ak.example/api/v3", "t", settings)
        self.assertEqual(allowed, {"a": "residents", "r": "residents"})
        self.assertEqual(admins, {"a"})

    def test_run_sets_the_flag_per_person(self):
        settings = example_settings(authentik_api="http://ak.example/api/v3", authentik_token="t")
        db = mock.MagicMock()
        db.__enter__.return_value = db
        with mock.patch.object(offboarding, "read_directory", return_value=({"a": "residents", "r": "residents"}, {"a"})), \
                mock.patch.object(offboarding.registry, "connect", return_value=db), \
                mock.patch.object(offboarding.registry, "subjects_to_check", return_value={"a", "r"}), \
                mock.patch.object(offboarding.registry, "set_admin") as set_admin, \
                mock.patch.object(offboarding.registry, "prune"), \
                mock.patch.object(offboarding.registry, "mark_job"), \
                mock.patch.object(offboarding.web, "apply_policy", return_value=0):
            offboarding.run(settings)
        self.assertEqual(sorted(c.args[1:] for c in set_admin.call_args_list), [("a", True), ("r", False)])


if __name__ == "__main__":
    unittest.main()
