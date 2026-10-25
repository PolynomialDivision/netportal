"""The dashboard's routes (netportal/web.py) with Flask's test client: who may read which device,
JSON answers for the scripts (401 instead of the login redirect), the scripts' CSP only on the
dashboard pages. Registry mocked, Prometheus faked (tests/test_telemetry.py), templates mocked
(the pages' own tests are the frontend's). Example values only."""

import sys
import time
import unittest
from pathlib import Path
from unittest import mock

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_telemetry import MAC_A, MAC_B, FakeSession, live, row  # noqa: E402
from test_web import ADMIN_SUB, RESIDENT_SUB, FakeDb, example_settings  # noqa: E402

from netportal import config, telemetry, web  # noqa: E402

OTHER_SUB = "sub-other"
MINE, THEIRS = "00000000-0000-4000-8000-00000000000a", "00000000-0000-4000-8000-00000000000b"
DEVICES = {MINE: row(MINE, MAC_A.upper().replace(":", "-"), owner=RESIDENT_SUB, name="My phone"),
           THEIRS: row(THEIRS, MAC_B.upper().replace(":", "-"), owner=OTHER_SUB, name="Their laptop")}
PEOPLE = {RESIDENT_SUB: {"sub": RESIDENT_SUB, "username": "resident", "display": "Rea Resident"},
          OTHER_SUB: {"sub": OTHER_SUB, "username": "other", "display": "Otto Other"}}
DASHBOARD_CSP = "script-src 'self'; connect-src 'self'"


def find_devices(db, owner=None, include_revoked=False):
    return [d for d in DEVICES.values() if owner is None or d["owner"] == owner]


def find_claims(db, macs):
    """registry.mac_claims over DEVICES: the owners of active devices per normalised MAC."""
    claims = {}
    for d in DEVICES.values():
        mac = telemetry.normalise_mac(d["calling_station"])
        if mac in macs and not d["revoked"]:
            claims.setdefault(mac, set()).add(d["owner"])
    return claims


def find_device(db, device_id, owner=None):
    dev = DEVICES.get(str(device_id))
    return dev if dev and (owner is None or dev["owner"] == owner) else None


class DashboardApiCase(unittest.TestCase):
    def setUp(self):
        self.state = {RESIDENT_SUB: {"admin": False}, ADMIN_SUB: {"admin": True}, OTHER_SUB: {"admin": False}}
        self.render = mock.Mock(return_value="page")
        self.registry_rename = mock.Mock()
        patches = [
            mock.patch.object(web.enroll, "Issuer"),
            mock.patch.object(web.registry, "connect", return_value=FakeDb()),
            mock.patch.object(web.registry, "person_state", side_effect=lambda db, sub: self.state.get(sub)),
            mock.patch.object(web.registry, "devices", side_effect=find_devices),
            mock.patch.object(web.registry, "device", side_effect=find_device),
            mock.patch.object(web.registry, "people", return_value=PEOPLE),
            mock.patch.object(web.registry, "rename", self.registry_rename),
            mock.patch.object(web.registry, "mac_claims", side_effect=find_claims),
            mock.patch.object(web, "render_template", self.render),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.app = web.create_app(example_settings())
        self.session = FakeSession(live({MAC_A, MAC_B}))
        self.app.extensions["netportal"]["telemetry"] = telemetry.Prometheus(
            "http://prometheus.example:9090", 4, ssid="Example", session=self.session)
        self.client = self.app.test_client()

    def log_in(self, sub, login_at=None):
        with self.client.session_transaction() as sess:
            sess["user"] = {"sub": sub, "username": sub, "name": sub}
            sess["login_at"] = int(time.time()) if login_at is None else login_at
            sess["csrf"] = "example-csrf"

    def rendered(self, template):
        calls = [c for c in self.render.call_args_list if c.args[0] == template]
        self.assertTrue(calls, template)
        return calls[-1].kwargs


class OwnershipTests(DashboardApiCase):
    def test_a_resident_gets_their_devices_only(self):
        self.log_in(RESIDENT_SUB)
        resp = self.client.get("/api/devices")
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertEqual([d["id"] for d in body["devices"]], [MINE])
        self.assertEqual(body["telemetry"], "ok")
        self.assertEqual(body["devices"][0]["state"], "online")
        self.assertNotIn("owner", body["devices"][0])
        self.assertTrue(all(MAC_B not in q for q in self.session.queries()))   # not even asked about theirs

    def test_another_residents_device_is_not_found(self):
        self.log_in(RESIDENT_SUB)
        for url in ("/api/devices/%s/history" % THEIRS, "/api/devices/%s/history?range=7d" % THEIRS):
            resp = self.client.get(url)
            self.assertEqual(resp.status_code, 404, url)
            self.assertEqual(resp.get_json(), {"error": "not_found"})
        self.assertEqual(self.client.get("/devices/%s" % THEIRS).status_code, 404)
        self.assertTrue(all(MAC_B not in q for q in self.session.queries()))

    def test_own_history(self):
        self.log_in(RESIDENT_SUB)
        body = self.client.get("/api/devices/%s/history?range=7d" % MINE).get_json()
        self.assertEqual((body["range"], body["step_s"], body["telemetry"]), ("7d", 1800, "ok"))
        self.assertIn("online", body["series"])
        self.assertEqual(self.client.get("/api/devices/%s/history?range=1y" % MINE).get_json(), {"error": "bad_range"})

    def test_the_detail_page(self):
        self.log_in(RESIDENT_SUB)
        resp = self.client.get("/devices/%s" % MINE)
        self.assertEqual(resp.status_code, 200)
        ctx = self.rendered("device.html")
        self.assertEqual(ctx["device"]["id"], MINE)
        self.assertEqual(ctx["dashboard"]["devices"], [ctx["device"]])
        self.assertEqual(ctx["ranges"], ("24h", "7d", "30d"))

    def test_an_admin_reads_any_device(self):
        self.log_in(ADMIN_SUB)
        self.assertEqual(self.client.get("/api/devices/%s/history" % THEIRS).status_code, 200)
        self.assertEqual(self.client.get("/devices/%s" % THEIRS).status_code, 200)
        self.assertEqual(self.rendered("device.html")["device"]["owner"], {"username": "other", "display": "Otto Other"})
        body = self.client.get("/api/admin/devices").get_json()
        self.assertEqual({d["id"]: d["owner"]["username"] for d in body["devices"]}, {MINE: "resident", THEIRS: "other"})

    def test_admin_search_and_state(self):
        self.log_in(ADMIN_SUB)
        ids = lambda url: [d["id"] for d in self.client.get(url).get_json()["devices"]]  # noqa: E731
        self.assertEqual(ids("/api/admin/devices?q=otto"), [THEIRS])
        self.assertEqual(ids("/api/admin/devices?q=MY%20PHONE"), [MINE])
        self.assertEqual(ids("/api/admin/devices?q=" + MAC_B.upper().replace(":", "-")), [THEIRS])
        self.assertEqual(ids("/api/admin/devices?state=online"), [MINE])
        self.assertEqual(ids("/api/admin/devices?state=offline"), [THEIRS])
        self.assertEqual(len(ids("/api/admin/devices?state=nonsense")), 2)

    def test_the_admin_api_is_for_admins(self):
        self.log_in(RESIDENT_SUB)
        resp = self.client.get("/api/admin/devices")
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.get_json(), {"error": "forbidden"})

    def test_the_pages_get_the_dashboard(self):
        self.log_in(ADMIN_SUB)
        self.client.get("/")
        ctx = self.rendered("devices.html")
        self.assertEqual([d["id"] for d in ctx["dashboard"]["devices"]], [])          # the admin owns none
        self.assertIn("options", ctx)                                                  # the enrolment as before
        self.client.get("/admin")
        ctx = self.rendered("admin.html")
        self.assertEqual(len(ctx["dashboard"]["devices"]), 2)
        self.assertIn("people", ctx)                                                   # revoke, people as before

    def test_the_house(self):
        self.log_in(RESIDENT_SUB)
        house = self.client.get("/api/house").get_json()
        self.assertEqual(set(house), set(telemetry.empty_house()))
        self.assertEqual(house["internet"], "ok")


class OneDeviceTests(DashboardApiCase):
    """GET /api/devices/<id> and the detail page's history."""

    def test_own_device(self):
        self.log_in(RESIDENT_SUB)
        body = self.client.get("/api/devices/%s" % MINE).get_json()
        self.assertEqual(sorted(body), ["device", "generated_at", "house", "stale", "telemetry"])
        self.assertEqual((body["device"]["id"], body["device"]["state"], body["telemetry"]), (MINE, "online", "ok"))
        self.assertNotIn("owner", body["device"])

    def test_another_residents_or_a_revoked_device_is_not_found(self):
        self.log_in(RESIDENT_SUB)
        resp = self.client.get("/api/devices/%s" % THEIRS)
        self.assertEqual((resp.status_code, resp.get_json()), (404, {"error": "not_found"}))
        self.assertTrue(all(MAC_B not in q for q in self.session.queries()))
        with mock.patch.dict(DEVICES, {MINE: dict(DEVICES[MINE], revoked="2026-10-25")}):
            self.assertEqual(self.client.get("/api/devices/%s" % MINE).status_code, 404)
            self.assertEqual(self.client.get("/devices/%s" % MINE).status_code, 404)
        self.log_in(ADMIN_SUB)
        with mock.patch.dict(DEVICES, {THEIRS: dict(DEVICES[THEIRS], revoked="2026-10-25")}):
            self.assertEqual(self.client.get("/api/devices/%s" % THEIRS).status_code, 404)

    def test_an_admin_gets_any_device_with_its_owner(self):
        self.log_in(ADMIN_SUB)
        body = self.client.get("/api/devices/%s" % THEIRS).get_json()
        self.assertEqual(body["device"]["id"], THEIRS)
        self.assertEqual(body["device"]["owner"], {"username": "other", "display": "Otto Other"})

    def test_no_session(self):
        resp = self.client.get("/api/devices/%s" % MINE)
        self.assertEqual((resp.status_code, resp.get_json()), (401, {"error": "login_required"}))

    def test_the_detail_page_gets_the_history(self):
        self.log_in(RESIDENT_SUB)
        self.client.get("/devices/%s" % MINE)
        ctx = self.rendered("device.html")
        self.assertEqual((ctx["history"]["range"], ctx["history"]["telemetry"]), ("24h", "ok"))
        self.assertEqual(ctx["row"]["id"], MINE)
        self.client.get("/devices/%s?range=30d" % MINE)
        self.assertEqual(self.rendered("device.html")["history"]["range"], "30d")
        for bad in ("1y", "", "24h%27"):
            self.client.get("/devices/%s?range=%s" % (MINE, bad))
            self.assertEqual(self.rendered("device.html")["history"]["range"], "24h", bad)

    def test_the_detail_page_without_prometheus(self):
        self.session.fail = requests.ConnectionError("refused")
        self.log_in(RESIDENT_SUB)
        resp = self.client.get("/devices/%s?range=7d" % MINE)
        self.assertEqual(resp.status_code, 200)
        ctx = self.rendered("device.html")
        self.assertEqual((ctx["history"]["telemetry"], ctx["history"]["range"]), ("unavailable", "7d"))
        self.assertEqual(ctx["history"]["timeline"], [])
        self.assertEqual(ctx["dashboard"]["telemetry"], "unavailable")
        self.assertEqual(self.client.get("/api/devices/%s" % MINE).get_json()["telemetry"], "unavailable")

    def test_the_template_globals(self):
        self.assertIn("fmt", self.app.jinja_env.globals)
        self.assertIn("diagnoses", self.app.jinja_env.globals)


class SessionTests(DashboardApiCase):
    def test_no_session_answers_401_json(self):
        for url in ("/api/devices", "/api/house", "/api/admin/devices", "/api/devices/%s" % MINE,
                    "/api/devices/%s/history" % MINE):
            resp = self.client.get(url)
            self.assertEqual(resp.status_code, 401, url)
            self.assertEqual(resp.get_json(), {"error": "login_required"})
            self.assertNotIn("Location", resp.headers)

    def test_an_expired_session_answers_401_and_leaves_the_login_target_alone(self):
        self.log_in(RESIDENT_SUB, login_at=int(time.time()) - web.SESSION_MAX_SECONDS - 5)
        resp = self.client.get("/api/devices")
        self.assertEqual(resp.status_code, 401)
        with self.client.session_transaction() as sess:
            self.assertNotIn("next", sess)
            self.assertNotIn("user", sess)

    def test_an_offboarded_person_gets_401(self):
        self.log_in(RESIDENT_SUB)
        del self.state[RESIDENT_SUB]
        self.assertEqual(self.client.get("/api/devices").status_code, 401)

    def test_pages_still_go_to_the_login(self):
        resp = self.client.get("/devices/%s" % MINE)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/login", resp.headers["Location"])

    def test_unknown_api_path_is_json(self):
        self.log_in(RESIDENT_SUB)
        resp = self.client.get("/api/nothing")
        self.assertEqual((resp.status_code, resp.get_json()), (404, {"error": "not_found"}))


class RenameTests(DashboardApiCase):
    JSON = (("Accept", "application/json"),)

    def test_json_rename(self):
        self.log_in(RESIDENT_SUB)
        resp = self.client.post("/devices/%s/rename" % MINE, data={"csrf": "example-csrf", "name": " Kitchen tablet "},
                                headers=self.JSON)
        self.assertEqual((resp.status_code, resp.get_json()), (200, {"ok": True, "name": "Kitchen tablet"}))
        self.registry_rename.assert_called_once()
        self.assertEqual(self.registry_rename.call_args.args[2], "Kitchen tablet")

    def test_json_rename_refusals(self):
        self.log_in(RESIDENT_SUB)
        resp = self.client.post("/devices/%s/rename" % MINE, data={"csrf": "example-csrf", "name": "  "}, headers=self.JSON)
        self.assertEqual((resp.status_code, resp.get_json()), (400, {"ok": False, "name": "My phone"}))
        resp = self.client.post("/devices/%s/rename" % THEIRS, data={"csrf": "example-csrf", "name": "x"}, headers=self.JSON)
        self.assertEqual((resp.status_code, resp.get_json()), (404, {"error": "not_found"}))
        resp = self.client.post("/devices/%s/rename" % MINE, data={"csrf": "wrong", "name": "x"}, headers=self.JSON)
        self.assertEqual((resp.status_code, resp.get_json()), (400, {"error": "bad_request"}))
        self.registry_rename.assert_not_called()

    def test_json_rename_after_the_session_ended(self):
        self.log_in(RESIDENT_SUB, login_at=int(time.time()) - web.SESSION_MAX_SECONDS - 5)
        resp = self.client.post("/devices/%s/rename" % MINE, data={"csrf": "example-csrf", "name": "x"}, headers=self.JSON)
        self.assertEqual((resp.status_code, resp.get_json()), (401, {"error": "login_required"}))

    def test_the_form_still_redirects(self):
        self.log_in(RESIDENT_SUB)
        resp = self.client.post("/devices/%s/rename" % MINE, data={"csrf": "example-csrf", "name": "Kitchen tablet"},
                                headers={"Accept": "text/html,application/xhtml+xml,*/*;q=0.8"})
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp.headers["Location"], "/")


class CspTests(DashboardApiCase):
    def csp(self, url):
        return self.client.get(url).headers["Content-Security-Policy"]

    def test_scripts_only_on_the_dashboard_pages(self):
        self.log_in(ADMIN_SUB)
        for url in ("/", "/admin", "/devices/%s" % MINE):
            self.assertIn(DASHBOARD_CSP, self.csp(url), url)
            self.assertIn("default-src 'none'", self.csp(url))
        for url in ("/welcome", "/api/devices", "/api/house", "/devices/%s/nothing" % MINE, "/healthz"):
            self.assertNotIn("script-src", self.csp(url), url)
        resp = self.client.post("/devices/%s/rename" % MINE, data={"csrf": "example-csrf", "name": "x"})
        self.assertNotIn("script-src", resp.headers["Content-Security-Policy"])

    def test_the_default_csp_is_unchanged(self):
        self.assertEqual(self.csp("/welcome"), "default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; "
                                               "frame-ancestors 'none'; form-action 'self'")


class TelemetryStateTests(DashboardApiCase):
    def test_prometheus_down_is_not_an_error_page(self):
        self.session.fail = requests.ConnectionError("refused")
        self.log_in(RESIDENT_SUB)
        resp = self.client.get("/api/devices")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["telemetry"], "unavailable")
        self.assertEqual(resp.get_json()["devices"][0]["state"], "unknown")
        self.assertEqual(self.client.get("/api/devices/%s/history" % MINE).get_json()["telemetry"], "unavailable")
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_telemetry_off_without_a_prometheus_url(self):
        app = web.create_app(example_settings())
        self.assertIsNone(app.extensions["netportal"]["telemetry"])
        app = web.create_app(example_settings(prometheus_url="http://prometheus:9090", prometheus_timeout=2.5))
        prom = app.extensions["netportal"]["telemetry"]
        self.assertEqual((prom.url, prom.timeout), ("http://prometheus:9090", 2.5))
        client = app.test_client()
        app.extensions["netportal"]["telemetry"] = None
        self.log_in_on(client, RESIDENT_SUB)
        self.assertEqual(client.get("/api/devices").get_json()["telemetry"], "off")

    def log_in_on(self, client, sub):
        with client.session_transaction() as sess:
            sess["user"] = {"sub": sub, "username": sub, "name": sub}
            sess["login_at"] = int(time.time())

    def test_settings(self):
        self.assertEqual(config._prometheus_url("http://prometheus:9090/"), "http://prometheus:9090")
        self.assertEqual(config._prometheus_url(""), "")
        for bad in ("prometheus:9090", "ftp://prometheus", "http://a b", "javascript:alert(1)"):
            with self.assertRaises(RuntimeError):
                config._prometheus_url(bad)
        self.assertEqual(config.Settings.prometheus_timeout, 4.0)


SPOOF = "00000000-0000-4000-8000-00000000000c"


class SpoofedMacTests(DashboardApiCase):
    """Another resident enrols a device that logs in with the resident's MAC (H1)."""

    def setUp(self):
        super().setUp()
        spoof = row(SPOOF, MAC_A.lower(), owner=OTHER_SUB, name="Not my phone")
        patcher = mock.patch.dict(DEVICES, {SPOOF: spoof})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_neither_resident_sees_the_macs_data(self):
        for sub, device_id in ((RESIDENT_SUB, MINE), (OTHER_SUB, SPOOF)):
            self.log_in(sub)
            body = self.client.get("/api/devices/%s" % device_id).get_json()
            self.assertEqual(body["device"]["state"], "unknown", sub)
            self.assertEqual(body["device"]["diagnostics"], [{"code": "mac_conflict", "severity": "warn", "params": {}}])
            self.assertIsNone(body["device"]["ap"])
            h = self.client.get("/api/devices/%s/history?range=30d" % device_id).get_json()
            self.assertEqual((h["telemetry"], h["withheld"], h["timeline"]), ("ok", "mac_conflict", []))
            self.assertTrue(all(v == [] for v in h["series"].values()))
            self.client.get("/devices/%s" % device_id)
            self.assertEqual(self.rendered("device.html")["history"]["withheld"], "mac_conflict")
        self.assertTrue(all(MAC_A not in q for q in self.session.queries()))       # never asked

    def test_an_admin_sees_the_data_and_the_conflict(self):
        self.log_in(ADMIN_SUB)
        device = self.client.get("/api/devices/%s" % MINE).get_json()["device"]
        self.assertEqual(device["state"], "online")
        self.assertEqual(device["diagnostics"][0], {"code": "mac_conflict", "severity": "warn", "params": {"owners": 1}})
        h = self.client.get("/api/devices/%s/history" % MINE).get_json()
        self.assertIsNone(h["withheld"])
        listed = {d["id"]: d for d in self.client.get("/api/admin/devices").get_json()["devices"]}
        self.assertEqual(listed[SPOOF]["diagnostics"][0]["params"], {"owners": 1})

    def test_a_revoked_claim_is_no_conflict(self):
        DEVICES[SPOOF] = dict(DEVICES[SPOOF], revoked="2026-10-25")
        self.log_in(RESIDENT_SUB)
        self.assertEqual(self.client.get("/api/devices/%s" % MINE).get_json()["device"]["state"], "online")


class FirstSeenTests(DashboardApiCase):
    def test_the_history_starts_at_the_first_login_with_this_mac(self):
        import datetime
        utc = datetime.timezone.utc
        created, first = datetime.datetime(2026, 10, 1, tzinfo=utc), datetime.datetime(2026, 10, 20, tzinfo=utc)
        with mock.patch.dict(DEVICES, {MINE: dict(DEVICES[MINE], created=created, first_seen=first)}):
            self.log_in(RESIDENT_SUB)
            h = self.client.get("/api/devices/%s/history" % MINE).get_json()
        self.assertEqual(h["data_from"], int(first.timestamp()))


class ErrorShapeTests(DashboardApiCase):
    def test_api_errors_are_json(self):
        self.log_in(RESIDENT_SUB)
        resp = self.client.post("/api/devices", data={"csrf": "example-csrf"})
        self.assertEqual((resp.status_code, resp.get_json()), (405, {"error": "method_not_allowed"}))
        with mock.patch.object(web.telemetry, "dashboard", side_effect=RuntimeError("bug")):
            resp = self.client.get("/api/devices")
        self.assertEqual((resp.status_code, resp.get_json()), (500, {"error": "internal_error"}))

    def test_a_broken_prometheus_reply_is_unavailable_not_500(self):
        self.session.handlers.insert(0, ("^(timestamp(", {"resultType": "vector", "result": [{"metric": {}, "value": 7}]}))
        self.log_in(RESIDENT_SUB)
        resp = self.client.get("/api/devices")
        self.assertEqual((resp.status_code, resp.get_json()["telemetry"]), (200, "unavailable"))

    def test_pages_keep_their_error_pages(self):
        resp = self.client.delete("/welcome")
        self.assertEqual(resp.status_code, 405)
        self.assertNotEqual(resp.mimetype, "application/json")


class RenameRulesTests(DashboardApiCase):
    JSON = (("Accept", "application/json"),)

    def test_a_revoked_device_is_not_renamed(self):
        with mock.patch.dict(DEVICES, {MINE: dict(DEVICES[MINE], revoked="2026-10-25")}):
            self.log_in(RESIDENT_SUB)
            resp = self.client.post("/devices/%s/rename" % MINE, data={"csrf": "example-csrf", "name": "x"},
                                    headers=self.JSON)
            self.assertEqual((resp.status_code, resp.get_json()), (404, {"error": "not_found"}))
            resp = self.client.post("/devices/%s/rename" % MINE, data={"csrf": "example-csrf", "name": "x"})
            self.assertEqual(resp.status_code, 404)
        self.registry_rename.assert_not_called()

    def test_an_ended_session_is_401_before_the_csrf_check(self):
        # the session (and with it the CSRF token the page had) is gone: "log in again"
        resp = self.client.post("/devices/%s/rename" % MINE, data={"csrf": "from-the-old-page", "name": "x"},
                                headers=self.JSON)
        self.assertEqual((resp.status_code, resp.get_json()), (401, {"error": "login_required"}))
        self.log_in(RESIDENT_SUB, login_at=int(time.time()) - web.SESSION_MAX_SECONDS - 5)
        resp = self.client.post("/devices/%s/rename" % MINE, data={"csrf": "wrong", "name": "x"}, headers=self.JSON)
        self.assertEqual(resp.status_code, 401)
        self.registry_rename.assert_not_called()
        # logged in: a wrong token is still refused
        self.log_in(RESIDENT_SUB)
        resp = self.client.post("/devices/%s/rename" % MINE, data={"csrf": "wrong", "name": "x"}, headers=self.JSON)
        self.assertEqual(resp.status_code, 400)
        # a plain form after the session ended: the CSRF check as before
        with self.client.session_transaction() as sess:
            sess.clear()
        self.assertEqual(self.client.post("/devices/%s/rename" % MINE, data={"name": "x"}).status_code, 400)


if __name__ == "__main__":
    unittest.main()
