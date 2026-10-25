"""The dashboard's routes (netportal/web.py) with Flask's test client: who may read which device,
JSON answers for the scripts (401 instead of the login redirect), the scripts' CSP only on the
dashboard pages. Registry mocked, Prometheus faked (tests/test_telemetry.py), templates mocked
(the pages' own tests are the frontend's). Example values only."""

import datetime
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_telemetry import MAC_A, MAC_B, FakeSession, live, row  # noqa: E402
from test_telemetry_registry import FakeRegistry  # noqa: E402
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


EARLY = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)


class DevicesRegistry(FakeRegistry):
    """The registry's windows and conflicts over DEVICES, as it would make them from their logins:
    each device's MAC (calling_station) from its first login (or 2020) until now; another
    person's active device with the same MAC is a conflict for all that time."""

    def device_windows(self, db, device_ids, since=None, until=None):
        self.calls.append(("device_windows", tuple(str(i) for i in device_ids), since, until))
        out = {}
        for i in device_ids:
            d = DEVICES.get(str(i)) or {}
            mac = telemetry.normalise_mac(d.get("calling_station"))
            now = datetime.datetime.now(datetime.timezone.utc)
            # the device's only MAC, logged in just now: current, its window capped at now
            out[i] = [] if not mac else [{"mac": mac, "first_seen": d.get("first_seen") or EARLY, "last_seen": now,
                                          "window_end": now + web.registry.WINDOW_GRACE, "current": True,
                                          "randomized": telemetry.randomized(mac), "auth_count": 3}]
        return out

    def window_conflicts(self, db, device_ids, since=None, until=None):
        self.calls.append(("window_conflicts", tuple(str(i) for i in device_ids), since, until))
        out = {}
        for i in device_ids:
            d = DEVICES.get(str(i)) or {}
            mac = telemetry.normalise_mac(d.get("calling_station"))
            others = {o["owner"] for o in DEVICES.values() if o is not d and not o["revoked"]
                      and telemetry.normalise_mac(o["calling_station"]) == mac} - {d.get("owner")}
            out[i] = [{"mac": mac, "other_owners": len(others), "from": EARLY, "to": None}] if mac and others else []
        return out


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
            mock.patch.object(web, "render_template", self.render),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.registry = DevicesRegistry().patch(self)
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
        self.assertEqual(self.client.get("/api/devices/%s/history?range=2y" % MINE).get_json(), {"error": "bad_range"})

    def test_the_detail_page(self):
        self.log_in(RESIDENT_SUB)
        resp = self.client.get("/devices/%s" % MINE)
        self.assertEqual(resp.status_code, 200)
        ctx = self.rendered("device.html")
        self.assertEqual(ctx["device"]["id"], MINE)
        self.assertEqual(ctx["dashboard"]["devices"], [ctx["device"]])
        self.assertEqual(ctx["ranges"], ("24h", "7d", "30d", "90d", "1y", "all"))

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
        for bad in ("2y", "", "24h%27"):
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
            self.assertEqual([(f["code"], f["params"]) for f in body["device"]["diagnostics"]], [("mac_conflict", {})])
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
        self.assertEqual((device["diagnostics"][0]["code"], device["diagnostics"][0]["params"]),
                         ("mac_conflict", {"owners": 1}))
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


def utc(t):
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc)


class AdminApiTests(DashboardApiCase):
    """The admins' endpoints and pages: admin-only, JSON errors, the shapes D renders."""
    API = ("/api/admin/overview", "/api/admin/aps", "/api/admin/incidents", "/api/admin/auth",
           "/api/admin/devices/%s/raw" % THEIRS)
    PAGES = ("/admin/aps", "/admin/incidents", "/admin/devices/%s" % THEIRS)

    def setUp(self):
        super().setUp()
        now = time.time()
        self.registry.incident_rows = [
            {"id": 1, "kind": "ap_down", "subject": "60:22:32:37:48:00", "subject_name": "ap-scharni-2-corner",
             "started": utc(now - 600), "ended": None, "basis": "measured", "detail": {}},
            {"id": 2, "kind": "internet_down", "subject": "", "subject_name": None, "started": utc(now - 2 * 86400),
             "ended": utc(now - 2 * 86400 + 300), "basis": "measured", "detail": {"probe": "icmp"}}]
        self.registry.failures = [
            {"at": utc(now - 100), "reason": "revoked", "serial": "0a", "device_id": THEIRS, "owner": OTHER_SUB,
             "mac": MAC_B, "bssid": None, "ssid": "Example", "nas_ip": "10.0.10.27"},
            {"at": utc(now - 50), "reason": "no_cert", "serial": None, "device_id": None, "owner": None,
             "mac": "02:00:00:00:00:99", "bssid": None, "ssid": "Example", "nas_ip": None}]
        self.registry.jobs = [{"name": "rollup", "last_success": utc(now - 60), "last_attempt": utc(now - 60),
                               "last_error": None, "duration_s": 1.5, "cursor": {}},
                              {"name": "unifi_events", "last_success": utc(now - 3600), "last_attempt": utc(now - 60),
                               "last_error": "Loki: timeout", "duration_s": 10.0, "cursor": {"ts": 1}}]

    def test_residents_and_strangers_are_refused(self):
        for url in self.API:
            resp = self.client.get(url)
            self.assertEqual((resp.status_code, resp.get_json()), (401, {"error": "login_required"}), url)
        self.log_in(RESIDENT_SUB)
        for url in self.API:
            resp = self.client.get(url)
            self.assertEqual((resp.status_code, resp.get_json()), (403, {"error": "forbidden"}), url)
        for url in ("/admin",) + self.PAGES:
            self.assertEqual(self.client.get(url).status_code, 403, url)
        self.assertEqual(self.registry.called("auth_failures"), [])          # nothing read for them

    def test_overview(self):
        self.log_in(ADMIN_SUB)
        body = self.client.get("/api/admin/overview").get_json()
        self.assertEqual(set(body), {"generated_at", "telemetry", "stale", "house", "incidents", "aps", "auth", "jobs",
                                     "jobs_available", "freshness"})
        self.assertEqual([i["id"] for i in body["incidents"]["open"]], [1])
        self.assertEqual([i["id"] for i in body["incidents"]["recent"]], [2])
        self.assertEqual(body["incidents"]["counts_7d"], {"ap_down": 1, "internet_down": 1})
        self.assertEqual((body["auth"]["count"], body["auth"]["by_reason"]), (2, {"revoked": 1, "no_cert": 1}))
        self.assertEqual(body["auth"]["recent"][1]["owner"], {"username": "other", "display": "Otto Other"})
        self.assertEqual(body["auth"]["recent"][1]["device_id"], THEIRS)
        self.assertEqual([(j["name"], j["ok"]) for j in body["jobs"]], [("rollup", True), ("unifi_events", False)])
        self.assertTrue(body["jobs_available"])
        self.assertFalse(body["freshness"]["jobs_ok"])
        self.assertEqual(body["telemetry"], "ok")

    def test_a_failing_section_is_unavailable_not_an_error(self):
        self.log_in(ADMIN_SUB)
        with mock.patch.object(web.registry, "job_status", side_effect=RuntimeError("no table"), create=True):
            body = self.client.get("/api/admin/overview").get_json()
        self.assertEqual((body["jobs"], body["jobs_available"]), ([], False))
        self.assertTrue(body["incidents"]["available"])

    def test_aps(self):
        self.log_in(ADMIN_SUB)
        self.session.handlers[:0] = [
            ("unpoller_device_info", telemetry_vector(({"mac": "60:22:32:37:48:00", "name": "ap-scharni-2-corner",
                                                        "ip": "10.0.10.27", "model": "UAL6"}, 1),)),
            ("sum by (name) (unpoller_device_stations", telemetry_vector(({"name": "ap-scharni-2-corner"}, 12),))]
        body = self.client.get("/api/admin/aps").get_json()
        ap = body["aps"][0]
        self.assertEqual((ap["name"], ap["mac"], ap["clients"], ap["state"]), ("ap-scharni-2-corner", "60:22:32:37:48:00",
                                                                               12, "down"))
        self.assertEqual([i["id"] for i in ap["open_incidents"]], [1])
        self.assertEqual(ap["days"], [])
        self.assertEqual((ap["warnings"], ap["warning_details"][0]["code"]), (["down"], "down"))   # its open ap_down
        self.session.handlers.insert(0, ("max by (name) (unpoller_device_uptime_seconds",
                                         telemetry_vector(({"name": "ap-scharni-2-corner"}, 3600),)))
        self.session.handlers.insert(0, ("min by (name) (unpoller_device_uplink_speed_mbps",
                                         telemetry_vector(({"name": "ap-scharni-2-corner"}, 100),)))
        prom = self.app.extensions["netportal"]["telemetry"]
        prom._cache.clear()
        ap = self.client.get("/api/admin/aps").get_json()["aps"][0]
        self.assertEqual(ap["warnings"], ["down"])
        self.registry.incident_rows = self.registry.incident_rows[1:]                    # the AP is back
        ap = self.client.get("/api/admin/aps").get_json()["aps"][0]
        self.assertEqual(ap["warnings"], ["uplink", "restarted"])
        self.assertEqual(ap["warning_details"][0]["params"], {"uplink_mbps": 100})
        overview = self.client.get("/api/admin/overview").get_json()
        self.assertEqual(overview["aps"][0]["warnings"], ["uplink", "restarted"])

    def drop_outs(self):
        now = time.time()
        ev = lambda at, ap_mac, ap, kind="disconnected": {  # noqa: E731
            "at": utc(at), "kind": kind, "source": "unifi_syslog", "mac": MAC_B, "ap_mac": ap_mac, "ap_name": ap,
            "from_ap_mac": None, "from_ap_name": None, "ssid": "Example", "radio": "na", "channel": 36, "rssi": -60,
            "duration_s": None, "rx_bytes": None, "tx_bytes": None}
        self.registry.events = {
            THEIRS: [ev(now - 590, "60:22:32:37:48:00", "ap-scharni-2-corner"), ev(now - 2 * 86400 + 60, None, None)],
            MINE: [ev(now - 580, "68:d7:9a:1c:61:46", "ap-colbe-2-far"),                  # another AP
                   ev(now - 570, "60:22:32:37:48:00", "ap-scharni-2-corner", kind="connected")]}   # no drop-out

    def test_incident_devices(self):
        self.drop_outs()
        self.log_in(ADMIN_SUB)
        body = self.client.get("/api/admin/incidents").get_json()
        ap_down, internet = body["incidents"]
        self.assertEqual(ap_down["devices"], [{"id": THEIRS, "name": "Their laptop",
                                               "owner": {"username": "other", "display": "Otto Other"}}])
        self.assertEqual((ap_down["devices_truncated"], ap_down["devices_basis"]), (False, "inferred"))
        self.assertEqual([d["id"] for d in internet["devices"]], [THEIRS])               # house-wide: anyone's
        overview = self.client.get("/api/admin/overview").get_json()
        self.assertEqual([d["id"] for d in overview["incidents"]["open"][0]["devices"]], [THEIRS])
        # two registry queries per active device for the whole list, not per incident
        self.assertEqual(len(self.registry.called("connection_events")), 2 * 2)          # incidents + overview
        self.log_in(RESIDENT_SUB)
        self.assertEqual(self.client.get("/api/admin/incidents").status_code, 403)

    def test_incident_devices_bounded(self):
        self.drop_outs()
        self.log_in(ADMIN_SUB)
        with mock.patch.object(web.telemetry.admin, "INCIDENT_DEVICES_MAX", 0):
            body = self.client.get("/api/admin/incidents").get_json()
        self.assertEqual((body["incidents"][0]["devices"], body["incidents"][0]["devices_truncated"]), ([], True))
        with mock.patch.object(web.telemetry.admin, "DEVICES_SPAN_S", 3600):
            body = self.client.get("/api/admin/incidents").get_json()
        self.assertIsNone(body["incidents"][1]["devices"])                               # older: not computed

    def test_incidents_range_and_kind(self):
        self.log_in(ADMIN_SUB)
        body = self.client.get("/api/admin/incidents").get_json()
        self.assertEqual([i["id"] for i in body["incidents"]], [1, 2])
        self.assertEqual(body["incidents"][1]["duration_s"], 300)
        body = self.client.get("/api/admin/incidents?kind=ap_down").get_json()
        self.assertEqual([i["id"] for i in body["incidents"]], [1])
        since = int(time.time()) - 3600
        body = self.client.get("/api/admin/incidents?from=%d" % since).get_json()
        self.assertEqual([i["id"] for i in body["incidents"]], [1])
        self.assertEqual(len(self.client.get("/api/admin/incidents?range=1y").get_json()["incidents"]), 2)
        self.client.get("/admin/incidents?range=30d")
        ctx = self.rendered("admin_incidents.html")
        self.assertIn("ap_restarted", ctx["incident_kinds"])
        self.assertLess(web.parse_time(ctx["incidents"]["from"], 0), time.time() - 29 * 86400)
        body = self.client.get("/api/admin/incidents?from=2026-10-01&to=2026-10-02T00:00:00Z").get_json()
        self.assertEqual(body["from"], "2026-10-01T00:00:00+00:00")
        for bad, error in (("from=yesterday", "bad_range"), ("from=2020-01-01", "bad_range"),
                           ("from=2026-10-02&to=2026-10-01", "bad_range"), ("kind=AP%22", "bad_kind")):
            resp = self.client.get("/api/admin/incidents?" + bad)
            self.assertEqual((resp.status_code, resp.get_json()), (400, {"error": error}), bad)

    def test_auth(self):
        self.log_in(ADMIN_SUB)
        body = self.client.get("/api/admin/auth?result=reject").get_json()
        self.assertEqual([e["reason"] for e in body["events"]], ["no_cert", "revoked"])
        self.assertEqual(body["events"][1]["device_name"], "Their laptop")
        self.assertEqual(self.registry.called("auth_failures")[-1][3], 500)
        self.client.get("/api/admin/auth?limit=20")
        self.assertEqual(self.registry.called("auth_failures")[-1][3], 20)
        for bad, error in (("result=accept", "bad_result"), ("limit=0", "bad_limit"), ("limit=501", "bad_limit"),
                           ("limit=%C2%B2", "bad_limit"), ("limit=%D9%A3", "bad_limit"), ("limit=+5", "bad_limit"),
                           ("from=2026-01-01&to=2026-03-01", "bad_range")):     # "²" and "٣": isdigit, not ASCII
            resp = self.client.get("/api/admin/auth?" + bad)
            self.assertEqual((resp.status_code, resp.get_json()), (400, {"error": error}), bad)

    def test_raw(self):
        self.log_in(ADMIN_SUB)
        self.registry.auth = {THEIRS: [{"at": utc(time.time() - 60), "result": "accept", "reason": "ok", "mac": MAC_B,
                                        "bssid": None, "ssid": "Example", "nas_ip": "10.0.10.27"}]}
        body = self.client.get("/api/admin/devices/%s/raw" % THEIRS).get_json()
        self.assertEqual(set(body), {"device", "from", "to", "windows", "conflicts", "auth", "acct", "events", "days",
                                     "incidents", "limits", "truncated"})
        self.assertEqual(body["device"]["owner"], {"username": "other", "display": "Otto Other"})
        self.assertEqual(body["windows"][0]["mac"], MAC_B)
        self.assertEqual(body["auth"][0]["reason"], "ok")
        self.assertEqual(body["truncated"], {"auth": False, "acct": False, "events": False})
        resp = self.client.get("/api/admin/devices/00000000-0000-4000-8000-0000000000ff/raw")
        self.assertEqual((resp.status_code, resp.get_json()), (404, {"error": "not_found"}))
        resp = self.client.get("/api/admin/devices/%s/raw?from=2026-01-01&to=2026-03-01" % THEIRS)
        self.assertEqual(resp.status_code, 400)

    def test_pages_and_their_context(self):
        self.log_in(ADMIN_SUB)
        self.client.get("/admin")
        self.assertEqual(self.rendered("admin.html")["overview"]["incidents"]["open"][0]["id"], 1)
        self.assertEqual(self.client.get("/admin/aps").status_code, 200)
        self.assertIn("aps", self.rendered("admin_aps.html")["aps"])
        self.client.get("/admin/incidents?kind=ap_down")
        ctx = self.rendered("admin_incidents.html")
        self.assertEqual(([i["id"] for i in ctx["incidents"]["incidents"]], ctx["range"]["kind"]), ([1], "ap_down"))
        self.client.get("/admin/incidents?from=nonsense")                          # a page falls back to 7 days
        self.assertEqual(self.rendered("admin_incidents.html")["range"]["kind"], "")
        self.client.get("/admin/devices/%s" % THEIRS)
        ctx = self.rendered("device.html")
        self.assertTrue(ctx["admin_view"])
        self.assertEqual(ctx["raw"]["device"]["id"], THEIRS)
        self.assertEqual(ctx["device"]["id"], THEIRS)
        for url in ("/admin",) + self.PAGES:
            self.assertIn(DASHBOARD_CSP, self.client.get(url).headers["Content-Security-Policy"], url)
        for url in self.API:
            self.assertNotIn("script-src", self.client.get(url).headers["Content-Security-Policy"], url)


def telemetry_vector(*rows):
    from test_telemetry import vector
    return vector(*rows)


class BudgetSharingTests(DashboardApiCase):
    def test_the_device_page_has_one_budget_for_live_and_history(self):
        self.log_in(RESIDENT_SUB)
        prom = self.app.extensions["netportal"]["telemetry"]
        with mock.patch.object(prom, "within", wraps=prom.within) as within:
            self.assertEqual(self.client.get("/devices/%s?range=7d" % MINE).status_code, 200)
        self.assertEqual(within.call_count, 1)
        self.assertEqual(self.rendered("device.html")["history"]["telemetry"], "ok")

    def test_each_view_its_own(self):
        self.log_in(RESIDENT_SUB)
        prom = self.app.extensions["netportal"]["telemetry"]
        with mock.patch.object(prom, "within", wraps=prom.within) as within:
            self.client.get("/api/devices")
            self.client.get("/api/devices/%s/history" % MINE)
        self.assertEqual(within.call_count, 2)

    def test_long_ranges_come_from_the_rollups(self):
        self.log_in(RESIDENT_SUB)
        before = len([u for u, _p in self.session.calls if u.endswith("query_range")])
        body = self.client.get("/api/devices/%s/history?range=1y" % MINE).get_json()
        self.assertEqual((body["range"], body["step"]), ("1y", "day"))
        self.assertEqual(len([u for u, _p in self.session.calls if u.endswith("query_range")]), before)
        self.assertEqual(len(self.registry.called("device_days")), 1)


if __name__ == "__main__":
    unittest.main()
