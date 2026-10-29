"""Every route of INVENTORY 3.2 by who asks (anonymous, resident, admin, a refused person),
method handling (HEAD, OPTIONS, 405, the trailing slash) and the error bodies of 3.6."""

import uuid

from harness import (A, ContractCase, Person, admin_person, allow, enrol, newest_device,
                     resident)

UNKNOWN = str(uuid.uuid4())

# (method, path template, anonymous expectation) for every route of 3.2. {own}: a device of the
# resident, {other}: someone else's. "login": 302 /login; "login_json": 401 login_required.
ROUTES = [
    ("GET", "/devices/{own}", "login"),
    ("GET", "/download/not-a-token", "login"),
    ("GET", "/admin", "login"),
    ("GET", "/admin/aps", "login"),
    ("GET", "/admin/incidents", "login"),
    ("GET", "/admin/devices/{own}", "login"),
    ("GET", "/oauth/authorize?client_id=app.eduroam.geteduroam", "login"),
    ("GET", "/api/devices", "login_json"),
    ("GET", "/api/devices/{own}", "login_json"),
    ("GET", "/api/devices/{own}/history", "login_json"),
    ("GET", "/api/house", "login_json"),
    ("GET", "/api/admin/devices", "login_json"),
    ("GET", "/api/admin/overview", "login_json"),
    ("GET", "/api/admin/aps", "login_json"),
    ("GET", "/api/admin/incidents", "login_json"),
    ("GET", "/api/admin/auth", "login_json"),
    ("GET", "/api/admin/devices/{own}/raw", "login_json"),
]
# Form POSTs that need a login: with a valid CSRF token an anonymous browser goes to the login.
LOGIN_POSTS = ["/enroll", "/devices/{own}/renew", "/devices/{own}/rename", "/devices/{own}/revoke"]
ADMIN_PAGES = ["/admin", "/admin/aps", "/admin/incidents", "/admin/devices/{other}"]
ADMIN_APIS = ["/api/admin/devices", "/api/admin/overview", "/api/admin/aps", "/api/admin/incidents",
              "/api/admin/auth", "/api/admin/devices/{other}/raw"]


class RouteAuthTests(ContractCase):
    """INVENTORY 3.2 (auth column), 3.6, 4.3."""

    @classmethod
    def setUpClass(cls):
        cls.res, cls.other, cls.adm = resident("rta"), resident("rtb"), admin_person("rtc")
        cls.rb = A.browser().logged_in(cls.res)
        enrol(cls.rb, "apple", "mine")
        cls.own = str(newest_device(A, cls.res.sub)["id"])
        ob = A.browser().logged_in(cls.other)
        enrol(ob, "apple", "theirs")
        cls.theirs = str(newest_device(A, cls.other.sub)["id"])
        cls.ab = A.browser().logged_in(cls.adm)

    def fill(self, path):
        return path.format(own=self.own, other=self.theirs)

    def test_anonymous_get_routes(self):
        """3.2 rows 5-25, 27: login pages redirect to /login, the JSON API answers 401
        login_required (never a redirect)."""
        for method, path, want in ROUTES:
            with self.subTest(path=path):
                r = A.browser().request(method, self.fill(path))
                if want == "login":
                    self.assertToLogin(r)
                else:
                    self.assertJsonError(r, 401, "login_required")

    def test_anonymous_index_and_welcome(self):
        """3.2 rows 4, 5: / goes straight to /login (no button page); /welcome is public and
        links to /login."""
        self.assertToLogin(A.browser().get("/"))
        r = A.browser().get("/welcome")
        self.assertPage(r, 200, "/login")

    def test_anonymous_form_posts_go_to_the_login(self):
        """3.2 rows 7, 8, 10, 11 with a valid CSRF token and no login: 302 /login."""
        for path in LOGIN_POSTS:
            with self.subTest(path=path):
                b = A.browser()
                r = b.post(self.fill(path), data={"csrf": b.csrf(), "format": "apple", "name": "x"})
                self.assertToLogin(r)

    def test_anonymous_public_routes(self):
        """3.2 rows 1, 2, 3, 26, 28, 29, 30, 31, 32."""
        b = A.browser()
        r = b.get("/login")
        self.assertEqual(r.status_code, 302)
        self.assertTrue(r.headers["Location"].startswith("http://127.0.0.1:29000/application/o/authorize/"))
        self.assertPage(b.get("/auth/callback"), 400)                     # no pending login (state)
        self.assertPage(A.browser().post("/logout"), 400)                 # no CSRF token
        r = b.get("/.well-known/letswifi.json")
        self.assertEqual(r.status_code, 200)
        # 400 or 401: not pinned (README, "Deliberately not pinned"); RFC 6749 5.2 allows a 401 only
        # with WWW-Authenticate, which a public client cannot answer
        r = b.post("/oauth/token")
        self.assertIn(r.status_code, (400, 401))
        self.assertJsonError(r, r.status_code, "invalid_client")
        self.assertJsonError(b.post("/api/eap-config/"), 401, "invalid_token")
        r = b.get("/healthz")
        self.assertEqual((r.status_code, r.text.strip()), (200, "ok"))
        self.assertEqual(A.metrics()[0].status_code, 200)
        self.assertEqual(b.get("/static/style.css").status_code, 200)

    def test_metrics_are_not_on_the_public_listener(self):
        """Security review 2026-10-29 L6: /metrics has a listener of its own
        (NETPORTAL_METRICS_LISTEN); the portal's port, which Caddy forwards, does not serve it."""
        r = A.browser().get("/metrics")
        self.assertEqual(r.status_code, 404)
        self.assertNotIn("netportal_", r.text)
        self.assertEqual(A.metrics()[0].status_code, 200)

    def test_resident_pages(self):
        """3.2 rows 4-6, 16-19 for a resident; admin pages 403 (page), admin API 403 forbidden
        (4.3)."""
        for path in ["/", "/welcome", "/devices/{own}"]:
            with self.subTest(path=path):
                self.assertPage(self.rb.get(self.fill(path)), 200)
        for path in ["/api/devices", "/api/devices/{own}", "/api/devices/{own}/history", "/api/house"]:
            with self.subTest(path=path):
                r = self.rb.get(self.fill(path))
                self.assertEqual(r.status_code, 200, r.text[:200])
                self.assertJson(r, 200)
        for path in ADMIN_PAGES:
            with self.subTest(path=path):
                self.assertPage(self.rb.get(self.fill(path)), 403, "Something went wrong.")
        for path in ADMIN_APIS:
            with self.subTest(path=path):
                self.assertJsonError(self.rb.get(self.fill(path)), 403, "forbidden")

    def test_resident_cannot_see_someone_elses_device(self):
        """4.3: someone else's device is 404 for a resident on every device route."""
        theirs = self.theirs
        self.assertPage(self.rb.get("/devices/" + theirs), 404)
        self.assertJsonError(self.rb.get("/api/devices/" + theirs), 404, "not_found")
        self.assertJsonError(self.rb.get("/api/devices/%s/history" % theirs), 404, "not_found")
        csrf = self.rb.csrf()
        self.assertPage(self.rb.post("/devices/%s/renew" % theirs, data={"csrf": csrf}), 404)
        self.assertPage(self.rb.post("/devices/%s/revoke" % theirs, data={"csrf": csrf}), 404)
        self.assertPage(self.rb.post("/devices/%s/rename" % theirs, data={"csrf": csrf, "name": "x"}), 404)
        r = self.rb.post("/devices/%s/rename" % theirs, data={"csrf": csrf, "name": "x"},
                         headers={"Accept": "application/json"})
        self.assertJsonError(r, 404, "not_found")
        self.assertEqual(A.reg.device(theirs)["name"], "theirs")

    def test_unknown_device_ids(self):
        """3 (URL converters): an unknown UUID is 404; a non-UUID never matches (404)."""
        self.assertPage(self.ab.get("/devices/" + UNKNOWN), 404)
        self.assertJsonError(self.ab.get("/api/devices/" + UNKNOWN), 404, "not_found")
        self.assertJsonError(self.ab.get("/api/admin/devices/%s/raw" % UNKNOWN), 404, "not_found")
        self.assertPage(self.ab.get("/devices/not-a-uuid"), 404)
        self.assertJsonError(self.ab.get("/api/devices/1234"), 404, "not_found")
        self.assertPage(self.ab.get("/devices/" + self.own.upper()), 200)      # either case

    def test_admin_routes(self):
        """3.2 rows 12-25 for an admin; admins see any device (4.3)."""
        for path in ADMIN_PAGES + ["/devices/{other}"]:
            with self.subTest(path=path):
                self.assertPage(self.ab.get(self.fill(path)), 200)
        for path in ADMIN_APIS + ["/api/devices/{other}", "/api/devices/{other}/history"]:
            with self.subTest(path=path):
                r = self.ab.get(self.fill(path))
                self.assertEqual(r.status_code, 200, r.text[:200])
                self.assertJson(r, 200)

    def test_refused_person_stays_anonymous(self):
        """4.3/4.4: a person outside every policy and the admin groups is refused (403
        no_access) and stays anonymous everywhere."""
        b = A.browser()
        callback, _ = b.login(Person(["vpn-users"], "foreign"))
        self.assertPage(callback, 403, "Your account has no access to the house Wi-Fi.")
        self.assertToLogin(b.get("/"))
        self.assertToLogin(b.get("/admin"))
        self.assertJsonError(b.get("/api/devices"), 401, "login_required")


class MethodTests(ContractCase):
    """INVENTORY 3 (HEAD, OPTIONS, trailing slash) and 3.6 (405)."""

    @classmethod
    def setUpClass(cls):
        cls.rb = A.browser().logged_in(resident("mth"))

    def test_head(self):
        """HEAD answers like GET without a body (at least /healthz and the pages)."""
        b = A.browser()
        for path, status in [("/healthz", 200), ("/welcome", 200), ("/", 302), ("/.well-known/letswifi.json", 200)]:
            with self.subTest(path=path):
                r = b.request("HEAD", path)
                self.assertEqual(r.status_code, status)
                self.assertEqual(r.content, b"")
        r = self.rb.request("HEAD", "/")
        self.assertEqual((r.status_code, r.content), (200, b""))
        self.assertPage(r, 200)

    def test_options(self):
        """OPTIONS changes nothing; when answered with 2xx it lists the route's methods."""
        b = A.browser()
        for path, methods in [("/login", {"GET", "HEAD"}), ("/healthz", {"GET", "HEAD"}),
                              ("/oauth/token", {"POST"}), ("/api/eap-config/", {"POST"}),
                              ("/oauth/authorize", {"GET", "HEAD", "POST"}), ("/logout", {"POST"})]:
            with self.subTest(path=path):
                r = b.request("OPTIONS", path)
                self.assertIn(r.status_code, (200, 204, 405))
                self.assertEqual(allow(r) - {"OPTIONS"}, methods)

    def test_405_pages(self):
        """3.6, RFC 9110 15.5.6: a wrong method is 405 with an Allow header."""
        b = A.browser()
        for method, path, methods in [("GET", "/logout", {"POST", "OPTIONS"}), ("GET", "/enroll", {"POST", "OPTIONS"}),
                                      ("PUT", "/healthz", {"GET", "HEAD", "OPTIONS"}),
                                      ("GET", "/oauth/token", {"POST", "OPTIONS"})]:
            with self.subTest(path=path):
                r = b.request(method, path)
                self.assertEqual(r.status_code, 405)
                self.assertEqual(allow(r) - {"OPTIONS"}, methods - {"OPTIONS"})

    def test_405_json(self):
        """3.6: under /api/ the 405 is JSON method_not_allowed (GET /api/eap-config/ too, 3.5)."""
        self.assertJsonError(A.browser().get("/api/eap-config/"), 405, "method_not_allowed")
        self.assertJsonError(self.rb.request("DELETE", "/api/devices"), 405, "method_not_allowed")
        self.assertJsonError(self.rb.request("PUT", "/api/house"), 405, "method_not_allowed")

    def test_405_json_has_allow(self):
        """RFC 9110 15.5.6: every 405 names the allowed methods."""
        self.assertEqual(allow(A.browser().get("/api/eap-config/")) - {"OPTIONS"}, {"POST"})
        self.assertEqual(allow(self.rb.request("DELETE", "/api/devices")) - {"OPTIONS"}, {"GET", "HEAD"})

    def test_eap_config_without_trailing_slash(self):
        """3 (trailing slash): an app POSTing to /api/eap-config reaches the endpoint, by a 308
        to /api/eap-config/ (method and body kept) or by being served there directly."""
        r = A.browser().post("/api/eap-config", headers={"Authorization": "Bearer not-a-token"})
        if r.status_code == 308:
            self.assertRedirect(r, "/api/eap-config/", status=308)
        else:
            self.assertJsonError(r, 401, "invalid_token")


class ErrorResponseTests(ContractCase):
    """INVENTORY 3.6 and 4.7: JSON bodies for API requests, the message page otherwise."""

    def test_unknown_paths(self):
        self.assertPage(A.browser().get("/no-such-page"), 404, "Something went wrong.")
        self.assertJsonError(A.browser().get("/api/no-such-api"), 404, "not_found")

    def test_bad_request_page_and_json(self):
        person = resident("err")
        b = A.browser().logged_in(person)
        r = b.post("/enroll", data={"csrf": b.csrf(), "format": "windows"})
        self.assertPage(r, 400, "Something went wrong.")
        enrol(b, "apple")
        dev = str(newest_device(A, person.sub)["id"])
        r = b.post("/devices/%s/rename" % dev, data={"csrf": "wrong", "name": "x"},
                   headers={"Accept": "application/json"})
        self.assertJsonError(r, 400, "bad_request")

    def test_json_bodies_are_objects_with_one_key(self):
        """3.6: {"error": code} and nothing else, Content-Type application/json."""
        r = A.browser().get("/api/devices")
        self.assertEqual(self.assertJson(r, 401), {"error": "login_required"})
