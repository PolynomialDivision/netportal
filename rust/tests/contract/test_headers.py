"""Security headers per response (INVENTORY 3.1, 3.4, 4.8) and static files (3.2 row 32)."""

from harness import A, ContractCase, admin_person, csp, download, enrol, resident

BASE = {"default-src": ["'none'"], "style-src": ["'self'"], "img-src": ["'self'"], "base-uri": ["'none'"],
        "frame-ancestors": ["'none'"], "form-action": ["'self'"]}
DASHBOARD = dict(BASE, **{"script-src": ["'self'"], "connect-src": ["'self'"]})


class HeaderTests(ContractCase):
    """INVENTORY 3.1 (response headers), 3.4 (CSP), 4.8 (security headers), 3.2 row 32 (static)."""

    @classmethod
    def setUpClass(cls):
        cls.person = resident("hdr")
        cls.b = A.browser().logged_in(cls.person)
        _, _, cls.dev = download(cls.b, "apple")
        cls.ab = A.browser().logged_in(admin_person("hdr"))

    def responses(self):
        """(label, response, expected CSP, expected Cache-Control)."""
        install, _ = enrol(self.b, "apple")
        anon = A.browser()
        return [
            ("start page", self.b.get("/"), DASHBOARD, "no-store"),
            ("device page", self.b.get("/devices/" + self.dev), DASHBOARD, "no-store"),
            ("admin", self.ab.get("/admin"), DASHBOARD, "no-store"),
            ("admin aps", self.ab.get("/admin/aps"), DASHBOARD, "no-store"),
            ("admin incidents", self.ab.get("/admin/incidents"), DASHBOARD, "no-store"),
            ("admin device", self.ab.get("/admin/devices/" + self.dev), DASHBOARD, "no-store"),
            ("welcome", anon.get("/welcome"), BASE, "no-store"),
            ("install page", install, BASE, "no-store"),
            ("404 page", anon.get("/nope"), BASE, "no-store"),
            ("403 page", self.b.get("/admin"), BASE, "no-store"),
            ("login redirect", anon.get("/"), BASE, "no-store"),
            ("JSON API", self.b.get("/api/house"), BASE, "no-store"),
            ("JSON error", anon.get("/api/devices"), BASE, "no-store"),
            ("discovery", anon.get("/.well-known/letswifi.json"), BASE, "no-store"),
            ("token endpoint", anon.post("/oauth/token"), BASE, "no-store"),
            ("healthz", anon.get("/healthz"), BASE, "no-store"),
        ]

    def test_csp_and_headers_per_response(self):
        """3.4: no script anywhere except the dashboard pages' own static scripts ('self',
        no inline, no eval); no framing; forms only to the portal. 4.8: nosniff,
        Referrer-Policy no-referrer, nothing personal cached."""
        for label, r, policy, cache in self.responses():
            with self.subTest(response=label):
                self.assertEqual(csp(r), policy)
                self.assertEqual(r.headers.get("X-Content-Type-Options"), "nosniff")
                self.assertEqual(r.headers.get("Referrer-Policy"), "no-referrer")
                self.assertEqual({p.strip() for p in r.headers.get("Cache-Control", "").split(",")},
                                 {p.strip() for p in cache.split(",")})

    def test_consent_page_allows_the_app_redirect(self):
        """3.4: only form-action differs on the consent page (the app's redirect target)."""
        r = self.b.get("/oauth/authorize", params={
            "client_id": "app.eduroam.geteduroam", "redirect_uri": "app.eduroam.geteduroam:/",
            "response_type": "code", "code_challenge": "x" * 43, "code_challenge_method": "S256"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(csp(r), dict(BASE, **{"form-action": sorted(["'self'", "app.eduroam.geteduroam:"])}))

    def test_downloads_have_the_headers_too(self):
        r, _, _ = download(self.b, "eap-config")
        self.assertEqual(csp(r), BASE)
        self.assertEqual(r.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertIn("no-store", r.headers.get("Cache-Control", ""))

    def test_static_files(self):
        """The dashboard's scripts are ES modules: browsers load them only with a JavaScript
        MIME type (and nosniff); the stylesheet as text/css."""
        for path, mime in [("/static/style.css", "text/css"), ("/static/dashboard.js", "text/javascript"),
                           ("/static/live.js", "text/javascript")]:
            with self.subTest(path=path):
                r = A.browser().get(path)
                self.assertEqual(r.status_code, 200)
                got = r.headers["Content-Type"].split(";")[0].strip().lower()
                if mime == "text/javascript":
                    self.assertIn(got, ("text/javascript", "application/javascript"))
                else:
                    self.assertEqual(got, mime)
                self.assertEqual(r.headers.get("X-Content-Type-Options"), "nosniff")
                self.assertEqual(csp(r), BASE)
        self.assertEqual(A.browser().get("/static/../web.py").status_code, 404)
        self.assertEqual(A.browser().get("/static/nope.js").status_code, 404)
