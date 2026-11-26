"""The session cookie (INVENTORY 4.1) and CSRF (4.2, 3.1).

Not black-box testable (the portal's clock cannot be moved from outside): that the server itself refuses a
session idle for 8 h (not only the browser dropping the cookie) and the 12 h absolute limit
after the login; see README."""

import email.utils
import time

from harness import (A, B, SESSION_IDLE_S, ContractCase, cookie_expired, enrol, form_csrf, meta_csrf,
                     newest_device, resident, set_cookies)


def portal_cookies(resp):
    """The cookies the portal sets in this response (the session; its name is free over http)."""
    return [c for c in set_cookies(resp) if not cookie_expired(c)]


def expiry(cookie):
    """Seconds until the cookie expires (Max-Age wins over Expires), None for a browser-session cookie."""
    a = cookie["attrs"]
    if "max-age" in a:
        return int(a["max-age"])
    if "expires" in a:
        return email.utils.parsedate_to_datetime(a["expires"]).timestamp() - time.time()
    return None


class CookieTests(ContractCase):
    """INVENTORY 4.1: the session cookie's security attributes and the 8 h idle lifetime."""

    def check_attrs(self, cookie, secure):
        a = cookie["attrs"]
        self.assertIs(a.get("httponly"), True, cookie)
        self.assertEqual(a.get("path"), "/", cookie)
        # Lax, not Strict: the login comes back from the identity provider as a cross-site navigation
        self.assertEqual(str(a.get("samesite", "")).lower(), "lax", cookie)
        self.assertNotIn("domain", a, cookie)
        if secure:
            self.assertIs(a.get("secure"), True, cookie)
            self.assertTrue(cookie["name"].startswith("__Host-"), cookie)
        else:
            self.assertNotIn("secure", a, cookie)          # a Secure cookie would never come back over http

    def test_first_page_sets_the_session_cookie(self):
        """3.1/4.2: the first page carries a CSRF token, so it sets the session cookie."""
        r = A.browser().get("/welcome")
        cookies = portal_cookies(r)
        self.assertEqual(len(cookies), 1, r.headers)
        self.check_attrs(cookies[0], secure=False)

    def test_https_base_url_uses_a_host_prefixed_secure_cookie(self):
        """4.1: NETPORTAL_BASE_URL https:// -> a __Host- cookie: Secure, Path=/, no Domain."""
        cookies = portal_cookies(B.browser().get("/welcome"))
        self.assertEqual(len(cookies), 1)
        self.check_attrs(cookies[0], secure=True)

    def test_login_makes_the_cookie_last_eight_hours_idle(self):
        """4.1: after the login the cookie expires 8 h after the last request (sliding: an
        authenticated request re-sends it with a new expiry)."""
        b = A.browser()
        callback, _ = b.login(resident("ck"))
        cookies = portal_cookies(callback)
        self.assertEqual(len(cookies), 1)
        self.check_attrs(cookies[0], secure=False)
        self.assertAbout(expiry(cookies[0]), SESSION_IDLE_S, 120)
        time.sleep(1.1)
        for path in ["/", "/api/devices"]:
            with self.subTest(path=path):
                cookies = portal_cookies(b.get(path))
                self.assertEqual(len(cookies), 1, "the idle expiry must move with the request")
                self.assertAbout(expiry(cookies[0]), SESSION_IDLE_S, 120)

    def test_secure_cookie_after_login(self):
        b = B.browser()
        callback, final = b.login(resident("cks"))
        self.assertEqual(final.status_code, 200)
        cookies = portal_cookies(callback)
        self.assertEqual(len(cookies), 1)
        self.check_attrs(cookies[0], secure=True)
        self.assertAbout(expiry(cookies[0]), SESSION_IDLE_S, 120)

    def test_login_rotates_the_session(self):
        """4.1 rotation (no session fixation): the cookie value and the CSRF token change at
        the login; the token from before no longer works (14.5: CSRF rotation)."""
        b = A.browser()
        before = b.csrf()
        cookie_before = dict(b.cookies)
        b.login(resident("rot"))
        after = b.csrf()
        self.assertTrue(before and after)
        self.assertNotEqual(before, after)
        self.assertNotEqual(cookie_before, b.cookies)
        self.assertPage(b.post("/logout", data={"csrf": before}), 400)
        self.assertEqual(b.get("/").status_code, 200)            # still logged in

    def test_old_cookie_does_not_log_in(self):
        """No session fixation: the anonymous cookie from before the login is not the logged-in session."""
        b = A.browser()
        b.get("/welcome")
        anonymous = dict(b.cookies)
        b.login(resident("fix"))
        other = A.browser()
        other.cookies = anonymous
        self.assertToLogin(other.get("/"))

    def test_tampered_cookie_is_ignored(self):
        """4.1: a cookie that does not verify is no session (and the browser gets a new one)."""
        b = A.browser().logged_in(resident("tmp"))
        for name, value in list(b.cookies.items()):
            b.cookies[name] = value[:-2] + ("AA" if not value.endswith("AA") else "BB")
        r = b.get("/")
        self.assertToLogin(r)
        self.assertJsonError(b.get("/api/devices"), 401, "login_required")

    def test_session_is_bound_to_the_secret(self):
        """4.1: the session is bound to NETPORTAL_SESSION_SECRET (A and B have different ones)."""
        a = A.browser().logged_in(resident("sec"))
        name = portal_cookies(B.browser().get("/welcome"))[0]["name"]
        b = B.browser()
        b.cookies = {name: v for v in a.cookies.values()}
        self.assertToLogin(b.get("/"))

    def test_one_csrf_token_per_session(self):
        """4.2: the token stays the same for the session; the meta tag (scripts) and the forms agree."""
        b = A.browser().logged_in(resident("stay"))
        page = b.get("/").text
        self.assertEqual(meta_csrf(page), form_csrf(page))
        self.assertEqual(meta_csrf(page), b.csrf())
        self.assertRegex(meta_csrf(page), r"^[A-Za-z0-9_-]{22,}$")      # >= 128 bits


class CsrfTests(ContractCase):
    """INVENTORY 4.2 and the order of the checks in 3.1."""

    @classmethod
    def setUpClass(cls):
        cls.person = resident("csrf")
        cls.b = A.browser().logged_in(cls.person)
        enrol(cls.b, "apple", "csrf device")
        cls.dev = str(newest_device(A, cls.person.sub)["id"])

    def test_missing_or_wrong_token_is_400(self):
        for data in [{}, {"csrf": ""}, {"csrf": "wrong"}, {"csrf": self.b.csrf() + "x"}]:
            with self.subTest(data=data):
                r = self.b.post("/wifi/devices/%s/rename" % self.dev, data=dict(data, name="changed"))
                self.assertPage(r, 400)
        self.assertEqual(A.reg.device(self.dev)["name"], "csrf device")

    def test_token_from_another_session_is_refused(self):
        other = A.browser().logged_in(resident("csrf2"))
        r = self.b.post("/wifi/devices/%s/rename" % self.dev, data={"csrf": other.csrf(), "name": "x"})
        self.assertPage(r, 400)

    def test_token_in_a_header_does_not_count(self):
        """4.2: only the form field is read (no header-based token)."""
        r = self.b.post("/wifi/devices/%s/rename" % self.dev, data={"name": "x"},
                        headers={"X-CSRF-Token": self.b.csrf(), "X-CSRFToken": self.b.csrf()})
        self.assertPage(r, 400)

    def test_script_post_with_wrong_token_is_json_400(self):
        r = self.b.post("/wifi/devices/%s/rename" % self.dev, data={"csrf": "wrong", "name": "x"},
                        headers={"Accept": "application/json"})
        self.assertJsonError(r, 400, "bad_request")

    def test_stale_script_post_is_401_before_csrf(self):
        """3.1: a script's POST (Accept: application/json) without a login answers 401
        login_required BEFORE the CSRF check, with or without a token; a form POST without a
        token is 400."""
        anon = A.browser()
        for data in [{"name": "x"}, {"name": "x", "csrf": "wrong"}, {"name": "x", "csrf": anon.csrf()}]:
            with self.subTest(data=data):
                r = anon.post("/wifi/devices/%s/rename" % self.dev, data=data, headers={"Accept": "application/json"})
                self.assertJsonError(r, 401, "login_required")
        self.assertPage(A.browser().post("/wifi/devices/%s/rename" % self.dev, data={"name": "x"}), 400)
        self.assertJsonError(A.browser().post("/wifi/enroll", data={"format": "apple"},
                                              headers={"Accept": "application/json"}), 401, "login_required")

    def test_accept_must_prefer_json(self):
        """3.1 wants_json: the best match of Accept must be application/json."""
        anon = A.browser()
        r = anon.post("/wifi/devices/%s/rename" % self.dev, data={"name": "x"},
                      headers={"Accept": "text/html, application/json;q=0.5"})
        self.assertPage(r, 400)

    def test_exempt_endpoints(self):
        """4.2: /oauth/token and /api/eap-config/ take no CSRF token (they answer their own errors)."""
        r = self.b.post("/oauth/token", data={"client_id": "nope"})
        self.assertIn(r.status_code, (400, 401))            # not pinned (README), as test_letswifi
        self.assertJsonError(r, r.status_code, "invalid_client")
        self.assertJsonError(self.b.post("/api/eap-config/"), 401, "invalid_token")

    def test_logout_needs_the_token(self):
        """3.2 row 3: POST /logout checks CSRF; afterwards the session (and its token) is gone."""
        b = A.browser().logged_in(resident("lo"))
        self.assertPage(b.post("/logout"), 400)
        self.assertEqual(b.get("/").status_code, 200)
        token = b.csrf()
        r = b.post("/logout", data={"csrf": token})
        self.assertRedirect(r, A.env["NETPORTAL_LOGOUT_URL"])
        self.assertToLogin(b.get("/"))
        self.assertPage(b.post("/logout", data={"csrf": token}), 400)
