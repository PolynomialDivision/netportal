"""Login and logout through (mock) Authentik (INVENTORY 4.4), where the login returns to, and
rights read from the registry on every request (4.3)."""

import urllib.parse

from harness import (A, B, IDP, ContractCase, Person, admin_person, enrol, idp_users, newest_device, resident)


def split(location):
    p = urllib.parse.urlsplit(location)
    return p.path, urllib.parse.parse_qs(p.query, keep_blank_values=True)


class LoginTests(ContractCase):
    """INVENTORY 4.4."""

    def test_authorization_request(self):
        """/login: code flow with state, nonce and PKCE S256 to the issuer's authorization
        endpoint, redirect_uri = NETPORTAL_BASE_URL + /auth/callback."""
        for inst in (A, B):
            with self.subTest(instance=inst.name):
                r = inst.browser().get("/login")
                self.assertEqual(r.status_code, 302)
                url = urllib.parse.urlsplit(r.headers["Location"])
                self.assertEqual("%s://%s%s" % (url.scheme, url.netloc, url.path), IDP + "/application/o/authorize/")
                q = dict(urllib.parse.parse_qsl(url.query))
                self.assertEqual(q["response_type"], "code")
                self.assertEqual(q["client_id"], "netportal")
                self.assertEqual(q["redirect_uri"], inst.base_url + "/auth/callback")
                self.assertEqual(set(q["scope"].split()), {"openid", "profile", "email"})
                self.assertEqual(q["code_challenge_method"], "S256")
                self.assertRegex(q["code_challenge"], r"^[A-Za-z0-9_-]{43}$")
                self.assertTrue(q.get("state"))
                self.assertTrue(q.get("nonce"))

    def test_login_records_the_person(self):
        """4.4 effects: upsert_person (username, display, admin from the groups, last_login),
        the policy from NETPORTAL_POLICIES; 302 to / by default."""
        p = Person(["residents"], "rec", name="Rec Ord")
        callback, final = A.browser().login(p)
        self.assertRedirect(callback, "/")
        self.assertPage(final, 200, "Your devices")
        self.assertEqual(A.reg.person(p.sub), {"username": p.username, "display": "Rec Ord", "admin": False,
                                               "policy": "residents", "offboarded": False, "recent_login": True})

    def test_policy_and_admin_from_the_groups(self):
        """4.3 may log in: the first policy sharing a group; admins outside every policy get the
        FIRST policy; admin = in NETPORTAL_ADMIN_GROUPS."""
        cases = [(["house-admins"], "residents", False), (["former-residents"], "guests", False),
                 (["it-admins"], "residents", True), (["it-admins", "former-residents"], "guests", True),
                 (["former-residents", "residents"], "residents", False)]
        for groups, policy, admin in cases:
            with self.subTest(groups=groups):
                p = Person(groups, "pol")
                callback, _ = A.browser().login(p)
                self.assertEqual(callback.status_code, 302)
                row = A.reg.person(p.sub)
                self.assertEqual((row["policy"], row["admin"]), (policy, admin))

    def test_single_policy_and_default_admin_groups(self):
        """2.2: instance B has one policy, residents (VLAN 40) for the groups residents and staff;
        without NETPORTAL_ADMIN_GROUPS the admin group is it-admins."""
        self.assertEqual(B.reg.policies(), {"residents": 40})
        for groups, admin in [(["staff"], False), (["residents"], False), (["it-admins"], True)]:
            with self.subTest(groups=groups):
                p = Person(groups, "leg")
                callback, _ = B.browser().login(p)
                self.assertEqual(callback.status_code, 302)
                row = B.reg.person(p.sub)
                self.assertEqual((row["policy"], row["admin"]), ("residents", admin))
        callback, _ = B.browser().login(Person(["former-residents"], "leg"))
        self.assertPage(callback, 403)

    def test_refused_without_policy(self):
        """3.2 row 2: no policy for the groups, or no groups claim -> 403 no_access, the session
        cleared, no person recorded."""
        for p in [Person(["vpn-users"], "ref"), Person(["residents"], "ref", omit=["groups"])]:
            with self.subTest(omit=p.omit, groups=p.groups):
                b = A.browser()
                callback, _ = b.login(p)
                self.assertPage(callback, 403, "Your account has no access to the house Wi-Fi.")
                self.assertIsNone(A.reg.person(p.sub))
                self.assertToLogin(b.get("/"))

    def test_id_token_without_sub_is_refused(self):
        """OIDC Core 2: sub is required; a token without it is a failed login (4xx page), never a 500."""
        p = Person(["residents"], "nosub", omit=["sub"])
        b = A.browser()
        callback, _ = b.login(p)
        self.assertIn(callback.status_code, (400, 403))
        self.assertPage(callback, callback.status_code)
        self.assertToLogin(b.get("/"))

    def test_claim_fallbacks(self):
        """4.4 claims: preferred_username falls back to sub, name to the username."""
        p = Person(["residents"], "fb", omit=["preferred_username", "name"])
        callback, _ = A.browser().login(p)
        self.assertEqual(callback.status_code, 302)
        row = A.reg.person(p.sub)
        self.assertEqual((row["username"], row["display"]), (p.sub, p.sub))
        p = Person(["residents"], "fb2", omit=["name"])
        A.browser().login(p)
        self.assertEqual(A.reg.person(p.sub)["display"], p.username)

    def test_replayed_callback_is_400(self):
        """3.2 row 2 / 4.4 failure: OAuthError (replayed or stale callback) -> 400 t.error."""
        b = A.browser()
        b.login(resident("rep"))
        callback_url = [r.url for r in b.history if "/auth/callback" in r.url][-1]
        self.assertEqual(b.get("/").status_code, 200)
        r = b.get(callback_url)
        self.assertPage(r, 400, "Something went wrong.")

    def test_a_foreign_callback_keeps_the_session(self):
        """Security review 2026-10-29 L1: a replayed or forged /auth/callback (another site can
        link there: GET, SameSite=Lax sends the cookie) is a 400 and drops only that pending
        login; the session the browser has stays."""
        b = A.browser()
        b.login(resident("cbx"))
        callback_url = [r.url for r in b.history if "/auth/callback" in r.url][-1]
        for url in (callback_url, "/auth/callback?state=bogus&code=x", "/auth/callback?error=access_denied&state=x"):
            with self.subTest(url=url[:40]):
                self.assertPage(b.get(url), 400, "Something went wrong.")
                self.assertEqual(b.get("/").status_code, 200)

    def test_error_from_the_identity_provider(self):
        """4.4 failure: the IdP sends error=access_denied (cancelled) -> 400."""
        b = A.browser()
        r = b.get("/login")
        state = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(r.headers["Location"]).query))["state"]
        r = b.get("/auth/callback?" + urllib.parse.urlencode({"error": "access_denied", "state": state}))
        self.assertPage(r, 400, "Something went wrong.")

    def test_wrong_state(self):
        b = A.browser()
        idp_users(resident("st"))
        r = b.get("/login")
        r = b.get(r.headers["Location"])
        target = urllib.parse.urlsplit(r.headers["Location"])
        q = dict(urllib.parse.parse_qsl(target.query))
        q["state"] = "not-the-state"
        self.assertPage(b.get("/auth/callback?" + urllib.parse.urlencode(q)), 400)
        self.assertToLogin(b.get("/"))

    def test_login_again_clears_offboarded(self):
        """8.2 interaction with login: a person offboarded earlier is active again after a login."""
        p = resident("again")
        A.browser().login(p)
        A.reg.set_offboarded(p.sub)
        callback, _ = A.browser().login(p)
        self.assertEqual(callback.status_code, 302)
        self.assertFalse(A.reg.person(p.sub)["offboarded"])


class ReturnToTests(ContractCase):
    """INVENTORY 4.4 "Return after login" (return_to)."""

    def after_login(self, person, first):
        """Do `first(browser)` without a login, then log in: the callback's Location."""
        b = A.browser()
        r = first(b)
        self.assertToLogin(r)
        callback, final = b.login(person)
        self.assertEqual(callback.status_code, 302, callback.text[:200])
        return callback.headers["Location"], final

    def assertPathQuery(self, location, path, query=None):
        got_path, got_query = split(location)
        self.assertEqual(got_path, path)
        self.assertEqual(got_query, query or {})

    def test_get_returns_to_the_page_with_its_query(self):
        """GET -> the full path (with or without a bare "?" when there is no query)."""
        adm = admin_person("rt")
        loc, final = self.after_login(adm, lambda b: b.get("/admin?q=abc&state=online"))
        self.assertPathQuery(loc, "/admin", {"q": ["abc"], "state": ["online"]})
        self.assertEqual(final.status_code, 200)
        loc, _ = self.after_login(adm, lambda b: b.get("/admin/aps"))
        self.assertPathQuery(loc, "/admin/aps")

    def test_device_page_and_download(self):
        p = resident("rtd")
        b = A.browser().logged_in(p)
        _, token = enrol(b, "apple")
        dev = str(newest_device(A, p.sub)["id"])
        loc, final = self.after_login(p, lambda b: b.get("/devices/" + dev))
        self.assertPathQuery(loc, "/devices/" + dev)
        self.assertEqual(final.status_code, 200)
        loc, final = self.after_login(p, lambda b: b.get("/download/" + token))
        self.assertPathQuery(loc, "/download/" + token)
        self.assertEqual(final.headers["Content-Type"], "application/x-apple-aspen-config")

    def test_consent_post_returns_to_the_authorize_url(self):
        """POST /oauth/authorize -> the authorize URL rebuilt from the non-empty consent fields."""
        fields = {"client_id": "app.geteduroam.win", "redirect_uri": "http://127.0.0.1:4711/cb",
                  "response_type": "code", "code_challenge": "c" * 43, "code_challenge_method": "S256",
                  "state": "", "scope": "eap-metadata"}

        def first(b):
            return b.post("/oauth/authorize", data=dict(fields, csrf=b.csrf(), name="laptop"))
        loc, final = self.after_login(resident("rtc"), first)
        want = {k: [v] for k, v in fields.items() if v}
        self.assertPathQuery(loc, "/oauth/authorize", want)
        self.assertPage(final, 200, "geteduroam")

    def test_post_with_back_admin_returns_to_admin(self):
        def first(b):
            return b.post("/devices/00000000-0000-4000-8000-000000000000/revoke", data={"csrf": b.csrf(), "back": "/admin"})
        loc, _ = self.after_login(admin_person("rtb"), first)
        self.assertPathQuery(loc, "/admin")

    def test_other_posts_return_to_the_start_page(self):
        for back in ["", "/elsewhere", "//evil.example/"]:
            with self.subTest(back=back):
                def first(b):
                    return b.post("/enroll", data={"csrf": b.csrf(), "format": "apple", "back": back})
                loc, _ = self.after_login(resident("rto"), first)
                self.assertPathQuery(loc, "/")

    def test_index_without_login_sets_no_return_target(self):
        """3.2 row 5: GET / redirects to /login without remembering a target, so an earlier one stays."""
        adm = admin_person("rti")
        b = A.browser()
        self.assertToLogin(b.get("/admin/aps"))
        self.assertToLogin(b.get("/"))
        callback, _ = b.login(adm)
        self.assertPathQuery(callback.headers["Location"], "/admin/aps")


class LogoutTests(ContractCase):
    """INVENTORY 3.2 row 3, 4.4 Logout."""

    def test_logout_goes_to_the_house_logout(self):
        b = A.browser().logged_in(resident("out"))
        r = b.post("/logout", data={"csrf": b.csrf()})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.headers["Location"], A.env["NETPORTAL_LOGOUT_URL"])
        self.assertToLogin(b.get("/"))
        self.assertJsonError(b.get("/api/devices"), 401, "login_required")

    def test_logout_without_logout_url_goes_to_the_start_page(self):
        b = B.browser().logged_in(resident("outb"))
        r = b.post("/logout", data={"csrf": b.csrf()})
        self.assertRedirect(r, "/")
        self.assertToLogin(b.get("/"))

    def test_anonymous_logout_with_token(self):
        b = A.browser()
        r = b.post("/logout", data={"csrf": b.csrf()})
        self.assertEqual(r.headers.get("Location"), A.env["NETPORTAL_LOGOUT_URL"])


class RegistryRightsTests(ContractCase):
    """INVENTORY 4.3: admin and "still a person" are read from the registry on every request;
    the cookie carries no rights."""

    def test_admin_granted_and_taken_between_requests(self):
        p = resident("adm")
        b = A.browser().logged_in(p)
        self.assertPage(b.get("/admin"), 403)
        self.assertJsonError(b.get("/api/admin/devices"), 403, "forbidden")
        A.reg.set_admin(p.sub, True)
        self.assertPage(b.get("/admin"), 200)
        self.assertEqual(b.get("/api/admin/devices").status_code, 200)
        A.reg.set_admin(p.sub, False)
        self.assertPage(b.get("/admin"), 403)
        self.assertJsonError(b.get("/api/admin/overview"), 403, "forbidden")

    def test_admin_from_the_groups_is_not_in_the_cookie(self):
        """An it-admins login whose registry row loses admin has no admin rights from then on."""
        p = admin_person("adm2")
        b = A.browser().logged_in(p)
        self.assertPage(b.get("/admin"), 200)
        A.reg.set_admin(p.sub, False)
        self.assertPage(b.get("/admin"), 403)

    def test_offboarded_person_loses_the_session_at_the_next_request(self):
        """4.3: no active person row -> the session ends now; the CSRF token stays (a form sent
        now goes through the login, not into a CSRF error)."""
        p = resident("gone")
        b = A.browser().logged_in(p)
        token = b.csrf()
        self.assertEqual(b.get("/").status_code, 200)
        A.reg.set_offboarded(p.sub)
        self.assertToLogin(b.get("/"))
        self.assertJsonError(b.get("/api/devices"), 401, "login_required")
        self.assertEqual(b.csrf(), token)
        r = b.post("/enroll", data={"csrf": token, "format": "apple"})
        self.assertToLogin(r)

    def test_deleted_person_loses_the_session(self):
        p = resident("del")
        b = A.browser().logged_in(p)
        A.reg.delete_person(p.sub)
        self.assertToLogin(b.get("/"))

    def test_admin_powers_over_other_devices(self):
        """4.3 own vs any: admins view, rename and revoke any device, renew only their own."""
        owner = resident("own")
        ob = A.browser().logged_in(owner)
        enrol(ob, "apple", "owned")
        dev = str(newest_device(A, owner.sub)["id"])
        adm = admin_person("pow")
        ab = A.browser().logged_in(adm)
        self.assertPage(ab.get("/devices/" + dev), 200)
        self.assertEqual(ab.get("/api/devices/" + dev).json()["device"]["id"], dev)
        self.assertNotIn(dev, [d["id"] for d in ab.get("/api/devices").json()["devices"]])   # own list: own only
        self.assertIn(dev, [d["id"] for d in ab.get("/api/admin/devices").json()["devices"]])
        csrf = ab.csrf()
        self.assertPage(ab.post("/devices/%s/renew" % dev, data={"csrf": csrf}), 404)
        r = ab.post("/devices/%s/rename" % dev, data={"csrf": csrf, "name": "renamed by admin"},
                    headers={"Accept": "application/json"})
        self.assertEqual((r.status_code, r.json()), (200, {"ok": True, "name": "renamed by admin"}))
        r = ab.post("/devices/%s/revoke" % dev, data={"csrf": csrf, "back": "/admin"})
        self.assertRedirect(r, "/admin")
        self.assertTrue(A.reg.device(dev)["revoked"])
        self.assertIn((adm.sub, "revoke"), A.reg.audit(dev))
        self.assertJsonError(ob.get("/api/devices/" + dev), 404, "not_found")
