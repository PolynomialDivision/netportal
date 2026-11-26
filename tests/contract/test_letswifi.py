"""The Let's Wi-Fi authorization server for the geteduroam apps (INVENTORY 3.5, consent 4.5):
discovery, authorize and consent, PKCE (RFC 7636), codes, access and refresh tokens (RFC 6749,
OAuth 2.0 Security BCP RFC 9700: one-time codes, refresh rotation, replay revokes the grant),
loopback redirects (RFC 8252 7.3), the eap-config endpoint (RFC 6750 bearer)."""

import base64
import hashlib
import re
import secrets
import urllib.parse

import requests

from harness import (A, B, ContractCase, csp, eap_config, load_p12, newest_device,
                     resident, sample, serial_hex)

ANDROID = ("app.eduroam.geteduroam", "app.eduroam.geteduroam:/")
WINDOWS = ("app.geteduroam.win", "http://127.0.0.1:4711/callback")
LINUX = ("app.geteduroam.sh", "http://[::1]:5555/")
DISCOVERY_KEY = "http://letswifi.app/api#v2"


def pkce():
    verifier = secrets.token_urlsafe(48)[:64]
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def query_of(location):
    return dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(location).query, keep_blank_values=True))


def leaf_of_eap_config(body):
    tree = eap_config(body)
    return load_p12(base64.b64decode(tree.findtext(".//ClientCertificate")), tree.findtext(".//Passphrase"))[1]


class Flow:
    """One app's run through the flow, as the geteduroam apps do it."""

    def __init__(self, client=ANDROID, instance=A, person=None, name=None):
        self.client_id, self.redirect_uri = client
        self.instance = instance
        self.person = person or resident("lw")
        self.browser = instance.browser().logged_in(self.person)
        self.verifier, self.challenge = pkce()
        self.state = secrets.token_urlsafe(8)
        self.name = name

    def params(self, **changes):
        p = {"client_id": self.client_id, "redirect_uri": self.redirect_uri, "response_type": "code",
             "code_challenge": self.challenge, "code_challenge_method": "S256", "state": self.state,
             "scope": "eap-metadata"}
        p.update(changes)
        return {k: v for k, v in p.items() if v is not None}

    def authorize(self, **changes):
        return self.browser.get("/oauth/authorize?" + urllib.parse.urlencode(self.params(**changes)))

    def consent(self, **changes):
        """GET the consent page, POST it: the redirect response."""
        page = self.authorize(**changes)
        assert page.status_code == 200, (page.status_code, page.text[:200])
        data = dict(self.params(**changes), csrf=self.browser.csrf())
        if self.name is not None:
            data["name"] = self.name
        return self.browser.post("/oauth/authorize", data=data)

    def code(self):
        r = self.consent()
        assert r.status_code in (302, 303), r.status_code
        return query_of(r.headers["Location"])["code"]

    def token(self, **form):
        return requests.post(self.instance.url + "/oauth/token", data=form, timeout=10)

    def exchange(self, code, **changes):
        form = {"grant_type": "authorization_code", "code": code, "client_id": self.client_id,
                "redirect_uri": self.redirect_uri, "code_verifier": self.verifier}
        form.update(changes)
        return self.token(**{k: v for k, v in form.items() if v is not None})

    def tokens(self):
        r = self.exchange(self.code())
        assert r.status_code == 200, r.text
        return r.json()

    def refresh(self, refresh_token, client_id=None):
        return self.token(grant_type="refresh_token", refresh_token=refresh_token, client_id=client_id or self.client_id)

    def eap(self, access_token, scheme="Bearer"):
        return requests.post(self.instance.url + "/api/eap-config/",
                             headers={"Authorization": "%s %s" % (scheme, access_token)}, timeout=30)


class DiscoveryTests(ContractCase):
    """INVENTORY 3.2 row 26, 3.5 Discovery."""

    def expected(self, inst):
        return {DISCOVERY_KEY: {"authorization_endpoint": inst.base_url + "/oauth/authorize",
                                "token_endpoint": inst.base_url + "/oauth/token",
                                "eapconfig_endpoint": inst.base_url + "/api/eap-config/"}}

    def test_well_known_document(self):
        for inst in (A, B):         # B: NETPORTAL_BASE_URL with a trailing slash, no double slash
            with self.subTest(instance=inst.name):
                r = requests.get(inst.url + "/.well-known/letswifi.json", timeout=10)
                self.assertEqual(self.assertJson(r, 200), self.expected(inst))

    def test_base_url_probe(self):
        """The apps probe the base URL with Accept: application/json."""
        r = requests.get(A.url + "/", headers={"Accept": "application/json"}, allow_redirects=False, timeout=10)
        self.assertEqual(self.assertJson(r, 200), self.expected(A))
        r = requests.get(A.url + "/", headers={"Accept": "text/html, application/json"}, allow_redirects=False,
                         timeout=10)
        self.assertToLogin(r)


class AuthorizeTests(ContractCase):
    """INVENTORY 3.5 /oauth/authorize, 4.5 consent."""

    def test_consent_page(self):
        """GET: the consent page re-sends the app's request; its CSP form-action allows the
        app's redirect target (browsers apply form-action to the redirect after the POST)."""
        for client, origin in [(ANDROID, "app.eduroam.geteduroam:"), (WINDOWS, "http://127.0.0.1:4711"),
                               (LINUX, "http://[::1]:5555")]:
            with self.subTest(client=client[0]):
                f = Flow(client)
                r = f.authorize()
                self.assertPage(r, 200, "geteduroam")
                for key, value in f.params().items():
                    self.assertRegex(r.text, r'name="%s" value="%s"' % (re.escape(key), re.escape(
                        value.replace("&", "&amp;"))))
                self.assertIn('value="geteduroam (%s)"' % f.person.username, r.text)
                self.assertEqual(csp(r)["form-action"], sorted(["'self'", origin]))
                self.assertNotIn("script-src", csp(r))

    def test_consent_page_names_the_app_and_its_target(self):
        """Security review 2026-10-29 I4: the page names the app and the redirect target, so a
        resident can tell a consent they did not start (a link from elsewhere)."""
        for client, name in [(ANDROID, "geteduroam (Android, iPhone, iPad)"), (WINDOWS, "geteduroam (Windows)"),
                             (LINUX, "geteduroam (Linux)")]:
            with self.subTest(client=client[0]):
                r = Flow(client).authorize()
                self.assertIn("<strong>%s</strong>" % name, r.text)
                self.assertIn("<code>%s</code>" % client[1], r.text)

    def test_unknown_client_or_redirect_is_400_never_a_redirect(self):
        """3.5: unknown client_id or a redirect URI that is not allowed -> 400 page, no Location."""
        cases = [("app.unknown", "app.eduroam.geteduroam:/"),
                 (ANDROID[0], "app.eduroam.geteduroam:/other"),       # exact match for the mobile app
                 (ANDROID[0], "http://127.0.0.1:4711/"),               # loopback only where registered
                 (WINDOWS[0], "http://localhost:4711/"),               # RFC 8252 8.3: not "localhost"
                 (WINDOWS[0], "http://127.0.0.2/"),
                 (WINDOWS[0], "https://127.0.0.1/"),
                 (WINDOWS[0], "http://127.0.0.1.evil.example/"),
                 (WINDOWS[0], "http://evil.example/?u=http://127.0.0.1/"),
                 (LINUX[0], "http://[::2]/"),
                 (WINDOWS[0], "")]
        f = Flow(WINDOWS)
        for client_id, redirect_uri in cases:
            with self.subTest(client=client_id, redirect=redirect_uri):
                r = f.authorize(client_id=client_id, redirect_uri=redirect_uri)
                self.assertPage(r, 400)
                self.assertNotIn("Location", r.headers)

    def test_loopback_any_port_and_path(self):
        """RFC 8252 7.3: the desktop apps may use any port and path on 127.0.0.1 and [::1]."""
        for client_id, uri in [(WINDOWS[0], "http://127.0.0.1/"), (WINDOWS[0], "http://127.0.0.1:61234/x/y"),
                               (WINDOWS[0], "http://[::1]:5000/"), (LINUX[0], "http://127.0.0.1:1/")]:
            with self.subTest(uri=uri):
                self.assertPage(Flow((client_id, uri)).authorize(), 200)

    def test_request_errors_go_back_to_the_app(self):
        """RFC 6749 4.1.2.1 / RFC 7636 4.4.1: a bad request with a valid redirect goes back with
        error and the state."""
        f = Flow(WINDOWS)
        for changes in [{"code_challenge": None}, {"code_challenge": ""}, {"code_challenge_method": "plain"},
                        {"code_challenge_method": None}]:
            with self.subTest(changes=changes):
                r = f.authorize(**changes)
                self.assertIn(r.status_code, (302, 303))
                loc = r.headers["Location"]
                self.assertTrue(loc.startswith(f.redirect_uri + "?"), loc)
                self.assertEqual(query_of(loc), {"error": "invalid_request", "state": f.state})

    def test_error_redirect_keeps_the_query_and_omits_an_empty_state(self):
        f = Flow((WINDOWS[0], "http://127.0.0.1:4711/cb?x=1"))
        r = f.authorize(code_challenge=None, state="")
        loc = r.headers["Location"]
        self.assertTrue(loc.startswith("http://127.0.0.1:4711/cb?x=1&"), loc)
        self.assertEqual(query_of(loc), {"x": "1", "error": "invalid_request"})

    def test_unsupported_response_type(self):
        """RFC 6749 4.1.2.1: response_type other than code -> error=unsupported_response_type."""
        f = Flow(WINDOWS)
        r = f.authorize(response_type="token")
        self.assertEqual(query_of(r.headers["Location"]), {"error": "unsupported_response_type", "state": f.state})

    def test_consent_needs_csrf(self):
        f = Flow(ANDROID)
        r = f.browser.post("/oauth/authorize", data=f.params())
        self.assertPage(r, 400)

    def test_consent_issues_a_code(self):
        """POST: a grant named as entered, a one-time code bound to the redirect URI and the
        challenge, valid for a few minutes, back to the app with the state."""
        f = Flow(ANDROID, name="  " + "Pixel " * 15)
        r = f.consent()
        self.assertIn(r.status_code, (302, 303))
        loc = r.headers["Location"]
        self.assertTrue(loc.startswith("app.eduroam.geteduroam:/?"), loc)
        q = query_of(loc)
        self.assertEqual(set(q), {"code", "state"})
        self.assertEqual(q["state"], f.state)
        self.assertRegex(q["code"], r"^[A-Za-z0-9_-]{43,}$")
        expires = f.instance.reg.token_expires_in(q["code"])
        self.assertTrue(60 <= expires <= 600, expires)                  # RFC 6749 4.1.2: short-lived
        grant = f.instance.reg.grant(q["code"])
        self.assertEqual(grant["client_id"], ANDROID[0])
        self.assertEqual(grant["owner"], f.person.sub)
        self.assertEqual(grant["device_name"], ("Pixel " * 15).strip()[:60])
        self.assertIsNone(grant["device_id"])
        self.assertIn("letswifi-consent:" + ANDROID[0], f.instance.reg.audit_of(f.person.sub))

    def test_consent_default_name(self):
        f = Flow(ANDROID, name="   ")
        code = f.code()
        self.assertEqual(f.instance.reg.grant(code)["device_name"], "geteduroam (%s)" % f.person.username)


class TokenTests(ContractCase):
    """INVENTORY 3.5 /oauth/token."""

    def test_code_exchange_mobile_app(self):
        """No refresh token for the mobile app; Bearer, expires_in; never cached."""
        f = Flow(ANDROID)
        r = f.exchange(f.code())
        body = self.assertJson(r, 200)
        self.assertEqual(set(body), {"access_token", "token_type", "expires_in"} | ({"scope"} & set(body)))
        self.assertEqual(body["token_type"].lower(), "bearer")
        self.assertIsInstance(body["expires_in"], int)
        self.assertTrue(0 < body["expires_in"] <= 3600)
        self.assertAbout(f.instance.reg.token_expires_in(body["access_token"]), body["expires_in"], 10)
        self.assertIn("no-store", r.headers.get("Cache-Control", ""))          # RFC 6749 5.1
        self.assertRegex(body["access_token"], r"^[A-Za-z0-9_.~+/-]{43,}=*$")
        self.assertFalse(f.instance.reg.stores_plain_token(body["access_token"]))

    def test_code_exchange_desktop_apps_get_a_refresh_token(self):
        for client in (WINDOWS, LINUX):
            with self.subTest(client=client[0]):
                f = Flow(client)
                body = f.tokens()
                self.assertIn("refresh_token", body)
                self.assertNotEqual(body["refresh_token"], body["access_token"])
                lifetime = f.instance.reg.token_expires_in(body["refresh_token"])
                self.assertTrue(86400 < lifetime <= 400 * 86400 + 60, lifetime)

    def test_unknown_client(self):
        f = Flow(ANDROID)
        for client_id in ["app.unknown", "", None]:
            with self.subTest(client_id=client_id):
                r = f.exchange(f.code(), client_id=client_id)
                self.assertIn(r.status_code, (400, 401))
                self.assertJsonError(r, r.status_code, "invalid_client")

    def test_invalid_grant(self):
        """Each failure is invalid_grant: wrong or malformed verifier (43..128 characters),
        another client, another or missing redirect URI, unknown or expired code."""
        f = Flow(WINDOWS)
        short = "a" * 42
        short_challenge = base64.urlsafe_b64encode(hashlib.sha256(short.encode()).digest()).rstrip(b"=").decode()
        cases = {"wrong verifier": {"code_verifier": pkce()[0]},
                 "no verifier": {"code_verifier": None},
                 "other client": {"client_id": LINUX[0]},
                 "other redirect": {"redirect_uri": "http://127.0.0.1:4712/callback"},
                 "no redirect": {"redirect_uri": None},
                 "unknown code": {"code": secrets.token_urlsafe(32)}}
        for name, changes in cases.items():
            with self.subTest(case=name):
                code = changes.pop("code", None) or f.code()
                self.assertJsonError(f.exchange(code, **changes), 400, "invalid_grant")
        # a 42-character verifier whose hash matches is still too short (RFC 7636 4.1)
        g = Flow(WINDOWS)
        g.verifier, g.challenge = short, short_challenge
        self.assertJsonError(g.exchange(g.code()), 400, "invalid_grant")
        code = f.code()
        f.instance.reg.expire_token(code)
        self.assertJsonError(f.exchange(code), 400, "invalid_grant")

    def test_unsupported_grant_type(self):
        f = Flow(ANDROID)
        for grant_type in ["password", "client_credentials"]:
            with self.subTest(grant_type=grant_type):
                r = f.token(grant_type=grant_type, client_id=ANDROID[0])
                self.assertJsonError(r, 400, "unsupported_grant_type")

    # A parameter sent without a value counts as omitted (RFC 6749 3.1), so "" is missing too.
    def test_grant_type_missing_or_not_for_this_client(self):
        """RFC 6749 5.2: a missing grant_type is invalid_request; a grant type the server supports
        but this client may not use (refresh tokens for the mobile app) is unauthorized_client."""
        f = Flow(ANDROID)
        for grant_type in ["", None]:
            with self.subTest(grant_type=grant_type):
                r = f.token(**{k: v for k, v in {"grant_type": grant_type, "client_id": ANDROID[0]}.items()
                               if v is not None})
                self.assertJsonError(r, 400, "invalid_request")
        self.assertJsonError(f.refresh("x" * 43), 400, "unauthorized_client")

    def test_code_is_single_use_and_reuse_revokes_the_grant(self):
        """RFC 6749 4.1.2 / RFC 9700 2.1.1: a second use of a code fails and revokes what the
        first use issued."""
        f = Flow(WINDOWS)
        code = f.code()
        first = f.exchange(code).json()
        self.assertEqual(f.eap(first["access_token"]).status_code, 200)
        self.assertJsonError(f.exchange(code), 400, "invalid_grant")
        self.assertJsonError(f.eap(first["access_token"]), 401, "invalid_token")
        self.assertJsonError(f.refresh(first["refresh_token"]), 400, "invalid_grant")

    def test_a_replayed_code_revokes_the_certificate_it_produced(self):
        """Security review 2026-10-29 M2: whoever replays a code (or the app, if someone else was
        first) ends the grant AND the device it made, with a Disconnect-Request for its session."""
        A.nas.reset("ack")
        f = Flow(ANDROID)
        code = f.code()
        first = f.exchange(code).json()
        cert = leaf_of_eap_config(f.eap(first["access_token"]).content)
        dev = newest_device(A, f.person.sub)["id"]
        A.reg.radius_session(dev, cert, calling="02:00:00:00:dd:01")
        self.assertEqual(A.reg.credential(cert)["status"], "valid")
        self.assertJsonError(f.exchange(code), 400, "invalid_grant")
        self.assertEqual(A.reg.credential(cert)["status"], "revoked")
        self.assertTrue(A.reg.device(dev)["revoked"])
        packets = A.nas.wait(1)
        self.assertEqual(len(packets), 1, packets)
        self.assertTrue(packets[0]["valid"])

    def test_a_replayed_refresh_token_revokes_the_device(self):
        """Security review 2026-10-29 M2: a replayed refresh token ends the grant and revokes the
        certificate it produced (not only the tokens)."""
        f = Flow(LINUX)
        first = f.tokens()
        cert = leaf_of_eap_config(f.eap(first["access_token"]).content)
        f.refresh(first["refresh_token"])
        self.assertJsonError(f.refresh(first["refresh_token"]), 400, "invalid_grant")
        self.assertEqual(A.reg.credential(cert)["status"], "revoked")

    def test_failed_exchange_burns_the_code(self):
        """A wrong verifier uses the code up: the right one afterwards fails too (no guessing)."""
        f = Flow(ANDROID)
        code = f.code()
        self.assertJsonError(f.exchange(code, code_verifier=pkce()[0]), 400, "invalid_grant")
        self.assertJsonError(f.exchange(code), 400, "invalid_grant")

    def test_refresh_rotation(self):
        """RFC 9700 4.14.2: each refresh returns a new refresh token; the new tokens work."""
        f = Flow(WINDOWS)
        first = f.tokens()
        r = f.refresh(first["refresh_token"])
        second = self.assertJson(r, 200)
        self.assertEqual(second["token_type"].lower(), "bearer")
        self.assertNotEqual(second["access_token"], first["access_token"])
        self.assertNotEqual(second["refresh_token"], first["refresh_token"])
        self.assertTrue(0 < second["expires_in"] <= 3600)
        self.assertEqual(f.eap(second["access_token"]).status_code, 200)
        third = self.assertJson(f.refresh(second["refresh_token"]), 200)
        self.assertEqual(f.eap(third["access_token"]).status_code, 200)

    def test_refresh_replay_revokes_the_grant(self):
        """RFC 9700 4.14.2: a replayed (already rotated) refresh token revokes the grant: the
        tokens issued since stop working."""
        f = Flow(LINUX)
        first = f.tokens()
        second = f.refresh(first["refresh_token"]).json()
        self.assertJsonError(f.refresh(first["refresh_token"]), 400, "invalid_grant")
        self.assertJsonError(f.eap(second["access_token"]), 401, "invalid_token")
        self.assertJsonError(f.refresh(second["refresh_token"]), 400, "invalid_grant")
        self.assertTrue(f.instance.reg.grant(second["refresh_token"])["revoked"])

    def test_refresh_token_of_another_client(self):
        f = Flow(WINDOWS)
        body = f.tokens()
        self.assertJsonError(f.refresh(body["refresh_token"], client_id=LINUX[0]), 400, "invalid_grant")

    def test_refresh_with_an_access_token_or_garbage(self):
        f = Flow(WINDOWS)
        body = f.tokens()
        self.assertJsonError(f.refresh(body["access_token"]), 400, "invalid_grant")
        self.assertJsonError(f.refresh(""), 400, "invalid_grant")

    def test_offboarded_owner(self):
        """3.5: the tokens of a person who lost access stop at once."""
        f = Flow(WINDOWS)
        body = f.tokens()
        f.instance.reg.set_offboarded(f.person.sub)
        self.assertJsonError(f.eap(body["access_token"]), 401, "invalid_token")
        self.assertJsonError(f.refresh(body["refresh_token"]), 400, "invalid_grant")


class EapConfigEndpointTests(ContractCase):
    """INVENTORY 3.5 /api/eap-config/."""

    def test_first_call_enrols_a_device(self):
        f = Flow(WINDOWS, name="Laptop")
        access = f.tokens()["access_token"]
        _, before = A.metrics()
        r = f.eap(access)
        self.assertEqual(r.status_code, 200, r.text[:200])
        self.assertEqual(r.headers["Content-Type"].split(";")[0].strip(), "application/eap-config")
        self.assertIsNone(r.headers.get("Content-Disposition"))
        self.assertIn("no-store", r.headers.get("Cache-Control", ""))
        leaf = leaf_of_eap_config(r.content)
        dev = newest_device(A, f.person.sub)
        self.assertEqual(dev["name"], "Laptop")
        self.assertEqual(leaf.subject.rfc4514_string(), "CN=%s@%s" % (dev["id"], A.realm))
        self.assertEqual(A.reg.grant(access)["device_id"], dev["id"])
        self.assertIn((f.person.sub, "enrol:letswifi"), A.reg.audit(dev["id"]))
        self.assertEqual([d["name"] for d in f.browser.get("/api/devices").json()["devices"]], ["Laptop"])
        _, after = A.metrics()
        self.assertEqual((sample(after, "netportal_enrolments_total", format="letswifi") or 0)
                         - (sample(before, "netportal_enrolments_total", format="letswifi") or 0), 1)

    def test_later_calls_renew_the_same_device(self):
        """Every call (here with a refreshed access token, as the desktop apps renew) issues a new
        certificate for the bound device."""
        f = Flow(WINDOWS)
        tokens = f.tokens()
        first = leaf_of_eap_config(f.eap(tokens["access_token"]).content)
        _, before = A.metrics()
        access = f.refresh(tokens["refresh_token"]).json()["access_token"]
        second = leaf_of_eap_config(f.eap(access).content)
        self.assertEqual(second.subject, first.subject)
        self.assertNotEqual(serial_hex(second), serial_hex(first))
        self.assertEqual(len(A.reg.devices(f.person.sub)), 1)
        self.assertEqual(A.reg.credential(second)["status"], "valid")
        dev = newest_device(A, f.person.sub)["id"]
        self.assertEqual(A.reg.audit(dev)[-1], (f.person.sub, "renew:letswifi"))
        _, after = A.metrics()
        self.assertEqual(sample(after, "netportal_enrolments_total", format="letswifi"),
                         sample(before, "netportal_enrolments_total", format="letswifi"))

    def test_one_eap_config_per_access_token(self):
        """Security review 2026-10-29 M2: an access token yields one certificate; a second call
        with it is refused (the app gets a new token: the desktop apps refresh)."""
        f = Flow(ANDROID)
        access = f.tokens()["access_token"]
        self.assertEqual(f.eap(access).status_code, 200)
        self.assertJsonError(f.eap(access), 401, "invalid_token")
        dev = newest_device(A, f.person.sub)["id"]
        self.assertEqual(A.reg.credential_count(dev), 1)

    def test_a_quick_reissue_retires_the_previous_certificate(self):
        """Security review 2026-10-29 M2: a certificate issued within an hour of the device's
        previous one retires that one at once (a retry, or someone minting certificates), so a
        device has at most one older certificate in its overlap."""
        f = Flow(WINDOWS)
        tokens = f.tokens()
        first = leaf_of_eap_config(f.eap(tokens["access_token"]).content)
        access = f.refresh(tokens["refresh_token"]).json()["access_token"]
        second = leaf_of_eap_config(f.eap(access).content)
        self.assertEqual(A.reg.credential(first)["status"], "retired")
        self.assertEqual(A.reg.credential(second)["status"], "valid")

    def test_revoked_device_stops_the_tokens(self):
        f = Flow(WINDOWS)
        body = f.tokens()
        f.eap(body["access_token"])
        dev = newest_device(A, f.person.sub)["id"]
        f.browser.post("/wifi/devices/%s/revoke" % dev, data={"csrf": f.browser.csrf()})
        self.assertJsonError(f.eap(body["access_token"]), 401, "invalid_token")
        self.assertJsonError(f.refresh(body["refresh_token"]), 400, "invalid_grant")

    def test_bad_or_missing_bearer(self):
        f = Flow(ANDROID)
        for headers in [{}, {"Authorization": "Bearer"}, {"Authorization": "Bearer " + "x" * 43},
                        {"Authorization": "Basic Zm9vOmJhcg=="}, {"Authorization": "Bearer  " + "x" * 43}]:
            with self.subTest(headers=headers):
                r = requests.post(A.url + "/api/eap-config/", headers=headers, timeout=10)
                self.assertJsonError(r, 401, "invalid_token")
        code = f.tokens()["access_token"]
        A.reg.expire_token(code)
        self.assertJsonError(f.eap(code), 401, "invalid_token")

    def test_the_code_is_no_access_token(self):
        f = Flow(ANDROID)
        self.assertJsonError(f.eap(f.code()), 401, "invalid_token")

    def test_401_names_the_bearer_scheme(self):
        """RFC 6750 3 / RFC 9110 11.6.1: a 401 carries WWW-Authenticate: Bearer (with the error)."""
        r = requests.post(A.url + "/api/eap-config/", headers={"Authorization": "Bearer nope"}, timeout=10)
        self.assertEqual(r.status_code, 401)
        self.assertTrue(r.headers.get("WWW-Authenticate", "").lower().startswith("bearer"), r.headers)

    def test_auth_scheme_is_case_insensitive(self):
        """RFC 9110 11.1: the authentication scheme is case-insensitive."""
        f = Flow(ANDROID)
        self.assertEqual(f.eap(f.tokens()["access_token"], scheme="bearer").status_code, 200)

    def test_renew_in_the_portal_points_to_the_app(self):
        """3.2 row 8: an app's device is renewed by the app; the page says so with the server name."""
        f = Flow(ANDROID)
        f.eap(f.tokens()["access_token"])
        dev = newest_device(A, f.person.sub)["id"]
        r = f.browser.post("/wifi/devices/%s/renew" % dev, data={"csrf": f.browser.csrf()})
        self.assertPage(r, 200, "geteduroam")
        self.assertIn(urllib.parse.urlsplit(A.base_url).netloc, r.text)
        self.assertNotIn("/download/", r.text)

    def test_instance_b_issues_for_its_realm(self):
        f = Flow(WINDOWS, instance=B)
        r = f.eap(f.tokens()["access_token"])
        self.assertEqual(r.status_code, 200)
        self.assertTrue(leaf_of_eap_config(r.content).subject.rfc4514_string().endswith("@" + B.realm))
