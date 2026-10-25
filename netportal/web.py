"""The portal: Authentik login, the resident's devices, enrolment per platform, renewal,
revocation (with an immediate Disconnect-Request), an admin view, the "My devices" dashboard
(Wi-Fi state from Prometheus, netportal/telemetry.py) and the Let's Wi-Fi API for the geteduroam
apps (Windows, Linux, Android fallback).

Every page works without JavaScript; the dashboard pages (/, /devices/<id>, /admin) add static
scripts from 'self' that read the JSON API (/api/...) of the same login. Every change is a POST
with a CSRF token; strict CSP.
"""

import base64
import hashlib
import hmac
import logging
import secrets
import time
import urllib.parse

from authlib.integrations.base_client.errors import OAuthError
from authlib.integrations.flask_client import OAuth
from flask import Flask, abort, g, jsonify, redirect, render_template, request, session, url_for

from . import config, disconnect, enroll, i18n, metrics, registry, telemetry

log = logging.getLogger("netportal")

# The geteduroam apps (Let's Wi-Fi clients), as the reference portal registers them.
LETSWIFI_CLIENTS = {
    "app.eduroam.geteduroam": {"redirect": ["app.eduroam.geteduroam:/"], "refresh": False},  # Android, iOS
    "app.geteduroam.win": {"redirect": ["http://127.0.0.1/", "http://[::1]/"], "refresh": True},
    "app.geteduroam.sh": {"redirect": ["http://127.0.0.1/", "http://[::1]/"], "refresh": True},
}
ACCESS_SECONDS, CODE_SECONDS, REFRESH_SECONDS = 3600, 300, 400 * 86400
# A portal session ends after 8 hours without a request, and 12 hours after the login at the
# latest, however busy (the login is automatic through the house account).
SESSION_IDLE_SECONDS, SESSION_MAX_SECONDS = 8 * 3600, 12 * 3600
FORMATS = ("apple", "apple-mac", "android", "eap-config")
# The dashboard's history ranges (telemetry.RANGES).
HISTORY_RANGES = tuple(telemetry.RANGES)
# The device states the admin list filters by.
DEVICE_STATES = ("online", "offline", "never_connected", "unknown")
# The app's authorization request, as the consent form sends it back (templates/consent.html).
CONSENT_ARGS = ("client_id", "redirect_uri", "response_type", "code_challenge", "code_challenge_method", "state",
                "scope")


def no_passpoint_browser(user_agent):
    """An Android browser that saves a Passpoint file instead of handing it to Android's
    installer: Firefox and its kin (Gecko). Only Chromium browsers (Chrome, Vanadium, Samsung
    Internet, Edge) install it; Firefox 158 on Android 15 downloaded the XML (2026-10-23)."""
    ua = user_agent or ""
    return "Android" in ua and ("Firefox/" in ua or ("Gecko/" in ua and "like Gecko" not in ua))


def platform_of(user_agent):
    """The enrolment options for this browser, best first."""
    ua = user_agent or ""
    if "iPhone" in ua or "iPad" in ua:
        return ["apple"]
    if "Macintosh" in ua:            # a Mac, or an iPad asking for the desktop site
        return ["apple-mac", "apple"]
    if no_passpoint_browser(ua):     # the app first: the Passpoint file does not install here
        return ["android-app", "android"]
    if "Android" in ua:
        return ["android", "android-app"]
    if "Windows" in ua:
        return ["windows"]
    if "Linux" in ua or "X11" in ua:
        return ["linux"]
    return ["apple", "apple-mac", "android", "android-app", "windows", "linux"]


def enrol_options(user_agent, passpoint):
    """platform_of without the Passpoint download while it is off (the app comes first then)."""
    return [opt for opt in platform_of(user_agent) if passpoint or opt != "android"]


def redirect_allowed(client, uri):
    """Exact match, except loopback redirects of clients registered with one: any port and path
    (RFC 8252 7.3), only to 127.0.0.1 or [::1] (never "localhost", never another host)."""
    if uri in client["redirect"]:
        return True
    parsed = urllib.parse.urlsplit(uri)
    if parsed.scheme == "http" and parsed.hostname in ("127.0.0.1", "::1"):
        bare = "http://%s/" % ("[::1]" if parsed.hostname == "::1" else "127.0.0.1")
        return bare in client["redirect"]
    return False


def pkce_ok(verifier, challenge):
    if not verifier or not challenge or not 43 <= len(verifier) <= 128:
        return False
    digest = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return hmac.compare_digest(digest, challenge)


def create_app(settings=None):
    settings = settings or config.load()
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=settings.session_secret,
        SESSION_COOKIE_NAME="__Host-netportal",
        SESSION_COOKIE_SECURE=settings.base_url.startswith("https://"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=SESSION_IDLE_SECONDS,
    )
    if not app.config["SESSION_COOKIE_SECURE"]:
        app.config["SESSION_COOKIE_NAME"] = "netportal"   # __Host- requires Secure (local tests only)
    issuer = enroll.Issuer(settings)
    oauth = OAuth(app)
    oauth.register(
        "authentik",
        client_id=settings.oidc_client_id,
        client_secret=settings.oidc_client_secret,
        server_metadata_url=settings.oidc_issuer.rstrip("/") + "/.well-known/openid-configuration",
        client_kwargs={"scope": "openid profile email", "code_challenge_method": "S256"},
    )
    # One Prometheus client (one HTTP session, one cache) for the process; None: telemetry off.
    prometheus = (telemetry.Prometheus(settings.prometheus_url, settings.prometheus_timeout, ssid=settings.ssid)
                  if settings.prometheus_url else None)
    app.extensions["netportal"] = {"settings": settings, "issuer": issuer, "telemetry": prometheus}
    # the dashboard templates' language-aware formatting and the finding codes (i18n)
    app.jinja_env.globals.update(i18n.template_globals())

    # --- request plumbing -------------------------------------------------------------------

    @app.before_request
    def _setup():
        # /metrics opens its own connection (a registry outage must show as netportal_registry_up 0,
        # not as a failed scrape); static files need none.
        if request.endpoint not in ("static", "metrics_endpoint"):
            g.db = registry.connect(settings.database_url)
        g.lang = i18n.pick(request.headers.get("Accept-Language"), request.cookies.get("house_lang"))
        g.t = i18n.TEXT[g.lang]
        g.user = session.get("user")
        if g.user and not session_fresh(session.get("login_at"), time.time()):
            end_login()                    # the CSRF token stays: a form sent now goes to the login
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(24)
        if request.method == "POST" and not g.user and wants_json() and request.endpoint not in (
                "oauth_token", "letswifi_eap_config"):
            # a dashboard script's POST after the session ended: "log in again", not a CSRF error
            # (nothing is changed either way)
            abort(json_error("login_required", 401))
        if request.method == "POST" and request.endpoint not in ("oauth_token", "letswifi_eap_config"):
            sent = request.form.get("csrf", "")
            if not hmac.compare_digest(sent, session.get("csrf", "")):
                abort(400)

    @app.teardown_request
    def _teardown(exc):
        db = g.pop("db", None)
        if db is not None:
            if exc is None:
                db.commit()
            db.close()

    @app.after_request
    def _headers(resp):
        form_action = getattr(g, "form_action", "'self'")
        # the dashboard pages run the portal's own static scripts, which read its JSON API;
        # every other page runs no script at all
        scripts = "script-src 'self'; connect-src 'self'; " if getattr(g, "dashboard_page", False) else ""
        resp.headers.setdefault("Content-Security-Policy",
                                "default-src 'none'; %sstyle-src 'self'; img-src 'self'; base-uri 'none'; "
                                "frame-ancestors 'none'; form-action %s" % (scripts, form_action))
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    @app.context_processor
    def _context():
        return {"t": g.t, "lang": g.lang, "user": g.user, "csrf": session.get("csrf"), "settings": settings,
                "host": urllib.parse.urlsplit(settings.base_url).netloc, "platform_label": i18n.PLATFORM_LABEL,
                "no_passpoint_browser": no_passpoint_browser(request.user_agent.string)}

    def end_login():
        session.pop("user", None)
        session.pop("login_at", None)
        g.user = None

    def load_user():
        """The logged-in person as the registry knows them now, or None. Rights (admin) come from
        the registry on every request, which the login and every offboarding round keep current;
        the cookie only says who it is."""
        if not g.user:
            return None
        state = registry.person_state(g.db, g.user["sub"])
        if state is None:
            end_login()                    # offboarded since the login: the session ends now
            return None
        g.user = dict(g.user, admin=bool(state["admin"]))
        return g.user

    def return_to():
        """Where the login goes back to: the page itself for a GET. A form sent once the session
        has ended goes back to the page it came from (the consent page with the app's request, the
        admin page), else to the start page: its POST URL would answer the redirect with 405, and
        the form is not sent again."""
        if request.method in ("GET", "HEAD"):
            return request.full_path
        if request.endpoint == "oauth_authorize":
            return url_for("oauth_authorize", **{k: request.form[k] for k in CONSENT_ARGS if request.form.get(k)})
        if request.form.get("back") == "/admin":
            return url_for("admin")
        return url_for("index")

    def need_user(admin=False):
        if not load_user():
            session["next"] = return_to()
            abort(redirect(url_for("login")))
        if admin and not g.user["admin"]:
            abort(403)
        return g.user

    def actor():
        return g.user["sub"] if g.user else "system"

    def wants_json():
        """The dashboard's API, or a dashboard script's form POST (Accept: application/json):
        errors and expired sessions answer JSON, never a page or a redirect to the login."""
        if request.path.startswith("/api/") and request.endpoint != "letswifi_eap_config":
            return True
        return request.method == "POST" and request.accept_mimetypes.best == "application/json"

    def api_user(admin=False):
        """need_user for JSON: 401 when the session has ended (the script reloads the page,
        which goes through the login), 403 for a non-admin."""
        if not load_user():
            abort(json_error("login_required", 401))
        if admin and not g.user["admin"]:
            abort(json_error("forbidden", 403))
        return g.user

    def own_device(device_id, user):
        """The device if this person may see it (theirs; any for an admin), else 404. Revoked
        devices are not on the dashboard."""
        dev = registry.device(g.db, device_id, owner=None if user["admin"] else user["sub"])
        if not dev or dev["revoked"]:
            abort(json_error("not_found", 404) if wants_json() else 404)
        return dev

    def mac_claims(rows):
        """Who else's active devices claim the MACs of these devices (only asked with telemetry on:
        without it nothing of a MAC's data is shown)."""
        if app.extensions["netportal"]["telemetry"] is None:
            return {}
        return registry.mac_claims(g.db, [telemetry.normalise_mac(r.get("calling_station")) for r in rows])

    def dashboard(rows, owners=None):
        """The /api/devices payload (telemetry.dashboard) with the certificate's renewal hint. A
        MAC that other people's devices claim too is withheld from residents (a device sends its
        own MAC: it could send someone else's); admins see the data and the conflict."""
        payload = telemetry.dashboard(app.extensions["netportal"]["telemetry"], rows, owners=owners,
                                      claims=mac_claims(rows), admin=bool(g.user and g.user.get("admin")))
        for device, row in zip(payload["devices"], rows):
            device["expires_soon"] = enroll.expires_soon(row.get("expires"))
        return payload

    def admin_dashboard(q="", state=""):
        """Every active device with its owner, filtered by a search (name, owner, MAC) and a state."""
        people = registry.people(g.db)
        payload = dashboard(registry.devices(g.db, include_revoked=False), owners=people)
        q = q.strip().lower()
        if q:
            mac_q = q.replace("-", ":")
            payload["devices"] = [d for d in payload["devices"] if q in d["name"].lower()
                                  or q in (d["owner"]["username"] or "").lower()
                                  or q in (d["owner"]["display"] or "").lower()
                                  or (d["mac"] and mac_q in d["mac"])]
        if state in DEVICE_STATES:
            payload["devices"] = [d for d in payload["devices"] if d["state"] == state]
        return payload

    # --- login --------------------------------------------------------------------------------

    @app.get("/login")
    def login():
        return oauth.authentik.authorize_redirect(settings.base_url + url_for("auth_callback"))

    @app.get("/auth/callback")
    def auth_callback():
        try:
            token = oauth.authentik.authorize_access_token()   # validates state, nonce, ID token
        except OAuthError as e:            # cancelled at Authentik, stale or replayed callback
            log.info("login failed: %s", e.error)
            session.clear()
            return render_template("message.html", message=g.t["error"]), 400
        claims = token.get("userinfo") or {}
        groups = set(claims.get("groups") or [])
        policy = settings.policy_for(groups)
        if not claims.get("sub") or policy is None:
            session.clear()
            return render_template("message.html", message=g.t["no_access"]), 403
        username = claims.get("preferred_username") or claims["sub"]
        is_admin = bool(groups & settings.admin_groups)
        registry.upsert_person(g.db, claims["sub"], username, claims.get("name") or username, admin=is_admin)
        apply_policy(g.db, claims["sub"], policy, claims["sub"], settings)
        nxt = session.pop("next", None)
        session.clear()
        session["user"] = {"sub": claims["sub"], "username": username, "name": claims.get("name") or username}
        session["login_at"] = int(time.time())
        session["csrf"] = secrets.token_urlsafe(24)
        session.permanent = True
        return redirect(nxt if nxt and nxt.startswith("/") and not nxt.startswith("//") else url_for("index"))

    @app.post("/logout")
    def logout():
        session.clear()
        # the portal's own page would log straight back in (the login is automatic there):
        # to the house's logout, which ends the session at the identity provider
        return redirect(settings.logout_url or url_for("index"))

    # --- the resident's devices ---------------------------------------------------------------

    @app.get("/welcome")
    def welcome():
        load_user()
        return render_template("landing.html")

    @app.get("/")
    def index():
        if "application/json" in request.headers.get("Accept", "") and "text/html" not in request.headers.get("Accept", ""):
            return letswifi_document()
        if not load_user():
            # straight to the house login, no page with a button in between (2026-10-19);
            # the landing page stays at /welcome for the texts
            return redirect(url_for("login"))
        devices = registry.devices(g.db, owner=g.user["sub"])
        g.dashboard_page = True
        return render_template("devices.html", devices=devices, dashboard=dashboard(devices),
                               options=enrol_options(request.user_agent.string, settings.passpoint),
                               expires_soon=enroll.expires_soon)

    def device_payload(dev, user):
        """telemetry.dashboard for one device (with its owner for an admin)."""
        return dashboard([dev], owners=registry.people(g.db) if user["admin"] else None)

    def device_history(dev, range_key):
        """The /history payload; an unknown range is 24h here (the page's links send only known ones)."""
        range_key = range_key if range_key in HISTORY_RANGES else "24h"
        mac = telemetry.normalise_mac(dev.get("calling_station"))
        conflict = telemetry.other_owners(mac_claims([dev]), mac, dev.get("owner"))
        withheld = "mac_conflict" if conflict and not g.user["admin"] else None
        return telemetry.history(app.extensions["netportal"]["telemetry"], mac, range_key,
                                 since=telemetry.data_bound(dev), withheld=withheld)

    @app.get("/devices/<uuid:device_id>")
    def device_page(device_id):
        """One device: its state, diagnostics, the connection list (also without the script) and,
        with the script, the charts."""
        user = need_user()
        dev = own_device(device_id, user)
        payload = device_payload(dev, user)
        g.dashboard_page = True
        return render_template("device.html", dashboard=payload, device=payload["devices"][0], row=dev,
                               history=device_history(dev, request.args.get("range", "24h")),
                               ranges=HISTORY_RANGES, expires_soon=enroll.expires_soon)

    @app.post("/enroll")
    def enroll_device():
        user = need_user()
        fmt = request.form.get("format", "")
        if fmt not in FORMATS or (fmt == "android" and not settings.passpoint):
            abort(400)
        name = (request.form.get("name") or "").strip()[:60] or default_name(fmt)
        device_id = registry.create_device(g.db, user["sub"], name, fmt, owner_policy(g.db, user["sub"], settings))
        registry.audit(g.db, user["sub"], "enrol:" + fmt, device_id)
        token = registry.create_download(g.db, device_id, fmt)
        metrics.ENROLMENTS.labels(fmt).inc()
        return render_template("install.html", fmt=fmt, token=token, name=name)

    @app.post("/devices/<uuid:device_id>/renew")
    def renew(device_id):
        user = need_user()
        dev = registry.device(g.db, device_id, owner=user["sub"])
        if not dev or dev["revoked"]:
            abort(404)
        if dev["platform"] == "letswifi":
            return render_template("message.html", message=g.t["install_app"].format(
                host=urllib.parse.urlsplit(settings.base_url).netloc))
        if dev["platform"] == "android" and not settings.passpoint:
            abort(400)
        token = registry.create_download(g.db, device_id, dev["platform"])
        registry.audit(g.db, user["sub"], "renew", device_id)
        return render_template("install.html", fmt=dev["platform"], token=token, name=dev["name"])

    @app.get("/download/<token>")
    def download(token):
        user = need_user()
        found = registry.consume_download(g.db, token, user["sub"])
        if not found:
            abort(404)
        dev, fmt = found
        body, ctype, filename, headers = issuer.artefact(g.db, dev["id"], fmt)
        g.db.commit()      # the certificate is in the registry before the device can use it
        resp = app.response_class(body, mimetype=ctype)
        for key, value in headers.items():
            resp.headers[key] = value
        if filename:
            resp.headers["Content-Disposition"] = 'attachment; filename="%s"' % filename
        return resp

    @app.post("/devices/<uuid:device_id>/rename")
    def rename(device_id):
        as_json = wants_json()
        user = api_user() if as_json else need_user()
        dev = own_device(device_id, user)
        name = (request.form.get("name") or "").strip()[:60]
        if name:
            registry.rename(g.db, device_id, name)
        if as_json:
            # the inline rename: the name as stored, or the old one for an empty name
            return jsonify({"ok": bool(name), "name": name or dev["name"]}), (200 if name else 400)
        return redirect(url_for("index"))

    @app.post("/devices/<uuid:device_id>/revoke")
    def revoke(device_id):
        user = need_user()
        dev = registry.device(g.db, device_id, owner=None if user["admin"] else user["sub"])
        if not dev or dev["revoked"]:
            abort(404)
        revoke_now(g.db, device_id, user["sub"], settings)
        return redirect(request.form.get("back") if request.form.get("back") == "/admin" else url_for("index"))

    @app.get("/admin")
    def admin():
        need_user(admin=True)
        g.dashboard_page = True
        return render_template("admin.html", devices=registry.devices(g.db, include_revoked=False),
                               people=registry.people(g.db), expires_soon=enroll.expires_soon,
                               dashboard=admin_dashboard(), states=DEVICE_STATES)

    # --- the dashboard's JSON API (same login as the pages) ------------------------------------

    @app.get("/api/devices")
    def api_devices():
        user = api_user()
        return jsonify(dashboard(registry.devices(g.db, owner=user["sub"])))

    @app.get("/api/devices/<uuid:device_id>")
    def api_device(device_id):
        """One device as /api/devices shows it (the detail page's refresh, also an admin's view
        of someone else's device)."""
        user = api_user()
        payload = device_payload(own_device(device_id, user), user)
        payload["device"] = payload.pop("devices")[0]
        return jsonify(payload)

    @app.get("/api/devices/<uuid:device_id>/history")
    def api_history(device_id):
        user = api_user()
        dev = own_device(device_id, user)
        range_key = request.args.get("range", "24h")
        if range_key not in HISTORY_RANGES:
            return json_error("bad_range", 400)
        return jsonify(device_history(dev, range_key))

    @app.get("/api/house")
    def api_house():
        api_user()
        return jsonify(telemetry.house(app.extensions["netportal"]["telemetry"]))

    @app.get("/api/admin/devices")
    def api_admin_devices():
        api_user(admin=True)
        return jsonify(admin_dashboard(request.args.get("q", ""), request.args.get("state", "")))

    # --- Let's Wi-Fi API (geteduroam apps) ----------------------------------------------------

    def letswifi_document():
        base = settings.base_url
        return jsonify({"http://letswifi.app/api#v2": {
            "authorization_endpoint": base + "/oauth/authorize",
            "token_endpoint": base + "/oauth/token",
            "eapconfig_endpoint": base + "/api/eap-config/",
        }})

    @app.get("/.well-known/letswifi.json")
    def letswifi_well_known():
        return letswifi_document()

    @app.route("/oauth/authorize", methods=["GET", "POST"])
    def oauth_authorize():
        user = need_user()
        args = request.values
        client = LETSWIFI_CLIENTS.get(args.get("client_id", ""))
        redirect_uri = args.get("redirect_uri", "")
        if not client or not redirect_allowed(client, redirect_uri):
            abort(400)            # never redirect to an unknown target
        state = args.get("state", "")
        if (args.get("response_type") != "code" or args.get("code_challenge_method") != "S256"
                or not args.get("code_challenge")):
            return redirect(_with_query(redirect_uri, error="invalid_request", state=state))
        if request.method == "GET":
            g.form_action = "'self' %s" % _origin(redirect_uri)
            return render_template("consent.html", args=args, consent_args=CONSENT_ARGS,
                                   name=default_name("letswifi"))
        name = (request.form.get("name") or "").strip()[:60] or default_name("letswifi")
        grant_id = registry.create_grant(g.db, user["sub"], args["client_id"], name)
        code = registry.issue_token(g.db, grant_id, "code", CODE_SECONDS, args["code_challenge"], redirect_uri)
        registry.audit(g.db, user["sub"], "letswifi-consent:" + args["client_id"])
        return redirect(_with_query(redirect_uri, code=code, state=state))

    @app.post("/oauth/token")
    def oauth_token():
        form = request.form
        client = LETSWIFI_CLIENTS.get(form.get("client_id", ""))
        if not client:
            return _oauth_error("invalid_client", 401)
        if form.get("grant_type") == "authorization_code":
            row = registry.use_token(g.db, form.get("code", ""), "code", single_use=True)
            if (not row or row["client_id"] != form["client_id"] or row["redirect_uri"] != form.get("redirect_uri")
                    or not pkce_ok(form.get("code_verifier", ""), row["pkce_challenge"])):
                return _oauth_error("invalid_grant")
        elif form.get("grant_type") == "refresh_token" and client["refresh"]:
            row = registry.use_token(g.db, form.get("refresh_token", ""), "refresh", single_use=True)
            if not row or row["client_id"] != form["client_id"]:
                return _oauth_error("invalid_grant")
        else:
            return _oauth_error("unsupported_grant_type")
        body = {"access_token": registry.issue_token(g.db, row["grant_id"], "access", ACCESS_SECONDS),
                "token_type": "Bearer", "expires_in": ACCESS_SECONDS}
        if client["refresh"]:
            body["refresh_token"] = registry.issue_token(g.db, row["grant_id"], "refresh", REFRESH_SECONDS)
        g.db.commit()
        return jsonify(body)

    @app.post("/api/eap-config/")
    def letswifi_eap_config():
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return _oauth_error("invalid_token", 401)
        row = registry.use_token(g.db, auth[7:], "access", single_use=False)
        if not row:
            return _oauth_error("invalid_token", 401)
        device_id = row["device_id"]
        if device_id is None:                          # first eap-config of this grant: the device
            device_id = registry.create_device(g.db, row["owner"], row["device_name"], "letswifi",
                                               owner_policy(g.db, row["owner"], settings))
            registry.bind_grant(g.db, row["grant_id"], device_id)
            registry.audit(g.db, row["owner"], "enrol:letswifi", device_id)
            metrics.ENROLMENTS.labels("letswifi").inc()
        else:
            dev = registry.device(g.db, device_id)
            if not dev or dev["revoked"]:
                return _oauth_error("invalid_token", 401)
            registry.audit(g.db, row["owner"], "renew:letswifi", device_id)
        body, ctype, _filename, _headers = issuer.artefact(g.db, device_id, "eap-config")
        g.db.commit()
        return app.response_class(body, mimetype=ctype)

    # --- operations ---------------------------------------------------------------------------

    @app.get("/healthz")
    def healthz():
        g.db.execute("SELECT 1")
        return "ok\n"

    @app.get("/metrics")
    def metrics_endpoint():
        # Only for Prometheus on the internal network: never through the reverse proxy.
        if request.headers.get("X-Forwarded-For"):
            abort(404)
        try:
            db = registry.connect(settings.database_url)
        except Exception:  # noqa: BLE001 (shown as netportal_registry_up 0)
            db = None
        try:
            body = metrics.render(db)
        finally:
            if db is not None:
                db.close()
        return app.response_class(body, mimetype="text/plain; version=0.0.4")

    @app.errorhandler(405)
    @app.errorhandler(500)
    def _api_error(e):
        """The API answers JSON for these too; pages keep Flask's own answer."""
        if wants_json():
            return json_error({405: "method_not_allowed", 500: "internal_error"}[e.code], e.code)
        return e

    @app.errorhandler(400)
    @app.errorhandler(403)
    @app.errorhandler(404)
    def _error(e):
        if wants_json():
            return json_error({400: "bad_request", 403: "forbidden", 404: "not_found"}[e.code], e.code)
        return render_template("message.html", message=g.t["error"] if hasattr(g, "t") else "error"), e.code

    def default_name(fmt):
        return {"apple": "iPhone/iPad", "apple-mac": "Mac", "android": "Android",
                "eap-config": "Android", "letswifi": "geteduroam"}.get(fmt, "device") + " (%s)" % g.user["username"]

    return app


def session_fresh(login_at, now):
    """A login is good for SESSION_MAX_SECONDS, however often it is used (the cookie's own expiry
    moves with every request). A session without a login time (from before 2026-10-22) is not."""
    return isinstance(login_at, int) and 0 <= now - login_at < SESSION_MAX_SECONDS


def revoke_now(db, device_id, actor_sub, settings):
    """Revoke in the registry (effective for every new authentication), then cut the running
    session with a Disconnect-Request (effective now)."""
    sess = registry.revoke(db, device_id, actor_sub)
    db.commit()
    result = disconnect.disconnect(sess, settings.dae_secret, port=settings.dae_port) if sess else "no-session"
    registry.audit(db, actor_sub, "disconnect:" + result, device_id)   # metrics across both processes
    db.commit()
    metrics.DISCONNECTS.labels(result).inc()
    log.info("revoked device %s by %s; disconnect: %s", device_id, actor_sub, result)
    return result


def owner_policy(db, sub, settings):
    """The policy for a new device of this person: theirs from the last login or offboarding
    round, the first one if none is known yet."""
    return registry.person_policy(db, sub) or settings.policies[0].name


def apply_policy(db, sub, policy, actor_sub, settings):
    """Give the person this policy; a device that had another one gets a Disconnect-Request and
    authenticates again into the policy's VLAN (someone moved out: residents -> guests).
    Returns the number of devices moved."""
    moved = registry.set_policy(db, sub, policy)
    db.commit()
    for device_id, sess in moved:
        registry.audit(db, actor_sub, "policy:" + policy, device_id)
        result = disconnect.disconnect(sess, settings.dae_secret, port=settings.dae_port) if sess else "no-session"
        registry.audit(db, actor_sub, "disconnect:" + result, device_id)
        db.commit()
        metrics.DISCONNECTS.labels(result).inc()
        log.info("moved device %s to policy %s by %s; disconnect: %s", device_id, policy, actor_sub, result)
    return len(moved)


def _origin(uri):
    p = urllib.parse.urlsplit(uri)
    if p.scheme in ("http", "https"):
        return "%s://%s" % (p.scheme, p.netloc)
    return p.scheme + ":"


def _with_query(uri, **params):
    sep = "&" if "?" in uri else "?"
    return uri + sep + urllib.parse.urlencode({k: v for k, v in params.items() if v})


def json_error(code, status):
    resp = jsonify({"error": code})
    resp.status_code = status
    return resp


def _oauth_error(code, status=400):
    resp = jsonify({"error": code})
    resp.status_code = status
    return resp

