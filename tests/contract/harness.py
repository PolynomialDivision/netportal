"""Shared helpers of the contract suite: the running instances (tests/runs/contract/
suite.json, written by run.sh), a browser with its own cookie handling (the B instance's
cookie is Secure on a plain-http test listener, which requests' cookie jar would never send),
logins through the mock IdP, SQL, the CLI commands, /metrics and artefact parsers.

Black box: the portal is the binary under test (suite.json "bin"), reached only over HTTP,
RADIUS (Disconnect), its CLI and its registry database.
"""

import base64
import datetime
import email.utils
import hashlib
import json
import os
import plistlib
import re
import secrets
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.parse
import xml.etree.ElementTree as ET
from pathlib import Path

import requests
from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs12

import registry_adapter
from fake_nas import FakeNas

SUITE = json.loads(Path(os.environ["CT_SUITE"]).read_text())
ROOT = Path(SUITE["root"])
RUN = Path(SUITE["run"])
BIN = SUITE["bin"]
IDP = SUITE["idp"]

ANDROID_UA = ("Mozilla/5.0 (Linux; Android 16; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/141.0.0.0 Mobile Safari/537.36")
FIREFOX_ANDROID_UA = "Mozilla/5.0 (Android 16; Mobile; rv:144.0) Gecko/144.0 Firefox/144.0"
IPHONE_UA = ("Mozilla/5.0 (iPhone; CPU iPhone OS 19_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) "
             "Version/19.0 Mobile/15E148 Safari/604.1")
MAC_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
          "Version/19.0 Safari/605.1.15")
WINDOWS_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36"
LINUX_UA = "Mozilla/5.0 (X11; Linux x86_64; rv:144.0) Gecko/20100101 Firefox/144.0"

DEFAULT_CSP = ("default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; "
               "frame-ancestors 'none'; form-action 'self'")
DASHBOARD_CSP = ("default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; img-src 'self'; "
                 "base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
SESSION_IDLE_S = 8 * 3600
TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{43}")          # secrets.token_urlsafe(32)


def env_file(path):
    env = {}
    for line in Path(path).read_text().splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            env[k] = v
    return env


class Instance:
    def __init__(self, name, spec):
        self.name = name
        self.url = spec["url"]
        # /metrics: a listener of its own (NETPORTAL_METRICS_LISTEN, security review L6)
        self.metrics_url = spec["metrics_url"]
        self.db_url = spec["db"]
        self.env = env_file(RUN / ("env-" + name))
        self.base_url = self.env["NETPORTAL_BASE_URL"].rstrip("/")     # what the portal calls itself
        self.dae_port, self.dae_secret = spec["dae_port"], spec["dae_secret"]
        # the instance's PKI (`netportal pki`): the device CA's name constraints hold its realm only
        self.pki = Path(spec["pki"])
        self._nas = None
        self._reg = None
        self._lock = threading.Lock()

    @property
    def nas(self):
        with self._lock:
            if self._nas is None:
                self._nas = FakeNas(self.dae_port, self.dae_secret)
            return self._nas

    @property
    def root_cert(self):
        return pem_cert(self.pki / "root.pem")

    @property
    def device_ca(self):
        return pem_cert(self.pki / "device-ca.pem")

    @property
    def realm(self):
        return self.env["NETPORTAL_REALM"]

    def browser(self, ua=ANDROID_UA, lang="en"):
        return Browser(self, ua, lang)

    @property
    def reg(self):
        """The registry adapter (registry_adapter.py): setup and inspection without a schema."""
        if self._reg is None:
            self._reg = registry_adapter.Registry(self.db_url, SUITE["radius_password"])
        return self._reg

    # --- CLI
    def command(self, *args, env=None, unset=(), timeout=60, background=False):
        """netportal <args> with exactly this instance's environment (+ PATH, HOME, overrides)."""
        full = {"PATH": os.environ["PATH"], "HOME": os.environ.get("HOME", "/tmp")}
        full.update(self.env)
        for k in unset:
            full.pop(k, None)
        full.update(env or {})
        argv = [BIN] + list(args)
        if background:
            return subprocess.Popen(argv, cwd=ROOT, env=full, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True)
        return subprocess.run(argv, cwd=ROOT, env=full, capture_output=True, text=True, timeout=timeout)

    # --- /metrics
    def metrics(self, headers=None):
        r = requests.get(self.metrics_url + "/metrics", headers=headers or {}, timeout=10)
        return r, parse_metrics(r.text) if r.status_code == 200 else {}


class Spawned:
    """An extra portal process (`serve`) with the given settings, for start-up checks."""

    def __init__(self, settings, port):
        self.url = "http://127.0.0.1:%d" % port
        self.metrics_url = "http://127.0.0.1:%d" % (port + 1000)
        full = {"PATH": os.environ["PATH"], "HOME": os.environ.get("HOME", "/tmp")}
        full.update(settings)
        argv = [BIN, "serve"]
        full["NETPORTAL_LISTEN"] = "127.0.0.1:%d" % port
        # never the instances' metrics port (it would fail to start for that reason)
        full["NETPORTAL_METRICS_LISTEN"] = "127.0.0.1:%d" % (port + 1000)
        self.log = tempfile.TemporaryFile(mode="w+")
        self.proc = subprocess.Popen(argv, cwd=ROOT, env=full, stdout=self.log, stderr=subprocess.STDOUT)

    def healthy(self, timeout=30):
        """True once /healthz answers 200; False if the process exits or the time runs out."""
        end = time.time() + timeout
        while time.time() < end:
            if self.proc.poll() is not None:
                return False
            try:
                if requests.get(self.url + "/healthz", timeout=2).status_code == 200:
                    return True
            except requests.RequestException:
                pass
            time.sleep(0.3)
        return False

    def exit_code(self, timeout=30):
        try:
            return self.proc.wait(timeout)
        except subprocess.TimeoutExpired:
            return None

    def output(self):
        self.log.seek(0)
        return self.log.read()

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
        try:
            self.proc.wait(10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(10)
        self.log.close()


INSTANCES = {name: Instance(name, spec) for name, spec in SUITE["instances"].items()}
A, B = INSTANCES["a"], INSTANCES["b"]


# --- cookies ------------------------------------------------------------------------------------

def parse_set_cookie(header):
    """{"name", "value", "attrs": {lower-case attribute: value or True}}."""
    parts = [p.strip() for p in header.split(";")]
    name, _, value = parts[0].partition("=")
    attrs = {}
    for p in parts[1:]:
        if not p:
            continue
        k, eq, v = p.partition("=")
        attrs[k.strip().lower()] = v.strip() if eq else True
    return {"name": name.strip(), "value": value.strip(), "attrs": attrs}


def set_cookies(resp):
    return [parse_set_cookie(h) for h in resp.raw.headers.getlist("Set-Cookie")]


def cookie_expired(cookie):
    a = cookie["attrs"]
    if "max-age" in a:
        try:
            return int(a["max-age"]) <= 0
        except ValueError:
            return False
    if "expires" in a:
        when = email.utils.parsedate_to_datetime(a["expires"])
        return when.timestamp() <= time.time()
    return False


class Browser:
    """One browser of one person against one instance: its own cookie jar (sent to the portal
    only, Secure or not), redirects followed by hand, external base URL mapped to the local
    listener."""

    def __init__(self, instance, ua=ANDROID_UA, lang="en"):
        self.instance = instance
        self.http = requests.Session()
        self.http.trust_env = False
        self.headers = {"User-Agent": ua, "Accept-Language": lang}
        self.cookies = {}
        self.history = []

    def local(self, url):
        if url.startswith("/"):
            return self.instance.url + url
        if url.startswith(self.instance.base_url + "/") or url == self.instance.base_url:
            return self.instance.url + url[len(self.instance.base_url):]
        return url

    def request(self, method, url, follow=False, headers=None, cookies=True, **kw):
        url = self.local(url)
        h = dict(self.headers)
        h.update(headers or {})
        portal = url.startswith(self.instance.url + "/")
        if cookies and portal and self.cookies:
            h["Cookie"] = "; ".join("%s=%s" % kv for kv in self.cookies.items())
        r = self.http.request(method, url, headers=h, allow_redirects=False, timeout=30, **kw)
        self.http.cookies.clear()
        if portal:
            for c in set_cookies(r):
                if cookie_expired(c):
                    self.cookies.pop(c["name"], None)
                else:
                    self.cookies[c["name"]] = c["value"]
        self.history.append(r)
        if follow:
            for _ in range(10):
                if r.status_code not in (301, 302, 303, 307, 308):
                    break
                nxt = urllib.parse.urljoin(r.url, r.headers["Location"])
                r = self.request("GET", nxt, headers=headers)
        return r

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def post(self, url, **kw):
        return self.request("POST", url, **kw)

    def csrf(self, path="/welcome"):
        """The session's CSRF token, as every page carries it (<meta name="csrf">)."""
        return meta_csrf(self.get(path).text)

    def login(self, person):
        """Through the mock IdP (the person logs in, as the first user of the list). Returns
        (callback response, final response)."""
        idp_users(person)
        r = self.get("/login")
        assert r.status_code == 302, r.status_code
        r = self.get(r.headers["Location"])                 # IdP authorize -> 302 to the callback
        assert r.status_code == 302, (r.status_code, r.text[:200])
        callback = self.get(r.headers["Location"])
        final = callback
        if callback.status_code in (301, 302, 303):
            final = self.get(urllib.parse.urljoin(callback.url, callback.headers["Location"]), follow=True)
        return callback, final

    def logged_in(self, person):
        callback, final = self.login(person)
        assert callback.status_code == 302, (callback.status_code, callback.text[:300])
        return self


def meta_csrf(html):
    m = re.search(r'<meta name="csrf" content="([^"]*)">', html)
    return m.group(1) if m else None


def form_csrf(html):
    m = re.search(r'name="csrf" value="([^"]+)"', html)
    return m.group(1) if m else None


# --- people and the mock IdP ------------------------------------------------------------------

class Person:
    def __init__(self, groups=("residents",), prefix="p", sub=None, username=None, name=None, omit=()):
        tag = secrets.token_hex(4)
        self.sub = sub or "ct-%s-%s" % (prefix, tag)
        self.username = username or "%s%s" % (prefix, tag)
        self.name = name or self.username.title()
        self.groups = list(groups)
        self.active = True
        self.omit = list(omit)

    def json(self, **changes):
        d = {"sub": self.sub, "username": self.username, "name": self.name, "groups": self.groups,
             "active": self.active}
        if self.omit:
            d["omit"] = self.omit
        d.update(changes)
        return d


def resident(prefix="res"):
    return Person(["residents"], prefix)


def admin_person(prefix="adm"):
    return Person(["it-admins"], prefix)


def idp_users(*people):
    requests.post(IDP + "/_test/users", json=[p.json() if isinstance(p, Person) else p for p in people],
                  timeout=10).raise_for_status()


def idp_directory(**kw):
    requests.post(IDP + "/_test/directory", json=kw, timeout=10).raise_for_status()


def idp_api_requests():
    return requests.get(IDP + "/_test/api-requests", timeout=10).json()


# --- enrolment ------------------------------------------------------------------------------------

def enrol(browser, fmt, name=""):
    """POST /enroll: (response, download token or None)."""
    r = browser.post("/enroll", data={"csrf": browser.csrf(), "format": fmt, "name": name})
    m = re.search(r'href="/download/([^"]+)"', r.text)
    return r, (m.group(1) if m else None)


def newest_device(instance, owner):
    return instance.reg.newest_device(owner)


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


# --- /metrics ---------------------------------------------------------------------------------------

_SAMPLE = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{(.*)\})? (\S+)(?: (\d+))?$')
_LABEL = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"')


def parse_metrics(text):
    """{"samples": {(name, ((label, value), ...)): float}, "types": {family: type},
    "help": {family: text}, "bad_lines": [...]}."""
    out = {"samples": {}, "types": {}, "help": {}, "bad_lines": []}
    for line in text.splitlines():
        if not line:
            continue
        if line.startswith("# TYPE "):
            _, _, fam, typ = line.split(" ", 3)
            out["types"][fam] = typ
            continue
        if line.startswith("# HELP "):
            parts = line.split(" ", 3)
            out["help"][parts[2]] = parts[3] if len(parts) > 3 else ""
            continue
        if line.startswith("#"):
            continue
        m = _SAMPLE.match(line)
        if not m:
            out["bad_lines"].append(line)
            continue
        labels = tuple(sorted(_LABEL.findall(m.group(3) or "")))
        out["samples"][(m.group(1), labels)] = float(m.group(4))
    return out


def sample(metrics, name, **labels):
    return metrics["samples"].get((name, tuple(sorted(labels.items()))))


# --- artefacts ---------------------------------------------------------------------------------

def openssl(*args, data=None):
    """openssl <args> with `data` as the input file; (returncode, stdout + stderr)."""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "in"
        if data is not None:
            path.write_bytes(data)
        argv = ["openssl"] + [a.replace("{in}", str(path)) for a in args]
        out = subprocess.run(argv, capture_output=True, text=True)
        return out.returncode, out.stdout + out.stderr


def p12_info(p12, password):
    """openssl pkcs12 -info (legacy provider loaded) of a PKCS#12: the algorithm lines."""
    return openssl("pkcs12", "-info", "-legacy", "-noout", "-in", "{in}", "-passin", "pass:" + password, data=p12)


def p12_bag_attributes(p12, password):
    """The full dump without keys (bag attributes: friendlyName, localKeyID)."""
    return openssl("pkcs12", "-info", "-legacy", "-nokeys", "-in", "{in}", "-passin", "pass:" + password, data=p12)


def load_p12(p12, password):
    """(key, leaf certificate, [additional certificates])."""
    return pkcs12.load_key_and_certificates(p12, password.encode() if isinstance(password, str) else password)


def mobileconfig(body):
    return plistlib.loads(body)


def payload(profile, ptype):
    found = [p for p in profile["PayloadContent"] if p["PayloadType"] == ptype]
    return found[0] if found else None


def parse_passpoint(body):
    """The Android installer's view (AOSP ConfigParser.parseMimeMultipartMessage, written
    again here strictly): a base64 body of a MIME multipart with CRLF lines. Returns
    {"outer": [header lines], "boundary": str, "parts": [(content type, transfer encoding,
    decoded bytes)]}."""
    message = base64.b64decode(body, validate=True).decode("ascii")
    head, sep, rest = message.partition("\r\n\r\n")
    assert sep, "no blank line after the outer headers"
    outer = head.split("\r\n")
    m = re.fullmatch(r"Content-Type: multipart/mixed; boundary=(\S+)", outer[0])
    assert m, outer
    boundary = m.group(1)
    parts = []
    chunks = rest.split("--" + boundary)
    assert chunks[0] == "", repr(chunks[0][:80])
    assert chunks[-1] in ("--", "--\r\n"), repr(chunks[-1][:80])
    for chunk in chunks[1:-1]:
        assert chunk.startswith("\r\n"), repr(chunk[:40])
        headers, sep, content = chunk[2:].partition("\r\n\r\n")
        assert sep
        hdr = dict(line.split(": ", 1) for line in headers.split("\r\n"))
        parts.append((hdr.get("Content-Type"), hdr.get("Content-Transfer-Encoding"),
                      base64.b64decode("".join(content.split()), validate=True), content))
    return {"outer": outer, "boundary": boundary, "parts": parts}


def eap_config(body):
    return ET.fromstring(body)


def credentials_of(fmt, body):
    """(key, leaf certificate, [chain]) inside a downloaded artefact of this format."""
    if fmt in ("apple", "apple-mac"):
        pk = payload(mobileconfig(body), "com.apple.security.pkcs12")
        return load_p12(pk["PayloadContent"], pk["Password"])
    if fmt == "android":
        part = [p for p in parse_passpoint(body)["parts"] if p[0] == "application/x-pkcs12"][0]
        return load_p12(part[2], b"")
    tree = eap_config(body)
    return load_p12(base64.b64decode(tree.findtext(".//ClientCertificate")), tree.findtext(".//Passphrase"))


def download(browser, fmt, name=""):
    """Enrol and download: (download response, leaf certificate, device id from the CN)."""
    _, token = enrol(browser, fmt, name)
    r = browser.get("/download/" + token)
    assert r.status_code == 200, (r.status_code, r.text[:200])
    cert = credentials_of(fmt, r.content)[1]
    return r, cert, cn_device(cert)


def cn_device(cert):
    cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    return cn.split("@", 1)[0]


def cert_of(der_or_cert):
    return der_or_cert if isinstance(der_or_cert, x509.Certificate) else x509.load_der_x509_certificate(der_or_cert)


def pem_cert(path):
    return x509.load_pem_x509_certificate(Path(path).read_bytes())


def serial_hex(cert):
    """The registry's serial: lowercase hex, left-padded with one 0 to an even length."""
    h = "%x" % cert.serial_number
    return ("0" + h) if len(h) % 2 else h


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


# --- assertions ---------------------------------------------------------------------------------

def media_type(resp):
    """(type/subtype lower-case, {param: value lower-case}) of the Content-Type."""
    raw = resp.headers.get("Content-Type", "")
    parts = [p.strip() for p in raw.split(";")]
    params = {}
    for p in parts[1:]:
        k, _, v = p.partition("=")
        params[k.strip().lower()] = v.strip().strip('"').lower()
    return parts[0].lower(), params


def csp(resp):
    """{directive: [sources]} of the Content-Security-Policy."""
    out = {}
    for part in resp.headers.get("Content-Security-Policy", "").split(";"):
        words = part.split()
        if words:
            out[words[0].lower()] = sorted(words[1:])
    return out


def allow(resp):
    return {m.strip().upper() for m in resp.headers.get("Allow", "").split(",") if m.strip()}


def is_rfc3339(text):
    return isinstance(text, str) and re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})", text) is not None


class ContractCase(unittest.TestCase):
    maxDiff = 4000

    def assertJson(self, resp, status):
        self.assertEqual(resp.status_code, status, resp.text[:300])
        self.assertEqual(media_type(resp)[0], "application/json", resp.headers)
        return resp.json()

    def assertJsonError(self, resp, status, code):
        body = self.assertJson(resp, status)
        self.assertIsInstance(body, dict)
        self.assertEqual(body.get("error"), code, body)

    def assertPage(self, resp, status, text=None):
        self.assertEqual(resp.status_code, status, resp.text[:300])
        mt, params = media_type(resp)
        self.assertEqual(mt, "text/html")
        self.assertEqual(params.get("charset"), "utf-8")
        if text is not None:
            self.assertIn(text, resp.text)

    def assertRedirect(self, resp, location, status=None):
        """A redirect (302/303, or `status`) whose Location resolves to `location`."""
        if status is None:
            self.assertIn(resp.status_code, (302, 303), resp.text[:300])
        else:
            self.assertEqual(resp.status_code, status, resp.text[:300])
        got = urllib.parse.urljoin(resp.url, resp.headers.get("Location", ""))
        want = urllib.parse.urljoin(resp.url, location)
        self.assertEqual(got, want)

    def assertToLogin(self, resp):
        self.assertRedirect(resp, "/login")

    def assertAbout(self, value, expected, tolerance, msg=None):
        self.assertIsNotNone(value, msg)
        self.assertLessEqual(abs(value - expected), tolerance,
                             msg or "%r not within %r of %r" % (value, tolerance, expected))
