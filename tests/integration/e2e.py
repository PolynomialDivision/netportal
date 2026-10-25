#!/usr/bin/env python3
"""The Wi-Fi flows end to end (started by tests/integration/run.sh).

A resident logs in through (mock) Authentik, enrols devices per platform, the access point
(eapol_test) connects with what the device would install, revocation cuts the session (a
Disconnect-Request the fake access point accepts) and the next connection fails; renewal,
the Let's Wi-Fi OAuth flow of the geteduroam apps, offboarding, admin rights, CSRF, metrics.
"""

import base64
import hashlib
import plistlib
import re
import secrets
import subprocess
import sys
import time
import urllib.parse
import xml.etree.ElementTree as ET
from pathlib import Path

import psycopg
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT))
from test_profiles import aosp_parse  # noqa: E402
from netportal import disconnect, pki, registry  # noqa: E402

PORTAL, IDP = "http://127.0.0.1:18080", "http://127.0.0.1:19000"
DB = "postgresql://netportal:it-db-password@127.0.0.1:15432/netportal"
RUN = Path(sys.argv[1])
failures = []
LAST_REPLY = ""   # eapol_test output of the last connect()


def check(name, ok, detail=""):
    print(("ok    " if ok else "FAIL  ") + name + ("" if ok else "  -> " + str(detail)[:300]))
    if not ok:
        failures.append(name)


def users(*people):
    requests.post(IDP + "/_test/users", json=[
        {"sub": sub, "username": name, "name": name.title(), "groups": groups, "active": active}
        for sub, name, groups, active in people]).raise_for_status()


ALICE = ("sub-alice", "alice", ["residents"], True)
CAROL = ("sub-carol", "carol", ["residents"], True)
ADMIN = ("sub-admin", "admin", ["it-admins"], True)
BOB = ("sub-bob", "bob", ["vpn-users"], True)
FIA = ("sub-fia", "fia", ["former-residents"], True)      # moved out before (policy guests)


def login(person, ua="Mozilla/5.0 (Linux; Android 16)", others=(ALICE, CAROL, ADMIN, BOB)):
    users(person, *others)
    s = requests.Session()
    s.headers.update({"User-Agent": ua, "Accept-Language": "en"})
    r = s.get(PORTAL + "/login")
    return s, r


def csrf(session, path="/"):
    page = session.get(PORTAL + path).text
    m = re.search(r'name="csrf" value="([^"]+)"', page)
    return m.group(1) if m else ""


def enrol(s, fmt, name=None):
    r = s.post(PORTAL + "/enroll", data={"csrf": csrf(s), "format": fmt, "name": name or ""})
    m = re.search(r'href="(/download/[^"]+)"', r.text)
    return m.group(1) if m else None


def device_ids(owner_sub):
    with psycopg.connect(DB) as db:
        return [str(r[0]) for r in db.execute(
            "SELECT id FROM device WHERE owner = %s ORDER BY created", (owner_sub,))]


def sql(query, *args):
    with psycopg.connect(DB) as db:
        rows = list(db.execute(query, args)) if query.lstrip().upper().startswith("SELECT") else db.execute(query, args)
        db.commit()
        return rows


def write_client(name, key, cert, chain):
    (RUN / "client" / (name + ".key")).write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (RUN / "client" / (name + ".crt")).write_bytes(b"".join(
        c.public_bytes(serialization.Encoding.PEM) for c in [cert] + list(chain)))
    (RUN / "client" / (name + ".conf")).write_text(
        'network={\n ssid="Scharni"\n key_mgmt=WPA-EAP\n eap=TLS\n identity="anonymous@scharni.org"\n'
        ' ca_cert="/pki/root.pem"\n client_cert="/client/%s.crt"\n private_key="/client/%s.key"\n'
        ' domain_match="radius.scharni.org"\n phase1="tls_disable_tlsv1_3=0"\n}\n' % (name, name))
    for f in (RUN / "client").glob(name + ".*"):
        f.chmod(0o644)


def connect(name, mac=None):
    """eapol_test as the access point: (verdict, vlan). mac: the device's MAC (Calling-Station-Id;
    eapol_test's default 02:00:00:00:00:01)."""
    out = subprocess.run(["docker", "run", "--rm", "--network", "netportal-it", "--ip", "10.199.0.20",
                          "-v", "%s:/client:ro" % (RUN / "client"), "-v", "%s:/pki:ro" % (RUN / "pki"),
                          "netportal-it-client", "eapol_test", "-c", "/client/%s.conf" % name,
                          "-a", "10.199.0.10", "-s", "it-radius-secret", "-r0", "-t", "10"]
                         + (["-M" + mac] if mac else []),
                         capture_output=True, text=True).stdout
    global LAST_REPLY
    LAST_REPLY = out
    vlan = "-"
    m = re.search(r"Attribute 81 \(Tunnel-Private-Group-Id\) length=\d+\s+Value: ([0-9a-f]+)", out)
    if m:
        vlan = bytes.fromhex(m.group(1)).decode()
    if "code=2 (Access-Accept)" in out:
        return ("accept" if re.search(r"^SUCCESS", out, re.M) else "accept-without-eap"), vlan
    return ("reject" if "code=3 (Access-Reject)" in out else "none"), vlan


def from_eap_config(body):
    tree = ET.fromstring(body)
    p12 = base64.b64decode(tree.findtext(".//ClientCertificate"))
    return pkcs12.load_key_and_certificates(p12, tree.findtext(".//Passphrase").encode())


def from_mobileconfig(body):
    profile = plistlib.loads(body)
    ident = next(p for p in profile["PayloadContent"] if p["PayloadType"] == "com.apple.security.pkcs12")
    return pkcs12.load_key_and_certificates(ident["PayloadContent"], ident["Password"].encode())


def from_passpoint(body):
    return pkcs12.load_key_and_certificates(aosp_parse(body)["application/x-pkcs12"], b"")


def metric(name):
    text = requests.get(PORTAL + "/metrics").text
    m = re.search(r"^%s ([0-9.e+]+)$" % re.escape(name), text, re.M)
    return float(m.group(1)) if m else None


def main():
    # --- access ---------------------------------------------------------------------------
    s, r = login(BOB)
    check("a person outside the Wi-Fi groups is refused", r.status_code == 403, r.status_code)
    s, r = login(ALICE)
    check("a resident logs in through Authentik", r.status_code == 200 and "Your devices" in r.text, r.status_code)
    if failures:
        print("cannot log in: stopping")
        return 1
    check("security headers", "default-src 'none'" in r.headers.get("Content-Security-Policy", "")
          and r.headers.get("Cache-Control") == "no-store", r.headers)
    check("Android browser: Passpoint is the first option",
          r.text.find('value="android"') < r.text.find('value="eap-config"') and 'value="android"' in r.text)
    bad = s.post(PORTAL + "/enroll", data={"format": "apple"})
    check("a POST without CSRF token is refused", bad.status_code == 400, bad.status_code)

    # --- enrolment per platform -----------------------------------------------------------
    fmts = {"android": from_passpoint, "apple": from_mobileconfig, "eap-config": from_eap_config}
    for fmt, extract in fmts.items():
        link = enrol(s, fmt, "alice " + fmt)
        dl = s.get(PORTAL + link)
        expected = {"android": "application/x-wifi-config", "apple": "application/x-apple-aspen-config",
                    "eap-config": "application/eap-config"}[fmt]
        check("%s: download has the right type" % fmt, dl.headers.get("Content-Type", "").startswith(expected),
              dl.headers.get("Content-Type"))
        if fmt == "android":
            check("android: no Content-Disposition, base64 transfer encoding",
                  "Content-Disposition" not in dl.headers and dl.headers.get("Content-Transfer-Encoding") == "base64")
        key, cert, chain = extract(dl.content)
        write_client("alice-" + fmt, key, cert, chain)
        verdict = connect("alice-" + fmt)
        check("%s: the installed credential connects (VLAN 30)" % fmt, verdict == ("accept", "30"), verdict)
        if fmt == "android":
            m = re.search(r"Attribute 27 \(Session-Timeout\) length=6\s+Value: ([0-9]+)", LAST_REPLY)
            check("the Accept carries the Session-Timeout backstop", m and int(m.group(1)) == 43200,
                  m and m.group(1))
        again = s.get(PORTAL + link)
        check("%s: the download link works only once" % fmt, again.status_code == 404, again.status_code)
    android_id, apple_id, eap_id = device_ids("sub-alice")

    rows = sql("SELECT nas_ip, calling_station, user_name FROM radius_session WHERE device_id = %s", android_id)
    check("RADIUS records the latest session (for Disconnect)", len(rows) == 1 and rows[0][2] == "anonymous@scharni.org",
          rows)

    # --- first_seen: the dashboard's data starts at the first login with the MAC ----------
    session_of = lambda: sql("SELECT calling_station, first_seen, updated FROM radius_session "  # noqa: E731
                             "WHERE device_id = %s", android_id)[0]
    before = session_of()
    check("a new session has first_seen", before[1] is not None and before[1] <= before[2], before)
    time.sleep(1.1)
    connect("alice-android")
    same = session_of()
    check("a login with the same MAC keeps first_seen and moves updated", same[1] == before[1] and same[2] > before[2],
          (before, same))
    time.sleep(1.1)
    connect("alice-android", mac="02:00:00:00:00:99")
    moved = session_of()
    check("a login with another MAC starts first_seen again",
          moved[0].lower().replace("-", ":") == "02:00:00:00:00:99" and moved[1] > same[1], (same, moved))
    with registry.connect(DB) as db:
        claims = registry.mac_claims(db, ["02:00:00:00:00:99", "02:00:00:00:00:98"])
    check("the registry tells whose devices claim a MAC", claims == {"02:00:00:00:00:99": {"sub-alice"}}, claims)

    # --- ownership ------------------------------------------------------------------------
    c, _ = login(CAROL)
    r = c.post(PORTAL + "/devices/%s/revoke" % android_id, data={"csrf": csrf(c)})
    check("another resident cannot revoke alice's device", r.status_code == 404, r.status_code)
    r = c.get(PORTAL + "/")
    check("another resident does not see alice's devices", "alice android" not in r.text)

    # --- revocation: registry + Disconnect-Request ----------------------------------------
    s, _ = login(ALICE)
    sql("UPDATE radius_session SET nas_ip = '10.199.0.11'")        # the fake access point
    before = metric('netportal_disconnects_total{result="ack"}') or 0
    r = s.post(PORTAL + "/devices/%s/revoke" % android_id, data={"csrf": csrf(s)})
    check("revoke answers", r.status_code in (200, 302), r.status_code)
    after = metric('netportal_disconnects_total{result="ack"}') or 0
    check("revoke sends a Disconnect-Request the access point accepts (ACK)", after == before + 1, (before, after))
    forged = disconnect.disconnect({"nas_ip": "10.199.0.11", "calling_station": "02-00-00-00-00-01",
                                    "user_name": "anonymous@scharni.org"}, "not-the-secret", timeout=1, retries=0)
    check("the access point drops a Disconnect-Request with a wrong secret", forged == "timeout", forged)
    check("a revoked device cannot connect", connect("alice-android")[0] == "reject")
    check("other devices of the same person still connect", connect("alice-apple") == ("accept", "30"))

    # --- renewal --------------------------------------------------------------------------
    r = s.post(PORTAL + "/devices/%s/renew" % apple_id, data={"csrf": csrf(s)})
    link = re.search(r'href="(/download/[^"]+)"', r.text).group(1)
    key, cert, chain = from_mobileconfig(s.get(PORTAL + link).content)
    write_client("alice-apple-renewed", key, cert, chain)
    check("renewal: the new certificate connects", connect("alice-apple-renewed") == ("accept", "30"))
    check("renewal: the old certificate still works during the overlap", connect("alice-apple")[0] == "accept")
    sql("UPDATE credential SET retired_after = now() - interval '1 minute' WHERE retired_after IS NOT NULL "
        "AND device_id = %s", apple_id)
    check("renewal: after the overlap only the new certificate works",
          connect("alice-apple")[0] == "reject" and connect("alice-apple-renewed")[0] == "accept")
    check("renewal keeps one device", len(device_ids("sub-alice")) == 3)
    sql("UPDATE credential SET not_after = now() - interval '1 minute' WHERE device_id = %s", eap_id)
    check("an expired certificate cannot connect", connect("alice-eap-config")[0] == "reject")

    # --- the FreeRADIUS traps: certificates that must fail although the chain looks fine ----
    device_ca = pki.load(RUN / "pki" / "device-ca.pem", (RUN / "pki" / "device-ca.key").read_bytes())
    root = pki.load(RUN / "pki" / "root.pem", (RUN / "pki" / "root.key").read_bytes())
    _, unregistered = pki.device_cert(device_ca, "scharni.org")
    write_client("unregistered", unregistered.key, unregistered.cert, [device_ca.cert])
    check("a device-CA certificate that is not in the registry cannot connect",
          connect("unregistered")[0] == "reject")
    # Registered serials, so only the issuer checks stand in the way.
    other_root = pki.make_ca("Test Network Root", days=30, path_length=1)
    other_ca = pki.make_ca("Test Device CA", issuer=other_root, days=30, path_length=0)  # same names
    _, foreign = pki.device_cert(other_ca, "scharni.org")
    _, root_signed = pki.device_cert(root, "scharni.org")
    sql("INSERT INTO device (id, owner, name, kind, platform, policy) VALUES "
        "('00000000-0000-4000-8000-000000000001', 'sub-carol', 'trap', 'cert', 'apple', 'residents')")
    for issued in (foreign, root_signed):
        sql("INSERT INTO credential (serial, device_id, not_after) VALUES "
            "(%s, '00000000-0000-4000-8000-000000000001', now() + interval '1 day')", issued.serial_hex)
    write_client("foreign", foreign.key, foreign.cert, [other_ca.cert, other_root.cert])
    check("a certificate of a foreign CA with the same names cannot connect", connect("foreign")[0] == "reject")
    write_client("root-signed", root_signed.key, root_signed.cert, [root.cert])
    check("a certificate the root signed directly (not the device CA) cannot connect",
          connect("root-signed")[0] == "reject")
    sql("DELETE FROM device WHERE id = '00000000-0000-4000-8000-000000000001'")

    # --- Let's Wi-Fi (geteduroam apps) ----------------------------------------------------
    doc = requests.get(PORTAL + "/", headers={"Accept": "application/json"}).json()
    api = doc.get("http://letswifi.app/api#v2", {})
    check("the typed server address answers the apps' endpoint document",
          api.get("eapconfig_endpoint") == PORTAL + "/api/eap-config/", doc)
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    params = {"client_id": "app.geteduroam.sh", "redirect_uri": "http://127.0.0.1:43210/", "response_type": "code",
              "code_challenge": challenge, "code_challenge_method": "S256", "scope": "eap-metadata", "state": "xyz"}
    r = s.get(PORTAL + "/oauth/authorize", params={**params, "redirect_uri": "https://evil.example/"},
              allow_redirects=False)
    check("an unknown redirect URI is refused (no redirect)", r.status_code == 400, r.status_code)
    r = s.get(PORTAL + "/oauth/authorize", params=params)
    check("the app's login shows the consent page", "geteduroam" in r.text and r.status_code == 200, r.status_code)
    r = s.post(PORTAL + "/oauth/authorize", data={**params, "csrf": csrf(s, "/oauth/authorize?" + urllib.parse.urlencode(params)),
                                                  "name": "alice laptop"}, allow_redirects=False)
    q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(r.headers.get("Location", "")).query))
    check("consent redirects to the app with code and state", q.get("state") == "xyz" and q.get("code"), r.headers)
    token = {"grant_type": "authorization_code", "client_id": "app.geteduroam.sh", "code": q.get("code", ""),
             "redirect_uri": "http://127.0.0.1:43210/"}
    bad = requests.post(PORTAL + "/oauth/token", data={**token, "code_verifier": secrets.token_urlsafe(48)})
    check("a wrong PKCE verifier is refused", bad.status_code == 400, bad.text)
    # The failed try used the code: OAuth codes are single use, so the app starts again.
    r = s.post(PORTAL + "/oauth/authorize", data={**params, "csrf": csrf(s), "name": "alice laptop"},
               allow_redirects=False)
    token["code"] = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(r.headers["Location"]).query))["code"]
    tok = requests.post(PORTAL + "/oauth/token", data={**token, "code_verifier": verifier}).json()
    check("the code becomes access and refresh tokens", tok.get("access_token") and tok.get("refresh_token"), tok)
    replay = requests.post(PORTAL + "/oauth/token", data={**token, "code_verifier": verifier})
    check("a replayed code is refused", replay.status_code == 400, replay.status_code)
    eap = requests.post(PORTAL + "/api/eap-config/", headers={"Authorization": "Bearer " + tok.get("access_token", "")})
    check("a replayed code revokes the grant (its tokens stop working)", eap.status_code == 401, eap.status_code)
    # Once more, cleanly.
    r = s.post(PORTAL + "/oauth/authorize", data={**params, "csrf": csrf(s), "name": "alice laptop"},
               allow_redirects=False)
    token["code"] = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(r.headers["Location"]).query))["code"]
    tok = requests.post(PORTAL + "/oauth/token", data={**token, "code_verifier": verifier}).json()
    eap = requests.post(PORTAL + "/api/eap-config/", headers={"Authorization": "Bearer " + tok["access_token"]})
    check("the app gets an eap-config", eap.status_code == 200 and eap.headers["Content-Type"].startswith("application/eap-config"),
          eap.status_code)
    key, cert, chain = from_eap_config(eap.content)
    write_client("alice-app", key, cert, chain)
    check("the app's credential connects", connect("alice-app") == ("accept", "30"))
    ref = requests.post(PORTAL + "/oauth/token", data={"grant_type": "refresh_token", "client_id": "app.geteduroam.sh",
                                                       "refresh_token": tok["refresh_token"]}).json()
    eap2 = requests.post(PORTAL + "/api/eap-config/", headers={"Authorization": "Bearer " + ref.get("access_token", "")})
    key, cert, chain = from_eap_config(eap2.content)
    write_client("alice-app-renewed", key, cert, chain)
    check("refresh renews the app's certificate on the same device",
          connect("alice-app-renewed")[0] == "accept" and len(device_ids("sub-alice")) == 4)

    # Someone else's download link: refused, and not used up for its owner.
    spare = enrol(s, "apple", "alice spare")
    check("another resident cannot use alice's download link", c.get(PORTAL + spare).status_code == 404)
    check("... and the link still works for alice", s.get(PORTAL + spare).status_code == 200)
    # An app that got its tokens but has not fetched its profile yet (no device so far).
    r = s.post(PORTAL + "/oauth/authorize", data={**params, "csrf": csrf(s), "name": "alice tablet"},
               allow_redirects=False)
    token["code"] = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(r.headers["Location"]).query))["code"]
    pending = requests.post(PORTAL + "/oauth/token", data={**token, "code_verifier": verifier}).json()

    # --- admin ----------------------------------------------------------------------------
    a, _ = login(ADMIN)
    page = a.get(PORTAL + "/admin")
    check("an admin sees every device with its owner", page.status_code == 200 and "alice laptop" in page.text
          and "Alice" in page.text, page.status_code)
    check("a resident cannot open the admin view", s.get(PORTAL + "/admin").status_code == 403)

    # --- guests: former residents get the guests' VLAN (2026-10-22) ---------------------
    f, r = login(FIA)
    check("a former resident logs in", r.status_code == 200 and "Your devices" in r.text, r.status_code)
    key, cert, chain = from_eap_config(f.get(PORTAL + enrol(f, "eap-config", "fia phone")).content)
    write_client("fia", key, cert, chain)
    verdict = connect("fia")
    check("... and her device connects into the guests' VLAN 50", verdict == ("accept", "50"), verdict)
    c, _ = login(CAROL)
    key, cert, chain = from_eap_config(c.get(PORTAL + enrol(c, "eap-config", "carol phone")).content)
    write_client("carol", key, cert, chain)
    verdict = connect("carol")
    check("a resident's device connects into VLAN 30", verdict == ("accept", "30"), verdict)
    carol_phone = sql("SELECT id FROM device WHERE owner = 'sub-carol' AND name = 'carol phone'")[0][0]
    sql("UPDATE radius_session SET nas_ip = '10.199.0.11'")        # the fake access point
    users(("sub-carol", "carol", ["former-residents"], True), ALICE, ADMIN, FIA)   # carol moved out
    out = subprocess.run([sys.executable, "-m", "netportal", "offboard"], cwd=ROOT, capture_output=True, text=True)
    check("offboarding runs after someone moved out", out.returncode == 0, out.stderr[-300:])
    actions = {r[0] for r in sql("SELECT action FROM audit WHERE device_id = %s", carol_phone)}
    check("... her device moves to the guests' policy with a Disconnect, and is not revoked",
          {"policy:guests", "disconnect:ack"} <= actions
          and sql("SELECT policy, revoked FROM device WHERE id = %s", carol_phone)[0] == ("guests", None), actions)
    verdict = connect("carol")
    check("... and connects into VLAN 50 from then on", verdict == ("accept", "50"), verdict)
    c, r = login(("sub-carol", "carol", ["former-residents"], True), others=(ALICE, ADMIN, FIA))
    key, cert, chain = from_eap_config(c.get(PORTAL + enrol(c, "eap-config", "carol tablet")).content)
    write_client("carol-tablet", key, cert, chain)
    verdict = connect("carol-tablet")
    check("... and a device she enrols now too", verdict == ("accept", "50"), verdict)
    page = a.get(PORTAL + "/admin")
    check("the admin view shows each device's policy", ">guests<" in page.text and ">residents<" in page.text)
    # Admin rights are checked against the registry on every request (2026-10-22): removed from
    # it-admins, the open session loses the admin view at the next offboarding round.
    users(("sub-admin", "admin", ["residents"], True), ("sub-carol", "carol", ["former-residents"], True), ALICE, FIA)
    out = subprocess.run([sys.executable, "-m", "netportal", "offboard"], cwd=ROOT, capture_output=True, text=True)
    r = a.get(PORTAL + "/admin")
    check("someone removed from the admin group loses the admin view at once, in the open session",
          out.returncode == 0 and r.status_code == 403, (out.returncode, r.status_code))

    # --- offboarding ----------------------------------------------------------------------
    s, _ = login(ALICE)
    form_before = csrf(s)                 # alice's portal session from before she left
    users(("sub-alice", "alice", [], True), CAROL, ADMIN)
    out = subprocess.run([sys.executable, "-m", "netportal", "offboard"], cwd=ROOT, capture_output=True, text=True)
    check("offboarding runs", out.returncode == 0, out.stderr[-300:])
    check("someone who left the Wi-Fi groups loses every device",
          connect("alice-app-renewed")[0] == "reject" and connect("alice-apple-renewed")[0] == "reject")
    late = requests.post(PORTAL + "/api/eap-config/", headers={"Authorization": "Bearer " + pending["access_token"]})
    check("... and an app grant without a device yet cannot create one", late.status_code == 401
          and len(sql("SELECT 1 FROM device WHERE owner = 'sub-alice' AND revoked IS NULL")) == 0, late.status_code)
    r = s.post(PORTAL + "/enroll", data={"csrf": form_before, "format": "apple"}, allow_redirects=False)
    check("... and her open portal session cannot enrol a new device",
          r.status_code == 302 and "/login" in r.headers.get("Location", ""), r.status_code)
    r = s.get(PORTAL + "/", allow_redirects=False)
    check("... and the portal sends her to the login again (no page in between, 2026-10-19)",
          r.status_code == 302 and "/login" in r.headers.get("Location", ""), r.status_code)
    r = s.get(PORTAL + "/welcome")
    check("... the landing page stays at /welcome", r.status_code == 200 and "/login" in r.text, r.status_code)
    requests.post(IDP + "/_test/users", json=[])
    out = subprocess.run([sys.executable, "-m", "netportal", "offboard"], cwd=ROOT, capture_output=True, text=True)
    check("an empty Authentik answer revokes nothing (fails safe)", out.returncode != 0)

    # --- monitoring -----------------------------------------------------------------------
    text = requests.get(PORTAL + "/metrics").text
    check("metrics: devices and certificate states", "netportal_devices{state=\"active\"}" in text
          and "netportal_certificates{state=\"expiring_30d\"}" in text, text[:200])
    check("metrics: the offboarding sidecar's last success (from the registry)",
          (metric("netportal_offboarding_last_success_timestamp_seconds") or 0) > time.time() - 600)
    check("metrics: Disconnect results of the last hour (portal and offboarding)",
          (metric('netportal_disconnects_last_hour{result="ack"}') or 0) >= 1
          and metric('netportal_disconnects_last_hour{result="timeout"}') is not None)
    hidden = requests.get(PORTAL + "/metrics", headers={"X-Forwarded-For": "1.2.3.4"})
    check("metrics are not served through the proxy", hidden.status_code == 404, hidden.status_code)

    print("%d failure(s)" % len(failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
