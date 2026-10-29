#!/usr/bin/env python3
"""The Wi-Fi flows end to end, against the RUST stack (started by rust/tests/integration/run.sh
with IMPL=rust: the Rust portal, rust/radius/ and the Rust registry's schema).

A copy of tests/integration/e2e.py that differs ONLY in how it reaches the registry and the
implementation; every check keeps its name, its steps and its meaning. The differences, all of
them (rust/migrations/0001_registry.sql, 0002_radius_contract.sql, rust/docs/RADIUS_CONTRACT.md;
each changed line is marked "difference N" or "# N", except the four offboard calls, which
use CLI, difference 5):
  1. Column names: device.created -> created_at, device.revoked -> revoked_at,
     credential.retired_after -> retired_at, radius_auth.count -> tries.
  2. The expired case also moves credential.issued_at back two days: the Rust schema checks
     not_after > issued_at, and a certificate is issued before it expires.
  3. The FreeRADIUS contract lives in the schema radius: radius_cert -> radius.valid_cert,
     radius_reject / radius_login / radius_accounting -> radius.reject / radius.login /
     radius.accounting (in the role checks, the pool check's patterns and the REVOKE).
  4. The Python registry functions e2e.py calls are replaced by their Rust queries
     (crates/netportal-core/src/registry.rs: mac_claims, device_windows, acct_sessions; here
     module-level helpers of the same names), and the Python migrate by `$NETPORTAL_BIN init-db`.
  5. The CLI: `python -m netportal offboard` -> `$NETPORTAL_BIN offboard` (the binary under test).
  6. Security review 2026-10-29 (rust/docs/PARITY.md, deliberate deviations): /metrics is read on
     its own listener (METRICS, NETPORTAL_METRICS_LISTEN; the portal's port answers 404); a
     removal from the admin group ends the open portal session (to the login, not a 403); someone
     who lost access is offboarded by the second round that finds them so (two offboard calls).
pki (the trap certificates, signed with the Rust ceremony's CAs) and disconnect (the forged
Disconnect-Request) stay the Python package's, as test tooling exactly as in e2e.py.

The Wi-Fi flows end to end (started by tests/integration/run.sh).

A resident logs in through (mock) Authentik, enrols devices per platform, the access point
(eapol_test) connects with what the device would install, revocation cuts the session (a
Disconnect-Request the fake access point accepts) and the next connection fails; renewal,
the Let's Wi-Fi OAuth flow of the geteduroam apps, offboarding, admin rights, CSRF, metrics.
Telemetry v2 (docs/TELEMETRY.md): every decision logged with its reason, the Class token in the
Accept, accounting from the fake access point (radclient), the radius role's rights, and that
no logging failure (functions revoked, the database stopped) changes a decision.
"""

import base64
import hashlib
import os
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

ROOT = Path(__file__).resolve().parents[3]          # rust/tests/integration -> the repo root (difference: one level deeper than e2e.py)
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT))
from test_profiles import aosp_parse  # noqa: E402
from netportal import disconnect, pki  # noqa: E402   (difference 4: no registry)

PORTAL, IDP = "http://127.0.0.1:18080", "http://127.0.0.1:19000"
METRICS = "http://127.0.0.1:18090"   # difference 6: NETPORTAL_METRICS_LISTEN (run.sh)
DB = "postgresql://netportal:it-db-password@127.0.0.1:15432/netportal"
RUN = Path(sys.argv[1])
failures = []
LAST_REPLY = ""   # eapol_test output of the last connect()
RADIUS_DB = "postgresql://radius:it-radius-db-password@127.0.0.1:15432/netportal"
CALLED = "AA-BB-CC-00-00-01:Scharni"     # what hostapd sends: <BSSID>:<SSID>
FAKE_NAS = "10.199.0.11"
CLI = [os.environ["NETPORTAL_BIN"]]      # difference 5: the binary under test


# difference 4: registry.rs's queries for the Python registry functions e2e.py calls
def mac_claims(macs):
    """registry::mac_claims: {mac: {owner}} of active devices by their latest session."""
    claims = {}
    for mac, owner in sql("""SELECT np_mac(s.calling_station)::text, d.owner
                             FROM radius_session s JOIN device d ON d.id = s.device_id
                             WHERE d.revoked_at IS NULL AND np_mac(s.calling_station) = ANY(%s::macaddr[])""",
                          list(macs)):
        claims.setdefault(mac, set()).add(owner)
    return claims


def device_windows(device_ids):
    """registry::device_windows (open bounds): {device: [{"mac", "auth_count", "randomized", ...}]}."""
    result = {d: [] for d in device_ids}
    for row in sql("""SELECT device_id::text, mac::text, first_seen, last_seen, window_end, current, randomized,
                             auth_count FROM device_mac_window WHERE device_id = ANY(%s::uuid[])
                      ORDER BY first_seen, mac""", list(device_ids)):
        result[row[0]].append(dict(zip(("mac", "first_seen", "last_seen", "window_end", "current", "randomized",
                                        "auth_count"), row[1:])))
    return result


def acct_sessions(device_id):
    """registry::acct_sessions over the last hour, oldest first: [{"acct_session_id", ...}]."""
    rows = sql("""SELECT acct_session_id, host(nas_ip), started, updated, stopped FROM radius_acct
                  WHERE device_id = %s AND coalesce(started, updated) <= now()
                    AND coalesce(stopped, updated) >= now() - interval '1 hour'
                  ORDER BY coalesce(started, updated) DESC LIMIT 1000""", device_id)
    return [{"acct_session_id": r[0], "nas_ip": r[1], "started": r[2], "updated": r[3], "stopped": r[4]}
            for r in reversed(rows)]


def migrate():
    """The binary's init-db (it gets this process's NETPORTAL_* from run.sh)."""
    out = subprocess.run(CLI + ["init-db"], cwd=ROOT, capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError("init-db failed: %s" % out.stderr[-500:])


def check(name, ok, detail=""):
    print(("ok    " if ok else "FAIL  ") + name + ("" if ok else "  -> " + str(detail)[:1200]))
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
            "SELECT id FROM device WHERE owner = %s ORDER BY created_at", (owner_sub,))]   # difference 1


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


def connect(name, mac=None, timeout=10):
    """eapol_test as the access point: (verdict, vlan). mac: the device's MAC (Calling-Station-Id;
    eapol_test's default 02:00:00:00:00:01). Called-Station-Id as hostapd sends it."""
    out = subprocess.run(["docker", "run", "--rm", "--network", "netportal-it", "--ip", "10.199.0.20",
                          "-v", "%s:/client:ro" % (RUN / "client"), "-v", "%s:/pki:ro" % (RUN / "pki"),
                          "netportal-it-client", "eapol_test", "-c", "/client/%s.conf" % name,
                          "-a", "10.199.0.10", "-s", "it-radius-secret", "-r0", "-t", str(timeout),
                          "-N30:s:" + CALLED]
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


def reply_class():
    """The Class of the last connect()'s Access-Accept (text) or None."""
    m = re.search(r"Attribute 25 \(Class\) length=\d+\s+Value: ([0-9a-f]+)", LAST_REPLY)
    return bytes.fromhex(m.group(1)).decode() if m else None


def last_reject():
    """(reason, device id or None, serial) of the latest logged reject (a repeat adds to an
    earlier row: its last_at is the latest)."""
    rows = sql("SELECT reason, device_id::text, serial FROM radius_auth WHERE result = 'reject' "
               "ORDER BY coalesce(last_at, at) DESC, id DESC LIMIT 1")
    return tuple(rows[0]) if rows else None


def connect_many(name, n, mac, timeout=20):
    """n eapol_test runs at once from one access point (one container): how many ended with an
    Accept and EAP success."""
    run = ("eapol_test -c /client/%s.conf -a 10.199.0.10 -s it-radius-secret -r0 -t %d -N30:s:%s -M%s"
           % (name, timeout, CALLED, mac))
    script = ('for i in $(seq %d); do %s > /tmp/out.$i 2>&1 & done; wait; '
              'for i in $(seq %d); do grep -q "^SUCCESS" /tmp/out.$i && echo OK; done' % (n, run, n))
    out = subprocess.run(["docker", "run", "--rm", "--network", "netportal-it", "--ip", "10.199.0.20",
                          "-v", "%s:/client:ro" % (RUN / "client"), "-v", "%s:/pki:ro" % (RUN / "pki"),
                          "netportal-it-client", "sh", "-c", script], capture_output=True, text=True).stdout
    return out.split().count("OK")


def radius_pools():
    """{instance: [last query]} of FreeRADIUS's database connections (application_name
    "FreeRADIUS <version> - <name> (<instance>)")."""
    pools = {}
    for app, query in sql("SELECT application_name, query FROM pg_stat_activity WHERE application_name LIKE 'FreeRADIUS%%'"):
        m = re.search(r"\((\w+)\)$", app)
        if m:
            pools.setdefault(m.group(1), []).append(query or "")
    return pools


def accounting(attrs, nas=FAKE_NAS):
    """An Accounting-Request from the fake access point (radclient): True if answered. nas: the
    NAS-IP-Address it names (another access point of the house, from the same container)."""
    body = "".join("%s = %s\n" % kv for kv in [("NAS-IP-Address", nas)] + list(attrs.items()))
    out = subprocess.run(["docker", "exec", "-i", "netportal-it-nas", "radclient", "-t", "4", "-r", "2",
                          "10.199.0.10:1813", "acct", "it-radius-secret"], input=body, capture_output=True, text=True)
    return "Received Accounting-Response" in out.stdout


def acct_row(session_id):
    rows = sql("SELECT link, device_id::text, mac::text, bssid::text, ssid, host(framed_ip), started, stopped, "
               "session_time_s, input_octets, output_octets, terminate_cause FROM radius_acct "
               "WHERE nas_ip = %s AND acct_session_id = %s", FAKE_NAS, session_id)
    return rows[0] if rows else None


def radius_role_can(query):
    """Whether FreeRADIUS's role may run this query (False: permission denied)."""
    try:
        with psycopg.connect(RADIUS_DB) as db:
            db.execute(query)
            return True
    except psycopg.errors.InsufficientPrivilege:
        return False


def db_ready():
    for _ in range(60):
        try:
            with psycopg.connect(DB, connect_timeout=2) as db:
                db.execute("SELECT 1")
                return True
        except psycopg.OperationalError:
            time.sleep(1)
    return False


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
    text = requests.get(METRICS + "/metrics").text   # 6
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
    android_class = None
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
            m = re.search(r"Attribute 85 \(Acct-Interim-Interval\) length=6\s+Value: ([0-9]+)", LAST_REPLY)
            check("the Accept asks for accounting updates every NETPORTAL_ACCT_INTERIM_S (120 s here)",
                  m and int(m.group(1)) == 120, m and m.group(1))
            android_class = reply_class()
        again = s.get(PORTAL + link)
        check("%s: the download link works only once" % fmt, again.status_code == 404, again.status_code)
    android_id, apple_id, eap_id = device_ids("sub-alice")

    # --- telemetry: every login logged with the Class token the Accept carries --------------
    logged = sql("SELECT device_id::text, result, reason, mac::text, bssid::text, ssid FROM radius_auth "
                 "WHERE class_token = %s", android_class or "")
    check("the Accept carries a Class token, logged with the login (device, MAC, BSSID, SSID)",
          bool(re.fullmatch(r"np1:[-_0-9A-Za-z]{22}", android_class or ""))
          and logged == [(android_id, "accept", "ok", "02:00:00:00:00:01", "aa:bb:cc:00:00:01", "Scharni")],
          (android_class, logged))

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
    claims = mac_claims(["02:00:00:00:00:99", "02:00:00:00:00:98"])          # difference 4
    windows = device_windows([android_id])[android_id]
    check("the registry tells whose devices claim a MAC", claims == {"02:00:00:00:00:99": {"sub-alice"}}, claims)
    check("both MACs of the device are kept as identities with their logins (device_mac)",
          [(w["mac"], w["auth_count"], w["randomized"]) for w in windows]
          == [("02:00:00:00:00:01", 2, True), ("02:00:00:00:00:99", 1, True)], windows)

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
    check("... and the reject is logged with its reason (revoked, the device)",
          last_reject()[:2] == ("revoked", android_id), last_reject())
    check("other devices of the same person still connect", connect("alice-apple") == ("accept", "30"))

    # --- renewal --------------------------------------------------------------------------
    r = s.post(PORTAL + "/devices/%s/renew" % apple_id, data={"csrf": csrf(s)})
    link = re.search(r'href="(/download/[^"]+)"', r.text).group(1)
    key, cert, chain = from_mobileconfig(s.get(PORTAL + link).content)
    write_client("alice-apple-renewed", key, cert, chain)
    check("renewal: the new certificate connects", connect("alice-apple-renewed") == ("accept", "30"))
    check("renewal: the old certificate still works during the overlap", connect("alice-apple")[0] == "accept")
    sql("UPDATE credential SET retired_at = now() - interval '1 minute' WHERE retired_at IS NOT NULL "   # difference 1
        "AND device_id = %s", apple_id)
    old_cert = connect("alice-apple")[0]
    retired = last_reject()
    check("renewal: after the overlap only the new certificate works",
          old_cert == "reject" and connect("alice-apple-renewed")[0] == "accept")
    check("... the old certificate's reject is logged as retired", retired[:2] == ("retired", apple_id), retired)
    check("renewal keeps one device", len(device_ids("sub-alice")) == 3)
    sql("UPDATE credential SET issued_at = now() - interval '2 days', not_after = now() - interval '1 minute' "
        "WHERE device_id = %s", eap_id)                                          # difference 2
    check("an expired certificate cannot connect", connect("alice-eap-config")[0] == "reject")
    check("... logged as expired", last_reject()[:2] == ("expired", eap_id), last_reject())

    # --- the FreeRADIUS traps: certificates that must fail although the chain looks fine ----
    device_ca = pki.load(RUN / "pki" / "device-ca.pem", (RUN / "pki" / "device-ca.key").read_bytes())
    root = pki.load(RUN / "pki" / "root.pem", (RUN / "pki" / "root.key").read_bytes())
    _, unregistered = pki.device_cert(device_ca, "scharni.org")
    write_client("unregistered", unregistered.key, unregistered.cert, [device_ca.cert])
    check("a device-CA certificate that is not in the registry cannot connect",
          connect("unregistered")[0] == "reject")
    check("... logged as unknown_cert with its serial, no device",
          last_reject() == ("unknown_cert", None, unregistered.serial_hex.lower()), last_reject())
    connect("unregistered")
    rows = sql("SELECT tries, last_at > at FROM radius_auth WHERE serial = %s",   # difference 1
               unregistered.serial_hex.lower())
    check("a repeated reject (same MAC, reason, serial, AP within 60 s) adds to its row: one row, count 2",
          [tuple(r) for r in rows] == [(2, True)], rows)
    nocert = (RUN / "client" / "alice-android.conf").read_text().replace(' client_cert="/client/alice-android.crt"\n', "")
    (RUN / "client" / "no-cert.conf").write_text(nocert.replace(' private_key="/client/alice-android.key"\n', ""))
    (RUN / "client" / "no-cert.conf").chmod(0o644)
    check("EAP-TLS without a client certificate cannot connect, logged as no_cert",
          connect("no-cert")[0] == "reject" and last_reject() == ("no_cert", None, None), last_reject())
    out = subprocess.run(["docker", "exec", "-i", "netportal-it-nas", "radclient", "-t", "4", "10.199.0.10:1812", "auth",
                          "it-radius-secret"], capture_output=True, text=True,
                         input='User-Name = "bob", User-Password = "x", Message-Authenticator = 0x00\n').stdout
    check("a request without EAP (password) is rejected, logged as not_eap",
          "Access-Reject" in out and last_reject() == ("not_eap", None, None), (out[-200:], last_reject()))
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
    check("... logged as bad_chain (its chain did not verify)", last_reject()[:2] == ("bad_chain", None), last_reject())
    write_client("root-signed", root_signed.key, root_signed.cert, [root.cert])
    check("a certificate the root signed directly (not the device CA) cannot connect",
          connect("root-signed")[0] == "reject")
    check("... logged as bad_chain, not attributed to the registered device (not proven ours)",
          last_reject() == ("bad_chain", None, root_signed.serial_hex.lower()), last_reject())
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
    out = subprocess.run(CLI + ["offboard"], cwd=ROOT, capture_output=True, text=True)
    check("offboarding runs after someone moved out", out.returncode == 0, out.stderr[-300:])
    actions = {r[0] for r in sql("SELECT action FROM audit WHERE device_id = %s", carol_phone)}
    check("... her device moves to the guests' policy with a Disconnect, and is not revoked",
          {"policy:guests", "disconnect:ack"} <= actions
          and sql("SELECT policy, revoked_at FROM device WHERE id = %s",   # difference 1
                  carol_phone)[0] == ("guests", None), actions)
    verdict = connect("carol")
    check("... and connects into VLAN 50 from then on", verdict == ("accept", "50"), verdict)
    c, r = login(("sub-carol", "carol", ["former-residents"], True), others=(ALICE, ADMIN, FIA))
    key, cert, chain = from_eap_config(c.get(PORTAL + enrol(c, "eap-config", "carol tablet")).content)
    write_client("carol-tablet", key, cert, chain)
    verdict = connect("carol-tablet")
    check("... and a device she enrols now too", verdict == ("accept", "50"), verdict)
    page = a.get(PORTAL + "/admin")
    check("the admin view shows each device's policy", ">guests<" in page.text and ">residents<" in page.text)
    telemetry_checks(sql("SELECT id::text FROM device WHERE owner = 'sub-carol' AND name = 'carol tablet'")[0][0], c)
    # Admin rights are checked against the registry on every request (2026-10-22): removed from
    # it-admins, the open session loses the admin view at the next offboarding round.
    users(("sub-admin", "admin", ["residents"], True), ("sub-carol", "carol", ["former-residents"], True), ALICE, FIA)
    out = subprocess.run(CLI + ["offboard"], cwd=ROOT, capture_output=True, text=True)
    r = a.get(PORTAL + "/admin", allow_redirects=False)       # 6: the open session ends (to the login)
    check("someone removed from the admin group loses the admin view at once, in the open session",
          out.returncode == 0 and r.status_code == 302 and "/login" in r.headers.get("Location", ""),
          (out.returncode, r.status_code))

    # --- offboarding ----------------------------------------------------------------------
    s, _ = login(ALICE)
    form_before = csrf(s)                 # alice's portal session from before she left
    users(("sub-alice", "alice", [], True), CAROL, ADMIN)
    first = subprocess.run(CLI + ["offboard"], cwd=ROOT, capture_output=True, text=True)   # 6: noted only
    out = subprocess.run(CLI + ["offboard"], cwd=ROOT, capture_output=True, text=True)
    check("offboarding runs", first.returncode == 0 and out.returncode == 0, (first.stderr + out.stderr)[-300:])
    check("someone who left the Wi-Fi groups loses every device",
          connect("alice-app-renewed")[0] == "reject" and connect("alice-apple-renewed")[0] == "reject")
    late = requests.post(PORTAL + "/api/eap-config/", headers={"Authorization": "Bearer " + pending["access_token"]})
    check("... and an app grant without a device yet cannot create one", late.status_code == 401
          and len(sql("SELECT 1 FROM device WHERE owner = 'sub-alice' AND revoked_at IS NULL")) == 0,  # difference 1
          late.status_code)
    r = s.post(PORTAL + "/enroll", data={"csrf": form_before, "format": "apple"}, allow_redirects=False)
    check("... and her open portal session cannot enrol a new device",
          r.status_code == 302 and "/login" in r.headers.get("Location", ""), r.status_code)
    r = s.get(PORTAL + "/", allow_redirects=False)
    check("... and the portal sends her to the login again (no page in between, 2026-10-19)",
          r.status_code == 302 and "/login" in r.headers.get("Location", ""), r.status_code)
    r = s.get(PORTAL + "/welcome")
    check("... the landing page stays at /welcome", r.status_code == 200 and "/login" in r.text, r.status_code)
    requests.post(IDP + "/_test/users", json=[])
    out = subprocess.run(CLI + ["offboard"], cwd=ROOT, capture_output=True, text=True)
    check("an empty Authentik answer revokes nothing (fails safe)", out.returncode != 0)

    # --- monitoring -----------------------------------------------------------------------
    text = requests.get(METRICS + "/metrics").text   # 6
    check("metrics: devices and certificate states", "netportal_devices{state=\"active\"}" in text
          and "netportal_certificates{state=\"expiring_30d\"}" in text, text[:200])
    check("metrics: the offboarding sidecar's last success (from the registry)",
          (metric("netportal_offboarding_last_success_timestamp_seconds") or 0) > time.time() - 600)
    check("metrics: Disconnect results of the last hour (portal and offboarding)",
          (metric('netportal_disconnects_last_hour{result="ack"}') or 0) >= 1
          and metric('netportal_disconnects_last_hour{result="timeout"}') is not None)
    hidden = requests.get(METRICS + "/metrics", headers={"X-Forwarded-For": "1.2.3.4"})   # 6
    check("metrics are not served through the proxy", hidden.status_code == 404, hidden.status_code)
    public = requests.get(PORTAL + "/metrics")   # 6
    check("metrics are not served on the portal's own port", public.status_code == 404, public.status_code)

    print("%d failure(s)" % len(failures))
    return 1 if failures else 0


def presence_of(portal, device_id, etag=None):
    """(status, DEVICE or None, ETag, poll_s) of GET /api/devices/<id> as the dashboard polls it."""
    r = portal.get(PORTAL + "/api/devices/%s" % device_id, headers={"If-None-Match": etag} if etag else {})
    body = r.json() if r.status_code == 200 else {}
    return r.status_code, body.get("device"), r.headers.get("ETag"), body.get("poll_s")


def presence_checks(tablet, portal, mac):
    """Presence (docs/TELEMETRY.md): the portal has no Prometheus here, so RADIUS decides alone:
    a fresh login is connecting, its Start online, a roam's late Stop of the old AP changes
    nothing, the current session's Stop is offline at once, reordered and repeated packets change
    nothing, the measured interval sets the staleness, the AP's Accounting-Off ends it; the API
    answers 304 while nothing changed."""
    ap_a, ap_b = "10.199.0.31", "10.199.0.32"
    connect("carol-tablet", mac=mac)
    token = "0x" + (reply_class() or "").encode().hex()
    base = {"Calling-Station-Id": '"A4-83-E7-00-00-05"', "Called-Station-Id": '"AA-BB-CC-00-00-03:Scharni"',
            "Class": token}
    status, dev, tag, poll = presence_of(portal, tablet)
    check("presence: a fresh login without an accounting Start is connecting (radius_auth), polled fast",
          status == 200 and dev["state"] == "connecting" and dev["presence"]["confirmed_by"] == "radius_auth"
          and poll == 5 and not any(f["code"] == "offline" for f in dev["diagnostics"]),
          (status, dev and dev["state"], dev and [(e["kind"], e["at"]) for e in dev["presence"]["evidence"]],
           sql("SELECT acct_session_id, started, stopped FROM radius_acct WHERE device_id = %s", tablet),
           sql("SELECT updated FROM radius_session WHERE device_id = %s", tablet)))
    # Event-Timestamps up to now + 7 below: never in the future (radius_accounting takes a future
    # one as its arrival), and after the login (the earlier sessions ended before it)
    time.sleep(9)
    now = -int(-time.time()) - 8       # whole seconds after the earlier sessions' (sub-second) times
    accounting({**base, "Acct-Status-Type": "Start", "Acct-Session-Id": '"P-1"', "Event-Timestamp": str(now)}, nas=ap_a)
    status, dev, tag, poll = presence_of(portal, tablet)
    check("presence: the Start makes it online at once (radius_acct, acct_start), since the Start",
          dev and dev["state"] == "online" and dev["presence"]["reason"] == "acct_start"
          and dev["presence"]["session"]["acct_session_id"] == "P-1" and dev["since"] is not None,
          dev and dev["presence"])
    accounting({**base, "Acct-Status-Type": "Start", "Acct-Session-Id": '"P-2"', "Event-Timestamp": str(now + 1)},
               nas=ap_b)
    accounting({**base, "Acct-Status-Type": "Stop", "Acct-Session-Id": '"P-1"', "Acct-Session-Time": "2",
                "Acct-Terminate-Cause": "User-Request", "Event-Timestamp": str(now + 2)}, nas=ap_a)
    status, dev, tag, poll = presence_of(portal, tablet)
    check("presence: a roam (new AP's Start before the old AP's Stop) stays online on the new session",
          dev and dev["state"] == "online" and dev["presence"]["session"]["acct_session_id"] == "P-2"
          and dev["presence"]["session"]["nas_ip"] == ap_b, dev and dev["presence"])
    status, _dev, tag2, _ = presence_of(portal, tablet, tag)
    check("presence: nothing changed -> 304 with the same ETag", status == 304 and tag2 == tag, (status, tag, tag2))
    # reordered: an earlier session's Stop arrives before its Start
    accounting({**base, "Acct-Status-Type": "Stop", "Acct-Session-Id": '"P-3"', "Acct-Session-Time": "5",
                "Event-Timestamp": str(now - 10)}, nas=ap_b)
    accounting({**base, "Acct-Status-Type": "Start", "Acct-Session-Id": '"P-3"', "Event-Timestamp": str(now - 15)},
               nas=ap_b)
    row = sql("SELECT started, stopped FROM radius_acct WHERE nas_ip = %s AND acct_session_id = 'P-3'", ap_b)
    check("accounting: a Stop that overtook its Start leaves the session stopped",
          row and row[0][1] is not None and row[0][0] is not None and row[0][0] < row[0][1], row)
    status, dev, _tag, _ = presence_of(portal, tablet)
    check("presence: ... and the session that is still running keeps it online",
          dev and dev["state"] == "online" and dev["presence"]["session"]["acct_session_id"] == "P-2",
          dev and dev["presence"])
    stop = {**base, "Acct-Status-Type": "Stop", "Acct-Session-Id": '"P-2"', "Acct-Session-Time": "4",
            "Acct-Terminate-Cause": "User-Request", "Event-Timestamp": str(now + 5)}
    accounting(stop, nas=ap_b)
    status, dev, tag, poll = presence_of(portal, tablet)
    check("presence: the Stop of the current session is offline at once (radius_acct, acct_stop), not connected",
          dev and dev["state"] == "offline" and dev["presence"]["reason"] == "acct_stop" and poll == 5
          and any(f["code"] == "offline" and f["evidence"]["confirmed_by"] == "radius_acct" for f in dev["diagnostics"]),
          dev and dev["presence"])
    accounting(stop, nas=ap_b)                                            # the AP repeats its Stop
    accounting({**base, "Acct-Status-Type": "Interim-Update", "Acct-Session-Id": '"P-2"', "Acct-Session-Time": "3",
                "Event-Timestamp": str(now + 4)}, nas=ap_b)              # and a late Interim arrives
    status, _dev, tag2, _ = presence_of(portal, tablet, tag)
    check("presence: a repeated Stop and a late Interim change nothing (304)", status == 304 and tag2 == tag,
          (status, _dev and _dev["presence"]))
    # the measured interval: Start and Interim 120 s apart
    accounting({**base, "Acct-Status-Type": "Start", "Acct-Session-Id": '"P-4"', "Event-Timestamp": str(now - 240)},
               nas=ap_a)
    accounting({**base, "Acct-Status-Type": "Interim-Update", "Acct-Session-Id": '"P-4"', "Acct-Session-Time": "120",
                "Event-Timestamp": str(now - 120)}, nas=ap_a)
    accounting({**base, "Acct-Status-Type": "Start", "Acct-Session-Id": '"P-5"', "Event-Timestamp": str(now + 6)},
               nas=ap_a)
    status, dev, _tag, _ = presence_of(portal, tablet)
    measured = sql("SELECT interim_s FROM radius_acct WHERE nas_ip = %s AND acct_session_id = 'P-4'", ap_a)
    check("accounting: the measured interval is recorded (120 s) and applies to the AP's new session (300 s stale)",
          measured == [(120,)] and dev and dev["state"] == "online"
          and dev["presence"]["session"]["acct_session_id"] == "P-5"
          and dev["presence"]["session"]["interim_s"] == 120 and dev["presence"]["stale_after_s"] == 300,
          (measured, dev and dev["presence"]))
    accounting({"Acct-Status-Type": "Accounting-Off", "Event-Timestamp": str(now + 7)}, nas=ap_a)
    status, dev, _tag, _ = presence_of(portal, tablet)
    check("presence: the AP's Accounting-Off ends its sessions: offline (ap_down)",
          dev and dev["state"] == "offline" and dev["presence"]["reason"] == "ap_down", dev and dev["presence"])


def telemetry_checks(tablet, portal=None):
    """Accounting from the fake access point, the radius role's rights, and fail-open logging.
    tablet: an active device whose credential is RUN/client/carol-tablet.*; portal: its owner's
    logged-in session (the presence checks)."""
    mac = "a4:83:e7:00:00:05"
    connect("carol-tablet", mac=mac)
    token = reply_class()
    now = int(time.time())
    base = {"Calling-Station-Id": '"A4-83-E7-00-00-05"', "Called-Station-Id": '"AA-BB-CC-00-00-02:Scharni"'}
    answered = [accounting({**base, "Acct-Status-Type": "Start", "Acct-Session-Id": '"IT-1"',
                            "Class": "0x" + (token or "").encode().hex(), "Framed-IP-Address": "10.50.0.7",
                            "Event-Timestamp": str(now - 120)}),
                accounting({**base, "Acct-Status-Type": "Interim-Update", "Acct-Session-Id": '"IT-1"',
                            "Class": "0x" + (token or "").encode().hex(), "Acct-Session-Time": "60",
                            "Acct-Input-Octets": "1000", "Acct-Input-Gigawords": "1", "Acct-Output-Octets": "500",
                            "Event-Timestamp": str(now - 60)})]
    row = acct_row("IT-1")
    check("accounting Start and Interim with the Accept's Class: the session belongs to the device (link class)",
          all(answered) and row and row[:6] == ("class", tablet, mac, "aa:bb:cc:00:00:02", "Scharni", "10.50.0.7")
          and row[9] == 2 ** 32 + 1000 and row[10] == 500 and row[7] is None, (answered, row))
    answered = accounting({**base, "Acct-Status-Type": "Stop", "Acct-Session-Id": '"IT-1"', "Acct-Session-Time": "120",
                           "Acct-Input-Octets": "2000", "Acct-Input-Gigawords": "1", "Acct-Output-Octets": "900",
                           "Acct-Terminate-Cause": "User-Request", "Event-Timestamp": str(now)})
    row = acct_row("IT-1")
    check("accounting Stop ends the session with its cause, time and octets",
          answered and row and row[7] is not None and row[8:] == (120, 2 ** 32 + 2000, 900, "User-Request"), row)
    answered = accounting({**base, "Acct-Status-Type": "Start", "Acct-Session-Id": '"IT-2"'})
    row = acct_row("IT-2")
    check("accounting without Class: linked by the MAC's window (mac_window)",
          answered and row and row[:2] == ("mac_window", tablet), row)
    answered = accounting({"Calling-Station-Id": '"A4-83-E7-00-00-77"', "Acct-Status-Type": "Start",
                           "Acct-Session-Id": '"IT-3"'})
    row = acct_row("IT-3")
    check("accounting of a MAC no device logged in with: kept, linked to nobody", answered and row
          and row[:2] == ("none", None), row)
    answered = accounting({"Acct-Status-Type": "Accounting-On"})
    rows = {sid: acct_row(sid) for sid in ("IT-1", "IT-2", "IT-3")}
    check("Accounting-On (the access point restarted) closes its open sessions",
          answered and all(r[7] is not None for r in rows.values())
          and [rows[s][11] for s in ("IT-1", "IT-2", "IT-3")] == ["User-Request", "NAS-Reboot", "NAS-Reboot"], rows)
    sessions = acct_sessions(tablet)                                             # difference 4
    check("the registry lists the device's sessions", [s["acct_session_id"] for s in sessions] == ["IT-1", "IT-2"],
          sessions)
    if portal is not None:
        presence_checks(tablet, portal, mac)

    # --- the radius role: the decision view and the logging functions, no table ---------
    check("the radius role reads the decision view", radius_role_can("SELECT * FROM radius.valid_cert"))  # 3
    check("the radius role cannot read people, devices or sessions",
          not any(radius_role_can("SELECT 1 FROM %s" % t) for t in ("person", "device", "credential",
                                                                     "radius_session", "radius_auth", "radius_acct")))
    check("the radius role cannot write the session table directly (only through radius.login)",  # 3
          not radius_role_can("UPDATE radius_session SET nas_ip = '1.2.3.4'"))
    check("the radius role may call the logging functions",
          radius_role_can("SELECT radius.reject('', '', '', '', 'other')"))  # difference 3

    # --- logging has its own connection pool (radius/mods/sql_log) ----------------------------
    connect("carol-tablet", mac=mac)
    pools = radius_pools()
    logging_calls = re.compile(r"radius\.(login|reject|accounting)\(")            # difference 3
    check("the logging calls run on their own pool (sql_log), the decision's pool (sql) only reads radius.valid_cert",
          any(logging_calls.search(q) for q in pools.get("sql_log", []))
          and not any(logging_calls.search(q) for q in pools.get("sql", []))
          and any("radius.valid_cert" in q for q in pools.get("sql", [])), pools)  # difference 3
    # Logging blocked (the tables it writes locked, as a long transaction might): logins still
    # get in, also more at once than either pool has connections, and are answered in time.
    blocker = psycopg.connect(DB)
    try:
        blocker.execute("LOCK TABLE radius_auth, device_mac, radius_session IN ACCESS EXCLUSIVE MODE")
        began = time.monotonic()
        verdict = connect("carol-tablet", mac=mac)
        took = time.monotonic() - began
        check("with logging blocked, a valid device still connects (without Class), in time",
              verdict == ("accept", "50") and reply_class() is None and took < 8, (verdict, round(took, 1)))
        check("... and an unregistered one is still rejected", connect("unregistered")[0] == "reject")
        accepted = connect_many("carol-tablet", 10, mac)
        check("... and ten logins at once all get in (more than the 8 decision and 4 logging connections)",
              accepted == 10, accepted)
    finally:
        blocker.rollback()
        blocker.close()

    # --- fail open for logging, fail closed for access --------------------------------------
    sql("REVOKE EXECUTE ON FUNCTION radius.login(text, text, text, text, text, text, text), "   # difference 3
        "radius.reject(text, text, text, text, text), radius.accounting(" + ", ".join(["text"] * 14) + ") FROM radius")
    before = sql("SELECT count(*) FROM radius_auth")[0][0]
    verdict = connect("carol-tablet", mac=mac)
    check("with the logging functions failing, a valid device still connects (without Class)",
          verdict == ("accept", "50") and reply_class() is None, verdict)
    check("... and an unregistered one is still rejected", connect("unregistered")[0] == "reject")
    check("... and accounting is still answered", accounting({**base, "Acct-Status-Type": "Start",
                                                             "Acct-Session-Id": '"IT-4"'}))
    check("... (nothing was logged)", sql("SELECT count(*) FROM radius_auth")[0][0] == before and acct_row("IT-4") is None)
    migrate()                  # radius_grants.sql: the declared rights again (difference 4)
    verdict = connect("carol-tablet", mac=mac)
    check("migrate restores the radius role's rights (declarative grants): logged with Class again",
          verdict == ("accept", "50") and reply_class() is not None, verdict)
    subprocess.run(["docker", "stop", "-t", "5", "netportal-it-pg"], capture_output=True)
    try:
        verdict = connect("carol-tablet", mac=mac, timeout=30)
        check("with the database down nobody gets in (fail closed)", verdict[0] != "accept", verdict)
        check("... and accounting is still answered", accounting({**base, "Acct-Status-Type": "Interim-Update",
                                                                 "Acct-Session-Id": '"IT-5"'}))
    finally:
        subprocess.run(["docker", "start", "netportal-it-pg"], capture_output=True)
    ready = db_ready()
    for _ in range(5):                         # FreeRADIUS reconnects its pool
        verdict = connect("carol-tablet", mac=mac)
        if verdict[0] == "accept":
            break
        time.sleep(2)
    check("... and once it is back, the device connects again", ready and verdict == ("accept", "50"), verdict)


if __name__ == "__main__":
    sys.exit(main())
