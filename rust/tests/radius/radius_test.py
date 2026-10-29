#!/usr/bin/env python3
"""The RADIUS checks against the Rust registry (started by rust/tests/radius/run.sh).

FreeRADIUS runs rust/radius/ against a database migrated by the Rust binary; eapol_test and
radclient play the access point. The cases and their expected values are tests/integration/e2e.py's
(the names below are e2e.py's check names where the check is the same), so a pass here means
the same decisions and the same records as the Python setup (radius/ + the Python schema),
which tests/integration/run.sh shows. What e2e.py checks through the portal (enrolment,
Disconnect, presence API, offboarding) is not here: that is rust/tests/integration/.

The registry is written with the registry's own SQL (crates/netportal-core/src/registry.rs:
create_device, add_credential, revoke), read with its queries (mac_claims, device_windows,
acct_sessions), and the radius role is used only as FreeRADIUS uses it.

Environment (run.sh): RT_RUN, RT_DB (superuser), RT_RADIUS_DB (role radius), RT_PG_CONTAINER,
RT_AP_CONTAINER, RT_MIGRATE (shell command: the migration step).
"""

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import psycopg

RUN = Path(os.environ["RT_RUN"])
DB = os.environ["RT_DB"]
RADIUS_DB = os.environ["RT_RADIUS_DB"]
PG = os.environ["RT_PG_CONTAINER"]
AP = os.environ["RT_AP_CONTAINER"]
MIGRATE = os.environ["RT_MIGRATE"]
RADIUS_IP, SECRET = "10.198.0.10", "rt-radius-secret"
CALLED = "AA-BB-CC-00-00-01:Scharni"     # what hostapd sends: <BSSID>:<SSID>
FAKE_NAS = "10.198.0.11"                 # the NAS-IP-Address the accounting packets name
CERTS = json.loads((RUN / "certs.json").read_text())
failures = []
LAST_REPLY = ""


def check(name, ok, detail=""):
    print(("ok    " if ok else "FAIL  ") + name + ("" if ok else "  -> " + str(detail)[:1200]))
    if not ok:
        failures.append(name)


def sql(query, *args):
    with psycopg.connect(DB) as db:
        cur = db.execute(query, args)
        rows = list(cur) if cur.description else cur.rowcount
        db.commit()
        return rows


# --- the registry, as the portal writes it (registry.rs) -------------------------------------------

def person(sub, username, policy):
    sql("INSERT INTO person (sub, username, display_name, policy) VALUES (%s, %s, %s, %s)",
        sub, username, username.title(), policy)


def create_device(name, owner, policy, platform="eap-config"):
    """registry::create_device with the certificate's device id, then registry::add_credential."""
    cert = CERTS[name]
    sql("INSERT INTO device (id, owner, name, kind, platform, policy) VALUES (%s, %s, %s, 'cert', %s, %s)",
        cert["device_id"], owner, name, platform, policy)
    add_credential(name)
    return cert["device_id"]


def add_credential(name, overlap_days=2):
    """registry::add_credential: the device's earlier credentials end after the overlap."""
    cert = CERTS[name]
    sql("UPDATE credential SET retired_at = now() + make_interval(days => %s) WHERE device_id = %s AND retired_at IS NULL",
        overlap_days, cert["device_id"])
    sql("INSERT INTO credential (serial, device_id, not_after) VALUES (%s, %s, to_timestamp(%s))",
        cert["serial"].lower(), cert["device_id"], cert["not_after"])


def write_conf(name, client_cert=True):
    (RUN / "client" / (name + ".conf")).write_text(
        'network={\n ssid="Scharni"\n key_mgmt=WPA-EAP\n eap=TLS\n identity="anonymous@scharni.org"\n'
        ' ca_cert="/pki/root.pem"\n'
        + (' client_cert="/client/%s.crt"\n private_key="/client/%s.key"\n' % (name, name) if client_cert else "")
        + ' domain_match="radius.scharni.org"\n phase1="tls_disable_tlsv1_3=0"\n}\n')
    (RUN / "client" / (name + ".conf")).chmod(0o644)


# --- the access point -----------------------------------------------------------------------------

def connect(name, mac=None, timeout=10):
    """eapol_test as the access point: (verdict, vlan); as e2e.py's connect()."""
    out = subprocess.run(["docker", "exec", AP, "eapol_test", "-c", "/client/%s.conf" % name, "-a", RADIUS_IP,
                          "-s", SECRET, "-r0", "-t", str(timeout), "-N30:s:" + CALLED]
                         + (["-M" + mac] if mac else []), capture_output=True, text=True).stdout
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
    m = re.search(r"Attribute 25 \(Class\) length=\d+\s+Value: ([0-9a-f]+)", LAST_REPLY)
    return bytes.fromhex(m.group(1)).decode() if m else None


def connect_many(name, n, mac, timeout=20):
    run = ("eapol_test -c /client/%s.conf -a %s -s %s -r0 -t %d -N30:s:%s -M%s"
           % (name, RADIUS_IP, SECRET, timeout, CALLED, mac))
    script = ('for i in $(seq %d); do %s > /tmp/out.$i 2>&1 & done; wait; '
              'for i in $(seq %d); do grep -q "^SUCCESS" /tmp/out.$i && echo OK; done' % (n, run, n))
    out = subprocess.run(["docker", "exec", AP, "sh", "-c", script], capture_output=True, text=True).stdout
    return out.split().count("OK")


def accounting(attrs, nas=FAKE_NAS):
    body = "".join("%s = %s\n" % kv for kv in [("NAS-IP-Address", nas)] + list(attrs.items()))
    out = subprocess.run(["docker", "exec", "-i", AP, "radclient", "-t", "4", "-r", "2", "%s:1813" % RADIUS_IP,
                          "acct", SECRET], input=body, capture_output=True, text=True)
    return "Received Accounting-Response" in out.stdout


# --- reading the registry (schema of rust/migrations) ---------------------------------------------

def last_reject():
    """(reason, device id or None, serial) of the latest logged reject (a repeat adds to its row)."""
    rows = sql("SELECT reason, device_id::text, serial FROM radius_auth WHERE result = 'reject' "
               "ORDER BY coalesce(last_at, at) DESC, id DESC LIMIT 1")
    return tuple(rows[0]) if rows else None


def acct_row(session_id, nas=FAKE_NAS):
    rows = sql("SELECT link, device_id::text, mac::text, bssid::text, ssid, host(framed_ip), started, stopped, "
               "session_time_s, input_octets, output_octets, terminate_cause, interim_s, updated FROM radius_acct "
               "WHERE nas_ip = %s AND acct_session_id = %s", nas, session_id)
    return rows[0] if rows else None


def mac_claims(macs):
    """registry::mac_claims: {mac: owners} by the latest session of active devices."""
    claims = {}
    for mac, owner in sql("""SELECT np_mac(s.calling_station)::text AS mac, d.owner
                             FROM radius_session s JOIN device d ON d.id = s.device_id
                             WHERE d.revoked_at IS NULL AND np_mac(s.calling_station) = ANY(%s::macaddr[])""",
                          list(macs)):
        claims.setdefault(mac, set()).add(owner)
    return claims


def device_windows(device_id):
    """registry::device_windows (open bounds): [(mac, auth_count, randomized)], oldest first."""
    return [tuple(r) for r in sql("""SELECT mac::text, auth_count, randomized FROM device_mac_window
                                     WHERE device_id = %s ORDER BY first_seen, mac""", device_id)]


def acct_sessions(device_id):
    """registry::acct_sessions over the last hour: the session ids, oldest first."""
    rows = sql("""SELECT acct_session_id FROM radius_acct
                  WHERE device_id = %s AND coalesce(started, updated) <= now()
                    AND coalesce(stopped, updated) >= now() - interval '1 hour'
                  ORDER BY coalesce(started, updated) DESC LIMIT 1000""", device_id)
    return [r[0] for r in reversed(rows)]


def radius_role_can(query):
    try:
        with psycopg.connect(RADIUS_DB) as db:
            db.execute(query)
            return True
    except psycopg.errors.InsufficientPrivilege:
        return False


def radius_pools():
    pools = {}
    for app, query in sql("SELECT application_name, query FROM pg_stat_activity WHERE application_name LIKE 'FreeRADIUS%%'"):
        m = re.search(r"\((\w+)\)$", app)
        if m:
            pools.setdefault(m.group(1), []).append(query or "")
    return pools


def db_ready():
    for _ in range(60):
        try:
            with psycopg.connect(DB, connect_timeout=2) as db:
                db.execute("SELECT 1")
                return True
        except psycopg.OperationalError:
            time.sleep(1)
    return False


def migrate():
    out = subprocess.run(["bash", "-c", MIGRATE], capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError("the migration step failed: %s" % (out.stdout + out.stderr)[-500:])


# --- the cases -------------------------------------------------------------------------------------

def resumption_checks():
    """Security review 2026-10-29 I9: TLS session resumption stays off (mods/eap: cache { enable =
    no }; FreeRADIUS then sets SSL_OP_NO_TICKET, no session cache and no TLS 1.3 tickets). A
    resumed session would skip the certificate check: a revoked device could come back on its old
    session. eapol_test re-authenticates once (-r1) over the same TLS state, offering whatever it
    can resume; both runs must be full handshakes with the client certificate, for TLS 1.3 and 1.2."""
    for version, phase1 in (("1.3", "tls_disable_tlsv1_3=0"), ("1.2", "tls_disable_tlsv1_3=1 tls_disable_session_ticket=0")):
        conf = RUN / "client" / ("resume-%s.conf" % version)
        conf.write_text('network={\n ssid="Scharni"\n key_mgmt=WPA-EAP\n eap=TLS\n identity="anonymous@scharni.org"\n'
                        ' ca_cert="/pki/root.pem"\n client_cert="/client/carol-tablet.crt"\n'
                        ' private_key="/client/carol-tablet.key"\n domain_match="radius.scharni.org"\n'
                        ' phase1="%s"\n}\n' % phase1)
        conf.chmod(0o644)
        out = subprocess.run(["docker", "exec", AP, "eapol_test", "-c", "/client/" + conf.name, "-a", RADIUS_IP,
                              "-s", SECRET, "-r1", "-t", "15", "-N30:s:" + CALLED], capture_output=True, text=True).stdout
        successes = out.count("CTRL-EVENT-EAP-SUCCESS")
        resumed = re.findall(r"resumed=(\d)", out)
        peer_certs = out.count("CTRL-EVENT-EAP-PEER-CERT depth=0")
        check("TLS %s: a re-authentication is a full handshake (no session resumption)" % version,
              successes == 2 and resumed and set(resumed) == {"0"} and peer_certs >= 2,
              (successes, resumed, peer_certs, out[-400:]))
        check("TLS %s: ... and the server hands out no session ticket" % version,
              not re.search(r"(?i)NewSessionTicket|session ticket \(len=[1-9]", out), out[-400:])


def main():
    person("sub-alice", "alice", "residents")
    person("sub-carol", "carol", "guests")
    person("sub-fia", "fia", "guests")
    for name in CERTS:
        write_conf(name)
    write_conf("no-cert", client_cert=False)
    android_id = create_device("alice-android", "sub-alice", "residents", "android")
    apple_id = create_device("alice-apple", "sub-alice", "residents", "apple")
    eap_id = create_device("alice-eap-config", "sub-alice", "residents")
    create_device("fia", "sub-fia", "guests")
    tablet = create_device("carol-tablet", "sub-carol", "guests")

    # --- access and what an Accept carries
    verdict = connect("alice-android")
    check("android: the installed credential connects (VLAN 30)", verdict == ("accept", "30"), verdict)
    m = re.search(r"Attribute 27 \(Session-Timeout\) length=6\s+Value: ([0-9]+)", LAST_REPLY)
    check("the Accept carries the Session-Timeout backstop", m and int(m.group(1)) == 43200, m and m.group(1))
    m = re.search(r"Attribute 85 \(Acct-Interim-Interval\) length=6\s+Value: ([0-9]+)", LAST_REPLY)
    check("the Accept asks for accounting updates every NETPORTAL_ACCT_INTERIM_S (120 s here)",
          m and int(m.group(1)) == 120, m and m.group(1))
    android_class = reply_class()
    for name, vlan in (("alice-apple", "30"), ("alice-eap-config", "30")):
        verdict = connect(name)
        check("%s: connects (VLAN %s)" % (name, vlan), verdict == ("accept", vlan), verdict)
    verdict = connect("fia")
    check("... and her device connects into the guests' VLAN 50", verdict == ("accept", "50"), verdict)

    # --- every login logged with the Class token the Accept carries
    logged = sql("SELECT device_id::text, result, reason, mac::text, bssid::text, ssid FROM radius_auth "
                 "WHERE class_token = %s", android_class or "")
    check("the Accept carries a Class token, logged with the login (device, MAC, BSSID, SSID)",
          bool(re.fullmatch(r"np1:[-_0-9A-Za-z]{22}", android_class or ""))
          and logged == [(android_id, "accept", "ok", "02:00:00:00:00:01", "aa:bb:cc:00:00:01", "Scharni")],
          (android_class, logged))
    serial = sql("SELECT serial FROM radius_auth WHERE class_token = %s", android_class or "")
    check("... with the certificate's serial (lowercase hex)", serial == [(CERTS["alice-android"]["serial"],)], serial)
    rows = sql("SELECT host(nas_ip), calling_station, user_name FROM radius_session WHERE device_id = %s", android_id)
    check("RADIUS records the latest session (for Disconnect)", len(rows) == 1 and rows[0][2] == "anonymous@scharni.org",
          rows)

    # --- first_seen: the dashboard's data starts at the first login with the MAC
    def session_of():
        return sql("SELECT calling_station, first_seen, updated FROM radius_session WHERE device_id = %s", android_id)[0]
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
    claims = mac_claims(["02:00:00:00:00:99", "02:00:00:00:00:98"])
    check("the registry tells whose devices claim a MAC", claims == {"02:00:00:00:00:99": {"sub-alice"}}, claims)
    windows = device_windows(android_id)
    check("both MACs of the device are kept as identities with their logins (device_mac)",
          windows == [("02:00:00:00:00:01", 2, True), ("02:00:00:00:00:99", 1, True)], windows)

    # --- revocation (registry::revoke); the Disconnect itself is the portal's
    sql("UPDATE device SET revoked_at = now() WHERE id = %s AND revoked_at IS NULL", android_id)
    check("a revoked device cannot connect", connect("alice-android")[0] == "reject")
    check("... and the reject is logged with its reason (revoked, the device)",
          last_reject()[:2] == ("revoked", android_id), last_reject())
    check("other devices of the same person still connect", connect("alice-apple") == ("accept", "30"))

    # --- renewal (registry::add_credential with the overlap), retired, expired
    add_credential("alice-apple-renewed")
    check("renewal: the new certificate connects", connect("alice-apple-renewed") == ("accept", "30"))
    check("renewal: the old certificate still works during the overlap", connect("alice-apple")[0] == "accept")
    sql("UPDATE credential SET retired_at = now() - interval '1 minute' WHERE retired_at IS NOT NULL "
        "AND device_id = %s", apple_id)
    old_cert = connect("alice-apple")[0]
    retired = last_reject()
    check("renewal: after the overlap only the new certificate works",
          old_cert == "reject" and connect("alice-apple-renewed")[0] == "accept")
    check("... the old certificate's reject is logged as retired", retired[:2] == ("retired", apple_id), retired)
    # credential CHECK (not_after > issued_at): the certificate was issued before it expired
    sql("UPDATE credential SET issued_at = now() - interval '2 days', not_after = now() - interval '1 minute' "
        "WHERE device_id = %s", eap_id)
    check("an expired certificate cannot connect", connect("alice-eap-config")[0] == "reject")
    check("... logged as expired", last_reject()[:2] == ("expired", eap_id), last_reject())

    # --- the FreeRADIUS traps: certificates that must fail although the chain looks fine
    unregistered = CERTS["unregistered"]["serial"]
    check("a device-CA certificate that is not in the registry cannot connect", connect("unregistered")[0] == "reject")
    check("... logged as unknown_cert with its serial, no device",
          last_reject() == ("unknown_cert", None, unregistered), last_reject())
    connect("unregistered")
    rows = sql("SELECT tries, last_at > at FROM radius_auth WHERE serial = %s", unregistered)
    check("a repeated reject (same MAC, reason, serial, AP within 60 s) adds to its row: one row, count 2",
          [tuple(r) for r in rows] == [(2, True)], rows)
    check("EAP-TLS without a client certificate cannot connect, logged as no_cert",
          connect("no-cert")[0] == "reject" and last_reject() == ("no_cert", None, None), last_reject())
    out = subprocess.run(["docker", "exec", "-i", AP, "radclient", "-t", "4", "%s:1812" % RADIUS_IP, "auth", SECRET],
                         capture_output=True, text=True,
                         input='User-Name = "bob", User-Password = "x", Message-Authenticator = 0x00\n').stdout
    check("a request without EAP (password) is rejected, logged as not_eap",
          "Access-Reject" in out and last_reject() == ("not_eap", None, None), (out[-200:], last_reject()))
    # Registered serials of the devices the certificates name, so only the issuer checks stand
    # in the way.
    for name in ("foreign", "root-signed"):
        sql("INSERT INTO device (id, owner, name, kind, platform, policy) VALUES (%s, 'sub-carol', 'trap', 'cert', "
            "'apple', 'residents')", CERTS[name]["device_id"])
        sql("INSERT INTO credential (serial, device_id, not_after) VALUES (%s, %s, now() + interval '1 day')",
            CERTS[name]["serial"], CERTS[name]["device_id"])
    check("a certificate of a foreign CA with the same names cannot connect", connect("foreign")[0] == "reject")
    check("... logged as bad_chain (its chain did not verify)", last_reject()[:2] == ("bad_chain", None), last_reject())
    check("a certificate the root signed directly (not the device CA) cannot connect",
          connect("root-signed")[0] == "reject")
    check("... logged as bad_chain, not attributed to the registered device (not proven ours)",
          last_reject() == ("bad_chain", None, CERTS["root-signed"]["serial"]), last_reject())
    sql("DELETE FROM device WHERE id IN (%s, %s)", CERTS["foreign"]["device_id"], CERTS["root-signed"]["device_id"])
    check("a device of the guests' policy connects into VLAN 50", connect("carol-tablet") == ("accept", "50"))
    # security review 2026-10-29 L3: the decision is bound to the certificate's identity, not
    # only its serial. A device-CA certificate whose serial is registered for carol's tablet but
    # that names another device (CN <device id>@<realm>) does not get in as the tablet.
    sql("INSERT INTO credential (serial, device_id, not_after) VALUES (%s, %s, now() + interval '1 day')",
        CERTS["mallory"]["serial"], tablet)
    check("a certificate whose serial is registered for another device (its CN names a different one) cannot connect",
          connect("mallory")[0] == "reject", LAST_REPLY[-300:])
    check("... logged as bad_chain, not attributed to the device of the serial",
          last_reject() == ("bad_chain", None, CERTS["mallory"]["serial"]), last_reject())
    sql("DELETE FROM credential WHERE serial = %s", CERTS["mallory"]["serial"])
    check("... and the tablet itself still connects", connect("carol-tablet") == ("accept", "50"))
    resumption_checks()

    telemetry_checks(tablet)
    print("%d failure(s)" % len(failures))
    return 1 if failures else 0


def accounting_order_checks(tablet, mac):
    """The database side of e2e.py's presence_checks (the presence API is the portal's):
    reordered and repeated packets, the measured interval, Accounting-Off."""
    ap_a, ap_b = "10.198.0.31", "10.198.0.32"
    connect("carol-tablet", mac=mac)
    token = "0x" + (reply_class() or "").encode().hex()
    base = {"Calling-Station-Id": '"A4-83-E7-00-00-05"', "Called-Station-Id": '"AA-BB-CC-00-00-03:Scharni"',
            "Class": token}
    time.sleep(9)
    now = -int(-time.time()) - 8
    accounting({**base, "Acct-Status-Type": "Start", "Acct-Session-Id": '"P-1"', "Event-Timestamp": str(now)}, nas=ap_a)
    accounting({**base, "Acct-Status-Type": "Start", "Acct-Session-Id": '"P-2"', "Event-Timestamp": str(now + 1)},
               nas=ap_b)
    accounting({**base, "Acct-Status-Type": "Stop", "Acct-Session-Id": '"P-1"', "Acct-Session-Time": "2",
                "Acct-Terminate-Cause": "User-Request", "Event-Timestamp": str(now + 2)}, nas=ap_a)
    p1, p2 = acct_row("P-1", ap_a), acct_row("P-2", ap_b)
    check("accounting: a roam (new AP's Start before the old AP's Stop) leaves the new session open (link class)",
          p1 and p1[7] is not None and p2 and p2[7] is None and p2[:2] == ("class", tablet), (p1, p2))
    accounting({**base, "Acct-Status-Type": "Stop", "Acct-Session-Id": '"P-3"', "Acct-Session-Time": "5",
                "Event-Timestamp": str(now - 10)}, nas=ap_b)
    accounting({**base, "Acct-Status-Type": "Start", "Acct-Session-Id": '"P-3"', "Event-Timestamp": str(now - 15)},
               nas=ap_b)
    row = sql("SELECT started, stopped FROM radius_acct WHERE nas_ip = %s AND acct_session_id = 'P-3'", ap_b)
    check("accounting: a Stop that overtook its Start leaves the session stopped",
          row and row[0][1] is not None and row[0][0] is not None and row[0][0] < row[0][1], row)
    stop = {**base, "Acct-Status-Type": "Stop", "Acct-Session-Id": '"P-2"', "Acct-Session-Time": "4",
            "Acct-Terminate-Cause": "User-Request", "Event-Timestamp": str(now + 5)}
    accounting(stop, nas=ap_b)
    stopped = acct_row("P-2", ap_b)
    accounting(stop, nas=ap_b)
    accounting({**base, "Acct-Status-Type": "Interim-Update", "Acct-Session-Id": '"P-2"', "Acct-Session-Time": "3",
                "Event-Timestamp": str(now + 4)}, nas=ap_b)
    check("accounting: a repeated Stop and a late Interim change nothing",
          stopped and stopped[7] is not None and acct_row("P-2", ap_b) == stopped, (stopped, acct_row("P-2", ap_b)))
    accounting({**base, "Acct-Status-Type": "Start", "Acct-Session-Id": '"P-4"', "Event-Timestamp": str(now - 240)},
               nas=ap_a)
    accounting({**base, "Acct-Status-Type": "Interim-Update", "Acct-Session-Id": '"P-4"', "Acct-Session-Time": "120",
                "Event-Timestamp": str(now - 120)}, nas=ap_a)
    accounting({**base, "Acct-Status-Type": "Start", "Acct-Session-Id": '"P-5"', "Event-Timestamp": str(now + 6)},
               nas=ap_a)
    measured = sql("SELECT interim_s FROM radius_acct WHERE nas_ip = %s AND acct_session_id = 'P-4'", ap_a)
    nas = sql("SELECT interim_s FROM radius_nas WHERE nas_ip = %s", ap_a)
    check("accounting: the measured interval is recorded (120 s), per session and per AP",
          measured == [(120,)] and nas == [(120,)], (measured, nas))
    accounting({"Acct-Status-Type": "Accounting-Off", "Event-Timestamp": str(now + 7)}, nas=ap_a)
    p5 = acct_row("P-5", ap_a)
    reset = sql("SELECT reset_cause FROM radius_nas WHERE nas_ip = %s", ap_a)
    check("accounting: the AP's Accounting-Off ends its sessions (NAS-Request) and is remembered",
          p5 and p5[7] is not None and p5[11] == "NAS-Request" and reset == [("NAS-Request",)], (p5, reset))


def telemetry_checks(tablet):
    """e2e.py's telemetry_checks, RADIUS side: accounting, the radius role's rights, the pools,
    fail-open logging and fail-closed access."""
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
          answered and row and row[7] is not None and row[8:12] == (120, 2 ** 32 + 2000, 900, "User-Request"), row)
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
    sessions = acct_sessions(tablet)
    check("the registry lists the device's sessions", sessions == ["IT-1", "IT-2"], sessions)
    accounting_order_checks(tablet, mac)

    # --- the radius role: the schema radius only (rust/docs/RADIUS_CONTRACT.md)
    check("the radius role reads the decision view", radius_role_can("SELECT * FROM radius.valid_cert"))
    check("the radius role cannot read people, devices or sessions",
          not any(radius_role_can("SELECT 1 FROM %s" % t) for t in (
              "person", "device", "credential", "radius_session", "radius_auth", "radius_acct", "device_mac",
              "device_mac_window", "public.policy")))
    check("the radius role cannot write the session table directly (only through radius.login)",
          not radius_role_can("UPDATE radius_session SET nas_ip = '1.2.3.4'"))
    check("the radius role may call the logging functions",
          radius_role_can("SELECT radius.reject('', '', '', '', 'other')"))
    check("the radius role may call radius.cert_status (diagnostics)",
          radius_role_can("SELECT radius.cert_status('00')"))
    check("the radius role cannot call the helpers in public (np_mac, np_device_for_mac)",
          not radius_role_can("SELECT np_mac('02:00:00:00:00:01')")
          and not radius_role_can("SELECT np_device_for_mac('02:00:00:00:00:01', now())"))
    check("the radius role cannot create objects in its schema",
          not radius_role_can("CREATE VIEW radius.x AS SELECT 1"))

    # --- logging has its own connection pool (rust/radius/mods/sql_log)
    connect("carol-tablet", mac=mac)
    pools = radius_pools()
    logging_calls = re.compile(r"radius\.(login|reject|accounting)\(")
    check("the logging calls run on their own pool (sql_log), the decision's pool (sql) only reads radius.valid_cert",
          any(logging_calls.search(q) for q in pools.get("sql_log", []))
          and not any(logging_calls.search(q) for q in pools.get("sql", []))
          and any("radius.valid_cert" in q for q in pools.get("sql", [])), pools)
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

    # --- fail open for logging, fail closed for access
    sql("REVOKE EXECUTE ON FUNCTION radius.login(text, text, text, text, text, text, text), "
        "radius.reject(text, text, text, text, text), radius.accounting(" + ", ".join(["text"] * 14) + ") FROM radius")
    before = sql("SELECT count(*) FROM radius_auth")[0][0]
    verdict = connect("carol-tablet", mac=mac)
    check("with the logging functions failing, a valid device still connects (without Class)",
          verdict == ("accept", "50") and reply_class() is None, verdict)
    check("... and an unregistered one is still rejected", connect("unregistered")[0] == "reject")
    check("... and accounting is still answered", accounting({**base, "Acct-Status-Type": "Start",
                                                             "Acct-Session-Id": '"IT-4"'}))
    check("... (nothing was logged)", sql("SELECT count(*) FROM radius_auth")[0][0] == before and acct_row("IT-4") is None)
    migrate()
    verdict = connect("carol-tablet", mac=mac)
    check("migrate restores the radius role's rights (declarative grants): logged with Class again",
          verdict == ("accept", "50") and reply_class() is not None, verdict)
    subprocess.run(["docker", "stop", "-t", "5", PG], capture_output=True)
    try:
        verdict = connect("carol-tablet", mac=mac, timeout=30)
        check("with the database down nobody gets in (fail closed)", verdict[0] != "accept", verdict)
        check("... and accounting is still answered", accounting({**base, "Acct-Status-Type": "Interim-Update",
                                                                 "Acct-Session-Id": '"IT-5"'}))
    finally:
        subprocess.run(["docker", "start", PG], capture_output=True)
    ready = db_ready()
    for _ in range(5):
        verdict = connect("carol-tablet", mac=mac)
        if verdict[0] == "accept":
            break
        time.sleep(2)
    check("... and once it is back, the device connects again", ready and verdict == ("accept", "50"), verdict)


if __name__ == "__main__":
    sys.exit(main())
