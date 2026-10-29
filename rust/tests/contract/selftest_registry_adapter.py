#!/usr/bin/env python3
"""Self-test of registry_adapter.RustRegistry against a migrated Rust database, no portal.

    python3 rust/tests/contract/selftest_registry_adapter.py

Starts a throwaway PostgreSQL (rust/tools/test-db.sh) unless NETPORTAL_TEST_DATABASE_URL is
set (a superuser's URL; a fresh database is created in it), creates the role radius, migrates
with the Rust binary (rust/target/debug/netportal init-db; NETPORTAL_BIN overrides; if it is
missing, every rust/migrations/*.sql in order and rust/sql/radius_grants.sql are applied
directly), writes rows the way crates/netportal-core/src/registry.rs does, and calls every
adapter function the contract tests use, checking the return shapes and values. Not a contract
test (the name does not match test_*.py, so contract/run.sh does not collect it).
"""

import datetime
import hashlib
import os
import subprocess
import sys
import unittest
import uuid
from pathlib import Path

import psycopg
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from psycopg.conninfo import conninfo_to_dict, make_conninfo

HERE = Path(__file__).resolve().parent
RUST = HERE.parents[1]
sys.path.insert(0, str(HERE))
import registry_adapter  # noqa: E402

RADIUS_PASSWORD = "selftest-radius-password"
STATE = {}


def cert(serial):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "selftest")])
    now = datetime.datetime.now(datetime.timezone.utc)
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(serial).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256()))


def setUpModule():
    url = os.environ.get("NETPORTAL_TEST_DATABASE_URL")
    if not url:
        out = subprocess.run([str(RUST / "tools" / "test-db.sh")], capture_output=True, text=True)
        if out.returncode != 0:
            raise unittest.SkipTest("no throwaway PostgreSQL: " + out.stderr.strip())
        for line in out.stdout.splitlines():
            key, _, value = line.removeprefix("export ").partition("=")
            STATE[key] = value.strip("'")
        url = STATE["NETPORTAL_TEST_DATABASE_URL"]
    with psycopg.connect(url, autocommit=True) as db:
        name = "adapter_selftest_%s" % uuid.uuid4().hex[:8]
        db.execute("CREATE DATABASE %s" % name)
        if not db.execute("SELECT 1 FROM pg_roles WHERE rolname = 'radius'").fetchone():
            db.execute("CREATE ROLE radius LOGIN PASSWORD '%s'" % RADIUS_PASSWORD)
        else:
            db.execute("ALTER ROLE radius PASSWORD '%s'" % RADIUS_PASSWORD)
    params = conninfo_to_dict(url)
    params["dbname"] = name
    STATE["url"] = make_conninfo(**params)
    STATE["uri"] = "postgresql://%s:%s@%s:%s/%s" % (params["user"], params["password"], params.get("host", "127.0.0.1"),
                                                    params.get("port", "5432"), name)
    binary = Path(os.environ.get("NETPORTAL_BIN", RUST / "target" / "debug" / "netportal"))
    if binary.exists():
        out = subprocess.run([str(binary), "init-db"], capture_output=True, text=True,
                             env={"PATH": os.environ["PATH"], "NETPORTAL_DATABASE_URL": STATE["uri"],
                                  "NETPORTAL_POLICIES": "residents=30:residents;guests=50:former-residents"})
        if out.returncode != 0:
            raise RuntimeError("init-db: " + out.stderr)
        STATE["migrated_by"] = "netportal init-db"
    else:
        with psycopg.connect(STATE["url"], autocommit=True) as db:
            for f in sorted((RUST / "migrations").glob("*.sql")) + [RUST / "sql" / "radius_grants.sql"]:
                with db.transaction():
                    db.execute(f.read_text())
            db.execute("INSERT INTO policy (name, vlan) VALUES ('residents', 30), ('guests', 50)")
            db.execute("INSERT INTO job (name, last_success) VALUES ('offboarding', now())")
        STATE["migrated_by"] = "rust/migrations + rust/sql/radius_grants.sql (no binary at %s)" % binary
    print("selftest database migrated by", STATE["migrated_by"], file=sys.stderr)


def tearDownModule():
    if "NETPORTAL_TEST_DB_CONTAINER" in STATE:
        subprocess.run([str(RUST / "tools" / "test-db.sh"), "stop", STATE["NETPORTAL_TEST_DB_CONTAINER"]],
                       capture_output=True)


class Instance:
    """The part of contract/harness.Instance the adapter reads."""
    def __init__(self, db_url):
        self.db_url = db_url


class RustRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["CT_SCHEMA"] = "rust"
        cls.reg = registry_adapter.for_instance(Instance(STATE["uri"]), "python", RADIUS_PASSWORD)
        cls.sql = staticmethod(lambda q, *a: cls.reg._sql(q, *a))

    def test_selected_by_ct_schema(self):
        self.assertIsInstance(self.reg, registry_adapter.RustRegistry)

    def test_people(self):
        self.sql("INSERT INTO person (sub, username, display_name, policy) VALUES ('p1', 'pat', 'Pat', 'residents')")
        self.assertEqual(self.reg.person("p1"), {"username": "pat", "display": "Pat", "admin": False,
                                                 "policy": "residents", "offboarded": False, "recent_login": True})
        self.reg.set_admin("p1", True)
        self.reg.set_offboarded("p1")
        row = self.reg.person("p1")
        self.assertTrue(row["admin"] and row["offboarded"])
        self.reg.delete_person("p1")
        self.assertIsNone(self.reg.person("p1"))
        self.assertEqual(self.reg.policies(), {"residents": 30, "guests": 50})
        self.assertIsInstance(self.reg.offboarding_last_success(), float)

    def test_devices_audit_credentials_session(self):
        self.sql("INSERT INTO person (sub, username, display_name, policy) VALUES ('p2', 'quinn', 'Quinn', 'residents')")
        first, second = uuid.uuid4(), uuid.uuid4()
        for dev, name, age in ((first, "older", "1 minute"), (second, "newer", "0 seconds")):
            self.sql("INSERT INTO device (id, owner, name, kind, platform, policy, created_at) "
                     "VALUES (%s, 'p2', %s, 'cert', 'apple', 'residents', now() - %s::interval)", dev, name, age)
        self.assertEqual(self.reg.device(first), {"id": str(first), "owner": "p2", "name": "older", "platform": "apple",
                                                  "policy": "residents", "revoked": False})
        self.assertIsNone(self.reg.device(uuid.uuid4()))
        self.assertEqual([d["name"] for d in self.reg.devices("p2")], ["newer", "older"])
        self.assertEqual(self.reg.newest_device("p2")["id"], str(second))
        self.assertIsNone(self.reg.newest_device("nobody"))
        # registry::audit, twice in one transaction (same now()): the insertion order holds
        with psycopg.connect(STATE["uri"]) as db:
            for action in ("enrol:apple", "revoke", "disconnect:ack"):
                db.execute("INSERT INTO audit (actor, action, device_id) VALUES ('p2', %s, %s)", (action, first))
        self.assertEqual(self.reg.audit(first), [("p2", "enrol:apple"), ("p2", "revoke"), ("p2", "disconnect:ack")])
        self.assertEqual(self.reg.audit_of("p2"), ["enrol:apple", "revoke", "disconnect:ack"])

        # registry::add_credential twice: the first one retires after a 2-day overlap
        old, new = cert(0x0abc), cert(0x80 << 120 | 7)
        for c in (old, new):
            self.sql("UPDATE credential SET retired_at = now() + make_interval(days => 2) "
                     "WHERE device_id = %s AND retired_at IS NULL", first)
            self.sql("INSERT INTO credential (serial, device_id, not_after) VALUES (%s, %s, now() + interval '1 day')",
                     registry_adapter.serial_hex(c), first)
        self.assertEqual(registry_adapter.serial_hex(old), "0abc")
        o, n = self.reg.credential(old), self.reg.credential(new)
        self.assertEqual((o["device_id"], o["status"], n["status"]), (str(first), "valid", "valid"))
        self.assertAlmostEqual(o["retires_in_s"], 2 * 86400, delta=60)
        self.assertIsNone(n["retires_in_s"])
        self.assertIsInstance(n["not_after"], datetime.datetime)
        self.assertIsNotNone(n["not_after"].tzinfo)
        self.assertIsNone(self.reg.credential(cert(0x1234)))
        self.assertEqual(self.reg.credential_count(first), 2)

        token = self.reg.radius_session(first, new, nas_ip="10.0.0.9")
        self.assertRegex(token, r"^np1:[-_0-9A-Za-z]{22}$")
        rows = self.sql("SELECT host(nas_ip) AS nas, calling_station, user_name FROM radius_session WHERE device_id = %s",
                        first)
        self.assertEqual(rows, [{"nas": "10.0.0.9", "calling_station": "02:00:00:00:aa:01",
                                 "user_name": "anonymous@scharni.org"}])

        self.sql("UPDATE device SET revoked_at = now() WHERE id = %s", first)
        self.assertTrue(self.reg.device(first)["revoked"])
        self.assertEqual(self.reg.credential(new)["status"], "revoked")
        self.sql("UPDATE device SET revoked_at = NULL WHERE id = %s", first)
        self.sql("UPDATE credential SET retired_at = now() - interval '1 second' WHERE serial = '0abc'")
        self.assertEqual(self.reg.credential(old)["status"], "retired")
        self.sql("UPDATE credential SET issued_at = now() - interval '2 days', not_after = now() - interval '1 second' "
                 "WHERE serial = %s", registry_adapter.serial_hex(new))
        self.assertEqual(self.reg.credential(new)["status"], "expired")

    def test_downloads_and_tokens(self):
        self.sql("INSERT INTO person (sub, username, display_name, policy) VALUES ('p3', 'rae', 'Rae', 'residents')")
        dev, grant = uuid.uuid4(), uuid.uuid4()
        self.sql("INSERT INTO device (id, owner, name, platform, policy) VALUES (%s, 'p3', 'x', 'eap-config', 'residents')",
                 dev)
        h = lambda t: hashlib.sha256(t.encode()).hexdigest()  # noqa: E731 (registry::token_hash)
        # registry::create_download (10 minutes)
        self.sql("INSERT INTO download (token_hash, device_id, format, expires_at) "
                 "VALUES (%s, %s, 'apple', now() + make_interval(mins => 10))", h("dl-token"), dev)
        self.assertAlmostEqual(self.reg.download_expires_in("dl-token"), 600, delta=5)
        self.assertIsNone(self.reg.download_expires_in("other"))
        self.assertEqual(self.reg.expire_download("dl-token"), 1)
        self.assertLess(self.reg.download_expires_in("dl-token"), 0)
        # registry::create_grant + issue_token
        self.sql("INSERT INTO oauth_grant (id, owner, client_id, device_name) VALUES (%s, 'p3', 'app.x', 'laptop')", grant)
        self.sql("INSERT INTO oauth_token (token_hash, grant_id, kind, expires_at) "
                 "VALUES (%s, %s, 'access', now() + make_interval(secs => 3600))", h("access-token"), grant)
        self.assertAlmostEqual(self.reg.token_expires_in("access-token"), 3600, delta=5)
        self.assertEqual(self.reg.grant("access-token"), {"owner": "p3", "client_id": "app.x", "device_name": "laptop",
                                                          "device_id": None, "revoked": False})
        self.sql("UPDATE oauth_grant SET device_id = %s, revoked_at = now() WHERE id = %s", dev, grant)
        self.assertEqual(self.reg.grant("access-token")["device_id"], str(dev))
        self.assertTrue(self.reg.grant("access-token")["revoked"])
        self.assertIsNone(self.reg.grant("unknown"))
        self.assertEqual(self.reg.expire_token("access-token"), 1)
        self.assertLess(self.reg.token_expires_in("access-token"), 0)
        self.assertFalse(self.reg.stores_plain_token("access-token"))
        self.assertFalse(self.reg.stores_plain_token("dl-token"))
        self.assertTrue(self.reg.stores_plain_token(h("access-token")))   # a stored value is found


if __name__ == "__main__":
    unittest.main(verbosity=2)
