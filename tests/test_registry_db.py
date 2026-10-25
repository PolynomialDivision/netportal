"""The registry against a real PostgreSQL 18 (local Docker, a throwaway container on a random
port): migrations, the radius role's rights, the functions FreeRADIUS writes through, and every
read/write function of the telemetry interface. Skipped when Docker is not available.

    python3 -m unittest tests.test_registry_db -v
    NETPORTAL_TEST_PG_IMAGE=postgres:18 ... (another image)
"""

import datetime
import os
import secrets
import shutil
import subprocess
import sys
import time
import unittest
import uuid
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import psycopg  # noqa: E402

from netportal import registry  # noqa: E402
from test_registry import MAC_CASES  # noqa: E402  (the cases of the Python normaliser)

# The image production runs (house-infra stacks/netaccess/stack.yml).
IMAGE = os.environ.get("NETPORTAL_TEST_PG_IMAGE", "docker.io/library/postgres:18.6-alpine@sha256:"
                       "898c60cb390d1085bc97bdd6a1ae968757421df394b071848b52b1c09c89d6a5")
ROOT = Path(__file__).resolve().parent.parent
UTC = datetime.timezone.utc
PASSWORD = "test-" + secrets.token_hex(8)
RADIUS_PASSWORD = "radius-" + secrets.token_hex(8)
T0 = datetime.datetime(2026, 1, 1, tzinfo=UTC)
HOUR = datetime.timedelta(hours=1)
DAY = datetime.timedelta(days=1)

_container = None
_port = None


def _docker_ok():
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "info"], capture_output=True).returncode == 0


def setUpModule():
    global _container, _port
    if not _docker_ok():
        raise unittest.SkipTest("Docker is not available")
    name = "netportal-test-pg-" + secrets.token_hex(4)
    out = subprocess.run(["docker", "run", "-d", "--rm", "--name", name, "-p", "127.0.0.1::5432",
                          "-e", "POSTGRES_USER=netportal", "-e", "POSTGRES_PASSWORD=" + PASSWORD,
                          "-e", "POSTGRES_DB=netportal", IMAGE], capture_output=True, text=True)
    if out.returncode:
        raise unittest.SkipTest("cannot start PostgreSQL: " + out.stderr.strip()[-200:])
    _container = name
    _port = subprocess.run(["docker", "port", name, "5432/tcp"], capture_output=True,
                           text=True).stdout.split()[0].rsplit(":", 1)[1]
    deadline = time.time() + 60
    while time.time() < deadline:
        # Over TCP: during the image's first-start init only the socket listens.
        ready = subprocess.run(["docker", "exec", name, "pg_isready", "-q", "-h", "127.0.0.1", "-U", "netportal"])
        if ready.returncode == 0:
            break
        time.sleep(0.5)
    else:
        tearDownModule()
        raise unittest.SkipTest("PostgreSQL did not start")
    with admin() as db:
        db.execute("CREATE ROLE radius LOGIN PASSWORD '%s'" % RADIUS_PASSWORD)


def tearDownModule():
    if _container:
        subprocess.run(["docker", "rm", "-f", _container], capture_output=True)


def dsn(dbname="netportal", user="netportal", password=None):
    return "postgresql://%s:%s@127.0.0.1:%s/%s" % (user, password or PASSWORD, _port, dbname)


def admin():
    return psycopg.connect(dsn(), autocommit=True)


def fresh_database():
    name = "t_" + secrets.token_hex(6)
    with admin() as db:
        db.execute("CREATE DATABASE %s" % name)
    return name


def baseline_sql():
    """The registry as schema.sql made it until 2026-10-25: 0001 plus the grants it ended with."""
    return (ROOT / "netportal" / "migrations" / "0001_baseline.sql").read_text() + """
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'radius') THEN
        GRANT SELECT ON radius_cert TO radius;
        GRANT SELECT, INSERT, UPDATE ON radius_session TO radius;
    END IF;
END $$;
"""


class Policy:
    def __init__(self, name, vlan):
        self.name, self.vlan = name, vlan


class DbCase(unittest.TestCase):
    """A fresh, migrated database per test class; self.db (dict rows) per test."""

    @classmethod
    def setUpClass(cls):
        cls.dbname = fresh_database()
        with registry.connect(dsn(cls.dbname)) as db:
            registry.init(db, [Policy("residents", 30), Policy("guests", 50)])

    def setUp(self):
        self.db = registry.connect(dsn(self.dbname))
        self.addCleanup(self.db.close)

    def radius(self):
        conn = psycopg.connect(dsn(self.dbname, "radius", RADIUS_PASSWORD), autocommit=True)
        self.addCleanup(conn.close)
        return conn

    def scalar(self, sql, *args):
        row = self.db.execute(sql, args).fetchone()
        return None if row is None else next(iter(row.values()))

    def person(self, sub=None):
        sub = sub or "sub-" + secrets.token_hex(4)
        registry.upsert_person(self.db, sub, sub, sub.title())
        return sub

    def device(self, owner=None, serial=None, not_after=None, revoked=False):
        owner = owner or self.person()
        device_id = registry.create_device(self.db, owner, "dev", "apple", "residents")
        serial = serial or secrets.token_hex(8)
        self.db.execute("INSERT INTO credential (serial, device_id, not_after) VALUES (%s, %s, %s)",
                        (serial, device_id, not_after or datetime.datetime.now(UTC) + DAY))
        if revoked:
            self.db.execute("UPDATE device SET revoked = now() WHERE id = %s", (device_id,))
        self.db.commit()
        return str(device_id), serial

    def window(self, device_id, mac, first, last):
        self.db.execute("""INSERT INTO device_mac (device_id, mac, first_seen, last_seen, auth_count, randomized)
                           VALUES (%s, %s, %s, %s, 1, false)""", (device_id, mac, first, last))
        self.db.commit()


# --- migrations ---------------------------------------------------------------------------------

class MigrationTests(unittest.TestCase):
    def test_empty_database_then_idempotent(self):
        name = fresh_database()
        with registry.connect(dsn(name)) as db:
            first = registry.migrate(db)
            self.assertEqual(first["applied"], [1, 2, 3])
            self.assertEqual(first["version"], 3)
            self.assertTrue(first["radius_role"])
            second = registry.migrate(db)
            self.assertEqual(second["applied"], [])
            self.assertEqual(second["version"], 3)
            tables = {r["table_name"] for r in db.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'")}
            self.assertLessEqual({"device", "credential", "radius_session", "device_mac", "radius_auth", "radius_acct",
                                  "connection_event", "device_day", "ap_day", "incident", "job",
                                  "schema_migration", "radius_nas"}, tables)
            rows = list(db.execute("SELECT version, name, checksum FROM schema_migration ORDER BY version"))
            self.assertEqual([(r["version"], r["name"]) for r in rows],
                             [(1, "baseline"), (2, "telemetry"), (3, "presence")])
            self.assertEqual([r["checksum"] for r in rows], [f[3] for f in registry.migration_files()])

    def test_upgrade_from_schema_sql(self):
        """A database schema.sql made (no schema_migration) with data: migrate keeps the data,
        records both versions and fills device_mac from radius_session."""
        name = fresh_database()
        with registry.connect(dsn(name)) as db:
            db.execute(baseline_sql())
            db.execute("INSERT INTO policy (name, vlan) VALUES ('residents', 30)")
            db.execute("INSERT INTO person (sub, username, display) VALUES ('sub-a', 'a', 'A')")
            dev, dev2 = uuid.uuid4(), uuid.uuid4()
            for d in (dev, dev2):
                db.execute("""INSERT INTO device (id, owner, name, kind, platform, policy)
                              VALUES (%s, 'sub-a', 'phone', 'cert', 'apple', 'residents')""", (d,))
            db.execute("INSERT INTO credential (serial, device_id, not_after) VALUES ('ab12', %s, now() + interval '1 day')",
                       (dev,))
            db.execute("""INSERT INTO radius_session (device_id, nas_ip, calling_station, user_name, updated, first_seen)
                          VALUES (%s, '10.0.0.2', 'A4-83-E7-00-00-01', 'anonymous@x', '2026-10-20 12:00Z', '2026-10-01 08:00Z'),
                                 (%s, '10.0.0.2', 'not-a-mac', 'anonymous@x', '2026-10-20 12:00Z', '2026-10-20 12:00Z')""",
                       (dev, dev2))
            db.execute("INSERT INTO job (name, last_success) VALUES ('offboarding', now())")
            db.commit()
            result = registry.migrate(db)
            self.assertEqual(result["applied"], [1, 2, 3])
            macs = list(db.execute("SELECT device_id, mac::text AS mac, first_seen, last_seen, auth_count, randomized "
                                   "FROM device_mac"))
            self.assertEqual(len(macs), 1, macs)
            self.assertEqual((macs[0]["device_id"], macs[0]["mac"], macs[0]["randomized"]),
                             (dev, "a4:83:e7:00:00:01", False))
            self.assertEqual(macs[0]["first_seen"], datetime.datetime(2026, 10, 1, 8, tzinfo=UTC))
            self.assertEqual(macs[0]["last_seen"], datetime.datetime(2026, 10, 20, 12, tzinfo=UTC))
            self.assertEqual(db.execute("SELECT count(*) AS n FROM radius_cert").fetchone()["n"], 1)
            job = db.execute("SELECT last_success, cursor FROM job WHERE name = 'offboarding'").fetchone()
            self.assertIsNotNone(job["last_success"])
            self.assertEqual(job["cursor"], {})
            # The old direct write rights of FreeRADIUS are gone.
            rights = db.execute("""SELECT has_table_privilege('radius', 'radius_session', 'INSERT') AS i,
                                          has_table_privilege('radius', 'radius_session', 'SELECT') AS s""").fetchone()
            self.assertEqual(rights, {"i": False, "s": False})

    def test_changed_migration_is_refused(self):
        name = fresh_database()
        with registry.connect(dsn(name)) as db:
            registry.migrate(db)
            db.execute("UPDATE schema_migration SET checksum = 'edited' WHERE version = 2")
            db.commit()
            with self.assertRaises(registry.MigrationError) as err:
                registry.migrate(db)
            self.assertIn("0002_telemetry.sql", str(err.exception))
            # Nothing half-done: the connection is usable, the record unchanged.
            self.assertEqual(db.execute("SELECT checksum FROM schema_migration WHERE version = 2").fetchone()["checksum"],
                             "edited")

    def test_migration_files(self):
        files = registry.migration_files()
        self.assertEqual([f[:2] for f in files], [(1, "baseline"), (2, "telemetry"), (3, "presence")])
        self.assertFalse((ROOT / "netportal" / "schema.sql").exists())

    def test_missing_radius_role_warns(self):
        name = fresh_database()
        with admin() as a:
            a.execute("ALTER ROLE radius RENAME TO radius_away")
        try:
            with registry.connect(dsn(name)) as db, self.assertLogs("netportal.registry", "WARNING") as logs:
                result = registry.migrate(db)
                self.assertFalse(result["radius_role"])
                self.assertFalse(registry.stats(db)["radius_role"])
            self.assertIn("radius", logs.output[0])
        finally:
            with admin() as a:
                a.execute("ALTER ROLE radius_away RENAME TO radius")
                a.execute("ALTER ROLE radius PASSWORD '%s'" % RADIUS_PASSWORD)   # a rename clears an MD5 password

    def test_concurrent_migrate(self):
        """Two processes starting together: the advisory lock serialises them."""
        import threading
        name = fresh_database()
        results, errors = [], []

        def run():
            try:
                with registry.connect(dsn(name)) as db:
                    results.append(registry.migrate(db)["applied"])
            except Exception as e:  # noqa: BLE001
                errors.append(e)
        threads = [threading.Thread(target=run) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(sorted(results), [[], [], [1, 2, 3]])

    def test_upgrade_from_the_deployed_0002(self):
        """Production runs 0001 and 0002: migrate applies 0003 only and keeps the sessions."""
        name = fresh_database()
        files = registry.migration_files()
        with registry.connect(dsn(name)) as db:
            with mock.patch.object(registry, "migration_files", return_value=files[:2]):
                self.assertEqual(registry.migrate(db)["applied"], [1, 2])
            db.execute("""INSERT INTO radius_acct (nas_ip, acct_session_id, link, started, updated)
                          VALUES ('10.0.0.2', 'OLD-1', 'none', now() - interval '1 hour', now())""")
            db.commit()
            result = registry.migrate(db)
            self.assertEqual((result["applied"], result["version"]), ([3], 3))
            row = db.execute("SELECT acct_session_id, interim_s FROM radius_acct").fetchone()
            self.assertEqual(row, {"acct_session_id": "OLD-1", "interim_s": None})


# --- rights -----------------------------------------------------------------------------------

class GrantTests(DbCase):
    def test_radius_role_rights(self):
        dev, serial = self.device()
        r = self.radius()
        self.assertEqual(r.execute("SELECT vlan FROM radius_cert WHERE serial = %s", (serial,)).fetchone(), (30,))
        for table in ("device", "person", "credential", "radius_session", "radius_auth", "radius_acct", "device_mac",
                      "job", "audit"):
            with self.subTest(table=table), self.assertRaises(psycopg.errors.InsufficientPrivilege):
                r.execute("SELECT 1 FROM %s LIMIT 1" % table)
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            r.execute("INSERT INTO radius_session (device_id, nas_ip, calling_station, user_name) "
                      "VALUES (%s, '1.2.3.4', 'x', 'y')", (dev,))
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            r.execute("SELECT np_device_for_mac('aa:bb:cc:dd:ee:ff', now())")
        token = r.execute("SELECT radius_login(%s, %s, 'AA-BB-CC-DD-EE-01', 'AA-BB-CC-00-00-01:Scharni', '10.0.0.2', '', "
                          "'anonymous@x')", (dev, serial)).fetchone()[0]
        self.assertRegex(token, r"^np1:[A-Za-z0-9_-]{22}$")
        r.execute("SELECT radius_reject('', 'AA-BB-CC-DD-EE-01', '', '10.0.0.2', 'no_cert')")
        r.execute("SELECT radius_accounting('Start', 's1', '', 'AA-BB-CC-DD-EE-01', '', '10.0.0.2', '', '', '', '', '', "
                  "'', '', '')")
        self.assertEqual(r.execute("SELECT radius_cert_status(%s)", (serial,)).fetchone(), ("valid",))
        self.assertEqual(r.execute("SELECT np_mac('AA-BB-CC-DD-EE-01')::text").fetchone(), ("aa:bb:cc:dd:ee:01",))
        self.assertEqual(r.execute("SHOW statement_timeout").fetchone(), ("2s",))

    def test_public_cannot_execute(self):
        rows = list(self.db.execute("""
            SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = 'public' AND has_function_privilege('public', p.oid, 'EXECUTE')"""))
        self.assertEqual(rows, [])

    def test_functions_are_definer_with_search_path(self):
        rows = {r["proname"]: r for r in self.db.execute("""
            SELECT p.proname, p.prosecdef, p.proconfig FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = 'public'""")}
        for name in ("radius_login", "radius_reject", "radius_accounting", "radius_cert_status"):
            self.assertTrue(rows[name]["prosecdef"], name)
        for name, row in rows.items():
            self.assertIn("search_path=public, pg_temp", row["proconfig"] or [], name)


# --- MACs -----------------------------------------------------------------------------------

class MacTests(DbCase):
    def test_np_mac_matches_normalise_mac(self):
        for raw, expected in MAC_CASES.items():
            with self.subTest(raw=raw):
                self.assertEqual(registry.normalise_mac(raw), expected)
                self.assertEqual(self.scalar("SELECT np_mac(%s)::text", raw), expected)
        self.assertIsNone(registry.normalise_mac(None))
        self.assertIsNone(self.scalar("SELECT np_mac(NULL)::text"))
        self.assertIsNone(registry.normalise_mac(123))

    def test_called_station(self):
        cases = {"AA-BB-CC-00-00-01:Scharni": ("aa:bb:cc:00:00:01", "Scharni"),
                 "aa:bb:cc:00:00:01:Scharni": ("aa:bb:cc:00:00:01", "Scharni"),
                 "AABBCC000001:Sch:arni": ("aa:bb:cc:00:00:01", "Sch:arni"),
                 "AA-BB-CC-00-00-01": ("aa:bb:cc:00:00:01", None),
                 "Scharni": (None, None), "": (None, None)}
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                row = self.db.execute("SELECT bssid::text AS bssid, ssid FROM np_called_station(%s)", (raw,)).fetchone()
                self.assertEqual((row["bssid"], row["ssid"]), expected)



# --- FreeRADIUS functions -------------------------------------------------------------------

def login(db, dev, serial, mac="AA-BB-CC-DD-EE-01", called="AA-BB-CC-00-00-01:Scharni", nas="10.0.0.2", acct=""):
    return db.execute("SELECT radius_login(%s, %s, %s, %s, %s, %s, 'anonymous@scharni.org') AS t",
                      (dev, serial, mac, called, nas, acct)).fetchone()["t"]


def accounting(db, status, sid, cls="", mac="AA-BB-CC-DD-EE-01", nas="10.0.0.2", **kw):
    args = {"called": "AA-BB-CC-00-00-02:Scharni", "framed": "", "time": "", "in": "", "out": "", "ingw": "",
            "outgw": "", "cause": "", "ts": ""}
    args.update(kw)
    db.execute("""SELECT radius_accounting(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
               (status, sid, cls, mac, args["called"], nas, args["framed"], args["time"], args["in"], args["out"],
                args["ingw"], args["outgw"], args["cause"], args["ts"]))


class LoginTests(DbCase):
    def test_login_logs_and_returns_class(self):
        dev, serial = self.device()
        token = login(self.db, dev, serial, acct="ACCT-1")
        self.assertRegex(token, r"^np1:[A-Za-z0-9_-]{22}$")
        row = self.db.execute("SELECT * FROM radius_auth WHERE class_token = %s", (token,)).fetchone()
        self.assertEqual((row["result"], row["reason"], str(row["device_id"]), row["serial"], str(row["mac"]),
                          str(row["nas_ip"]), str(row["bssid"]), row["ssid"], row["acct_session_id"]),
                         ("accept", "ok", dev, serial, "aa:bb:cc:dd:ee:01", "10.0.0.2", "aa:bb:cc:00:00:01", "Scharni",
                          "ACCT-1"))
        self.assertNotEqual(login(self.db, dev, serial), token)       # fresh per login

    def test_device_mac_and_session(self):
        dev, serial = self.device()
        login(self.db, dev, serial)
        s1 = self.db.execute("SELECT * FROM radius_session WHERE device_id = %s", (dev,)).fetchone()
        self.assertEqual((s1["nas_ip"], s1["calling_station"], s1["user_name"]),
                         ("10.0.0.2", "AA-BB-CC-DD-EE-01", "anonymous@scharni.org"))
        self.db.commit()
        login(self.db, dev, serial, nas="10.0.0.3")
        s2 = self.db.execute("SELECT * FROM radius_session WHERE device_id = %s", (dev,)).fetchone()
        self.assertEqual(s2["first_seen"], s1["first_seen"])            # same MAC: kept
        self.assertEqual(s2["nas_ip"], "10.0.0.3")
        self.db.commit()
        login(self.db, dev, serial, mac="DA-00-00-00-00-02")
        login(self.db, dev, serial, mac="A4-83-E7-00-00-02")
        s3 = self.db.execute("SELECT * FROM radius_session WHERE device_id = %s", (dev,)).fetchone()
        self.assertGreater(s3["first_seen"], s1["first_seen"])          # another MAC: new
        macs = {str(r["mac"]): r for r in self.db.execute("SELECT * FROM device_mac WHERE device_id = %s", (dev,))}
        self.assertEqual(set(macs), {"aa:bb:cc:dd:ee:01", "da:00:00:00:00:02", "a4:83:e7:00:00:02"})
        self.assertEqual(macs["aa:bb:cc:dd:ee:01"]["auth_count"], 2)
        self.assertFalse(macs["a4:83:e7:00:00:02"]["randomized"])
        self.assertTrue(macs["da:00:00:00:00:02"]["randomized"])

    def test_a_locked_row_does_not_hold_up_the_login(self):
        """The collector (or anything) holding the device's device_mac row: the login waits 500 ms
        for it (lock_timeout), skips that write and returns its token well inside the role's
        statement_timeout (2 s), whose query_canceled no EXCEPTION block would catch."""
        dev, serial = self.device()
        r = self.radius()
        call = ("SELECT radius_login(%s, %s, 'AA-BB-CC-DD-EE-01', 'AA-BB-CC-00-00-01:Scharni', '10.0.0.2', '', "
                "'anonymous@x')")
        r.execute(call, (dev, serial))
        other = psycopg.connect(dsn(self.dbname))
        self.addCleanup(other.close)
        other.execute("UPDATE device_mac SET last_seen = last_seen WHERE device_id = %s", (dev,))   # row lock held
        began = time.monotonic()
        token = r.execute(call, (dev, serial)).fetchone()[0]
        elapsed = time.monotonic() - began
        other.rollback()
        self.assertRegex(token or "", r"^np1:")
        self.assertTrue(0.4 < elapsed < 0.9, elapsed)            # 500 ms, not the role's 1 s
        self.assertEqual(self.scalar("SELECT auth_count FROM device_mac WHERE device_id = %s", dev), 1)   # skipped
        self.assertEqual(self.scalar("SELECT count(*) FROM radius_auth WHERE device_id = %s", dev), 2)      # logged

    def test_bad_input_never_raises(self):
        dev, serial = self.device()
        for args in [(None, None, None, None, None, None), ("not-a-uuid", serial, "x", "y", "z", ""),
                     (str(uuid.uuid4()), serial, "", "", "", ""), ("'; DROP TABLE device; --", "", "", "", "", "")]:
            with self.subTest(args=args):
                self.assertIsNone(login(self.db, *args))
        # A login with junk attributes is still logged (the device is known).
        token = login(self.db, dev, "zz", mac="junk", called="junk", nas="999.1.1.1", acct="x" * 400)
        row = self.db.execute("SELECT * FROM radius_auth WHERE class_token = %s", (token,)).fetchone()
        self.assertEqual((row["serial"], row["mac"], row["nas_ip"], row["bssid"], len(row["acct_session_id"])),
                         (None, None, None, None, 253))
        self.db.execute("SELECT radius_reject(NULL, NULL, NULL, NULL, NULL)")
        accounting(self.db, None, None, None, None, None)
        accounting(self.db, "Start", "s", "0xzz", "junk", "10.0.0.2", ts="99999999999999999999", time="-1",
                   ingw="999999999999999999")


class RejectTests(DbCase):
    def reason(self, serial, hint=""):
        """The row the reject went into (a repeat of the same key adds to an earlier one)."""
        self.db.execute("SELECT radius_reject(%s, 'AA-BB-CC-DD-EE-09', 'AA-BB-CC-00-00-01:Scharni', '10.0.0.2', %s)",
                        (serial, hint))
        self.db.commit()                            # a transaction per reject, as FreeRADIUS calls it
        return self.db.execute("SELECT reason, device_id::text AS device_id, serial, mac::text AS mac, ssid FROM radius_auth "
                               "WHERE result = 'reject' ORDER BY coalesce(last_at, at) DESC, id DESC LIMIT 1").fetchone()

    def rows(self, mac):
        return list(self.db.execute("SELECT id, reason, count, at, last_at FROM radius_auth WHERE mac = %s ORDER BY id",
                                    (mac,)))

    def test_repeats_are_one_row(self):
        """Anyone in range can loop EAP: repeats of one key within 60 s are one row with a count."""
        r = self.radius()                           # autocommit: each call its own transaction
        reject = "SELECT radius_reject(%s, %s, 'AA-BB-CC-00-00-01:Scharni', '10.0.0.2', 'no_cert')"
        for _ in range(3):
            r.execute(reject, ("", "AA-BB-CC-DD-EE-21"))
        rows = self.rows("aa:bb:cc:dd:ee:21")
        self.assertEqual([x["count"] for x in rows], [3])
        self.assertGreater(rows[0]["last_at"], rows[0]["at"])
        r.execute(reject, ("", "AA-BB-CC-DD-EE-22"))                        # another MAC: its own row
        r.execute("SELECT radius_reject('', 'AA-BB-CC-DD-EE-21', 'AA-BB-CC-00-00-01:Scharni', '10.0.0.2', 'not_eap')")
        r.execute("SELECT radius_reject('', 'AA-BB-CC-DD-EE-21', 'AA-BB-CC-00-00-02:Scharni', '10.0.0.2', 'no_cert')")
        r.execute("SELECT radius_reject('0123ab', 'AA-BB-CC-DD-EE-21', 'AA-BB-CC-00-00-01:Scharni', '10.0.0.2', '')")
        self.assertEqual([(x["reason"], x["count"]) for x in self.rows("aa:bb:cc:dd:ee:21")],
                         [("no_cert", 3), ("not_eap", 1), ("no_cert", 1), ("unknown_cert", 1)])
        self.assertEqual(len(self.rows("aa:bb:cc:dd:ee:22")), 1)
        # more than 60 s after the latest try: a new row
        self.db.execute("UPDATE radius_auth SET at = at - interval '2 minutes', last_at = last_at - interval '61 seconds' "
                        "WHERE id = %s", (rows[0]["id"],))
        self.db.commit()
        r.execute(reject, ("", "AA-BB-CC-DD-EE-21"))
        self.assertEqual([x["count"] for x in self.rows("aa:bb:cc:dd:ee:21") if x["reason"] == "no_cert"], [3, 1, 1])
        # a row spans at most an hour, however steady the flood
        newest = self.rows("aa:bb:cc:dd:ee:21")[-1]["id"]
        self.db.execute("UPDATE radius_auth SET at = now() - interval '61 minutes' WHERE id = %s", (newest,))
        self.db.commit()
        r.execute(reject, ("", "AA-BB-CC-DD-EE-21"))
        self.assertEqual([x["count"] for x in self.rows("aa:bb:cc:dd:ee:21") if x["reason"] == "no_cert"], [3, 1, 1, 1])
        # without a MAC (not from an access point) too
        for _ in range(2):
            r.execute("SELECT radius_reject('', '', '', '10.0.0.9', 'not_eap')")
        self.assertEqual(self.scalar("SELECT array_agg(count) FROM radius_auth WHERE mac IS NULL "
                                     "AND host(nas_ip) = '10.0.0.9'"), [2])

    def test_a_row_being_updated_is_skipped_not_waited_for(self):
        r = self.radius()
        reject = "SELECT radius_reject('', 'AA-BB-CC-DD-EE-23', '', '10.0.0.2', 'no_cert')"
        r.execute(reject)
        other = psycopg.connect(dsn(self.dbname))
        self.addCleanup(other.close)
        other.execute("SELECT 1 FROM radius_auth WHERE mac = 'aa:bb:cc:dd:ee:23' FOR UPDATE")  # held, not committed
        began = time.monotonic()
        r.execute(reject)
        self.assertLess(time.monotonic() - began, 0.4)
        other.rollback()
        self.assertEqual([x["count"] for x in self.rows("aa:bb:cc:dd:ee:23")], [1, 1])

    def test_reasons(self):
        now = datetime.datetime.now(UTC)
        valid, valid_serial = self.device()
        revoked, revoked_serial = self.device(revoked=True)
        expired, expired_serial = self.device(not_after=now - HOUR)
        retired, retired_serial = self.device()
        self.db.execute("UPDATE credential SET retired_after = now() - interval '1 minute' WHERE serial = %s",
                        (retired_serial,))
        self.assertEqual(self.reason("0123abcd")["reason"], "unknown_cert")
        self.assertIsNone(self.reason("0123abcd")["device_id"])
        self.assertEqual(self.reason(revoked_serial.upper())["reason"], "revoked")
        self.assertEqual(self.reason(revoked_serial)["device_id"], revoked)
        self.assertEqual(self.reason(expired_serial)["reason"], "expired")
        self.assertEqual(self.reason(retired_serial)["reason"], "retired")
        row = self.reason(valid_serial)            # the registry would accept: the TLS layer refused
        self.assertEqual((row["reason"], row["device_id"], row["serial"]), ("bad_chain", None, valid_serial))
        self.assertEqual(self.reason("", "no_cert")["reason"], "no_cert")
        self.assertEqual(self.reason("", "not_eap")["reason"], "not_eap")
        self.assertEqual(self.reason("", "something")["reason"], "other")
        row = self.reason("not hex!", "no_cert")
        self.assertEqual((row["reason"], row["serial"], row["mac"], row["ssid"]),
                         ("no_cert", None, "aa:bb:cc:dd:ee:09", "Scharni"))


class AccountingTests(DbCase):
    def session(self, sid, nas="10.0.0.2"):
        return self.db.execute("SELECT *, device_id::text AS dev, mac::text AS m, host(framed_ip) AS ip FROM radius_acct "
                               "WHERE nas_ip = %s AND acct_session_id = %s", (nas, sid)).fetchone()

    def test_start_interim_stop_with_class(self):
        dev, serial = self.device()
        token = login(self.db, dev, serial)
        ts = int(time.time()) - 900
        accounting(self.db, "Start", "S1", "0x" + token.encode().hex(), framed="10.30.0.5", ts=str(ts))
        s = self.session("S1")
        self.assertEqual((s["dev"], s["link"], s["m"], s["ip"], s["ssid"], s["stopped"]),
                         (dev, "class", "aa:bb:cc:dd:ee:01", "10.30.0.5", "Scharni", None))
        self.assertEqual(s["started"], datetime.datetime.fromtimestamp(ts, UTC))
        accounting(self.db, "Interim-Update", "S1", "0x" + token.encode().hex(), time="300", **{"in": "1000", "out": "5"},
                   ingw="1", outgw="2", ts=str(ts + 300))
        s = self.session("S1")
        self.assertEqual((s["session_time_s"], s["input_octets"], s["output_octets"]),
                         (300, 1000 + 2 ** 32, 5 + 2 * 2 ** 32))
        accounting(self.db, "Stop", "S1", "", time="600", **{"in": "2000", "out": "10"}, ingw="1", outgw="2",
                   cause="Lost-Carrier", ts=str(ts + 600))
        s = self.session("S1")
        self.assertEqual((s["link"], s["dev"], s["terminate_cause"], s["session_time_s"], s["input_octets"]),
                         ("class", dev, "Lost-Carrier", 600, 2000 + 2 ** 32))
        self.assertEqual(s["stopped"], datetime.datetime.fromtimestamp(ts + 600, UTC))
        # A late Interim (reordered) does not shrink counters or reopen the session.
        accounting(self.db, "Interim-Update", "S1", "", time="300", **{"in": "1000"}, ts=str(ts + 300))
        s = self.session("S1")
        self.assertEqual((s["session_time_s"], s["input_octets"], s["stopped"] is not None), (600, 2000 + 2 ** 32, True))
        # The plain token (not hex) works as well.
        accounting(self.db, "Start", "S1b", token)
        self.assertEqual(self.session("S1b")["link"], "class")

    def test_mac_window_and_none(self):
        dev, serial = self.device()
        login(self.db, dev, serial, mac="AA-BB-CC-DD-EE-21")
        accounting(self.db, "Start", "S2", "", mac="AA-BB-CC-DD-EE-21")
        s = self.session("S2")
        self.assertEqual((s["link"], s["dev"]), ("mac_window", dev))
        accounting(self.db, "Start", "S3", "", mac="AA-BB-CC-DD-EE-22")
        s = self.session("S3")
        self.assertEqual((s["link"], s["dev"]), ("none", None))
        accounting(self.db, "Start", "S4", "np1:AAAAAAAAAAAAAAAAAAAAAA", mac="AA-BB-CC-DD-EE-22")
        self.assertEqual(self.session("S4")["link"], "none")         # unknown token, no window
        # The window grows with accounting.
        before = self.scalar("SELECT last_seen FROM device_mac WHERE device_id = %s", dev)
        self.db.commit()
        accounting(self.db, "Interim-Update", "S2", "", mac="AA-BB-CC-DD-EE-21")
        self.assertGreater(self.scalar("SELECT last_seen FROM device_mac WHERE device_id = %s", dev), before)

    def test_class_link_kept(self):
        dev, serial = self.device()
        token = login(self.db, dev, serial, mac="AA-BB-CC-DD-EE-31")
        accounting(self.db, "Start", "S5", token, mac="AA-BB-CC-DD-EE-31")
        accounting(self.db, "Interim-Update", "S5", "", mac="AA-BB-CC-DD-EE-99")
        s = self.session("S5")
        self.assertEqual((s["link"], s["dev"], s["m"]), ("class", dev, "aa:bb:cc:dd:ee:99"))

    def test_accounting_on_closes_open_sessions_of_the_nas(self):
        accounting(self.db, "Start", "A1", "", nas="10.0.0.7")
        accounting(self.db, "Start", "A2", "", nas="10.0.0.7")
        accounting(self.db, "Start", "B1", "", nas="10.0.0.8")
        accounting(self.db, "Accounting-On", "", "", mac="", nas="10.0.0.7")
        self.assertEqual(self.session("A1", "10.0.0.7")["terminate_cause"], "NAS-Reboot")
        self.assertIsNotNone(self.session("A2", "10.0.0.7")["stopped"])
        self.assertIsNone(self.session("B1", "10.0.0.8")["stopped"])
        accounting(self.db, "Accounting-Off", "", "", mac="", nas="10.0.0.8")
        self.assertEqual(self.session("B1", "10.0.0.8")["terminate_cause"], "NAS-Request")

    def test_the_measured_interval(self):
        ts = int(time.time()) - 1000
        accounting(self.db, "Start", "M1", "", nas="10.0.0.40", ts=str(ts))
        self.assertIsNone(self.session("M1", "10.0.0.40")["interim_s"])
        accounting(self.db, "Interim-Update", "M1", "", nas="10.0.0.40", ts=str(ts + 120))
        self.assertEqual(self.session("M1", "10.0.0.40")["interim_s"], 120)
        accounting(self.db, "Interim-Update", "M1", "", nas="10.0.0.40", ts=str(ts + 120))     # duplicate
        accounting(self.db, "Interim-Update", "M1", "", nas="10.0.0.40", ts=str(ts + 60))      # reordered, older
        s = self.session("M1", "10.0.0.40")
        self.assertEqual((s["interim_s"], s["updated"]), (120, datetime.datetime.fromtimestamp(ts + 120, UTC)))
        accounting(self.db, "Interim-Update", "M1", "", nas="10.0.0.40", ts=str(ts + 130))     # a retransmission
        self.assertEqual(self.session("M1", "10.0.0.40")["interim_s"], 120)
        accounting(self.db, "Interim-Update", "M1", "", nas="10.0.0.40", ts=str(ts + 360))     # one lost: 240
        accounting(self.db, "Interim-Update", "M1", "", nas="10.0.0.40", ts=str(ts + 960))     # an outage: 600
        self.assertEqual(self.session("M1", "10.0.0.40")["interim_s"], 120)                  # the smallest gap
        self.assertEqual(self.scalar("SELECT interim_s FROM radius_nas WHERE nas_ip = '10.0.0.40'"), 120)
        # another session's estimate within 10 % does not rewrite the NAS's; a different one does
        nas_at = self.scalar("SELECT interim_at FROM radius_nas WHERE nas_ip = '10.0.0.40'")
        accounting(self.db, "Start", "M2", "", nas="10.0.0.40", ts=str(ts + 100))
        accounting(self.db, "Interim-Update", "M2", "", nas="10.0.0.40", ts=str(ts + 230))     # 130
        self.assertEqual(self.scalar("SELECT interim_at FROM radius_nas WHERE nas_ip = '10.0.0.40'"), nas_at)
        accounting(self.db, "Start", "M3", "", nas="10.0.0.40", ts=str(ts + 100))
        accounting(self.db, "Interim-Update", "M3", "", nas="10.0.0.40", ts=str(ts + 400))     # 300
        self.assertEqual(self.scalar("SELECT interim_s FROM radius_nas WHERE nas_ip = '10.0.0.40'"), 300)
        # a Stop measures nothing
        accounting(self.db, "Stop", "M1", "", nas="10.0.0.40", ts=str(ts + 970))
        self.assertEqual(self.session("M1", "10.0.0.40")["interim_s"], 120)

    def test_a_locked_radius_nas_row_does_not_lose_the_session_update(self):
        # review 7: the NAS row's write has its own exception block
        ts = int(time.time()) - 1000
        accounting(self.db, "Start", "LK", "", nas="10.0.0.44", ts=str(ts))
        self.db.commit()
        other = registry.connect(dsn(self.dbname))
        self.addCleanup(other.close)
        other.execute("INSERT INTO radius_nas (nas_ip, interim_s) VALUES ('10.0.0.44', 999)")
        try:
            accounting(self.db, "Interim-Update", "LK", "", nas="10.0.0.44", ts=str(ts + 120))
            s = self.session("LK", "10.0.0.44")
            self.assertEqual((s["interim_s"], s["updated"]), (120, datetime.datetime.fromtimestamp(ts + 120, UTC)))
        finally:
            other.rollback()

    def test_a_clock_ahead_is_taken_as_now(self):
        # review 8: an Event-Timestamp in the future is never later than the arrival
        accounting(self.db, "Start", "FU", "", ts=str(int(time.time()) + 240))
        started = self.session("FU")["started"]
        self.assertLessEqual(started, datetime.datetime.now(UTC))

    def test_a_reused_session_id_opens_again(self):
        # review 9: a Start newer than the Stop, or an Interim well after it
        ts = int(time.time()) - 3000
        accounting(self.db, "Start", "RU", "", ts=str(ts))
        accounting(self.db, "Stop", "RU", "", cause="User-Request", ts=str(ts + 100))
        accounting(self.db, "Start", "RU", "", ts=str(ts + 500))
        s = self.session("RU")
        self.assertEqual((s["started"], s["stopped"], s["terminate_cause"]),
                         (datetime.datetime.fromtimestamp(ts + 500, UTC), None, None))
        accounting(self.db, "Stop", "RU", "", ts=str(ts + 600))
        accounting(self.db, "Interim-Update", "RU", "", time="60", ts=str(ts + 620))           # within an interval
        self.assertIsNotNone(self.session("RU")["stopped"])
        accounting(self.db, "Interim-Update", "RU", "", time="60", ts=str(ts + 1000))          # well after
        s = self.session("RU")
        self.assertEqual((s["stopped"], s["started"]), (None, datetime.datetime.fromtimestamp(ts + 940, UTC)))

    def test_reordered_stop_and_start(self):
        ts = int(time.time()) - 1000
        # the Stop overtakes the Start (and an Interim): the session ends up stopped
        accounting(self.db, "Stop", "R1", "", time="600", cause="User-Request", ts=str(ts + 600))
        accounting(self.db, "Start", "R1", "", ts=str(ts))
        accounting(self.db, "Interim-Update", "R1", "", time="300", ts=str(ts + 300))
        s = self.session("R1")
        self.assertEqual((s["started"], s["updated"], s["stopped"], s["terminate_cause"]),
                         (datetime.datetime.fromtimestamp(ts, UTC), datetime.datetime.fromtimestamp(ts + 600, UTC),
                          datetime.datetime.fromtimestamp(ts + 600, UTC), "User-Request"))
        # a retransmitted Stop (no Event-Timestamp: its arrival) keeps the first stop time
        accounting(self.db, "Stop", "R1", "", time="600", cause="User-Request")
        self.assertEqual(self.session("R1")["stopped"], datetime.datetime.fromtimestamp(ts + 600, UTC))
        # a retransmitted Start (its Event-Timestamp) keeps the start and the Stop
        accounting(self.db, "Start", "R1", "", ts=str(ts))
        s = self.session("R1")
        self.assertEqual((s["started"], s["stopped"]), (datetime.datetime.fromtimestamp(ts, UTC),
                                                        datetime.datetime.fromtimestamp(ts + 600, UTC)))

    def test_a_stop_ends_only_its_own_session(self):
        ts = int(time.time()) - 600
        accounting(self.db, "Start", "OLD", "", nas="10.0.0.41", ts=str(ts))
        accounting(self.db, "Start", "NEW", "", nas="10.0.0.42", ts=str(ts + 300))             # the roam's new AP
        accounting(self.db, "Stop", "OLD", "", nas="10.0.0.41", cause="User-Request", ts=str(ts + 310))
        self.assertIsNotNone(self.session("OLD", "10.0.0.41")["stopped"])
        self.assertIsNone(self.session("NEW", "10.0.0.42")["stopped"])
        # the same session id at another AP is another session
        accounting(self.db, "Start", "OLD", "", nas="10.0.0.42", ts=str(ts + 320))
        self.assertIsNone(self.session("OLD", "10.0.0.42")["stopped"])

    def test_accounting_on_and_reordering(self):
        nas, ts = "10.0.0.43", int(time.time()) - 600
        accounting(self.db, "Start", "N1", "", nas=nas, ts=str(ts + 200))
        accounting(self.db, "Accounting-On", "", "", mac="", nas=nas, ts=str(ts + 100))      # older, arrives late
        self.assertIsNone(self.session("N1", nas)["stopped"])
        # a Start from before the reboot that arrives after the Accounting-On: ended by it
        accounting(self.db, "Start", "N0", "", nas=nas, ts=str(ts + 50))
        s = self.session("N0", nas)
        self.assertEqual((s["stopped"], s["terminate_cause"]),
                         (datetime.datetime.fromtimestamp(ts + 100, UTC), "NAS-Reboot"))
        # a newer Accounting-Off closes N1; an older Off after it changes nothing
        accounting(self.db, "Accounting-Off", "", "", mac="", nas=nas, ts=str(ts + 300))
        accounting(self.db, "Accounting-Off", "", "", mac="", nas=nas, ts=str(ts + 250))
        s = self.session("N1", nas)
        self.assertEqual((s["stopped"], s["terminate_cause"]),
                         (datetime.datetime.fromtimestamp(ts + 300, UTC), "NAS-Request"))
        self.assertEqual(self.scalar("SELECT reset_at FROM radius_nas WHERE nas_ip = %s", nas),
                         datetime.datetime.fromtimestamp(ts + 300, UTC))
        # a session updated after the reset is not ended by a late older packet
        accounting(self.db, "Start", "N2", "", nas=nas, ts=str(ts + 400))
        accounting(self.db, "Interim-Update", "N2", "", nas=nas, ts=str(ts + 280))
        self.assertIsNone(self.session("N2", nas)["stopped"])

    def test_accounting_on_keeps_the_last_contact_of_abandoned_sessions(self):
        # review 1: a session silent for 3 days is closed at its last contact + 2 x interval +
        # 60 s, not at the reboot, and its updated stays
        nas, ts = "10.0.0.45", int(time.time()) - 6 * 86400
        accounting(self.db, "Start", "AB", "", nas=nas, ts=str(ts))
        accounting(self.db, "Start", "LIVE", "", nas=nas, ts=str(int(time.time()) - 100))
        accounting(self.db, "Accounting-On", "", "", mac="", nas=nas)
        s = self.session("AB", nas)
        self.assertEqual((s["updated"], s["stopped"], s["terminate_cause"]),
                         (datetime.datetime.fromtimestamp(ts, UTC), datetime.datetime.fromtimestamp(ts + 660, UTC),
                          "NAS-Reboot"))
        live = self.session("LIVE", nas)
        self.assertLess(abs((live["stopped"] - datetime.datetime.now(UTC)).total_seconds()), 60)

    def test_implausible_event_timestamp(self):
        accounting(self.db, "Start", "T1", "", ts="1000")      # 1970: the AP's clock is not set
        started = self.session("T1")["started"]
        self.assertLess(abs((started - datetime.datetime.now(UTC)).total_seconds()), 60)

    def test_ignored_packets(self):
        accounting(self.db, "Start", "", "")                   # no session id
        accounting(self.db, "Start", "X1", "", nas="")         # no NAS
        accounting(self.db, "Weird", "X2", "")
        self.assertEqual(self.scalar("SELECT count(*) FROM radius_acct WHERE acct_session_id IN ('', 'X1', 'X2')"), 0)


# --- windows --------------------------------------------------------------------------------

class WindowTests(DbCase):
    MAC = "aa:bb:cc:dd:ee:51"

    def test_recycled_mac_at_different_times(self):
        a, _ = self.device()
        b, _ = self.device()
        self.window(a, self.MAC, T0, T0 + DAY)
        self.window(b, self.MAC, T0 + 2 * DAY, T0 + 3 * DAY)
        self.assertEqual(registry.window_conflicts(self.db, [a, b]), {})
        self.assertEqual(registry.device_for_mac(self.db, self.MAC, T0 + HOUR), a)
        self.assertEqual(registry.device_for_mac(self.db, "AA-BB-CC-DD-EE-51", T0 + DAY + datetime.timedelta(minutes=10)), a)
        # a's only (current) window reaches 12 h 15 min past its last login; then nobody's.
        self.assertEqual(registry.device_for_mac(self.db, self.MAC, T0 + DAY + 12 * HOUR), a)
        self.assertIsNone(registry.device_for_mac(self.db, self.MAC, T0 + DAY + 13 * HOUR))
        self.assertEqual(registry.device_for_mac(self.db, self.MAC, T0 + 2 * DAY + HOUR), b)
        self.assertIsNone(registry.device_for_mac(self.db, "junk", T0))
        windows = registry.device_windows(self.db, [a, b, str(uuid.uuid4())])
        self.assertEqual(len(windows), 3)
        self.assertEqual([(w["mac"], w["first_seen"], w["last_seen"], w["window_end"], w["current"]) for w in windows[a]],
                         [(self.MAC, T0, T0 + DAY, T0 + DAY + registry.CURRENT_WINDOW, True)])
        self.assertEqual(registry.device_windows(self.db, [a], since=T0 + 2 * DAY), {a: []})
        self.assertEqual(len(registry.device_windows(self.db, [a], since=T0 + DAY + 12 * HOUR)[a]), 1)
        self.assertEqual(registry.device_windows(self.db, [b], until=T0 + DAY), {b: []})

    def test_overlapping_owners_conflict(self):
        a, _ = self.device()
        b, _ = self.device()
        self.window(a, self.MAC.replace("51", "52"), T0, T0 + 4 * DAY)
        self.window(b, self.MAC.replace("51", "52"), T0 + DAY, T0 + 2 * DAY)
        conflicts = registry.window_conflicts(self.db, [a, b])
        mac = self.MAC.replace("51", "52")
        self.assertEqual(conflicts[a], [{"mac": mac, "other_owners": 1, "from": T0 + DAY,
                                         "to": T0 + 2 * DAY + registry.CURRENT_WINDOW}])
        self.assertEqual(conflicts[b][0]["other_owners"], 1)
        self.assertIsNone(registry.device_for_mac(self.db, mac, T0 + DAY + HOUR))
        self.assertEqual(registry.device_for_mac(self.db, mac, T0 + 3 * DAY), a)
        clipped = registry.window_conflicts(self.db, [a], since=T0 + DAY + HOUR, until=T0 + DAY + 2 * HOUR)
        self.assertEqual((clipped[a][0]["from"], clipped[a][0]["to"]), (T0 + DAY + HOUR, T0 + DAY + 2 * HOUR))
        self.assertEqual(registry.window_conflicts(self.db, [a], since=T0 + 3 * DAY), {})

    def test_current_window(self):
        """Only the newest MAC of an active device is stretched (to the next forced login), and
        never beyond now; an overlap inside the stretch is a conflict."""
        now = datetime.datetime.now(UTC)
        a, _ = self.device()
        old, new, mac = "aa:bb:cc:dd:ee:55", "aa:bb:cc:dd:ee:56", "aa:bb:cc:dd:ee:57"
        self.window(a, old, T0, T0 + HOUR)                    # replaced by the newer MAC
        self.window(a, new, now - 2 * HOUR, now - HOUR)       # current, last login an hour ago
        w = {x["mac"]: x for x in registry.device_windows(self.db, [a])[a]}
        self.assertEqual((w[old]["current"], w[old]["window_end"]), (False, T0 + HOUR + registry.WINDOW_GRACE))
        self.assertTrue(w[new]["current"])
        self.assertLess(abs((w[new]["window_end"] - now).total_seconds()), 60)      # open up to now
        self.assertIsNone(registry.device_for_mac(self.db, old, T0 + 2 * HOUR))
        self.assertEqual(registry.device_for_mac(self.db, new, now - datetime.timedelta(minutes=5)), a)
        gone, _ = self.device(revoked=True)
        self.window(gone, "aa:bb:cc:dd:ee:58", T0, T0 + HOUR)
        self.assertEqual(registry.device_windows(self.db, [gone])[gone][0]["window_end"], T0 + HOUR + registry.WINDOW_GRACE)
        # Someone else logs in with the MAC an hour after a's login, while a's window is current.
        b, _ = self.device()
        c, _ = self.device()
        self.window(b, mac, T0, T0)
        self.window(c, mac, T0 + HOUR, T0 + HOUR)
        conflicts = registry.window_conflicts(self.db, [b, c])
        self.assertEqual(conflicts[b][0]["from"], T0 + HOUR)
        self.assertEqual(conflicts[b][0]["to"], T0 + registry.CURRENT_WINDOW)
        self.assertIsNone(registry.device_for_mac(self.db, mac, T0 + 2 * HOUR))
        self.assertEqual(registry.device_for_mac(self.db, mac, T0 + 30 * datetime.timedelta(minutes=1)), b)
        self.assertEqual(registry.device_for_mac(self.db, mac, T0 + 13 * HOUR), c)

    def test_same_owner_is_no_conflict_a_revoked_device_still_is(self):
        owner = self.person()
        a, _ = self.device(owner)
        a2, _ = self.device(owner)
        mac = self.MAC.replace("51", "53")
        self.window(a, mac, T0, T0 + 2 * DAY)
        self.window(a2, mac, T0 + DAY, T0 + 3 * DAY)          # re-enrolled: the newer one
        self.assertNotIn(a, registry.window_conflicts(self.db, [a]))
        self.assertEqual(registry.device_for_mac(self.db, mac, T0 + 2 * DAY + HOUR), a2)
        self.assertEqual(registry.device_for_mac(self.db, mac, T0 + 1.5 * DAY), a2)
        # Someone else's device had it at the same time and was revoked since: that time stays
        # nobody's (np_device_for_mac) and withheld (window_conflicts), the same rule.
        gone, _ = self.device(revoked=True)
        self.window(gone, mac, T0, T0 + DAY)
        self.assertIsNone(registry.device_for_mac(self.db, mac, T0 + HOUR))
        conflicts = registry.window_conflicts(self.db, [a, a2])
        self.assertEqual(conflicts[a], [{"mac": mac, "other_owners": 1, "from": T0,
                                         "to": T0 + DAY + registry.WINDOW_GRACE}])
        self.assertEqual(conflicts[a2][0]["from"], T0 + DAY)
        self.assertEqual(registry.window_conflicts(self.db, [a], since=T0 + 2 * DAY), {})   # nothing after it


# --- the read and write interface -------------------------------------------------------------

class InterfaceTests(DbCase):
    def test_auth_events_and_failures(self):
        owner = self.person()
        dev, serial = self.device(owner)
        login(self.db, dev, serial, mac="AA-BB-CC-DD-EE-61")
        self.db.execute("SELECT radius_reject('', 'AA-BB-CC-DD-EE-61', '', '10.0.0.2', 'no_cert')")
        self.db.execute("SELECT radius_reject('', 'AA-BB-CC-DD-EE-62', '', '10.0.0.2', 'no_cert')")   # not its MAC
        self.db.execute("UPDATE device SET revoked = now() WHERE id = %s", (dev,))
        self.db.execute("SELECT radius_reject(%s, 'AA-BB-CC-DD-EE-61', 'AA-BB-CC-00-00-01:S', '10.0.0.2', '')", (serial,))
        now = datetime.datetime.now(UTC)
        events = registry.auth_events(self.db, dev, now - HOUR, now + HOUR)
        self.assertEqual([(e["result"], e["reason"], e["match"]) for e in events],
                         [("accept", "ok", "device"), ("reject", "no_cert", "mac"), ("reject", "revoked", "device")])
        self.assertEqual(set(events[0]), {"at", "result", "reason", "mac", "bssid", "ssid", "nas_ip", "match", "count",
                                          "last_at"})
        self.assertEqual([(e["count"], e["last_at"]) for e in events], [(1, None)] * 3)
        self.assertEqual((events[0]["mac"], events[0]["nas_ip"]), ("aa:bb:cc:dd:ee:61", "10.0.0.2"))
        self.assertEqual(len(registry.auth_events(self.db, dev, now - HOUR, now + HOUR, limit=1)), 1)
        self.assertEqual(registry.auth_events(self.db, dev, now + HOUR, now + 2 * HOUR), [])
        failures = registry.auth_failures(self.db, now - HOUR)
        self.assertEqual(failures[0]["reason"], "revoked")
        self.assertEqual((failures[0]["device_id"], failures[0]["owner"], failures[0]["owner_name"]),
                         (dev, owner, owner.title()))
        self.assertEqual({f["reason"] for f in failures}, {"revoked", "no_cert"})
        self.assertLessEqual({"at", "reason", "serial", "device_id", "owner", "mac", "bssid", "ssid", "nas_ip", "count",
                              "last_at"}, set(failures[0]))
        self.assertEqual(len(registry.auth_failures(self.db, now - HOUR, limit=1)), 1)
        # repeats: one row with their count, in both lists
        self.db.commit()
        r = self.radius()
        for _ in range(4):
            r.execute("SELECT radius_reject('', 'AA-BB-CC-DD-EE-61', '', '10.0.0.3', 'no_cert')")
        now = datetime.datetime.now(UTC)
        repeated = [e for e in registry.auth_events(self.db, dev, now - HOUR, now + HOUR) if e["nas_ip"] == "10.0.0.3"]
        self.assertEqual([(e["count"], e["match"]) for e in repeated], [(4, "mac")])
        self.assertGreater(repeated[0]["last_at"], repeated[0]["at"])
        self.assertEqual([f["count"] for f in registry.auth_failures(self.db, now - HOUR) if f["nas_ip"] == "10.0.0.3"],
                         [4])

    def test_acct_sessions(self):
        dev, serial = self.device()
        token = login(self.db, dev, serial)
        ts = int(time.time())
        accounting(self.db, "Start", "Q1", token, ts=str(ts - 1000))
        accounting(self.db, "Stop", "Q1", token, ts=str(ts - 500), time="500", cause="User-Request")
        accounting(self.db, "Start", "Q2", token, ts=str(ts - 100), framed="10.30.0.9")
        now = datetime.datetime.fromtimestamp(ts, UTC)
        rows = registry.acct_sessions(self.db, dev, now - HOUR, now)
        self.assertEqual([r["acct_session_id"] for r in rows], ["Q1", "Q2"])
        self.assertEqual(set(rows[0]), set(registry.ACCT_COLUMNS))
        self.assertEqual((rows[0]["terminate_cause"], rows[1]["framed_ip"], rows[1]["nas_ip"]),
                         ("User-Request", "10.30.0.9", "10.0.0.2"))
        recent = registry.acct_sessions(self.db, dev, now - datetime.timedelta(seconds=300), now)
        self.assertEqual([r["acct_session_id"] for r in recent], ["Q2"])

    def test_latest_sessions_and_events_for_a_page(self):
        dev, serial = self.device()
        dev2, serial2 = self.device()
        token, token2 = login(self.db, dev, serial), login(self.db, dev2, serial2, mac="AA-BB-CC-DD-EE-02")
        ts = int(time.time()) - 3000
        for i in range(7):
            accounting(self.db, "Start", "L%d" % i, token, nas="10.0.0.50", ts=str(ts + i * 100))
        accounting(self.db, "Interim-Update", "L6", token, nas="10.0.0.50", ts=str(ts + 720))
        accounting(self.db, "Start", "K1", token2, nas="10.0.0.51", mac="AA-BB-CC-DD-EE-02", ts=str(ts))
        self.db.commit()
        found = registry.latest_sessions(self.db, [dev, dev2, uuid.uuid4()])
        self.assertEqual(len(found), 3)
        self.assertEqual([r["acct_session_id"] for r in found[str(dev)]], ["L6", "L5", "L4", "L3", "L2"])
        self.assertEqual((found[str(dev)][0]["interim_s"], found[str(dev)][0]["nas_interim_s"],
                          found[str(dev)][1]["nas_interim_s"]), (120, 120, 120))
        self.assertEqual([r["acct_session_id"] for r in found[str(dev2)]], ["K1"])
        self.assertEqual(found[str(dev2)][0]["nas_interim_s"], None)
        self.assertEqual(registry.latest_sessions(self.db, []), {})
        mac = "aa:bb:cc:dd:ee:72"
        self.window(dev, mac, T0, T0 + DAY)
        rows = [{"at": T0 + i * HOUR, "kind": kind, "mac": mac, "ssid": ssid, "dedup_key": "p%d" % i}
                for i, (kind, ssid) in enumerate([("connected", "Scharni"), ("other", "Scharni"),
                                                  ("disconnected", "Scharni"), ("connected", "Guests"),
                                                  ("roamed", None)])]
        registry.insert_connection_events(self.db, rows)
        events = registry.latest_connection_events(self.db, [dev, dev2], ssid="Scharni")
        self.assertEqual([e["kind"] for e in events[str(dev)]], ["roamed", "disconnected", "connected"])
        self.assertEqual(events[str(dev2)], [])
        self.assertEqual(len(registry.latest_connection_events(self.db, [dev])[str(dev)]), 3)
        self.assertEqual(registry.latest_connection_events(self.db, [dev], per_device=1)[str(dev)][0]["kind"], "roamed")
        self.db.execute("SET enable_seqscan = off")         # a tiny table: show that the index serves it
        plan = "\n".join(r["QUERY PLAN"] for r in self.db.execute(
            "EXPLAIN SELECT * FROM radius_acct WHERE device_id = %s ORDER BY updated DESC LIMIT 5", (dev,)))
        self.assertIn("radius_acct_device", plan)
        self.db.execute("RESET enable_seqscan")

    def test_connection_events(self):
        dev, _ = self.device()
        mac = "aa:bb:cc:dd:ee:71"
        self.window(dev, mac, T0, T0 + HOUR)
        rows = [{"at": T0 + 30 * datetime.timedelta(minutes=1), "kind": "connected", "source": "unifi_syslog",
                 "mac": "AA-BB-CC-DD-EE-71", "ap_mac": "AA:BB:CC:00:00:01", "ap_name": "AP Flur", "ssid": "Scharni",
                 "radio": "na", "channel": 36, "rssi": -60, "dedup_key": "k1", "detail": {"raw": 1}},
                {"at": T0 + 14 * HOUR, "kind": "roamed", "mac": mac, "from_ap_mac": "aa:bb:cc:00:00:01",
                 "ap_mac": "aa:bb:cc:00:00:02", "dedup_key": "k2"},       # outside the window: nobody's
                {"at": T0 + HOUR + datetime.timedelta(minutes=10), "kind": "weird", "mac": mac, "dedup_key": "k3"},
                {"at": T0, "kind": "connected", "mac": "junk", "dedup_key": "k4"},
                {"at": T0, "kind": "connected", "mac": mac}]                      # no dedup key
        self.assertEqual(registry.insert_connection_events(self.db, rows), 3)
        self.assertEqual(registry.insert_connection_events(self.db, rows), 0)     # idempotent
        events = registry.connection_events(self.db, dev, T0, T0 + DAY)
        self.assertEqual([(e["kind"], e["ap_mac"]) for e in events], [("connected", "aa:bb:cc:00:00:01"), ("other", None)])
        self.assertEqual((events[0]["detail"], events[0]["channel"], events[0]["source"]), ({"raw": 1}, 36, "unifi_syslog"))
        self.assertLessEqual(set(registry.EVENT_COLUMNS), set(events[0]))
        # The resolved events extended the window (the "other" one at +70 min).
        self.assertEqual(self.scalar("SELECT last_seen FROM device_mac WHERE device_id = %s", dev),
                         T0 + HOUR + datetime.timedelta(minutes=10))
        self.assertIsNone(self.scalar("SELECT device_id FROM connection_event WHERE dedup_key = 'k2'"))
        self.assertEqual(len(registry.connection_events(self.db, dev, T0, T0 + DAY, limit=1)), 1)

    def test_rollups(self):
        dev, _ = self.device()
        day = datetime.date(2026, 10, 24)
        registry.upsert_device_day(self.db, {"device_id": dev, "day": day, "online_s": 100, "aps": {"aa:bb": 100},
                                             "signal_avg_dbm": -60.5})
        registry.upsert_device_day(self.db, {"device_id": dev, "day": day, "online_s": 200, "roams": 2})
        rows = registry.device_days(self.db, dev, day, day)
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["online_s"], rows[0]["roams"], rows[0]["aps"], rows[0]["signal_avg_dbm"]),
                         (200, 2, {"aa:bb": 100}, -60.5))
        with self.assertRaises(ValueError):
            registry.upsert_device_day(self.db, {"device_id": dev, "day": day, "nope; DROP": 1})
        registry.upsert_ap_day(self.db, {"ap_mac": "AA-BB-CC-00-00-01", "day": day, "ap_name": "AP Flur",
                                         "clients_max": 7, "channel_util_avg": {"ng": 0.4}})
        registry.upsert_ap_day(self.db, {"ap_mac": "aa:bb:cc:00:00:02", "day": day + datetime.timedelta(days=1)})
        self.assertEqual([r["ap_mac"] for r in registry.ap_days(self.db, day, day + datetime.timedelta(days=1))],
                         ["aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"])
        only = registry.ap_days(self.db, day, day + datetime.timedelta(days=5), ap_macs=["AA:BB:CC:00:00:01"])
        self.assertEqual([(r["ap_mac"], r["clients_max"], r["channel_util_avg"]) for r in only],
                         [("aa:bb:cc:00:00:01", 7, {"ng": 0.4})])
        with self.assertRaises(ValueError):
            registry.upsert_ap_day(self.db, {"ap_mac": "junk", "day": day})

    def test_incidents(self):
        first = registry.open_incident(self.db, "ap_down", "aa:bb:cc:00:00:01", "AP Flur", T0, "measured", {"why": 1})
        again = registry.open_incident(self.db, "ap_down", "aa:bb:cc:00:00:01", "AP Flur", T0 + HOUR, "measured")
        self.assertEqual(first, again)                           # no second open incident
        other = registry.open_incident(self.db, "internet_down", "", None, T0, "measured")
        self.assertNotEqual(other, first)
        self.assertEqual(registry.close_incident(self.db, "ap_down", "aa:bb:cc:00:00:01", T0 + 2 * HOUR), 1)
        self.assertEqual(registry.close_incident(self.db, "ap_down", "aa:bb:cc:00:00:01", T0 + 3 * HOUR), 0)
        # The same start again (a re-evaluation of the same window): the same incident, still closed.
        self.assertEqual(registry.open_incident(self.db, "ap_down", "aa:bb:cc:00:00:01", "AP Flur", T0, "measured"), first)
        later = registry.open_incident(self.db, "ap_down", "aa:bb:cc:00:00:01", "AP Flur", T0 + 5 * HOUR, "inferred")
        self.assertNotEqual(later, first)
        rows = registry.incidents(self.db, T0, T0 + DAY)
        self.assertEqual([(r["id"], r["ended"]) for r in rows if r["kind"] == "ap_down"],
                         [(first, T0 + 2 * HOUR), (later, None)])
        self.assertEqual(rows[0]["detail"], {"why": 1})
        self.assertEqual([r["id"] for r in registry.incidents(self.db, T0 + 3 * HOUR, T0 + 4 * HOUR)], [other])
        self.assertEqual([r["id"] for r in registry.incidents(self.db, T0, kinds=["internet_down"])], [other])
        self.assertEqual([r["id"] for r in registry.incidents(self.db, T0, subjects=["aa:bb:cc:00:00:01"])],
                         [first, later])

    def test_jobs(self):
        registry.job_begin(self.db, "rollup")
        status = {j["name"]: j for j in registry.job_status(self.db)}
        self.assertIsNone(status["rollup"]["last_success"])
        self.assertIsNotNone(status["rollup"]["last_attempt"])
        self.assertIn("offboarding", status)
        registry.job_end(self.db, "rollup", False, error="boom", duration_s=1.5)
        status = {j["name"]: j for j in registry.job_status(self.db)}["rollup"]
        self.assertEqual((status["last_error"], status["duration_s"], status["last_success"]), ("boom", 1.5, None))
        registry.job_end(self.db, "rollup", True, duration_s=2.0, cursor={"day": "2026-10-24"})
        status = {j["name"]: j for j in registry.job_status(self.db)}["rollup"]
        self.assertEqual((status["last_error"], status["cursor"]), (None, {"day": "2026-10-24"}))
        self.assertIsNotNone(status["last_success"])
        registry.job_end(self.db, "rollup", True)
        self.assertEqual({j["name"]: j for j in registry.job_status(self.db)}["rollup"]["cursor"], {"day": "2026-10-24"})
        registry.mark_job(self.db, "offboarding")                 # the old way still works

    def test_prune(self):
        dev, serial = self.device()
        revoked, _ = self.device(revoked=True)
        now = datetime.datetime.now(UTC)
        old = now - 401 * DAY
        self.db.execute("INSERT INTO radius_auth (at, result, reason) VALUES (%s, 'reject', 'other'), (%s, 'reject', 'other')",
                        (old, now))
        self.db.execute("""INSERT INTO radius_acct (nas_ip, acct_session_id, link, updated) VALUES
                           ('10.0.0.2', 'old', 'none', %s), ('10.0.0.2', 'new', 'none', %s)""", (old, now))
        registry.insert_connection_events(self.db, [{"at": old, "kind": "connected", "mac": "aa:bb:cc:dd:ee:81",
                                                     "dedup_key": "p1"}])
        self.window(dev, "aa:bb:cc:dd:ee:82", old - DAY, old)
        self.window(revoked, "aa:bb:cc:dd:ee:83", old - DAY, old)
        self.window(revoked, "aa:bb:cc:dd:ee:84", now - DAY, now)
        self.db.execute("INSERT INTO audit (at, actor, action) VALUES (%s, 'x', 'y')", (now - 91 * DAY,))
        registry.upsert_device_day(self.db, {"device_id": dev, "day": old.date(), "online_s": 1})
        registry.open_incident(self.db, "router_down", "", None, old, "measured")
        deleted = registry.prune(self.db, now=now)
        self.assertEqual({k: deleted[k] for k in ("radius_auth", "radius_acct", "connection_event", "device_mac",
                                                  "audit")},
                         {"radius_auth": 1, "radius_acct": 1, "connection_event": 1, "device_mac": 1, "audit": 1})
        self.assertIn("oauth_token", deleted)
        self.assertEqual(self.scalar("SELECT count(*) FROM device_mac WHERE device_id IN (%s, %s)", dev, revoked),
                         2)                                       # the active device's old row is kept
        self.assertEqual(self.scalar("SELECT count(*) FROM device_day"), 1)
        self.assertEqual(self.scalar("SELECT count(*) FROM incident"), 1)
        registry.prune(self.db)                                   # the offboarding's call

    def test_prune_in_batches(self):
        """A backlog is deleted in statements of `batch` rows, each committed by the caller's
        callable: none of them grows with the backlog."""
        old = datetime.datetime.now(UTC) - 401 * DAY
        self.db.execute("DELETE FROM radius_auth")
        self.db.execute("INSERT INTO radius_auth (at, result, reason) "
                        "SELECT %s, 'reject', 'other' FROM generate_series(1, 7)", (old,))
        self.db.execute("INSERT INTO radius_auth (result, reason) VALUES ('reject', 'other')")
        self.db.commit()
        commits, batches = [], []
        execute = self.db.execute

        def counting(sql, args=None):
            if sql.startswith("DELETE FROM radius_auth"):
                batches.append(args[-1])
            return execute(sql, args)

        with mock.patch.object(self.db, "execute", counting):
            deleted = registry.prune(self.db, batch=3, commit=lambda: commits.append(1) or self.db.commit())
        self.assertEqual(deleted["radius_auth"], 7)
        self.assertEqual(batches, [3, 3, 3])                    # 3 + 3 + 1
        self.assertEqual(self.scalar("SELECT count(*) FROM radius_auth"), 1)
        self.assertGreaterEqual(len(commits), 3 + 6)            # each batch, every other table at least once

    def test_stats(self):
        row = registry.stats(self.db)
        self.assertEqual((row["radius_role"], row["schema_version"]), (True, 3))


if __name__ == "__main__":
    unittest.main()
