"""Registry pieces without a database: the MAC normaliser, the migration files and the runner's
decisions (with a fake connection). The SQL itself is tested in test_registry_db.py."""

import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from netportal import registry  # noqa: E402

# Shared with test_registry_db.py, which checks SQL np_mac on the same cases.
MAC_CASES = {
    "AA-BB-CC-DD-EE-FF": "aa:bb:cc:dd:ee:ff",
    "aa:bb:cc:dd:ee:ff": "aa:bb:cc:dd:ee:ff",
    "AABBCCDDEEFF": "aa:bb:cc:dd:ee:ff",
    "  aa-bb-cc-dd-ee-0f\n": "aa:bb:cc:dd:ee:0f",
    "\tAABBCCDDEE01 ": "aa:bb:cc:dd:ee:01",
    "aa:bb-cc:dd:ee:ff": None,
    "aabb.ccdd.eeff": None,
    "aa:bb:cc:dd:ee": None,
    "aa:bb:cc:dd:ee:ff:00": None,
    "gg:bb:cc:dd:ee:ff": None,
    "aabbccddeef": None,
    "": None,
    "anonymous@scharni.org": None,
    "aa bb cc dd ee ff": None,
    "a:b:c:d:e:f": None,
    "AA:BB:CC:DD:EE:FF;DROP": None,
    " aa:bb:cc:dd:ee:ff": None,      # only ASCII whitespace is stripped (as btrim in np_mac)
}


class NormaliseMacTests(unittest.TestCase):
    def test_cases(self):
        for raw, expected in MAC_CASES.items():
            with self.subTest(raw=raw):
                self.assertEqual(registry.normalise_mac(raw), expected)

    def test_not_a_string(self):
        for raw in (None, 123, b"aa:bb:cc:dd:ee:ff", ["aa:bb:cc:dd:ee:ff"]):
            self.assertIsNone(registry.normalise_mac(raw))

    def test_randomized(self):
        self.assertTrue(registry.is_randomized("02:00:00:00:00:01"))
        self.assertTrue(registry.is_randomized("aa:bb:cc:dd:ee:ff"))     # 0xaa has the bit
        self.assertFalse(registry.is_randomized("a4:83:e7:00:00:01"))


class MigrationFileTests(unittest.TestCase):
    def test_versions_names_checksums(self):
        files = registry.migration_files()
        self.assertEqual([(v, n) for v, n, _, _ in files], [(1, "baseline"), (2, "telemetry")])
        for _, _, sql, checksum in files:
            self.assertEqual(checksum, hashlib.sha256(sql.encode()).hexdigest())

    def test_schema_sql_is_gone(self):
        root = Path(registry.__file__).parent
        self.assertFalse((root / "schema.sql").exists())
        self.assertTrue((root / "migrations" / "grants.sql").exists())

    def test_baseline_is_idempotent_ddl(self):
        """0001 runs on databases schema.sql made: only IF NOT EXISTS / OR REPLACE creations."""
        sql = registry.migration_files()[0][2]
        for line in sql.splitlines():
            if line.startswith("CREATE "):
                self.assertTrue("IF NOT EXISTS" in line or "OR REPLACE" in line, line)

    def test_functions_are_hardened(self):
        sql = registry.migration_files()[1][2]
        for name in ("radius_login", "radius_reject", "radius_accounting", "radius_cert_status"):
            head = sql[sql.index("CREATE FUNCTION %s(" % name):]
            head = head[:head.index(" AS $$")]
            self.assertIn("SECURITY DEFINER", head, name)
            self.assertIn("SET search_path = public, pg_temp", head, name)
        grants = (Path(registry.__file__).parent / "migrations" / "grants.sql").read_text()
        self.assertIn("REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC", grants)


class _Result:
    def __init__(self, rows):
        self.rows = rows

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def __iter__(self):
        return iter(self.rows)


class FakeDb:
    """Answers the runner's queries from `applied` ({version: checksum}); records the rest."""

    def __init__(self, applied):
        self.applied = applied
        self.executed, self.commits, self.rollbacks = [], 0, 0

    def execute(self, sql, args=None):
        self.executed.append(sql)
        if sql.startswith("SELECT version, name, checksum"):
            return _Result([{"version": v, "name": "x", "checksum": c} for v, c in self.applied.items()])
        if "pg_roles" in sql:
            return _Result([{"ok": True}])
        if sql.startswith("SELECT max(version)"):
            return _Result([{"v": max(self.applied or {0: 0})}])
        return _Result([])

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1


class MigrateRunnerTests(unittest.TestCase):
    def setUp(self):
        self.files = registry.migration_files()

    def test_applies_missing_in_order_under_the_lock(self):
        db = FakeDb({1: self.files[0][3]})
        result = registry.migrate(db)
        self.assertEqual(result["applied"], [2])
        self.assertIn("pg_advisory_xact_lock", db.executed[0])
        self.assertIn(self.files[1][2], db.executed)
        self.assertNotIn(self.files[0][2], db.executed)
        self.assertEqual((db.commits, db.rollbacks), (1, 0))

    def test_changed_file_refused_and_rolled_back(self):
        db = FakeDb({1: self.files[0][3], 2: "0" * 64})
        with self.assertRaises(registry.MigrationError):
            registry.migrate(db)
        self.assertEqual((db.commits, db.rollbacks), (0, 1))
        self.assertFalse(any("REVOKE" in sql for sql in db.executed))     # grants not run either

    def test_newer_schema_is_left_alone(self):
        db = FakeDb({1: self.files[0][3], 2: self.files[1][3], 99: "f" * 64})
        with self.assertLogs("netportal.registry", "INFO") as logs:
            result = registry.migrate(db)
        self.assertEqual(result["applied"], [])
        self.assertTrue(any("99" in line for line in logs.output))
        self.assertEqual(db.commits, 1)


if __name__ == "__main__":
    unittest.main()
