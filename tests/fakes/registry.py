"""An in-memory stand-in for the registry functions the collector calls (the contract of
docs/TELEMETRY.md / the Telemetry v2 work split), and a fake database connection.

    reg = FakeRegistry()
    with reg.patched():            # netportal.registry.<function> -> reg.<function>
        scheduler.run_job(job, settings)

Only behaviour the collector relies on is modelled: advisory locks per name (shared by all
connections of one FakeRegistry), job bookkeeping, incidents idempotent on (kind, subject,
started) with at most one open per kind+subject, connection events deduplicated by dedup_key,
device windows with a grace, day rows keyed per (device, day) / (AP, day).
"""

import contextlib
import datetime
import re
from unittest import mock

UTC = datetime.timezone.utc
GRACE = datetime.timedelta(minutes=15)


def normalise_mac(raw):
    if not isinstance(raw, str):
        return None
    mac = raw.strip().lower()
    if re.fullmatch(r"[0-9a-f]{12}", mac):
        mac = ":".join(mac[i:i + 2] for i in range(0, 12, 2))
    elif re.fullmatch(r"[0-9a-f]{2}([-:])[0-9a-f]{2}(\1[0-9a-f]{2}){4}", mac):
        mac = mac.replace("-", ":")
    else:
        return None
    return mac


class _Result:
    def __init__(self, row):
        self.row = row

    def fetchone(self):
        return self.row

    def __iter__(self):
        return iter([self.row] if self.row is not None else [])


class FakeDB:
    """A connection: advisory locks, SET, commit/rollback counts, context manager."""

    def __init__(self, reg):
        self.reg, self.commits, self.rollbacks, self.closed, self.held = reg, 0, 0, False, set()
        self.statements = []

    def execute(self, sql, args=()):
        self.statements.append(sql)
        if "pg_try_advisory_lock" in sql:
            key = args[0]
            if key in self.reg.locks and self.reg.locks[key] is not self:
                return _Result({"locked": False})
            self.reg.locks[key] = self
            self.held.add(key)
            return _Result({"locked": True})
        if "pg_advisory_unlock" in sql:
            key = args[0]
            if self.reg.locks.get(key) is self:
                del self.reg.locks[key]
                self.held.discard(key)
            return _Result({"pg_advisory_unlock": True})
        return _Result(None)

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        for key in list(self.held):
            if self.reg.locks.get(key) is self:
                del self.reg.locks[key]
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class FakeRegistry:
    FUNCTIONS = ("connect", "normalise_mac", "job_begin", "job_end", "job_status", "device_for_mac",
                 "insert_connection_events", "open_incident", "close_incident", "incidents", "prune",
                 "devices", "device_windows", "device_days", "ap_days", "upsert_device_day", "upsert_ap_day",
                 "auth_events", "connection_events")

    def __init__(self):
        self.locks, self.jobs, self.events, self.incident_rows = {}, {}, {}, []
        self.windows = {}           # device_id -> [{"mac", "first_seen", "last_seen", "randomized", "auth_count"}]
        self.device_rows = []       # registry.devices rows
        self.device_day_rows, self.ap_day_rows = {}, {}
        self.auth, self.prune_calls = {}, []
        self.connections = []
        self.connect_error = None
        self.now = lambda: datetime.datetime.now(UTC)
        self.WINDOW_GRACE = GRACE

    @contextlib.contextmanager
    def patched(self):
        from netportal import registry
        with contextlib.ExitStack() as stack:
            for name in self.FUNCTIONS:
                stack.enter_context(mock.patch.object(registry, name, getattr(self, name), create=True))
            stack.enter_context(mock.patch.object(registry, "WINDOW_GRACE", GRACE, create=True))
            yield self

    # --- connection and jobs ------------------------------------------------------------------
    def connect(self, dsn):
        if self.connect_error:
            raise self.connect_error
        db = FakeDB(self)
        self.connections.append(db)
        return db

    normalise_mac = staticmethod(normalise_mac)

    def job_begin(self, db, name):
        row = self.jobs.setdefault(name, {"name": name, "last_success": None, "last_attempt": None,
                                          "last_error": None, "duration_s": None, "cursor": {}})
        row["last_attempt"] = self.now()

    def job_end(self, db, name, ok, error=None, duration_s=None, cursor=None):
        row = self.jobs[name]
        if ok:
            row["last_success"], row["last_error"] = self.now(), None
        else:
            row["last_error"] = error
        row["duration_s"] = duration_s
        if cursor is not None:
            row["cursor"] = cursor

    def job_status(self, db):
        return [dict(r) for r in self.jobs.values()]

    def prune(self, db, now=None, commit=None):
        self.prune_calls.append(now)
        self.prune_commits = commit
        return {"radius_auth": 3, "connection_event": 0}

    # --- windows and events -------------------------------------------------------------------
    def device_for_mac(self, db, mac, at):
        owners = {d for d, rows in self.windows.items() for w in rows
                  if w["mac"] == mac and w["first_seen"] <= at <= w["last_seen"] + GRACE}
        return next(iter(owners)) if len(owners) == 1 else None

    def insert_connection_events(self, db, rows):
        new = 0
        for row in rows:
            if row["dedup_key"] in self.events:
                continue
            self.events[row["dedup_key"]] = dict(row, device_id=self.device_for_mac(db, row["mac"], row["at"]))
            new += 1
        return new

    def connection_events(self, db, device_id, since, until, limit=2000):
        return [e for e in self.events.values() if e.get("device_id") == device_id and since <= e["at"] < until]

    def auth_events(self, db, device_id, since, until, limit=1000):
        return [a for a in self.auth.get(device_id, []) if since <= a["at"] < until]

    # --- incidents ----------------------------------------------------------------------------
    def open_incident(self, db, kind, subject, subject_name, started, basis, detail):
        for row in self.incident_rows:
            if (row["kind"], row["subject"], row["started"]) == (kind, subject, started) or \
                    (row["kind"], row["subject"]) == (kind, subject) and row["ended"] is None:
                return row["id"]
        row = {"id": len(self.incident_rows) + 1, "kind": kind, "subject": subject, "subject_name": subject_name,
               "started": started, "ended": None, "basis": basis, "detail": detail}
        self.incident_rows.append(row)
        return row["id"]

    def close_incident(self, db, kind, subject, ended):
        n = 0
        for row in self.incident_rows:
            if (row["kind"], row["subject"]) == (kind, subject) and row["ended"] is None:
                row["ended"] = max(ended, row["started"])
                n += 1
        return n

    def incidents(self, db, since, until=None, kinds=None, subjects=None):
        return [dict(r) for r in self.incident_rows
                if (r["ended"] is None or r["ended"] >= since) and (until is None or r["started"] <= until)
                and (kinds is None or r["kind"] in kinds) and (subjects is None or r["subject"] in subjects)]

    # --- rollups ------------------------------------------------------------------------------
    def devices(self, db, owner=None, include_revoked=False):
        return list(self.device_rows)

    def device_windows(self, db, device_ids, since=None, until=None):
        return {d: [dict(w) for w in self.windows.get(d, [])] for d in device_ids if d in self.windows}

    def device_days(self, db, device_id, since_day, until_day):
        return [r for (d, day), r in sorted(self.device_day_rows.items(), key=lambda kv: kv[0][1])
                if d == device_id and since_day <= day <= until_day]

    def ap_days(self, db, since_day, until_day, ap_macs=None):
        return [r for (mac, day), r in self.ap_day_rows.items()
                if since_day <= day <= until_day and (ap_macs is None or mac in ap_macs)]

    def upsert_device_day(self, db, row):
        self.device_day_rows[(row["device_id"], row["day"])] = dict(row)

    def upsert_ap_day(self, db, row):
        self.ap_day_rows[(row["ap_mac"], row["day"])] = dict(row)
