"""The device registry (PostgreSQL, netportal/migrations): every query the portal and the
collector make.

Stored per device: owner (OIDC subject), the name the owner gave it, platform, policy,
certificates (serial, validity). Not stored: keys, user agents. Since telemetry v2
(docs/TELEMETRY.md): the MACs a device logged in with and when (device_mac), every RADIUS
decision (radius_auth) and accounting session (radius_acct), UniFi's client events
(connection_event), daily rollups (device_day, ap_day) and incidents; pruned after 400 days.

Conventions: times are aware datetimes, MACs normalised strings aa:bb:cc:dd:ee:ff, IPs strings.
Functions that write leave the transaction open: the caller commits (as before); migrate and
init commit themselves.
"""

import datetime
import hashlib
import logging
import re
import secrets
import uuid
from importlib import resources

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

UTC = datetime.timezone.utc
log = logging.getLogger(__name__)


def connect(dsn):
    return psycopg.connect(dsn, row_factory=dict_row)


# --- schema -----------------------------------------------------------------------------------
# netportal/migrations/NNNN_name.sql, applied once each, in order, in one transaction under an
# advisory lock (the web app, init-db and the collector may start together), recorded with their
# checksum in schema_migration; grants.sql (FreeRADIUS's rights, declarative) after every run.

MIGRATIONS = "migrations"
_MIGRATION_FILE = re.compile(r"(\d{4})_([a-z0-9_]+)\.sql")
SCHEMA_LOCK = "netportal-schema"


class MigrationError(RuntimeError):
    """The schema cannot be brought up to date safely (a changed applied migration)."""


def migration_files():
    """[(version, name, sql, sha256 hex)] of netportal/migrations, by version."""
    found = []
    for entry in resources.files("netportal").joinpath(MIGRATIONS).iterdir():
        m = _MIGRATION_FILE.fullmatch(entry.name)
        if m:
            data = entry.read_bytes()
            found.append((int(m.group(1)), m.group(2), data.decode(), hashlib.sha256(data).hexdigest()))
    found.sort()
    versions = [f[0] for f in found]
    if len(set(versions)) != len(versions):
        raise MigrationError("two migrations with the same version: %s" % versions)
    return found


def _grants_sql():
    return resources.files("netportal").joinpath(MIGRATIONS, "grants.sql").read_text()


def migrate(db):
    """Bring the schema up to date and apply the radius role's grants; commits.

    Returns {"applied": [versions applied now], "version": highest applied, "radius_role": bool}.
    Refuses (MigrationError, nothing changed) when an applied migration's file was changed
    since. Versions in the database that this code does not know (a newer release ran) are
    left alone: migrations only add, so this release still works on that schema. A missing
    radius role is a warning (and stats()["radius_role"] for /metrics), not an error."""
    files = migration_files()
    try:
        db.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (SCHEMA_LOCK,))
        db.execute("""CREATE TABLE IF NOT EXISTS schema_migration (
                          version  integer PRIMARY KEY,
                          name     text NOT NULL,
                          checksum text NOT NULL,
                          applied  timestamptz NOT NULL DEFAULT now())""")
        applied = {r["version"]: r for r in db.execute("SELECT version, name, checksum FROM schema_migration")}
        done = []
        for version, name, sql, checksum in files:
            if version in applied:
                if applied[version]["checksum"] != checksum:
                    raise MigrationError("migration %04d_%s.sql was changed after it was applied (checksum %s, "
                                         "recorded %s): put the change into a new migration"
                                         % (version, name, checksum[:12], applied[version]["checksum"][:12]))
                continue
            log.info("applying migration %04d_%s", version, name)
            db.execute(sql)
            db.execute("INSERT INTO schema_migration (version, name, checksum) VALUES (%s, %s, %s)",
                       (version, name, checksum))
            done.append(version)
        unknown = sorted(set(applied) - {f[0] for f in files})
        if unknown:
            log.info("the schema has migrations this release does not know (a newer one ran): %s", unknown)
        db.execute(_grants_sql())
        role = db.execute("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'radius') AS ok").fetchone()["ok"]
        version = db.execute("SELECT max(version) AS v FROM schema_migration").fetchone()["v"]
        db.commit()
    except BaseException:
        db.rollback()
        raise
    if not role:
        log.warning("the database role radius does not exist: FreeRADIUS cannot read the registry "
                    "(the stack creates it: house-infra stacks/netaccess files/init-radius-role.sh)")
    return {"applied": done, "version": version, "radius_role": role}


def init(db, policies):
    """The schema (migrate) and the seeds: the policies with their VLANs, the offboarding job."""
    migrate(db)
    for policy in policies:
        db.execute("""INSERT INTO policy (name, vlan) VALUES (%s, %s)
                      ON CONFLICT (name) DO UPDATE SET vlan = excluded.vlan""", (policy.name, policy.vlan))
    # A fresh registry counts as reconciled now: an offboarding that never succeeds alerts an
    # hour later instead of never.
    db.execute("INSERT INTO job (name, last_success) VALUES ('offboarding', now()) ON CONFLICT (name) DO NOTHING")
    db.commit()


def now():
    return datetime.datetime.now(UTC)


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


# --- MACs ---------------------------------------------------------------------------------------

_SEPARATED_MAC = re.compile(r"[0-9a-f]{2}([-:])[0-9a-f]{2}(?:\1[0-9a-f]{2}){4}")
_BARE_MAC = re.compile(r"[0-9a-f]{12}")
_WHITESPACE = " \t\n\r\f\v"


def normalise_mac(raw):
    """aa:bb:cc:dd:ee:ff from what the AP sends as Calling-Station-Id (AA-BB-CC-DD-EE-FF), the
    colon form or 12 bare hex digits, any case, surrounding whitespace ignored; None for anything
    else (mixed separators, dots, junk, not a string). The twin of SQL np_mac (0002_telemetry.sql;
    tests/test_registry_db.py checks both on the same cases)."""
    if not isinstance(raw, str):
        return None
    mac = raw.strip(_WHITESPACE).lower()
    if _BARE_MAC.fullmatch(mac):
        return ":".join(mac[i:i + 2] for i in range(0, 12, 2))
    if _SEPARATED_MAC.fullmatch(mac):
        return mac.replace("-", ":")
    return None


def is_randomized(mac):
    """The locally administered bit (what phones set for a private address)."""
    return bool(int(mac[:2], 16) & 0x02)


# A device's window on a MAC: [first_seen, window_end]. window_end = last_seen + WINDOW_GRACE
# (data until the device leaves), for the device's current window (its MAC with the newest
# last_seen, device active) last_seen + CURRENT_WINDOW but not beyond now: it logs in again at
# least every 12 h (Session-Timeout) and accounting moves last_seen meanwhile. The rule lives in
# SQL (view device_mac_window, 0002_telemetry.sql); these constants describe it for callers, and
# every function here reads window_end from the view.
WINDOW_GRACE = datetime.timedelta(minutes=15)
CURRENT_WINDOW = datetime.timedelta(hours=12, minutes=15)


# --- people ---------------------------------------------------------------------------------

def upsert_person(db, sub, username, display, admin=False):
    db.execute("""INSERT INTO person (sub, username, display, admin) VALUES (%s, %s, %s, %s)
                  ON CONFLICT (sub) DO UPDATE SET username = excluded.username, display = excluded.display,
                  admin = excluded.admin, last_login = now(), offboarded = NULL""", (sub, username, display, admin))


def set_admin(db, sub, admin):
    """Whether the person is in the admin groups now (the offboarding round, from the directory)."""
    db.execute("UPDATE person SET admin = %s WHERE sub = %s AND admin IS DISTINCT FROM %s", (admin, sub, admin))


def person_policy(db, sub):
    row = db.execute("SELECT policy FROM person WHERE sub = %s", (sub,)).fetchone()
    return row["policy"] if row else None


def set_policy(db, sub, policy):
    """The person's policy now; their active devices that had another one move with it.
    Returns [(device id, latest RADIUS session or None)] of the moved devices: a Disconnect
    makes each authenticate again, into the new VLAN."""
    db.execute("UPDATE person SET policy = %s WHERE sub = %s AND policy IS DISTINCT FROM %s", (policy, sub, policy))
    moved = [r["id"] for r in db.execute("""UPDATE device SET policy = %s
                                            WHERE owner = %s AND revoked IS NULL AND policy <> %s
                                            RETURNING id""", (policy, sub, policy))]
    return [(device_id, db.execute("SELECT nas_ip, calling_station, user_name FROM radius_session WHERE device_id = %s",
                                   (device_id,)).fetchone()) for device_id in moved]


def people(db):
    return {r["sub"]: r for r in db.execute("SELECT sub, username, display FROM person")}


def person_state(db, sub):
    """{"admin": bool} while the person is active (logged in, not offboarded since), else None.
    Asked on every request that needs a login: rights come from here, not from the cookie."""
    return db.execute("SELECT admin FROM person WHERE sub = %s AND offboarded IS NULL", (sub,)).fetchone()


def subjects_to_check(db):
    """Everyone the offboarding looks at: people not yet offboarded, owners of active devices
    and of live app grants (a grant creates its device only at the app's first download)."""
    return {r["sub"] for r in db.execute("""
        SELECT sub FROM person WHERE offboarded IS NULL
        UNION SELECT owner FROM device WHERE revoked IS NULL
        UNION SELECT owner FROM oauth_grant WHERE revoked IS NULL""")}


def offboard_person(db, sub):
    """The person lost access: no portal session, no app grants (devices: revoke each)."""
    db.execute("UPDATE person SET offboarded = now(), admin = false WHERE sub = %s AND offboarded IS NULL", (sub,))
    db.execute("UPDATE oauth_grant SET revoked = now() WHERE owner = %s AND revoked IS NULL", (sub,))


# --- devices ----------------------------------------------------------------------------------

def create_device(db, owner, name, platform, policy):
    device_id = uuid.uuid4()
    db.execute("INSERT INTO device (id, owner, name, kind, platform, policy) VALUES (%s, %s, %s, 'cert', %s, %s)",
               (device_id, owner, name, platform, policy))
    return device_id


DEVICE_LIST = """
    SELECT d.id, d.owner, d.name, d.platform, d.policy, d.created, d.revoked,
           (SELECT max(c.not_after) FROM credential c WHERE c.device_id = d.id
              AND (c.retired_after IS NULL OR c.retired_after > now())) AS expires,
           (SELECT count(*) FROM credential c WHERE c.device_id = d.id) AS certificates,
           s.updated AS last_seen, s.calling_station, s.first_seen
    FROM device d LEFT JOIN radius_session s ON s.device_id = d.id
"""
# last_seen: the device's latest RADIUS login; calling_station: its MAC as the AP sent it
# (normalise_mac); first_seen: its first login with that MAC. One row per device: the table keeps
# only the latest session. The MAC history is device_windows (device_mac).


def devices(db, owner=None, include_revoked=False):
    where, args = [], []
    if owner is not None:
        where.append("d.owner = %s")
        args.append(owner)
    if not include_revoked:
        where.append("d.revoked IS NULL")
    sql = DEVICE_LIST + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY d.created DESC"
    return list(db.execute(sql, args))


def device(db, device_id, owner=None):
    sql = DEVICE_LIST + " WHERE d.id = %s" + (" AND d.owner = %s" if owner is not None else "")
    args = [device_id] + ([owner] if owner is not None else [])
    return db.execute(sql, args).fetchone()


def mac_claims(db, macs):
    """{mac: {owner sub}}: whose active devices last logged in with one of these MACs
    (normalised aa:bb:cc:dd:ee:ff). The MAC is what the device sends: a device can claim another's.
    Compared by hex digits, whatever separators the AP used. Legacy (v1, latest session only):
    the web app uses device_windows / window_conflicts now; kept for the integration test and
    admin scripts, remove when nothing needs it."""
    wanted = sorted({m.replace(":", "") for m in macs if m})
    if not wanted:
        return {}
    claims = {}
    for r in db.execute("""SELECT regexp_replace(lower(s.calling_station), '[^0-9a-f]', '', 'g') AS hex, d.owner
                           FROM radius_session s JOIN device d ON d.id = s.device_id
                           WHERE d.revoked IS NULL
                             AND regexp_replace(lower(s.calling_station), '[^0-9a-f]', '', 'g') = ANY(%s)""",
                        (wanted,)):
        mac = ":".join(r["hex"][i:i + 2] for i in range(0, 12, 2))
        claims.setdefault(mac, set()).add(r["owner"])
    return claims


def rename(db, device_id, name):
    db.execute("UPDATE device SET name = %s WHERE id = %s AND revoked IS NULL", (name, device_id))


def revoke(db, device_id, actor, reason="revoke"):
    """Revoke a device; returns its latest RADIUS session (for the Disconnect-Request) or None."""
    db.execute("UPDATE device SET revoked = now() WHERE id = %s AND revoked IS NULL", (device_id,))
    db.execute("UPDATE oauth_grant SET revoked = now() WHERE device_id = %s AND revoked IS NULL", (device_id,))
    audit(db, actor, reason, device_id)
    return db.execute("SELECT nas_ip, calling_station, user_name FROM radius_session WHERE device_id = %s",
                      (device_id,)).fetchone()


def add_credential(db, device_id, serial_hex, not_after, overlap_days):
    """A new certificate for the device; earlier ones end after the renewal overlap."""
    db.execute("""UPDATE credential SET retired_after = now() + make_interval(days => %s)
                  WHERE device_id = %s AND retired_after IS NULL""", (overlap_days, device_id))
    db.execute("INSERT INTO credential (serial, device_id, not_after) VALUES (%s, %s, %s)",
               (serial_hex.lower(), device_id, not_after))


def audit(db, actor, action, device_id=None):
    db.execute("INSERT INTO audit (actor, action, device_id) VALUES (%s, %s, %s)", (actor, action, device_id))


# --- retention --------------------------------------------------------------------------------

RETENTION_DAYS = 400      # radius_auth, radius_acct, connection_event, device_mac of revoked devices
AUDIT_DAYS = 90
# Rows per DELETE: every statement stays far inside the collector's statement_timeout (120 s)
# and holds its row locks briefly, also when a flood of rejects left millions of old rows.
PRUNE_BATCH = 10000


def _prune_statements(now, audit_days):
    """{table: (the rows to delete as a SELECT of their ctid, args)}."""
    cutoff = now - datetime.timedelta(days=RETENTION_DAYS)
    return {
        "radius_auth": ("SELECT ctid FROM radius_auth WHERE at < %s", (cutoff,)),
        "radius_acct": ("SELECT ctid FROM radius_acct WHERE updated < %s", (cutoff,)),
        "connection_event": ("SELECT ctid FROM connection_event WHERE at < %s", (cutoff,)),
        "device_mac": ("""SELECT m.ctid FROM device_mac m JOIN device d ON d.id = m.device_id
                          WHERE d.revoked IS NOT NULL AND m.last_seen < %s""", (cutoff,)),
        "audit": ("SELECT ctid FROM audit WHERE at < %s", (now - datetime.timedelta(days=audit_days),)),
        "download": ("SELECT ctid FROM download WHERE expires < %s", (now,)),
        "oauth_token": ("SELECT ctid FROM oauth_token WHERE expires < %s", (now,)),
    }


def prune(db, now=None, audit_days=AUDIT_DAYS, batch=PRUNE_BATCH, commit=None):
    """Housekeeping (docs/TELEMETRY.md, retention): RADIUS decisions, accounting sessions and
    UniFi events older than 400 days, the MAC identities of revoked devices 400 days after their
    last use, audit rows after 90 days, used or expired tokens and downloads. Rollups and
    incidents are kept. Every table in DELETEs of at most `batch` rows, repeated until one deletes
    fewer; commit (a callable, the collector's db.commit) runs after each, so no statement or
    transaction grows with the backlog. Without it the caller commits. Returns {table: rows
    deleted}."""
    now = now or datetime.datetime.now(UTC)
    deleted = {}
    for table, (select, args) in _prune_statements(now, audit_days).items():
        deleted[table] = 0
        while True:
            n = db.execute("DELETE FROM %s WHERE ctid = ANY(ARRAY(%s LIMIT %%s))" % (table, select),
                           args + (batch,)).rowcount
            deleted[table] += n
            if commit is not None:
                commit()
            if n < batch:
                break
    return deleted


# --- one-time downloads -----------------------------------------------------------------------

def create_download(db, device_id, fmt, minutes=10):
    token = secrets.token_urlsafe(32)
    db.execute("INSERT INTO download (token, device_id, format, expires) VALUES (%s, %s, %s, now() + make_interval(mins => %s))",
               (token_hash(token), device_id, fmt, minutes))
    return token


def consume_download(db, token, owner):
    """The download for this token and owner, once: (device row, format) or None. Someone
    else's token is left alone (not used up)."""
    row = db.execute("""DELETE FROM download dl USING device d
                        WHERE dl.token = %s AND dl.expires > now() AND d.id = dl.device_id AND d.owner = %s
                        RETURNING dl.device_id, dl.format""", (token_hash(token), owner)).fetchone()
    if not row:
        return None
    dev = device(db, row["device_id"])
    if not dev or dev["revoked"]:
        return None
    return dev, row["format"]


# --- OAuth (Let's Wi-Fi) ----------------------------------------------------------------------

def create_grant(db, owner, client_id, device_name):
    grant_id = uuid.uuid4()
    db.execute("INSERT INTO oauth_grant (id, owner, client_id, device_name) VALUES (%s, %s, %s, %s)",
               (grant_id, owner, client_id, device_name))
    return grant_id


def issue_token(db, grant_id, kind, seconds, pkce_challenge=None, redirect_uri=None):
    token = secrets.token_urlsafe(32)
    db.execute("""INSERT INTO oauth_token (hash, grant_id, kind, expires, pkce_challenge, redirect_uri)
                  VALUES (%s, %s, %s, now() + make_interval(secs => %s), %s, %s)""",
               (token_hash(token), grant_id, kind, seconds, pkce_challenge, redirect_uri))
    return token


def use_token(db, token, kind, single_use):
    """The grant row for a valid token of this kind (marked used if single_use), or None.
    A replayed single-use token revokes its whole grant (OAuth 2.1 code/refresh replay).
    Tokens of an offboarded person stop working at once."""
    h = token_hash(token)
    row = db.execute("""SELECT t.grant_id, t.used, t.expires > now() AS live, t.pkce_challenge, t.redirect_uri,
                               g.owner, g.client_id, g.device_name, g.device_id, g.revoked,
                               (p.sub IS NOT NULL AND p.offboarded IS NULL) AS owner_active
                        FROM oauth_token t JOIN oauth_grant g ON g.id = t.grant_id
                        LEFT JOIN person p ON p.sub = g.owner
                        WHERE t.hash = %s AND t.kind = %s""", (h, kind)).fetchone()
    if not row or not row["live"] or row["revoked"] or not row["owner_active"]:
        return None
    if single_use:
        if row["used"]:
            db.execute("UPDATE oauth_grant SET revoked = now() WHERE id = %s", (row["grant_id"],))
            db.commit()
            return None
        db.execute("UPDATE oauth_token SET used = now() WHERE hash = %s", (h,))
    return row


def bind_grant(db, grant_id, device_id):
    db.execute("UPDATE oauth_grant SET device_id = %s WHERE id = %s", (device_id, grant_id))


# --- MAC windows (device_mac) -----------------------------------------------------------------
# Data of a MAC belongs to a device inside the device's window on it; windows of different
# owners that overlap are a conflict (docs/TELEMETRY.md, principle 2).

def _ids(device_ids):
    return [str(d) for d in device_ids]


def _overlap_args(since, until):
    """SQL bounds for "a window [first_seen, window_end] overlaps [since, until]"."""
    return (since or datetime.datetime(1970, 1, 1, tzinfo=UTC), until or datetime.datetime(9999, 1, 1, tzinfo=UTC))


def device_windows(db, device_ids, since=None, until=None):
    """{device_id: [{"mac", "first_seen", "last_seen", "window_end", "current", "randomized",
    "auth_count"}]} of the given devices whose window overlaps [since, until] (None: open),
    oldest first. last_seen is the raw value; window_end the end by the window rule (above), the
    one device_for_mac and window_conflicts use. Every requested id is a key (empty list)."""
    result = {d: [] for d in _ids(device_ids)}
    if not result:
        return result
    lo, hi = _overlap_args(since, until)
    for r in db.execute("""SELECT device_id::text AS device_id, mac::text AS mac, first_seen, last_seen,
                                  window_end, current, randomized, auth_count
                           FROM device_mac_window
                           WHERE device_id = ANY(%s::uuid[]) AND first_seen <= %s AND window_end >= %s
                           ORDER BY first_seen, mac""",
                        (list(result), hi, lo)):
        result[r.pop("device_id")].append(r)
    return result


def window_conflicts(db, device_ids, since=None, until=None):
    """{device_id: [{"mac", "other_owners", "from", "to"}]}: where devices of other owners have
    overlapping windows on one of this device's MACs; from/to span the overlaps (clipped to
    [since, until] when given). Devices without a conflict are not keys. Revoked devices count
    (as in np_device_for_mac and the rollups): what a MAC did while two owners claimed it stays
    nobody's after one of the devices is revoked. A revoked device's window ends at last_seen +
    WINDOW_GRACE (it is never current), so it cannot make a conflict now beyond that."""
    ids = _ids(device_ids)
    if not ids:
        return {}
    lo, hi = _overlap_args(since, until)
    result = {}
    for r in db.execute("""
            SELECT m.device_id::text AS device_id, m.mac::text AS mac, count(DISTINCT od.owner) AS other_owners,
                   greatest(min(greatest(m.first_seen, o.first_seen)), %(lo)s) AS "from",
                   least(max(least(m.window_end, o.window_end)), %(hi)s) AS "to"
            FROM device_mac_window m
            JOIN device d ON d.id = m.device_id
            JOIN device_mac_window o ON o.mac = m.mac AND o.device_id <> m.device_id
            JOIN device od ON od.id = o.device_id AND od.owner <> d.owner
            WHERE m.device_id = ANY(%(ids)s::uuid[])
              AND o.first_seen <= m.window_end AND m.first_seen <= o.window_end
              AND greatest(m.first_seen, o.first_seen) <= %(hi)s
              AND least(m.window_end, o.window_end) >= %(lo)s
            GROUP BY m.device_id, m.mac ORDER BY 1, 4""",
            {"ids": ids, "lo": lo, "hi": hi}):
        result.setdefault(r.pop("device_id"), []).append(r)
    return result


def device_for_mac(db, mac, at):
    """The device id (str) whose window on this MAC contains `at`; None when there is none or
    devices of more than one owner claim it then (SQL np_device_for_mac, the same rule
    FreeRADIUS's accounting uses)."""
    mac = normalise_mac(mac)
    if not mac:
        return None
    row = db.execute("SELECT np_device_for_mac(%s::macaddr, %s)::text AS id", (mac, at)).fetchone()
    return row["id"]


# --- RADIUS: decisions and accounting ---------------------------------------------------------
# Repeated rejects are one radius_auth row (SQL radius_reject): the same MAC, reason, serial, NAS,
# BSSID and SSID within REJECT_REPEAT of the row's latest try add to its count and last_at; a row
# spans at most REJECT_SPAN. These constants describe the SQL; reads count with `count`.
REJECT_REPEAT = datetime.timedelta(seconds=60)
REJECT_SPAN = datetime.timedelta(hours=1)


def _limit(limit, cap=10000):
    return max(1, min(int(limit), cap))


def auth_events(db, device_id, since, until, limit=1000):
    """The device's RADIUS decisions in [since, until] (by their first time `at`), oldest first
    (the newest `limit`): [{"at", "result", "reason", "mac", "bssid", "ssid", "nas_ip", "match",
    "count", "last_at"}]. match "device": logged with the device (its logins; rejects of its
    certificate); "mac": a reject without a known certificate from one of its MACs inside its
    window there (no_cert, not_eap, ...), whoever else claimed the MAC then (callers that show it
    to a resident withhold the conflicts: timeline.restrict). count: the decisions of the row
    (repeated rejects, REJECT_REPEAT), the last at last_at (None: one)."""
    rows = list(db.execute("""
        SELECT * FROM (
            SELECT a.id, a.at, a.result, a.reason, a.mac::text AS mac, a.bssid::text AS bssid, a.ssid,
                   host(a.nas_ip) AS nas_ip, 'device' AS match, a.count, a.last_at
            FROM radius_auth a WHERE a.device_id = %(dev)s AND a.at BETWEEN %(since)s AND %(until)s
            UNION ALL
            SELECT a.id, a.at, a.result, a.reason, a.mac::text, a.bssid::text, a.ssid, host(a.nas_ip), 'mac',
                   a.count, a.last_at
            FROM radius_auth a
            WHERE a.device_id IS NULL AND a.result = 'reject' AND a.at BETWEEN %(since)s AND %(until)s
              AND EXISTS (SELECT 1 FROM device_mac_window m WHERE m.device_id = %(dev)s AND m.mac = a.mac
                          AND a.at BETWEEN m.first_seen AND m.window_end)
        ) e ORDER BY at DESC, id DESC LIMIT %(limit)s""",
        {"dev": str(device_id), "since": since, "until": until, "limit": _limit(limit)}))
    rows.reverse()
    for r in rows:
        del r["id"]
    return rows


def auth_failures(db, since, until=None, limit=500):
    """Rejects in [since, until] (by their first time `at`), newest first (admin view): [{"at",
    "reason", "serial", "device_id", "owner", "owner_name", "device_name", "mac", "bssid", "ssid",
    "nas_ip", "count", "last_at"}]; device and owner only when the certificate is ours (revoked,
    expired, retired). count: the tries the row stands for (repeats, REJECT_REPEAT), the last at
    last_at (None: one)."""
    return list(db.execute("""
        SELECT a.at, a.reason, a.serial, a.device_id::text AS device_id, d.owner, p.display AS owner_name,
               d.name AS device_name, a.mac::text AS mac, a.bssid::text AS bssid, a.ssid, host(a.nas_ip) AS nas_ip,
               a.count, a.last_at
        FROM radius_auth a
        LEFT JOIN device d ON d.id = a.device_id
        LEFT JOIN person p ON p.sub = d.owner
        WHERE a.result = 'reject' AND a.at >= %s AND a.at <= %s
        ORDER BY a.at DESC, a.id DESC LIMIT %s""",
        (since, until or now(), _limit(limit))))


ACCT_COLUMNS = ("nas_ip", "acct_session_id", "link", "mac", "bssid", "ssid", "framed_ip", "started", "updated",
                "stopped", "session_time_s", "input_octets", "output_octets", "terminate_cause")


def acct_sessions(db, device_id, since, until, limit=1000):
    """The device's accounting sessions overlapping [since, until], oldest first (the newest
    `limit`): [{"nas_ip", "acct_session_id", "link", "mac", "bssid", "ssid", "framed_ip",
    "started", "updated", "stopped", "session_time_s", "input_octets", "output_octets",
    "terminate_cause"}]. stopped None: open (or its Stop never came: see updated)."""
    rows = list(db.execute("""
        SELECT host(nas_ip) AS nas_ip, acct_session_id, link, mac::text AS mac, bssid::text AS bssid, ssid,
               host(framed_ip) AS framed_ip, started, updated, stopped, session_time_s, input_octets,
               output_octets, terminate_cause
        FROM radius_acct
        WHERE device_id = %s AND coalesce(started, updated) <= %s AND coalesce(stopped, updated) >= %s
        ORDER BY coalesce(started, updated) DESC LIMIT %s""", (str(device_id), until, since, _limit(limit))))
    rows.reverse()
    return rows


# --- UniFi connection events -------------------------------------------------------------------

EVENT_COLUMNS = ("at", "kind", "source", "mac", "ap_mac", "ap_name", "from_ap_mac", "from_ap_name", "ssid", "radio",
                 "channel", "rssi", "duration_s", "rx_bytes", "tx_bytes")
EVENT_KINDS = ("connected", "disconnected", "roamed", "other")


def connection_events(db, device_id, since, until, limit=2000):
    """The device's connection events in [since, until], oldest first (the newest `limit`):
    [{"at", "kind", "source", "mac", "ap_mac", "ap_name", "from_ap_mac", "from_ap_name", "ssid",
    "radio", "channel", "rssi", "duration_s", "rx_bytes", "tx_bytes", "detail"}]."""
    rows = list(db.execute("""
        SELECT id, at, kind, source, mac::text AS mac, ap_mac::text AS ap_mac, ap_name,
               from_ap_mac::text AS from_ap_mac, from_ap_name, ssid, radio, channel, rssi, duration_s,
               rx_bytes, tx_bytes, detail
        FROM connection_event WHERE device_id = %s AND at BETWEEN %s AND %s
        ORDER BY at DESC, id DESC LIMIT %s""", (str(device_id), since, until, _limit(limit))))
    rows.reverse()
    for r in rows:
        del r["id"]
    return rows


def insert_connection_events(db, rows):
    """Store connection events idempotently: rows as connection_events returns them plus
    "dedup_key" (required, unique per source event) and optionally "detail" (dict) and
    "device_id". Without a device_id the device is resolved by its MAC window at the event's time
    (device_for_mac); a resolved event extends that window (device_mac.last_seen). Rows without a
    valid MAC, time or dedup_key are skipped; an unknown kind is stored as "other"; a repeated
    dedup_key is ignored. Returns the number of rows inserted; the caller commits."""
    inserted = 0
    for row in rows:
        mac, at, key = normalise_mac(row.get("mac")), row.get("at"), row.get("dedup_key")
        if not mac or not isinstance(at, datetime.datetime) or not key:
            continue
        values = {c: row.get(c) for c in EVENT_COLUMNS}
        values.update(mac=mac, kind=row.get("kind") if row.get("kind") in EVENT_KINDS else "other",
                      source=row.get("source") or "unifi_syslog",
                      ap_mac=normalise_mac(row.get("ap_mac")), from_ap_mac=normalise_mac(row.get("from_ap_mac")),
                      detail=Jsonb(row.get("detail") or {}), dedup_key=str(key)[:512])
        device_id = row.get("device_id") or device_for_mac(db, mac, at)
        values["device_id"] = str(device_id) if device_id else None
        cols = list(values)
        cur = db.execute("INSERT INTO connection_event (%s) VALUES (%s) ON CONFLICT (dedup_key) DO NOTHING"
                         % (", ".join(cols), ", ".join("%%(%s)s" % c for c in cols)), values)
        if cur.rowcount:
            inserted += 1
            if device_id:
                db.execute("""UPDATE device_mac SET last_seen = greatest(last_seen, %s)
                              WHERE device_id = %s AND mac = %s::macaddr""", (at, values["device_id"], mac))
    return inserted


# --- rollups ----------------------------------------------------------------------------------

DEVICE_DAY_COLUMNS = ("online_s", "stale_s", "signal_avg_dbm", "signal_p10_dbm", "snr_avg_db", "health_avg",
                      "health_min", "retry_ratio_avg", "rx_bytes", "tx_bytes", "link_rx_avg_bps", "roams",
                      "reconnects", "disconnects", "aps", "bands", "macs", "auth_ok", "auth_failed")
AP_DAY_COLUMNS = ("ap_name", "clients_avg", "clients_max", "channel_util_avg", "weak_client_share", "restarts",
                  "down_s")
_JSON_COLUMNS = {"aps", "bands", "channel_util_avg", "detail", "cursor"}


def _upsert_day(db, table, keys, columns, row):
    """INSERT ... ON CONFLICT (keys) DO UPDATE for a rollup row: the given columns (others keep
    their value on update), computed = now(). Unknown keys in the row are refused."""
    unknown = set(row) - set(keys) - set(columns) - {"computed"}
    if unknown:
        raise ValueError("%s: unknown columns %s" % (table, sorted(unknown)))
    values = {c: (Jsonb(row[c]) if c in _JSON_COLUMNS and row[c] is not None else row[c])
              for c in keys + tuple(c for c in columns if c in row)}
    cols = list(values)
    sets = ", ".join("%s = EXCLUDED.%s" % (c, c) for c in cols if c not in keys)
    db.execute("INSERT INTO %s (%s) VALUES (%s) ON CONFLICT (%s) DO UPDATE SET %scomputed = now()"
               % (table, ", ".join(cols), ", ".join("%%(%s)s" % c for c in cols), ", ".join(keys),
                  sets + ", " if sets else ""), values)


def upsert_device_day(db, row):
    """Store one device_day row ({"device_id", "day"} + any DEVICE_DAY_COLUMNS); idempotent."""
    row = dict(row, device_id=str(row["device_id"]))
    _upsert_day(db, "device_day", ("device_id", "day"), DEVICE_DAY_COLUMNS, row)


def upsert_ap_day(db, row):
    """Store one ap_day row ({"ap_mac", "day"} + any AP_DAY_COLUMNS); idempotent."""
    mac = normalise_mac(row.get("ap_mac"))
    if not mac:
        raise ValueError("ap_day: invalid ap_mac %r" % (row.get("ap_mac"),))
    _upsert_day(db, "ap_day", ("ap_mac", "day"), AP_DAY_COLUMNS, dict(row, ap_mac=mac))


def device_days(db, device_id, since_day, until_day):
    """The device's device_day rows for since_day..until_day (dates, inclusive), by day."""
    return list(db.execute("""SELECT device_id::text AS device_id, day, %s, computed FROM device_day
                              WHERE device_id = %%s AND day BETWEEN %%s AND %%s ORDER BY day"""
                           % ", ".join(DEVICE_DAY_COLUMNS), (str(device_id), since_day, until_day)))


def ap_days(db, since_day, until_day, ap_macs=None):
    """ap_day rows for since_day..until_day (inclusive), of the given AP MACs (None: all), by
    day and AP."""
    macs = None if ap_macs is None else [m for m in map(normalise_mac, ap_macs) if m]
    return list(db.execute("""SELECT ap_mac::text AS ap_mac, day, %s, computed FROM ap_day
                              WHERE day BETWEEN %%s AND %%s AND (%%s::macaddr[] IS NULL OR ap_mac = ANY(%%s::macaddr[]))
                              ORDER BY day, ap_mac""" % ", ".join(AP_DAY_COLUMNS),
                           (since_day, until_day, macs, macs)))


# --- incidents --------------------------------------------------------------------------------

def incidents(db, since, until=None, kinds=None, subjects=None):
    """Incidents overlapping [since, until] (until None: no upper bound; open ones overlap
    everything after their start, also when they started before `since`), by start:
    [{"id", "kind", "subject", "subject_name", "started", "ended", "basis", "detail"}]."""
    return list(db.execute("""
        SELECT id, kind, subject, subject_name, started, ended, basis, detail FROM incident
        WHERE (%s::timestamptz IS NULL OR started <= %s) AND (ended IS NULL OR ended >= %s)
          AND (%s::text[] IS NULL OR kind = ANY(%s::text[])) AND (%s::text[] IS NULL OR subject = ANY(%s::text[]))
        ORDER BY started, id""",
        (until, until, since, kinds and list(kinds), kinds and list(kinds),
         subjects and list(subjects), subjects and list(subjects))))


def open_incident(db, kind, subject, subject_name, started, basis, detail=None):
    """Open an incident (or find it) and return its id. Idempotent: an open incident of the same
    kind and subject is returned as it is (one open per kind+subject, index incident_open), as
    is one with the same start (closed or not); subject_name and detail of a found one are
    refreshed."""
    args = {"kind": kind, "subject": subject or "", "name": subject_name, "started": started, "basis": basis,
            "detail": Jsonb(detail or {})}
    for _ in range(2):    # a concurrent opener wins the race: then find its row
        row = db.execute("""SELECT id FROM incident WHERE kind = %(kind)s AND subject = %(subject)s
                              AND (ended IS NULL OR started = %(started)s)
                            ORDER BY (ended IS NULL) DESC LIMIT 1""", args).fetchone()
        if row:
            db.execute("""UPDATE incident SET subject_name = coalesce(%(name)s, subject_name),
                                 detail = CASE WHEN %(detail)s = '{}'::jsonb THEN detail ELSE %(detail)s END
                          WHERE id = %(id)s""", dict(args, id=row["id"]))
            return row["id"]
        row = db.execute("""INSERT INTO incident (kind, subject, subject_name, started, basis, detail)
                            VALUES (%(kind)s, %(subject)s, %(name)s, %(started)s, %(basis)s, %(detail)s)
                            ON CONFLICT DO NOTHING RETURNING id""", args).fetchone()
        if row:
            return row["id"]
    raise RuntimeError("incident %s/%s: neither found nor inserted" % (kind, subject))


def close_incident(db, kind, subject, ended):
    """End the open incident of this kind and subject (not before its start); returns the
    number of incidents closed (0 or 1)."""
    return db.execute("""UPDATE incident SET ended = greatest(started, %s)
                         WHERE kind = %s AND subject = %s AND ended IS NULL""", (ended, kind, subject or "")).rowcount


# --- monitoring -------------------------------------------------------------------------------

def mark_job(db, name):
    db.execute("""INSERT INTO job (name, last_success) VALUES (%s, now())
                  ON CONFLICT (name) DO UPDATE SET last_success = now()""", (name,))


def job_begin(db, name):
    """A job run starts: last_attempt = now (the row is created for a new job)."""
    db.execute("""INSERT INTO job (name, last_attempt) VALUES (%s, now())
                  ON CONFLICT (name) DO UPDATE SET last_attempt = now()""", (name,))


def job_end(db, name, ok, error=None, duration_s=None, cursor=None):
    """A job run ended: ok sets last_success and clears last_error, otherwise last_error (cut
    to 2000 characters) is set; duration_s and cursor (a JSON-able dict, replacing the stored
    one) when given."""
    db.execute("""INSERT INTO job (name, last_attempt) VALUES (%(name)s, now()) ON CONFLICT (name) DO NOTHING""",
               {"name": name})
    db.execute("""UPDATE job SET last_success = CASE WHEN %(ok)s THEN now() ELSE last_success END,
                                 last_error = CASE WHEN %(ok)s THEN NULL ELSE %(error)s END,
                                 duration_s = coalesce(%(duration)s, duration_s),
                                 cursor = coalesce(%(cursor)s, cursor)
                  WHERE name = %(name)s""",
               {"name": name, "ok": bool(ok), "error": None if ok else str(error or "failed")[:2000],
                "duration": duration_s, "cursor": None if cursor is None else Jsonb(cursor)})


def job_status(db):
    """[{"name", "last_success", "last_attempt", "last_error", "duration_s", "cursor"}] by name."""
    return list(db.execute("""SELECT name, last_success, last_attempt, last_error, duration_s, cursor
                              FROM job ORDER BY name"""))


DISCONNECT_FAILURES = ("timeout", "nak", "error")


def stats(db):
    """Counts for /metrics, from the registry: also what the offboarding sidecar (another
    process) did, i.e. its last success and the Disconnect results of the last hour; whether the
    radius role exists and the schema version."""
    row = db.execute("""SELECT
        (SELECT count(*) FROM device WHERE revoked IS NULL) AS active,
        (SELECT count(*) FROM device WHERE revoked IS NOT NULL) AS revoked,
        (SELECT count(*) FROM radius_cert) AS valid_certificates,
        (SELECT count(DISTINCT c.device_id) FROM credential c JOIN device d ON d.id = c.device_id
           WHERE d.revoked IS NULL AND c.retired_after IS NULL
             AND c.not_after BETWEEN now() AND now() + interval '30 days') AS expiring_30d,
        (SELECT count(DISTINCT c.device_id) FROM credential c JOIN device d ON d.id = c.device_id
           WHERE d.revoked IS NULL AND c.retired_after IS NULL AND c.not_after <= now()) AS expired,
        (SELECT extract(epoch FROM last_success) FROM job WHERE name = 'offboarding') AS offboarding_last_success,
        EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'radius') AS radius_role,
        (SELECT max(version) FROM schema_migration) AS schema_version
    """).fetchone()
    recent = {r["action"]: r["n"] for r in db.execute(
        """SELECT action, count(*) AS n FROM audit
           WHERE action LIKE 'disconnect:%' AND at > now() - interval '1 hour' GROUP BY action""")}
    row["disconnects_1h"] = {result: recent.get("disconnect:" + result, 0)
                             for result in ("ack", "no-session", "skipped") + DISCONNECT_FAILURES}
    return row
