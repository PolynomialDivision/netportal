"""The device registry (PostgreSQL, schema.sql): every query the portal makes.

Stored per device: owner (OIDC subject), the name the owner gave it, platform, policy,
certificates (serial, validity). Not stored: keys, IP history, user agents, traffic.
"""

import datetime
import hashlib
import secrets
import uuid
from importlib import resources

import psycopg
from psycopg.rows import dict_row

UTC = datetime.timezone.utc


def connect(dsn):
    return psycopg.connect(dsn, row_factory=dict_row)


def init(db, policies):
    db.execute(resources.files("netportal").joinpath("schema.sql").read_text())
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


# --- people ---------------------------------------------------------------------------------

def upsert_person(db, sub, username, display):
    db.execute("""INSERT INTO person (sub, username, display) VALUES (%s, %s, %s)
                  ON CONFLICT (sub) DO UPDATE SET username = excluded.username,
                  display = excluded.display, last_login = now(), offboarded = NULL""", (sub, username, display))


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


def person_active(db, sub):
    """True while the person has logged in and was not offboarded since."""
    return db.execute("SELECT 1 FROM person WHERE sub = %s AND offboarded IS NULL", (sub,)).fetchone() is not None


def subjects_to_check(db):
    """Everyone the offboarding looks at: people not yet offboarded, owners of active devices
    and of live app grants (a grant creates its device only at the app's first download)."""
    return {r["sub"] for r in db.execute("""
        SELECT sub FROM person WHERE offboarded IS NULL
        UNION SELECT owner FROM device WHERE revoked IS NULL
        UNION SELECT owner FROM oauth_grant WHERE revoked IS NULL""")}


def offboard_person(db, sub):
    """The person lost access: no portal session, no app grants (devices: revoke each)."""
    db.execute("UPDATE person SET offboarded = now() WHERE sub = %s AND offboarded IS NULL", (sub,))
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
           s.updated AS last_seen
    FROM device d LEFT JOIN radius_session s ON s.device_id = d.id
"""


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


def prune(db, audit_days=90):
    """Housekeeping: old audit rows, used/expired tokens and downloads."""
    db.execute("DELETE FROM audit WHERE at < now() - make_interval(days => %s)", (audit_days,))
    db.execute("DELETE FROM download WHERE expires < now()")
    db.execute("DELETE FROM oauth_token WHERE expires < now()")


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


# --- monitoring -------------------------------------------------------------------------------

def mark_job(db, name):
    db.execute("""INSERT INTO job (name, last_success) VALUES (%s, now())
                  ON CONFLICT (name) DO UPDATE SET last_success = now()""", (name,))


DISCONNECT_FAILURES = ("timeout", "nak", "error")


def stats(db):
    """Counts for /metrics, from the registry: also what the offboarding sidecar (another
    process) did, i.e. its last success and the Disconnect results of the last hour."""
    row = db.execute("""SELECT
        (SELECT count(*) FROM device WHERE revoked IS NULL) AS active,
        (SELECT count(*) FROM device WHERE revoked IS NOT NULL) AS revoked,
        (SELECT count(*) FROM radius_cert) AS valid_certificates,
        (SELECT count(DISTINCT c.device_id) FROM credential c JOIN device d ON d.id = c.device_id
           WHERE d.revoked IS NULL AND c.retired_after IS NULL
             AND c.not_after BETWEEN now() AND now() + interval '30 days') AS expiring_30d,
        (SELECT count(DISTINCT c.device_id) FROM credential c JOIN device d ON d.id = c.device_id
           WHERE d.revoked IS NULL AND c.retired_after IS NULL AND c.not_after <= now()) AS expired,
        (SELECT extract(epoch FROM last_success) FROM job WHERE name = 'offboarding') AS offboarding_last_success
    """).fetchone()
    recent = {r["action"]: r["n"] for r in db.execute(
        """SELECT action, count(*) AS n FROM audit
           WHERE action LIKE 'disconnect:%' AND at > now() - interval '1 hour' GROUP BY action""")}
    row["disconnects_1h"] = {result: recent.get("disconnect:" + result, 0)
                             for result in ("ack", "no-session", "skipped") + DISCONNECT_FAILURES}
    return row
