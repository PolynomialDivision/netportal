"""The registry as the contract tests see it: a few adapter functions for setup and
inspection, so the tests never touch the schema directly (migrations/; checked against a
migrated database by selftest_registry_adapter.py, no portal needed).

Prefer observing behaviour over HTTP or RADIUS; use these only where nothing outside shows the
state (an expired token, a grant revoked by a replay, an audit trail, a credential's overlap).

Values returned are plain: bool, str, int seconds, datetimes (aware) only where stated.
"""

import hashlib
import secrets

import psycopg
from psycopg.conninfo import conninfo_to_dict, make_conninfo
from psycopg.rows import dict_row


def _hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def serial_hex(cert):
    h = "%x" % cert.serial_number
    return ("0" + h) if len(h) % 2 else h


class Registry:
    """The registry's schema (migrations/0001_registry.sql, 0002_radius_contract.sql); the
    queries follow crates/netportal-core/src/registry.rs. The RADIUS functions live in the schema
    radius (radius.cert_status, radius.login; docs/RADIUS_CONTRACT.md). The audit actions are
    returned as the portal stores them (enrol:<format>, renew, revoke, disconnect:<result>,
    policy:<name>); two audit rows with the same time are ordered by their id."""

    def __init__(self, dsn, radius_password):
        self.dsn = dsn
        self.radius_password = radius_password

    def _sql(self, query, *args):
        with psycopg.connect(self.dsn, row_factory=dict_row, autocommit=True) as db:
            cur = db.execute(query, args)
            return list(cur) if cur.description else cur.rowcount

    def _one(self, query, *args):
        rows = self._sql(query, *args)
        return rows[0] if rows else None

    def _radius_dsn(self):
        """The instance's database as FreeRADIUS's role radius (any user and password in the URL
        are replaced)."""
        params = conninfo_to_dict(self.dsn)
        params.update(user="radius", password=self.radius_password)
        return make_conninfo(**params)

    # --- people
    def person(self, sub):
        """{"username", "display", "admin": bool, "policy", "offboarded": bool,
        "recent_login": bool (within a minute)} or None."""
        return self._one("""SELECT username, display_name AS display, is_admin AS admin, policy,
                                   offboarded_at IS NOT NULL AS offboarded,
                                   now() - last_login_at < interval '1 minute' AS recent_login
                            FROM person WHERE sub = %s""", sub)

    def set_admin(self, sub, admin):
        self._sql("UPDATE person SET is_admin = %s WHERE sub = %s", admin, sub)

    def set_offboarded(self, sub):
        self._sql("UPDATE person SET offboarded_at = now() WHERE sub = %s", sub)

    def delete_person(self, sub):
        self._sql("DELETE FROM person WHERE sub = %s", sub)

    def policies(self):
        return {r["name"]: r["vlan"] for r in self._sql("SELECT name, vlan FROM policy")}

    def offboarding_last_success(self):
        """Unix seconds of the offboarding's last successful round, or None."""
        row = self._one("SELECT extract(epoch FROM last_success)::float8 AS t FROM job WHERE name = 'offboarding'")
        return row["t"] if row else None

    # --- devices
    def device(self, device_id):
        """{"id", "owner", "name", "platform", "policy", "revoked": bool} or None."""
        return self._one("""SELECT id::text, owner, name, platform, policy, revoked_at IS NOT NULL AS revoked
                            FROM device WHERE id = %s""", str(device_id))

    def devices(self, owner):
        """Newest first (registry::devices: created_at DESC, then id)."""
        return self._sql("""SELECT id::text, owner, name, platform, policy, revoked_at IS NOT NULL AS revoked
                            FROM device WHERE owner = %s ORDER BY created_at DESC, id""", owner)

    def newest_device(self, owner):
        found = self.devices(owner)
        return found[0] if found else None

    def audit(self, device_id):
        """[(actor, action)] of a device, oldest first."""
        return [(r["actor"], r["action"]) for r in self._sql(
            "SELECT actor, action FROM audit WHERE device_id = %s ORDER BY at, id", str(device_id))]

    def audit_of(self, actor):
        return [r["action"] for r in self._sql("SELECT action FROM audit WHERE actor = %s ORDER BY at, id", actor)]

    # --- credentials (the RADIUS decision's view of a certificate)
    def credential(self, cert):
        """{"device_id", "status": valid|revoked|retired|expired|unknown_cert, "retires_in_s":
        seconds until the renewal overlap ends or None, "not_after": aware datetime} for a
        certificate, or None when the registry does not know it."""
        row = self._one("""SELECT device_id::text, not_after,
                                  extract(epoch FROM retired_at - now())::float8 AS retires_in_s
                           FROM credential WHERE serial = %s""", serial_hex(cert))
        if row is None:
            return None
        row["status"] = self._one("SELECT radius.cert_status(%s) AS s", serial_hex(cert))["s"]
        return row

    def credential_count(self, device_id):
        return self._one("SELECT count(*) AS n FROM credential WHERE device_id = %s", str(device_id))["n"]

    def radius_session(self, device_id, cert, calling="02:00:00:00:aa:01", nas_ip="127.0.0.1",
                       user_name="anonymous@scharni.org", called="AA-BB-CC-00-00-01:Scharni"):
        """What FreeRADIUS records after an Accept (radius/sites/default post-auth: the
        same call, as the role radius): the device's latest session, the target of a
        Disconnect-Request. Returns the Class token."""
        with psycopg.connect(self._radius_dsn(), row_factory=dict_row, autocommit=True) as db:
            return db.execute("SELECT radius.login(%s, %s, %s, %s, %s, %s, %s) AS class",
                              (str(device_id), serial_hex(cert), calling, called, nas_ip, secrets.token_hex(4),
                               user_name)).fetchone()["class"]

    # --- one-time downloads
    def download_expires_in(self, token):
        row = self._one("SELECT extract(epoch FROM expires_at - now())::float8 AS s FROM download WHERE token_hash = %s",
                        _hash(token))
        return row["s"] if row else None

    def expire_download(self, token):
        return self._sql("UPDATE download SET expires_at = now() - interval '1 second' WHERE token_hash = %s",
                         _hash(token))

    # --- Let's Wi-Fi
    def token_expires_in(self, token):
        row = self._one("SELECT extract(epoch FROM expires_at - now())::float8 AS s FROM oauth_token "
                        "WHERE token_hash = %s", _hash(token))
        return row["s"] if row else None

    def expire_token(self, token):
        return self._sql("UPDATE oauth_token SET expires_at = now() - interval '1 second' WHERE token_hash = %s",
                         _hash(token))

    def grant(self, token):
        """The grant a token belongs to: {"owner", "client_id", "device_name", "device_id"
        (str or None), "revoked": bool} or None."""
        return self._one("""SELECT g.owner, g.client_id, g.device_name, g.device_id::text,
                                   g.revoked_at IS NOT NULL AS revoked
                            FROM oauth_token t JOIN oauth_grant g ON g.id = t.grant_id WHERE t.token_hash = %s""",
                         _hash(token))

    def stores_plain_token(self, token):
        """Whether the token appears in clear anywhere it is stored (app tokens and download
        links: both keep only the SHA-256)."""
        return bool(self._one("""SELECT 1 AS x FROM oauth_token WHERE token_hash = %s
                                 UNION ALL SELECT 1 FROM download WHERE token_hash = %s""", token, token))
