"""Configuration (INVENTORY 2: *_FILE secrets, required settings, validation), the CLI's
init-db and pki (1.1, 6.1), start-up refusals and a registry outage (1.3, 3.2 rows 30-31, 10)."""

import base64
import datetime
import os
import stat
import tempfile
import time
from pathlib import Path

import psycopg
import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtendedKeyUsageOID

import registry_adapter
from harness import (A, B, RUN, SUITE, ContractCase, Spawned, download, idp_directory, parse_metrics, resident,
                     sample)

PG_ADMIN = SUITE["pg_admin"]


def admin_sql(*statements):
    with psycopg.connect(PG_ADMIN, autocommit=True) as db:
        for s in statements:
            db.execute(s)


def db_url(name):
    return A.db_url.rsplit("/", 1)[0] + "/" + name


class FileSecretTests(ContractCase):
    """2.1/2.2: secrets from NAME_FILE (instance B has every secret only in a file, with a trailing
    newline; setting both NAME and NAME_FILE is refused, StartupTests); NETPORTAL_DEVICE_CA_KEY
    as a file."""

    def test_database_session_and_oidc_secrets_from_files(self):
        b = B.browser()
        callback, final = b.login(resident("file"))
        self.assertEqual(callback.status_code, 302, callback.text[:300])     # OIDC client secret from the file
        self.assertPage(final, 200, "Your devices")                         # database URL and session secret
        self.assertEqual(b.get("/api/devices").status_code, 200)

    def test_device_ca_key_from_a_file(self):
        b = B.browser().logged_in(resident("filekey"))
        _, cert, _ = download(b, "eap-config")
        cert.verify_directly_issued_by(x509.load_pem_x509_certificate((B.pki / "device-ca.pem").read_bytes()))

    def test_dae_secret_from_a_file(self):
        """The fake access point of B checks the authenticators with the file's secret."""
        B.nas.reset("ack")
        p = resident("filedae")
        b = B.browser().logged_in(p)
        _, cert, dev = download(b, "apple")
        B.reg.radius_session(dev, cert, user_name="anonymous@" + B.realm)
        b.post("/devices/%s/revoke" % dev, data={"csrf": b.csrf()})
        packets = B.nas.wait(1)
        self.assertEqual(len(packets), 1)
        self.assertTrue(packets[0]["valid"], packets[0])
        self.assertEqual(B.reg.audit(dev)[-1], (p.sub, "disconnect:ack"))

    def test_authentik_token_from_a_file(self):
        idp_directory(reset=True)
        before = B.reg.offboarding_last_success()
        time.sleep(1.1)
        out = B.command("offboard", env={"NETPORTAL_HEARTBEAT": str(RUN / "heartbeat-file")})
        self.assertEqual(out.returncode, 0, out.stderr[-2000:])
        self.assertGreater(B.reg.offboarding_last_success(), before)


class StartupTests(ContractCase):
    """2.1: a missing or invalid setting stops the process at start; 6.1: a device CA key that
    does not match its certificate stops the portal."""

    def refuses(self, port, **changes):
        settings = dict(A.env)
        for k, v in changes.items():
            if v is None:
                settings.pop(k, None)
            else:
                settings[k] = v
        proc = Spawned(settings, port)
        try:
            self.assertFalse(proc.healthy(timeout=25), "started although %s" % changes)
            code = proc.exit_code(timeout=20)
            self.assertIsNotNone(code, "still running without answering")
            self.assertNotEqual(code, 0)
        finally:
            proc.stop()

    def test_missing_required_settings(self):
        for name in ("NETPORTAL_REALM", "NETPORTAL_SESSION_SECRET", "NETPORTAL_DATABASE_URL", "NETPORTAL_BASE_URL"):
            with self.subTest(missing=name):
                self.refuses(28083, **{name: None})

    def test_a_secret_and_its_file_both_set(self):
        """2.2: NAME and NAME_FILE together are ambiguous: the portal refuses to start (A sets
        NETPORTAL_SESSION_SECRET; the file holds a valid secret)."""
        self.refuses(28083, NETPORTAL_SESSION_SECRET_FILE=str(RUN / "secrets" / "session-secret"))

    def test_invalid_settings(self):
        for name, value in [("NETPORTAL_POLICIES", "residents=5000:residents"),
                            ("NETPORTAL_POLICIES", "residents=30:residents;guests=50:residents"),
                            ("NETPORTAL_ACCT_INTERIM_S", "10"),
                            ("NETPORTAL_PROMETHEUS_URL", "not a url")]:
            with self.subTest(**{name: value}):
                self.refuses(28083, **{name: value})

    def test_device_ca_key_must_match_the_certificate(self):
        # as a file (the only way the portal reads it: test_device_ca_key_only_from_a_file)
        self.refuses(28083, NETPORTAL_DEVICE_CA_KEY=str(A.pki / "root.key"))

    def test_device_ca_key_only_from_a_file(self):
        """Security review 2026-10-29 L3: a key in the environment is readable by every process of
        the user and in `docker inspect`, and cannot be wiped: the portal refuses
        NETPORTAL_DEVICE_CA_KEY_B64."""
        right = base64.b64encode((A.pki / "device-ca.key").read_bytes()).decode()
        self.refuses(28083, NETPORTAL_DEVICE_CA_KEY=None, NETPORTAL_DEVICE_CA_KEY_B64=right)

    def test_init_db_needs_the_settings(self):
        # init-db needs the registry and the policies and reads only those (one settings loader
        # per process), so a missing portal-only setting such as NETPORTAL_REALM is no error there.
        settings = dict(A.env)
        out = A.command("init-db", unset=("NETPORTAL_DATABASE_URL",))
        self.assertNotEqual(out.returncode, 0)
        out = A.command("init-db", env=dict(settings, NETPORTAL_POLICIES="x=1:"))
        self.assertNotEqual(out.returncode, 0)


class InitDbTests(ContractCase):
    """1.1 init-db: creates the schema and the policies on an empty database; idempotent."""

    def test_fresh_database(self):
        name = "netportal_init_%d" % os.getpid()
        admin_sql("DROP DATABASE IF EXISTS %s" % name, "CREATE DATABASE %s" % name)
        try:
            settings = {"NETPORTAL_DATABASE_URL": db_url(name)}
            for run in (1, 2):
                with self.subTest(run=run):
                    out = A.command("init-db", env=settings)
                    self.assertEqual(out.returncode, 0, out.stdout + out.stderr[-2000:])
            reg = registry_adapter.Registry(db_url(name), SUITE["radius_password"])
            self.assertEqual(reg.policies(), {"residents": 30, "guests": 50})
        finally:
            admin_sql("DROP DATABASE IF EXISTS %s WITH (FORCE)" % name)


class RegistryOutageTests(ContractCase):
    """1.3/3.2 rows 30-31/10: while the database is unreachable /healthz fails, pages and the API
    answer server errors (JSON for the API), /metrics still answers with netportal_registry_up 0;
    afterwards everything works again without a restart."""

    def test_database_down_and_back(self):
        name = "netportal_outage_%d" % os.getpid()
        admin_sql("DROP DATABASE IF EXISTS %s" % name, "CREATE DATABASE %s" % name)
        proc = Spawned(dict(A.env, NETPORTAL_DATABASE_URL=db_url(name)), 28084)
        try:
            self.assertTrue(proc.healthy(), proc.output()[-2000:])
            # a login of the same secret and OIDC client (instance A's), for the pages that need one
            cookie = "; ".join("%s=%s" % kv for kv in A.browser().logged_in(resident("outage")).cookies.items())
            admin_sql("ALTER DATABASE %s WITH ALLOW_CONNECTIONS false" % name,
                      "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '%s'" % name)
            # within the check interval: the registry is asked at most every 10 s, so a flood of
            # /healthz opens no connection
            failed = False
            for _ in range(30):
                if requests.get(proc.url + "/healthz", timeout=10).status_code >= 500:
                    failed = True
                    break
                time.sleep(0.5)
            self.assertTrue(failed, "/healthz still ok without the registry")
            r = requests.get(proc.url + "/api/devices", headers={"Cookie": cookie}, timeout=10)
            self.assertGreaterEqual(r.status_code, 500)
            self.assertIn("error", r.json())
            r = requests.get(proc.metrics_url + "/metrics", timeout=10)
            self.assertEqual(r.status_code, 200)
            self.assertEqual(sample(parse_metrics(r.text), "netportal_registry_up"), 0)
            admin_sql("ALTER DATABASE %s WITH ALLOW_CONNECTIONS true" % name)
            ok = False
            for _ in range(30):
                if requests.get(proc.url + "/healthz", timeout=10).status_code == 200:
                    ok = True
                    break
                time.sleep(0.5)
            self.assertTrue(ok, "no recovery after the database came back")
            self.assertEqual(sample(parse_metrics(requests.get(proc.metrics_url + "/metrics", timeout=10).text),
                                    "netportal_registry_up"), 1)
        finally:
            proc.stop()
            admin_sql("ALTER DATABASE %s WITH ALLOW_CONNECTIONS true" % name,
                      "DROP DATABASE IF EXISTS %s WITH (FORCE)" % name)


    def test_anonymous_pages_need_no_registry(self):
        """Security review 2026-10-29 H1: a request without a login takes no registry connection
        (a flood of them cannot use up the database's connections): /welcome, the start page's
        redirect to the login and the static files work while the registry is unreachable."""
        name = "netportal_anon_%d" % os.getpid()
        admin_sql("DROP DATABASE IF EXISTS %s" % name, "CREATE DATABASE %s" % name)
        proc = Spawned(dict(A.env, NETPORTAL_DATABASE_URL=db_url(name)), 28085)
        try:
            self.assertTrue(proc.healthy(), proc.output()[-2000:])
            admin_sql("ALTER DATABASE %s WITH ALLOW_CONNECTIONS false" % name,
                      "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '%s'" % name)
            self.assertEqual(requests.get(proc.url + "/welcome", timeout=10).status_code, 200)
            r = requests.get(proc.url + "/", timeout=10, allow_redirects=False)
            self.assertEqual((r.status_code, r.headers.get("Location")), (302, "/login"))
            self.assertEqual(requests.get(proc.url + "/static/style.css", timeout=10).status_code, 200)
            r = requests.get(proc.url + "/api/devices", timeout=10)
            self.assertEqual(r.status_code, 401)
        finally:
            proc.stop()
            admin_sql("ALTER DATABASE %s WITH ALLOW_CONNECTIONS true" % name,
                      "DROP DATABASE IF EXISTS %s WITH (FORCE)" % name)


class PkiTests(ContractCase):
    """6.1: `netportal pki` (the CA ceremony): the files house-infra and FreeRADIUS read, secret
    files 0600, and certificates FreeRADIUS and every client platform accept (Apple: a TLS server
    certificate needs serverAuth, a DNS SAN and at most 825 days)."""

    def test_ceremony(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "pki"
            out = A.command("pki", "--out", str(out_dir), "--name", "Contract", "--server-name", "radius.example.test")
            self.assertEqual(out.returncode, 0, out.stderr[-2000:])
            files = {"root.pem": False, "root.key": True, "device-ca.pem": False, "device-ca.key": True,
                     "device-ca-chain.pem": False, "radius-server.pem": False, "radius-server.key": True}
            for name, secret in files.items():
                with self.subTest(file=name):
                    mode = stat.S_IMODE(os.stat(out_dir / name).st_mode)
                    if secret:
                        self.assertEqual(mode & 0o077, 0, oct(mode))
                    else:
                        self.assertEqual(mode & 0o022, 0, oct(mode))
            load = lambda n: x509.load_pem_x509_certificate((out_dir / n).read_bytes())  # noqa: E731
            root, ca, server = load("root.pem"), load("device-ca.pem"), load("radius-server.pem")
            now = datetime.datetime.now(datetime.timezone.utc)
            # root: self-signed CA that may sign one level of CA
            self.assertEqual(root.subject, root.issuer)
            root.verify_directly_issued_by(root)
            bc = root.extensions.get_extension_for_class(x509.BasicConstraints)
            self.assertTrue(bc.critical and bc.value.ca)
            self.assertEqual(bc.value.path_length, 1)
            self.assertTrue(root.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign)
            # device CA: signed by the root, signs only end entities; its DN is what FreeRADIUS pins
            ca.verify_directly_issued_by(root)
            bc = ca.extensions.get_extension_for_class(x509.BasicConstraints)
            self.assertTrue(bc.critical and bc.value.ca)
            self.assertEqual(bc.value.path_length, 0)
            self.assertEqual(ca.subject.rfc4514_string(), "CN=Contract Device CA")
            self.assertGreater(ca.not_valid_after_utc, now + datetime.timedelta(days=5 * 365))
            # the chain file FreeRADIUS reads: device CA, then root
            chain = x509.load_pem_x509_certificates((out_dir / "device-ca-chain.pem").read_bytes())
            self.assertEqual(chain, [ca, root])
            # RADIUS server certificate
            server.verify_directly_issued_by(root)
            self.assertFalse(server.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
            eku = list(server.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)
            self.assertIn(ExtendedKeyUsageOID.SERVER_AUTH, eku)
            san = server.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            self.assertEqual(san.get_values_for_type(x509.DNSName), ["radius.example.test"])
            self.assertLessEqual((server.not_valid_after_utc - server.not_valid_before_utc).days, 825)
            # keys belong to their certificates
            for cert_name, key_name in [("root.pem", "root.key"), ("device-ca.pem", "device-ca.key"),
                                        ("radius-server.pem", "radius-server.key")]:
                with self.subTest(key=key_name):
                    key = serialization.load_pem_private_key((out_dir / key_name).read_bytes(), None)
                    spki = serialization.PublicFormat.SubjectPublicKeyInfo
                    self.assertEqual(key.public_key().public_bytes(serialization.Encoding.DER, spki),
                                     load(cert_name).public_key().public_bytes(serialization.Encoding.DER, spki))
