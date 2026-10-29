# Black-box tests

The suites test the portal from outside: the `netportal` binary (`crates/netportal`), the
FreeRADIUS configuration (`radius/`) and the registry schema (`migrations/`, `sql/`). They are
Python scripts (test tooling only: `requests`, `psycopg`, `cryptography`), plus the mock
Authentik and, for certificates the portal would never issue, the small Rust tool
`radius/certs`. Unit tests live in the crates (`cargo test`).

| Suite | What it is | Command |
|---|---|---|
| `contract/` | 194 black-box tests (about 760 assertion call sites, many inside loops and subtests) over HTTP, the mock IdP, a fake access point (UDP Disconnect) and the CLI, against two portal instances | `tests/contract/run.sh` |
| `integration/` | the whole path, 127 checks: login through the mock Authentik, enrolment per platform, EAP-TLS with eapol_test through FreeRADIUS (`radius/`), revocation with a Disconnect-Request to a fake access point, renewal, the Let's Wi-Fi flow, offboarding, admin, metrics, accounting, presence, the radius role's rights, fail-closed, the Disconnect reconciliation (a lost Disconnect cut later by the sidecar, a stale record settled by a NAK 503) | `tests/integration/run.sh` |
| `radius/` | FreeRADIUS (`radius/`) against a database migrated by the binary, no portal, 73 checks: the RADIUS cases of `integration/e2e.py` (decisions, logged reasons, Class, the Accept's VLAN, sessions, accounting, the radius role, the pools, logging blocked or revoked, database down), the certificate-identity binding and no TLS session resumption | `tests/radius/run.sh` |
| `js/` | the dashboard's ES modules (`crates/netportal-web/static/`) under Node's test runner, partly against the server's implementation as an oracle | `node --test tests/js/` |

## Running

```sh
tests/contract/run.sh                                   # builds target/debug/netportal first
NETPORTAL_BIN=target/release/netportal tests/contract/run.sh   # another binary (not built)
CT_ARGS="test_letswifi test_login.LogoutTests" tests/contract/run.sh   # only some tests
KEEP=1 tests/contract/run.sh                            # leave PostgreSQL, IdP and portals running
python3 tests/contract/selftest_registry_adapter.py     # the registry adapter against the schema

tests/integration/run.sh                                # builds target/debug/netportal first
NETPORTAL_BIN=target/release/netportal tests/integration/run.sh
KEEP=1 tests/integration/run.sh                         # leave everything running

tests/radius/run.sh                                     # FreeRADIUS + the registry
MIGRATE=psql tests/radius/run.sh                        # migrate without the binary

node --test tests/js/
```

Without `NETPORTAL_BIN`, `contract/run.sh` and `integration/run.sh` run `cargo build -q -p
netportal` and test `target/debug/netportal`; with it they test that binary as it is. Run the
Docker suites one after the other: several checks are timing-based (logins answered in time,
`/healthz` within its check interval) and fail under parallel load. Their ports and Docker
networks are separate (contract: 25432, 28080-28091, 29000; integration: 15432, 18080, 18090,
19000, network `netportal-it`; radius: 17432, network `netportal-rt`), and each script refuses to
start while an earlier `KEEP=1` environment still holds them. Run output goes to
`tests/runs/<suite>/`.

After a `KEEP=1` contract run you can rerun single modules against the running environment:
`cd tests/contract && CT_SUITE=../runs/contract/suite.json python3 -m unittest test_api -v`.
To tear it down, stop the two `netportal serve` processes on 28080/28081 and `mock_idp.py`, then
`docker rm -f netportal-ct-pg`.

Results on 2026-10-29 (debug build, one suite at a time):

* contract: `Ran 194 tests in 42.1s, OK`, about 53 s wall time;
* integration: 127 `ok` lines, `0 failure(s)`, about 120 s (the reconciliation case waits about
  30 s for the sidecar);
* radius: 73 `ok` lines, `0 failure(s)`, about 73 s;
* `selftest_registry_adapter.py`: 3 tests OK, about 4 s.

Requirements: Docker; `cargo`; `python3` with `requests`, `psycopg` (3), `cryptography`; `lxml`
(optional, for the eap-config XSD check); the `openssl` CLI (3.x); `ss` (iproute2) and `curl`;
Node for `js/`. The XSD is read from `target/eap-metadata.xsd` (GÉANT CAT,
`devices/eap_config/eap-metadata.xsd`, downloaded by `check.sh`); without it that one test is
skipped.

### Ignored tests

`./check.sh` reports `2 ignored`. Both are in `crates/netportal-pki/tests` and are meant to be
run by hand; neither is a check that a normal run could make:

| Test | Why ignored | What covers it in every run | By hand |
|---|---|---|---|
| `disconnect.rs::live_dae_server` | sends a real Disconnect-Request to a real access point (its address and the RADIUS secret needed; it names a made-up MAC, 02:00:00:00:aa:42, so it cuts nothing: an ACK or NAK shows that the access point answers and the reply passed every check) | the packet and reply checks against fake access points (`disconnect.rs`), the contract suite's independent RFC 5176/3579 implementation (`test_devices.RevokeTests`), hostapd in `integration/` | `NETPORTAL_PKI_LIVE_DAE=<ap>:3799:<secret> cargo test -p netportal-pki --test disconnect -- --ignored live --nocapture` (prints the outcome; the UniFi check in `docs/CUTOVER.md`) |
| `tls.rs::export_for_eapol_test` | a tool, not a check: writes a CA, server and client keys and a PKCS#12 into a directory for a manual eapol_test run | `integration/` and `radius/` (EAP-TLS with eapol_test through FreeRADIUS, every platform's artefact) | `NETPORTAL_PKI_EXPORT=<empty dir> cargo test -p netportal-pki --test tls -- --ignored export` (delete the directory afterwards: test keys) |

Run without their setting they fail (they used to pass without doing anything). Last run by
hand 2026-10-29: the export wrote its files; the live test needs the hardware test.

## `contract/`

### What the suite relies on

* `netportal serve` listens on `NETPORTAL_LISTEN` (`127.0.0.1:28080`/`28081`) and serves
  `/metrics` on `NETPORTAL_METRICS_LISTEN` (`28090`/`28091`; `suite.json` `metrics_url`); the
  portal's own port answers 404 there. Every other setting comes from the `NETPORTAL_*`
  variables, secrets also as `*_FILE`; the device CA key only as a file
  (`NETPORTAL_DEVICE_CA_KEY`).
* The schema is ready before `/healthz` answers 200.
* An `http://127.0.0.1` OIDC issuer works (loopback only).
* CLI commands `offboard [--every N]`, `init-db` and `pki --out DIR --name NAME --server-name FQDN`.
  Exit code 0 means success; a failed offboarding round exits non-zero.
* The portal environment is exact: `env -i` plus `PATH` and `HOME`. Use
  `PORTAL_EXTRA_ENV="RUST_LOG=debug"` for extra variables.

### The registry adapter

The tests never use SQL directly. Setup and inspection go through
`contract/registry_adapter.py` (`Registry`): people, devices, audit actions, credentials and
their RADIUS status, download and OAuth token expiry, grants, and a RADIUS session as FreeRADIUS
records it, with the queries of `crates/netportal-core/src/registry.rs` and the functions of the
schema `radius` (`radius.cert_status`, and `radius.login` as the role radius). The tests observe
over HTTP or RADIUS wherever they can. `contract/selftest_registry_adapter.py` checks every
adapter function against a database migrated by the binary (`tools/test-db.sh`, no portal;
`NETPORTAL_TEST_DATABASE_URL` reuses a running server). It is not collected by `run.sh`.

### Deliberately not pinned

* the session cookie's name over plain http; `Expires` before the login;
* float spelling and rounding; timestamp spelling (any RFC 3339 timestamp is accepted);
* a bare trailing `?` on return-to paths;
* the healthz Content-Type;
* `OPTIONS` handling, beyond "if answered with 2xx, `Allow` lists the methods";
* whether `invalid_client` is a 400 or a 401;
* whether `POST /api/eap-config` (no slash) is a 308 to the slash URL or served there;
* the exact PKCS#12 iteration counts;
* the PPS MO and eap-config byte serialisation (XML declaration, ASCII escaping);
* `*_created` series, HELP texts and the exposition format's version parameter;
* the order of the CSRF check versus the 405.

### Set-up (`contract/run.sh`)

* PostgreSQL 18 (Docker) at `127.0.0.1:25432`, one database per instance.
* The mock IdP `contract/mock_idp.py` at `127.0.0.1:29000`. It imports
  `integration/mock_authentik.py` by path and adds a directory separate from the login user,
  pagination, failure modes, a request log and claims that can be left out.
* One PKI per instance from `netportal pki` (`tests/runs/contract/pki`, `pki-b`): the device
  CA's name constraints permit its own realm only, so the two realms cannot share one.
* Two portal instances:
  * **A**, `127.0.0.1:28080`: plain variables, http, realm `scharni.org`, Passpoint on,
    `NETPORTAL_POLICIES` with two policies, logout URL, device CA key file.
  * **B**, `127.0.0.1:28081`: every secret only in a `*_FILE` (with a trailing newline), device
    CA key file, https base URL with a trailing slash, one policy
    (`residents=40:residents,staff`), the default admin group, Passpoint off, default display
    name, non-ASCII SSID, realm `house.example.net`, `CERT_DAYS=30`, `RENEW_OVERLAP_DAYS=5`.
* The fake access points (`contract/fake_nas.py`) run inside the test process on UDP
  `127.0.0.1:23799` (A) and `:23798` (B), so the tests can read what they received.
* Extra instances started by tests use ports 28083 to 28085 (their metrics: port + 1000).

### What is not black-box testable here, and why

* **8 h idle and 12 h absolute session limits on the server.** The portal's clock cannot be
  moved from outside, and a test cannot age a signed cookie. What is tested: the cookie's 8 h
  expiry after login and its renewal on use. Not tested: the server refusing a session idle for
  8 h, and the 12 h limit after `login_at`. Possible ways: a test-only
  `NETPORTAL_SESSION_MAX_SECONDS`, or an `LD_PRELOAD` clock shim.
* **Logging rules (4.9)**: no tokens, keys or user agents in the logs. Possible as a log scan of
  `tests/runs/contract/portal-*.log`, but not done: the tokens are spread over many tests.
* **The sidecar's `netportal_offboarded_devices_total`.** The offboarding process exposes no
  endpoint.
* **Telemetry with Prometheus or Loki, and the collector (`collect`, `job`).** No suite has a
  Prometheus or Loki fake, so the dashboards run with telemetry `off` (the crates' own tests
  cover those queries).
* **Real installs on iPhone, Mac and Android.** Only the platforms' documented constraints are
  checked. The integration suite authenticates eapol_test with the extracted certificates.
* **HTML beyond the contract strings** (texts, the template-side admin filters), other
  languages, and concurrency.
* **The Disconnect `error` result** (an IPv6 NAS address) and `skipped` (no DAE secret): not
  exercised; it would need a third instance.

### Artefact constraints and their sources (`test_artefacts.py`)

| Artefact | Constraint asserted | Source |
|---|---|---|
| Apple `.mobileconfig` | Configuration profile with Root, PKCS#12 identity and Wi-Fi payloads (and Ethernet for macOS only: iOS refuses it); unique upper-case UUIDs; EAP-TLS only (`AcceptEAPTypes [13]`); pinned `TLSTrustedServerNames`; anchor = the root, inside `EAPClientConfiguration`; outer identity `anonymous@realm`; TLS ≥ 1.2; PayloadIdentifier reverse DNS of the realm and stable per device across renewals (iOS/macOS replace by identifier) | Apple Configuration Profile Reference (Wi-Fi, EAPClientConfiguration, Certificate payloads); apple/device-management `com.apple.wifi.managed.yaml` |
| Apple PKCS#12 | MAC HMAC-SHA1; bags encrypted with `pbeWithSHA1And3-KeyTripleDES-CBC`; no PBES2; key shrouded; readable without OpenSSL's legacy provider | SecPKCS12Import on the iOS/macOS versions in use refuses OpenSSL 3's defaults (PBES2/AES-256-CBC with an HMAC-SHA256 MAC: "MAC verification failed" on releases before 2024). This is why netportal uses 3DES |
| Android Passpoint | base64 body; MIME multipart with `application/x-passpoint-profile`, `application/x-x509-ca-cert` (the root), `application/x-pkcs12`, each base64; no `Content-Disposition`; `Content-Transfer-Encoding: base64` | AOSP `ConfigParser.parseMimeMultipartMessage` (hotspot2); source.android.com "Passpoint R1 provisioning" |
| Android PKCS#12 | opens with an EMPTY password, MAC included | AOSP loads it with `KeyStore.load(in, new char[0])` |
| PPS MO | `MgmtTree`, `PerProviderSubscription` with DDF name `urn:wfa:mo:hotspot2dot0-perprovidersubscription:1.0`; HomeSP FriendlyName and FQDN = realm; Credential Realm, DigitalCertificate x509v3 with the SHA-256 fingerprint of the client certificate | Wi-Fi Alliance Hotspot 2.0 PPS MO; AOSP `PpsMoParser` |
| eap-config | GÉANT CAT `eap-metadata.xsd` valid; EAP type 13; CA = root; ServerID; OuterIdentity; PKCS#12 opens with its Passphrase; SSID; MinRSNProto CCMP; ValidUntil = the certificate's notAfter | GÉANT CAT / geteduroam apps |
| Device certificates | `CN=<device id>@<realm>` only (no personal data); issued by the instance's device CA (FreeRADIUS `check_cert_issuer`); EC P-256/P-384 or RSA ≥ 2048 with SHA-2; not a CA; critical KeyUsage digitalSignature; EKU clientAuth (no serverAuth); AKI = the CA's SKI; serial positive, 64–159 bits, unique; validity `NETPORTAL_CERT_DAYS` | RFC 5280; EAP-TLS (RFC 5216) |
| `pki` output | file names and permissions as house-infra and FreeRADIUS read them; root CA pathlen 1, device CA pathlen 0 with DN `CN=<name> Device CA`; chain file = device CA + root; server certificate with serverAuth, a DNS SAN and at most 825 days | Apple's TLS server certificate rules (iOS 13 / macOS 10.15); `radius/mods/eap` |

### What each test covers

Each test names its inventory section in its own docstring or in its class docstring.
Section numbers refer to `docs/INVENTORY.md`; "security review" items to the review of
2026-10-29.

| Module.Class (tests) | INVENTORY | What is asserted |
|---|---|---|
| `test_routes.RouteAuthTests` (10) | 3.2 auth column, 3.6, 4.3 | every route of 3.2 for anonymous, resident, admin and refused users: 302 `/login`, 401 `login_required`, 403 page / `forbidden`, 404 for other people's devices on every device route, UUID matching; `/metrics` not on the portal's port |
| `test_routes.MethodTests` (6) | 3 (HEAD, OPTIONS, trailing slash), 3.6 | HEAD without a body, OPTIONS `Allow`, 405 with `Allow` (page and JSON), `/api/eap-config` without the slash |
| `test_routes.ErrorResponseTests` (3) | 3.6, 4.7 | message page versus `{"error": …}` JSON per status |
| `test_session.CookieTests` (9) | 4.1 | HttpOnly, SameSite=Lax, Path=/, no Domain, not Secure over http; https: `__Host-` and Secure; 8 h idle expiry after login, renewed on use; rotation at login; no fixation; tampered cookie refused; bound to the secret; one CSRF token per session (≥ 128 bits) |
| `test_session.CsrfTests` (8) | 4.2, 3.1 | missing, wrong or foreign token gives 400 (page and JSON); header tokens do not count; a stale script POST gets 401 before the CSRF check; the `Accept` rule; exempt endpoints; logout |
| `test_login.LoginTests` (12) | 4.4, 4.3 | authorization request (code, PKCE S256, state, nonce, scopes, redirect URI); person recorded; policy and admin from the groups; instance B's single policy and default admin group; refused without a policy or groups; missing `sub` (a 4xx, never a 500); claim fallbacks; replayed, cancelled and wrong-state callbacks give 400; a foreign callback keeps the session; a new login clears `offboarded` |
| `test_login.ReturnToTests` (6) | 4.4 return-to | GET with its query, device page, download, consent POST rebuilt as the authorize URL, `back=/admin`, other POSTs go to `/`, and `/` sets no target |
| `test_login.LogoutTests` (5) | 3.2 row 3, 4.4, owner's review 2026-10-29 | to `NETPORTAL_LOGOUT_URL` or `/`; the session ends, only this one (a copy of its cookie too, the person's other sessions stay); `POST /logout/all` ends every session of the person (CSRF), nobody else's |
| `test_login.RegistryRightsTests` (7) | 4.3, owner's review 2026-10-29 | the registry's admin flag alone grants nothing (Authentik's users API is asked live; the flag is cleared and the session ends when it says no), granted with both, taken in the registry; out of the admin group in Authentik: the next admin page and the next direct admin API call refused, flag cleared, every session ended; Authentik failing: admin requests 503, resident pages fine; offboarded or deleted person ends the session at the next request (the CSRF token survives); admin powers over other people's devices |
| `test_devices.EnrolTests` (5) | 3.2 row 7, 4.6 | each format; token ≥ 256 bits, about 10 minutes; default names; name stripped and cut to 60; bad formats 400; Passpoint off; recommended format per User-Agent |
| `test_devices.DownloadTests` (8) | 4.6, 6.4 | Content-Type, file names (ASCII, default `Wi-Fi`), Passpoint framing, no-store; one-time; someone else's token refused and not used up; expired; revoked device; a new certificate per download, known to the registry |
| `test_devices.RenewTests` (2) | 3.2 row 8, 6.2 | same device, new serial, overlap `NETPORTAL_RENEW_OVERLAP_DAYS` (2 and 5); revoked or foreign gives 404 |
| `test_devices.RenameTests` (2) | 3.2 row 10 | form and JSON variants, empty name, 60-character cut |
| `test_devices.LimitTests` (1) | security review L5 | the 11th new device within an hour is a 429 |
| `test_devices.RevokeTests` (7) | 3.2 row 11, 7.1 | Disconnect-Request checked by an independent RFC 5176/3579 implementation (authenticators, User-Name, Calling-Station-Id, NAS-IP-Address, Event-Timestamp); ack, nak (Error-Cause 503: nothing left to cut, the redirect), no-session and timeout (retransmissions with the same identifier; the page says the cut is not confirmed); RADIUS status revoked; metrics; `back` |
| `test_artefacts.CertificateTests` (3) | 6.1, 6.2 | device certificates of every format and both instances (see the table above) |
| `test_artefacts.AppleTests` (5) | 6.3, 6.5 | profile structure (iOS, macOS, non-ASCII SSID); server anchor inside `EAPClientConfiguration`; PKCS#12 readable by Apple; identifier stable; reverse DNS of the realm |
| `test_artefacts.PasspointTests` (3) | 6.3, 6.6 | installer layout, PPS MO values and fingerprint, FQDN kept on renewal |
| `test_artefacts.EapConfigTests` (2) | 6.7 | values on both instances, XSD |
| `test_letswifi.DiscoveryTests` (2) | 3.2 row 26, 3.5 | `/.well-known/letswifi.json` (base URL normalised), the `Accept: application/json` probe of `/` |
| `test_letswifi.AuthorizeTests` (10) | 3.5, 4.5, 3.4 | consent page and its `form-action`, naming the app and its target; unknown client or redirect gives 400 with no Location; loopback rules (RFC 8252: any port and path, never localhost); error redirects with state; `unsupported_response_type`; CSRF; code issuance, lifetime ≤ 10 minutes, grant name |
| `test_letswifi.TokenTests` (15) | 3.5 | token response fields, `expires_in` ≤ 3600 matching storage, no-store, hashed storage; refresh tokens only for desktop clients, ≤ 400 days; invalid_client, invalid_grant (verifier, client, redirect, expiry, 42-character verifier), unsupported_grant_type, invalid_request and unauthorized_client; code reuse revokes the grant and the certificate it produced; a failed exchange burns the code; refresh rotation; refresh replay revokes the grant and the device; another client's refresh token; offboarded owner |
| `test_letswifi.EapConfigEndpointTests` (11) | 3.5, 6.7 | first call enrols (name, CN, binding, audit, metric); later calls renew with overlap; one eap-config per access token; a quick re-issue retires the previous certificate; revoked device stops the tokens; bad, missing or expired bearer; a code is not an access token; `WWW-Authenticate: Bearer` and scheme case; portal renewal points to the app; realm of B |
| `test_api.PolledApiTests` (7) | 3.3 | weak ETag, `private, no-store`, stable across polls, 304 (strong, weak, `*` and list forms), changes with the data, login checked before the 304, the single-device API |
| `test_api.PayloadTests` (3) | 9.12 | DASHBOARD, DEVICE, HOUSE and HISTORY field names, types, enums, RFC 3339 times, order; `bad_range` |
| `test_api.AdminApiTests` (5) | 3.2 rows 20-25 | owner block, `q` and `state` filters, counts of all devices; incidents, auth (including `²` and `٣`) and raw parameter errors; raw shows revoked devices |
| `test_headers.HeaderTests` (4) | 3.1, 3.4, 4.8, 3.2 row 32 | CSP per response as a directive set (scripts only on dashboard pages, `'self'`); nosniff; Referrer-Policy; Cache-Control; consent `form-action`; downloads; JavaScript MIME type for the ES modules; path traversal |
| `test_metrics.MetricsTests` (4) | 10, 3.2 row 31 | family names and types the alert rules use (with the reconciliation's `netportal_disconnect_rechecks_total` and `netportal_locked_sessions_live`); label sets; values follow enrolment and revocation; 404 with `X-Forwarded-For` |
| `test_metrics.MetricsTokenTests` (1) | owner's review 2026-10-29 | instance B's `NETPORTAL_METRICS_TOKEN_FILE` (a read-only file): 401 with `WWW-Authenticate: Bearer` without, with a wrong or another scheme's token; 200 with it; 404 through the proxy whatever the token |
| `test_offboarding.OffboardingTests` (14) | 8.1-8.3, 7.1 | inactive, group lost or deleted: offboarded, devices revoked with a Disconnect, app tokens stopped, session ended; two rounds before a removal; a mass removal is held back (exit ≠ 0, nothing changed); moved out (guests VLAN, Disconnect); admin follows the groups, and losing it ends the sessions; pagination and `include_groups`; strangers ignored; API 500, wrong token, empty directory and unreachable API change nothing (exit ≠ 0, heartbeat still touched); off switch; `--every` |
| `test_config.FileSecretTests` (4) | 2.1, 2.2 | secrets from `*_FILE` (database URL, session secret, OIDC client secret, DAE secret checked by the fake NAS, Authentik token); device CA key from a file |
| `test_config.StartupTests` (6) | 2.1, 2.2, 6.1 | missing or invalid settings, a secret set both as `NAME` and `NAME_FILE`, a device CA key in the environment (`NETPORTAL_DEVICE_CA_KEY_B64`) and a mismatched device CA key stop `serve` (exit ≠ 0); `init-db` checks its settings (it reads only the registry's) |
| `test_config.InitDbTests` (1) | 1.1 | `init-db` on an empty database, twice; policies seeded |
| `test_config.RegistryOutageTests` (2) | 1.3, 3.2 rows 30-31, 10 | database down: `/healthz` and pages give 5xx, the API a 5xx with a JSON error, `/metrics` shows `netportal_registry_up 0`; recovery without a restart; anonymous pages (`/welcome`, `/` to the login, static files, a 401 from the API) need no registry |
| `test_config.PkiTests` (1) | 6.1 | the ceremony's files, permissions and certificates |

## `integration/`

`integration/run.sh` starts, on the Docker network `netportal-it` (10.199.0.0/24):

* PostgreSQL 18 at 10.199.0.5 (`127.0.0.1:15432`) with the role radius;
* the PKI from `netportal pki` and, for the FreeRADIUS traps, certificates from `radius/certs`
  (`radius-test-certs`, built as in `radius/run.sh`: an unregistered device certificate, one
  from a foreign root and device CA with the same names, one the root signed directly;
  `tests/runs/integration/certs.json` names their device ids and serials);
* the mock Authentik (`integration/mock_authentik.py`, `127.0.0.1:19000`);
* the portal: `NETPORTAL_LISTEN=127.0.0.1:18080 $NETPORTAL_BIN serve`, `/metrics` on
  `127.0.0.1:18090`;
* FreeRADIUS at 10.199.0.10, built from `radius/Dockerfile` (the production configuration);
* the fake access point at 10.199.0.11: stock FreeRADIUS with `integration/fake-nas` as the
  Disconnect receiver (RFC 5176, an independent check of the portal's packets; it signs its
  replies with a Message-Authenticator, as hostapd does, and answers a NAK with Error-Cause 503
  for an `Acct-Session-Id` starting with `gone-`) and radclient for accounting; eapol_test runs
  in throwaway containers (`integration/client/Dockerfile`) at 10.199.0.20.

`integration/e2e.py <run dir>` then plays residents, apps and admins. It reaches the registry
through the schema of `migrations/` (and `radius.*`, `docs/RADIUS_CONTRACT.md`), runs
`$NETPORTAL_BIN offboard` and `init-db`, reads a Passpoint download the way Android's installer
does (a port of AOSP's `ConfigParser`), and builds the forged Disconnect-Request (wrong secret,
which the access point must drop) itself. The reconciliation case pauses the fake access point
(`docker pause`) during a revocation, so its Disconnect is lost, then runs the sidecar
(`$NETPORTAL_BIN offboard --every 3600` with `NETPORTAL_DISCONNECT_RECHECK_S=2`, the offboarding
itself off) until it has cut the session, and reads the access point's log for the requests it
got. The foreign and root-signed traps are registered for
the device ids their CNs name, so only the issuer checks stand in their way (logged as
`bad_chain`).

## `radius/`: FreeRADIUS against the registry, no portal

`run.sh` needs no portal. It:

1. builds `netportal` (`cargo build -p netportal`) and the certificate tool
   `tests/radius/certs` (its own small Cargo workspace on `netportal-pki`, target
   `target/radius-test-certs`, lock file seeded from `Cargo.lock`). If the binary does
   not build, it says so and uses `MIGRATE=psql`;
2. runs the CA ceremony (`netportal pki`, or the same `ceremony::command` through the tool) and
   issues the device certificates with `netportal_pki::pki::device_cert`: alice's (VLAN 30),
   fia's and carol's (guests, VLAN 50), a renewal of the same device, an unregistered one, one
   from a foreign root and device CA with the same names, one the root signed directly, and one
   whose serial is registered for another device;
3. starts PostgreSQL (the image of `tools/test-db.sh`, started directly because the
   outage case stops and starts it: test-db.sh's container is `--rm`), creates the role radius,
   migrates with `netportal init-db` (`MIGRATE=psql`: `migrations/*.sql` in order and
   `sql/radius_grants.sql` with psql, plus the seeds);
4. builds FreeRADIUS from `radius/Dockerfile` (`RT_RADIUS_IMAGE=<image>` tests another
   image) and starts the access point container (`tests/integration/client`: eapol_test and
   radclient) on the Docker network `netportal-rt` (10.198.0.0/24, next to the integration
   suite's 10.199.0.0/24), PostgreSQL on 127.0.0.1:17432;
5. runs `radius_test.py`: devices and credentials written with registry.rs's SQL
   (`create_device`, `add_credential` with its overlap, `revoke`), then the RADIUS cases of
   `integration/e2e.py` with its check names and expected values: valid per VLAN,
   Session-Timeout, Acct-Interim-Interval, Class logged with device/MAC/BSSID/SSID/serial,
   radius_session and first_seen, device_mac windows and mac_claims, revoked, renewal overlap and
   retired, expired, unknown_cert and its repeat row (`tries` 2), no_cert, not_eap, foreign CA
   and root-signed (bad_chain, not attributed), a serial registered for another device
   (bad_chain); accounting Start/Interim/Stop with Class, gigawords, mac_window, none,
   Accounting-On, the device's sessions; the database side of the presence checks (roam, a Stop
   before its Start, repeated Stop and late Interim, measured interval per session and NAS,
   Accounting-Off); the radius role (reads `radius.valid_cert`, nothing in public, no direct
   writes, may call `radius.reject` and `radius.cert_status`, not `np_mac` /
   `np_device_for_mac`, no CREATE in its schema); the two pools; logging blocked (tables locked:
   accepted without Class in time, unregistered rejected, ten at once all in); logging functions
   revoked (accepted, rejected, accounting answered, nothing logged) and restored by the
   migration step; database down (nobody in, accounting answered, back in afterwards); no TLS
   session resumption (TLS 1.3 and 1.2: a re-authentication is a full handshake, no session
   ticket; eapol_test `-r1`).

Mutation checks with `RT_RADIUS_IMAGE`: without `check_cert_issuer` the two root-signed checks
fail; with `virtual_server` moved into `tls-config` (README lesson 1) every valid device is
rejected by post-auth's guard (nothing gets in without a registry decision) and the run fails;
with `cache { enable = yes }` in `mods/eap` the server sends a TLS 1.3 NewSessionTicket and the
ticket check fails (TLS 1.2 resumption could not be provoked with eapol_test even then, so the
"full handshake" check for 1.2 is the weaker one).
