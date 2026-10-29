# Black-box tests for the Rust port

Two suites that run against either implementation of the portal: the current Python one
(the default) or the Rust binary, and one RADIUS-level test of the Rust registry with the Rust
FreeRADIUS configuration (`rust/radius/`). All sit in `rust/tests/` and change nothing outside
it.

| Suite | What it is | Command |
|---|---|---|
| `contract/` | 188 black-box tests (686 assertion call sites, many inside loops and subtests) over HTTP, the mock IdP, a fake access point (UDP Disconnect) and the CLI | `rust/tests/contract/run.sh` |
| `integration/` | the whole-path test: for Python the EXISTING `tests/integration/e2e.py` unchanged (116 checks: EAP-TLS through the production FreeRADIUS config, accounting, presence, the radius role's grants, fail-closed); for Rust its schema-adapted copy `e2e_rust.py` with `rust/radius/` | `rust/tests/integration/run.sh` |
| `radius/` | FreeRADIUS (`rust/radius/`) against a database migrated by the Rust binary, no portal: 72 checks: the RADIUS cases of e2e.py (decisions, logged reasons, Class, sessions, accounting, the radius role, the pools, logging blocked or revoked, database down), the certificate-identity binding and no TLS session resumption (security review 2026-10-29) | `rust/tests/radius/run.sh` |

## Running

```sh
rust/tests/contract/run.sh                                   # against Python (gunicorn netportal.wsgi:app)
IMPL=rust NETPORTAL_BIN=rust/target/release/netportal rust/tests/contract/run.sh
CT_ARGS="test_letswifi test_login.LogoutTests" rust/tests/contract/run.sh   # only some tests
KEEP=1 rust/tests/contract/run.sh                            # leave PostgreSQL, IdP and portals running

rust/tests/integration/run.sh                                # e2e.py against Python
IMPL=rust NETPORTAL_BIN=rust/target/release/netportal rust/tests/integration/run.sh   # e2e_rust.py

rust/tests/radius/run.sh                                     # rust/radius + the Rust registry
MIGRATE=psql rust/tests/radius/run.sh                        # migrate without the binary
python3 rust/tests/contract/selftest_registry_adapter.py     # RustRegistry against the schema
```

After a `KEEP=1` run you can rerun single modules against the running environment:
`cd rust/tests/contract && CT_SUITE=../runs/contract/suite.json python3 -m unittest test_api -v`.
To tear it down, stop the two gunicorn/serve processes on 28080/28081 and `mock_idp.py`, then
`docker rm -f netportal-ct-pg`.

Results on 2026-10-28 against Python (netportal `372b8c0` + working tree):

* contract: `Ran 172 tests in 53.5s, OK (expected failures=7)`, 59 s wall time;
* integration: `116` ok lines, `0 failure(s)`, about 2 minutes.

Results on 2026-10-29 with the Rust web port (`netportal serve`, debug build):

* contract, `IMPL=rust CT_SCHEMA=rust`: `Ran 174 tests in 87.5s, OK` (every deviation test passes);
* contract against Python: `Ran 174 tests in 52.2s, OK (expected failures=9)`.

After the fixes of the security review of 2026-10-29 (debug build):

* contract, `IMPL=rust CT_SCHEMA=rust`: `Ran 188 tests in 40.6s, OK`;
* contract against Python: `Ran 188 tests in 56.2s, OK (skipped=1, expected failures=22)` (the
  skip: `test_offboarding.test_a_mass_removal_is_held_back`, which would offboard every person of
  the suite against Python);
* radius: 72 ok, `0 failure(s)`;
* integration, `IMPL=rust`: 117 ok, `0 failure(s)`.

Both scripts were also run with `IMPL=rust` and a stand-in binary that hands each command to
Python (2026-10-28, before the Rust schema was wired in). The contract suite then fails exactly
the 7 marked deviations (8 subtests) and passes everything else. The integration suite passed
all 116 checks then; since `IMPL=rust` runs `e2e_rust.py` against `rust/radius/` and the Rust
schema, a stand-in on the Python schema no longer passes it. A real Rust run waits for the web
crate (below).

Requirements, all present on this machine: Docker; `python3` with `requests`, `psycopg` (3),
`cryptography`; `lxml` (optional, for the eap-config XSD check); the `openssl` CLI (3.x); `ss`
(iproute2) and `curl`. For `IMPL=python` you also need the portal's own packages. On CachyOS these
are `python-flask python-authlib python-psycopg python-prometheus_client python-itsdangerous
gunicorn python-cryptography python-lxml python-requests` (netportal README). The contract suite's
fixture PKI and the integration test's helper imports (`pki` for the trap certificates,
`disconnect`) use the Python `netportal` package as test tooling in both modes; the
integration suite's PKI comes from `$NETPORTAL_BIN pki` for IMPL=rust, and `rust/tests/radius/`
uses the Rust PKI only (plus `cargo`). The XSD is read from `poc/runs/eap-metadata.xsd`, which `tests/test_profiles.py`
fetches. If the file is missing, that one test is skipped.

### What the Rust binary must offer

* `netportal serve` listens on **`NETPORTAL_LISTEN`** (`host:port`, default `127.0.0.1:<port>`;
  the scripts set it to `127.0.0.1:28080`/`28081`, or `18080` for the integration suite), and
  serves `/metrics` on **`NETPORTAL_METRICS_LISTEN`** (`28090`/`28091`, `18090`; the suites read
  it there, `suite.json` `metrics_url`). Every other setting comes from the same `NETPORTAL_*`
  variables as the Python app, including the `*_FILE` variants; the device CA key only as a file
  (`NETPORTAL_DEVICE_CA_KEY`; the scripts give instance A the file for `IMPL=rust`).
* The schema is ready before `/healthz` answers 200.
* An `http://127.0.0.1` OIDC issuer must work. The scripts also set `AUTHLIB_INSECURE_TRANSPORT=1`
  for the Rust binary, which may use or ignore it.
* CLI commands `offboard [--every N]`, `init-db` and `pki --out DIR --name NAME --server-name FQDN`.
  Exit code 0 means success; a failed offboarding round must exit non-zero.
* The portal environment is exact: `env -i` plus `PATH` and `HOME`. Use
  `PORTAL_EXTRA_ENV="RUST_LOG=debug"` for extra variables.

### The registry adapter (no schema in the tests)

The Rust version gets its own database and schema, so the tests never use SQL directly. Setup
and inspection go through `contract/registry_adapter.py`: people, devices, audit actions,
credentials and their RADIUS status, download and OAuth token expiry, grants, and a RADIUS
session as FreeRADIUS records it. The tests observe over HTTP or RADIUS wherever they can.

* `PythonRegistry` implements the adapter for the Python schema.
* `RustRegistry` implements it for the Rust schema (`rust/migrations/`), with the queries of
  `crates/netportal-core/src/registry.rs`: the same method names, arguments and return shapes;
  the RADIUS functions through the schema `radius` (`radius.cert_status`, and `radius.login` as
  the role radius for `radius_session`). Audit actions are returned as the portal stored them
  (registry.rs uses the Python vocabulary: `enrol:<format>`, `renew`, `revoke`,
  `disconnect:<result>`, `policy:<name>`). Its docstring lists the column differences.
  `contract/selftest_registry_adapter.py` checks every adapter function against a database
  migrated by the binary (`rust/tools/test-db.sh`, no portal; 4 tests, about 4 s;
  `NETPORTAL_TEST_DATABASE_URL` reuses a running server). It is not collected by `run.sh`.
* `CT_SCHEMA=python|rust` chooses the adapter. The default is the implementation under test.

### Known Python deviations

Where Python has a quirk or bug, the test asserts the intended behaviour and carries
`@python_known_deviation("reason")`. Against Python such a test is an expected failure; if it
unexpectedly passes, the run fails, so the marker cannot go stale. Against Rust it is a normal
test. `rust/docs/PARITY.md` should list the same items as deliberate deviations.

| Test | Intended behaviour | What Python does |
|---|---|---|
| `test_artefacts.AppleTests.test_profile_identifier_is_reverse_dns_of_the_realm` | PayloadIdentifier is reverse DNS of the realm (`org.scharni.…`) | `org.org.scharni.network.<id>`: the prefix is `"org." + reversed realm` (INVENTORY 6.5, R4) |
| `test_letswifi.AuthorizeTests.test_unsupported_response_type` | `response_type` other than `code` redirects with `error=unsupported_response_type` (RFC 6749 4.1.2.1) | `error=invalid_request` |
| `test_letswifi.TokenTests.test_grant_type_missing_or_not_for_this_client` | a missing or empty `grant_type` is `invalid_request`; the mobile app's `refresh_token` grant is `unauthorized_client` (RFC 6749 5.2, 3.1) | `unsupported_grant_type` for both (added with the Rust web port, split from `test_unsupported_grant_type`) |
| `test_letswifi.EapConfigEndpointTests.test_401_names_the_bearer_scheme` | a 401 from `/api/eap-config/` carries `WWW-Authenticate: Bearer` (RFC 6750 3) | no `WWW-Authenticate` header |
| `test_letswifi.EapConfigEndpointTests.test_auth_scheme_is_case_insensitive` | `bearer <token>` is accepted (RFC 9110 11.1) | only the exact prefix `Bearer ` |
| `test_login.LoginTests.test_id_token_without_sub_is_refused` | an ID token without `sub` is a failed login (4xx page) | **500**: Authlib raises a JOSE `MissingClaimError`, which is not an `OAuthError` |
| `test_routes.MethodTests.test_405_json_has_allow` | every 405 has an `Allow` header (RFC 9110 15.5.6) | the JSON 405 under `/api/` drops it (the HTML 405 has it) |
| `test_config.StartupTests.test_device_ca_key_only_from_a_file` | a device CA key in the environment (`NETPORTAL_DEVICE_CA_KEY_B64`) stops the start | accepted |
| `test_config.RegistryOutageTests.test_anonymous_pages_need_no_registry` | `/welcome`, `/` (to the login), static files and an anonymous API call (401) work without the registry | 500: a connection per request, first |
| `test_api.PolledApiTests.test_polled_answers_are_not_stored` | `Cache-Control: private, no-store` (200 and 304) | `private, no-cache` |
| `test_routes.RouteAuthTests.test_metrics_are_not_on_the_public_listener` | the portal's port answers 404 for `/metrics` (its own listener serves it) | served on the public port |
| `test_login.LoginTests.test_a_foreign_callback_keeps_the_session` | a replayed or forged `/auth/callback` is a 400 and the session stays | the session is cleared (forced logout by any site) |
| `test_offboarding.OffboardingTests.test_losing_admin_ends_the_portal_sessions` | a round that takes the admin right away ends the person's portal sessions | the session stays (without the right) |
| `test_offboarding.OffboardingTests.test_two_rounds_before_a_removal` | the first round without access only notes it; the second offboards | the first round offboards |
| `test_letswifi.AuthorizeTests.test_consent_page_names_the_app_and_its_target` | the consent page names the app and the redirect target | it does not |
| `test_letswifi.TokenTests.test_a_replayed_code_revokes_the_certificate_it_produced` | a replayed code revokes the device (certificate) with a Disconnect | only the grant |
| `test_letswifi.TokenTests.test_a_replayed_refresh_token_revokes_the_device` | the same for a replayed refresh token | only the grant |
| `test_letswifi.EapConfigEndpointTests.test_one_eap_config_per_access_token` | a second eap-config with the same access token is a 401 | any number of certificates per token |
| `test_letswifi.EapConfigEndpointTests.test_a_quick_reissue_retires_the_previous_certificate` | a re-issue within an hour retires the previous certificate at once | the overlap (2 days) |
| `test_devices.LimitTests.test_enrolment_rate` | the 11th new device within an hour is a 429 | no limit |
| `test_routes.MethodTests.test_eap_config_without_trailing_slash` | an app's `POST /api/eap-config` (no slash) reaches the endpoint: a 308 to the slash URL, or served there | 401 `login_required`: the stale-script rule (3.1) runs before routing's 308. The 308 that INVENTORY 3 describes only comes for a logged-in browser that sends a CSRF token. `GET /api/eap-config` is 404 |

### Deliberately not pinned (Python accidents)

The tests do not pin these:

* the session cookie's name over plain http; `Expires` before the login;
* float spelling and rounding; `isoformat` spelling (any RFC 3339 timestamp is accepted);
* the trailing `?` Werkzeug adds to return-to paths;
* the healthz Content-Type;
* `OPTIONS` handling, beyond "if answered with 2xx, `Allow` lists the methods";
* whether `invalid_client` is a 400 or a 401;
* the exact PKCS#12 iteration counts;
* the PPS MO and eap-config byte serialisation (XML declaration, ASCII escaping);
* prometheus-client's `*_created` series, HELP texts and the `0.0.4` version parameter;
* the order of the CSRF check versus the 405.

## Artefact constraints and their sources (`test_artefacts.py`)

| Artefact | Constraint asserted | Source |
|---|---|---|
| Apple `.mobileconfig` | Configuration profile with Root, PKCS#12 identity and Wi-Fi payloads (and Ethernet for macOS only: iOS refuses it); unique upper-case UUIDs; EAP-TLS only (`AcceptEAPTypes [13]`); pinned `TLSTrustedServerNames`; anchor = the root; outer identity `anonymous@realm`; TLS ≥ 1.2; PayloadIdentifier stable per device across renewals (iOS/macOS replace by identifier) | Apple Configuration Profile Reference (Wi-Fi, EAPClientConfiguration, Certificate payloads) |
| Apple PKCS#12 | MAC HMAC-SHA1; bags encrypted with `pbeWithSHA1And3-KeyTripleDES-CBC`; no PBES2; key shrouded; readable without OpenSSL's legacy provider | SecPKCS12Import on the iOS/macOS versions in use refuses OpenSSL 3's defaults (PBES2/AES-256-CBC with an HMAC-SHA256 MAC: "MAC verification failed" on releases before 2024). This is why netportal chose 3DES (`netportal/profiles.py:50-52`) |
| Android Passpoint | base64 body; MIME multipart with `application/x-passpoint-profile`, `application/x-x509-ca-cert` (the root), `application/x-pkcs12`, each base64; no `Content-Disposition`; `Content-Transfer-Encoding: base64` | AOSP `ConfigParser.parseMimeMultipartMessage` (hotspot2); source.android.com "Passpoint R1 provisioning" |
| Android PKCS#12 | opens with an EMPTY password, MAC included | AOSP loads it with `KeyStore.load(in, new char[0])` |
| PPS MO | `MgmtTree`, `PerProviderSubscription` with DDF name `urn:wfa:mo:hotspot2dot0-perprovidersubscription:1.0`; HomeSP FriendlyName and FQDN = realm; Credential Realm, DigitalCertificate x509v3 with the SHA-256 fingerprint of the client certificate | Wi-Fi Alliance Hotspot 2.0 PPS MO; AOSP `PpsMoParser` |
| eap-config | GÉANT CAT `eap-metadata.xsd` valid; EAP type 13; CA = root; ServerID; OuterIdentity; PKCS#12 opens with its Passphrase; SSID; MinRSNProto CCMP; ValidUntil = the certificate's notAfter | GÉANT CAT / geteduroam apps |
| Device certificates | `CN=<device id>@<realm>` only (no personal data); issued by the device CA (FreeRADIUS `check_cert_issuer`); EC P-256/P-384 or RSA ≥ 2048 with SHA-2; not a CA; critical KeyUsage digitalSignature; EKU clientAuth (no serverAuth); AKI = the CA's SKI; serial positive, 64–159 bits, unique; validity `NETPORTAL_CERT_DAYS` | RFC 5280; EAP-TLS (RFC 5216) |
| `pki` output | file names and permissions as house-infra and FreeRADIUS read them; root CA pathlen 1, device CA pathlen 0 with DN `CN=<name> Device CA`; chain file = device CA + root; server certificate with serverAuth, a DNS SAN and at most 825 days | Apple's TLS server certificate rules (iOS 13 / macOS 10.15); `radius/mods/eap` |

## What each test covers

Each test names its inventory section in its own docstring or in its class docstring.
Section numbers refer to `rust/docs/INVENTORY.md`.

| Module.Class (tests) | INVENTORY | What is asserted |
|---|---|---|
| `test_routes.RouteAuthTests` (9) | 3.2 auth column, 3.6, 4.3 | every route of 3.2 for anonymous, resident, admin and refused users: 302 `/login`, 401 `login_required`, 403 page / `forbidden`, 404 for other people's devices on every device route, UUID matching |
| `test_routes.MethodTests` (6) | 3 (HEAD, OPTIONS, trailing slash), 3.6 | HEAD without a body, OPTIONS `Allow`, 405 with `Allow` (page and JSON), `/api/eap-config` without the slash (deviation) |
| `test_routes.ErrorResponseTests` (3) | 3.6, 4.7 | message page versus `{"error": …}` JSON per status |
| `test_session.CookieTests` (9) | 4.1 | HttpOnly, SameSite=Lax, Path=/, no Domain, not Secure over http; https: `__Host-` and Secure; 8 h idle expiry after login, renewed on use; rotation at login; no fixation; tampered cookie refused; bound to the secret; one CSRF token per session (≥ 128 bits) |
| `test_session.CsrfTests` (8) | 4.2, 3.1 | missing, wrong or foreign token gives 400 (page and JSON); header tokens do not count; a stale script POST gets 401 before the CSRF check; the `Accept` rule; exempt endpoints; logout |
| `test_login.LoginTests` (11) | 4.4, 4.3 | authorization request (code, PKCE S256, state, nonce, scopes, redirect URI); person recorded; policy and admin from the groups; legacy single policy; refused without a policy or groups; missing `sub` (deviation); claim fallbacks; replayed, cancelled and wrong-state callbacks give 400 and end the session; a new login clears `offboarded` |
| `test_login.ReturnToTests` (6) | 4.4 return-to | GET with its query, device page, download, consent POST rebuilt as the authorize URL, `back=/admin`, other POSTs go to `/`, and `/` sets no target |
| `test_login.LogoutTests` (3) | 3.2 row 3, 4.4 | to `NETPORTAL_LOGOUT_URL` or `/`; the session ends |
| `test_login.RegistryRightsTests` (5) | 4.3 | admin granted or taken in the registry between requests; offboarded or deleted person ends the session at the next request (the CSRF token survives); admin powers over other people's devices |
| `test_devices.EnrolTests` (5) | 3.2 row 7, 4.6 | each format; token ≥ 256 bits, about 10 minutes; default names; name stripped and cut to 60; bad formats 400; Passpoint off; recommended format per User-Agent |
| `test_devices.DownloadTests` (8) | 4.6, 6.4 | Content-Type, file names (ASCII, default `Wi-Fi`), Passpoint framing, no-store; one-time; someone else's token refused and not used up; expired; revoked device; a new certificate per download, known to the registry |
| `test_devices.RenewTests` (2) | 3.2 row 8, 6.2 | same device, new serial, overlap `NETPORTAL_RENEW_OVERLAP_DAYS` (2 and 5); revoked or foreign gives 404 |
| `test_devices.RenameTests` (2) | 3.2 row 10 | form and JSON variants, empty name, 60-character cut |
| `test_devices.RevokeTests` (7) | 3.2 row 11, 7.1 | Disconnect-Request checked by an independent RFC 5176/3579 implementation (authenticators, User-Name, Calling-Station-Id, NAS-IP-Address, Event-Timestamp); ack, nak, no-session and timeout (retransmissions with the same identifier); RADIUS status revoked; metrics; `back` |
| `test_artefacts.CertificateTests` (3) | 6.1, 6.2 | device certificates of every format and both instances (see the table above) |
| `test_artefacts.AppleTests` (4) | 6.3, 6.5 | profile structure (iOS, macOS, non-ASCII SSID); PKCS#12 readable by Apple; identifier stable; reverse DNS (deviation) |
| `test_artefacts.PasspointTests` (3) | 6.3, 6.6 | installer layout, PPS MO values and fingerprint, FQDN kept on renewal |
| `test_artefacts.EapConfigTests` (2) | 6.7 | values on both instances, XSD |
| `test_letswifi.DiscoveryTests` (2) | 3.2 row 26, 3.5 | `/.well-known/letswifi.json` (base URL normalised), the `Accept: application/json` probe of `/` |
| `test_letswifi.AuthorizeTests` (9) | 3.5, 4.5, 3.4 | consent page and its `form-action`; unknown client or redirect gives 400 with no Location; loopback rules (RFC 8252: any port and path, never localhost); error redirects with state; `unsupported_response_type` (deviation); CSRF; code issuance, lifetime ≤ 10 minutes, grant name |
| `test_letswifi.TokenTests` (13) | 3.5 | token response fields, `expires_in` ≤ 3600 matching storage, no-store, hashed storage; refresh tokens only for desktop clients, ≤ 400 days; invalid_client, invalid_grant (verifier, client, redirect, expiry, 42-character verifier), unsupported_grant_type, invalid_request and unauthorized_client (deviation); code reuse revokes the grant; a failed exchange burns the code; refresh rotation; refresh replay revokes the grant; another client's refresh token; offboarded owner |
| `test_letswifi.EapConfigEndpointTests` (9) | 3.5, 6.7 | first call enrols (name, CN, binding, audit, metric); later calls renew with overlap; revoked device stops the tokens; bad, missing or expired bearer; a code is not an access token; WWW-Authenticate and scheme case (deviations); portal renewal points to the app; realm of B |
| `test_api.PolledApiTests` (6) | 3.3 | weak ETag, `private, no-cache`, stable across polls, 304 (strong, weak, `*` and list forms), changes with the data, login checked before the 304, the single-device API |
| `test_api.PayloadTests` (3) | 9.12 | DASHBOARD, DEVICE, HOUSE and HISTORY field names, types, enums, RFC 3339 times, order; `bad_range` |
| `test_api.AdminApiTests` (5) | 3.2 rows 20-25 | owner block, `q` and `state` filters, counts of all devices; incidents, auth (including `²` and `٣`) and raw parameter errors; raw shows revoked devices |
| `test_headers.HeaderTests` (4) | 3.1, 3.4, 4.8, 3.2 row 32 | CSP per response as a directive set (scripts only on dashboard pages, `'self'`); nosniff; Referrer-Policy; Cache-Control; consent `form-action`; downloads; JavaScript MIME type for the ES modules; path traversal |
| `test_metrics.MetricsTests` (4) | 10, 3.2 row 31 | family names and types the alert rules use; label sets; values follow enrolment and revocation; 404 with `X-Forwarded-For` |
| `test_offboarding.OffboardingTests` (11) | 8.1-8.3, 7.1 | inactive, group lost or deleted: offboarded, devices revoked with a Disconnect, app tokens stopped, session ended; moved out (guests VLAN, Disconnect); admin follows the groups; pagination and `include_groups`; strangers ignored; API 500, wrong token, empty directory and unreachable API change nothing (exit ≠ 0, heartbeat still touched); off switch; `--every` |
| `test_config.FileSecretTests` (4) | 2.1, 2.2 | `*_FILE` wins over the plain variables (database URL, session secret, OIDC client secret, DAE secret checked by the fake NAS, Authentik token); device CA key from a file |
| `test_config.StartupTests` (4) | 2.1, 6.1 | missing or invalid settings and a mismatched device CA key stop `serve` (exit ≠ 0); `init-db` checks its settings (the database URL: the Rust `init-db` reads only the registry's settings) |
| `test_config.InitDbTests` (1) | 1.1 | `init-db` on an empty database, twice; policies seeded |
| `test_config.RegistryOutageTests` (1) | 1.3, 3.2 rows 30-31, 10 | database down: `/healthz` and pages give 5xx, the API a 5xx with a JSON error, `/metrics` shows `netportal_registry_up 0`; recovery without a restart |
| `test_config.PkiTests` (1) | 6.1 | the ceremony's files, permissions and certificates |

Set-up of the contract suite (`contract/run.sh`):

* PostgreSQL 18 (Docker) at `127.0.0.1:25432`, one database per instance.
* The mock IdP `contract/mock_idp.py` at `127.0.0.1:29000`. It imports
  `tests/integration/mock_authentik.py` by path and adds a directory separate from the login
  user, pagination, failure modes, a request log and claims that can be left out.
* Two portal instances:
  * **A**, `127.0.0.1:28080`: plain variables, http, Passpoint on, `NETPORTAL_POLICIES`, logout URL.
  * **B**, `127.0.0.1:28081`: every secret in a `*_FILE` (the plain variables are set to wrong
    values), device CA key file, https base URL with a trailing slash, legacy single policy,
    Passpoint off, default display name, non-ASCII SSID, realm `house.example.net`,
    `CERT_DAYS=30`, `RENEW_OVERLAP_DAYS=5`. For `IMPL=rust` the legacy single policy becomes
    the equivalent `NETPORTAL_POLICIES=residents=40:residents,staff`, and the wrong plain values
    next to the `*_FILE` secrets are left out: the Rust settings have no legacy policy and refuse
    a secret set both ways (`rust/docs/PARITY.md`, settings).
* The fake access points (`contract/fake_nas.py`) run inside the test process on UDP
  `127.0.0.1:23799` (A) and `:23798` (B), so the tests can read what they received.
* Extra instances started by tests use ports 28083 and 28084.

## What is not black-box testable here, and why

* **8 h idle and 12 h absolute session limits on the server.** The Python app has no clock
  control, and a test cannot age a signed cookie. What is tested: the cookie's 8 h expiry after
  login and its renewal on use. Not tested: the server refusing a session idle for 8 h, and the
  12 h limit after `login_at`. Possible ways: a test-only `NETPORTAL_SESSION_MAX_SECONDS` in the
  Rust version, or an `LD_PRELOAD` clock shim that would work for both.
* **Logging rules (4.9)**: no tokens, keys or user agents in the logs. Possible as a log scan of
  `rust/tests/runs/contract/portal-*.log`, but not done: the tokens are spread over many tests.
* **The sidecar's `netportal_offboarded_devices_total`.** The offboarding process exposes no
  endpoint.
* **Telemetry with Prometheus or Loki, and the collector (`collect`, `job`).** Neither suite
  has a Prometheus or Loki fake, so the dashboards run with telemetry `off`. The fakes in
  `tests/fakes/` could be wired in: they answer by exact PromQL text, which the Rust version may
  change.
* **Real installs on iPhone, Mac and Android.** Only the platforms' documented constraints are
  checked. The integration suite authenticates eapol_test with the extracted certificates.
* **HTML beyond the contract strings** (texts, the template-side admin filters), other
  languages, and concurrency or timing (single worker versus async).
* **The Disconnect `error` result** (an IPv6 NAS address) and `skipped` (no DAE secret): not
  exercised; it would need a third instance.

## `rust/tests/integration/run.sh` versus `tests/integration/run.sh`

The script header lists every difference:

1. How the portal starts (gunicorn, or `NETPORTAL_LISTEN=127.0.0.1:18080 $NETPORTAL_BIN serve`).
2. The test starts through `e2e_impl.py`: IMPL=python runs `tests/integration/e2e.py` unchanged,
   IMPL=rust runs `e2e_rust.py`.
3. The run directory is `rust/tests/runs/integration`.
4. It checks that the ports and the Docker network are free, and stops if `/healthz` never
   answers.
5. There is no `IMAGES=1`.
6. IMPL=rust: FreeRADIUS from `rust/radius/Dockerfile`, the PKI from `$NETPORTAL_BIN pki`.
7. IMPL=rust: a session secret of at least 32 bytes (the Rust portal refuses shorter ones).

`e2e_rust.py` is `tests/integration/e2e.py` with only the schema and CLI access changed; its
header lists the five differences (column names; `issued_at` moved with the expired case; the
schema `radius`; registry.rs's queries for `mac_claims`, `device_windows`, `acct_sessions` and
`init-db` for the migrate; `$NETPORTAL_BIN offboard`), each changed line is marked
`difference N`, and every check keeps its name and meaning. It was generated from e2e.py by
exact replacements, so `diff tests/integration/e2e.py rust/tests/integration/e2e_rust.py`
shows nothing else.

State on 2026-10-29: IMPL=python passes (see above). IMPL=rust stops at the start: the binary's
`serve` exits with "serve is not ported yet" (the web crate is being written), so no check
runs. The RADIUS half of e2e_rust.py (the same queries and expected values) passes in
`rust/tests/radius/`.

## `rust/tests/radius/`: FreeRADIUS against the Rust registry

`run.sh` needs no portal. It:

1. builds `netportal` (`cargo build -p netportal`) and the certificate tool
   `rust/tests/radius/certs` (its own small Cargo workspace on `netportal-pki`, target
   `rust/target/radius-test-certs`, lock file seeded from `rust/Cargo.lock`). If the binary does
   not build, it says so and uses `MIGRATE=psql`;
2. runs the CA ceremony (`netportal pki`, or the same `ceremony::command` through the tool) and
   issues the device certificates with `netportal_pki::pki::device_cert`: alice's (VLAN 30),
   fia's and carol's (guests, VLAN 50), a renewal of the same device, an unregistered one, one
   from a foreign root and device CA with the same names, and one the root signed directly;
3. starts PostgreSQL (the image of `rust/tools/test-db.sh`, started directly because the
   outage case stops and starts it: test-db.sh's container is `--rm`), creates the role radius,
   migrates with `netportal init-db` (`MIGRATE=psql`: `rust/migrations/*.sql` in order and
   `rust/sql/radius_grants.sql` with psql, plus the seeds);
4. builds FreeRADIUS from `rust/radius/Dockerfile` (`RT_RADIUS_IMAGE=<image>` tests another
   image) and starts the access point container (`tests/integration/client`: eapol_test and
   radclient) on the Docker network `netportal-rt` (10.198.0.0/24, next to the integration
   suite's 10.199.0.0/24), PostgreSQL on 127.0.0.1:17432;
5. runs `radius_test.py`: devices and credentials written with registry.rs's SQL
   (`create_device`, `add_credential` with its overlap, `revoke`), then the RADIUS cases of
   e2e.py with e2e.py's check names and expected values: valid per VLAN, Session-Timeout,
   Acct-Interim-Interval, Class logged with device/MAC/BSSID/SSID/serial, radius_session and
   first_seen, device_mac windows and mac_claims, revoked, renewal overlap and retired,
   expired, unknown_cert and its repeat row (`tries` 2), no_cert, not_eap, foreign CA and
   root-signed (bad_chain, not attributed); accounting Start/Interim/Stop with Class,
   gigawords, mac_window, none, Accounting-On, the device's sessions; the database side of the
   presence checks (roam, a Stop before its Start, repeated Stop and late Interim, measured
   interval per session and NAS, Accounting-Off); the radius role (reads `radius.valid_cert`,
   nothing in public, no direct writes, may call `radius.reject` and `radius.cert_status`, not
   `np_mac` / `np_device_for_mac`, no CREATE in its schema); the two pools; logging blocked
   (tables locked: accepted without Class in time, unregistered rejected, ten at once all in);
   logging functions revoked (accepted, rejected, accounting answered, nothing logged) and
   restored by the migration step; database down (nobody in, accounting answered, back in
   afterwards).

Result on 2026-10-29: `65` ok lines (63 checks, plus the migration and the healthcheck), `0 failure(s)`, about 75 s, with `netportal init-db` and with `MIGRATE=psql`. Mutation checks with
`RT_RADIUS_IMAGE`: without `check_cert_issuer` the two root-signed checks fail; with
`virtual_server` moved into `tls-config` (README lesson 1) every valid device is rejected by
post-auth's guard (nothing gets in without a registry decision) and the run fails.

After the security review of 2026-10-29: `72` ok lines, `0 failure(s)`, with the new checks "a
certificate whose serial is registered for another device (its CN names a different one) cannot
connect" (plus its logged reason and that the tablet itself still connects; the foreign and
root-signed traps are now registered for the devices their CNs name, so only the issuer checks
stand in their way), and "TLS 1.3 / TLS 1.2: a re-authentication is a full handshake (no session
resumption)" and "... the server hands out no session ticket" (eapol_test `-r1`). Mutation check:
with `cache { enable = yes }` in `mods/eap` the server sends a TLS 1.3 NewSessionTicket and the
ticket check fails; TLS 1.2 resumption could not be provoked with eapol_test even then (the
"full handshake" check for 1.2 is the weaker one).
