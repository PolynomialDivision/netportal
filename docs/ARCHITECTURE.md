# netportal in Rust: architecture and migration

Decided 2026-10-28. The reference for behaviour is the Python implementation and
`docs/INVENTORY.md` (section numbers below refer to it). The Python code was removed from the
repository after 578a2ba (owner, 2026-10-29); house-infra builds it from its pinned commit until
the Rust version has replaced it in production (section "Cutover").

## Goals and non-goals

Owner, 2026-10-28: hardly anything is rolled out yet, so **do it right, even if devices have to
be enrolled again**. Compatibility with what exists is not a goal in itself.

- Full feature parity: every function of the Python version (pages, APIs, artefacts for every
  platform, Let's Wi-Fi, RADIUS, offboarding, telemetry, collector, admin views, translations,
  metrics) must exist and work. Nothing is dropped.
- Correct over compatible: quirks and bugs of the Python version are fixed, not copied (e.g.
  the Apple PayloadIdentifier `org.org.…`, Python-specific number and time formatting in JSON,
  implicit Flask behaviour). Each such change is listed in `PARITY.md` under "deliberate
  deviations" with the reason.
- A fresh start is allowed: a new database (own name, clean migrations designed for the Rust
  version), a new device CA if that is cleaner, new session and token formats. Residents enrol
  their devices once more at cutover; the geteduroam apps log in once more.
- Kept where other systems depend on it, and changed together with them when that is better:
  the FreeRADIUS contract (`radius/`, same repo), the house-infra stack (env names, container
  names, healthchecks, alert rules on metric names), the URLs residents and apps use.
- Security properties of the Python version are the floor, not the ceiling.
- The Python version stays deployable until cutover (house-infra builds it from a pinned commit
  that has it); it keeps its own database, so rollback is switching back to it (section
  "Cutover").

## Workspace

The repository is a Cargo workspace; one crate per area, so the areas can be built and tested on their
own (and ported in parallel) and the device controller can later be one more crate on top of
`netportal-core`.

| Crate | Python counterpart | Depends on |
|---|---|---|
| `netportal-core` | `config.py`, `registry.py`, `migrations/`, `i18n.py` (data), shared types, time and number conventions (RFC 3339 UTC, explicit rounding; INVENTORY 9.13 for what Python did) | – |
| `netportal-pki` | `pki.py`, `enroll.py`, `profiles.py`, `disconnect.py` | core |
| `netportal-telemetry` | `telemetry/`, `presence.py`, `diagnostics.py` | core |
| `netportal-collect` | `collect/` | core, telemetry |
| `netportal-offboard` | `offboarding.py` | core, pki |
| `netportal-web` | `web.py`, `metrics.py`, templates, static | all of the above |
| `netportal` (binary) | `__main__.py`, `wsgi.py` | all of the above |

One binary, `netportal`, with the Python CLI's subcommands (`serve` instead of gunicorn,
`init-db`, `offboard [--every N]`, `collect [--once] [--jobs a,b]`, `job <name>`, `pki`), so the
three containers keep one image.

## Crates (chosen 2026-10-28)

| Need | Crate | Why |
|---|---|---|
| HTTP server | `axum` 0.8, `tokio`, `tower-http` | the de-facto standard; explicit routing and extractors |
| Templates | `minijinja` | Jinja2 semantics (the templates port with few changes), autoescape like markupsafe |
| PostgreSQL | `sqlx` (runtime-checked queries, no compile-time DB) | async, pooled; builds without a database |
| OIDC client | `openidconnect` | maintained, strict (nonce, PKCE, ID-token validation) |
| X.509, EC keys, PKCS#12 | `openssl` (bindings) | the Python version uses OpenSSL too (`cryptography`), so the legacy PKCS#12 formats (3DES/SHA-1 for Apple, unencrypted with a MAC for Android) come out the same, without the openssl CLI; no own crypto |
| Apple profiles | `plist` | XML plists |
| XML (Passpoint, eap-config) | `quick-xml` | writer with escaping |
| HTTP client | `reqwest` (rustls) | Authentik, Prometheus, Loki |
| Metrics | `prometheus-client` | the same text format |
| Tokens, CSRF, hashes | `rand`, `sha2`, `hmac`, `subtle` | constant-time comparisons |
| Session cookie | `axum-extra` private (encrypted and signed) cookies | stateless like Flask's, the same limits (INVENTORY 4.1) |
| CLI | `clap` | |
| Time | `time` | explicit formatting to match Python's `isoformat` |

## Rules for the port

- Behaviour first: port the Python tests of an area (INVENTORY 14) before or with the code;
  keep their names recognisable (`test_<python name>`).
- The database is the Rust version's own (new migrations under `migrations/`), designed
  from the Python schema: keep what is right, fix what is not, document each change.
- Static files: `crates/netportal-web/static/` (the Python version's, unchanged at the port).
- Translations: one file, `crates/netportal-core/i18n.json` (exported from `netportal/i18n.py`
  at the port, edited by hand since).
- No `unsafe`, no `unwrap` on input, no secrets in logs (INVENTORY 4.9).
- Each crate builds and tests on its own: `cargo test -p <crate>`.

## Tests

- Unit and module tests per crate (ported from the Python tests).
- PostgreSQL tests against a local Docker PostgreSQL (`tools/test-db.sh`), skipped with a
  clear message when Docker is missing.
- Comparison tests: the Python functions generate reference artefacts (certificates, PKCS#12,
  profiles, JSON payloads); the Rust tests compare structure and fields, not random bytes.
- Contract tests (`tests/contract/`): black-box tests over HTTP, the database and RADIUS,
  run against both implementations with the same expectations, plus the existing
  `tests/integration` suite run against the Rust binary.

## Cutover (prepared, not done)

1. house-infra gets an opt-in switch for the netaccess stack (image and commands), default
   Python.
2. The Rust version gets its own database next to the Python one; residents enrol their
   devices again (announced), the old devices keep working until the Python containers stop.
3. Rollback: switch back to the Python image and its untouched database.
