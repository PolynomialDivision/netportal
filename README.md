# netportal

The house's Wi-Fi onboarding portal and device registry (design: house-infra
`docs/NETWORK-ACCESS.md`; stack: house-infra `stacks/netaccess`). Residents log in with Authentik,
enrol devices with their own EAP-TLS certificate, rename, renew and remove them; FreeRADIUS
decides every Wi-Fi login from the registry.

Written in Rust. Until 578a2ba the portal was a Python (Flask) app; it was replaced by this
port. Where comments and docs say "Python:", they mean that version: `docs/INVENTORY.md`
describes it, `docs/PARITY.md` lists what was ported and what deliberately differs, and
`git show 578a2ba:<path>` shows its code. Decisions: `docs/ARCHITECTURE.md`; the FreeRADIUS
contract: `docs/RADIUS_CONTRACT.md`; telemetry and presence: `docs/TELEMETRY.md`; the production
switch-over: `docs/CUTOVER.md`.

## Build and test

```sh
cargo build --workspace                   # debug build; the binary is target/debug/netportal
cargo build --release -p netportal        # target/release/netportal
./check.sh                                # fmt, clippy -D warnings, all tests, cargo deny, cargo audit
./check.sh --no-db                        # the same without the database tests
node --test tests/js/                     # the dashboard scripts (cross-checked against the Rust formatters)
tests/contract/run.sh                     # black-box: HTTP, database, Disconnect, CLI
tests/integration/run.sh                  # the whole Wi-Fi path on local Docker (portal, FreeRADIUS, eapol_test)
tests/radius/run.sh                       # FreeRADIUS against the registry, without the portal
```

The suites under `tests/` are described in `tests/README.md`.

`check.sh` runs `cargo deny check` (`deny.toml`) and `cargo audit` (`.cargo/audit.toml`) when
they are installed (`cargo install --locked cargo-deny cargo-audit`); the advisories ignored on
purpose are listed in both with the reason. It downloads GÉANT CAT's `eap-metadata.xsd` to
`target/` for the eap-config schema check (skipped without it).

`check.sh` starts a throwaway PostgreSQL in Docker for the database tests (and removes it), unless
`NETPORTAL_TEST_DATABASE_URL` is already set. By hand:

```sh
eval "$(tools/test-db.sh)"                # exports NETPORTAL_TEST_DATABASE_URL (a superuser URL)
cargo test --workspace                    # or: cargo test -p netportal-core --test registry_db
tools/test-db.sh stop                     # remove the container
```

Without `NETPORTAL_TEST_DATABASE_URL` the database tests pass with a "skipped" message (visible
with `-- --nocapture`). The image is the one production runs (`NETPORTAL_TEST_PG_IMAGE`
overrides it). Every crate builds and tests on its own: `cargo test -p <crate>`.

The images (from the repository root; house-infra builds them from a git context):
`docker build -t netportal .` (portal, offboarding, collector, one-shots) and
`docker build -f radius/Dockerfile -t netportal-radius .` (FreeRADIUS).

Translations: `crates/netportal-core/i18n.json` (en, de, uk; every key in every language, the
same placeholders: unit tests check both).

## Layout

| Path | What |
|---|---|
| `Cargo.toml` | the workspace; every dependency of the project in `[workspace.dependencies]` |
| `crates/netportal-core` | settings (`config`), database connection and the web's pool (`db`), registry and migrations (`registry`), translations (`i18n`), number and time conventions (`conventions`), log format (`logging`) |
| `crates/netportal-pki` | PKI, issuing, the per-platform artefacts (Apple profile, Android Passpoint, eap-config), RADIUS Disconnect |
| `crates/netportal-telemetry` | the "My devices" data, presence, diagnostics |
| `crates/netportal-collect` | the collector: UniFi events from Loki, incidents and rollups from Prometheus, retention |
| `crates/netportal-offboard` | reconciliation with Authentik's users API (devices, app grants, portal sessions) |
| `crates/netportal-web` | routes, sessions, OIDC, Let's Wi-Fi (geteduroam apps), limits, templates (`templates/`), static files (`static/`), `/metrics` on its own listener |
| `crates/netportal` | the binary: `serve`, `init-db`, `offboard [--every N]`, `collect [--once] [--jobs a,b]`, `job <name>`, `pki`, `health` |
| `migrations/` | the schema, applied in order by `registry::migrate` (`NNNN_name.sql`; never edit an applied one) |
| `sql/radius_grants.sql` | the FreeRADIUS role's rights, applied after every migration run |
| `radius/` | FreeRADIUS 3.2 configuration and image (EAP-TLS only, registry lookup, logging through its own pool `sql_log`, status server) |
| `Dockerfile` | the portal image (also the offboarding and collector containers) |
| `tests/` | black-box suites (contract, integration, radius) and the dashboard scripts' tests |
| `tools/test-db.sh` | the throwaway test database |
| `docs/` | architecture, inventory of the Python version, parity, RADIUS contract, telemetry, cutover |

## Conventions for the code

- Settings come from `netportal_core::config` (one loader per process); secrets are
  `config::Secret`, never logged.
- Database access goes through `netportal_core::Db` and the functions of `registry`: writing
  functions leave the transaction open, the caller commits (`db.commit()`). Statements are never
  logged. The web takes its connections from one `netportal_core::Pool` per process
  (`App::registry`, the `Reg` extractor), only in handlers that need one and after the cheap
  checks; pooled connections never change session state (`Db::autocommit` refuses).
- Times in JSON: `conventions::rfc3339`; display numbers: `conventions::round_to`,
  `i18n::format_number`.
- Log with `tracing` and a target `netportal.<module>` (the logger name in the log line).
- A change of behaviour against the Python version gets a row in `docs/PARITY.md`.
- No `unsafe` (forbidden in the workspace lints), no `unwrap` on external input, clippy clean.

## FreeRADIUS lessons (3.2)

Three configurations that look right and let every validly signed device in:

1. `virtual_server = check-eap-tls` inside `tls-config` is ignored without a warning; it belongs
   in `eap { tls { … } }`.
2. A condition on a missing attribute is an error and counts as false — also inside `!( … )`.
3. An empty SQL result in an integer attribute becomes `0`, and `&attr` is then true.

So `radius/sites/` grants access only inside an `if` whose test is true; every other path
rejects, and post-auth rejects every Accept that has no registry decision. The radius and
integration suites' "unregistered", "revoked", "expired", "foreign CA" and "root-signed" cases
guard them (a run with `check_cert_issuer` removed fails "root-signed").
FreeRADIUS also reads its TLS key after dropping to the freerad user: `radius/entrypoint.sh`
copies the root-owned secret for it.
