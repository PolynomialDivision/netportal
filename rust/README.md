# netportal in Rust

The Rust version of netportal (the house's network access portal). Decisions:
`docs/ARCHITECTURE.md`; the Python version's behaviour: `docs/INVENTORY.md`; what is ported and
what deliberately differs: `docs/PARITY.md`; the FreeRADIUS contract: `docs/RADIUS_CONTRACT.md`.

## Build and test

```sh
cd rust
cargo build --workspace                   # debug build; the binary is target/debug/netportal
cargo build --release -p netportal        # target/release/netportal
./check.sh                                # fmt, clippy -D warnings, all tests (+ cargo deny if installed)
./check.sh --no-db                        # the same without the database tests
```

`check.sh` runs `cargo deny check` (`deny.toml`) and `cargo audit` (`.cargo/audit.toml`) when
they are installed (`cargo install --locked cargo-deny cargo-audit`); the advisories ignored on
purpose are listed in both with the reason.

The production image (`Dockerfile`, from the repository root; house-infra builds it from a git
context): `docker build -f rust/Dockerfile -t netportal-rust .`. The cutover: `docs/CUTOVER.md`.

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

Translations: `crates/netportal-core/i18n.json` is generated from `netportal/i18n.py`:

```sh
python3 tools/export_i18n.py              # after changing netportal/i18n.py
```

A unit test fails when the file is out of date (it runs `python3`; without it, it skips). The
few texts only the Rust version has are in `crates/netportal-core/i18n_rust.json` (by hand, every
language; merged at load, and a test refuses a key that `i18n.json` has too).

## Layout

| Path | What |
|---|---|
| `Cargo.toml` | the workspace; every dependency of the project in `[workspace.dependencies]` |
| `crates/netportal-core` | settings (`config`), database connection and the web's pool (`db`), registry and migrations (`registry`), translations (`i18n`), number and time conventions (`conventions`), log format (`logging`) |
| `crates/netportal-pki` | PKI, issuing, artefacts, RADIUS Disconnect (Python `pki.py`, `enroll.py`, `profiles.py`, `disconnect.py`) |
| `crates/netportal-telemetry` | telemetry, presence, diagnostics (Python `telemetry/`, `presence.py`, `diagnostics.py`) |
| `crates/netportal-collect` | the collector (Python `collect/`) |
| `crates/netportal-offboard` | the offboarding (Python `offboarding.py`) |
| `crates/netportal-web` | routes, sessions, OIDC, Let's Wi-Fi, limits, templates, static files, `/metrics` on its own listener (Python `web.py`, `metrics.py`) |
| `crates/netportal` | the binary `netportal` (Python `__main__.py`, `wsgi.py`) |
| `migrations/` | the schema, applied in order by `registry::migrate` (`NNNN_name.sql`; never edit an applied one) |
| `sql/radius_grants.sql` | the FreeRADIUS role's rights, applied after every migration run |
| `tools/test-db.sh`, `tools/export_i18n.py` | test database, translation export |
| `docs/` | architecture, inventory, parity, RADIUS contract |

## Conventions for the code

- Settings come from `netportal_core::config` (one loader per process); secrets are
  `config::Secret`, never logged.
- Database access goes through `netportal_core::Db` and the functions of `registry`: writing
  functions leave the transaction open, the caller commits (`db.commit()`), as the Python code
  did. Statements are never logged. The web takes its connections from one `netportal_core::Pool`
  per process (`App::registry`, the `Reg` extractor), only in handlers that need one and after
  the cheap checks; pooled connections never change session state (`Db::autocommit` refuses).
- Times in JSON: `conventions::rfc3339`; display numbers: `conventions::round_to`,
  `i18n::format_number`.
- Log with `tracing` and a target `netportal.<module>` (the logger name in the log line).
- Tests are named after the Python test they port (`test_<python name>`); add rows to
  `docs/PARITY.md` for what you port.
- No `unsafe` (forbidden in the workspace lints), no `unwrap` on external input, clippy clean.
