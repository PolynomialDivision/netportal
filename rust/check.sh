#!/usr/bin/env bash
# Everything a change must pass: formatting, clippy (warnings are errors), all tests, and the
# supply-chain checks cargo-deny (licenses, bans, advisories, sources: deny.toml) and cargo-audit
# (RustSec advisories: .cargo/audit.toml) when they are installed
# (cargo install --locked cargo-deny cargo-audit).
#
#   ./check.sh            the database tests run against $NETPORTAL_TEST_DATABASE_URL, or a
#                         throwaway PostgreSQL started here (Docker) and removed afterwards
#   ./check.sh --no-db    without the database tests (they skip with a message)
set -euo pipefail
cd "$(dirname "$0")"

cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings

if [ "${1:-}" = "--no-db" ]; then
    unset NETPORTAL_TEST_DATABASE_URL
elif [ -z "${NETPORTAL_TEST_DATABASE_URL:-}" ]; then
    if started="$(tools/test-db.sh)"; then
        eval "$started"
        trap 'tools/test-db.sh stop "$NETPORTAL_TEST_DB_CONTAINER"' EXIT
    else
        echo "note: no throwaway PostgreSQL (Docker missing?): the database tests are skipped" >&2
    fi
fi

cargo test --workspace

if cargo deny --version >/dev/null 2>&1; then
    cargo deny check
else
    echo "note: cargo-deny is not installed (cargo install --locked cargo-deny): licenses, bans, advisories and sources not checked" >&2
fi

if cargo audit --version >/dev/null 2>&1; then
    cargo audit --deny warnings
else
    echo "note: cargo-audit is not installed (cargo install --locked cargo-audit): RustSec advisories not checked" >&2
fi
