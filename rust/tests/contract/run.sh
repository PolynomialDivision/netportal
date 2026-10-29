#!/usr/bin/env bash
# Black-box contract tests of the portal (rust/tests/README.md): the same suite against the
# Python implementation (default) and the Rust binary.
#
#   rust/tests/contract/run.sh                              IMPL=python: gunicorn netportal.wsgi:app
#   IMPL=rust NETPORTAL_BIN=rust/target/release/netportal rust/tests/contract/run.sh
#   KEEP=1 ...            leave PostgreSQL, the mock IdP and both portals running (ports below)
#   CT_ARGS="test_letswifi" ...   only these test modules/classes (unittest names, space-separated)
#   PORTAL_EXTRA_ENV="RUST_LOG=debug" ...   extra KEY=VALUE pairs for both portal instances
#
# Started here: PostgreSQL 18 (Docker, 127.0.0.1:25432), the mock Authentik
# (tests/integration/mock_authentik.py, extended by mock_idp.py; 127.0.0.1:29000) and two portal
# instances with a fully controlled environment (env -i):
#   A  127.0.0.1:28080  plain variables, http base URL, Passpoint on, NETPORTAL_POLICIES
#      (IMPL=rust: the device CA key as a file, the Rust version has no _B64 variable; /metrics
#      on its own listener NETPORTAL_METRICS_LISTEN 127.0.0.1:28090, B's 127.0.0.1:28091)
#   B  127.0.0.1:28081  *_FILE secrets (plain variables set to wrong values), device CA key as a
#                       file, https base URL (Secure __Host- cookie), legacy single policy,
#                       Passpoint off, default display name, CERT_DAYS / RENEW_OVERLAP_DAYS set
# The fake access point (Disconnect receiver, UDP 127.0.0.1:23799 for A and :23798 for B) runs
# inside the test process (contract/fake_nas.py): the tests read what it received.
#
# Portal command: IMPL=python  cd <repo> && gunicorn --bind 127.0.0.1:<port> --workers 1
#                              --threads 4 netportal.wsgi:app
#                 IMPL=rust    NETPORTAL_LISTEN=127.0.0.1:<port> $NETPORTAL_BIN serve
# CLI commands the tests run: python3 -m netportal <cmd> (cwd = repo) vs $NETPORTAL_BIN <cmd>
# (offboard, offboard --every, init-db, pki). Both get exactly the instance's NETPORTAL_*
# environment plus PATH and HOME. AUTHLIB_INSECURE_TRANSPORT=1 is set for both: the issuer is
# plain http on 127.0.0.1 (the Rust side must accept that for a loopback issuer).
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$here/../../.." && pwd)
run="$root/rust/tests/runs/contract"
IMPL=${IMPL:-python}
PG_IMAGE=${NETPORTAL_TEST_PG_IMAGE:-docker.io/library/postgres:18.6-alpine@sha256:898c60cb390d1085bc97bdd6a1ae968757421df394b071848b52b1c09c89d6a5}
PG_NAME=netportal-ct-pg
PG_PORT=25432 IDP_PORT=29000 PORT_A=28080 PORT_B=28081 METRICS_A=28090 METRICS_B=28091
PG_PASS=ct-db-password
RADIUS_DB_PASS=ct-radius-db-password

case "$IMPL" in
  python) CMD_JSON='["python3", "-m", "netportal"]' ;;
  rust)
    if [ -z "${NETPORTAL_BIN:-}" ] || [ ! -x "$NETPORTAL_BIN" ]; then
      echo "IMPL=rust needs NETPORTAL_BIN=<path to the netportal binary>" >&2; exit 2
    fi
    NETPORTAL_BIN=$(cd "$(dirname "$NETPORTAL_BIN")" && pwd)/$(basename "$NETPORTAL_BIN")
    CMD_JSON=$(python3 -c 'import json,sys; print(json.dumps([sys.argv[1]]))' "$NETPORTAL_BIN") ;;
  *) echo "IMPL must be python or rust" >&2; exit 2 ;;
esac

pids=()
cleanup() {
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
  docker rm -f "$PG_NAME" >/dev/null 2>&1 || true
}
trap 'if [ -z "${KEEP:-}" ]; then cleanup; fi' EXIT
cleanup

# A stale portal from an earlier KEEP run would answer the health check (tests/runs pitfall).
for p in $PG_PORT $IDP_PORT $PORT_A $PORT_B $METRICS_A $METRICS_B; do
  if ss -Hltn "sport = :$p" | grep -q .; then echo "port $p is in use (an earlier KEEP=1 run?)" >&2; exit 1; fi
done
for p in 23799 23798; do
  if ss -Hlun "sport = :$p" | grep -q .; then echo "udp port $p is in use" >&2; exit 1; fi
done

rm -rf "$run" && mkdir -p "$run/secrets"
# Fixture PKI (the ceremony itself is a contract test: test_pki.py runs <impl> pki).
(cd "$root" && python3 -m netportal pki --out "$run/pki" --name Test --server-name radius.scharni.org >/dev/null)

# --- registry: one database per portal instance
docker run -d --name "$PG_NAME" -p 127.0.0.1:$PG_PORT:5432 -e POSTGRES_USER=netportal \
  -e POSTGRES_PASSWORD="$PG_PASS" -e POSTGRES_DB=netportal "$PG_IMAGE" >/dev/null
for _ in $(seq 60); do docker exec "$PG_NAME" pg_isready -q -h 127.0.0.1 -U netportal 2>/dev/null && break; sleep 1; done
sleep 1
docker exec "$PG_NAME" psql -q -U netportal -d netportal -c "CREATE ROLE radius LOGIN PASSWORD '$RADIUS_DB_PASS'" >/dev/null
docker exec "$PG_NAME" psql -q -U netportal -d netportal -c "CREATE DATABASE netportal_b" >/dev/null

# --- secrets of instance B (files with a trailing newline: the reader strips it). Session secrets
# are 32 bytes or more in both instances: the Rust portal refuses shorter ones.
db_a="postgresql://netportal:$PG_PASS@127.0.0.1:$PG_PORT/netportal"
db_b="postgresql://netportal:$PG_PASS@127.0.0.1:$PG_PORT/netportal_b"
printf '%s\n' "$db_b" > "$run/secrets/database-url"
printf 'ct-session-secret-b-of-at-least-32-bytes\n' > "$run/secrets/session-secret"
printf 'ct-oidc-secret\n' > "$run/secrets/oidc-client-secret"
printf 'ct-dae-secret-b\n' > "$run/secrets/dae-secret"
printf 'mock-reader-token\n' > "$run/secrets/authentik-token"
chmod 0600 "$run"/secrets/*

# The instances' environments, one KEY=VALUE per line (no quoting: env -i gets each line as is).
common() {
  cat <<EOF
NETPORTAL_OIDC_ISSUER=http://127.0.0.1:$IDP_PORT/application/o/netportal/
NETPORTAL_OIDC_CLIENT_ID=netportal
NETPORTAL_ROOT_CERT=$run/pki/root.pem
NETPORTAL_DEVICE_CA_CERT=$run/pki/device-ca.pem
NETPORTAL_AUTHENTIK_API=http://127.0.0.1:$IDP_PORT/api/v3
NETPORTAL_ACCT_INTERIM_S=120
AUTHLIB_INSECURE_TRANSPORT=1
EOF
  for kv in ${PORTAL_EXTRA_ENV:-}; do echo "$kv"; done
}
{ common; cat <<EOF
NETPORTAL_BASE_URL=http://127.0.0.1:$PORT_A
NETPORTAL_REALM=scharni.org
NETPORTAL_SSID=Scharni
NETPORTAL_RADIUS_SERVER_NAME=radius.scharni.org
NETPORTAL_DISPLAY_NAME=Scharni
NETPORTAL_DATABASE_URL=$db_a
NETPORTAL_SESSION_SECRET=ct-session-secret-a-of-at-least-32-bytes
NETPORTAL_OIDC_CLIENT_SECRET=ct-oidc-secret
NETPORTAL_POLICIES=residents=30:residents,house-admins;guests=50:former-residents
NETPORTAL_ADMIN_GROUPS=it-admins
NETPORTAL_DEVICE_CA_KEY_B64=$(base64 -w0 "$run/pki/device-ca.key")
NETPORTAL_DAE_SECRET=ct-dae-secret-a
NETPORTAL_DAE_PORT=23799
NETPORTAL_AUTHENTIK_TOKEN=mock-reader-token
NETPORTAL_PASSPOINT=true
NETPORTAL_LOGOUT_URL=http://127.0.0.1:$IDP_PORT/if/flow/house-logout/
NETPORTAL_HEARTBEAT=$run/heartbeat-a
EOF
} > "$run/env-a"
{ common; cat <<EOF
NETPORTAL_BASE_URL=https://wifi.example.test/
NETPORTAL_REALM=house.example.net
NETPORTAL_SSID=Haus Gäste
NETPORTAL_RADIUS_SERVER_NAME=radius.house.example.net
NETPORTAL_DATABASE_URL=postgresql://wrong:wrong@127.0.0.1:1/wrong
NETPORTAL_DATABASE_URL_FILE=$run/secrets/database-url
NETPORTAL_SESSION_SECRET_FILE=$run/secrets/session-secret
NETPORTAL_OIDC_CLIENT_SECRET=wrong-oidc-secret
NETPORTAL_OIDC_CLIENT_SECRET_FILE=$run/secrets/oidc-client-secret
NETPORTAL_DEFAULT_VLAN=40
NETPORTAL_ALLOWED_GROUPS=residents, staff
NETPORTAL_DEVICE_CA_KEY=$run/pki/device-ca.key
NETPORTAL_CERT_DAYS=30
NETPORTAL_RENEW_OVERLAP_DAYS=5
NETPORTAL_DAE_SECRET=wrong-dae-secret
NETPORTAL_DAE_SECRET_FILE=$run/secrets/dae-secret
NETPORTAL_DAE_PORT=23798
NETPORTAL_AUTHENTIK_TOKEN_FILE=$run/secrets/authentik-token
NETPORTAL_PASSPOINT=false
NETPORTAL_HEARTBEAT=$run/heartbeat-b
EOF
} > "$run/env-b"
# The Rust portal has no legacy single policy (rust/docs/PARITY.md, deliberate deviations,
# settings: NETPORTAL_POLICIES is required): instance B gets the policy that
# NETPORTAL_DEFAULT_VLAN / NETPORTAL_ALLOWED_GROUPS describe, so test_login's legacy-policy test
# checks the same behaviour against both implementations.
# It also refuses a secret set both as NAME and NAME_FILE (deliberate deviation: ambiguous), so
# B's wrong plain values next to the *_FILE variants are left out for it: the secrets still come
# from the files only.
if [ "$IMPL" = rust ]; then
  # the device CA key from a file only (security review 2026-10-29, L3); /metrics on a listener
  # of its own (L6)
  grep -v '^NETPORTAL_DEVICE_CA_KEY_B64=' "$run/env-a" > "$run/env-a.rust"
  echo "NETPORTAL_DEVICE_CA_KEY=$run/pki/device-ca.key" >> "$run/env-a.rust"
  echo "NETPORTAL_METRICS_LISTEN=127.0.0.1:$METRICS_A" >> "$run/env-a.rust"
  mv "$run/env-a.rust" "$run/env-a"
  echo "NETPORTAL_METRICS_LISTEN=127.0.0.1:$METRICS_B" >> "$run/env-b"
  echo "NETPORTAL_POLICIES=residents=40:residents,staff" >> "$run/env-b"
  grep -v -E '^NETPORTAL_(DATABASE_URL|OIDC_CLIENT_SECRET|DAE_SECRET|SESSION_SECRET|AUTHENTIK_TOKEN)=' "$run/env-b" > "$run/env-b.rust"
  mv "$run/env-b.rust" "$run/env-b"
fi

# --- identity provider (the integration test's mock, extended: contract/mock_idp.py)
python3 "$here/mock_idp.py" --port $IDP_PORT --client-id netportal --client-secret ct-oidc-secret \
  > "$run/idp.log" 2>&1 &
pids+=($!)

start_portal() {   # name port
  local name=$1 port=$2 envfile="$run/env-$1"
  local -a envs
  mapfile -t envs < "$envfile"
  if [ "$IMPL" = python ]; then
    (cd "$root" && exec env -i PATH="$PATH" HOME="$HOME" "${envs[@]}" \
      gunicorn --bind 127.0.0.1:$port --workers 1 --threads 4 --log-level warning netportal.wsgi:app) \
      > "$run/portal-$name.log" 2>&1 &
  else
    env -i PATH="$PATH" HOME="$HOME" "${envs[@]}" NETPORTAL_LISTEN=127.0.0.1:$port "$NETPORTAL_BIN" serve \
      > "$run/portal-$name.log" 2>&1 &
  fi
  pids+=($!)
  for _ in $(seq 40); do
    curl -sf -o /dev/null "http://127.0.0.1:$port/healthz" && return 0
    sleep 0.5
  done
  echo "portal $name did not answer /healthz:" >&2; tail -30 "$run/portal-$name.log" >&2; exit 1
}
start_portal a $PORT_A
start_portal b $PORT_B

if [ "$IMPL" = rust ]; then metrics_a="http://127.0.0.1:$METRICS_A" metrics_b="http://127.0.0.1:$METRICS_B"
else metrics_a="http://127.0.0.1:$PORT_A" metrics_b="http://127.0.0.1:$PORT_B"; fi
cat > "$run/suite.json" <<EOF
{"impl": "$IMPL", "cmd": $CMD_JSON, "root": "$root", "run": "$run",
 "pg_admin": "postgresql://netportal:$PG_PASS@127.0.0.1:$PG_PORT/postgres",
 "radius_password": "$RADIUS_DB_PASS", "idp": "http://127.0.0.1:$IDP_PORT",
 "instances": {"a": {"url": "http://127.0.0.1:$PORT_A", "metrics_url": "$metrics_a", "db": "$db_a", "dae_port": 23799, "dae_secret": "ct-dae-secret-a"},
               "b": {"url": "http://127.0.0.1:$PORT_B", "metrics_url": "$metrics_b", "db": "$db_b", "dae_port": 23798, "dae_secret": "ct-dae-secret-b"}}}
EOF

echo "contract suite against IMPL=$IMPL (logs in $run)"
status=0
# shellcheck disable=SC2086
(cd "$here" && CT_SUITE="$run/suite.json" python3 -m unittest ${CT_ARGS:-discover -s . -p 'test_*.py'} -v) || status=$?
if [ "$status" -ne 0 ]; then
  echo "--- portal a (tail)"; tail -20 "$run/portal-a.log"
  echo "--- portal b (tail)"; tail -20 "$run/portal-b.log"
fi
exit "$status"
