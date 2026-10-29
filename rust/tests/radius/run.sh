#!/usr/bin/env bash
# The RADIUS-level test of the Rust registry (rust/tests/README.md, "radius/"): FreeRADIUS with
# rust/radius/ against a database migrated by the Rust binary, EAP-TLS logins by eapol_test with
# device certificates of the Rust PKI, accounting by radclient. No portal: devices and
# credentials are written with the registry's own SQL (crates/netportal-core/src/registry.rs).
#
#   rust/tests/radius/run.sh            everything; exit code 0 when every check passed
#   KEEP=1 rust/tests/radius/run.sh     leave PostgreSQL, FreeRADIUS and the access point running
#   RT_RADIUS_IMAGE=img rust/tests/radius/run.sh   test that FreeRADIUS image instead of rust/radius/
#   MIGRATE=psql rust/tests/radius/run.sh   migrate with psql (rust/migrations in order, then
#                                       rust/sql/radius_grants.sql) instead of `netportal init-db`
#
# The cases are those of tests/integration/e2e.py that FreeRADIUS decides or records (valid per
# policy/VLAN, revoked, retired after a renewal, expired, unregistered, no certificate, not EAP,
# foreign CA, root-signed; the logged reasons, the Class token, the session and MAC identity;
# accounting Start/Interim/Stop/On/Off; the radius role's rights; the two pools; logging blocked,
# logging functions revoked, the database down), with e2e.py's expected values: the Python setup
# (radius/ + the Python schema) gives exactly these, tests/integration/run.sh shows it.
#
# Set-up (all local Docker, network netportal-rt 10.198.0.0/24, so it can run next to the
# integration suite's netportal-it):
#   PostgreSQL  10.198.0.5, 127.0.0.1:17432 (the image of rust/tools/test-db.sh; started here
#               because the outage case stops and starts it, which test-db.sh's --rm forbids)
#   FreeRADIUS  10.198.0.10 (image built from rust/radius/Dockerfile)
#   access point 10.198.0.20 (tests/integration/client: eapol_test and radclient), one long-lived
#               container the checks `docker exec` into
# Certificates: `netportal pki` (the ceremony) and rust/tests/radius/certs (device certificates
# with netportal_pki::pki::device_cert; a foreign CA with the same names; one signed by the root;
# one whose serial is registered for another device).
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
mine="$root/rust/tests/radius"
run="$root/rust/tests/runs/radius"
NET=netportal-rt
PG_IMAGE=${NETPORTAL_TEST_PG_IMAGE:-docker.io/library/postgres:18.6-alpine@sha256:898c60cb390d1085bc97bdd6a1ae968757421df394b071848b52b1c09c89d6a5}
PG=netportal-rt-pg RADIUS=netportal-rt-radius AP=netportal-rt-ap
PG_PORT=17432
PG_PASS=rt-db-password RADIUS_DB_PASS=rt-radius-db-password STATUS_SECRET=rt-status-secret
POLICIES="residents=30:residents;guests=50:former-residents"
DB_URL="postgresql://netportal:$PG_PASS@127.0.0.1:$PG_PORT/netportal"
MIGRATE=${MIGRATE:-binary}
CARGO_TARGET_DIR_CERTS="$root/rust/target/radius-test-certs"

cleanup() {
  docker rm -f "$PG" "$RADIUS" "$AP" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
if ss -Hltn "sport = :$PG_PORT" | grep -q .; then echo "port $PG_PORT is in use (an earlier KEEP=1 run?)" >&2; exit 1; fi
if docker network inspect "$NET" >/dev/null 2>&1; then echo "docker network $NET exists (an earlier KEEP=1 run?)" >&2; exit 1; fi
trap 'if [ -z "${KEEP:-}" ]; then cleanup; fi' EXIT

rm -rf "$run" && mkdir -p "$run/client" && chmod 0777 "$run/client"

# --- the Rust binary (migrations, PKI ceremony) and the certificate tool
bin="$root/rust/target/debug/netportal"
if [ "$MIGRATE" = binary ]; then
  if ! (cd "$root/rust" && cargo build -q -p netportal) >"$run/cargo-netportal.log" 2>&1; then
    echo "note  cargo build -p netportal failed (see $run/cargo-netportal.log): migrating with psql instead"
    MIGRATE=psql
  fi
fi
cp "$root/rust/Cargo.lock" "$mine/certs/Cargo.lock"        # the product's versions
(cd "$mine/certs" && CARGO_TARGET_DIR="$CARGO_TARGET_DIR_CERTS" cargo build -q) >"$run/cargo-certs.log" 2>&1 \
  || { echo "FAIL  building rust/tests/radius/certs:"; tail -20 "$run/cargo-certs.log"; exit 1; }
certs="$CARGO_TARGET_DIR_CERTS/debug/radius-test-certs"

if [ "$MIGRATE" = binary ]; then
  "$bin" pki --out "$run/pki" --name Test --server-name radius.scharni.org >"$run/pki.log"
else
  "$certs" pki "$run/pki" Test radius.scharni.org >"$run/pki.log"   # the same ceremony function
fi
# FreeRADIUS (user freerad) reads the chain and its certificate through the read-only mount
chmod 0755 "$run/pki"
# alice's devices (residents, VLAN 30), fia's and carol's (guests, VLAN 50), and the traps
"$certs" --pki "$run/pki" --out "$run/client" --realm scharni.org \
  alice-android:device-ca alice-apple:device-ca alice-apple-renewed:device-ca:alice-apple \
  alice-eap-config:device-ca fia:device-ca carol-tablet:device-ca \
  unregistered:device-ca foreign:foreign root-signed:root mallory:device-ca >"$run/certs.json"
chmod 0644 "$run"/client/*

# --- registry
docker network create --subnet 10.198.0.0/24 "$NET" >/dev/null
docker run -d --name "$PG" --network "$NET" --ip 10.198.0.5 -p 127.0.0.1:$PG_PORT:5432 \
  -e POSTGRES_USER=netportal -e POSTGRES_PASSWORD="$PG_PASS" -e POSTGRES_DB=netportal "$PG_IMAGE" >/dev/null
for _ in $(seq 60); do docker exec "$PG" pg_isready -q -h 127.0.0.1 -U netportal 2>/dev/null && break; sleep 1; done
sleep 1
# the role exists before the migration (house-infra files/init-radius-role.sh creates it)
docker exec "$PG" psql -q -U netportal -d netportal -c "CREATE ROLE radius LOGIN PASSWORD '$RADIUS_DB_PASS'" >/dev/null

# The migration step, also run again by the checks ("migrate restores the radius role's rights").
if [ "$MIGRATE" = binary ]; then
  migrate_cmd="env -i PATH=\"\$PATH\" NETPORTAL_DATABASE_URL='$DB_URL' NETPORTAL_POLICIES='$POLICIES' '$bin' init-db"
else
  # what registry::init does, by hand: every migration in order, each in one transaction (here,
  # once), then on every run the declarative grants, the policies and the offboarding job
  for f in "$root"/rust/migrations/*.sql; do
    docker exec -i "$PG" psql -q -1 -v ON_ERROR_STOP=1 -U netportal -d netportal < "$f" >/dev/null
  done
  migrate_cmd="docker exec -i $PG psql -q -1 -v ON_ERROR_STOP=1 -U netportal -d netportal < '$root/rust/sql/radius_grants.sql' && \
docker exec $PG psql -q -v ON_ERROR_STOP=1 -U netportal -d netportal -c \"INSERT INTO policy (name, vlan) VALUES ('residents', 30), ('guests', 50) ON CONFLICT (name) DO UPDATE SET vlan = excluded.vlan; INSERT INTO job (name, last_success) VALUES ('offboarding', now()) ON CONFLICT (name) DO NOTHING\" && echo 'grants applied with psql'"
fi
bash -c "$migrate_cmd" >"$run/migrate.log" 2>&1 || { echo "FAIL  migration ($MIGRATE):"; cat "$run/migrate.log"; exit 1; }
echo "ok    registry migrated ($MIGRATE: $(tail -1 "$run/migrate.log" | tr -d '\n'))"

# --- FreeRADIUS (rust/radius) and the access point
cat > "$run/clients.conf" <<'EOF'
# Test network: the access point container (eapol_test, radclient).
client test-ap {
	ipaddr = 10.198.0.0/24
	secret = rt-radius-secret
	require_message_authenticator = yes
	limit_proxy_state = yes
}
EOF
docker build -q -t netportal-it-client "$root/tests/integration/client" >/dev/null
# RT_RADIUS_IMAGE=<image>: test that image instead (e.g. a configuration with a guard removed, to
# see the checks catch it; rust/tests/README.md)
radius_image=${RT_RADIUS_IMAGE:-netportal-radius:rust-rt}
[ -n "${RT_RADIUS_IMAGE:-}" ] || docker build -q -t "$radius_image" -f "$root/rust/radius/Dockerfile" "$root" >/dev/null
docker run -d --name "$RADIUS" --network "$NET" --ip 10.198.0.10 \
  -e RADIUS_DB_HOST=10.198.0.5 -e RADIUS_DB_NAME=netportal -e RADIUS_DB_PASSWORD="$RADIUS_DB_PASS" \
  -e RADIUS_STATUS_SECRET="$STATUS_SECRET" -e DEVICE_CA_DN="/CN=Test Device CA" -e RADIUS_SESSION_TIMEOUT=43200 \
  -e NETPORTAL_ACCT_INTERIM_S=120 \
  -v "$run/clients.conf:/etc/freeradius/clients.conf:ro" -v "$run/pki:/etc/netportal:ro" \
  -v "$run/pki/radius-server.key:/etc/netportal-secrets/radius-server.key:ro" \
  "$radius_image" >/dev/null
docker run -d --name "$AP" --network "$NET" --ip 10.198.0.20 \
  -v "$run/client:/client:ro" -v "$run/pki:/pki:ro" --entrypoint sleep netportal-it-client infinity >/dev/null
sleep 3
if ! docker ps --format '{{.Names}}' | grep -qx "$RADIUS"; then echo "FAIL  FreeRADIUS did not start:"; docker logs "$RADIUS" 2>&1 | tail -30; exit 1; fi
if docker exec "$RADIUS" sh -c "echo 'Message-Authenticator = 0x00' | radclient -q -t 2 127.0.0.1:18121 status '$STATUS_SECRET'"; then
  echo "ok    radius healthcheck (Status-Server)"
else
  echo "FAIL  radius healthcheck"; docker logs "$RADIUS" 2>&1 | tail -30; exit 1
fi

status=0
RT_RUN="$run" RT_DB="$DB_URL" RT_RADIUS_DB="postgresql://radius:$RADIUS_DB_PASS@127.0.0.1:$PG_PORT/netportal" \
  RT_PG_CONTAINER="$PG" RT_AP_CONTAINER="$AP" RT_MIGRATE="$migrate_cmd" \
  python3 "$mine/radius_test.py" || status=$?
docker logs "$RADIUS" >"$run/radius.log" 2>&1 || true
if [ "$status" -ne 0 ]; then echo "--- radius (tail; all of it in $run/radius.log)"; tail -15 "$run/radius.log"; fi
exit "$status"
