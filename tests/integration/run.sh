#!/usr/bin/env bash
# Integration test of the whole Wi-Fi path on local Docker (nothing leaves this machine):
#   PostgreSQL (registry) + FreeRADIUS (radius/, the production configuration) + a second
#   FreeRADIUS as the access point's Disconnect receiver + mock Authentik (OIDC, users API) +
#   the netportal binary (`serve`) on the host; tests/integration/e2e.py plays residents, apps
#   and admins, and eapol_test plays the access point.
#
#   tests/integration/run.sh       builds target/debug/netportal (cargo build -p netportal)
#   NETPORTAL_BIN=target/release/netportal tests/integration/run.sh   that binary instead (not built)
#   KEEP=1 ...                     leave everything running
#
# Set-up (Docker network netportal-it, 10.199.0.0/24):
#   PostgreSQL     10.199.0.5, 127.0.0.1:15432
#   FreeRADIUS     10.199.0.10 (image built from radius/Dockerfile)
#   access point   10.199.0.11: FreeRADIUS with fake-nas (the Disconnect receiver, RFC 5176) and
#                  radclient (accounting); eapol_test runs in throwaway containers at 10.199.0.20
#                  (client/Dockerfile)
#   mock Authentik 127.0.0.1:19000 (mock_authentik.py)
#   portal         127.0.0.1:18080, /metrics on 127.0.0.1:18090 (NETPORTAL_METRICS_LISTEN)
# Certificates: `$NETPORTAL_BIN pki` (the ceremony: the CAs the portal and FreeRADIUS use) and,
# for the FreeRADIUS traps (unregistered, a foreign CA with the same names, root-signed),
# tests/radius/certs (radius-test-certs, netportal_pki::pki::device_cert; $run/certs.json).
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
here="$root/tests/integration"
run="$root/tests/runs/integration"
NET=netportal-it
# The PostgreSQL production runs (house-infra stacks/netaccess/stack.yml).
PG_IMAGE=docker.io/library/postgres:18.6-alpine@sha256:898c60cb390d1085bc97bdd6a1ae968757421df394b071848b52b1c09c89d6a5
RADIUS_IMAGE=freeradius/freeradius-server:3.2.10@sha256:cc7fd136e7b03e7b332d94297530318e824a4ecfedbce54562cced723e71e812
PG_PASS=it-db-password
RADIUS_DB_PASS=it-radius-db-password
STATUS_SECRET=it-status-secret
CARGO_TARGET_DIR_CERTS="$root/target/radius-test-certs"

# The binary under test: target/debug/netportal, built here, unless NETPORTAL_BIN names another.
if [ -z "${NETPORTAL_BIN:-}" ]; then
  NETPORTAL_BIN="$root/target/debug/netportal"
  (cd "$root" && cargo build -q -p netportal) || { echo "cargo build -p netportal failed" >&2; exit 1; }
fi
if [ ! -x "$NETPORTAL_BIN" ]; then echo "NETPORTAL_BIN=$NETPORTAL_BIN is not an executable" >&2; exit 2; fi
NETPORTAL_BIN=$(cd "$(dirname "$NETPORTAL_BIN")" && pwd)/$(basename "$NETPORTAL_BIN")
export NETPORTAL_BIN

cleanup() {
  [ -n "${portal_pid:-}" ] && kill "$portal_pid" 2>/dev/null || true
  [ -n "${idp_pid:-}" ] && kill "$idp_pid" 2>/dev/null || true
  docker rm -f netportal-it-pg netportal-it-radius netportal-it-nas >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
# Refuse to start next to a running (KEEP=1) environment: a stale portal would answer the
# health check (INVENTORY 14.1.5).
for p in 15432 18080 18090 19000; do
  if ss -Hltn "sport = :$p" | grep -q .; then echo "port $p is in use (an earlier KEEP=1 run?)" >&2; exit 1; fi
done
if docker network inspect "$NET" >/dev/null 2>&1; then echo "docker network $NET exists (an earlier run?)" >&2; exit 1; fi
trap 'if [ -z "${KEEP:-}" ]; then cleanup; fi' EXIT

rm -rf "$run" && mkdir -p "$run/client" && chmod 0777 "$run/client"
"$NETPORTAL_BIN" pki --out "$run/pki" --name "Test" --server-name radius.scharni.org >/dev/null
chmod 0755 "$run/pki"                               # the ceremony makes it 0700; FreeRADIUS reads it
# The trap certificates (the tool builds against the product's Cargo.lock)
cp "$root/Cargo.lock" "$root/tests/radius/certs/Cargo.lock"
(cd "$root/tests/radius/certs" && CARGO_TARGET_DIR="$CARGO_TARGET_DIR_CERTS" cargo build -q) >"$run/cargo-certs.log" 2>&1 \
  || { echo "FAIL  building tests/radius/certs:"; tail -20 "$run/cargo-certs.log"; exit 1; }
"$CARGO_TARGET_DIR_CERTS/debug/radius-test-certs" --pki "$run/pki" --out "$run/client" --realm scharni.org \
  unregistered:device-ca foreign:foreign root-signed:root >"$run/certs.json"
chmod 0644 "$run"/client/*

mkdir -p "$run/fake-nas-sites" "$run/fake-nas-mods" && cp "$here/fake-nas" "$run/fake-nas-sites/" \
  && cp "$root/radius/mods/always" "$run/fake-nas-mods/"
docker build -q -t netportal-it-client "$here/client" >/dev/null
docker network create --subnet 10.199.0.0/24 "$NET" >/dev/null

# --- registry
docker run -d --name netportal-it-pg --network "$NET" --ip 10.199.0.5 -p 127.0.0.1:15432:5432 \
  -e POSTGRES_USER=netportal -e POSTGRES_PASSWORD="$PG_PASS" -e POSTGRES_DB=netportal "$PG_IMAGE" >/dev/null
for _ in $(seq 60); do docker exec netportal-it-pg pg_isready -q -h 127.0.0.1 -U netportal 2>/dev/null && break; sleep 1; done
sleep 1
# the role exists before the migration (house-infra files/init-radius-role.sh creates it)
docker exec netportal-it-pg psql -q -U netportal -d netportal -c "CREATE ROLE radius LOGIN PASSWORD '$RADIUS_DB_PASS'" >/dev/null

# --- identity provider and portal (the session secret: 32 bytes or more, the portal refuses less)
python3 "$here/mock_authentik.py" --port 19000 --client-id netportal --client-secret it-oidc-secret &
idp_pid=$!
export NETPORTAL_BASE_URL=http://127.0.0.1:18080 NETPORTAL_REALM=scharni.org NETPORTAL_SSID=Scharni \
  NETPORTAL_RADIUS_SERVER_NAME=radius.scharni.org NETPORTAL_DISPLAY_NAME=Scharni \
  NETPORTAL_DATABASE_URL="postgresql://netportal:$PG_PASS@127.0.0.1:15432/netportal" \
  NETPORTAL_SESSION_SECRET=it-session-secret-of-at-least-32-bytes \
  NETPORTAL_OIDC_ISSUER=http://127.0.0.1:19000/application/o/netportal/ \
  NETPORTAL_OIDC_CLIENT_ID=netportal NETPORTAL_OIDC_CLIENT_SECRET=it-oidc-secret \
  NETPORTAL_POLICIES="residents=30:residents;guests=50:former-residents" NETPORTAL_ADMIN_GROUPS=it-admins \
  NETPORTAL_ROOT_CERT="$run/pki/root.pem" NETPORTAL_DEVICE_CA_CERT="$run/pki/device-ca.pem" \
  NETPORTAL_DEVICE_CA_KEY="$run/pki/device-ca.key" \
  NETPORTAL_DAE_SECRET=it-dae-secret \
  NETPORTAL_AUTHENTIK_API=http://127.0.0.1:19000/api/v3 NETPORTAL_AUTHENTIK_TOKEN=mock-reader-token \
  NETPORTAL_PASSPOINT=true NETPORTAL_ACCT_INTERIM_S=120 NETPORTAL_METRICS_LISTEN=127.0.0.1:18090
NETPORTAL_LISTEN=127.0.0.1:18080 "$NETPORTAL_BIN" serve &
portal_pid=$!
healthy=
for _ in $(seq 30); do curl -sf -o /dev/null http://127.0.0.1:18080/healthz && { healthy=1; break; }; sleep 1; done
[ -n "$healthy" ] || { echo "FAIL  the portal never answered /healthz" >&2; exit 1; }

# --- RADIUS (the production configuration, radius/) and the fake access point
radius_env=(-e RADIUS_DB_HOST=10.199.0.5 -e RADIUS_DB_NAME=netportal -e RADIUS_DB_PASSWORD="$RADIUS_DB_PASS"
  -e RADIUS_STATUS_SECRET="$STATUS_SECRET" -e DEVICE_CA_DN="/CN=Test Device CA" -e RADIUS_SESSION_TIMEOUT=43200
  -e NETPORTAL_ACCT_INTERIM_S=120
  -v "$here/clients.conf:/etc/freeradius/clients.conf:ro" -v "$run/pki:/etc/netportal:ro"
  -v "$run/pki/radius-server.key:/etc/netportal-secrets/radius-server.key:ro")
docker build -q -t netportal-radius:it -f "$root/radius/Dockerfile" "$root" >/dev/null
docker run -d --name netportal-it-radius --network "$NET" --ip 10.199.0.10 "${radius_env[@]}" netportal-radius:it >/dev/null
docker run -d --name netportal-it-nas --network "$NET" --ip 10.199.0.11 \
  -v "$here/fake-nas-clients.conf:/etc/freeradius/clients.conf:ro" \
  -v "$run/fake-nas-sites:/etc/freeradius/sites-enabled:ro" \
  -v "$run/fake-nas-mods:/etc/freeradius/mods-enabled:ro" \
  "$RADIUS_IMAGE" -X >/dev/null
sleep 3
for c in netportal-it-radius netportal-it-nas; do
  if ! docker ps --format '{{.Names}}' | grep -qx "$c"; then echo "$c did not start:"; docker logs "$c" 2>&1 | tail -20; exit 1; fi
done
if docker exec netportal-it-radius sh -c "echo 'Message-Authenticator = 0x00' | radclient -q -t 2 127.0.0.1:18121 status '$STATUS_SECRET'"; then
  echo "ok    radius healthcheck (Status-Server)"
else
  echo "FAIL  radius healthcheck"; exit 1
fi

echo "e2e against $NETPORTAL_BIN"
status=0
python3 "$here/e2e.py" "$run" || status=$?
if [ "$status" -ne 0 ]; then
  echo "--- radius (tail)"; docker logs netportal-it-radius 2>&1 | tail -15
  echo "--- fake access point (Disconnect)"; docker logs netportal-it-nas 2>&1 | grep -iE "disconnect|coa|error" | tail -10
fi
exit "$status"
