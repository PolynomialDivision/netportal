#!/usr/bin/env bash
# Integration test of the whole Wi-Fi path on local Docker (nothing leaves this machine):
#   PostgreSQL (registry) + FreeRADIUS (radius/, production config) + a second FreeRADIUS as
#   the access point's Disconnect receiver + mock Authentik (OIDC, users API) + netportal under
#   gunicorn on the host; tests/integration/e2e.py plays residents, apps and admins, and
#   eapol_test plays the access point.
#   tests/integration/run.sh        (KEEP=1 leaves everything running)
#   IMAGES=1 tests/integration/run.sh   the same against the built images (Dockerfile, radius/Dockerfile)
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
here="$root/tests/integration"
run="$root/tests/runs/integration"
NET=netportal-it
PG_IMAGE=docker.io/library/postgres:16.15-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea
RADIUS_IMAGE=freeradius/freeradius-server:3.2.10@sha256:cc7fd136e7b03e7b332d94297530318e824a4ecfedbce54562cced723e71e812
PG_PASS=it-db-password
RADIUS_DB_PASS=it-radius-db-password
STATUS_SECRET=it-status-secret

cleanup() {
  [ -n "${portal_pid:-}" ] && kill "$portal_pid" 2>/dev/null || true
  [ -n "${idp_pid:-}" ] && kill "$idp_pid" 2>/dev/null || true
  docker rm -f netportal-it-pg netportal-it-radius netportal-it-nas netportal-it-portal >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap 'if [ -z "${KEEP:-}" ]; then cleanup; fi' EXIT
cleanup

rm -rf "$run" && mkdir -p "$run/client" && chmod 0777 "$run/client"
python3 -m netportal pki --out "$run/pki" --name "Test" --server-name radius.scharni.org >/dev/null
# The RADIUS key stays 0600 (as the stack renders secrets): FreeRADIUS reads it as root at start.
mkdir -p "$run/fake-nas-sites" "$run/fake-nas-mods" && cp "$here/fake-nas" "$run/fake-nas-sites/" \
  && cp "$root/radius/mods/always" "$run/fake-nas-mods/"
docker build -q -t netportal-it-client "$here/client" >/dev/null
docker network create --subnet 10.199.0.0/24 "$NET" >/dev/null

# --- registry
docker run -d --name netportal-it-pg --network "$NET" --ip 10.199.0.5 -p 127.0.0.1:15432:5432 \
  -e POSTGRES_USER=netportal -e POSTGRES_PASSWORD="$PG_PASS" -e POSTGRES_DB=netportal "$PG_IMAGE" >/dev/null
for _ in $(seq 60); do docker exec netportal-it-pg pg_isready -q -U netportal 2>/dev/null && break; sleep 1; done
sleep 1
docker exec netportal-it-pg psql -q -U netportal -d netportal -c "CREATE ROLE radius LOGIN PASSWORD '$RADIUS_DB_PASS'" >/dev/null

# --- identity provider and portal
python3 "$here/mock_authentik.py" --port 19000 --client-id netportal --client-secret it-oidc-secret &
idp_pid=$!
device_ca_key_b64=$(base64 -w0 "$run/pki/device-ca.key")
export NETPORTAL_BASE_URL=http://127.0.0.1:18080 NETPORTAL_REALM=scharni.org NETPORTAL_SSID=Scharni \
  NETPORTAL_RADIUS_SERVER_NAME=radius.scharni.org NETPORTAL_DISPLAY_NAME=Scharni \
  NETPORTAL_DATABASE_URL="postgresql://netportal:$PG_PASS@127.0.0.1:15432/netportal" \
  NETPORTAL_SESSION_SECRET=it-session-secret NETPORTAL_OIDC_ISSUER=http://127.0.0.1:19000/application/o/netportal/ \
  NETPORTAL_OIDC_CLIENT_ID=netportal NETPORTAL_OIDC_CLIENT_SECRET=it-oidc-secret \
  NETPORTAL_ALLOWED_GROUPS=residents NETPORTAL_ADMIN_GROUPS=it-admins \
  NETPORTAL_ROOT_CERT="$run/pki/root.pem" NETPORTAL_DEVICE_CA_CERT="$run/pki/device-ca.pem" \
  NETPORTAL_DEVICE_CA_KEY_B64="$device_ca_key_b64" NETPORTAL_DEFAULT_VLAN=30 \
  NETPORTAL_DAE_SECRET=it-dae-secret \
  NETPORTAL_AUTHENTIK_API=http://127.0.0.1:19000/api/v3 NETPORTAL_AUTHENTIK_TOKEN=mock-reader-token \
  NETPORTAL_PASSPOINT=true AUTHLIB_INSECURE_TRANSPORT=1
if [ -n "${IMAGES:-}" ]; then
  docker build -q -t netportal:it "$root" >/dev/null
  : > "$run/portal.env"
  for v in NETPORTAL_BASE_URL NETPORTAL_REALM NETPORTAL_SSID NETPORTAL_RADIUS_SERVER_NAME NETPORTAL_DISPLAY_NAME \
           NETPORTAL_DATABASE_URL NETPORTAL_SESSION_SECRET NETPORTAL_OIDC_ISSUER NETPORTAL_OIDC_CLIENT_ID \
           NETPORTAL_OIDC_CLIENT_SECRET NETPORTAL_ALLOWED_GROUPS NETPORTAL_ADMIN_GROUPS NETPORTAL_DAE_SECRET \
           NETPORTAL_AUTHENTIK_API NETPORTAL_AUTHENTIK_TOKEN NETPORTAL_PASSPOINT AUTHLIB_INSECURE_TRANSPORT \
           NETPORTAL_DEVICE_CA_KEY_B64 NETPORTAL_DEFAULT_VLAN; do
    printf '%s=%s\n' "$v" "${!v}" >> "$run/portal.env"
  done
  printf 'NETPORTAL_ROOT_CERT=/pki/root.pem\nNETPORTAL_DEVICE_CA_CERT=/pki/device-ca.pem\n' \
    >> "$run/portal.env"
  # Host network: the portal reaches the mock IdP and the database on 127.0.0.1, as the test does.
  docker run -d --name netportal-it-portal --network host --user "$(id -u)" --env-file "$run/portal.env" \
    -e GUNICORN_CMD_ARGS="--bind 127.0.0.1:18080 --workers 1 --threads 4" -v "$run/pki:/pki:ro" netportal:it >/dev/null
else
  (cd "$root" && exec gunicorn --bind 127.0.0.1:18080 --workers 1 --threads 4 --log-level warning \
    netportal.wsgi:app) &
  portal_pid=$!
fi
for _ in $(seq 30); do curl -sf -o /dev/null http://127.0.0.1:18080/healthz && break; sleep 1; done

# --- RADIUS (the production configuration in radius/) and the fake access point
radius_env=(-e RADIUS_DB_HOST=10.199.0.5 -e RADIUS_DB_NAME=netportal -e RADIUS_DB_PASSWORD="$RADIUS_DB_PASS"
  -e RADIUS_STATUS_SECRET="$STATUS_SECRET" -e DEVICE_CA_DN="/CN=Test Device CA" -e RADIUS_SESSION_TIMEOUT=43200
  -v "$here/clients.conf:/etc/freeradius/clients.conf:ro" -v "$run/pki:/etc/netportal:ro"
  -v "$run/pki/radius-server.key:/etc/netportal-secrets/radius-server.key:ro")
# The RADIUS image is always the one from radius/Dockerfile (its entrypoint matters).
docker build -q -t netportal-radius:it -f "$root/radius/Dockerfile" "$root" >/dev/null
docker run -d --name netportal-it-radius --network "$NET" --ip 10.199.0.10 "${radius_env[@]}" netportal-radius:it >/dev/null
docker run -d --name netportal-it-nas --network "$NET" --ip 10.199.0.11 \
  -v "$here/fake-nas-clients.conf:/etc/freeradius/clients.conf:ro" \
  -v "$run/fake-nas-sites:/etc/freeradius/sites-enabled:ro" \
  -v "$run/fake-nas-mods:/etc/freeradius/mods-enabled:ro" \
  "$RADIUS_IMAGE" -X >/dev/null
sleep 3
for c in netportal-it-radius netportal-it-nas ${IMAGES:+netportal-it-portal}; do
  if ! docker ps --format '{{.Names}}' | grep -qx "$c"; then echo "$c did not start:"; docker logs "$c" 2>&1 | tail -20; exit 1; fi
done
# The container healthcheck, as the stack will run it.
if docker exec netportal-it-radius sh -c "echo 'Message-Authenticator = 0x00' | radclient -q -t 2 127.0.0.1:18121 status '$STATUS_SECRET'"; then
  echo "ok    radius healthcheck (Status-Server)"
else
  echo "FAIL  radius healthcheck"; exit 1
fi

status=0
python3 "$here/e2e.py" "$run" || status=$?
if [ "$status" -ne 0 ]; then
  echo "--- radius (tail)"; docker logs netportal-it-radius 2>&1 | tail -15
  echo "--- fake access point (Disconnect)"; docker logs netportal-it-nas 2>&1 | grep -iE "disconnect|coa|error" | tail -10
fi
exit "$status"
