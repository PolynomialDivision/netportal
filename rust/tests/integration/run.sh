#!/usr/bin/env bash
# The whole-path integration test against either implementation: IMPL=python runs the EXISTING
# tests/integration/e2e.py unchanged against the Python stack; IMPL=rust runs its schema-adapted
# copy rust/tests/integration/e2e_rust.py against the Rust stack (Rust portal, rust/radius/, the
# Rust registry's schema):
#   rust/tests/integration/run.sh                                     IMPL=python (gunicorn)
#   IMPL=rust NETPORTAL_BIN=rust/target/release/netportal rust/tests/integration/run.sh
#   KEEP=1 ...   leave everything running
#
# This is tests/integration/run.sh with these differences, and only these:
#  1. The portal process: IMPL=python runs gunicorn exactly as tests/integration/run.sh does;
#     IMPL=rust runs `NETPORTAL_LISTEN=127.0.0.1:18080 $NETPORTAL_BIN serve` with the same
#     NETPORTAL_* environment.
#  2. The test is started through rust/tests/integration/e2e_impl.py: IMPL=python runs
#     tests/integration/e2e.py unchanged by path; IMPL=rust runs e2e_rust.py (e2e.py with the
#     Rust schema and `$NETPORTAL_BIN offboard` / `init-db`; its header lists every difference).
#  3. Run directory rust/tests/runs/integration instead of tests/runs/integration (nothing is
#     written outside rust/tests/).
#  4. Before starting, it checks that the host ports 15432, 18080 and 19000 and the Docker
#     network netportal-it are free (an earlier KEEP=1 run would otherwise answer the health
#     check: the stale-portal pitfall of INVENTORY 14.1.5), and it fails when /healthz never
#     answers instead of carrying on.
#  5. IMAGES=1 (the built images) is not offered here; use tests/integration/run.sh for that.
#  6. IMPL=rust only: FreeRADIUS is built from rust/radius/Dockerfile (the Rust registry's
#     contract, rust/docs/RADIUS_CONTRACT.md) instead of radius/Dockerfile, and the PKI comes
#     from `$NETPORTAL_BIN pki` (the Rust ceremony: the CAs the Rust portal and rust/radius use in
#     production) instead of `python3 -m netportal pki`.
#  7. IMPL=rust only: NETPORTAL_SESSION_SECRET is 32 bytes or more (the Rust portal refuses a
#     shorter one; Python accepted the 17-byte it-session-secret).
#  8. IMPL=rust only (security review 2026-10-29): the device CA key as a file
#     (NETPORTAL_DEVICE_CA_KEY; the Rust portal has no _B64 variable) and /metrics on its own
#     listener (NETPORTAL_METRICS_LISTEN=127.0.0.1:18090; e2e_rust.py reads it there).
# Reused by path, unchanged: tests/integration/{e2e.py,mock_authentik.py,clients.conf,
# fake-nas,fake-nas-clients.conf,client/Dockerfile}, radius/Dockerfile (IMPL=python),
# radius/mods/always, tests/test_profiles.py (aosp_parse, imported by e2e.py and e2e_rust.py).
# IMPL=python: the certificates come from `python3 -m netportal pki` as in the original.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
here="$root/tests/integration"                      # the original suite's files
mine="$root/rust/tests/integration"
run="$root/rust/tests/runs/integration"             # difference 3
NET=netportal-it
IMPL=${IMPL:-python}
PG_IMAGE=docker.io/library/postgres:18.6-alpine@sha256:898c60cb390d1085bc97bdd6a1ae968757421df394b071848b52b1c09c89d6a5
RADIUS_IMAGE=freeradius/freeradius-server:3.2.10@sha256:cc7fd136e7b03e7b332d94297530318e824a4ecfedbce54562cced723e71e812
PG_PASS=it-db-password
RADIUS_DB_PASS=it-radius-db-password
STATUS_SECRET=it-status-secret

case "$IMPL" in
  python) ;;
  rust)
    if [ -z "${NETPORTAL_BIN:-}" ] || [ ! -x "$NETPORTAL_BIN" ]; then
      echo "IMPL=rust needs NETPORTAL_BIN=<path to the netportal binary>" >&2; exit 2
    fi
    NETPORTAL_BIN=$(cd "$(dirname "$NETPORTAL_BIN")" && pwd)/$(basename "$NETPORTAL_BIN")
    export NETPORTAL_BIN ;;
  *) echo "IMPL must be python or rust" >&2; exit 2 ;;
esac
export IMPL

cleanup() {
  [ -n "${portal_pid:-}" ] && kill "$portal_pid" 2>/dev/null || true
  [ -n "${idp_pid:-}" ] && kill "$idp_pid" 2>/dev/null || true
  docker rm -f netportal-it-pg netportal-it-radius netportal-it-nas >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
# difference 4: refuse to start next to a running (KEEP) test environment
for p in 15432 18080 18090 19000; do
  if ss -Hltn "sport = :$p" | grep -q .; then echo "port $p is in use (an earlier KEEP=1 run?)" >&2; exit 1; fi
done
if docker network inspect "$NET" >/dev/null 2>&1; then echo "docker network $NET exists (an earlier run?)" >&2; exit 1; fi
trap 'if [ -z "${KEEP:-}" ]; then cleanup; fi' EXIT

rm -rf "$run" && mkdir -p "$run/client" && chmod 0777 "$run/client"
if [ "$IMPL" = python ]; then
  (cd "$root" && python3 -m netportal pki --out "$run/pki" --name "Test" --server-name radius.scharni.org >/dev/null)
  radius_dockerfile="$root/radius/Dockerfile"
else                                                # difference 6
  "$NETPORTAL_BIN" pki --out "$run/pki" --name "Test" --server-name radius.scharni.org >/dev/null
  chmod 0755 "$run/pki"                             # the ceremony makes it 0700; FreeRADIUS reads it
  radius_dockerfile="$root/rust/radius/Dockerfile"
fi
mkdir -p "$run/fake-nas-sites" "$run/fake-nas-mods" && cp "$here/fake-nas" "$run/fake-nas-sites/" \
  && cp "$root/radius/mods/always" "$run/fake-nas-mods/"
# The access point signs its Disconnect replies (hostapd adds a Message-Authenticator), and the
# Rust portal requires that (netportal-pki disconnect): the fake NAS does the same. FreeRADIUS
# computes the attribute when it is set to zero. Harmless for the Python portal, which ignores it.
sed -i 's/^\trecv-coa {$/\trecv-coa {\n\t\tupdate reply {\n\t\t\tMessage-Authenticator := 0x00\n\t\t}/' "$run/fake-nas-sites/fake-nas"
grep -q 'Message-Authenticator := 0x00' "$run/fake-nas-sites/fake-nas" || { echo "fake-nas: could not add the Message-Authenticator" >&2; exit 1; }
docker build -q -t netportal-it-client "$here/client" >/dev/null
docker network create --subnet 10.199.0.0/24 "$NET" >/dev/null

# --- registry
docker run -d --name netportal-it-pg --network "$NET" --ip 10.199.0.5 -p 127.0.0.1:15432:5432 \
  -e POSTGRES_USER=netportal -e POSTGRES_PASSWORD="$PG_PASS" -e POSTGRES_DB=netportal "$PG_IMAGE" >/dev/null
for _ in $(seq 60); do docker exec netportal-it-pg pg_isready -q -h 127.0.0.1 -U netportal 2>/dev/null && break; sleep 1; done
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
  NETPORTAL_POLICIES="residents=30:residents;guests=50:former-residents" NETPORTAL_ADMIN_GROUPS=it-admins \
  NETPORTAL_ROOT_CERT="$run/pki/root.pem" NETPORTAL_DEVICE_CA_CERT="$run/pki/device-ca.pem" \
  NETPORTAL_DEVICE_CA_KEY_B64="$device_ca_key_b64" \
  NETPORTAL_DAE_SECRET=it-dae-secret \
  NETPORTAL_AUTHENTIK_API=http://127.0.0.1:19000/api/v3 NETPORTAL_AUTHENTIK_TOKEN=mock-reader-token \
  NETPORTAL_PASSPOINT=true NETPORTAL_ACCT_INTERIM_S=120 AUTHLIB_INSECURE_TRANSPORT=1
# difference 7: the Rust portal wants a session secret of at least 32 bytes
[ "$IMPL" = python ] || export NETPORTAL_SESSION_SECRET=it-session-secret-of-at-least-32-bytes
# difference 8: the key from a file only, /metrics on a listener of its own
if [ "$IMPL" = rust ]; then
  unset NETPORTAL_DEVICE_CA_KEY_B64
  export NETPORTAL_DEVICE_CA_KEY="$run/pki/device-ca.key" NETPORTAL_METRICS_LISTEN=127.0.0.1:18090
fi
if [ "$IMPL" = python ]; then                       # difference 1
  (cd "$root" && exec gunicorn --bind 127.0.0.1:18080 --workers 1 --threads 4 --log-level warning \
    netportal.wsgi:app) &
else
  NETPORTAL_LISTEN=127.0.0.1:18080 "$NETPORTAL_BIN" serve &
fi
portal_pid=$!
healthy=
for _ in $(seq 30); do curl -sf -o /dev/null http://127.0.0.1:18080/healthz && { healthy=1; break; }; sleep 1; done
[ -n "$healthy" ] || { echo "FAIL  the portal ($IMPL) never answered /healthz" >&2; exit 1; }   # difference 4

# --- RADIUS (the production configuration: radius/, or rust/radius/ for IMPL=rust) and the fake access point
radius_env=(-e RADIUS_DB_HOST=10.199.0.5 -e RADIUS_DB_NAME=netportal -e RADIUS_DB_PASSWORD="$RADIUS_DB_PASS"
  -e RADIUS_STATUS_SECRET="$STATUS_SECRET" -e DEVICE_CA_DN="/CN=Test Device CA" -e RADIUS_SESSION_TIMEOUT=43200
  -e NETPORTAL_ACCT_INTERIM_S=120
  -v "$here/clients.conf:/etc/freeradius/clients.conf:ro" -v "$run/pki:/etc/netportal:ro"
  -v "$run/pki/radius-server.key:/etc/netportal-secrets/radius-server.key:ro")
docker build -q -t "netportal-radius:it-$IMPL" -f "$radius_dockerfile" "$root" >/dev/null
docker run -d --name netportal-it-radius --network "$NET" --ip 10.199.0.10 "${radius_env[@]}" "netportal-radius:it-$IMPL" >/dev/null
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

echo "e2e against IMPL=$IMPL"
status=0
python3 "$mine/e2e_impl.py" "$run" || status=$?     # difference 2
if [ "$status" -ne 0 ]; then
  echo "--- radius (tail)"; docker logs netportal-it-radius 2>&1 | tail -15
  echo "--- fake access point (Disconnect)"; docker logs netportal-it-nas 2>&1 | grep -iE "disconnect|coa|error" | tail -10
fi
exit "$status"
