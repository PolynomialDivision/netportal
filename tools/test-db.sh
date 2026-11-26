#!/usr/bin/env bash
# A throwaway PostgreSQL for the database tests (local Docker, random port on 127.0.0.1).
#
#   eval "$(tools/test-db.sh)"        start one; exports NETPORTAL_TEST_DATABASE_URL and
#                                     NETPORTAL_TEST_DB_CONTAINER
#   tools/test-db.sh stop [NAME]      remove it (default: $NETPORTAL_TEST_DB_CONTAINER)
#
# The URL is a superuser's (as in production, where the netportal user owns the database); the
# tests create a database per test and the role radius themselves. NETPORTAL_TEST_PG_IMAGE
# overrides the image (default: the one production and the Python tests run).
set -euo pipefail

IMAGE="${NETPORTAL_TEST_PG_IMAGE:-docker.io/library/postgres:18.6-alpine@sha256:898c60cb390d1085bc97bdd6a1ae968757421df394b071848b52b1c09c89d6a5}"

if [ "${1:-}" = "stop" ]; then
    name="${2:-${NETPORTAL_TEST_DB_CONTAINER:-}}"
    [ -n "$name" ] || { echo "test-db.sh stop: no container name" >&2; exit 2; }
    docker rm -f "$name" >/dev/null
    exit 0
fi

if ! command -v docker >/dev/null || ! docker info >/dev/null 2>&1; then
    echo "test-db.sh: Docker is not available" >&2
    exit 1
fi

password="test-$(od -An -tx1 -N8 /dev/urandom | tr -d ' \n')"
name="netportal-rust-test-pg-$(od -An -tx1 -N4 /dev/urandom | tr -d ' \n')"
docker run -d --rm --name "$name" -p 127.0.0.1::5432 \
    -e POSTGRES_USER=netportal -e POSTGRES_PASSWORD="$password" -e POSTGRES_DB=netportal \
    "$IMAGE" >/dev/null
port="$(docker port "$name" 5432/tcp | head -n1 | sed 's/.*://')"
for _ in $(seq 1 120); do
    # over TCP: during the image's first-start initialisation only the socket listens
    if docker exec "$name" pg_isready -q -h 127.0.0.1 -U netportal; then
        echo "export NETPORTAL_TEST_DATABASE_URL='postgresql://netportal:${password}@127.0.0.1:${port}/netportal'"
        echo "export NETPORTAL_TEST_DB_CONTAINER='${name}'"
        exit 0
    fi
    sleep 0.5
done
docker rm -f "$name" >/dev/null
echo "test-db.sh: PostgreSQL did not start" >&2
exit 1
