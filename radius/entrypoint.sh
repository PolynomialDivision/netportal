#!/bin/sh
# The RADIUS server key arrives as a root-owned 0600 file (the stack's secrets). FreeRADIUS
# reads its TLS key after dropping to the freerad user, so a copy readable only by freerad is
# made here (in the container's own filesystem), then the server starts.
set -eu
install -d -o freerad -g freerad -m 0700 /run/netportal
install -o freerad -g freerad -m 0400 /etc/netportal-secrets/radius-server.key /run/netportal/radius-server.key
exec freeradius "$@"
