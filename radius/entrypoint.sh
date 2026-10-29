#!/bin/sh
# The RADIUS server key arrives as a root-owned 0600 file (the stack's secrets). FreeRADIUS
# reads its TLS key after dropping to the freerad user, so a copy readable only by freerad is
# made here (in the container's own filesystem), then the server starts.
set -eu
# The accounting interval the Accept asks for (sites/default, Acct-Interim-Interval): whole
# seconds 30..86400 from the stack (the portal reads the same variable), else 300.
case "${NETPORTAL_ACCT_INTERIM_S:-}" in
  ''|0*|*[!0-9]*) NETPORTAL_ACCT_INTERIM_S=300 ;;
esac
if [ "${#NETPORTAL_ACCT_INTERIM_S}" -gt 5 ] || [ "$NETPORTAL_ACCT_INTERIM_S" -lt 30 ] || [ "$NETPORTAL_ACCT_INTERIM_S" -gt 86400 ]; then
  NETPORTAL_ACCT_INTERIM_S=300
fi
export NETPORTAL_ACCT_INTERIM_S
# The IoT SSID whose MAC logins the registry decides (sites/default: Called-Station-Id ends in
# ":<SSID>"); the stack sets it from unifi.yml, else the house's name.
if [ -z "${RADIUS_IOT_SSID:-}" ]; then
  RADIUS_IOT_SSID="Scharni-IoT"
fi
export RADIUS_IOT_SSID
install -d -o freerad -g freerad -m 0700 /run/netportal
install -o freerad -g freerad -m 0400 /etc/netportal-secrets/radius-server.key /run/netportal/radius-server.key
exec freeradius "$@"
