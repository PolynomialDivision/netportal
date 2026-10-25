# FreeRADIUS for the house Wi-Fi: the image's server with only our modules and sites
# (radius/mods, radius/sites). Mounted at run time: /etc/netportal (RADIUS server certificate,
# device CA chain), /etc/netportal-secrets/radius-server.key and clients.conf (the access
# points). Environment:
# RADIUS_DB_HOST, RADIUS_DB_NAME, RADIUS_DB_PASSWORD, RADIUS_STATUS_SECRET, DEVICE_CA_DN,
# RADIUS_SESSION_TIMEOUT (seconds), NETPORTAL_ACCT_INTERIM_S (accounting interval, seconds; default
# 300, set by the entrypoint).
# Built from the repository root (docker build -f radius/Dockerfile .): a git context with a
# subdirectory (repo.git#<commit>:radius) fails in buildx 0.38 ("failed to stat policy file
# Dockerfile.rego ... 404") whenever the git source is not cached yet.
FROM freeradius/freeradius-server:3.2.10@sha256:cc7fd136e7b03e7b332d94297530318e824a4ecfedbce54562cced723e71e812
RUN rm -rf /etc/freeradius/mods-enabled/* /etc/freeradius/sites-enabled/*
COPY radius/mods/ /etc/freeradius/mods-enabled/
COPY radius/sites/ /etc/freeradius/sites-enabled/
COPY radius/entrypoint.sh /usr/local/bin/netportal-radius
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD echo "Message-Authenticator = 0x00" | radclient -q -t 2 127.0.0.1:18121 status "$RADIUS_STATUS_SECRET" || exit 1
ENTRYPOINT ["/bin/sh", "/usr/local/bin/netportal-radius"]
CMD ["-f", "-l", "stdout"]
