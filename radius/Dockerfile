# FreeRADIUS for the house Wi-Fi: the image's server with only our modules and sites
# (radius/mods, radius/sites). Mounted at run time: /etc/netportal (RADIUS server certificate,
# device CA chain), /etc/netportal-secrets/radius-server.key and clients.conf (the access
# points). Environment:
# RADIUS_DB_HOST, RADIUS_DB_NAME, RADIUS_DB_PASSWORD, RADIUS_STATUS_SECRET, DEVICE_CA_DN,
# RADIUS_SESSION_TIMEOUT (seconds).
FROM freeradius/freeradius-server:3.2.10@sha256:cc7fd136e7b03e7b332d94297530318e824a4ecfedbce54562cced723e71e812
RUN rm -rf /etc/freeradius/mods-enabled/* /etc/freeradius/sites-enabled/*
COPY mods/ /etc/freeradius/mods-enabled/
COPY sites/ /etc/freeradius/sites-enabled/
COPY entrypoint.sh /usr/local/bin/netportal-radius
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD echo "Message-Authenticator = 0x00" | radclient -q -t 2 127.0.0.1:18121 status "$RADIUS_STATUS_SECRET" || exit 1
ENTRYPOINT ["/bin/sh", "/usr/local/bin/netportal-radius"]
CMD ["-f", "-l", "stdout"]
