# FreeRADIUS for the house Wi-Fi against the RUST registry (rust/docs/RADIUS_CONTRACT.md): a copy
# of radius/ whose only changes are the SQL names of the contract (schema radius: view
# radius.valid_cert, functions radius.login / radius.reject / radius.accounting) and comments;
# every access guard of radius/ is kept (README "FreeRADIUS lessons"). The Python version keeps
# radius/ and its own database.
# The image's server with only our modules and sites (rust/radius/mods, rust/radius/sites).
# Mounted at run time, exactly as for radius/: /etc/netportal (RADIUS server certificate, device
# CA chain; from `netportal pki`), /etc/netportal-secrets/radius-server.key and clients.conf (the
# access points). Environment (unchanged):
# RADIUS_DB_HOST, RADIUS_DB_NAME (the Rust registry's database), RADIUS_DB_PASSWORD,
# RADIUS_STATUS_SECRET, DEVICE_CA_DN, RADIUS_SESSION_TIMEOUT (seconds), NETPORTAL_ACCT_INTERIM_S
# (accounting interval, seconds; default 300, set by the entrypoint).
# Built from the repository root, like radius/Dockerfile (docker build -f rust/radius/Dockerfile .);
# rust/radius/Dockerfile.dockerignore keeps the context to rust/radius/ (not rust/target).
# Base image: the same pin as radius/Dockerfile.
FROM freeradius/freeradius-server:3.2.10@sha256:cc7fd136e7b03e7b332d94297530318e824a4ecfedbce54562cced723e71e812
RUN rm -rf /etc/freeradius/mods-enabled/* /etc/freeradius/sites-enabled/*
COPY rust/radius/mods/ /etc/freeradius/mods-enabled/
COPY rust/radius/sites/ /etc/freeradius/sites-enabled/
COPY rust/radius/entrypoint.sh /usr/local/bin/netportal-radius
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD echo "Message-Authenticator = 0x00" | radclient -q -t 2 127.0.0.1:18121 status "$RADIUS_STATUS_SECRET" || exit 1
ENTRYPOINT ["/bin/sh", "/usr/local/bin/netportal-radius"]
CMD ["-f", "-l", "stdout"]
