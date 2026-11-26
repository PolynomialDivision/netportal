# The test client: eapol_test (wpa_supplicant's EAP test tool) and radclient. PoC only.
FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends eapoltest freeradius-utils ca-certificates \
 && rm -rf /var/lib/apt/lists/*
