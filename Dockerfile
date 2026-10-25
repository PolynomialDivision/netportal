# netportal: the Wi-Fi portal (gunicorn, one worker with threads: metrics live in the process).
# The same image runs the offboarding sidecar: python -m netportal offboard --every 900
# and the collector: python -m netportal collect (docs/TELEMETRY.md)
FROM python:3.13-slim@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f
# openssl: the Android Passpoint PKCS#12 is made exactly like the reference tools (netportal/profiles.py).
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl curl \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /app netportal
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY netportal ./netportal
USER netportal
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8080/healthz >/dev/null || exit 1
# No access log: Caddy logs requests already; the portal logs only what it changes.
ENV GUNICORN_CMD_ARGS="--bind 0.0.0.0:8080 --workers 1 --threads 8"
CMD ["gunicorn", "netportal.wsgi:app"]
