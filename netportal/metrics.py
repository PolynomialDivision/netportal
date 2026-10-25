"""Prometheus metrics (counts only; no names, no devices). What the offboarding sidecar does
happens in another process: it comes from the registry (job, audit), not from counters here."""

from prometheus_client import CollectorRegistry, Counter, Gauge, generate_latest

from . import registry

REGISTRY = CollectorRegistry()
ENROLMENTS = Counter("netportal_enrolments_total", "Profiles and app enrolments handed out", ["format"],
                     registry=REGISTRY)
DISCONNECTS = Counter("netportal_disconnects_total", "Disconnect-Requests after a revocation, by result",
                      ["result"], registry=REGISTRY)
OFFBOARDED = Counter("netportal_offboarded_devices_total", "Devices revoked because the owner lost access "
                     "(offboarding process)", registry=REGISTRY)
OFFBOARDING_LAST = Gauge("netportal_offboarding_last_success_timestamp_seconds",
                         "When the Authentik reconciliation last succeeded", registry=REGISTRY)
DISCONNECTS_1H = Gauge("netportal_disconnects_last_hour", "Disconnect-Requests of the last hour by result "
                       "(portal and offboarding)", ["result"], registry=REGISTRY)
DEVICES = Gauge("netportal_devices", "Devices by state", ["state"], registry=REGISTRY)
CERTS = Gauge("netportal_certificates", "Devices by certificate state", ["state"], registry=REGISTRY)
TELEMETRY_QUERIES = Counter("netportal_telemetry_queries_total", "Prometheus queries of the device dashboard "
                            "(not the cached answers), by result", ["result"], registry=REGISTRY)
for _result in ("ok", "error"):
    TELEMETRY_QUERIES.labels(_result)         # both series from the start (rate() sees the first error)
UP = Gauge("netportal_registry_up", "Registry reachable", registry=REGISTRY)


def render(db):
    """The exposition; db None (or failing) shows netportal_registry_up 0."""
    try:
        if db is None:
            raise RuntimeError("no registry connection")
        s = registry.stats(db)
        DEVICES.labels("active").set(s["active"])
        DEVICES.labels("revoked").set(s["revoked"])
        CERTS.labels("valid").set(s["valid_certificates"])
        CERTS.labels("expiring_30d").set(s["expiring_30d"])
        CERTS.labels("expired").set(s["expired"])
        if s["offboarding_last_success"] is not None:
            OFFBOARDING_LAST.set(float(s["offboarding_last_success"]))
        for result, count in s["disconnects_1h"].items():
            DISCONNECTS_1H.labels(result).set(count)
        UP.set(1)
    except Exception:  # noqa: BLE001 (the scrape must still answer)
        UP.set(0)
    return generate_latest(REGISTRY)
