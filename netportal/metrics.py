"""Prometheus metrics (counts only; no names, no devices). What the offboarding sidecar and the
collector (netportal-collect) do happens in other processes: it comes from the registry (job,
audit), not from counters here."""

import logging

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
# The background jobs (the collector's and the offboarding), from the job table.
JOB_LAST_SUCCESS = Gauge("netportal_job_last_success_timestamp_seconds", "When the job last succeeded",
                         ["job"], registry=REGISTRY)
JOB_LAST_ATTEMPT = Gauge("netportal_job_last_attempt_timestamp_seconds", "When the job last started",
                         ["job"], registry=REGISTRY)
JOB_UP = Gauge("netportal_job_up", "Whether the job's last run succeeded", ["job"], registry=REGISTRY)
JOB_DURATION = Gauge("netportal_job_duration_seconds", "How long the job's last run took", ["job"],
                     registry=REGISTRY)

log = logging.getLogger("netportal.metrics")


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
    else:
        render_jobs(db)
    return generate_latest(REGISTRY)


def _epoch(value):
    return value.timestamp() if hasattr(value, "timestamp") else float(value)


def render_jobs(db):
    """The job gauges from registry.job_status. A job that never recorded an attempt (the
    offboarding marks successes only) gets no _up and no _last_attempt series. A failing
    job_status (an older schema) leaves the job gauges out, not the rest."""
    for gauge in (JOB_LAST_SUCCESS, JOB_LAST_ATTEMPT, JOB_UP, JOB_DURATION):
        gauge.clear()
    try:
        rows = registry.job_status(db)
    except Exception as e:  # noqa: BLE001
        log.warning("job status unreadable: %s", type(e).__name__)
        try:
            db.rollback()
        except Exception:  # noqa: BLE001
            pass
        return
    for row in rows:
        name = row.get("name")
        if not name:
            continue
        if row.get("last_success") is not None:
            JOB_LAST_SUCCESS.labels(name).set(_epoch(row["last_success"]))
        if row.get("last_attempt") is not None:
            JOB_LAST_ATTEMPT.labels(name).set(_epoch(row["last_attempt"]))
            JOB_UP.labels(name).set(1 if row.get("last_error") is None and row.get("last_success") is not None
                                    else 0)
        if row.get("duration_s") is not None:
            JOB_DURATION.labels(name).set(float(row["duration_s"]))
