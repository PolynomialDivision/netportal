"""The collector's jobs and their intervals (docs/TELEMETRY.md "Collector")."""

from . import incidents, prune, rollup, unifi_events
from .scheduler import Job

JOBS = (
    Job("unifi_events", 120, unifi_events.run, budget_s=60),
    Job("incidents", 120, incidents.run, budget_s=45),
    Job("rollup", 1800, rollup.run, budget_s=300),
    Job("prune", 86400, prune.run, budget_s=10),
)
BY_NAME = {job.name: job for job in JOBS}


def select(names):
    """The jobs named (comma-separated text or a list), in the table's order; raises on unknown ones."""
    if not names:
        return list(JOBS)
    wanted = [n.strip() for n in (names.split(",") if isinstance(names, str) else names) if n.strip()]
    unknown = sorted(set(wanted) - set(BY_NAME))
    if unknown:
        raise SystemExit("unknown job(s): %s (known: %s)" % (", ".join(unknown), ", ".join(BY_NAME)))
    return [job for job in JOBS if job.name in wanted]
