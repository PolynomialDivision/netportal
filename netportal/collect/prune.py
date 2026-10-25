"""Job prune: the retention of docs/TELEMETRY.md (registry.prune), once a day. Moved here from
the offboarding round (2026-10-25) so it also runs while Authentik cannot be read."""

import logging

from .. import registry

log = logging.getLogger("netportal.collect.prune")


def run(ctx):
    # In batches, each committed: a backlog (a flood of rejects, a first run after a long pause)
    # is many short statements, never one that runs into the statement timeout.
    deleted = registry.prune(ctx.db, now=ctx.now, commit=ctx.db.commit) or {}
    ctx.db.commit()
    if any(deleted.values()):
        log.info("prune: %s", ", ".join("%s %d" % kv for kv in sorted(deleted.items()) if kv[1]))
    return {"last_run": {k: int(v) for k, v in deleted.items()}}
