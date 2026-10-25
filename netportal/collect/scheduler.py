"""The collector's scheduler: one process, jobs one after another, each on its interval.

Per run of a job:
- its own database connection (statement_timeout STATEMENT_TIMEOUT, lock_timeout LOCK_TIMEOUT);
  pg_try_advisory_lock(hashtext('netportal-job:<name>')) so two
  collectors (a second container, `python -m netportal job x` by hand) never run the same job at
  once: the second one skips it ("locked");
- registry.job_begin (last_attempt), the job with its previous cursor and a time budget for its
  Prometheus/Loki requests, registry.job_end with ok/error text, duration and the new cursor.
  A failed run keeps the cursor of the progress it committed (ctx.save), nothing more;
- the next run is due one interval after this one started (a failure: after RETRY_S at most).

SIGTERM/SIGINT set a stop flag: the running job finishes its current step (jobs ask
ctx.stopping() between pages and days) and is recorded, then the process exits. The heartbeat
file is touched every HEARTBEAT_S (a thread; also while a job runs, for at most MAX_JOB_S of
it) and after every job, so the container's healthcheck (`find <file> -mmin -10`) can tell a
living scheduler from a hung one.
"""

import datetime
import logging
import signal
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from .. import registry
from .sources import Budget, Loki, Prometheus, SourceError

log = logging.getLogger("netportal.collect")

UTC = datetime.timezone.utc
TICK_S = 15                 # the longest sleep between two looks at the job list
RETRY_S = 900               # a failed job is tried again after at most this (daily jobs too)
STATEMENT_TIMEOUT = "120s"  # no statement of a job may hold the database longer
# A job waits this long at most for a row lock (then its run fails and is retried): it never
# queues behind a migration or a long transaction while holding locks of its own that
# FreeRADIUS's logging functions need (device_mac).
LOCK_TIMEOUT = "5s"
HEARTBEAT_S = 30            # the heartbeat file is touched this often while the loop lives ...
MAX_JOB_S = 600             # ... and a job runs no longer than this (a hung one: no heartbeat)

OK, FAILED, LOCKED = "ok", "failed", "locked"


@dataclass(frozen=True)
class Job:
    name: str
    every_s: int
    run: object                 # run(ctx) -> new cursor (dict) or None (keep the previous one)
    budget_s: float = 60.0      # all Prometheus/Loki requests of one run together


@dataclass
class Context:
    """What a job run gets."""
    db: object
    settings: object
    job: Job
    cursor: dict
    now: datetime.datetime
    stop: threading.Event = field(default_factory=threading.Event)
    saved: dict = None          # the cursor of committed progress (kept if the run fails later)
    _budget: Budget = None

    def stopping(self):
        return self.stop.is_set()

    def save(self, cursor):
        """Progress up to cursor is committed: a later failure keeps it."""
        self.saved = cursor

    @property
    def budget(self):
        if self._budget is None:
            self._budget = Budget(self.job.budget_s)
        return self._budget

    @property
    def prometheus(self):
        if not self.settings.prometheus_url:
            raise SourceError("NETPORTAL_PROMETHEUS_URL is not set")
        return Prometheus(self.settings.prometheus_url, self.settings.query_timeout, budget=self.budget)

    @property
    def loki(self):
        if not self.settings.loki_url:
            raise SourceError("NETPORTAL_LOKI_URL is not set")
        return Loki(self.settings.loki_url, self.settings.query_timeout, budget=self.budget)


def lock_key(name):
    return "netportal-job:" + name


def describe(error):
    """The error text stored in job.last_error (short; no traceback)."""
    text = "%s: %s" % (type(error).__name__, error)
    return text[:500]


def previous_cursor(db, name):
    for row in registry.job_status(db):
        if row.get("name") == name:
            return dict(row.get("cursor") or {})
    return {}


def _first(row):
    if row is None:
        return None
    return next(iter(row.values())) if isinstance(row, dict) else row[0]


def run_job(job, settings, stop=None, now=None):
    """One run of job, recorded in the job table. Returns OK, FAILED or LOCKED; never raises
    (a lost database connection is a failed run, the scheduler goes on)."""
    try:
        return _run_job(job, settings, stop or threading.Event(), now)
    except Exception as e:  # noqa: BLE001
        log.error("job %s: %s", job.name, describe(e))
        return FAILED


def _run_job(job, settings, stop, now):
    began = time.monotonic()
    try:
        db = registry.connect(settings.database_url)
    except Exception as e:  # noqa: BLE001 (recorded in the log; the next tick tries again)
        log.error("job %s: no database connection: %s", job.name, type(e).__name__)
        return FAILED
    with db:
        held = False
        try:
            db.execute("SET statement_timeout = '%s'" % STATEMENT_TIMEOUT)
            db.execute("SET lock_timeout = '%s'" % LOCK_TIMEOUT)
            held = bool(_first(db.execute("SELECT pg_try_advisory_lock(hashtext(%s)) AS locked",
                                          (lock_key(job.name),)).fetchone()))
            db.commit()                         # a session lock: it outlives the transaction
            if not held:
                log.info("job %s: running elsewhere, skipped", job.name)
                return LOCKED
            return _run_locked(db, job, settings, stop, now, began)
        finally:
            if held:
                try:
                    db.rollback()
                    db.execute("SELECT pg_advisory_unlock(hashtext(%s))", (lock_key(job.name),))
                    db.commit()
                except Exception:  # noqa: BLE001 (closing the connection releases it anyway)
                    pass


def _run_locked(db, job, settings, stop, now, began):
    ctx = Context(db=db, settings=settings, job=job, cursor={}, stop=stop,
                  now=now or datetime.datetime.now(UTC))
    try:
        ctx.cursor = previous_cursor(db, job.name)
        registry.job_begin(db, job.name)
        db.commit()
        cursor = job.run(ctx)
        db.commit()
    except Exception as e:  # noqa: BLE001 (recorded, the scheduler goes on)
        db.rollback()
        log.warning("job %s failed: %s", job.name, describe(e))
        try:
            registry.job_end(db, job.name, False, error=describe(e),
                             duration_s=round(time.monotonic() - began, 3), cursor=ctx.saved)
            db.commit()
        except Exception as e2:  # noqa: BLE001
            db.rollback()
            log.error("job %s: could not record the failure: %s", job.name, type(e2).__name__)
        return FAILED
    registry.job_end(db, job.name, True, duration_s=round(time.monotonic() - began, 3),
                     cursor=cursor if cursor is not None else ctx.saved)
    db.commit()
    log.info("job %s ok (%.1f s)", job.name, time.monotonic() - began)
    return OK


def touch(path):
    try:
        Path(path).touch()
    except OSError as e:
        log.warning("heartbeat %s: %s", path, e)


def install_signal_handlers(stop):
    """SIGTERM (docker stop) and SIGINT end the loop after the running step."""
    def handler(signum, _frame):
        log.info("signal %d: stopping after the current step", signum)
        stop.set()
    signal.signal(signal.SIGTERM, handler)
    signal.signal(signal.SIGINT, handler)


class Scheduler:
    def __init__(self, settings, jobs, stop=None, clock=time.time, tick_s=TICK_S, runner=run_job):
        self.settings = settings
        self.jobs = list(jobs)
        self.stop = stop or threading.Event()
        self.clock = clock
        self.tick_s = tick_s
        self.runner = runner
        self.next_due = {}
        self.job_started = None          # monotonic time the running job began (None: none runs)

    def _beat(self):
        """Touches the heartbeat while the loop lives and no job has run longer than MAX_JOB_S."""
        while not self.stop.wait(HEARTBEAT_S):
            started = self.job_started
            if started is None or time.monotonic() - started < MAX_JOB_S:
                touch(self.settings.heartbeat)

    def load_due(self):
        """Next due times from the job table (a restart does not rerun a daily job at once)."""
        now = self.clock()
        self.next_due = {job.name: now for job in self.jobs}
        try:
            with registry.connect(self.settings.database_url) as db:
                rows = {r.get("name"): r for r in registry.job_status(db)}
        except Exception as e:  # noqa: BLE001 (then everything is due now)
            log.warning("job status unreadable (%s): every job is due", type(e).__name__)
            return
        for job in self.jobs:
            last = (rows.get(job.name) or {}).get("last_attempt")
            if last is not None:
                self.next_due[job.name] = min(now + job.every_s, last.timestamp() + job.every_s)

    def run_once(self):
        """Every job once, in order (--once, `job <name>`): 0 if none failed."""
        failed = 0
        for job in self.jobs:
            if self.stop.is_set():
                break
            failed += self.runner(job, self.settings, self.stop) == FAILED
            touch(self.settings.heartbeat)
        return 1 if failed else 0

    def run_forever(self):
        self.load_due()
        threading.Thread(target=self._beat, name="heartbeat", daemon=True).start()
        while not self.stop.is_set():
            touch(self.settings.heartbeat)
            now = self.clock()
            due = sorted((self.next_due[j.name], i, j) for i, j in enumerate(self.jobs)
                         if self.next_due[j.name] <= now)
            if not due:
                wait = min(self.tick_s, min(self.next_due.values()) - now)
                self.stop.wait(max(0.1, wait))
                continue
            job = due[0][2]
            started = self.clock()
            self.job_started = time.monotonic()
            try:
                result = self.runner(job, self.settings, self.stop)
            finally:
                self.job_started = None
            touch(self.settings.heartbeat)
            self.next_due[job.name] = started + (job.every_s if result != FAILED else min(job.every_s, RETRY_S))
        touch(self.settings.heartbeat)
        return 0
