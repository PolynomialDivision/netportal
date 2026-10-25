"""The collector's scheduler, CLI, prune wiring and job metrics (netportal.collect, metrics.py).
The registry is the in-memory fake of tests/fakes/registry.py (no database)."""

import datetime
import logging
import os
import signal
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from fakes.registry import FakeRegistry

from netportal import __main__ as cli
from netportal import metrics, offboarding
from netportal.collect import jobs, scheduler
from netportal.collect import settings as collect_settings
from netportal.collect.scheduler import FAILED, LOCKED, OK, Job, Scheduler

UTC = datetime.timezone.utc
logging.getLogger("netportal.collect").setLevel(logging.ERROR + 10)     # the runs log a lot


def settings(tmp, **kw):
    values = dict(database_url="postgresql://fake/netportal", ssid="Scharni", heartbeat=str(Path(tmp) / "beat"))
    values.update(kw)
    return collect_settings.CollectSettings(**values)


class CollectorCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.reg = FakeRegistry()
        patch = self.reg.patched()
        patch.__enter__()
        self.addCleanup(patch.__exit__, None, None, None)
        self.settings = settings(self.tmp.name)


class RunJobTests(CollectorCase):
    def test_ok_records_begin_end_cursor_and_releases_the_lock(self):
        seen = []

        def work(ctx):
            seen.append((dict(ctx.cursor), self.reg.jobs["x"]["last_attempt"] is not None))
            return {"until": 5}

        self.assertEqual(scheduler.run_job(Job("x", 60, work), self.settings), OK)
        row = self.reg.jobs["x"]
        self.assertEqual(seen, [({}, True)])           # job_begin before the work, no cursor yet
        self.assertIsNotNone(row["last_success"])
        self.assertIsNone(row["last_error"])
        self.assertEqual(row["cursor"], {"until": 5})
        self.assertIsInstance(row["duration_s"], float)
        self.assertEqual(self.reg.locks, {})
        self.assertTrue(self.reg.connections[0].closed)
        self.assertIn("SET statement_timeout = '120s'", self.reg.connections[0].statements)
        self.assertIn("SET lock_timeout = '5s'", self.reg.connections[0].statements)

    def test_cursor_advances_from_run_to_run(self):
        def work(ctx):
            return {"n": ctx.cursor.get("n", 0) + 1}
        job = Job("x", 60, work)
        for _ in range(3):
            scheduler.run_job(job, self.settings)
        self.assertEqual(self.reg.jobs["x"]["cursor"], {"n": 3})

    def test_none_keeps_the_previous_cursor(self):
        scheduler.run_job(Job("x", 60, lambda ctx: {"a": 1}), self.settings)
        scheduler.run_job(Job("x", 60, lambda ctx: None), self.settings)
        self.assertEqual(self.reg.jobs["x"]["cursor"], {"a": 1})

    def test_error_is_recorded_with_the_committed_progress(self):
        def work(ctx):
            ctx.save({"until": 7})
            raise RuntimeError("Loki said no")

        scheduler.run_job(Job("x", 60, lambda ctx: {"until": 1}), self.settings)
        before = self.reg.jobs["x"]["last_success"]
        self.assertEqual(scheduler.run_job(Job("x", 60, work), self.settings), FAILED)
        row = self.reg.jobs["x"]
        self.assertEqual(row["last_error"], "RuntimeError: Loki said no")
        self.assertEqual(row["last_success"], before)
        self.assertEqual(row["cursor"], {"until": 7})
        self.assertEqual(self.reg.locks, {})
        self.assertGreaterEqual(self.reg.connections[-1].rollbacks, 1)

    def test_failure_without_progress_keeps_the_cursor(self):
        scheduler.run_job(Job("x", 60, lambda ctx: {"until": 1}), self.settings)

        def boom(ctx):
            raise ValueError("bad reply")
        scheduler.run_job(Job("x", 60, boom), self.settings)
        self.assertEqual(self.reg.jobs["x"]["cursor"], {"until": 1})

    def test_a_job_held_elsewhere_is_skipped(self):
        other = self.reg.connect("dsn")
        other.execute("SELECT pg_try_advisory_lock(hashtext(%s))", (scheduler.lock_key("x"),))
        ran = []
        self.assertEqual(scheduler.run_job(Job("x", 60, ran.append), self.settings), LOCKED)
        self.assertEqual(ran, [])
        self.assertNotIn("x", self.reg.jobs)                # no job_begin: nothing to record
        self.assertIs(self.reg.locks[scheduler.lock_key("x")], other)   # not released by the skipper
        self.assertEqual(scheduler.run_job(Job("y", 60, lambda ctx: None), self.settings), OK)  # per job

    def test_no_database_is_a_failed_run_not_a_crash(self):
        self.reg.connect_error = OSError("connection refused")
        self.assertEqual(scheduler.run_job(Job("x", 60, lambda ctx: None), self.settings), FAILED)

    def test_sources_need_their_urls(self):
        def work(ctx):
            ctx.prometheus.vector("up")
        scheduler.run_job(Job("x", 60, work), self.settings)
        self.assertIn("NETPORTAL_PROMETHEUS_URL", self.reg.jobs["x"]["last_error"])


class SchedulerTests(CollectorCase):
    def test_run_once_runs_each_job_and_reports_failures(self):
        calls = []

        def runner(job, settings, stop):
            calls.append(job.name)
            return FAILED if job.name == "b" else OK
        sched = Scheduler(self.settings, [Job("a", 60, None), Job("b", 60, None)], runner=runner)
        self.assertEqual(sched.run_once(), 1)
        self.assertEqual(calls, ["a", "b"])
        self.assertTrue(Path(self.settings.heartbeat).exists())

    def test_restart_does_not_rerun_a_daily_job_at_once(self):
        now = time.time()
        self.reg.jobs["prune"] = {"name": "prune", "last_attempt": datetime.datetime.fromtimestamp(now - 3600, UTC)}
        sched = Scheduler(self.settings, [Job("prune", 86400, None), Job("incidents", 120, None)], clock=lambda: now)
        sched.load_due()
        self.assertAlmostEqual(sched.next_due["prune"], now - 3600 + 86400, delta=1)
        self.assertEqual(sched.next_due["incidents"], now)

    def test_loop_runs_due_jobs_in_turn(self):
        clock = {"t": 1000.0}
        calls = []
        stop = threading.Event()

        def runner(job, settings, stop_):
            calls.append((job.name, clock["t"]))
            clock["t"] += 10
            if len(calls) >= 5:
                stop.set()
            return OK if job.name != "b" else FAILED
        sched = Scheduler(self.settings, [Job("a", 30, None), Job("b", 3600, None)], stop=stop,
                          clock=lambda: clock["t"], runner=runner, tick_s=0.01)
        orig_wait = stop.wait

        def fake_wait(timeout):        # sleeping moves the fake clock
            clock["t"] += timeout
            return orig_wait(0)
        stop.wait = fake_wait
        with mock.patch.object(Scheduler, "_beat", lambda self: None):     # its waits would move the clock
            sched.run_forever()
        names = [n for n, _ in calls]
        self.assertEqual(names[:2], ["a", "b"])
        self.assertEqual(names.count("b"), 1)               # failed: retried after RETRY_S, not within 50 s
        self.assertTrue(all(n == "a" for n in names[2:]))

    def test_heartbeat_while_a_job_runs_but_not_for_a_hung_one(self):
        beat = Path(self.settings.heartbeat)
        stop = threading.Event()
        release = threading.Event()

        def runner(job, settings, stop_):
            release.wait(2)
            return OK
        sched = Scheduler(self.settings, [Job("a", 3600, None)], stop=stop, runner=runner)
        with mock.patch.object(scheduler, "HEARTBEAT_S", 0.05), mock.patch.object(scheduler, "MAX_JOB_S", 0.3):
            thread = threading.Thread(target=sched.run_forever)
            thread.start()
            time.sleep(0.15)
            beat.unlink()
            time.sleep(0.1)
            self.assertTrue(beat.exists())                  # the job runs: still beating
            time.sleep(0.3)
            beat.unlink()
            time.sleep(0.2)
            self.assertFalse(beat.exists())                 # longer than MAX_JOB_S: hung, no beat
            release.set()
            stop.set()
            thread.join(2)
        self.assertTrue(beat.exists())

    def test_sigterm_ends_the_loop_after_the_running_job(self):
        stop = threading.Event()
        started, finished = threading.Event(), []

        def runner(job, settings, stop_):
            started.set()
            time.sleep(0.2)
            finished.append(stop_.is_set())
            return OK
        sched = Scheduler(self.settings, [Job("a", 3600, None)], stop=stop, runner=runner, tick_s=0.05)
        old = signal.getsignal(signal.SIGTERM), signal.getsignal(signal.SIGINT)
        self.addCleanup(signal.signal, signal.SIGTERM, old[0])
        self.addCleanup(signal.signal, signal.SIGINT, old[1])
        scheduler.install_signal_handlers(stop)
        result = {}
        thread = threading.Thread(target=lambda: result.setdefault("rc", sched.run_forever()))
        thread.start()
        self.assertTrue(started.wait(2))
        os.kill(os.getpid(), signal.SIGTERM)
        deadline = time.time() + 3
        while thread.is_alive() and time.time() < deadline:
            time.sleep(0.02)          # the handler runs in the main thread between bytecodes
        thread.join(1)
        self.assertFalse(thread.is_alive())
        self.assertEqual(result["rc"], 0)
        self.assertEqual(finished, [True])                   # the job finished, it saw the stop
        self.assertTrue(Path(self.settings.heartbeat).exists())


class CliTests(CollectorCase):
    ENV = {"NETPORTAL_DATABASE_URL": "postgresql://fake/netportal", "NETPORTAL_SSID": "Scharni"}

    def env(self, **extra):
        values = dict(self.ENV, NETPORTAL_COLLECT_HEARTBEAT=str(Path(self.tmp.name) / "hb"), **extra)
        return mock.patch.dict(os.environ, values, clear=True)

    def test_settings_need_no_web_secrets(self):
        with mock.patch.dict(os.environ, dict(self.ENV, NETPORTAL_HEARTBEAT="/tmp/x.heartbeat"), clear=True):
            self.assertEqual(collect_settings.load().heartbeat, "/tmp/x.heartbeat")    # the stack's name
        with self.env():
            s = collect_settings.load()
        self.assertEqual((s.ssid, s.timezone, s.prometheus_url, s.loki_url), ("Scharni", "Europe/Berlin", "", ""))
        self.assertEqual(s.loki_selector, '{application="unifi_system_log",category="CLIENT_DEVICES"}')

    def test_settings_refuse_bad_values(self):
        for extra in ({"NETPORTAL_PROMETHEUS_URL": "prometheus:9090"}, {"NETPORTAL_TIMEZONE": "Mars/Base"},
                      {"NETPORTAL_LOKI_SELECTOR": 'application="x"'}, {"NETPORTAL_RADIUS_CONTAINER": "a b"}):
            with self.env(**extra), self.assertRaises((RuntimeError, KeyError), msg=str(extra)):
                collect_settings.load()
        with mock.patch.dict(os.environ, {"NETPORTAL_SSID": "x"}, clear=True), self.assertRaises(RuntimeError):
            collect_settings.load()

    def test_job_command_runs_one_job(self):
        with self.env():
            rc = cli.main(["job", "prune"])
        self.assertEqual(rc, 0)
        self.assertEqual(len(self.reg.prune_calls), 1)
        self.assertTrue(callable(self.reg.prune_commits))              # in batches, each committed
        self.assertEqual(list(self.reg.jobs), ["prune"])
        self.assertTrue((Path(self.tmp.name) / "hb").exists())

    def test_collect_once_with_a_job_list(self):
        with self.env():
            rc = cli.main(["collect", "--once", "--jobs", "prune,incidents"])
        self.assertEqual(rc, 1)                              # incidents: no Prometheus configured
        self.assertIn("NETPORTAL_PROMETHEUS_URL", self.reg.jobs["incidents"]["last_error"])
        self.assertIsNotNone(self.reg.jobs["prune"]["last_success"])

    def test_unknown_job(self):
        with self.env(), self.assertRaises(SystemExit):
            cli.main(["job", "nope"])

    def test_the_job_table(self):
        self.assertEqual([(j.name, j.every_s) for j in jobs.JOBS],
                         [("unifi_events", 120), ("incidents", 120), ("rollup", 1800), ("prune", 86400)])


class PruneTests(CollectorCase):
    def test_prune_job_calls_the_registry_with_the_run_time(self):
        now = datetime.datetime(2026, 10, 25, 3, 0, tzinfo=UTC)
        self.assertEqual(scheduler.run_job(jobs.BY_NAME["prune"], self.settings, now=now), OK)
        self.assertEqual(self.reg.prune_calls, [now])
        self.assertEqual(self.reg.jobs["prune"]["cursor"], {"last_run": {"radius_auth": 3, "connection_event": 0}})

    def test_offboarding_no_longer_prunes(self):
        from types import SimpleNamespace
        db = mock.MagicMock()
        db.__enter__.return_value = db
        with mock.patch.object(offboarding, "read_directory", return_value=({}, set())), \
                mock.patch.object(offboarding.registry, "connect", return_value=db), \
                mock.patch.object(offboarding.registry, "subjects_to_check", return_value=set()), \
                mock.patch.object(offboarding.registry, "prune") as prune, \
                mock.patch.object(offboarding.registry, "mark_job") as mark:
            offboarding.run(SimpleNamespace(authentik_api="http://ak/api/v3", authentik_token="t",
                                            database_url="postgresql://fake"))
        prune.assert_not_called()
        mark.assert_called_once_with(db, "offboarding")


class JobMetricsTests(unittest.TestCase):
    def render(self, rows, stats_ok=True):
        db = mock.MagicMock()
        stats = {"active": 1, "revoked": 0, "valid_certificates": 1, "expiring_30d": 0, "expired": 0,
                 "offboarding_last_success": 1792900000.0, "disconnects_1h": {"ack": 0}}
        status = mock.Mock(return_value=rows) if not isinstance(rows, Exception) else mock.Mock(side_effect=rows)
        with mock.patch.object(metrics.registry, "stats", return_value=stats), \
                mock.patch.object(metrics.registry, "job_status", status, create=True):
            return metrics.render(db).decode()

    def test_job_gauges(self):
        t = datetime.datetime(2026, 10, 25, 12, 0, tzinfo=UTC)
        text = self.render([
            {"name": "rollup", "last_success": t, "last_attempt": t, "last_error": None, "duration_s": 3.5,
             "cursor": {}},
            {"name": "unifi_events", "last_success": None, "last_attempt": t, "last_error": "SourceError: x",
             "duration_s": 1.0, "cursor": {}},
            {"name": "offboarding", "last_success": t, "last_attempt": None, "last_error": None, "duration_s": None,
             "cursor": {}},
        ])
        self.assertIn('netportal_job_up{job="rollup"} 1.0', text)
        self.assertIn('netportal_job_up{job="unifi_events"} 0.0', text)
        self.assertNotIn('netportal_job_up{job="offboarding"}', text)       # successes only: no _up
        self.assertIn('netportal_job_last_success_timestamp_seconds{job="offboarding"} 1.7929296e+09', text)
        self.assertIn('netportal_job_last_attempt_timestamp_seconds{job="rollup"}', text)
        self.assertIn('netportal_job_duration_seconds{job="rollup"} 3.5', text)
        self.assertIn("netportal_offboarding_last_success_timestamp_seconds 1.7929e+09", text)
        self.assertIn("netportal_registry_up 1.0", text)

    def test_old_schema_leaves_out_only_the_job_gauges(self):
        text = self.render(RuntimeError("column cursor does not exist"))
        self.assertIn("netportal_registry_up 1.0", text)
        self.assertNotIn("netportal_job_up{", text)

    def test_vanished_jobs_disappear(self):
        t = datetime.datetime(2026, 10, 25, 12, 0, tzinfo=UTC)
        self.render([{"name": "old", "last_success": t, "last_attempt": t, "last_error": None}])
        self.assertNotIn('job="old"', self.render([]))


if __name__ == "__main__":
    unittest.main()
