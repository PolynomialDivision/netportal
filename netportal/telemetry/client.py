"""The Prometheus client: instant and range queries over one HTTP session, cached, one fetch per
query at a time (single flight), a circuit breaker, and page budgets.

Answers are cached 15 s (summaries: 60 s, long ranges: 5 min). Each page's queries share one
time budget (Budget, BUDGET_S): any failure or an exhausted budget makes the page's telemetry
"unavailable", and for 15 s nothing is asked (a slow Prometheus must not hold the portal's
threads). The query text is never logged: it holds MACs.
"""

import logging
import math
import threading
import time

import requests

from .. import metrics
from .common import number

log = logging.getLogger("netportal.telemetry")

CACHE_SECONDS = 15
SUMMARY_CACHE_SECONDS = 60      # the 24 h and 7 day summaries change slowly
LONG_CACHE_SECONDS = 300        # 30 and 90 day charts: a new point every 2 or 6 hours
CACHE_MAX_ENTRIES = 512
# All of a page's queries together; each query gets what is left, at most the configured timeout,
# and Prometheus is told to stop then too.
BUDGET_S = 5.0
_MISSING = object()


class Unavailable(Exception):
    """Prometheus did not answer usefully: down, slow, an error, an unexpected reply."""


def _labels(metric):
    if not isinstance(metric, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in metric.items()):
        raise ValueError("labels")
    return metric


def _parse_vector(data):
    if data["resultType"] != "vector":
        raise ValueError("not a vector")
    return [(_labels(r["metric"]), number(r["value"][1])) for r in data["result"]]


def _parse_matrix(data):
    if data["resultType"] != "matrix":
        raise ValueError("not a matrix")
    return [(_labels(r["metric"]), [(round(float(t)), number(v)) for t, v in r["values"]]) for r in data["result"]]


class Prometheus:
    """Instant and range queries over one HTTP session, cached, one fetch per query at a time."""

    def __init__(self, url, timeout=4.0, ssid="", session=None, clock=time.monotonic):
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.ssid = ssid                  # the house's EAP-TLS network: only its clients count
        self.session = session or requests.Session()
        self.clock = clock
        self._cache = {}
        self._inflight = {}
        self._down_until = 0.0
        self._lock = threading.Lock()

    def within(self, seconds=BUDGET_S):
        """This client with one time budget for all the queries made through it."""
        return Budget(self, self.clock() + seconds)

    def vector(self, promql, at=None, ttl=CACHE_SECONDS, deadline=None):
        """[(labels, value)] of an instant query."""
        return self._get("query", self._params(promql, time=at), _parse_vector, ttl, deadline)

    def matrix(self, promql, at=None, ttl=CACHE_SECONDS, deadline=None):
        """[(labels, [(t, value)])] of an instant query of a range (a subquery)."""
        return self._get("query", self._params(promql, time=at), _parse_matrix, ttl, deadline)

    def range(self, promql, start, end, step, ttl=CACHE_SECONDS, deadline=None):
        """[(labels, [(t, value)])] of a range query."""
        return self._get("query_range", self._params(promql, start=start, end=end, step=step), _parse_matrix,
                         ttl, deadline)

    @staticmethod
    def _params(promql, **extra):
        params = {"query": promql}
        params.update({k: "%d" % v for k, v in extra.items() if v is not None})
        return params

    def _lookup(self, key):
        hit = self._cache.get(key)
        return hit[1] if hit and hit[0] > self.clock() else _MISSING

    def _time_left(self, deadline):
        left = self.timeout if deadline is None else min(self.timeout, deadline - self.clock())
        return max(0.05, left)

    def _get(self, path, params, parse, ttl, deadline):
        key = (path, tuple(sorted(params.items())))
        refused = None
        with self._lock:
            hit = self._lookup(key)
            if hit is not _MISSING:
                return hit
            now = self.clock()
            if self._down_until > now:
                raise Unavailable("failed less than %d s ago" % CACHE_SECONDS)
            if deadline is not None and now >= deadline:
                refused = "time budget used up"
            else:
                flight = self._inflight.get(key)
                leader = flight is None
                if leader:
                    flight = self._inflight[key] = threading.Event()
        if refused:
            self._failed(refused, down=True)
            raise Unavailable(refused)
        if not leader:
            # the same query is on its way (another thread): wait for its answer, not a second fetch
            flight.wait(self._time_left(deadline))
            with self._lock:
                hit = self._lookup(key)
            if hit is not _MISSING:
                return hit
            raise Unavailable("the same query failed or did not finish")
        try:
            return self._fetch(key, path, params, parse, ttl, deadline)
        finally:
            with self._lock:
                self._inflight.pop(key, None)
            flight.set()

    def _fetch(self, key, path, params, parse, ttl, deadline):
        timeout = self._time_left(deadline)
        sent = dict(params, timeout="%ds" % max(1, math.ceil(timeout)))    # Prometheus stops evaluating too
        try:
            resp = self.session.get("%s/api/v1/%s" % (self.url, path), params=sent, timeout=timeout)
            status = resp.status_code
            body = resp.json()
        except (requests.RequestException, ValueError) as e:
            self._failed(type(e).__name__, down=True)
            raise Unavailable(type(e).__name__) from e
        if status != 200 or not isinstance(body, dict) or body.get("status") != "success":
            # 4xx: this query is wrong (a bug here), Prometheus itself works; 5xx: it does not
            self._failed("HTTP %s" % status, down=status >= 500)
            raise Unavailable("HTTP %s" % status)
        try:
            result = parse(body["data"])
        except (KeyError, TypeError, ValueError, IndexError, AttributeError) as e:
            self._failed("unexpected reply", down=False)
            raise Unavailable("unexpected reply") from e
        metrics.TELEMETRY_QUERIES.labels("ok").inc()
        with self._lock:
            now = self.clock()
            if len(self._cache) >= CACHE_MAX_ENTRIES:
                self._cache = {k: v for k, v in self._cache.items() if v[0] > now}
                if len(self._cache) >= CACHE_MAX_ENTRIES:
                    self._cache.clear()
            self._cache[key] = (now + ttl, result)
        return result

    def _failed(self, why, down):
        metrics.TELEMETRY_QUERIES.labels("error").inc()
        log.warning("Prometheus query failed: %s", why)        # never the query: it holds MACs
        if down:
            with self._lock:
                self._down_until = self.clock() + CACHE_SECONDS


class Budget:
    """A Prometheus client whose queries share one deadline (one page's worth). web.py makes one
    per page view and hands it to every telemetry function of that page (the device page: the
    live status and the history together)."""

    def __init__(self, client, deadline):
        self.client, self.deadline, self.ssid = client, deadline, client.ssid

    def within(self, seconds=BUDGET_S):
        return self                               # already counting

    def vector(self, promql, at=None, ttl=CACHE_SECONDS):
        return self.client.vector(promql, at, ttl, self.deadline)

    def matrix(self, promql, at=None, ttl=CACHE_SECONDS):
        return self.client.matrix(promql, at, ttl, self.deadline)

    def range(self, promql, start, end, step, ttl=CACHE_SECONDS):
        return self.client.range(promql, start, end, step, ttl, self.deadline)
