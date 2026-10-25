"""Small Prometheus and Loki clients for the collector.

Not telemetry.Prometheus: that one is built for page views (a cache, a 15 s down-latch, the
dashboard's query counter). The collector runs on a schedule and wants the opposite: no cache,
every failure raised (the job records it), and one time budget per job run so a slow source
cannot hold the scheduler. Queries never carry anything but validated MACs and quoted strings.
"""

import logging
import math
import re
import time

import requests

from .. import registry

log = logging.getLogger("netportal.collect")

MAC_RE = re.compile(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}")


class SourceError(Exception):
    """Prometheus or Loki did not answer usefully (down, slow, an error, an unexpected reply)."""


def normalise_mac(raw):
    """The registry's one normaliser (aa:bb:cc:dd:ee:ff or None)."""
    return registry.normalise_mac(raw)


def mac_matcher(macs):
    """mac="..." or mac=~"a|b" for normalised MACs; anything else is refused."""
    macs = sorted(set(macs))
    if not macs or not all(isinstance(m, str) and MAC_RE.fullmatch(m) for m in macs):
        raise ValueError("only normalised MACs go into a query")
    return 'mac="%s"' % macs[0] if len(macs) == 1 else 'mac=~"%s"' % "|".join(macs)


def promql_string(text):
    """A PromQL string literal of plain text (control characters refused)."""
    if not isinstance(text, str) or any(ord(c) < 32 or ord(c) == 127 for c in text):
        raise ValueError("not a plain string")
    return '"%s"' % text.replace("\\", "\\\\").replace('"', '\\"')


def number(text):
    """A sample value; NaN and infinities (no data) are None."""
    try:
        value = float(text)
    except (TypeError, ValueError):
        return None
    return value if math.isfinite(value) else None


class Budget:
    """One deadline for all the requests of a job run."""

    def __init__(self, seconds, clock=time.monotonic):
        self.clock = clock
        self.deadline = clock() + seconds

    def left(self, cap):
        left = self.deadline - self.clock()
        if left <= 0.05:
            raise SourceError("time budget used up")
        return min(cap, left)


class _Http:
    def __init__(self, url, timeout=20.0, session=None, budget=None):
        if not url:
            raise SourceError("not configured")
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.session = session or requests.Session()
        self.budget = budget

    def within(self, budget):
        """The same client with this budget for its requests."""
        clone = type(self).__new__(type(self))
        clone.__dict__.update(self.__dict__, budget=budget)
        return clone

    def _get(self, path, params):
        timeout = self.budget.left(self.timeout) if self.budget else self.timeout
        try:
            resp = self.session.get(self.url + path, params=params, timeout=timeout)
            status = resp.status_code
            body = resp.json()
        except (requests.RequestException, ValueError) as e:
            raise SourceError("%s %s" % (path, type(e).__name__)) from e
        if status != 200 or not isinstance(body, dict) or body.get("status") != "success":
            raise SourceError("%s HTTP %s" % (path, status))     # never the query: it may hold MACs
        data = body.get("data")
        if not isinstance(data, dict):
            raise SourceError("%s unexpected reply" % path)
        return data


class Prometheus(_Http):
    """Instant and range queries; results as plain Python."""

    def _query(self, path, params):
        timeout = self.budget.left(self.timeout) if self.budget else self.timeout
        params = dict(params, timeout="%ds" % max(1, math.ceil(timeout)))   # Prometheus stops too
        return self._get(path, params)

    def vector(self, promql, at=None):
        """[(labels, value)] of an instant query at Unix time at (None: now)."""
        params = {"query": promql}
        if at is not None:
            params["time"] = "%d" % at
        data = self._query("/api/v1/query", params)
        try:
            if data["resultType"] != "vector":
                raise ValueError("not a vector")
            return [(dict(r["metric"]), number(r["value"][1])) for r in data["result"]]
        except (KeyError, TypeError, ValueError, IndexError) as e:
            raise SourceError("unexpected reply") from e

    def range(self, promql, start, end, step):
        """[(labels, {t: value})] of a range query (t integer Unix seconds)."""
        params = {"query": promql, "start": "%d" % start, "end": "%d" % end, "step": "%d" % step}
        data = self._query("/api/v1/query_range", params)
        try:
            if data["resultType"] != "matrix":
                raise ValueError("not a matrix")
            return [(dict(r["metric"]), {int(round(float(t))): number(v) for t, v in r["values"]})
                    for r in data["result"]]
        except (KeyError, TypeError, ValueError, IndexError) as e:
            raise SourceError("unexpected reply") from e


class Loki(_Http):
    """query_range over log streams."""

    def entries(self, logql, start_ns, end_ns, limit=1000, direction="forward"):
        """[(ts_ns, line, stream labels)] in [start_ns, end_ns), sorted by time, at most limit."""
        params = {"query": logql, "start": "%d" % start_ns, "end": "%d" % end_ns, "limit": "%d" % limit,
                  "direction": direction}
        data = self._get("/loki/api/v1/query_range", params)
        out = []
        try:
            if data["resultType"] != "streams":
                raise ValueError("not streams")
            for stream in data["result"]:
                labels = stream.get("stream") or {}
                for ts, line in stream["values"]:
                    out.append((int(ts), line, labels))
        except (KeyError, TypeError, ValueError) as e:
            raise SourceError("unexpected reply") from e
        out.sort(key=lambda e: e[0], reverse=(direction == "backward"))
        return out
