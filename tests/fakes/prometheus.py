"""A fake Prometheus HTTP API: canned answers per exact PromQL text.

  range_series(promql, [(labels, {t: value})])   query_range answers the points in [start, end]
                                                 (on the request's step grid, like Prometheus)
  vector(promql, [(labels, value)])              instant query answer
  fail(promql=None, status=500)                  that query (None: every query) answers status
Unknown queries answer an empty success (no series), as Prometheus does for missing metrics.
"""

from .server import FakeServer


class FakePrometheus(FakeServer):
    def __init__(self):
        super().__init__()
        self.ranges, self.vectors, self.failures = {}, {}, {}

    def range_series(self, promql, series):
        self.ranges[promql] = series
        return self

    def vector(self, promql, series):
        self.vectors[promql] = series
        return self

    def fail(self, promql=None, status=500):
        self.failures[promql] = status
        return self

    def queries(self, path=None):
        """The PromQL texts asked (optionally only of one path)."""
        with self.lock:
            return [p.get("query") for pth, p in self.requests if path is None or pth == path]

    def answer(self, path, params):
        promql = params.get("query")
        status = self.failures.get(promql, self.failures.get(None))
        if status:
            return status, {"status": "error", "errorType": "fake", "error": "failing on purpose"}
        if path == "/api/v1/query_range":
            start, end, step = int(float(params["start"])), int(float(params["end"])), int(float(params["step"]))
            result = []
            for labels, points in self.ranges.get(promql, []):
                values = [[t, _text(v)] for t, v in sorted(points.items())
                          if start <= t <= end and (t - start) % step == 0]
                if values:
                    result.append({"metric": labels, "values": values})
            return 200, {"status": "success", "data": {"resultType": "matrix", "result": result}}
        if path == "/api/v1/query":
            at = float(params.get("time") or 0)
            result = [{"metric": labels, "value": [at, _text(v)]} for labels, v in self.vectors.get(promql, [])]
            return 200, {"status": "success", "data": {"resultType": "vector", "result": result}}
        return 404, {"status": "error", "error": "unknown path"}


def _text(value):
    if value is None:
        return "NaN"
    return repr(float(value)) if not isinstance(value, str) else value
