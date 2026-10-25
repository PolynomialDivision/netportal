"""A fake Loki query_range API over canned log lines.

  push(labels, ts_ns, line)    one entry of a stream
  fail(status=500)             every query answers status
The query's stream selector ({k="v", k=~"a|b"}; line filters after it are ignored) picks the
streams; entries in [start, end) sorted by direction, at most limit across all streams, grouped
back into streams, as Loki answers them.
"""

import re

from .server import FakeServer

_MATCHER = re.compile(r'\s*([A-Za-z_][A-Za-z0-9_]*)\s*(=~|!=|!~|=)\s*"((?:[^"\\]|\\.)*)"\s*,?')


def parse_selector(logql):
    m = re.match(r"\s*\{([^}]*)\}", logql or "")
    if not m:
        raise ValueError("no stream selector")
    return [(k, op, v.replace('\\"', '"')) for k, op, v in _MATCHER.findall(m.group(1))]


def matches(matchers, labels):
    for key, op, value in matchers:
        have = labels.get(key, "")
        if op == "=" and have != value or op == "!=" and have == value:
            return False
        if op == "=~" and not re.fullmatch(value, have) or op == "!~" and re.fullmatch(value, have):
            return False
    return True


class FakeLoki(FakeServer):
    def __init__(self):
        super().__init__()
        self.entries, self.status = [], None

    def push(self, labels, ts_ns, line):
        self.entries.append((dict(labels), int(ts_ns), line))
        return self

    def fail(self, status=500):
        self.status = status
        return self

    def answer(self, path, params):
        if self.status:
            return self.status, {"status": "error", "error": "failing on purpose"}
        if path != "/loki/api/v1/query_range":
            return 404, {"status": "error", "error": "unknown path"}
        matchers = parse_selector(params["query"])
        start, end = int(params["start"]), int(params["end"])
        limit, direction = int(params.get("limit", "100")), params.get("direction", "backward")
        picked = [e for e in self.entries if matches(matchers, e[0]) and start <= e[1] < end]
        picked.sort(key=lambda e: e[1], reverse=direction == "backward")
        picked = picked[:limit]
        streams = {}
        for labels, ts, line in picked:
            streams.setdefault(tuple(sorted(labels.items())), []).append([str(ts), line])
        result = [{"stream": dict(k), "values": v} for k, v in streams.items()]
        return 200, {"status": "success", "data": {"resultType": "streams", "result": result}}
