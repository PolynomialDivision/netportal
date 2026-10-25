"""Fake HTTP servers for unit tests (real sockets on 127.0.0.1, threads; no Docker):

  FakePrometheus   /api/v1/query and /api/v1/query_range from canned series per PromQL text
  FakeLoki         /loki/api/v1/query_range over canned log lines (selector, time range, limit,
                   direction as Loki does them)

    with FakePrometheus() as prom:
        prom.range_series('max(up{job="unifi"})', [({}, {1000: 1, 1060: 1})])
        client = Prometheus(prom.url)
"""

from .loki import FakeLoki
from .prometheus import FakePrometheus

__all__ = ["FakeLoki", "FakePrometheus"]
