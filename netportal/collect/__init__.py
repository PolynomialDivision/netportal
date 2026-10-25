"""The collector (container netportal-collect, docs/TELEMETRY.md "Collector"): scheduled jobs that
read Prometheus and Loki and write the registry's telemetry tables. Never run per page view.

  settings.py      the collector's own settings (no web secrets)
  sources.py       small Prometheus and Loki clients with a time budget per job run
  scheduler.py     jobs, intervals, advisory locks, job bookkeeping, SIGTERM, heartbeat
  unifi_events.py  UniFi system log (unpoller -> Loki) -> connection_event
  incidents.py     monitoring signals (Prometheus) -> incident
  rollup.py        Prometheus -> device_day / ap_day (Europe/Berlin days)
  prune.py         the retention (registry.prune), daily
"""
