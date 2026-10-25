"""The collector's settings, from the environment. Only what the collector uses: no session,
OIDC, DAE or CA secrets (config.load() requires those for the web app; the collector must start
without them).

  NETPORTAL_DATABASE_URL (or NETPORTAL_DATABASE_URL_FILE)   required
  NETPORTAL_PROMETHEUS_URL     http(s)://host:port; "" = the Prometheus jobs fail (recorded)
  NETPORTAL_LOKI_URL           http(s)://host:port; "" = unifi_events fails (recorded)
  NETPORTAL_SSID               the house's EAP-TLS network: only its clients count (required)
  NETPORTAL_TIMEZONE           the days of the rollups (Europe/Berlin)
  NETPORTAL_COLLECT_HEARTBEAT or NETPORTAL_HEARTBEAT
                               the file the scheduler touches (container healthcheck)
  NETPORTAL_COLLECT_QUERY_TIMEOUT   seconds per Prometheus/Loki request (20)
  NETPORTAL_LOKI_SELECTOR      the LogQL stream selector of the UniFi system log's client entries
  NETPORTAL_RADIUS_CONTAINER   the FreeRADIUS container's name in cadvisor (netaccess-radius)
"""

import os
import re
from dataclasses import dataclass
from pathlib import Path

DEFAULT_LOKI_SELECTOR = '{application="unifi_system_log",category="CLIENT_DEVICES"}'


def _env(name, default=None):
    value = os.environ.get(name, default)
    if value is None or value == "":
        raise RuntimeError("missing setting %s" % name)
    return value


def _secret(name):
    """NAME_FILE (a mounted secret file) wins over NAME."""
    path = os.environ.get(name + "_FILE")
    if path:
        return Path(path).read_text().strip()
    return _env(name)


def _url(name):
    url = os.environ.get(name, "").strip().rstrip("/")
    if url and not re.fullmatch(r"https?://[^\s/?#]+(/[^\s?#]*)?", url):
        raise RuntimeError("%s: %r is not an http(s) URL" % (name, url))
    return url


@dataclass(frozen=True)
class CollectSettings:
    database_url: str
    ssid: str
    prometheus_url: str = ""
    loki_url: str = ""
    timezone: str = "Europe/Berlin"
    heartbeat: str = "/tmp/netportal-collect.heartbeat"
    query_timeout: float = 20.0
    loki_selector: str = DEFAULT_LOKI_SELECTOR
    radius_container: str = "netaccess-radius"


def load():
    selector = os.environ.get("NETPORTAL_LOKI_SELECTOR", "").strip() or DEFAULT_LOKI_SELECTOR
    if not re.fullmatch(r"\{[^{}]+\}", selector):
        raise RuntimeError("NETPORTAL_LOKI_SELECTOR: %r is not a stream selector {...}" % selector)
    container = os.environ.get("NETPORTAL_RADIUS_CONTAINER", "").strip() or "netaccess-radius"
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", container):
        raise RuntimeError("NETPORTAL_RADIUS_CONTAINER: %r is not a container name" % container)
    timezone = os.environ.get("NETPORTAL_TIMEZONE", "").strip() or "Europe/Berlin"
    from zoneinfo import ZoneInfo
    ZoneInfo(timezone)                                  # raises for an unknown zone: at start, not at night
    return CollectSettings(
        database_url=_secret("NETPORTAL_DATABASE_URL"),
        ssid=_env("NETPORTAL_SSID"),
        prometheus_url=_url("NETPORTAL_PROMETHEUS_URL"),
        loki_url=_url("NETPORTAL_LOKI_URL"),
        timezone=timezone,
        heartbeat=(os.environ.get("NETPORTAL_COLLECT_HEARTBEAT", "") or os.environ.get("NETPORTAL_HEARTBEAT", "")
                   or "/tmp/netportal-collect.heartbeat"),
        query_timeout=float(os.environ.get("NETPORTAL_COLLECT_QUERY_TIMEOUT", "") or "20"),
        loki_selector=selector,
        radius_container=container,
    )
