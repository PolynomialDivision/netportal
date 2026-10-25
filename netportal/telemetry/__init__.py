"""Wi-Fi telemetry for the "My devices" dashboard and the admins' views (TELEMETRY.md).

Parts:
- client: the Prometheus client (cache, single flight, circuit breaker, page budgets)
- common: MACs, selectors, times, AP names
- identity: a device's MAC windows and conflicts (whose data it is)
- house: HOUSE (internet, router, DNS, speed test, Wi-Fi data age)
- live: DEVICE (live state, identity, login data, findings) and the /api/devices payload
- timeline: events from RADIUS, accounting, UniFi, Prometheus, MAC changes and incidents, merged
- history: the detail page's charts and timeline (24h..90d from Prometheus, 1y/all from rollups)
- admin: overview, APs, incidents, RADIUS rejects, a device's raw rows

Whose data it is: a device's data comes through its MAC windows (identity.py): a MAC's data
outside them belongs to nobody, and windows of different owners that overlap are withheld from
residents (admins see them marked). Only the house's EAP-TLS network counts (essid =
NETPORTAL_SSID on every client selector). Only validated MACs ever go into a query.

The names of the v1 module (netportal/telemetry.py) stay importable from here.
"""

from .admin import aps as admin_aps
from .admin import auth as admin_auth
from .admin import incidents as admin_incidents
from .admin import jsonable
from .admin import overview as admin_overview
from .admin import raw as admin_raw
from .client import (BUDGET_S, CACHE_MAX_ENTRIES, CACHE_SECONDS, LONG_CACHE_SECONDS, SUMMARY_CACHE_SECONDS, Budget,
                     Prometheus, Unavailable)
from .common import (AP_NAME_RE, BANDS, MAC_RE, ap_info, ap_ref, iso, mac_selector, normalise_mac, promql_string,
                     randomized, selectors)
from .history import (CHARTS, DAY_RANGES, HISTORY_RANGES, RANGES, SERIES, empty_history, history,
                      relevant_incidents, zone)
from .house import DEGRADED_LOSS_RATIO, DEGRADED_RTT_MS, empty_house, house, house_status, speedtest
from .identity import (CURRENT_WINDOW_S, RECENT_S, SESSION_S, WINDOW_GRACE_S, Identity, data_bound, from_registry, from_rows,
                       other_owners)
from .live import (ASSOCIATION_START, CACHE_AGE, DAY_TOTALS, GAUGES, LIVE_FIELDS, STALE_AFTER_S, count_changes,
                   count_reconnects, dashboard, device_entry, device_status, empty_status, reconnect_times)
from .timeline import MAX_EVENTS, SAME_ASSOCIATION_S, derive_timeline, event

__all__ = [
    "AP_NAME_RE", "ASSOCIATION_START", "BANDS", "BUDGET_S", "Budget", "CACHE_AGE", "CACHE_MAX_ENTRIES", "CACHE_SECONDS",
    "CHARTS", "DAY_RANGES", "DAY_TOTALS", "DEGRADED_LOSS_RATIO", "DEGRADED_RTT_MS", "GAUGES", "HISTORY_RANGES",
    "Identity", "LIVE_FIELDS", "LONG_CACHE_SECONDS", "MAC_RE", "MAX_EVENTS", "Prometheus", "RANGES", "RECENT_S",
    "SAME_ASSOCIATION_S", "SERIES", "SESSION_S", "STALE_AFTER_S", "SUMMARY_CACHE_SECONDS", "Unavailable",
    "WINDOW_GRACE_S", "CURRENT_WINDOW_S", "admin_aps", "admin_auth", "admin_incidents", "admin_overview", "admin_raw", "ap_info", "ap_ref",
    "count_changes", "count_reconnects", "dashboard", "data_bound", "derive_timeline", "device_entry",
    "device_status", "empty_history", "empty_house", "empty_status", "event", "from_registry", "from_rows", "history",
    "house", "house_status", "iso", "jsonable", "mac_selector", "normalise_mac", "other_owners", "promql_string",
    "randomized", "reconnect_times", "relevant_incidents", "selectors", "speedtest", "zone",
]
