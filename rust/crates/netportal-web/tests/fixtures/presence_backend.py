"""The Python backend's presence (netportal/presence.py decide + public) for the cases of
tests/test_dashboard_pages.py PresencePagesTests.test_the_backends_presence_renders, as JSON."""
import datetime as dt
import json
import sys

sys.path.insert(0, sys.argv[1])
from netportal import presence as backend  # noqa: E402

NOW = dt.datetime(2026, 10, 25, 12, 0, tzinfo=dt.UTC)
now = NOW.timestamp()
snapshot = backend.association({"present": False, "start": None, "last_seen": now - 3700}, "ok", now - 100, False)
cases = {
    "online": backend.decide(now, snapshot, sessions=[{
        "nas_ip": "10.10.0.23", "acct_session_id": "A-1", "link": "class", "mac": "a4:83:e7:00:00:01",
        "ap_name": "ap-colbe-0-far", "ap_mac": "d0:21:f9:00:00:03", "started": now - 14, "updated": now - 12,
        "stopped": None, "cause": None, "interim_s": None, "nas_interim_s": 300}], accept=now - 15),
    "connecting": backend.decide(now, snapshot, accept=now - 3),
    "offline": backend.decide(now, snapshot),
    "unknown": backend.decide(now, None, sessions=[{
        "nas_ip": "10.10.0.23", "acct_session_id": "A-0", "link": "class", "mac": None, "ap_name": None,
        "ap_mac": None, "started": now - 9000, "updated": now - 5000, "stopped": None, "cause": None,
        "interim_s": 300, "nas_interim_s": None}]),
}
out = {}
for state, decided in cases.items():
    assert decided["state"] == state, (state, decided["state"])
    out[state] = backend.public(decided)
print(json.dumps(out, indent=1, sort_keys=True))
