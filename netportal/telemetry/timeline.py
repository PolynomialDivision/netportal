"""A device's connection timeline: events from every source, normalised and merged
(TELEMETRY.md, "Sources and how they combine").

Sources and what they say (source name, basis):
- radius_auth (measured): authenticated / auth_rejected, with the BSSID and the NAS (the AP).
- radius_acct (measured): connected (Start), session_ended (Stop, with Acct-Terminate-Cause,
  octets, session time). A Stop followed within ROAM_S by a Start of the same device is a roam
  (another AP) or a reconnect (the same AP): one event, the Stop's cause in its detail.
- unifi_syslog (measured, connection_event): connected / disconnected / roamed (a roam between
  the radios of one AP is band_changed).
- prometheus (inferred, derive_timeline): connections from the association start (snapshot time
  - uptime), roams and band changes from the AP and radio labels, disconnects from new
  association starts and from the device's absence.
- device_mac (inferred): mac_changed, when a window with another MAC starts.
- incident (measured or inferred, as the incident row): incidents of the device's APs and of
  the whole house (router, internet, DNS, UniFi data, RADIUS).

Merge: events of different sources within MERGE_S describing the same thing (the same kind, or
disconnected/session_ended; the same AP when both name one) collapse into one with every source
in "sources"; the measured one wins (then the better source, SOURCE_RANK), the other only fills
what it lacks. An inferred event a measured one covers (COVERS, within MERGE_S) is dropped. A
disconnect followed within RECONNECT_S by a connection is one "reconnected". At most MAX_EVENTS
(the latest) are returned, with a truncation flag.

Times inside are Unix seconds; public() makes the API's shape (ISO times, AP dicts).
"""

from .common import BANDS, ap_ref, iso, normalise_mac, unix

MERGE_S = 120
RECONNECT_S = 120
ROAM_S = 120
# Association starts within this of each other are one connection: the snapshot time is
# exact, the uptime UniFi reports moves by up to a minute between snapshots.
SAME_ASSOCIATION_S = 120
MAX_EVENTS = 1000

MEASURED, INFERRED = "measured", "inferred"
SOURCE_RANK = {"unifi_syslog": 0, "radius_acct": 1, "radius_auth": 2, "incident": 3, "device_mac": 4,
               "prometheus": 5}
# what may collapse with what (the canonical kind)
MERGE_KIND = {"connected": "connected", "disconnected": "disconnected", "session_ended": "disconnected",
              "roamed": "roamed", "band_changed": "band_changed", "reconnected": "reconnected"}
# an inferred event of the key is dropped when a measured one of these kinds is that close
COVERS = {"connected": {"connected", "reconnected", "roamed"}, "disconnected": {"disconnected", "session_ended", "reconnected"},
          "roamed": {"roamed"}, "band_changed": {"band_changed", "roamed"}, "reconnected": {"reconnected"}}
# The kinds a disconnect counts as (diagnostics: frequent_disconnects, incident_correlated).
DISCONNECT_KINDS = ("disconnected", "session_ended", "reconnected")


# --- the v1 inferred timeline (Prometheus presence) ---------------------------------------------

def event(kind, at, ap=None, band=None, from_ap=None, from_band=None, duration_s=None, mac=None):
    return {"kind": kind, "at": at, "ap": ap, "band": band, "from_ap": from_ap, "from_band": from_band,
            "duration_s": None if duration_s is None else int(duration_s), "mac": mac}


def derive_timeline(points, res, last_fresh=None, since=None):
    """(events, spans) from [(t, association start, ap_name, radio[, mac])] sorted by t, fresh
    data only. A connection is one association start: a later start (with or without a gap) is a
    disconnect plus a new connection; a gap with the same start is missing data, not a
    disconnect (the device stayed associated). AP changes are roams, band changes on the same AP
    band changes. A device not seen for 3 resolutions before the last fresh data is disconnected
    now. Nothing before since (the device's data bound). Times are Unix seconds; spans are
    (connected at, last seen)."""
    events, spans, cur = [], [], None

    def close(c):
        c["event"]["duration_s"] = int(c["last"] - c["at"])
        spans.append((c["at"], c["last"]))

    for point in points:
        t, start, ap_name, radio = point[:4]
        mac = point[4] if len(point) > 4 else None
        if since is not None and t < since:
            continue
        start, band = min(start, t), BANDS.get(radio)
        if since is not None:
            start = max(start, since)
        if cur is not None and start - cur["start"] <= SAME_ASSOCIATION_S and mac == cur["mac"]:
            if (ap_name, band) != (cur["ap"], cur["band"]):
                kind = "roamed" if ap_name != cur["ap"] else "band_changed"
                events.append(event(kind, t, ap_name, band, cur["ap"], cur["band"], t - cur["changed"], mac))
                cur.update(ap=ap_name, band=band, changed=t)
            cur.update(start=start, last=t)
            continue
        at = start if cur is None else max(start, cur["last"])
        if cur is not None:
            close(cur)
            events.append(event("disconnected", cur["last"], cur["ap"], cur["band"], duration_s=at - cur["last"],
                                mac=cur["mac"]))
        new = event("connected", at, ap_name, band, duration_s=0, mac=mac)
        events.append(new)
        cur = {"start": start, "at": at, "last": t, "ap": ap_name, "band": band, "changed": at, "event": new, "mac": mac}
    if cur is not None:
        close(cur)
        if last_fresh is not None and last_fresh - cur["last"] >= 3 * res:
            events.append(event("disconnected", cur["last"], cur["ap"], cur["band"],
                                duration_s=last_fresh - cur["last"], mac=cur["mac"]))
    return events, spans


# --- normalised events ------------------------------------------------------------------------

def ev(kind, at, source, basis, ap=None, ap_mac=None, band=None, from_ap=None, from_ap_mac=None, from_band=None,
       mac=None, duration_s=None, detail=None):
    return {"kind": kind, "at": unix(at), "source": source, "sources": [source], "basis": basis, "ap": ap,
            "ap_mac": ap_mac, "band": band, "from_ap": from_ap, "from_ap_mac": from_ap_mac, "from_band": from_band,
            "mac": mac, "duration_s": None if duration_s is None else int(duration_s), "detail": dict(detail or {})}


class ApMap:
    """Which AP a BSSID, a NAS address or an AP MAC is (from unpoller: the VAPs' bssid and the
    devices' ip and mac labels). Empty when Prometheus did not answer: the events keep what
    their row says."""

    def __init__(self, bssids=None, nas=None, names=None):
        self.bssids = bssids or {}       # bssid -> (ap name, ap mac, band)
        self.nas = nas or {}             # ip -> (ap name, ap mac)
        self.names = names or {}         # ap mac -> ap name

    def by_bssid(self, bssid, nas_ip=None):
        """(ap name, ap mac, band) of a BSSID, else of the NAS, else (None, None, None)."""
        hit = self.bssids.get(normalise_mac(bssid) if bssid else None)
        if hit:
            return hit
        name, mac = self.nas.get(str(nas_ip) if nas_ip else None, (None, None))
        return name, mac, None

    def name(self, ap_mac, fallback=None):
        return self.names.get(ap_mac) or fallback


def from_presence(events):
    """derive_timeline's events (inferred, source prometheus)."""
    return [ev(e["kind"], e["at"], "prometheus", INFERRED, ap=e["ap"], band=e["band"], from_ap=e["from_ap"],
               from_band=e["from_band"], mac=e.get("mac"), duration_s=e["duration_s"]) for e in events]


def from_auth(rows, aps=None):
    """radius_auth rows (registry.auth_events): authenticated / auth_rejected, at the row's first
    time. detail: reason, bssid, ssid, match (how the row is the device's: "device" by its
    certificate, "mac" by one of its MACs only; restrict needs it), count (repeated rejects are
    one row) and last_at (ISO, the latest repeat, when there were repeats)."""
    aps = aps or ApMap()
    out = []
    for r in rows:
        name, ap_mac, band = aps.by_bssid(r.get("bssid"), r.get("nas_ip"))
        kind = "authenticated" if r.get("result") == "accept" else "auth_rejected"
        detail = {"reason": r.get("reason"), "bssid": _mac(r.get("bssid")), "ssid": r.get("ssid"),
                  "match": r.get("match"), "count": int(r.get("count") or 1)}
        if r.get("last_at") is not None:
            detail["last_at"] = iso(unix(r["last_at"]))
        out.append(ev(kind, r["at"], "radius_auth", MEASURED, ap=name, ap_mac=ap_mac, band=band,
                      mac=_mac(r.get("mac")), detail=detail))
    return out


def from_acct(rows, aps=None):
    """radius_acct sessions (registry.acct_sessions): connected at Start, session_ended at Stop;
    a Stop and a Start of the next session within ROAM_S are one roamed (another AP) or
    reconnected (the same AP)."""
    aps = aps or ApMap()
    sessions = sorted((r for r in rows if r.get("started") is not None or r.get("stopped") is not None),
                      key=lambda r: unix(r.get("started") or r.get("stopped")))
    out, prev = [], None
    for r in sessions:
        name, ap_mac, band = aps.by_bssid(r.get("bssid"), r.get("nas_ip"))
        started, stopped = unix(r.get("started")), unix(r.get("stopped"))
        mac = _mac(r.get("mac"))
        detail = {"acct_session_id": r.get("acct_session_id"), "framed_ip": _str(r.get("framed_ip")), "link": r.get("link")}
        if started is not None:
            joined = prev is not None and prev["stopped"] is not None and abs(started - prev["stopped"]) <= ROAM_S
            if joined:
                out.remove(prev["ended"])
                same = (prev["ap_mac"] or prev["ap"]) == (ap_mac or name) and (ap_mac or name) is not None
                kind = "reconnected" if same else "roamed"
                detail.update(from_cause=prev["cause"], from_session_s=prev["session_s"])
                out.append(ev(kind, started, "radius_acct", MEASURED, ap=name, ap_mac=ap_mac, band=band,
                              from_ap=prev["ap"], from_ap_mac=prev["ap_mac"], from_band=prev["band"], mac=mac,
                              detail=dict(detail, gap_s=int(started - prev["stopped"]))))
            else:
                out.append(ev("connected", started, "radius_acct", MEASURED, ap=name, ap_mac=ap_mac, band=band,
                              mac=mac, detail=detail))
        ended = None
        if stopped is not None:
            ended = ev("session_ended", stopped, "radius_acct", MEASURED, ap=name, ap_mac=ap_mac, band=band, mac=mac,
                       duration_s=r.get("session_time_s"),
                       detail=dict(detail, cause=r.get("terminate_cause"), session_time_s=r.get("session_time_s"),
                                   rx_bytes=r.get("output_octets"), tx_bytes=r.get("input_octets")))
            out.append(ended)
        prev = {"stopped": stopped, "ended": ended, "ap": name, "ap_mac": ap_mac, "band": band,
                "cause": r.get("terminate_cause"), "session_s": r.get("session_time_s")}
    return out


def from_unifi(rows, aps=None):
    """connection_event rows (registry.connection_events, UniFi's system log)."""
    aps = aps or ApMap()
    out = []
    for r in rows:
        kind = r.get("kind")
        if kind not in ("connected", "disconnected", "roamed"):
            continue
        ap_mac, from_ap_mac = _mac(r.get("ap_mac")), _mac(r.get("from_ap_mac"))
        name, from_name = aps.name(ap_mac, r.get("ap_name")), aps.name(from_ap_mac, r.get("from_ap_name"))
        if kind == "roamed" and ((ap_mac and ap_mac == from_ap_mac) or (not ap_mac and name and name == from_name)):
            kind = "band_changed"
        detail = {k: r.get(k) for k in ("rssi", "channel", "ssid", "radio", "rx_bytes", "tx_bytes") if r.get(k) is not None}
        out.append(ev(kind, r["at"], r.get("source") or "unifi_syslog", MEASURED, ap=name, ap_mac=ap_mac,
                      band=BANDS.get(r.get("radio")), from_ap=from_name if kind != "connected" else None,
                      from_ap_mac=from_ap_mac, mac=_mac(r.get("mac")), duration_s=r.get("duration_s"), detail=detail))
    return out


def from_windows(identity, start, end):
    """mac_changed (inferred, device_mac): a window with another MAC starts."""
    out, previous = [], None
    for w in sorted(identity.windows, key=lambda w: (w["first_seen"] or w["start"], w["mac"])):
        first = w["first_seen"] if w["first_seen"] is not None else w["start"]
        if previous is not None and previous["mac"] != w["mac"] and start <= first <= end:
            out.append(ev("mac_changed", first, "device_mac", INFERRED, mac=w["mac"],
                          detail={"from_mac": previous["mac"], "randomized": w["randomized"]}))
        previous = w
    return out


def from_incidents(rows):
    """Incident rows (registry.incidents): one "incident" event at the start."""
    out = []
    for r in rows:
        started, ended = unix(r["started"]), unix(r.get("ended"))
        is_ap = (r.get("kind") or "").startswith("ap_")
        out.append(ev("incident", started, "incident", r.get("basis") or INFERRED,
                      ap=r.get("subject_name") if is_ap else None, ap_mac=_mac(r.get("subject")) if is_ap else None,
                      duration_s=None if ended is None else ended - started,
                      detail={"id": r.get("id"), "incident": r.get("kind"), "subject": r.get("subject"),
                              "subject_name": r.get("subject_name"), "ended": iso(ended), "open": ended is None}))
    return out


def _mac(value):
    return normalise_mac(str(value)) if value is not None else None


def _str(value):
    return None if value is None else str(value)


# --- merge ------------------------------------------------------------------------------------

def _same_ap(a, b):
    if a["ap_mac"] and b["ap_mac"]:
        return a["ap_mac"] == b["ap_mac"]
    if a["ap"] and b["ap"]:
        return a["ap"].lower() == b["ap"].lower()
    return True


def _rank(e):
    return (0 if e["basis"] == MEASURED else 1, SOURCE_RANK.get(e["source"], 9))


def _absorb(twin, e):
    """Collapse e into twin (in place): the better one's fields, the other's where it has none."""
    primary, other = (e, twin) if _rank(e) < _rank(twin) else (twin, e)
    merged = dict(primary)
    for k in ("ap", "ap_mac", "band", "from_ap", "from_ap_mac", "from_band", "mac", "duration_s"):
        if merged[k] is None:
            merged[k] = other[k]
    merged["detail"] = dict(other["detail"], **primary["detail"])
    merged["sources"] = sorted(set(twin["sources"]) | set(e["sources"]), key=lambda s: SOURCE_RANK.get(s, 9))
    merged["basis"] = MEASURED if MEASURED in (twin["basis"], e["basis"]) else INFERRED
    twin.clear()
    twin.update(merged)


def _twin(merged, e):
    kind = MERGE_KIND.get(e["kind"])
    for m in reversed(merged):
        if m["at"] < e["at"] - MERGE_S:
            return None
        if (MERGE_KIND.get(m["kind"]) == kind and not set(m["sources"]) & set(e["sources"]) and _same_ap(m, e)):
            return m
    return None


def _reconnects(events):
    """disconnected + connected within RECONNECT_S: one reconnected (at the connection; the
    connection's duration, the gap in detail)."""
    out, pending = [], None
    for e in events:
        if e["kind"] == "disconnected":
            if pending is not None:
                out.append(pending)
            pending = e
            continue
        if pending is not None and e["kind"] == "connected" and e["at"] - pending["at"] <= RECONNECT_S:
            r = dict(e, kind="reconnected", from_ap=pending["ap"], from_ap_mac=pending["ap_mac"],
                     from_band=pending["band"],
                     sources=sorted(set(e["sources"]) | set(pending["sources"]), key=lambda s: SOURCE_RANK.get(s, 9)),
                     basis=MEASURED if MEASURED == e["basis"] == pending["basis"] else INFERRED,
                     detail=dict(pending["detail"], **e["detail"], gap_s=int(e["at"] - pending["at"])))
            if pending["mac"] and e["mac"] and pending["mac"] != e["mac"]:
                r["detail"]["from_mac"] = pending["mac"]
            out.append(r)
            pending = None
            continue
        if pending is not None and e["kind"] in MERGE_KIND:
            out.append(pending)
            pending = None
        out.append(e)
    if pending is not None:
        out.append(pending)
    return out


def merge(events, limit=MAX_EVENTS):
    """(events sorted by time, truncated): collapsed, covered ones dropped, reconnects joined,
    the latest `limit`."""
    events = sorted(events, key=lambda e: (e["at"], _rank(e)))
    merged = []
    for e in events:
        twin = _twin(merged, e) if e["kind"] in MERGE_KIND else None
        if twin is not None:
            _absorb(twin, e)
        else:
            merged.append(e)
    measured = [m for m in merged if m["basis"] == MEASURED]
    kept = []
    for e in merged:
        if e["basis"] == INFERRED and e["kind"] in COVERS:
            cover = next((m for m in measured if m["kind"] in COVERS[e["kind"]] and abs(m["at"] - e["at"]) <= MERGE_S
                          and _same_ap(m, e)), None)
            if cover is not None:
                cover["sources"] = sorted(set(cover["sources"]) | set(e["sources"]), key=lambda s: SOURCE_RANK.get(s, 9))
                continue
        kept.append(e)
    kept = sorted(_reconnects(kept), key=lambda e: e["at"])
    return kept[-limit:] if limit else kept, len(kept) > limit if limit else False


def _own(e):
    """An event that is the device's by its certificate, not only by the MAC: a RADIUS decision
    logged with the device (auth_events match "device") or an accounting session linked by the
    login's Class. A reject found by the MAC alone (match "mac": no certificate, so whoever sent
    it) is not."""
    if e["source"] == "radius_auth":
        return e["detail"].get("match") == "device"
    return e["source"] == "radius_acct" and e["detail"].get("link") == "class"


def restrict(events, identity):
    """Residents: nothing of a MAC in its withheld spans except what is the device's by its
    certificate (_own); admins: such events marked (detail.conflict = other owners)."""
    out = []
    for e in events:
        if e["mac"] and identity is not None:
            hits = [c for c in identity.conflicts if c["mac"] == e["mac"]
                    and (c["from"] is None or c["from"] <= e["at"]) and (c["to"] is None or e["at"] <= c["to"])]
            if hits and not identity.admin and not _own(e):
                continue
            if hits and identity.admin:
                e = dict(e, detail=dict(e["detail"], conflict=max(c["other_owners"] for c in hits)))
        out.append(e)
    return out


def disconnects(events, since=None):
    """[{"at", "basis", "source", "cause"}] of the disconnect events (the diagnostics' input)."""
    return [{"at": e["at"], "basis": e["basis"], "source": e["source"], "cause": e["detail"].get("cause")
             or e["detail"].get("from_cause")}
            for e in events if e["kind"] in DISCONNECT_KINDS and (since is None or e["at"] >= since)]


def public(events):
    """The API's EVENT: {kind, at (ISO), source, sources, basis, ap, band, from_ap, from_band, mac,
    duration_s, detail}; ap and from_ap as {"name", "house", "floor", "spot"[, "mac"]}."""
    return [{"kind": e["kind"], "at": iso(e["at"]), "source": e["source"], "sources": list(e["sources"]),
             "basis": e["basis"], "ap": ap_ref(e["ap"], e["ap_mac"]), "band": e["band"],
             "from_ap": ap_ref(e["from_ap"], e["from_ap_mac"]), "from_band": e["from_band"], "mac": e["mac"],
             "duration_s": e["duration_s"], "detail": e["detail"]} for e in events]
