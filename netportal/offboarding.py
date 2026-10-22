"""Keep Wi-Fi in line with Authentik: a person who is deactivated, deleted or no longer in the
allowed groups loses every device (revoked, sessions disconnected), their app grants and
their portal session. Someone whose groups now give another policy (moved out: residents ->
guests) keeps their devices; they move to that policy's VLAN (Disconnect, authenticate again).

Matches devices to people by the OIDC subject, which for Authentik's default subject mode
("hashed user ID") is the user's `uid` in the API. Read-only API token (directory-reader).
Safe by default: if Authentik cannot be read or returns nobody, nothing is revoked.
"""

import logging

import requests

from . import metrics, registry, web

log = logging.getLogger("netportal.offboarding")


def allowed_subjects(api, token, settings, timeout=15):
    """{uid: policy name} of every active user who may use Wi-Fi; raises on any API problem."""
    url, allowed, seen = api + "/core/users/?page_size=100&include_groups=true", {}, 0
    while url:
        resp = requests.get(url, headers={"Authorization": "Bearer " + token}, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        for user in data.get("results", []):
            seen += 1
            names = {grp.get("name") for grp in user.get("groups_obj") or []}
            policy = settings.policy_for(names)
            if user.get("is_active") and policy and user.get("uid"):
                allowed[user["uid"]] = policy
        url = (data.get("pagination") or {}).get("next") and _next_url(api, data)
    if seen == 0:
        raise RuntimeError("Authentik returned no users; refusing to offboard everyone")
    return allowed


def _next_url(api, data):
    page = data["pagination"]["next"]
    return api + "/core/users/?page_size=100&include_groups=true&page=%d" % page


def run(settings):
    """One reconciliation. Returns the number of devices revoked."""
    if not settings.authentik_api or not settings.authentik_token:
        return 0
    allowed = allowed_subjects(settings.authentik_api, settings.authentik_token, settings)
    revoked = moved = 0
    with registry.connect(settings.database_url) as db:
        subjects = registry.subjects_to_check(db)
        for sub in sorted(subjects & set(allowed)):
            moved += web.apply_policy(db, sub, allowed[sub], "offboarding", settings)
        for sub in sorted(subjects - set(allowed)):
            registry.offboard_person(db, sub)
            db.commit()
            for dev in registry.devices(db, owner=sub):
                web.revoke_now(db, dev["id"], "offboarding", settings)
                revoked += 1
                metrics.OFFBOARDED.inc()
        registry.prune(db)
        registry.mark_job(db, "offboarding")
        db.commit()
    if revoked or moved:
        log.info("offboarding revoked %d device(s), moved %d to another policy", revoked, moved)
    return revoked
