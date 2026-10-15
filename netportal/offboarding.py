"""Keep Wi-Fi in line with Authentik: a person who is deactivated, deleted or no longer in the
allowed groups loses every device (revoked, sessions disconnected), their app grants and
their portal session.

Matches devices to people by the OIDC subject, which for Authentik's default subject mode
("hashed user ID") is the user's `uid` in the API. Read-only API token (directory-reader).
Safe by default: if Authentik cannot be read or returns nobody, nothing is revoked.
"""

import logging

import requests

from . import metrics, registry, web

log = logging.getLogger("netportal.offboarding")


def allowed_subjects(api, token, allowed_groups, admin_groups, timeout=15):
    """{uid of every active user who may use Wi-Fi}; raises on any API problem."""
    groups = set(allowed_groups) | set(admin_groups)
    url, allowed, seen = api + "/core/users/?page_size=100&include_groups=true", set(), 0
    while url:
        resp = requests.get(url, headers={"Authorization": "Bearer " + token}, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        for user in data.get("results", []):
            seen += 1
            names = {grp.get("name") for grp in user.get("groups_obj") or []}
            if user.get("is_active") and names & groups and user.get("uid"):
                allowed.add(user["uid"])
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
    allowed = allowed_subjects(settings.authentik_api, settings.authentik_token,
                               settings.allowed_groups, settings.admin_groups)
    revoked = 0
    with registry.connect(settings.database_url) as db:
        for sub in sorted(registry.subjects_to_check(db) - allowed):
            registry.offboard_person(db, sub)
            db.commit()
            for dev in registry.devices(db, owner=sub):
                web.revoke_now(db, dev["id"], "offboarding", settings)
                revoked += 1
                metrics.OFFBOARDED.inc()
        registry.prune(db)
        registry.mark_job(db, "offboarding")
        db.commit()
    if revoked:
        log.info("offboarding revoked %d device(s)", revoked)
    return revoked
