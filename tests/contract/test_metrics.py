"""/metrics (INVENTORY 10, 3.2 row 31): the names and labels house-infra's alert rules and
dashboards use, values that follow what happens, never reachable through the proxy. Not
pinned: float spelling, HELP texts, prometheus-client's *_created series."""

from harness import RUN, A, B, ContractCase, download, resident, sample

FAMILIES = {
    "netportal_enrolments_total": "counter",
    "netportal_disconnects_total": "counter",
    "netportal_offboarded_devices_total": "counter",
    "netportal_offboarding_last_success_timestamp_seconds": "gauge",
    "netportal_disconnects_last_hour": "gauge",
    "netportal_devices": "gauge",
    "netportal_certificates": "gauge",
    "netportal_telemetry_queries_total": "counter",
    "netportal_registry_up": "gauge",
    "netportal_disconnect_rechecks_total": "counter",
    "netportal_locked_sessions_live": "gauge",
}


def family_type(metrics, name):
    """The TYPE of a family; counters may be declared with or without the _total suffix."""
    return metrics["types"].get(name) or metrics["types"].get(name[:-len("_total")] if name.endswith("_total") else name)


class MetricsTests(ContractCase):
    """INVENTORY 10 (names, types, labels, values), 3.2 row 31 (refused through the proxy)."""

    def test_exposition(self):
        r, m = A.metrics()
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.headers["Content-Type"].split(";")[0].strip(), "text/plain")
        self.assertEqual(m["bad_lines"], [])
        for name, typ in FAMILIES.items():
            with self.subTest(family=name):
                self.assertEqual(family_type(m, name), typ)

    def test_series_the_alert_rules_use(self):
        _, m = A.metrics()
        self.assertEqual(sample(m, "netportal_registry_up"), 1)
        for state in ("active", "revoked"):
            self.assertIsNotNone(sample(m, "netportal_devices", state=state), state)
        for state in ("valid", "expiring_30d", "expired"):
            self.assertIsNotNone(sample(m, "netportal_certificates", state=state), state)
        for result in ("ack", "nak", "not-found", "timeout", "error", "skipped", "no-session"):
            self.assertIsNotNone(sample(m, "netportal_disconnects_last_hour", result=result), result)
        for result in ("ok", "error"):
            self.assertIsNotNone(sample(m, "netportal_telemetry_queries_total", result=result), result)
        self.assertGreater(sample(m, "netportal_offboarding_last_success_timestamp_seconds") or 0, 0)
        self.assertGreater(sample(m, "netportal_job_last_success_timestamp_seconds", job="offboarding") or 0, 0)
        # the Disconnect reconciliation (owner's review 2026-10-29): its totals and the alert's gauge
        for result in ("ack", "not_found", "nak", "timeout", "error", "settled_stale", "given_up"):
            self.assertIsNotNone(sample(m, "netportal_disconnect_rechecks_total", result=result), result)
        for reason in ("revoked", "credential", "vlan"):
            self.assertEqual(sample(m, "netportal_locked_sessions_live", reason=reason), 0, reason)

    def test_values_follow_enrolment_and_revocation(self):
        _, before = A.metrics()
        b = A.browser().logged_in(resident("met"))
        _, _, dev = download(b, "apple-mac")
        _, mid = A.metrics()
        self.assertEqual(sample(mid, "netportal_enrolments_total", format="apple-mac")
                         - (sample(before, "netportal_enrolments_total", format="apple-mac") or 0), 1)
        self.assertEqual(sample(mid, "netportal_devices", state="active")
                         - sample(before, "netportal_devices", state="active"), 1)
        self.assertEqual(sample(mid, "netportal_certificates", state="valid")
                         - sample(before, "netportal_certificates", state="valid"), 1)
        b.post("/devices/%s/revoke" % dev, data={"csrf": b.csrf()})
        _, after = A.metrics()
        self.assertEqual(sample(after, "netportal_devices", state="active")
                         - sample(mid, "netportal_devices", state="active"), -1)
        self.assertEqual(sample(after, "netportal_devices", state="revoked")
                         - sample(mid, "netportal_devices", state="revoked"), 1)
        self.assertEqual(sample(after, "netportal_disconnects_last_hour", result="no-session")
                         - sample(mid, "netportal_disconnects_last_hour", result="no-session"), 1)
        self.assertEqual(sample(after, "netportal_disconnects_total", result="no-session")
                         - (sample(mid, "netportal_disconnects_total", result="no-session") or 0), 1)

    def test_not_through_the_proxy(self):
        """Refused (404, no metrics) when the request came through the reverse proxy (X-Forwarded-For)."""
        for value in ("203.0.113.7", "10.0.0.1, 10.0.0.2"):
            with self.subTest(xff=value):
                r, _ = A.metrics(headers={"X-Forwarded-For": value})
                self.assertEqual(r.status_code, 404)
                self.assertNotIn("netportal_", r.text)


class MetricsTokenTests(ContractCase):
    """Owner's review 2026-10-29: NETPORTAL_METRICS_TOKEN_FILE (instance B, a read-only file):
    /metrics only with `Authorization: Bearer <token>` (401 otherwise)."""

    def test_bearer_token(self):
        token = (RUN / "secrets" / "metrics-token").read_text().strip()
        for headers in ({}, {"Authorization": "Bearer wrong"}, {"Authorization": "Basic " + token},
                        {"Authorization": "Bearer " + token[:-1]}):
            with self.subTest(headers=headers):
                r, _ = B.metrics(headers=headers)
                self.assertEqual(r.status_code, 401)
                self.assertTrue(r.headers.get("WWW-Authenticate", "").startswith("Bearer"))
                self.assertNotIn("netportal_", r.text)
        r, m = B.metrics(headers={"Authorization": "Bearer " + token})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(sample(m, "netportal_registry_up"), 1)
        r, _ = B.metrics(headers={"Authorization": "Bearer " + token, "X-Forwarded-For": "203.0.113.7"})
        self.assertEqual(r.status_code, 404)
        # instance A has no token: open on its own listener
        self.assertEqual(A.metrics()[0].status_code, 200)
