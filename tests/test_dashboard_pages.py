"""The "My devices" pages (devices.html, device.html, admin.html) with Flask's test client:
registry mocked, the dashboard data built here in the shapes of the JSON API (/api/devices,
/api/devices/<id>/history, /api/admin/devices). The pages must be complete without JavaScript,
in every language, for every device state and telemetry state, and keep the strict CSP (no
inline code: the scripts' texts and data are JSON blocks). Example values only."""

import datetime as dt
import html
import json
import re
import sys
import unittest
import uuid
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from flask import render_template  # noqa: E402
from markupsafe import escape  # noqa: E402
from test_web import FakeDb, example_settings  # noqa: E402

from netportal import i18n, web  # noqa: E402

NOW = dt.datetime(2026, 10, 25, 12, 0, tzinfo=dt.UTC)
RESIDENT_SUB, ADMIN_SUB = "sub-resident", "sub-admin"
IDS = [str(uuid.UUID(int=i, version=4)) for i in range(1, 6)]


def iso(delta_s=0):
    return (NOW - dt.timedelta(seconds=delta_s)).isoformat()


def ap(name):
    """ap-<house>-<floor>-<spot> as the backend splits it (unknown names: house None)."""
    parts = name.split("-")
    if len(parts) == 4 and parts[0] == "ap":
        return {"name": name, "house": parts[1], "floor": int(parts[2]), "spot": parts[3]}
    return {"name": name, "house": None, "floor": None, "spot": None}


def device(i, name, state, **values):
    base = {"id": IDS[i], "name": name, "platform": "android", "policy": "residents", "created": iso(40 * 86400),
            "expires": iso(-300 * 86400), "expires_soon": False, "revoked": False,
            "mac": "02:00:00:00:00:%02x" % i, "state": state, "last_seen": None, "since": None, "ap": None,
            "ssid": None, "band": None, "channel": None, "proto": None, "ip": None, "signal_dbm": None,
            "noise_dbm": None, "snr_db": None, "health": None, "retry_ratio": None, "channel_util": None,
            "link_rx_bps": None, "link_tx_bps": None, "rx_bps": None, "tx_bps": None, "rx_24h_bytes": None,
            "tx_24h_bytes": None, "roams_1h": None, "diagnostics": []}
    base.update(values)
    return base


def sample_devices():
    return [
        device(0, "Pixel 8", "online", last_seen=iso(), since=iso(8130), ap=ap("ap-scharni-2-corner"),
               ssid="Example", band="5", channel=36, proto="ax", ip="10.30.0.23", signal_dbm=-58, noise_dbm=-95,
               snr_db=37, health=88, retry_ratio=0.03, channel_util=0.21, link_rx_bps=866_000_000,
               link_tx_bps=720_000_000, rx_bps=2_400_000, tx_bps=180_000, rx_24h_bytes=1_830_000_000,
               tx_24h_bytes=221_000_000, roams_1h=0),
        device(1, "MacBook Air", "online", platform="apple-mac", last_seen=iso(), since=iso(3 * 86400 + 4000),
               ap=ap("ap-colbe-0-far"), ssid="Example", band="2.4", channel=6, proto="n", ip="10.30.0.41",
               signal_dbm=-79, noise_dbm=-88, snr_db=9, health=41, retry_ratio=0.24, channel_util=0.72,
               link_rx_bps=52_000_000, link_tx_bps=26_000_000, rx_bps=310_000, tx_bps=41_000,
               rx_24h_bytes=640_000_000, tx_24h_bytes=95_000_000, roams_1h=7,
               diagnostics=[{"code": "weak_signal", "severity": "warn", "params": {"signal_dbm": -79}},
                            {"code": "high_retries", "severity": "bad", "params": {"retry_ratio": 0.24}},
                            {"code": "busy_channel", "severity": "warn", "params": {"channel_util": 0.72}},
                            {"code": "unstable_roaming", "severity": "warn", "params": {"roams_1h": 7}},
                            {"code": "stuck_on_2ghz", "severity": "info", "params": {}}]),
        device(2, "iPad", "offline", platform="apple", last_seen=iso(3 * 3600 + 600), ssid="Example",
               expires=iso(-12 * 86400), expires_soon=True,
               rx_24h_bytes=120_000_000, tx_24h_bytes=8_000_000,
               diagnostics=[{"code": "offline", "severity": "info", "params": {}},
                            {"code": "frequent_disconnects", "severity": "warn", "params": {"reconnects_24h": 6}}]),
        device(3, "Kindle", "never_connected", platform="eap-config", mac=None,
               diagnostics=[{"code": "never_connected", "severity": "info", "params": {}}]),
        device(4, "Sensor <&> \"Werkstatt\"", "online", platform="letswifi", last_seen=iso(), since=iso(30),
               ap=ap("ap-scharni-0-schlaglicht"), band="6", channel=37, proto="ax", signal_dbm=-66, health=72,
               diagnostics=[{"code": "slow_link", "severity": "warn", "params": {"link_rx_bps": 6_500_000, "signal_dbm": -66}},
                            {"code": "low_snr", "severity": "warn", "params": {"snr_db": 14}},
                            {"code": "stale_data", "severity": "info", "params": {"age_s": 900}}]),
    ]


def sample_house(**overrides):
    house = {"internet": "ok", "internet_loss_ratio": 0.0, "internet_rtt_ms": 11.4, "dns": "ok", "router": "ok",
             "speedtest": {"download_bps": 248_000_000, "upload_bps": 41_500_000, "ping_ms": 9.8, "at": iso(5400)},
             "wifi_data_age_s": 45}
    house.update(overrides)
    return house


def sample_dashboard(telemetry="ok", devices=None, admin=False, **overrides):
    payload = {"generated_at": iso(), "telemetry": telemetry, "stale": False, "house": sample_house(),
               "devices": sample_devices() if devices is None else devices}
    if telemetry != "ok":
        payload["house"] = sample_house(internet="unknown", dns="unknown", router="unknown", speedtest=None,
                                        internet_rtt_ms=None, internet_loss_ratio=None, wifi_data_age_s=None)
        for d in payload["devices"]:
            for key in ("signal_dbm", "health", "rx_bps", "tx_bps", "link_rx_bps", "link_tx_bps", "ap", "band",
                        "channel", "proto", "rx_24h_bytes", "tx_24h_bytes", "since"):
                d[key] = None
            if d["state"] == "online":
                d["state"] = "unknown"
            d["diagnostics"] = [f for f in d["diagnostics"] if f["code"] == "never_connected"]
    if admin:
        owners = [("Nick Example", "nick"), ("Fia Example", "fia")]
        for i, d in enumerate(payload["devices"]):
            d["owner"] = {"display": owners[i % 2][0], "username": owners[i % 2][1]}
    payload.update(overrides)
    return payload


def sample_history(range_="24h"):
    """A day (or more) of 5-minute samples: two connections, a roam, a band change and gaps."""
    import math
    span = {"24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400}[range_]
    step = {"24h": 300, "7d": 1800, "30d": 7200}[range_]
    end = int(NOW.timestamp())
    start = end - span
    series = {k: [] for k in ("signal_dbm", "health", "rx_bps", "tx_bps", "online", "link_rx_bps", "link_tx_bps")}
    off_from, off_to = end - int(span * 0.62), end - int(span * 0.55)       # a disconnect
    hole_from, hole_to = end - int(span * 0.30), end - int(span * 0.28)     # no data at all (scrape gap)
    for t in range(start, end + 1, step):
        if hole_from <= t < hole_to:
            continue
        online = not (off_from <= t < off_to)
        phase = (t - start) / span
        series["online"].append([t, 1 if online else 0])
        if not online:
            for k in ("signal_dbm", "health", "rx_bps", "tx_bps", "link_rx_bps", "link_tx_bps"):
                series[k].append([t, None])
            continue
        weak = phase > 0.8                                                   # moved to a far room
        sig = (-74 if weak else -58) + 4 * math.sin(phase * 40)
        series["signal_dbm"].append([t, round(sig, 1)])
        series["health"].append([t, round(max(0, min(100, 100 + (sig + 55) * 2.2)))])
        busy = 0.5 + 0.5 * math.sin(phase * 12)
        series["rx_bps"].append([t, round(busy * 4e6 + 1e5)])
        series["tx_bps"].append([t, round(busy * 6e5 + 2e4)])
        series["link_rx_bps"].append([t, 173_000_000 if weak else 866_000_000])
        series["link_tx_bps"].append([t, 144_000_000 if weak else 720_000_000])
    first = start - 3600
    timeline = [
        {"kind": "connected", "at": dt.datetime.fromtimestamp(first, dt.UTC).isoformat(),
         "ap": ap("ap-scharni-2-corner"), "band": "5", "from_ap": None, "from_band": None,
         "duration_s": off_from - first},
        {"kind": "disconnected", "at": dt.datetime.fromtimestamp(off_from, dt.UTC).isoformat(),
         "ap": ap("ap-scharni-2-corner"), "band": "5", "from_ap": None, "from_band": None, "duration_s": off_to - off_from},
        {"kind": "connected", "at": dt.datetime.fromtimestamp(off_to, dt.UTC).isoformat(),
         "ap": ap("ap-scharni-1-middle"), "band": "5", "from_ap": None, "from_band": None, "duration_s": None},
        {"kind": "roamed", "at": dt.datetime.fromtimestamp(end - int(span * 0.2), dt.UTC).isoformat(),
         "ap": ap("ap-colbe-0-far"), "band": "5", "from_ap": ap("ap-scharni-1-middle"), "from_band": "5",
         "duration_s": None},
        {"kind": "band_changed", "at": dt.datetime.fromtimestamp(end - int(span * 0.1), dt.UTC).isoformat(),
         "ap": ap("ap-colbe-0-far"), "band": "2.4", "from_ap": ap("ap-colbe-0-far"), "from_band": "5",
         "duration_s": None},
    ]
    return {"range": range_, "step_s": step, "start": start, "end": end, "telemetry": "ok", "series": series,
            "timeline": timeline, "timeline_truncated": False}


def registry_rows(devices, owners=("sub-resident",)):
    """Registry rows (registry.DEVICE_LIST) for these DEVICEs."""
    return [{"id": uuid.UUID(d["id"]), "owner": owners[i % len(owners)], "name": d["name"], "platform": d["platform"],
             "policy": "residents", "created": NOW - dt.timedelta(days=40), "revoked": None,
             "expires": dt.datetime.fromisoformat(d["expires"]), "certificates": 1, "last_seen": NOW,
             "calling_station": d["mac"]} for i, d in enumerate(devices)]


def esc(text):
    return str(escape(text))


def visible(page):
    """The page without its JSON blocks (they hold every text)."""
    return re.sub(r"<script.*?</script>", "", page, flags=re.DOTALL)


SCRIPT = re.compile(r"<script\b([^>]*)>(.*?)</script>", re.DOTALL)


class DashboardPagesTestCase(unittest.TestCase):
    """The pages through web.py's routes; registry and telemetry mocked."""
    telemetry = "ok"
    template_globals = True

    def setUp(self):
        self.devices = sample_devices()
        self.state = {RESIDENT_SUB: {"admin": False}, ADMIN_SUB: {"admin": True}}

        def fake_dashboard(client, rows, owners=None, now=None, **_kw):
            """telemetry.dashboard: the sample DEVICEs of these rows, in their order, with owners."""
            payload = sample_dashboard(self.telemetry, devices=[dict(d) for d in self.devices])
            by_id = {d["id"]: d for d in payload["devices"]}
            payload["devices"] = [by_id[str(r["id"])] for r in rows if str(r["id"]) in by_id]
            if owners is not None:
                for d, r in zip(payload["devices"], rows):
                    person = owners.get(r["owner"]) or {}
                    d["owner"] = {"username": person.get("username"), "display": person.get("display")}
            return payload

        # the resident owns the first four, the admin the sensor; one more row of somebody else
        rows = registry_rows(self.devices, owners=(RESIDENT_SUB,) * 4 + (ADMIN_SUB,))
        rows.append(dict(registry_rows([device(0, "Other", "offline")])[0], id=uuid.UUID(int=99, version=4),
                         owner="sub-other"))
        self.rows = rows
        patches = [
            mock.patch.object(web.enroll, "Issuer"),
            mock.patch.object(web.registry, "connect", return_value=FakeDb()),
            mock.patch.object(web.registry, "person_state", side_effect=lambda db, sub: self.state.get(sub)),
            mock.patch.object(web.registry, "devices", side_effect=lambda db, owner=None, include_revoked=False:
                              [r for r in rows if owner is None or r["owner"] == owner]),
            mock.patch.object(web.registry, "device", side_effect=lambda db, device_id, owner=None: next(
                (r for r in rows if str(r["id"]) == str(device_id) and (owner is None or r["owner"] == owner)), None)),
            mock.patch.object(web.registry, "people", return_value={
                RESIDENT_SUB: {"sub": RESIDENT_SUB, "username": "resi", "display": "Resi Example"},
                ADMIN_SUB: {"sub": ADMIN_SUB, "username": "admin", "display": "Admin Example"}}),
            mock.patch.object(web.telemetry, "dashboard", side_effect=fake_dashboard),
            mock.patch.object(web.telemetry, "history", side_effect=lambda client, mac, range_key, now=None, **_kw:
                              sample_history(range_key)),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.app = web.create_app(example_settings(passpoint=True))
        if self.template_globals:
            self.app.jinja_env.globals.update(i18n.template_globals())     # as web.py should (idempotent)
        else:
            for name in i18n.template_globals():
                self.app.jinja_env.globals.pop(name, None)
        self.client = self.app.test_client()

    def log_in(self, sub=RESIDENT_SUB):
        with self.client.session_transaction() as sess:
            sess["user"] = {"sub": sub, "username": sub, "name": sub}
            sess["login_at"] = int(dt.datetime.now().timestamp())
            sess["csrf"] = "example-csrf"

    def get(self, url, lang="en", sub=RESIDENT_SUB):
        self.log_in(sub)
        resp = self.client.get(url, headers={"Accept-Language": lang, "Accept": "text/html"})
        self.assertEqual(resp.status_code, 200, url)
        return resp, resp.get_data(as_text=True)

    def json_block(self, page, block_id):
        m = re.search(r'<script type="application/json" id="%s">(.*?)</script>' % block_id, page, re.DOTALL)
        self.assertIsNotNone(m, block_id)
        return json.loads(m.group(1))

    def assert_csp_safe(self, resp, page):
        """No inline code: scripts are static files (modules) or JSON data blocks; the CSP
        allows scripts from 'self' only; the CSRF token is in a meta tag for the rename."""
        for attrs, body in SCRIPT.findall(page):
            if "src=" in attrs:
                self.assertRegex(attrs, r'type="module" src="/static/[a-z]+\.js"')
                self.assertEqual(body.strip(), "")
            else:
                self.assertIn('type="application/json"', attrs)
                json.loads(body)                                # data, not code
        self.assertNotRegex(page, r"\son[a-z]+=")              # no inline event handlers
        self.assertNotIn("style=", page)                        # style-src 'self' forbids inline styles
        self.assertIn('<meta name="csrf" content="example-csrf">', page)
        csp = resp.headers["Content-Security-Policy"]
        self.assertIn("script-src 'self'", csp)
        self.assertIn("connect-src 'self'", csp)
        self.assertNotIn("unsafe", csp)


class DevicesPageTests(DashboardPagesTestCase):
    def test_every_language_renders_every_state(self):
        for lang in ("en", "de", "uk"):
            t = i18n.TEXT[lang]
            resp, page = self.get("/", lang)
            self.assert_csp_safe(resp, page)
            self.assertIn('<html lang="%s">' % lang, page)
            for state in ("online", "offline", "never_connected"):
                self.assertIn('class="dev-state state-%s"' % state, page)
                self.assertIn(t["state_" + state], page)
            self.assertIn(esc(t["house_title"]), page)
            self.assertIn(esc(t["house_speed_note"]), page)
            self.assertIn(esc(t["diag_weak_signal"]), page)
            self.assertIn(esc(t["diag_weak_signal_do"]), page)
            self.assertIn(esc(t["f_link_note"]), page)
            self.assertNotIn("{", visible(page))                                       # every placeholder filled

    def test_the_cards_are_complete_without_javascript(self):
        _resp, page = self.get("/", "de")
        self.assertIn("Scharni · 2. Stock · Ecke", page)                     # the room from the AP
        self.assertIn("5 GHz · Kanal 36 · Wi-Fi 6", page)
        self.assertIn("−58 dBm", page)
        self.assertIn("88 von 100", page)
        self.assertIn("2,4 Mbit/s", page)                                  # data now
        self.assertIn("1,8 GB", page)                                      # data in 24 hours
        self.assertIn("866 Mbit/s", page)                                  # the radio link rate
        self.assertIn("verbunden seit", page)
        self.assertIn("zuletzt gesehen", page)
        self.assertIn('href="/devices/%s"' % IDS[0], page)                  # the detail page
        self.assertIn('action="/devices/%s/rename"' % IDS[0], page)         # the rename form, also without JS
        self.assertIn(esc(i18n.TEXT["de"]["diag_never_connected_do"]), page)
        self.assertIn("Stand", page)                                       # "as of", replaced by the script
        self.assertIn(i18n.TEXT["de"]["expires_badge"], page)              # the iPad's key expires soon
        self.assertIn('action="/devices/%s/renew"' % IDS[2], page)
        self.assertIn('value="android"', page)                             # the enrolment stays
        self.assertIn('id="add"', page)

    def test_a_card_shows_two_findings_and_links_to_the_rest(self):
        _resp, page = self.get("/")
        card = page[page.index('id="device-%s"' % IDS[1]):page.index('id="device-%s"' % IDS[2])]
        self.assertEqual(card.count('class="finding sev-'), 2)
        self.assertIn(i18n.TEXT["en"]["diag_more"].format(n=3), card)

    def test_the_name_is_a_heading_with_an_edit_button(self):
        _resp, page = self.get("/")
        card = page[page.index('id="device-%s"' % IDS[0]):page.index('id="device-%s"' % IDS[1])]
        self.assertIn('<h2 class="dev-name-text" data-name>Pixel 8</h2>', card)
        self.assertIn('<summary class="edit-button" title="Rename">', card)
        self.assertIn('<span class="sr" data-name-label>Rename: Pixel 8</span>', card)
        # without the script: a plain POST form behind the button, with the CSRF token
        form = card[card.index('<form method="post" action="/devices/%s/rename"' % IDS[0]):]
        form = form[:form.index("</form>")]
        self.assertIn('name="csrf" value="example-csrf"', form)
        self.assertIn('name="name" value="Pixel 8"', form)
        self.assertIn('class="button small needs-js" data-cancel', form)     # Cancel only with the script
        self.assertNotIn('class="pill">Save', page)                             # no lone Save next to each name

    def test_a_conflicting_address_shows_the_finding_not_no_data(self):
        self.devices[0].update(state="unknown", signal_dbm=None, health=None, ap=None, rx_bps=None, tx_bps=None,
                               link_rx_bps=None, link_tx_bps=None, rx_24h_bytes=None, tx_24h_bytes=None, since=None,
                               last_seen=None, diagnostics=[{"code": "mac_conflict", "severity": "warn", "params": {"owners": 2}}])
        for lang in ("en", "de", "uk"):
            t = i18n.TEXT[lang]
            _resp, page = self.get("/", lang)
            card = page[page.index('id="device-%s"' % IDS[0]):page.index('id="device-%s"' % IDS[1])]
            self.assertIn(esc(t["diag_mac_conflict"]), card)
            self.assertIn(esc(t["diag_mac_conflict_do"]), card)
            self.assertNotIn(esc(t["unknown_line"]), card)
            self.assertNotIn(esc(t["diag_mac_conflict_admin_do"]), card)          # the residents' text
            _resp, page = self.get("/devices/%s" % IDS[0], lang)
            self.assertIn(esc(t["diag_mac_conflict_why"]), page)
            _resp, page = self.get("/admin", lang, sub=ADMIN_SUB)
            self.assertIn(esc(t["diag_mac_conflict_admin_why"].format(n=2)), page)
            self.assertIn(esc(t["diag_mac_conflict_admin_do"]), page)

    def test_names_are_escaped(self):
        _resp, page = self.get("/admin", sub=ADMIN_SUB)
        self.assertIn("Sensor &lt;&amp;&gt; &#34;Werkstatt&#34;", page)
        self.assertNotIn('Sensor <&> "Werkstatt"', page)
        data = self.json_block(page, "np-data")
        self.assertIn('Sensor <&> "Werkstatt"', [d["name"] for d in data["devices"]])

    def test_the_scripts_get_texts_config_and_data(self):
        _resp, page = self.get("/", "uk")
        self.assertEqual(self.json_block(page, "np-texts"), i18n.TEXT["uk"])
        config = self.json_block(page, "np-config")
        self.assertEqual(config["api"], "/api/devices")
        self.assertEqual(config["page"], "devices")
        self.assertEqual([d["id"] for d in self.json_block(page, "np-data")["devices"]], IDS[:4])

    def test_no_devices(self):
        self.devices = []
        _resp, page = self.get("/")
        self.assertIn(i18n.TEXT["en"]["no_devices"], page)
        self.assertLess(page.index('id="add"'), page.index('id="devices-h"'))   # enrolment first

    def test_without_the_formatting_global_the_page_still_renders(self):
        self.app.jinja_env.globals.pop("fmt", None)
        self.app.jinja_env.globals.pop("diagnoses", None)
        _resp, page = self.get("/")
        self.assertIn("-58 dBm", page)
        self.assertIn(i18n.TEXT["en"]["state_online"], page)


class TelemetryStatesTests(DashboardPagesTestCase):
    def test_off(self):
        self.telemetry = "off"
        for lang in ("en", "de", "uk"):
            _resp, page = self.get("/", lang)
            self.assertIn(esc(i18n.TEXT[lang]["telemetry_off"]), page)
            self.assertIn('data-part="house" hidden', page)                 # no house strip of unknowns
            self.assertIn("state-unknown", page)
            self.assertIn("state-never_connected", page)
            self.assertNotIn(esc(i18n.TEXT[lang]["all_good"]), visible(page))  # no "all good" without data

    def test_unavailable(self):
        self.telemetry = "unavailable"
        _resp, page = self.get("/", "de")
        self.assertIn(esc(i18n.TEXT["de"]["telemetry_unavailable"]), page)
        self.assertIn('data-part="house" hidden', page)                     # shown again by the script
        self.assertIn(i18n.TEXT["de"]["st_unknown"], page)
        self.assertIn(i18n.TEXT["de"]["house_speed_none"], page)

    def test_stale(self):
        _resp, page = self.render_devices(sample_dashboard(stale=True, house=sample_house(wifi_data_age_s=1500)))
        self.assertIn(esc(i18n.TEXT["en"]["live_stale"].split("{")[0]), page)
        self.assertIn(esc(i18n.TEXT["en"]["house_wifi_age"].format(age="25 min")), page)

    def render_devices(self, dashboard):
        with self.app.test_request_context("/", headers={"Accept-Language": "en"}):
            self.app.preprocess_request()
            return None, render_template("devices.html", dashboard=dashboard, devices=[], options=["apple"],
                                         expires_soon=lambda e: False)


class DevicePageTests(DashboardPagesTestCase):
    def test_every_language_and_state(self):
        for lang in ("en", "de", "uk"):
            t = i18n.TEXT[lang]
            for i in range(len(self.devices)):
                resp, page = self.get("/devices/%s" % IDS[i], lang, sub=ADMIN_SUB)   # admins may see any
                self.assert_csp_safe(resp, page)
                self.assertIn(esc(t["history_title"]), page)
                for key in ("signal", "quality", "traffic", "link", "online"):
                    self.assertIn('data-chart="%s"' % key, page)
                    self.assertIn(esc(t["ch_" + key]), page)
                self.assertIn(esc(t["ch_needs_js"]), page)               # in <noscript>: the list works without
                self.assertIn('class="chart-grid needs-js"', page)          # hidden without scripting
                self.assertIn('aria-current="true">%s<' % t["range_24h"], page)
                config = self.json_block(page, "np-config")
                self.assertEqual(config["device"], IDS[i])
                self.assertEqual(config["history"], "/api/devices/%s/history" % IDS[i])

    def test_details_and_full_findings(self):
        _resp, page = self.get("/devices/%s" % IDS[1])
        t = i18n.TEXT["en"]
        for code in ("weak_signal", "high_retries", "busy_channel", "unstable_roaming", "stuck_on_2ghz"):
            self.assertIn(esc(t["diag_%s_why" % code]), page)            # the explanation too
            self.assertIn(esc(t["diag_%s_do" % code]), page)
        self.assertIn("02:00:00:00:00:01", page)
        self.assertIn("10.30.0.41", page)
        self.assertIn("ap-colbe-0-far", page)
        self.assertIn("Colbe · ground floor · far end", page)
        self.assertIn("2.4 GHz · channel 6 · Wi-Fi 4", page)
        self.assertIn("7 per hour", page)
        self.assertIn("24%", page)

    def test_range_from_the_address(self):
        _resp, page = self.get("/devices/%s?range=7d" % IDS[0])
        self.assertIn('aria-current="true">7 days<', page)
        self.assertEqual(self.json_block(page, "np-config")["range"], "7d")
        _resp, page = self.get("/devices/%s?range=1y" % IDS[0])
        self.assertIn('aria-current="true">24 hours<', page)

    def test_another_residents_device_is_not_found(self):
        self.log_in(RESIDENT_SUB)
        self.assertEqual(self.client.get("/devices/%s" % IDS[4]).status_code, 404)   # the admin's device
        self.assertEqual(self.client.get("/devices/%s" % uuid.UUID(int=99, version=4)).status_code, 404)

    def test_from_the_admin_page(self):
        _resp, page = self.get("/devices/%s?from=admin" % IDS[0], sub=ADMIN_SUB)
        self.assertIn('href="/admin"', page)
        self.assertIn('name="back" value="/admin"', page)
        self.assertTrue(self.json_block(page, "np-config")["admin"])
        self.assertIn("Resi Example", page)                                   # the owner

    def test_the_event_list_without_javascript(self):
        device = sample_dashboard()["devices"][0]
        with self.app.test_request_context("/devices/x", headers={"Accept-Language": "en"}):
            self.app.preprocess_request()
            page = render_template("device.html", device=device, dashboard=sample_dashboard(), history=sample_history())
        t = i18n.TEXT["en"]
        self.assertIn("Connected: Scharni · 2nd floor · corner (5 GHz)", page)
        self.assertIn("Moved from Scharni · 1st floor · middle to Colbe · ground floor · far end", page)
        self.assertIn("Switched from 5 GHz to 2.4 GHz", page)
        self.assertIn(t["tl_disconnected"], page)
        self.assertLess(page.index("Switched from"), page.index("Moved from"))   # newest first
        self.assertIn(esc(t["ch_needs_js"]), page)
        self.assertIn('class="card timeline-card"', page)                       # shown without scripting


class AdminPageTests(DashboardPagesTestCase):
    def test_every_language(self):
        for lang in ("en", "de", "uk"):
            resp, page = self.get("/admin", lang, sub=ADMIN_SUB)
            self.assert_csp_safe(resp, page)
            self.assertEqual(page.count('class="adm-item"'), len(self.rows) - 1)          # "Other" has no telemetry sample
            self.assertIn(esc(i18n.TEXT[lang]["adm_search_ph"]), page)
            self.assertEqual(page.count('action="/devices/'), len(self.rows) - 1)      # a revoke form per device
            self.assertIn('name="back" value="/admin"', page)
            for code in i18n.DIAGNOSES:
                self.assertIn('<option value="%s"' % code, page)

    def names(self, page):
        """(name, hidden) in page order."""
        return [(html.unescape(name), "hidden" in attrs)
                for attrs, name in re.findall(r'<li class="adm-item"([^>]*)>.*?class="adm-name" data-part="sum-name">(.*?)</strong>',
                                              page, re.DOTALL)]

    def test_search_filters_and_sorting_without_javascript(self):
        _resp, page = self.get("/admin?q=MAC", sub=ADMIN_SUB)
        self.assertEqual([n for n, hidden in self.names(page) if not hidden], ["MacBook Air"])
        _resp, page = self.get("/admin?q=02-00-00-00-00-02", sub=ADMIN_SUB)       # a MAC as the AP writes it
        self.assertEqual([n for n, hidden in self.names(page) if not hidden], ["iPad"])
        _resp, page = self.get("/admin?q=admin%20example", sub=ADMIN_SUB)         # the owner
        self.assertEqual([n for n, hidden in self.names(page) if not hidden], ['Sensor <&> "Werkstatt"'])
        _resp, page = self.get("/admin?state=offline", sub=ADMIN_SUB)
        self.assertEqual([n for n, hidden in self.names(page) if not hidden], ["iPad"])
        _resp, page = self.get("/admin?problem=with&sort=signal", sub=ADMIN_SUB)
        self.assertEqual([n for n, hidden in self.names(page) if not hidden], ["MacBook Air", 'Sensor <&> "Werkstatt"', "iPad"])
        _resp, page = self.get("/admin?problem=slow_link", sub=ADMIN_SUB)
        self.assertEqual([n for n, hidden in self.names(page) if not hidden], ['Sensor <&> "Werkstatt"'])
        self.assertIn("1 of 5 shown", page)
        _resp, page = self.get("/admin?sort=seen", sub=ADMIN_SUB)
        self.assertEqual([n for n, _h in self.names(page)][-1], "Kindle")          # never seen: last
        _resp, page = self.get("/admin?q=nothing-matches", sub=ADMIN_SUB)
        self.assertNotIn("data-none hidden", page)

    def test_problem_badges(self):
        _resp, page = self.get("/admin", sub=ADMIN_SUB)
        self.assertIn("problems: 4", page)          # MacBook: warn and bad only, not the info
        self.assertIn("badge sev-bad", page)


class TextTests(unittest.TestCase):
    def test_every_diagnosis_has_its_texts_in_every_language(self):
        source = (Path(__file__).resolve().parent.parent / "netportal" / "diagnostics.py").read_text()
        codes = set(re.findall(r'finding\("([a-z_0-9]+)"', source))
        self.assertLessEqual(codes, set(i18n.DIAGNOSES))                  # nothing reported without a text
        for lang, text in i18n.TEXT.items():
            for code in i18n.DIAGNOSES:
                for suffix in ("", "_why", "_do"):
                    self.assertTrue(text.get("diag_%s%s" % (code, suffix)), (lang, code, suffix))

    def test_rooms(self):
        F = i18n.Format
        ap_ = {"name": "ap-scharni-0-corner", "house": "scharni", "floor": 0, "spot": "corner"}
        self.assertEqual(F.room(ap_, "en"), "Scharni · ground floor · corner")
        self.assertEqual(F.room(ap_, "de"), "Scharni · Erdgeschoss · Ecke")
        self.assertEqual(F.room(ap_, "uk"), "Scharni · перший поверх · кут")
        self.assertEqual(F.room({"name": "2. stock scharni mitte", "house": None}, "de"), "2. stock scharni mitte")
        self.assertEqual(F.room({"name": "ap-x-9-y", "house": "x", "floor": 9, "spot": "y"}, "en"), "X · floor 9 · y")
        for lang in ("en", "de", "uk"):
            for spot in ("corner", "middle", "far"):
                self.assertIn("room_spot_" + spot, i18n.TEXT[lang])

    def test_formatting(self):
        F = i18n.Format
        self.assertEqual(F.bytes(1_830_000_000, "de"), "1,8 GB")
        self.assertEqual(F.bitrate(950, "en"), "950 bit/s")
        self.assertEqual(F.duration(8130, "uk"), "2 год 15 хв")
        self.assertEqual(F.ago(iso(3 * 3600), "en", iso()), "3 h ago")
        self.assertEqual(F.when(iso(), "en", iso()), "13:00")                  # the house's time (CET)
        self.assertEqual(F.number(12345.6, "uk", 1), "12 345,6")
        for name in ("bytes", "bitrate", "dbm", "percent", "duration", "date"):
            self.assertEqual(getattr(F, name)(None, "en"), "–")
        self.assertEqual(F.signal(-70), (2, "sig_fair", "warn"))
        self.assertEqual(F.health(None), None)


if __name__ == "__main__":
    unittest.main()
