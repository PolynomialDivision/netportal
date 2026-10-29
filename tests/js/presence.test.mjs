// static/presence.js and its DOM in render.js: the state line from DEVICE.presence reads like
// the server's (render/format.rs presence_view; Python: Format.presence_view) in every language, never contradicts
// itself (no "offline" beside a fresh connection, "Not connected" only while offline), says why
// a state is unknown, and keeps its relative times current without a request.
// node --test tests/js/

import { test } from "node:test";
import assert from "node:assert/strict";
import { createFormatter } from "../../crates/netportal-web/static/format.js";
import * as P from "../../crates/netportal-web/static/presence.js";
import * as R from "../../crates/netportal-web/static/render.js";
import { installDom } from "./dom-shim.mjs";
import { askServer, SKIP } from "./web-oracle.mjs";

installDom();
const NOW = Date.parse("2026-10-25T15:53:00Z");
const ago = (s) => new Date(NOW - s * 1000).toISOString();
const presence = (state, reason, by = null, confirmedS = null, sinceS = null, extra = {}) => ({
  state, reason, confirmed_by: by, confirmed_at: confirmedS === null ? null : ago(confirmedS),
  since: sinceS === null ? null : ago(sinceS), basis: "measured", session: null, stale_after_s: 660, poll_s: 30, evidence: [], ...extra });

// the devices both sides get: every state, the reported case, the v1 fallbacks
const DEVICES = [
  { id: "a", state: "online", since: ago(14), last_seen: ago(12), diagnostics: [{ code: "offline", severity: "info" }],
    presence: presence("online", "acct_start", "radius_acct", 12, 14, { poll_s: 5 }) },
  { id: "b", state: "connecting", last_seen: ago(3), diagnostics: [], presence: presence("connecting", "accept_pending", "radius_auth", 3, 3) },
  { id: "c", state: "offline", last_seen: ago(130), diagnostics: [{ code: "offline", severity: "info" }],
    presence: presence("offline", "acct_stop", "radius_acct", 130, 130) },
  { id: "d", state: "offline", last_seen: ago(7200), diagnostics: [], presence: presence("offline", "association_gone", "prometheus", 40, 7200) },
  { id: "e", state: "unknown", last_seen: null, diagnostics: [], presence: presence("unknown", "telemetry_unavailable") },
  { id: "f", state: "unknown", last_seen: ago(4000), diagnostics: [], presence: presence("unknown", "session_stale") },
  { id: "g", state: "unknown", last_seen: null, diagnostics: [{ code: "mac_conflict", severity: "warn" }], presence: presence("unknown", "mac_conflict") },
  { id: "h", state: "unknown", last_seen: null, diagnostics: [], presence: presence("unknown", "something_new") },
  { id: "i", state: "never_connected", diagnostics: [], presence: presence("never_connected", null) },
  { id: "j", state: "online", since: ago(8130), last_seen: ago(0), diagnostics: [] },                    // v1: no presence
  { id: "k", state: "offline", last_seen: ago(11000), diagnostics: [] },
  { id: "l", state: "unknown", last_seen: null, diagnostics: [] },
  { id: "m", state: "online", diagnostics: [], presence: presence("online", "association", "unifi_brand_new", 70, 600) },
  { id: "n", state: "bogus", diagnostics: [], presence: { state: "nonsense" } },
];

const TIMES = [ago(0), ago(4), ago(5), ago(59), ago(61), ago(7200), "2026-03-29T01:30:07Z"];

const server = askServer("presence", { devices: DEVICES, now: new Date(NOW).toISOString(), times: TIMES });
const skip = !server && SKIP;
// the moments' ISO text differs in form (Z with or without milliseconds): compare the moment, and everything else
const norm = (view) => JSON.parse(JSON.stringify(view, (k, v) => (k === "time" && typeof v === "string" ? Date.parse(v) : v)));

test("the code tables are the server's", { skip }, () => {
  for (const name of ["PRESENCE_STATES", "PRESENCE_SOURCES", "PRESENCE_REASONS", "PRESENCE_ICON"]) {
    assert.deepEqual(P[name], server.tables[name], name);
  }
});

test("the state line reads like the server's, in every language", { skip }, () => {
  for (const lang of ["en", "de", "uk"]) {
    const f = createFormatter(lang, server.texts[lang]);
    DEVICES.forEach((d, i) => assert.deepEqual(norm(P.presenceView(d, f, NOW, { ssid: "Example" })), norm(server.views[lang][i]), `${lang} ${d.id}`));
    TIMES.forEach((t, i) => {
      assert.equal(f.recent(t, NOW), server.recent[lang][i], `${lang} recent ${t}`);
      assert.equal(f.stamp(t), server.stamp[lang][i], `${lang} stamp ${t}`);
    });
  }
  assert.deepEqual(DEVICES.map((d) => P.findingsShown(d).map((x) => x.code)), server.shown);
});

test("the reported case: just logged in is online, confirmed by the session records, no offline note", { skip }, () => {
  const f = createFormatter("en", server.texts.en);
  const d = DEVICES[0];
  const text = P.viewText(P.presenceView(d, f, NOW));
  assert.equal(text, "Online · connected since 16:52 (14 s) · Confirmed 12 s ago by Wi-Fi session records");
  assert.ok(!/offline|not connected/i.test(text));
  assert.deepEqual(P.findingsShown(d), []);
  const box = R.findings(d, f, { full: true });
  assert.ok(!box.textContent.includes(server.texts.en.diag_offline));
});

test("no state line contradicts itself, in any language", { skip }, () => {
  for (const lang of ["en", "de", "uk"]) {
    const t = server.texts[lang];
    const f = createFormatter(lang, t);
    for (const d of DEVICES) {
      const view = P.presenceView(d, f, NOW, { ssid: "Example" });
      const line = R.stateLine(d, f, { now: NOW, ssid: "Example" });
      const text = line.textContent;
      assert.equal(line.getAttribute("class"), `dev-state state-${view.state}`);
      assert.ok(text.startsWith(t[`state_${view.state}`]), `${lang} ${d.id}: ${text}`);
      assert.ok(!text.includes("{"), `${lang} ${d.id}: ${text}`);
      const others = P.PRESENCE_STATES.filter((s) => s !== view.state).map((s) => t[`state_${s}`]);
      for (const word of others) assert.ok(!text.includes(word), `${lang} ${d.id}: "${word}" in ${text}`);
      if (view.state !== "offline") {
        assert.ok(!text.includes(f.fill(t.pr_offline_since, { when: "" }).trim()), `${lang} ${d.id}`);
        assert.ok(!P.findingsShown(d).some((x) => x.code === "offline"), `${lang} ${d.id}`);
      }
      if (view.state === "online" || view.state === "connecting") assert.ok(!text.includes(f.fill(t.seen_line, { when: "" }).trim()), `${lang} ${d.id}`);
      if (view.state === "unknown") {
        assert.equal(view.confirmed, null);                                  // nothing confirmed
        assert.ok(!text.includes(d.presence?.reason || "\0"), `${lang} ${d.id}: no code for residents`);
      }
      if (d.presence === undefined) assert.equal(view.confirmed, null);     // a v1 payload claims nothing
    }
  }
});

test("unknown says why, connecting says what happens", { skip }, () => {
  const f = createFormatter("en", server.texts.en);
  const say = (d) => P.viewText(P.presenceView(d, f, NOW));
  assert.equal(say(DEVICES[4]), "Status unknown · The Wi-Fi data is not available right now.");
  assert.equal(say(DEVICES[5]), "Status unknown · The access point stopped reporting the last session, so the status cannot be confirmed. · last seen 1 h ago");
  assert.equal(say(DEVICES[6]), "Status unknown");                        // the mac_conflict finding explains it
  assert.equal(say(DEVICES[7]), "Status unknown · The status cannot be determined right now.");
  assert.equal(say(DEVICES[1]), "Connecting… · Login accepted, the Wi-Fi connection is being set up. · Confirmed just now by login server");
  assert.equal(say(DEVICES[2]), "Offline · disconnected 2 min ago · Confirmed 2 min ago by Wi-Fi session records");
  assert.equal(say(DEVICES[12]), "Online · connected since 16:43 (10 min) · Confirmed 1 min ago by unifi_brand_new");
  assert.equal(say(DEVICES[13]), "Status unknown · No live data at the moment.");           // no reason given
  assert.equal(P.stateOf(DEVICES[13]), "unknown");
});

test("moments carry their second in the title and tick without a request", { skip }, () => {
  const f = createFormatter("en", server.texts.en);
  const line = R.stateLine(DEVICES[0], f, { now: NOW });
  const times = line.querySelectorAll("time[data-rel]");
  assert.deepEqual(times.map((n) => n.getAttribute("data-rel")), ["elapsed", "recent"]);
  assert.equal(times[1].getAttribute("title"), "2026-10-25 16:52:48");
  assert.equal(times[1].getAttribute("datetime"), ago(12));
  assert.equal(R.tickTimes(line, f, NOW + 20e3), 2);
  assert.equal(times[1].textContent, "32 s ago");
  assert.equal(times[0].textContent, "34 s");
  assert.equal(R.tickTimes(line, f, NOW + 20e3), 0);                       // nothing to do: no DOM writes
  R.tickTimes(line, f, NOW + 600e3);
  assert.equal(times[1].textContent, "10 min ago");
  // the absolute clock ("since 16:52") is not a relative one
  assert.equal(line.querySelectorAll("time").length, 3);
  // "ago" times elsewhere tick too
  const el = R.timeEl(f, ago(30), "ago", NOW);
  assert.equal(el.getAttribute("data-rel"), "ago");
  assert.equal(R.timeEl(f, ago(30), "when", NOW).getAttribute("data-rel"), null);
});

test("the admin's view: reason code, session, staleness and evidence, newest first", { skip }, () => {
  const t = server.texts.en, f = createFormatter("en", t);
  const d = { ...DEVICES[0], presence: { ...DEVICES[0].presence, session: {
    nas_ip: "10.10.0.21", acct_session_id: "5F3A1C2B-00000042", ap: { name: "ap-scharni-2-corner", house: "scharni", floor: 2, spot: "corner" },
    started: ago(14), updated: ago(12), stopped: null, cause: null, interim_s: 300, interim_basis: "measured" },
  evidence: [{ source: "prometheus", at: ago(95), kind: "association_gone" }, { source: "radius_acct", at: ago(12), kind: "acct_start" },
    { source: "radius_auth", at: ago(15), kind: "accept" }, { source: "unifi_syslog", at: "garbage", kind: "connected" }] } };
  const box = R.presenceAdmin(d, f, NOW);
  const text = box.textContent;
  for (const s of ["acct_start", t.pr_reason_acct_start, "10.10.0.21", "5F3A1C2B-00000042", "Scharni · 2nd floor · corner",
    "started 14 s ago", "updated 12 s ago", "interval 5 min", "(measured)", "11 min without an update", "660 s", t.src_admin_radius_acct,
    t.pr_admin_title]) {
    assert.ok(text.includes(s), `${s} in ${text}`);
  }
  const kinds = box.querySelectorAll("li").map((li) => li.querySelector("span").textContent);
  assert.deepEqual(kinds, ["acct_start", "accept", "association_gone", "connected"]);
  assert.equal(R.presenceAdmin(DEVICES[9], f, NOW).textContent, "");     // no presence: nothing to show
  assert.ok(!text.includes("{"));
});
