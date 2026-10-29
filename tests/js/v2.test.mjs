// Telemetry v2's pure helpers: the evidence of findings, codes and their texts, incidents and
// APs (format.js, admin.js), the merged timeline, day bars, month ticks and incident lanes
// (charts.js), the event filter (render.js). Where the server formats the same thing
// (crates/netportal-web/src/render/format.rs; Python: i18n.Format) both must answer alike, in every language.
// node --test tests/js/

import { test } from "node:test";
import assert from "node:assert/strict";
import * as F from "../../crates/netportal-web/static/format.js";
import * as C from "../../crates/netportal-web/static/charts.js";
import * as A from "../../crates/netportal-web/static/admin.js";
import { EVENT_FILTERS, filterEvents } from "../../crates/netportal-web/static/render.js";
import { askServer, SKIP } from "./web-oracle.mjs";

const T0 = Date.parse("2026-10-25T10:00:00Z");
const iso = (ms) => new Date(ms).toISOString();

// findings as the diagnostics make them (code, severity, basis, evidence, params)
const FINDINGS = [
  { code: "weak_signal", evidence: { signal_dbm: -79, warn_dbm: -75, bad_dbm: -80 }, params: { signal_dbm: -79 } },
  { code: "low_snr", evidence: { snr_db: 14, noise_dbm: -88, signal_dbm: -74, warn_db: 20 } },
  { code: "high_retries", evidence: { retry_ratio: 0.24, tx_attempts_per_s: 41.5, warn: 0.1 } },
  { code: "busy_channel", evidence: { channel_util: 0.72, channel: 6 } },
  { code: "slow_link", evidence: { link_rx_bps: 6_500_000, signal_dbm: -62, throughput_bps: 2_100_000 } },
  { code: "unstable_roaming", basis: "inferred", evidence: { roams_1h: 7, roams_1h_measured: null, warn: 6 } },
  { code: "frequent_disconnects", evidence: { reconnects_24h: 8, disconnects_24h_measured: 7, causes: { "Lost-Carrier": 5, "2": 1 }, warn: 6 } },
  { code: "stuck_on_2ghz", evidence: { bands_7d: ["2.4", "5"], signal_dbm: -58, associated_s: 5400 } },
  { code: "auth_failures", evidence: { count_24h: 23, reasons: { unknown_cert: 20, weird: 3 }, last_at: "2026-10-25T09:53:00Z",
    last_reason: "unknown_cert", last_accept: null, locked_out: true, warn: 3 } },
  { code: "cert_expiring", evidence: { expires: "2026-10-31T10:00:00Z", days_left: 6 } },
  { code: "cert_expired", evidence: { expires: "2026-10-20T10:00:00Z", days_left: -5 } },
  { code: "rotating_mac", evidence: { macs_30d: 4, min_macs: 3 } },
  { code: "ap_overloaded", evidence: { ap: "ap-colbe-0-far", clients: 31, channel_util: 0.84, band: "2.4", clients_warn: 25 } },
  { code: "poor_coverage", evidence: { aps: { "ap-colbe-0-far": -77.4, "ap-x-9-y": -80 }, minutes: { a: 1 }, warn_dbm: -72 },
    params: { best_signal_dbm: -77.4, aps: 2 } },
  { code: "incident_correlated", basis: "inferred", evidence: { incident: { id: 7, kind: "ap_restarted", subject: "d0:21",
    subject_name: "ap-scharni-2-corner", started: "2026-10-25T07:00:00Z" }, disconnects: ["2026-10-25T07:01:00Z"], margin_s: 120 } },
  { code: "stale_data", evidence: { age_s: 900, threshold_s: 600 } },
  { code: "offline", evidence: { last_seen: "2026-10-25T08:00:00Z" } },
  { code: "never_connected", evidence: { logins: 0 } },
  { code: "something_new", evidence: { signal_dbm: -70, odd: { a: 1 } } },
];
const APS = [
  { state: "ok", clients: 31, radios: [{ channel_util: 0.86 }, { channel_util: 0.4 }], weak_clients: 10, uptime_s: 9e5, uplink_mbps: 2500 },
  { state: "ok", clients: 9, radios: [{ channel_util: 0.65 }], weak_clients: 0, uptime_s: 3600, uplink_mbps: 100 },
  { state: "down", clients: null, radios: [] },
  { state: "unknown", clients: 5, radios: [], weak_clients: 2 },
];

const INCIDENTS = [{ kind: "ap_down", subject: "d0", subject_name: "ap-scharni-2-corner" }, { kind: "internet_down", subject: "" },
  { kind: "switch_port_down", subject: "sw/7", subject_name: "sw-keller port 7" }, { kind: "brand_new" }, "dns_down"];
const DAYS = ["2026-10-24", "2026-01-01", "2026-03-29"];
const CAUSES = ["Lost-Carrier", "lost_carrier", "2", "22", "23", "", null, "User Request", "nonsense"];

const server = askServer("v2", { findings: FINDINGS, aps: APS, incidents: INCIDENTS, days: DAYS, causes: CAUSES });
const skip = !server && SKIP;

test("the code tables are the server's", { skip }, () => {
  for (const name of ["EVIDENCE_SPEC", "EVIDENCE_FORMAT", "EVIDENCE_WINDOW", "EVIDENCE_SHORT", "EVENT_KINDS", "REJECT_REASONS",
    "TERMINATE_CAUSES", "INCIDENT_KINDS", "MAC_MODES", "DIAGNOSES"]) {
    assert.deepEqual(F[name], server.tables[name], name);
  }
});

test("a finding's evidence reads like the server's, in every language", { skip }, () => {
  for (const lang of ["en", "de", "uk"]) {
    const f = F.createFormatter(lang, server.texts[lang]);
    FINDINGS.forEach((finding, i) => {
      const { items, window } = f.evidenceItems(finding);
      assert.deepEqual([items, window], server.lang[lang].items[i], `${lang} ${finding.code}`);
      assert.deepEqual(f.evidenceItems(finding, true).items, server.lang[lang].admin[i], `${lang} ${finding.code} (admin)`);
      assert.equal(f.evidenceShort(finding), server.lang[lang].short[i], `${lang} ${finding.code} (short)`);
    });
    INCIDENTS.forEach((inc, i) => assert.equal(f.incidentText(inc), server.lang[lang].incidents[i], `${lang} incident ${i}`));
    DAYS.forEach((d, i) => assert.equal(f.day(d), server.lang[lang].days[i], `${lang} ${d}`));
  }
});

test("residents never see a field name, admins see every value", { skip }, () => {
  const f = F.createFormatter("en", server.texts.en);
  const weak = f.evidenceItems(FINDINGS[0]);
  assert.deepEqual(weak.items, [["signal", "−79 dBm"], ["limit", "−75 dBm"]]);
  assert.ok(!JSON.stringify(f.evidenceItems(FINDINGS[8])).includes("count_24h"));
  assert.ok(JSON.stringify(f.evidenceItems(FINDINGS[8], true)).includes("locked_out"));
  assert.equal(f.evidenceItems(FINDINGS[8]).window, "in the last 24 hours");
  assert.equal(f.evidenceShort(FINDINGS[6]), "8 times in 24 hours");
  assert.equal(f.evidenceShort(FINDINGS[11]), "4 addresses seen");
  assert.equal(f.evidenceShort(FINDINGS[13]), "−77 dBm");
  assert.match(f.evidenceItems(FINDINGS[6]).items[2][1], /signal gone\) ×5/);
});

test("terminate causes by name or number, reject reasons", { skip }, () => {
  assert.deepEqual(CAUSES.map(F.causeKey), server.causes);
  assert.equal(F.causeKey("Port-Administratively-Disabled"), "port_administratively_disabled");
  assert.equal(F.reasonKey("revoked"), "revoked");
  assert.equal(F.reasonKey("<script>"), "other");
  for (const lang of ["en", "de", "uk"]) {
    const t = server.texts[lang];
    for (const c of F.TERMINATE_CAUSES.concat("unknown")) assert.ok(t[`cause_${c}`], `${lang} cause_${c}`);
    for (const r of F.REJECT_REASONS) for (const s of ["", "_admin"]) assert.ok(t[`rr_${r}${s}`], `${lang} rr_${r}${s}`);
    for (const k of F.EVENT_KINDS) assert.ok(t[`tl_kind_${k}`], `${lang} tl_kind_${k}`);
    for (const k of F.INCIDENT_KINDS) assert.ok(t[`inc_${k}`], `${lang} inc_${k}`);
    for (const m of F.MAC_MODES) for (const s of ["mm_", "mm_admin_"]) assert.ok(t[`${s}${m}`], `${lang} ${s}${m}`);
  }
});

test("AP names, states, load and warnings (as the server)", { skip }, () => {
  assert.deepEqual(F.apFromName("ap-scharni-2-corner"), { name: "ap-scharni-2-corner", house: "scharni", floor: 2, spot: "corner" });
  assert.equal(F.apFromName("Garage").house, null);
  assert.deepEqual(APS.map(A.apWarningCodes), server.ap_warnings);
  assert.deepEqual(APS.map(A.apState), ["up", "up", "down", "unknown"]);
  assert.equal(A.apWeakShare(APS[3]), 0.4);
  assert.equal(A.apLoad(APS[0]), 0.86);
  assert.equal(A.apLoad(APS[2]), null);
});

test("jobs, rejected logins, incidents, raw rows", () => {
  assert.equal(A.jobState({ name: "rollup" }), "never");
  assert.equal(A.jobState({ name: "rollup", last_attempt: iso(T0), last_success: iso(T0 - 60e3), ok: false, last_error: "x" }), "failed");
  assert.equal(A.jobState({ name: "unifi_events", last_attempt: iso(T0), last_success: iso(T0), ok: true, age_s: 3600 }), "late");
  assert.equal(A.jobState({ name: "prune", last_attempt: iso(T0), last_success: iso(T0), ok: true, age_s: 3600 }), "ok");
  const n = A.normaliseFailures({ available: true, count: 3, recent: [{ reason: "revoked" }, { reason: "revoked" }], by_reason: {} });
  assert.deepEqual([n.total, n.byReason, n.available], [3, { revoked: 2 }, true]);
  assert.equal(A.normaliseFailures({ available: false }).available, false);
  // a row of repeated rejects counts its tries ("count") where the server sent no by_reason
  assert.deepEqual(A.normaliseFailures([{ reason: "no_cert", count: 40 }, { reason: "no_cert" }]).byReason, { no_cert: 41 });
  assert.deepEqual(A.splitIncidents([{ id: 1, ended: null }, { id: 2, ended: iso(T0) }]), { open: [{ id: 1, ended: null }], recent: [{ id: 2, ended: iso(T0) }] });
  const rows = A.rawRows({ windows: [{ mac: "aa" }, { mac: "bb" }], conflicts: [{ mac: "bb", other_owners: 2 }] }, "macs");
  assert.deepEqual(rows.map((r) => r.other_owners), [null, 2]);
  assert.deepEqual(A.rawRows({ auth: [1] }, "auth"), [1]);
  assert.deepEqual(A.rawRows(null, "days"), []);
  for (const part of A.RAW_PARTS) assert.ok(A.RAW_COLUMNS[part].length, part);
});

test("the merged timeline: every kind, inferred spans stay inferred", () => {
  const ev = (kind, min, extra = {}) => ({ kind, at: iso(T0 + min * 60e3), basis: "measured", ...extra });
  const events = [
    ev("authenticated", 0), ev("connected", 1, { ap: "a", basis: "inferred" }), ev("roamed", 30, { ap: "b", from_ap: "a" }),
    ev("session_ended", 60), ev("auth_rejected", 70), ev("reconnected", 80, { ap: "c" }), ev("mac_changed", 85, { basis: "inferred" }),
    ev("incident", 90, { duration_s: 300 }), ev("disconnected", 100), ev("band_changed", 110, { ap: "c" }),
  ];
  const { spans, marks } = C.timelineSegments(events, T0, T0 + 120 * 60e3);
  assert.deepEqual(spans.map((s) => [s.ap, (s.start - T0) / 60e3, (s.end - T0) / 60e3, s.basis]),
    [["a", 1, 30, "inferred"], ["b", 30, 60, "measured"], ["c", 80, 100, "measured"], ["c", 110, 120, "measured"]]);
  assert.deepEqual(marks.map((m) => m.kind), ["roamed", "session_ended", "auth_rejected", "reconnected", "mac_changed", "incident",
    "disconnected", "band_changed"]);
  assert.ok(!marks.some((m) => m.kind === "authenticated" || m.kind === "connected"));
});

test("the event filters", () => {
  const all = F.EVENT_KINDS.map((kind) => ({ kind }));
  assert.equal(filterEvents(all, "all").length, all.length);
  assert.deepEqual(filterEvents(all, "logins").map((e) => e.kind), ["authenticated", "auth_rejected", "mac_changed"]);
  for (const kinds of Object.values(EVENT_FILTERS)) for (const k of kinds || []) assert.ok(F.EVENT_KINDS.includes(k), k);
});

test("day bars: each day to the next one, bytes from the average rate", () => {
  const day = 86400e3;
  const pts = [{ t: T0, v: 8000 }, { t: T0 + day - 3600e3, v: null }, { t: T0 + 2 * day - 3600e3, v: 800 }];   // a clock change
  assert.deepEqual(C.dayBars(pts).map((b) => (b.t1 - b.t0) / 3600e3), [23, 24, 24]);
  assert.deepEqual(C.bytesPerDay(pts).map((p) => p.v), [8000 * 23 * 3600 / 8, null, 800 * 86400 / 8]);
  const g = C.barGeometry(10, 0, 100, 2);
  assert.equal(g.slot, 10);
  assert.equal(g.gap, 2);
  assert.equal(g.bar, 4);
  assert.equal(g.x(3, 1), 3 * 10 + 1 + 4);
  assert.equal(C.barGeometry(0, 0, 100).slot, 0);
});

test("month ticks for a year, at the house's midnight", () => {
  const end = Date.parse("2026-10-25T12:00:00Z"), start = end - 365 * 86400e3;
  const ticks = C.timeTicks(start, end, 6);
  assert.ok(ticks.length <= 6 && ticks.length >= 4, String(ticks.length));
  for (const t of ticks) {
    const wall = new Date(t + C.zoneOffsetMs(t, "Europe/Berlin"));
    assert.equal(wall.getUTCDate(), 1);
    assert.equal(wall.getUTCHours(), 0);
  }
  assert.ok(C.timeTicks(end - 7 * 86400e3, end, 8).length > 0);          // short spans keep day ticks
});

test("the axis says months (with the year in January) for long spans", { skip }, () => {
  const f = F.createFormatter("de", server.texts.de);
  assert.equal(f.axisTime("2026-03-01T00:00:00+01:00", 365 * 86400), "März");
  assert.equal(f.axisTime("2026-01-01T00:00:00+01:00", 365 * 86400), "2026");
  assert.equal(f.axisTime("2026-03-01T00:00:00+01:00", 7 * 86400), "1. März");
});

test("incident lanes: one per kind and subject, open ones to the end, clipped", () => {
  const h = 3600e3;
  const incidents = [
    { id: 1, kind: "ap_down", subject: "x", started: iso(T0 + h), ended: null },
    { id: 2, kind: "ap_down", subject: "x", started: iso(T0 - 2 * h), ended: iso(T0 + 0.5 * h) },
    { id: 3, kind: "dns_down", subject: "", started: iso(T0 + 2 * h), ended: iso(T0 + 2 * h + 1000) },
    { id: 4, kind: "dns_down", subject: "", started: iso(T0 - 9 * h), ended: iso(T0 - 8 * h) },
  ];
  const { lanes, items } = C.incidentLanes(incidents, T0, T0 + 4 * h, 60e3);
  assert.deepEqual(lanes.map((l) => l.key), ["ap_down|x", "dns_down|"]);
  assert.deepEqual(items.map((i) => [i.inc.id, i.lane, (i.start - T0) / h, i.open]), [[1, 0, 1, true], [2, 0, 0, false], [3, 1, 2, false]]);
  assert.equal(items[0].end, T0 + 4 * h);
  assert.equal(items[2].end - items[2].start, 60e3);        // at least minMs wide
});
