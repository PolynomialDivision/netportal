// static/charts.js, its pure part: points, gaps, scales, ticks, paths and the connection
// timeline. node --test tests/js/

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  apSlots, availability, extent, linePath, nearestIndex, niceStep, niceTicks, scaleLinear, segments, stepPath,
  summary, timeTicks, timelineSegments, toMs, toPoints, zoneOffsetMs, AP_SLOTS,
} from "../../netportal/static/charts.js";

const T0 = 1_792_900_800;   // 2026-10-25 10:40 UTC, Unix seconds as the API sends them

test("timestamps: seconds, milliseconds and ISO", () => {
  assert.equal(toMs(T0), T0 * 1000);
  assert.equal(toMs(T0 * 1000), T0 * 1000);
  assert.equal(toMs("2026-10-25T10:40:00Z"), Date.parse("2026-10-25T10:40:00Z"));
  assert.equal(toMs(null), null);
  assert.equal(toMs("nonsense"), null);
});

test("points keep null as missing, never as zero", () => {
  const pts = toPoints([[T0 + 60, 2], [T0, null], [T0 + 120, "3"], [T0 + 180, undefined]]);
  assert.deepEqual(pts.map((p) => p.v), [null, 2, 3, null]);
  assert.deepEqual(pts.map((p) => p.t), [T0, T0 + 60, T0 + 120, T0 + 180].map((t) => t * 1000));
});

test("segments break at nulls and at missing samples", () => {
  const pts = toPoints([[0, 1], [60, 2], [120, null], [180, 4], [240, 5], [600, 6], [660, 7]]);
  const runs = segments(pts, 150e3);
  assert.deepEqual(runs.map((r) => r.map((p) => p.v)), [[1, 2], [4, 5], [6, 7]]);
  assert.deepEqual(segments(toPoints([[0, null], [60, null]])), []);
  assert.deepEqual(segments(toPoints([[0, 5]])).length, 1);         // a lone value is still drawn (a dot)
});

test("extent, summary, availability ignore missing values", () => {
  const pts = toPoints([[0, -60], [60, null], [120, -70], [180, -50]]);
  assert.deepEqual(extent(pts), [-70, -50]);
  assert.deepEqual(summary(pts), { min: -70, max: -50, avg: -60, last: -50, count: 3 });
  assert.equal(summary(toPoints([[0, null]])), null);
  assert.equal(extent([]), null);
  assert.equal(availability(toPoints([[0, 1], [60, 0], [120, null], [180, 1], [240, 1]])), 0.75);
  assert.equal(availability(toPoints([[0, null]])), null);
});

test("nice steps and ticks", () => {
  assert.equal(niceStep(100, 4), 25);
  assert.equal(niceStep(7, 4), 2);
  assert.equal(niceStep(4.2e6, 4), 2e6);              // rounds up: never more than about 4 parts
  assert.deepEqual(niceTicks(0, 4.1e6, 4).ticks, [0, 2e6, 4e6, 6e6]);
  assert.deepEqual(niceTicks(-78, -54, 4), { min: -80, max: -50, ticks: [-80, -70, -60, -50], step: 10 });
  const flat = niceTicks(5, 5, 4);
  assert.ok(flat.min < 5 && flat.max > 5);
});

test("a linear scale and its inverse", () => {
  const x = scaleLinear([0, 100], [50, 250]);
  assert.equal(x(0), 50);
  assert.equal(x(50), 150);
  assert.equal(x.invert(250), 100);
  const y = scaleLinear([-100, -30], [170, 10]);
  assert.equal(y(-30), 10);
  assert.equal(scaleLinear([1, 1], [0, 10])(1), 0);
});

test("paths", () => {
  const x = (t) => t / 1000, y = (v) => 100 - v;
  const run = toPoints([[0, 10], [60, 20]]);
  assert.equal(linePath(run, x, y), "M0,90L60,80");
  assert.equal(stepPath(run, x, y, 60e3), "M0,90H60L60,80H120");
});

test("the nearest sample", () => {
  const pts = toPoints([[0, 1], [60, 2], [120, 3]]);
  assert.equal(nearestIndex(pts, 0), 0);
  assert.equal(nearestIndex(pts, 50e3), 1);
  assert.equal(nearestIndex(pts, 1e9), 2);
  assert.equal(nearestIndex([], 5), -1);
});

test("time ticks fall on the house's round hours, also across the switch to winter time", () => {
  const start = Date.parse("2026-10-24T12:03:00Z"), end = start + 86400e3;
  const ticks = timeTicks(start, end, 6, "Europe/Berlin");
  assert.deepEqual(ticks.map((t) => new Date(t).toISOString()),
    ["2026-10-24T16:00:00.000Z", "2026-10-24T22:00:00.000Z", "2026-10-25T05:00:00.000Z", "2026-10-25T11:00:00.000Z"]);
  // 18:00 and 00:00 summer time, 06:00 and 12:00 winter time
  assert.equal(zoneOffsetMs(Date.parse("2026-10-24T16:00:00Z"), "Europe/Berlin"), 2 * 3600e3);
  assert.equal(zoneOffsetMs(Date.parse("2026-10-25T05:00:00Z"), "Europe/Berlin"), 3600e3);
  const week = timeTicks(start, start + 7 * 86400e3, 8, "Europe/Berlin");
  assert.equal(new Date(week[0]).toISOString(), "2026-10-24T22:00:00.000Z");   // midnight, 25 Oct
  assert.equal(new Date(week[1]).toISOString(), "2026-10-25T23:00:00.000Z");   // midnight, 26 Oct (25 h later)
  const month = timeTicks(start, start + 30 * 86400e3, 6, "Europe/Berlin");
  for (const t of month) assert.equal(new Date(t + 3600e3).getUTCDay(), 1);      // Mondays
  assert.deepEqual(timeTicks(end, start), []);
});

const at = (s) => new Date((T0 + s) * 1000).toISOString();
const ap = (name) => ({ name, house: null, floor: null, spot: null });

test("timeline: connections, a roam, a band change, a disconnect", () => {
  const start = T0 * 1000, end = (T0 + 10_000) * 1000;
  const events = [
    { kind: "connected", at: at(100), ap: ap("a"), band: "5", duration_s: 2900 },
    { kind: "roamed", at: at(1000), ap: ap("b"), band: "5", from_ap: ap("a"), from_band: "5", duration_s: 900 },
    { kind: "disconnected", at: at(3000), ap: ap("b"), band: "5", duration_s: 1000 },
    { kind: "connected", at: at(4000), ap: ap("b"), band: "5", duration_s: null },
    { kind: "band_changed", at: at(6000), ap: ap("b"), band: "2.4", from_ap: ap("b"), from_band: "5", duration_s: 2000 },
  ];
  const { spans, marks } = timelineSegments(events, start, end);
  assert.deepEqual(spans.map((s) => [(s.start / 1000) - T0, (s.end / 1000) - T0, s.ap.name, s.band, s.ongoing]), [
    [100, 1000, "a", "5", false],
    [1000, 3000, "b", "5", false],
    [4000, 6000, "b", "5", false],
    [6000, 10_000, "b", "2.4", true],
  ]);
  assert.deepEqual(marks.map((m) => m.kind), ["roamed", "disconnected", "band_changed"]);
});

test("timeline: a connection from before the range starts at its start; spans are clipped", () => {
  const start = T0 * 1000, end = (T0 + 1000) * 1000;
  const { spans } = timelineSegments([
    { kind: "connected", at: at(-5000), ap: ap("a"), band: "5", duration_s: 5500 },
    { kind: "connected", at: at(800), ap: ap("c"), band: "5", duration_s: 9999 },
  ], start, end);
  assert.deepEqual(spans.map((s) => [(s.start / 1000) - T0, (s.end / 1000) - T0, s.ap.name]), [[0, 500, "a"], [800, 1000, "c"]]);
  // only a roam in range: connected (on the old AP) since the start
  const roam = timelineSegments([{ kind: "roamed", at: at(400), ap: ap("b"), band: "5", from_ap: ap("a"), from_band: "5" }], start, end);
  assert.deepEqual(roam.spans.map((s) => [(s.start / 1000) - T0, (s.end / 1000) - T0, s.ap.name]), [[0, 400, "a"], [400, 1000, "b"]]);
  // only a disconnect: connected until then
  const gone = timelineSegments([{ kind: "disconnected", at: at(300), ap: ap("a"), band: "5", duration_s: 700 }], start, end);
  assert.deepEqual(gone.spans.map((s) => [(s.start / 1000) - T0, (s.end / 1000) - T0]), [[0, 300]]);
  assert.deepEqual(timelineSegments([], start, end), { spans: [], marks: [] });
});

test("access point colours follow the name, not the order of appearance", () => {
  const spans = ["b", "a", "b", "c"].map((name) => ({ ap: ap(name) }));
  const slots = apSlots(spans);
  assert.deepEqual([...slots.entries()], [["a", 0], ["b", 1], ["c", 2]]);
  const many = apSlots(Array.from({ length: AP_SLOTS + 2 }, (_, i) => ({ ap: ap(`ap-${i}`) })));
  assert.equal(many.get("ap-7"), "other");
  assert.equal(apSlots([{ ap: null }]).size, 0);
});
