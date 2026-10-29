// The data's ages from a body a 304 keeps (live.js withAges), against the Rust version: a copy of
// tests/js/ages.test.mjs whose server side is the Rust implementation (`cargo run --example
// js_oracle -p netportal-telemetry`, or the binary in NETPORTAL_JS_ORACLE) instead of python3.
// The ETag leaves the ages out, so with a frozen unpoller snapshot every poll answers 304 and the
// page must work out the Wi-Fi data's age itself (from house.wifi_data_at).
// node --test rust/tests/js/

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { createFormatter } from "../../../netportal/static/format.js";
import { createClient, createPoller, WIFI_AGE_BANNER_S, WIFI_STALE_S, withAges } from "../../../netportal/static/live.js";
import * as A from "../../../netportal/static/admin.js";
import * as R from "../../../netportal/static/render.js";
import { installDom } from "../../../tests/js/dom-shim.mjs";

installDom();
const rust = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const root = path.resolve(rust, "..");
const T0 = Date.parse("2026-10-25T16:00:00Z");
const at = (ms) => new Date(ms).toISOString();
const flush = () => new Promise((resolve) => setImmediate(resolve));

let server = null;
try {
  const oracle = process.env.NETPORTAL_JS_ORACLE;
  const out = oracle
    ? execFileSync(oracle, [], { encoding: "utf8" })
    : execFileSync("cargo", ["run", "-q", "-p", "netportal-telemetry", "--example", "js_oracle"], { cwd: rust, encoding: "utf8" });
  server = JSON.parse(out);
} catch {
  server = null;
}
const skip = !server && "the Rust oracle (cargo) is not available";

/** A /api/devices body of a frozen snapshot taken 250 s before T0. */
function body() {
  return {
    generated_at: at(T0), telemetry: "ok", stale: false, poll_s: 30,
    house: { internet: "ok", dns: "ok", router: "ok", speedtest: null, wifi_data_at: at(T0 - 250e3), wifi_data_age_s: 250 },
    devices: [
      { id: "a", name: "Laptop", state: "online", diagnostics: [] },
      { id: "b", name: "Phone", state: "unknown", diagnostics: [{ code: "stale_data", severity: "warn", basis: "measured",
        params: { age_s: 900 }, evidence: { age_s: 900, threshold_s: 600 } }] },
    ],
  };
}

test("the thresholds are the server's", { skip }, () => {
  assert.equal(WIFI_STALE_S, server.stale_after_s);
  // the Rust payloads' code tables the scripts know
  assert.deepEqual(server.tables.PRESENCE_STATES, ["online", "connecting", "offline", "unknown", "never_connected"]);
  const dash = readFileSync(path.join(root, "netportal/templates/_dash.html"), "utf8");
  assert.match(dash, new RegExp(`wifi_data_age_s > ${WIFI_AGE_BANNER_S} %}`));
});

test("every displayed age from its absolute time; the kept body stays as it is", () => {
  const b = body();
  const kept = structuredClone(b);
  const v = withAges(b, T0 + 100e3);
  assert.deepEqual(b, kept);                                           // pure
  assert.equal(v.house.wifi_data_age_s, 350);
  assert.equal(v.stale, false);
  assert.equal(v.devices[0], b.devices[0]);                            // untouched parts are the same objects
  assert.equal(v.devices[1].diagnostics[0].evidence.age_s, 350);
  assert.equal(v.devices[1].diagnostics[0].params.age_s, 350);
  assert.equal(v.devices[1].diagnostics[0].evidence.threshold_s, 600);
  assert.equal(withAges(b, T0 + 351e3).stale, true);                   // 601 s: as web.py's is_stale
  assert.equal(withAges({ ...b, telemetry: "unavailable" }, T0 + 900e3).stale, false);   // only with telemetry ok
  assert.equal(withAges(b, T0 - 900e3).house.wifi_data_age_s, 0);      // never negative
  // without the absolute time: as it came (an older portal)
  const old = { ...b, house: { ...b.house, wifi_data_at: null } };
  assert.equal(withAges(old, T0 + 900e3).house.wifi_data_age_s, 250);
  assert.equal(withAges(old, T0 + 900e3).devices[1].diagnostics[0].evidence.age_s, 900);
  assert.equal(withAges(null, T0), null);
});

test("the admin overview's freshness and job ages", () => {
  const ov = { telemetry: "ok", stale: false, house: { wifi_data_at: at(T0 - 30e3), wifi_data_age_s: 30 },
    freshness: { wifi_data_age_s: 30, prometheus: "ok", jobs_ok: true, oldest_job_success_age_s: 100 },
    jobs: [{ name: "unifi_events", last_success: at(T0 - 100e3), last_attempt: at(T0 - 100e3), ok: true, age_s: 100 },
      { name: "prune", last_success: null, last_attempt: null, ok: true, age_s: null }] };
  const v = withAges({ devices: [], overview: ov }, T0 + 300e3).overview;
  assert.equal(v.freshness.wifi_data_age_s, 330);
  assert.equal(v.freshness.oldest_job_success_age_s, 400);
  assert.deepEqual(v.jobs.map((j) => j.age_s), [400, null]);
  assert.equal(A.jobState(ov.jobs[0]), "ok");
  assert.equal(A.jobState(v.jobs[0]), "late");                         // 400 s > 3 × 120 s, without a new body
  assert.equal(v.stale, false);
});

test("a frozen snapshot answered with 304s: the banners appear and the ages advance", { skip }, async () => {
  const f = createFormatter("en", server.texts);
  let now = T0;
  const pending = new Map();
  let id = 0;
  const timers = { setTimeout(fn, ms) { pending.set(++id, { at: now + ms, fn }); return id; }, clearTimeout(h) { pending.delete(h); } };
  async function advance(ms) {
    const end = now + ms;
    for (;;) {
      const next = [...pending].filter(([, x]) => x.at <= end).sort((a, b) => a[1].at - b[1].at)[0];
      if (!next) break;
      pending.delete(next[0]);
      now = next[1].at;
      next[1].fn();
      await flush();
    }
    now = end;
    await flush();
  }
  let statuses = [];
  const client = createClient({ clock: () => now, timers,
    fetchFn: async () => {
      const first = !statuses.length;
      statuses.push(first ? 200 : 304);
      const h = { "content-type": "application/json", etag: '"frozen"' };
      return { status: first ? 200 : 304, ok: first, type: "basic", headers: { get: (k) => h[k.toLowerCase()] ?? null },
        json: async () => body() };
    } });
  const seen = [];
  const poller = createPoller({ timers, doc: { hidden: false, addEventListener() {} }, run: async () => {
    const r = await client.request("/api/devices", { conditional: true });
    const view = withAges(r.body, client.now());
    seen.push({ t: (now - T0) / 1000, fresh: r.fresh, banners: R.banners(view, f).textContent,
      finding: R.findings(view.devices[1], f, { full: true, telemetry: view.telemetry }).textContent });
    return 30e3;
  } });
  await poller.start(0);
  await advance(400e3);
  const t = server.texts;
  const at_ = (s) => seen.find((x) => x.t === s);
  assert.ok(statuses.slice(1).every((s) => s === 304) && statuses.length > 10, String(statuses));
  assert.equal(at_(30).fresh, false);
  assert.ok(!at_(30).banners.includes("old"), at_(30).banners);                         // 280 s: no banner yet
  assert.ok(at_(60).banners.includes(f.fill(t.house_wifi_age, { age: "5 min" })), at_(60).banners);   // 310 s
  assert.ok(at_(120).banners.includes(f.fill(t.house_wifi_age, { age: "6 min" })), at_(120).banners); // advances
  assert.ok(!at_(330).banners.includes(t.live_stale.split("{")[0]), at_(330).banners);   // 580 s
  assert.ok(at_(360).banners.includes(t.live_stale.split("{")[0]), at_(360).banners);    // 610 s: may be out of date
  assert.ok(at_(360).banners.includes(f.fill(t.house_wifi_age, { age: "10 min" })));
  assert.ok(at_(0).finding.includes("4 min"), at_(0).finding);                         // the finding's age: 250 s …
  assert.ok(at_(360).finding.includes("10 min"), at_(360).finding);                    // … 610 s, from the same body
  poller.stop();
});
