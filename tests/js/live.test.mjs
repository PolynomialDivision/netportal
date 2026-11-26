// static/live.js: conditional requests (ETag / If-None-Match, 304 keeps the body), the poll
// interval from poll_s, the backoff on errors, the pause while the tab is hidden and that there
// is only ever one timer and one request at a time. Fake timers, a fake fetch, a fake document.
// node --test tests/js/

import { test } from "node:test";
import assert from "node:assert/strict";
import { backoffMs, createClient, createPoller, HttpError, LoginEnded, POLL, pollMs } from "../../crates/netportal-web/static/live.js";

const flush = () => new Promise((resolve) => setImmediate(resolve));

/** setTimeout/clearTimeout on a clock of its own; `delays` records every timer asked for. */
function fakeTimers() {
  let now = 0, id = 0, maxPending = 0;
  const pending = new Map(), delays = [];
  return {
    setTimeout(fn, ms) {
      id += 1;
      pending.set(id, { at: now + ms, fn });
      delays.push(ms);
      maxPending = Math.max(maxPending, pending.size);
      return id;
    },
    clearTimeout(handle) { pending.delete(handle); },
    get pending() { return pending.size; },
    get maxPending() { return maxPending; },
    get now() { return now; },
    delays,
    /** Runs every timer due within `ms`, in order, letting promises settle after each. */
    async advance(ms) {
      const end = now + ms;
      for (;;) {
        let next = null;
        for (const [handle, timer] of pending) if (timer.at <= end && (!next || timer.at < next[1].at)) next = [handle, timer];
        if (!next) break;
        pending.delete(next[0]);
        now = next[1].at;
        next[1].fn();
        await flush();
      }
      now = end;
      await flush();
    },
  };
}

function fakeDoc() {
  const listeners = [];
  return {
    hidden: false,
    addEventListener(type, fn) { if (type === "visibilitychange") listeners.push(fn); },
    removeEventListener(type, fn) { const i = listeners.indexOf(fn); if (i >= 0) listeners.splice(i, 1); },
    show() { this.hidden = false; for (const fn of [...listeners]) fn(); },
    hide() { this.hidden = true; for (const fn of [...listeners]) fn(); },
    get listeners() { return listeners.length; },
  };
}

/** A Response as fetch gives it (headers by name, case-insensitive). */
function response(status, body = null, headers = {}) {
  const h = Object.fromEntries(Object.entries({ "Content-Type": body === null ? "text/plain" : "application/json", ...headers })
    .map(([k, v]) => [k.toLowerCase(), v]));
  return { status, ok: status >= 200 && status < 300, type: "basic", headers: { get: (k) => h[k.toLowerCase()] ?? null },
    json: async () => body };
}

test("poll_s sets the interval, within 5 s .. 5 min", () => {
  assert.equal(pollMs({ poll_s: 5 }), 5e3);
  assert.equal(pollMs({ poll_s: 30 }), 30e3);
  assert.equal(pollMs({ poll_s: 1 }), POLL.minMs);
  assert.equal(pollMs({ poll_s: 86400 }), POLL.maxMs);
  assert.equal(pollMs({}), POLL.defaultMs);
  assert.equal(pollMs(null), POLL.defaultMs);
  assert.equal(pollMs({ poll_s: "5" }), POLL.defaultMs);
  assert.equal(pollMs({ poll_s: -3 }), POLL.defaultMs);
  // without a top-level hint: the fastest device's
  assert.equal(pollMs({ devices: [{ presence: { poll_s: 30 } }, { presence: { poll_s: 5 } }, {}] }), 5e3);
  assert.equal(pollMs({ device: { presence: { poll_s: 5 } } }), 5e3);
  assert.equal(pollMs({ poll_s: 30, devices: [{ presence: { poll_s: 5 } }] }), 30e3);   // the payload's own wins
});

test("backoff doubles from 30 s to at most 5 min, with a little jitter", () => {
  const mid = () => 0.5;
  assert.deepEqual([1, 2, 3, 4, 5, 9].map((n) => backoffMs(n, { random: mid })), [30e3, 60e3, 120e3, 240e3, 300e3, 300e3]);
  assert.equal(backoffMs(1, { random: () => 0 }), 27e3);
  assert.equal(backoffMs(1, { random: () => 1 }), 33e3);
});

test("a conditional request sends the last ETag and a 304 hands back the kept body", async () => {
  const calls = [];
  const answers = [
    response(200, { n: 1 }, { ETag: '"v1"' }),
    response(304, null, { ETag: '"v1"' }),
    response(200, { n: 2 }, { ETag: '"v2"' }),
    response(200, { n: 3 }),                         // no ETag: nothing kept
    response(200, { n: 4 }, { ETag: '"v4"' }),
  ];
  const client = createClient({ fetchFn: async (url, options) => { calls.push({ url, options }); return answers.shift(); } });
  const a = await client.request("/api/devices", { conditional: true });
  assert.deepEqual([a.body, a.fresh], [{ n: 1 }, true]);
  assert.equal(calls[0].options.headers["If-None-Match"], undefined);
  assert.equal(calls[0].options.cache, "no-store");                 // the browser's cache stays out of it
  assert.equal(calls[0].options.credentials, "same-origin");
  const b = await client.request("/api/devices", { conditional: true });
  assert.equal(calls[1].options.headers["If-None-Match"], '"v1"');
  assert.equal(b.fresh, false);
  assert.equal(b.body, a.body);                                     // the same object: the page keeps its DOM
  const c = await client.request("/api/devices", { conditional: true });
  assert.equal(calls[2].options.headers["If-None-Match"], '"v1"');
  assert.deepEqual([c.body, c.fresh], [{ n: 2 }, true]);
  await client.request("/api/devices", { conditional: true });
  assert.equal(calls[3].options.headers["If-None-Match"], '"v2"');
  await client.request("/api/devices", { conditional: true });
  assert.equal(calls[4].options.headers["If-None-Match"], undefined);   // the answer without an ETag cleared it
});

test("plain requests never send an ETag; errors and an ended login", async () => {
  const answers = [response(200, { a: 1 }, { ETag: '"x"' }), response(200, { a: 2 }, { ETag: '"x"' }), response(401),
    { ...response(0), type: "opaqueredirect" }, response(500, { error: "boom" }), response(304)];
  const calls = [];
  const client = createClient({ fetchFn: async (url, options) => { calls.push(options); return answers.shift(); } });
  await client.json("/api/devices/1/history?range=24h");
  await client.json("/api/devices/1/history?range=24h");
  assert.equal(calls[1].headers["If-None-Match"], undefined);
  await assert.rejects(client.json("/api/devices"), LoginEnded);
  await assert.rejects(client.json("/api/devices"), LoginEnded);
  await assert.rejects(client.json("/api/devices"), (e) => e instanceof HttpError && e.status === 500 && e.body.error === "boom");
  await assert.rejects(client.request("/api/devices", { conditional: true }), (e) => e instanceof HttpError && e.status === 304);
});

test("the kept bodies are bounded (URLs with changing queries do not pile up)", async () => {
  let n = 0;
  const client = createClient({ maxEntries: 3, fetchFn: async () => response(200, { n: ++n }, { ETag: `"${n}"` }) });
  for (let i = 0; i < 10; i++) await client.request(`/api/admin/incidents?from=${i}`, { conditional: true });
  assert.equal(client.size, 3);
});

test("the portal's clock from the Date header when the device's is off", async () => {
  let local = Date.parse("2026-10-25T12:00:00Z");
  const client = createClient({ clock: () => local,
    fetchFn: async () => response(200, {}, { Date: "Sun, 25 Oct 2026 12:02:00 GMT" }) });
  await client.json("/api/devices");
  assert.ok(Math.abs(client.skewMs - 120.5e3) < 1e3, String(client.skewMs));
  assert.ok(Math.abs(client.now() - Date.parse("2026-10-25T12:02:00.5Z")) < 1e3);
  local = Date.parse("2026-10-25T12:01:58Z");                        // two seconds off: the device's own clock
  await client.json("/api/devices");
  assert.equal(client.skewMs, 0);
});

test("the next poll follows poll_s: 5 s while connecting, 30 s after", async () => {
  const timers = fakeTimers(), doc = fakeDoc();
  const hints = [5, 5, 30, 30];
  let runs = 0;
  const poller = createPoller({ timers, doc, random: () => 0.5, run: async () => { runs += 1; return pollMs({ poll_s: hints.shift() }); } });
  await poller.start(0);
  assert.equal(runs, 1);
  assert.deepEqual(timers.delays, [5e3]);
  await timers.advance(5e3);
  assert.equal(runs, 2);
  await timers.advance(5e3);
  assert.equal(runs, 3);
  assert.deepEqual(timers.delays, [5e3, 5e3, 30e3]);
  await timers.advance(29e3);
  assert.equal(runs, 3);
  await timers.advance(1e3);
  assert.equal(runs, 4);
  assert.equal(timers.maxPending, 1);
});

test("one timer chain: polls asked for at once share one request, never a second timer", async () => {
  const timers = fakeTimers(), doc = fakeDoc();
  let runs = 0, release;
  const poller = createPoller({ timers, doc, run: () => { runs += 1; return new Promise((resolve) => { release = () => resolve(30e3); }); } });
  poller.start(30e3);
  poller.start(30e3);                                                // a second start replaces the timer
  assert.equal(timers.pending, 1);
  const a = poller.poll(), b = poller.poll();
  doc.show();                                                        // visible again, the online event, pageshow …
  poller.poll();
  assert.equal(runs, 1);
  assert.equal(a, b);
  assert.equal(timers.pending, 0);                                   // no timer while the request runs
  release();
  await a;
  assert.equal(timers.pending, 1);
  assert.equal(timers.maxPending, 1);
  await timers.advance(30e3);
  assert.equal(runs, 2);
  release();
  await flush();
  assert.equal(timers.pending, 1);
});

test("hidden: no polls; shown again: a poll at once", async () => {
  const timers = fakeTimers(), doc = fakeDoc();
  let runs = 0;
  const poller = createPoller({ timers, doc, run: async () => { runs += 1; return 30e3; } });
  await poller.start(0);
  assert.equal(timers.pending, 1);
  doc.hide();
  assert.equal(timers.pending, 0);                                   // the timer is gone
  await timers.advance(10 * 60e3);
  assert.equal(runs, 1);
  await poller.poll();                                               // asked for while hidden: nothing
  assert.equal(runs, 1);
  doc.show();
  await flush();
  assert.equal(runs, 2);                                             // at once, not after 30 s
  assert.equal(timers.pending, 1);
  // hidden while a request runs: it finishes, but no next timer
  let release;
  const t2 = fakeTimers(), d2 = fakeDoc();
  const p2 = createPoller({ timers: t2, doc: d2, run: () => new Promise((r) => { release = () => r(30e3); }) });
  const pending = p2.poll();
  d2.hide();
  release();
  await pending;
  assert.equal(t2.pending, 0);
  p2.stop();
  assert.equal(d2.listeners, 0);                                     // stop() lets go of the document
});

test("errors back off, a success goes back to the hint", async () => {
  const timers = fakeTimers(), doc = fakeDoc();
  let fail = 5, runs = 0;
  const seen = [];
  const poller = createPoller({ timers, doc, random: () => 0.5,
    onError: (err, failures) => { seen.push(failures); },
    run: async () => { runs += 1; if (fail > 0) { fail -= 1; throw new Error("unreachable"); } return 5e3; } });
  await poller.start(0);
  for (const ms of [30e3, 60e3, 120e3, 240e3]) await timers.advance(ms);
  assert.equal(runs, 5);
  assert.deepEqual(seen, [1, 2, 3, 4, 5]);
  assert.deepEqual(timers.delays, [30e3, 60e3, 120e3, 240e3, 300e3]);
  await timers.advance(300e3);
  assert.equal(runs, 6);
  assert.equal(poller.failures, 0);
  assert.equal(timers.delays.at(-1), 5e3);
});

test("an ended login stops the polls; offline pauses them until asked", async () => {
  const timers = fakeTimers(), doc = fakeDoc();
  let runs = 0;
  const poller = createPoller({ timers, doc, onError: (err) => (err instanceof LoginEnded ? "stop" : "pause"),
    run: async () => { runs += 1; throw runs === 1 ? new Error("offline") : new LoginEnded(); } });
  await poller.start(0);
  assert.equal(timers.pending, 0);                                   // paused: no timer
  await timers.advance(60 * 60e3);
  assert.equal(runs, 1);
  await poller.poll();                                               // the online event
  assert.equal(runs, 2);
  assert.ok(poller.stopped);
  doc.show();
  await poller.poll();
  await timers.advance(60 * 60e3);
  assert.equal(runs, 2);
  assert.equal(timers.pending, 0);
});
