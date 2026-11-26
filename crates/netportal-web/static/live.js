// The live data's requests and their timing, without SSE or WebSockets (the portal runs one
// worker with eight threads: an open stream per page would hold a thread each).
//  - createClient: same-origin JSON requests; a conditional one sends the last ETag of its URL
//    as If-None-Match and a 304 hands back the body it stands for (the page keeps its DOM).
//  - createPoller: one timer chain only (one pending timer, never two requests at once), the
//    interval from the payload's poll_s (5 s while a device connects or just changed, else 30 s),
//    backoff on errors, paused while the tab is hidden and at once when it is shown again.
// No DOM of its own: the document, the timers, fetch and the clock come in from outside, so
// tests/js/live.test.mjs runs it under node.

export const POLL = { defaultMs: 30e3, minMs: 5e3, maxMs: 5 * 60e3, timeoutMs: 15e3 };

export class LoginEnded extends Error {}
export class Offline extends Error {}
export class HttpError extends Error {
  constructor(status) { super(`HTTP ${status}`); this.status = status; }
}

// The ages a page shows, from a body that a 304 may keep for long: the Wi-Fi data's age banner
// above WIFI_AGE_BANNER_S (templates/_dash.html banners), "may be out of date" above
// WIFI_STALE_S (diagnostics.STALE_AFTER_S), the stale_data finding's age, the admin overview's
// freshness and job ages. web.py's ETag leaves the ages out (they change with every request), so
// the page works them out itself from the absolute times beside them.
export const WIFI_AGE_BANNER_S = 300;
export const WIFI_STALE_S = 600;

const secondsSince = (iso, nowMs) => {
  const at = Date.parse(iso ?? "");
  return Number.isNaN(at) ? null : Math.max(0, Math.floor((nowMs - at) / 1000));
};

/** A house's wifi_data_age_s as of `nowMs`, from wifi_data_at (absolute); else as it came. */
function agedHouse(house, nowMs) {
  if (!house || typeof house !== "object") return house;
  const age = secondsSince(house.wifi_data_at, nowMs);
  return age === null ? house : { ...house, wifi_data_age_s: age };
}

/** A payload with every displayed age as of `nowMs` (the portal's clock): house.wifi_data_age_s,
 *  the `stale` flag (as web.py sets it: telemetry ok and the Wi-Fi data older than
 *  WIFI_STALE_S), the stale_data findings' age_s, and an admin overview's freshness and jobs.
 *  Pure: the kept body stays as it is; parts without their absolute time stay as they came. */
export function withAges(payload, nowMs) {
  if (!payload || typeof payload !== "object") return payload;
  const out = { ...payload };
  const house = agedHouse(payload.house, nowMs);
  const age = house && house !== payload.house ? house.wifi_data_age_s : null;
  if (house !== payload.house) {
    out.house = house;
    if (payload.telemetry === "ok") out.stale = age > WIFI_STALE_S;
  }
  const ageFinding = (d) => {
    if (age === null || !d || !Array.isArray(d.diagnostics) || !d.diagnostics.some((x) => x && x.code === "stale_data")) return d;
    return { ...d, diagnostics: d.diagnostics.map((x) => (x && x.code === "stale_data"
      ? { ...x, params: { ...(x.params || {}), age_s: age }, evidence: x.evidence ? { ...x.evidence, age_s: age } : x.evidence } : x)) };
  };
  if (Array.isArray(payload.devices)) out.devices = payload.devices.map(ageFinding);
  if (payload.device) out.device = ageFinding(payload.device);
  if (payload.overview && typeof payload.overview === "object") out.overview = withAges(payload.overview, nowMs);
  if (Array.isArray(payload.jobs)) {
    out.jobs = payload.jobs.map((j) => {
      const a = j ? secondsSince(j.last_success, nowMs) : null;
      return a === null ? j : { ...j, age_s: a };
    });
  }
  if (payload.freshness && typeof payload.freshness === "object") {
    const fr = { ...payload.freshness };
    if (age !== null) fr.wifi_data_age_s = age;
    if (out.jobs) {
      const ages = out.jobs.map((j) => j && j.age_s).filter((a) => typeof a === "number");
      if (ages.length) fr.oldest_job_success_age_s = Math.max(...ages);
    }
    out.freshness = fr;
  }
  return out;
}

/** The next poll from a payload: its top-level poll_s, else the smallest of its devices'
 *  presence.poll_s, within 5 s .. 5 min; without any the default. */
export function pollMs(payload, fallback = POLL.defaultMs) {
  const ok = (v) => typeof v === "number" && Number.isFinite(v) && v > 0;
  let s = payload && ok(payload.poll_s) ? payload.poll_s : null;
  if (s === null && payload) {
    const list = Array.isArray(payload.devices) ? payload.devices : payload.device ? [payload.device] : [];
    for (const d of list) {
      const v = d && d.presence ? d.presence.poll_s : null;
      if (ok(v)) s = s === null ? v : Math.min(s, v);
    }
  }
  if (s === null) return fallback;
  return Math.min(POLL.maxMs, Math.max(POLL.minMs, s * 1000));
}

/** After `failures` failed polls in a row: 30 s, 60 s, 2 min, 4 min, then 5 min, each ±10 %
 *  (pages that lost the portal together do not all come back in the same second). */
export function backoffMs(failures, { baseMs = POLL.defaultMs, maxMs = POLL.maxMs, random = Math.random } = {}) {
  const ms = Math.min(maxMs, baseMs * 2 ** Math.max(0, failures - 1));
  return Math.round(ms * (0.9 + 0.2 * random()));
}

/** JSON from the portal. An ended session answers 401, or (from an older portal) a redirect to
 *  the login, which is not followed: both throw LoginEnded. `now()` is the portal's clock (from
 *  the responses' Date header when the device's own clock is more than 5 s off). */
export function createClient({ fetchFn = (...args) => globalThis.fetch(...args), timeoutMs = POLL.timeoutMs,
  clock = () => Date.now(), timers = globalThis, maxEntries = 8 } = {}) {
  const cache = new Map();             // url -> {etag, body}, the newest last
  let skewMs = 0;

  function noteDate(header, sentAt) {
    const server = Date.parse(header || "");
    if (Number.isNaN(server)) return;
    const local = clock();
    // the Date header has whole seconds and was written somewhere between sending and now
    const off = server + 500 - (sentAt + local) / 2;
    skewMs = Math.abs(off) > 5e3 ? off : 0;
  }

  function remember(url, etag, body) {
    cache.delete(url);
    cache.set(url, { etag, body });
    while (cache.size > maxEntries) cache.delete(cache.keys().next().value);
  }

  /** {body, fresh}: fresh is false when the portal answered 304 (the body is the one kept). */
  async function request(url, { conditional = false, ...options } = {}) {
    const ctrl = typeof AbortController === "function" ? new AbortController() : null;
    const timer = ctrl ? timers.setTimeout(() => ctrl.abort(), timeoutMs) : null;
    const kept = conditional ? cache.get(url) : null;
    const headers = { Accept: "application/json", ...(options.headers || {}) };
    if (kept && kept.etag) headers["If-None-Match"] = kept.etag;
    const sentAt = clock();
    try {
      const res = await fetchFn(url, { credentials: "same-origin", redirect: "manual", cache: "no-store", ...options,
        headers, signal: ctrl ? ctrl.signal : undefined });
      if (res.type === "opaqueredirect" || res.status === 401) throw new LoginEnded();
      noteDate(res.headers.get("Date"), sentAt);
      if (res.status === 304) {
        if (!kept) throw new HttpError(304);
        remember(url, kept.etag, kept.body);
        return { body: kept.body, fresh: false };
      }
      const body = (res.headers.get("Content-Type") || "").includes("json") ? await res.json() : null;
      if (!res.ok) { const e = new HttpError(res.status); e.body = body; throw e; }
      if (conditional) {
        const etag = res.headers.get("ETag");
        if (etag) remember(url, etag, body); else cache.delete(url);
      }
      return { body, fresh: true };
    } finally {
      if (timer !== null) timers.clearTimeout(timer);
    }
  }

  return {
    request,
    json: async (url, options) => (await request(url, options)).body,
    now: () => clock() + skewMs,
    get skewMs() { return skewMs; },
    get size() { return cache.size; },
  };
}

/** The refresh loop. `run()` fetches and draws and returns the next interval (ms, e.g. from
 *  pollMs), or throws; `onError(err, failures)` says "stop" (the login ended), "pause" (offline:
 *  wait for poll() from the online event) or nothing (try again after the backoff). */
export function createPoller({ run, onError = () => undefined, timers = globalThis, doc = globalThis.document,
  initialMs = POLL.defaultMs, random = Math.random } = {}) {
  let timer = null, inFlight = null, failures = 0, stopped = false, paused = false, nextMs = initialMs;
  const hidden = () => Boolean(doc && doc.hidden);

  function clear() {
    if (timer !== null) { timers.clearTimeout(timer); timer = null; }
  }

  function schedule(ms = nextMs) {
    clear();
    if (stopped || paused || hidden()) return;
    timer = timers.setTimeout(() => { timer = null; poll(); }, ms);
  }

  /** Poll now (a request already on its way is the poll: no second one). */
  function poll() {
    if (inFlight) return inFlight;
    clear();
    if (stopped || hidden()) return Promise.resolve();
    paused = false;
    inFlight = (async () => {
      try {
        const ms = await run();
        failures = 0;
        nextMs = typeof ms === "number" && Number.isFinite(ms) && ms > 0 ? ms : initialMs;
      } catch (err) {
        failures += 1;
        nextMs = backoffMs(failures, { random });
        const verdict = onError(err, failures);
        if (verdict === "stop") stopped = true;
        else if (verdict === "pause") paused = true;
      } finally {
        inFlight = null;
      }
      schedule();
    })();
    return inFlight;
  }

  function onVisibility() {
    if (hidden()) clear();
    else poll();
  }
  if (doc && doc.addEventListener) doc.addEventListener("visibilitychange", onVisibility);

  return {
    /** The first poll after `ms` (0: now). */
    start(ms = nextMs) { if (ms <= 0) return poll(); schedule(ms); return Promise.resolve(); },
    poll,
    stop() { stopped = true; clear(); if (doc && doc.removeEventListener) doc.removeEventListener("visibilitychange", onVisibility); },
    get pending() { return timer !== null; },
    get busy() { return inFlight !== null; },
    get failures() { return failures; },
    get nextMs() { return nextMs; },
    get stopped() { return stopped; },
  };
}
