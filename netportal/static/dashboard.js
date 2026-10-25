// The "My devices" pages come alive: a refresh from the JSON API (live.js: conditional requests
// with the last ETag, every 30 seconds or every 5 while a device connects, backoff on errors,
// paused while the tab is hidden; relative times tick between requests), honest states
// (updating, offline, portal unreachable, stale data, login ended), the inline rename, the admin list's search, filters and sorting, the device page's
// charts (lines up to 90 days, day bars beyond) and merged connection timeline, the admin
// overview, the access point and incident pages, and a device's raw data on demand. Without
// this script every page is complete as the server sent it. No libraries, no inline code, no
// eval, same-origin requests only (the CSP allows nothing else).

import { createFormatter, toDate } from "./format.js";
import { createClient, createPoller, LoginEnded, Offline, POLL, pollMs, WIFI_AGE_BANNER_S, withAges } from "./live.js";
import { stateOf } from "./presence.js";
import * as R from "./render.js";
import * as A from "./admin.js";
import { apName, apSlots, availability, barChart, bytesPerDay, incidentLanes, laneChart, lineChart, summary, timelineChart,
  timelineSegments, toMs, toPoints } from "./charts.js";

const REFRESH_MS = POLL.defaultMs; // the live data, unless the payload's poll_s says otherwise
const TICK_MS = 5e3;              // relative times ("12 s ago") between two requests
const BUSY_AFTER_MS = 600;        // a request shows "updating" only when it takes this long
const OVERVIEW_EVERY_MS = 30e3;   // the admin overview: not every 5 s while a device connects
const HISTORY_EVERY_MS = 5 * 60e3; // the 24-hour charts follow along every 5 minutes
const RAW_MAX_MS = 31 * 86400e3;     // /api/admin/devices/<id>/raw answers at most 31 days
const RANGE_MS = { "24h": 86400e3, "7d": 7 * 86400e3, "30d": 30 * 86400e3, "90d": 90 * 86400e3, "1y": 365 * 86400e3 };
const STALE_AFTER_MS = 3 * REFRESH_MS;

function readJson(id) {
  const node = document.getElementById(id);
  if (!node) return null;
  try { return JSON.parse(node.textContent); } catch { return null; }
}

const client = createClient();
const requestJson = (url, options) => client.json(url, options);

function main() {
  const texts = readJson("np-texts"), config = readJson("np-config");
  if (!texts || !config) return;
  const f = createFormatter(config.lang || document.documentElement.lang || "en", texts);
  const t = f.t;
  const page = config.page;
  let data = readJson("np-data") || {};        // the body as the portal sent it (a 304 keeps it)
  let view = data;                               // the same with its ages as of now (live.js withAges)
  const age = () => { view = withAges(data, client.now()); return view; };
  const ctx = { ssid: config.ssid, now: client.now() };

  const announcer = document.querySelector("[data-announce]");
  const liveText = document.querySelector("[data-live-text]");
  const liveLine = document.querySelector("[data-part=live-line]");
  let lastAnnounced = "";
  function announce(text) {
    if (!announcer || !text || text === lastAnnounced) return;
    lastAnnounced = text;
    announcer.textContent = text;
  }

  // --- connection state and banners -------------------------------------------------------
  let problem = null;          // null | "offline" | "unreachable" | "login"
  let changed = false;         // the device list differs from the page's cards
  let busy = false;
  let lastOkAt = toDate(data.generated_at)?.getTime() || Date.now();

  function connectionBanners() {
    const out = [];
    if (problem === "login") {
      out.push(R.bannerNodes("bad", t("live_login"), " ", R.h("a", { href: location.pathname + location.search }, t("live_login_link"))));
    } else if (problem === "offline") {
      out.push(R.bannerNodes("warn", t("live_offline")));
    } else if (problem === "unreachable") {
      out.push(R.bannerNodes("warn", t("live_unreachable")));
    }
    if (problem && problem !== "login" && Date.now() - lastOkAt > STALE_AFTER_MS && !view.stale) {
      out.push(R.bannerNodes("warn", ...R.fillNodes(t("live_stale"), { when: R.timeEl(f, new Date(lastOkAt).toISOString(), "when") })));
    }
    if (changed) {
      out.push(R.bannerNodes("info", t("live_changed"), " ", R.h("a", { href: location.pathname + location.search }, t("live_reload"))));
    }
    return out;
  }

  function drawStatus() {
    const box = document.querySelector("[data-part=banners]");
    if (box) box.replaceWith(R.banners(view, f, connectionBanners()));
    if (liveText) {
      // the last answer (a 304 too: the data was checked then, it had not changed)
      const when = lastOkAt ? R.timeEl(f, new Date(lastOkAt).toISOString(), "when") : null;
      liveText.replaceChildren(...(busy ? [t("live_updating")]
        : when ? [...R.fillNodes(t("live_updated"), { when }), " · ", t("live_auto")] : [t("live_auto")]));
    }
    if (liveLine) liveLine.classList.toggle("busy", busy);
    const list = document.querySelector("[data-part=devices]");
    if (list) list.setAttribute("aria-busy", busy ? "true" : "false");
  }

  // --- drawing the devices ----------------------------------------------------------------
  const previous = new Map((data.devices || []).map((d) => [d.id, stateOf(d)]));

  function replacePart(root, part, node) {
    const old = root.querySelector(`[data-part="${part}"]`);
    if (old) old.replaceWith(node);
  }

  function drawCard(root, d, full, limit = 0) {
    const admin = page === "admin" || Boolean(config.admin);
    replacePart(root, "state", R.stateLine(d, f, ctx));
    if (admin) {
      const open = Boolean(root.querySelector("[data-part=presence] details")?.open);   // stays as the admin left it
      const box = R.presenceAdmin(d, f, ctx.now);
      if (open && box.querySelector("details")) box.querySelector("details").open = true;
      replacePart(root, "presence", box);
    }
    replacePart(root, "auth-alert", R.authAlert(d, f, ctx, admin));
    replacePart(root, "live", R.live(d, f));
    replacePart(root, "conn", R.howConnects(d, f, ctx, { full, admin }));
    drawDiag(root, d, full, limit);
    const box = root.querySelector("[data-name-box]");
    if (box && !box.querySelector("details").open) showName(box, d.name);
  }

  function drawDiag(root, d, full, limit = 0) {
    const admin = page === "admin" || Boolean(config.admin);
    replacePart(root, "diag", R.findings(d, f, { full, telemetry: view.telemetry, limit, admin }));
  }

  /** A device's card on this page and how it shows its findings: [root, full, limit]. */
  function cardOf(d) {
    if (page === "device") return d.id === config.device ? [document.querySelector(".dev-detail"), true, 0] : [null];
    const node = document.querySelector(`[data-device="${CSS.escape(d.id)}"]`);
    if (!node) return [null];
    return page === "admin" ? [node.querySelector(".adm-body"), false, 0] : [node, false, 2];
  }

  /** The name in the heading, the edit button's label and the (closed) form's field. */
  function showName(box, name) {
    box.querySelector("[data-name]").textContent = name;
    const label = box.querySelector("[data-name-label]");
    if (label) label.textContent = `${t("rename")}: ${name}`;
    const input = box.querySelector("input[name=name]");
    input.value = name;
    input.defaultValue = name;
  }

  function drawAdminRow(item, d) {
    const parts = R.summaryParts(d, f);
    for (const [part, node] of Object.entries(parts)) replacePart(item, part, node);
    drawCard(item.querySelector(".adm-body"), d, false);
    const state = stateOf(d);
    Object.assign(item.dataset, {
      name: (d.name || "").toLowerCase(), state, mac: d.mac || "",
      owner: `${d.owner?.display || ""} ${d.owner?.username || ""}`.toLowerCase(),
      codes: (d.diagnostics || []).map((x) => x.code).join(" "), problems: String(R.problemsOf(d).length),
      signal: d.signal_dbm ?? "", health: d.health ?? "", seen: ["online", "connecting"].includes(state) ? "~" : d.last_seen || "",
    });
  }

  function drawAll() {
    ctx.now = client.now();
    age();
    if (page === "aps") { drawAps(); drawStatus(); return; }
    if (page === "incidents") { drawIncidents(); drawStatus(); return; }
    if (page === "admin") drawOverview();
    const devices = view.devices || [];
    const onPage = [...document.querySelectorAll("[data-device]")].map((n) => n.dataset.device);
    const ids = devices.map((d) => d.id);
    if (page === "device") {
      const d = devices.find((x) => x.id === config.device);
      const card = document.querySelector(".dev-detail");
      if (d && card) drawCard(card, d, true);
    } else {
      changed = ids.length !== onPage.length || ids.some((id) => !onPage.includes(id));
      for (const d of devices) {
        const node = document.querySelector(`[data-device="${CSS.escape(d.id)}"]`);
        if (!node) continue;
        if (page === "admin") drawAdminRow(node, d); else drawCard(node, d, false, 2);
      }
      if (page === "admin") applyFilters();
    }
    if (view.house && document.querySelector("[data-part=house]")) {
      const strip = R.houseStrip(view.house, f);
      strip.hidden = view.telemetry !== "ok";
      replacePart(document, "house", strip);
    }
    let moved = false;
    for (const d of devices) {
      const state = stateOf(d);
      if (previous.has(d.id) && previous.get(d.id) !== state) {
        announce(f.fill(t("announce_state"), { name: d.name, state: t(`state_${state}`) }));
        moved = true;
      }
      previous.set(d.id, state);
    }
    drawStatus();
    return moved;
  }

  // --- the refresh (live.js: one timer chain, conditional requests) -----------------------
  let busyTimer = 0, overview = { at: 0, body: data.overview || null };

  /** This page's fresh data and whether any of it changed (false: every part answered 304).
   *  The device page asks for its one device (an admin's view of someone else's too), the admin
   *  overview for its devices and, at most every 30 seconds, the overview. */
  async function fetchPage() {
    if (page === "device") {
      const r = await client.request(`/api/devices/${encodeURIComponent(config.device)}`, { conditional: true });
      return { fresh: r.fresh, data: { ...r.body, devices: r.body && r.body.device ? [r.body.device] : [] } };
    }
    if (page === "admin" && config.overview) {
      const due = Date.now() - overview.at >= OVERVIEW_EVERY_MS || !overview.body;
      const [devices, ov] = await Promise.all([client.request(config.api, { conditional: true }),
        due ? client.request(config.overview, { conditional: true }) : Promise.resolve({ body: overview.body, fresh: false })]);
      if (due) overview = { at: Date.now(), body: ov.body };
      return { fresh: devices.fresh || ov.fresh, data: { ...devices.body, overview: ov.body } };
    }
    if (page === "incidents") {
      const to = new Date(), from = new Date(to.getTime() - (RANGE_MS[config.range] || RANGE_MS["7d"]));
      const params = new URLSearchParams({ range: config.range || "7d", from: from.toISOString(), to: to.toISOString() });
      if (config.kind) params.set("kind", config.kind);
      return { fresh: true, data: await requestJson(`${config.api}?${params}`) };
    }
    return client.request(config.api, { conditional: true }).then((r) => ({ fresh: r.fresh, data: r.body }));
  }

  /** One poll: fetch, draw what changed (a 304 keeps the DOM, only the relative times move),
   *  and the next interval from the payload's poll_s. */
  async function run() {
    if (navigator.onLine === false) throw new Offline();
    clearTimeout(busyTimer);
    busyTimer = setTimeout(() => { busy = true; drawStatus(); }, BUSY_AFTER_MS);
    let result;
    try {
      result = await fetchPage();
    } finally {
      clearTimeout(busyTimer);
      busy = false;
    }
    lastOkAt = Date.now();
    const recovered = problem !== null;
    problem = null;
    let moved = false;
    if (result.fresh || recovered) {
      if (result.fresh) data = result.data;
      moved = drawAll();
    } else {
      tick();                                     // the ages may have moved on: redrawn as needed
      drawStatus();
    }
    // the timeline follows along: every 5 minutes, and at once when the state changed (it shows
    // the connection that made the device online)
    if (page === "device" && hist.range === "24h" && (moved || Date.now() - hist.loadedAt > HISTORY_EVERY_MS)) {
      loadHistory(hist.range, { quiet: true });
    }
    return pollMs(data, REFRESH_MS);
  }

  function failed(err) {
    problem = err instanceof LoginEnded ? "login" : err instanceof Offline || navigator.onLine === false ? "offline" : "unreachable";
    announce(problem === "login" ? t("live_login") : problem === "offline" ? t("live_offline") : t("live_unreachable"));
    tick();
    drawStatus();
    return problem === "login" ? "stop" : problem === "offline" ? "pause" : undefined;
  }

  const poller = createPoller({ run, onError: failed, initialMs: pollMs(data, REFRESH_MS) });

  /** What the ages show (a part is redrawn only when its text would change). */
  function ageKeys(v) {
    const wifi = v.house ? v.house.wifi_data_age_s : null;
    const fr = v.overview && v.overview.freshness;
    const diag = new Map((v.devices || []).map((d) => [d.id, JSON.stringify((d.diagnostics || [])
      .filter((x) => x && x.code === "stale_data").map((x) => f.duration((x.evidence || x.params || {}).age_s)))]));
    return {
      status: JSON.stringify([Boolean(v.stale), typeof wifi === "number" && wifi > WIFI_AGE_BANNER_S ? f.duration(wifi) : null]),
      fresh: fr ? JSON.stringify([f.duration(fr.wifi_data_age_s), f.duration(fr.oldest_job_success_age_s),
        (v.overview.jobs || []).map(A.jobState)]) : "",
      diag,
    };
  }

  /** The relative times ("12 s ago", "for 2 h 5 min") and the data's ages ("The Wi-Fi system's
   *  data is 6 min old", a stale_data finding, the overview's freshness) as of now, without a
   *  request: a body a 304 keeps does not freeze them. */
  function tick() {
    if (document.hidden) return;
    const before = ageKeys(view);
    age();
    const after = ageKeys(view);
    ctx.now = client.now();
    if (after.status !== before.status) drawStatus();
    if (after.fresh !== before.fresh && page === "admin" && view.overview) {
      const ov = view.overview;
      replacePart(document, "ov-fresh", A.freshness(ov.freshness, ov.jobs, f, ov.jobs_available));
    }
    for (const d of view.devices || []) {
      if (after.diag.get(d.id) === before.diag.get(d.id)) continue;
      const [root, full, limit] = cardOf(d);
      if (root) drawDiag(root, d, full, limit);
    }
    R.tickTimes(document, f, client.now());
  }
  setInterval(tick, TICK_MS);
  document.addEventListener("visibilitychange", tick);

  window.addEventListener("online", () => poller.poll());
  window.addEventListener("offline", () => { problem = "offline"; drawStatus(); announce(t("live_offline")); });

  // --- inline rename ----------------------------------------------------------------------
  const csrf = document.querySelector('meta[name="csrf"]')?.content || "";
  for (const box of document.querySelectorAll("[data-name-box]")) {
    const details = box.querySelector("details");
    const summary = details.querySelector("summary");
    const form = box.querySelector("form[data-rename]");
    const input = form.elements.namedItem("name");
    const status = box.querySelector("[data-rename-status]");
    const save = form.querySelector("button:not([type=button])");
    const say = (text, tone) => {
      status.textContent = text;
      status.className = `rename-status${tone ? ` tone-text-${tone}` : ""}`;
    };
    // editing: the heading becomes the field (Enter saves, Esc or Cancel goes back)
    details.addEventListener("toggle", () => {
      box.classList.toggle("editing", details.open);
      if (details.open) {
        say("");
        input.focus();
        input.select();
      }
    });
    const close = (focus = true) => {
      input.value = input.defaultValue;
      details.open = false;
      box.classList.remove("editing");          // now, not at the toggle event: the button must be focusable
      if (focus) summary.focus();
    };
    form.querySelector("[data-cancel]").addEventListener("click", () => close());
    input.addEventListener("keydown", (e) => {
      if (e.key === "Escape") { e.preventDefault(); close(); }
    });
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const name = input.value.trim();
      if (!name || name === input.defaultValue) { close(); return; }
      save.disabled = true;
      form.setAttribute("aria-busy", "true");
      try {
        const body = new URLSearchParams({ csrf, name });
        const res = await requestJson(form.action, { method: "POST", body,
          headers: { "Content-Type": "application/x-www-form-urlencoded" } });
        const saved = res && res.name ? res.name : name;
        showName(box, saved);
        close();
        say(t("saved"), "ok");
        const id = box.closest("[data-device]")?.dataset.device;
        for (const d of [...(data.devices || []), ...(view.devices || [])]) if (d.id === id) d.name = saved;
        setTimeout(() => { if (status.textContent === t("saved")) say(""); }, 4000);
      } catch (err) {
        // the field stays open with what was typed: nothing is lost
        if (err instanceof LoginEnded) { problem = "login"; poller.stop(); drawStatus(); say(t("live_login"), "bad"); }
        else say(t("save_failed"), "bad");
        input.focus();
      } finally {
        save.disabled = false;
        form.removeAttribute("aria-busy");
      }
    });
  }

  // --- the admin list: search, filters, sorting -----------------------------------------
  const filters = document.querySelector("form[data-filters]");
  const STATE_ORDER = { offline: 0, never_connected: 1, unknown: 2, connecting: 3, online: 4 };
  function applyFilters() {
    if (!filters) return;
    const q = (filters.elements.namedItem("q").value || "").trim().toLowerCase();
    const qMac = q.replaceAll("-", ":");
    const state = filters.elements.namedItem("state").value;
    const problemWanted = filters.elements.namedItem("problem").value;
    const sort = filters.elements.namedItem("sort").value;
    const list = document.querySelector(".adm-list");
    const items = [...list.querySelectorAll(".adm-item")];
    let shown = 0;
    for (const item of items) {
      const ds = item.dataset;
      const hay = `${ds.name} ${ds.owner} ${ds.mac}`;
      const codes = (ds.codes || "").split(" ");
      const problems = Number(ds.problems || 0);
      const match = (!q || hay.includes(q) || hay.includes(qMac)) && (!state || ds.state === state)
        && (!problemWanted || (problemWanted === "with" && problems > 0) || (problemWanted === "without" && problems === 0)
          || codes.includes(problemWanted));
      item.hidden = !match;
      if (match) shown += 1;
    }
    const num = (v) => (v === "" || v === undefined ? 999 : Number(v));
    const key = {
      name: (ds) => ds.name, owner: (ds) => ds.owner.trim(), state: (ds) => STATE_ORDER[ds.state] ?? 2,
      signal: (ds) => num(ds.signal), health: (ds) => num(ds.health), seen: (ds) => ds.seen || "",
    }[sort] || ((ds) => ds.name);
    const sorted = [...items].sort((a, b) => {
      const ka = key(a.dataset), kb = key(b.dataset);
      const order = ka < kb ? -1 : ka > kb ? 1 : a.dataset.name.localeCompare(b.dataset.name);
      return sort === "seen" ? -order : order;
    });
    if (sorted.some((item, i) => item !== items[i])) list.append(...sorted);
    const count = document.querySelector("[data-shown]");
    if (count) count.textContent = f.fill(t("adm_shown"), { shown, total: items.length });
    const none = document.querySelector("[data-none]");
    if (none) none.hidden = shown > 0;
    // the address follows the filters (a reload or a shared link shows the same list)
    const params = new URLSearchParams();
    for (const name of ["q", "state", "problem", "sort"]) {
      const v = filters.elements.namedItem(name).value;
      if (v && !(name === "sort" && v === "name")) params.set(name, v);
    }
    const url = location.pathname + (params.toString() ? `?${params}` : "");
    if (url !== location.pathname + location.search) window.history.replaceState(null, "", url);
  }
    if (filters) {
    filters.classList.add("live");
    filters.querySelector("[data-apply]")?.setAttribute("hidden", "");
    filters.addEventListener("input", applyFilters);
    filters.addEventListener("change", applyFilters);
    filters.addEventListener("submit", (e) => { e.preventDefault(); applyFilters(); });
  }

  // --- the device page: history charts and timeline ----------------------------------------
  const hist = { range: config.range || "24h", loadedAt: 0, charts: [], request: 0, timeline: [], truncated: false, filter: "all" };
  const historyBox = document.querySelector("[data-history]");
  const admin = page !== "device" || Boolean(config.admin);
  for (const chip of document.querySelectorAll("[data-tl-filter] [data-filter]")) {
    chip.addEventListener("click", () => {
      hist.filter = chip.dataset.filter;
      for (const c of document.querySelectorAll("[data-tl-filter] [data-filter]")) c.setAttribute("aria-pressed", String(c === chip));
      drawEvents();
    });
  }

  const isDays = (payload) => payload.step === "day" || (payload.step_s >= 86400 && ["1y", "all"].includes(payload.range));

  function chartSpecs(payload) {
    if (isDays(payload)) return daySpecs(payload);
    const s = payload.series || {};
    const start = toMs(payload.start), end = toMs(payload.end), stepMs = (payload.step_s || 300) * 1000;
    const span = (end - start) / 1000;
    const base = { start, end, stepMs, axisTime: (ms) => f.axisTime(new Date(ms), span), tipTime: (ms) => f.when(new Date(ms)) };
    const signal = toPoints(s.signal_dbm), health = toPoints(s.health);
    const sMin = Math.min(-90, ...signal.filter((p) => p.v !== null).map((p) => Math.floor(p.v / 10) * 10));
    const range = (fmt) => (x) => x && f.fill(t("ch_summary"), { min: fmt(x.min), avg: fmt(x.avg), max: fmt(x.max) });
    return {
      signal: { ...base, kind: "line", series: [{ label: t("ch_signal"), points: signal, cls: "series-1" }],
        y: { min: sMin, max: -30, ticks: signalTicks(sMin) }, bands: [{ from: -67, to: -30, cls: "band-good", label: t("band_good") },
          { from: -200, to: -75, cls: "band-weak", label: t("band_weak") }],
        value: (v) => f.dbm(v), axisValue: (v) => f.number(v), sum: range(f.dbm) },
      quality: { ...base, kind: "line", series: [{ label: t("ch_quality"), points: health, cls: "series-1" }],
        y: { min: 0, max: 100, ticks: [0, 50, 100] }, bands: [{ from: 80, to: 100, cls: "band-good", label: t("q_good") }, { from: 0, to: 50, cls: "band-weak", label: t("q_poor") }],
        value: (v) => f.fill(t("quality_fmt"), { n: Math.round(v) }), axisValue: (v) => f.number(v), sum: range(f.number) },
      traffic: { ...base, kind: "area", legend: true, series: [{ label: t("dir_down"), points: toPoints(s.rx_bps), cls: "series-1" },
        { label: t("dir_up"), points: toPoints(s.tx_bps), cls: "series-2" }],
      value: (v) => f.bitrate(v), axisValue: (v) => compactRate(v), axisWidth: 64, sum: range(f.bitrate) },
      link: { ...base, kind: "line", legend: true, series: [{ label: t("dir_down"), points: toPoints(s.link_rx_bps), cls: "series-1" },
        { label: t("dir_up"), points: toPoints(s.link_tx_bps), cls: "series-2" }],
      value: (v) => f.bitrate(v), axisValue: (v) => compactRate(v), axisWidth: 64, sum: range(f.bitrate) },
      online: { ...base, kind: "step-area", height: 96, axisWidth: 12, series: [{ label: t("ch_online"), points: toPoints(s.online), cls: "series-ok" }],
        y: { min: 0, max: 1, ticks: [0, 1] }, value: (v) => t(v > 0 ? "state_online" : "state_offline"), axisValue: () => "",
        sum: (_x, points) => { const a = availability(points); return a === null ? null : f.fill(t("online_pct"), { pct: f.percent(a) }); } },
      retries: s.retry_ratio ? { ...base, kind: "line", series: [{ label: t("ch_retries"), points: toPoints(s.retry_ratio), cls: "series-1" }],
        y: { min: 0, max: Math.max(0.3, ...toPoints(s.retry_ratio).filter((p) => p.v !== null).map((p) => Math.ceil(p.v * 10) / 10)) },
        bands: [{ from: 0.1, to: 1, cls: "band-weak", label: "" }],
        value: (v) => f.percent(v, 1), axisValue: (v) => f.percent(v), sum: range((v) => f.percent(v, 1)) } : null,
      snr: s.snr_db ? { ...base, kind: "line", series: [{ label: t("ch_snr"), points: toPoints(s.snr_db), cls: "series-1" }],
        zeroBased: true, bands: [{ from: 25, to: 200, cls: "band-good", label: t("band_good") }, { from: -100, to: 15, cls: "band-weak", label: t("band_weak") }],
        value: (v) => f.db(v), axisValue: (v) => f.number(v), sum: range(f.db) } : null,
    };
  }

  /** The same charts from the daily rollups: one bar per day. */
  function daySpecs(payload) {
    const s = payload.series || {};
    const start = toMs(payload.start), end = toMs(payload.end), stepMs = 86400e3;
    const span = (end - start) / 1000;
    const base = { bar: true, start, end, stepMs, axisTime: (ms) => f.axisTime(new Date(ms), span), tipTime: (ms) => f.day(new Date(ms)) };
    const avg = (points) => { const x = summary(points); return x ? x.avg : null; };
    const signal = toPoints(s.signal_dbm);
    const sMin = Math.min(-90, ...signal.filter((p) => p.v !== null).map((p) => Math.floor(p.v / 10) * 10));
    const range = (fmt) => (x) => x && f.fill(t("ch_summary"), { min: fmt(x.min), avg: fmt(x.avg), max: fmt(x.max) });
    const rx = bytesPerDay(toPoints(s.rx_bps)), tx = bytesPerDay(toPoints(s.tx_bps));
    return {
      signal: { ...base, series: [{ label: t("ch_average"), points: signal, cls: "series-1" }], baseline: "min",
        marks: s.signal_p10_dbm ? { label: t("ch_weakest"), points: toPoints(s.signal_p10_dbm) } : null,
        y: { min: sMin, max: -30, ticks: signalTicks(sMin) }, value: (v) => f.dbm(v), axisValue: (v) => f.number(v), sum: range(f.dbm) },
      quality: { ...base, series: [{ label: t("ch_quality"), points: toPoints(s.health), cls: "series-1" }],
        y: { min: 0, max: 100, ticks: [0, 50, 100] }, value: (v) => f.fill(t("quality_fmt"), { n: Math.round(v) }),
        axisValue: (v) => f.number(v), sum: range(f.number) },
      traffic: { ...base, legend: true, series: [{ label: t("dir_down"), points: rx, cls: "series-1" }, { label: t("dir_up"), points: tx, cls: "series-2" }],
        value: (v) => f.bytes(v), axisValue: (v) => compactBytes(v), axisWidth: 64,
        sumAll: () => {
          const days = rx.map((p, i) => ({ t: p.t, v: (p.v ?? 0) + (tx[i]?.v ?? 0), known: p.v !== null || tx[i]?.v !== null }))
            .filter((p) => p.known);
          if (!days.length) return null;
          const top = days.reduce((a, b) => (b.v > a.v ? b : a));
          return f.fill(t("ch_traffic_day_summary"), { total: f.bytes(days.reduce((n, p) => n + p.v, 0)), day: f.day(new Date(top.t)), max: f.bytes(top.v) });
        } },
      link: { ...base, series: [{ label: t("dir_down"), points: toPoints(s.link_rx_bps), cls: "series-1" }],
        value: (v) => f.bitrate(v), axisValue: (v) => compactRate(v), axisWidth: 64, sum: range(f.bitrate) },
      online: { ...base, height: 120, series: [{ label: t("ch_online"), points: toPoints(s.online), cls: "series-ok" }],
        y: { min: 0, max: 1, ticks: [0, 0.5, 1] }, value: (v) => f.percent(v), axisValue: (v) => f.percent(v), axisWidth: 44,
        sum: (_x, points) => { const a = avg(points); return a === null ? null : f.fill(t("ch_online_day_summary"), { pct: f.percent(a) }); } },
      retries: s.retry_ratio ? { ...base, series: [{ label: t("ch_retries"), points: toPoints(s.retry_ratio), cls: "series-1" }],
        value: (v) => f.percent(v, 1), axisValue: (v) => f.percent(v), sum: range((v) => f.percent(v, 1)) } : null,
      snr: s.snr_db ? { ...base, series: [{ label: t("ch_snr"), points: toPoints(s.snr_db), cls: "series-1" }],
        value: (v) => f.db(v), axisValue: (v) => f.number(v), sum: range(f.db) } : null,
    };
  }

  // every 20 dB from the top (-30) down to the lowest value's decade
  function signalTicks(min) {
    const ticks = [];
    for (let v = -30; v >= min; v -= 20) ticks.unshift(v);
    return ticks;
  }

  function compactBytes(v) {
    if (!v) return "0";
    for (const [size, unit] of [[1e12, "T"], [1e9, "G"], [1e6, "M"], [1e3, "k"]]) {
      if (Math.abs(v) >= size) return `${f.number(v / size, v / size < 10 && v % size ? 1 : 0)} ${unit}`;
    }
    return f.number(v);
  }

  // Axis labels stay short: "120 M", "1,5 G" (the unit is in the tooltip and the summary).
  function compactRate(v) {
    if (!v) return "0";
    const units = [[1e9, "G"], [1e6, "M"], [1e3, "k"]];
    for (const [size, unit] of units) if (Math.abs(v) >= size) return `${f.number(v / size, v / size < 10 && v % size ? 1 : 0)} ${unit}`;
    return f.number(v);
  }

  function drawCharts(payload) {
    for (const chart of hist.charts) chart.destroy();
    hist.charts = [];
    const specs = chartSpecs(payload);
    const days = isDays(payload);
    let any = false;
    const note = document.querySelector("[data-days-note]");
    if (note) note.hidden = !days;
    for (const fig of document.querySelectorAll("[data-chart]")) {
      const key = fig.dataset.chart;
      const spec = specs[key];
      const host = fig.querySelector("[data-host]");
      const sumNode = fig.querySelector("[data-summary]");
      const legend = fig.querySelector("[data-legend]");
      const sub = fig.querySelector("[data-sub]");
      if (sub) { const dayText = t(`ch_${key}_sub_day`); sub.textContent = days && dayText !== `ch_${key}_sub_day` ? dayText : t(`ch_${key}_sub`); }
      if ("optional" in fig.dataset) fig.hidden = !spec;
      if (!spec || !host) continue;
      const all = spec.series.flatMap((s) => s.points);
      const sum = summary(all);
      if (!sum) {
        host.replaceChildren(R.h("p", { class: "chart-empty" }, t("ch_nodata")));
        host.removeAttribute("tabindex");
        if (sumNode) sumNode.textContent = "";
        if (legend) legend.hidden = true;
        continue;
      }
      any = true;
      const sumText = spec.sumAll ? spec.sumAll() || ""
        : spec.series.length > 1
          ? spec.series.map((x) => { const one = summary(x.points); return one ? `${x.label}: ${spec.sum(one, x.points)}` : null; })
            .filter(Boolean).join(". ")
          : spec.sum(sum, all) || "";
      if (sumNode) sumNode.textContent = sumText;
      if (legend) {
        legend.hidden = !spec.legend;
        legend.replaceChildren(...spec.series.map((s) => R.h("li", {}, R.h("i", { class: `chart-key ${s.cls}` }), s.label)));
      }
      const caption = fig.querySelector("h3")?.textContent || "";
      hist.charts.push((spec.bar ? barChart : lineChart)(host, { ...spec, label: `${caption}. ${sumText}`, noValue: "–" }));
    }
    const hint = document.querySelector("[data-chart-hint]");
    if (hint) hint.hidden = !any;
  }

  function drawTimeline(payload) {
    const host = document.querySelector("[data-timeline]");
    const legend = document.querySelector("[data-timeline-legend]");
    const info = document.querySelector("[data-timeline-info]");
    const events = document.querySelector("[data-events]");
    const start = toMs(payload.start), end = toMs(payload.end);
    const { spans, marks } = timelineSegments(payload.timeline || [], start, end);
    const slots = apSlots(spans);
    const span = (end - start) / 1000;
    const apOf = (ap) => (ap && typeof ap === "object" ? ap : ap ? { name: ap } : null);
    const range = (a, b) => `${f.when(new Date(a))} – ${f.when(new Date(b))}`;
    if (info) info.textContent = "";
    if (host) {
      host.replaceChildren();
      hist.charts.push(timelineChart(host, {
        spans, marks, start, end, slots,
        label: `${t("tl_title")}: ${spans.length ? spans.map((s) => f.room(apOf(s.ap))).filter((v, i, a) => a.indexOf(v) === i).join(", ") : t("tl_none")}`,
        axisTime: (ms) => f.axisTime(new Date(ms), span),
        spanLabel: (s) => `${f.fill(t("tl_connected"), { where: f.room(apOf(s.ap)) + (s.band ? ` (${f.bandName(s.band)})` : "") })} · ${range(s.start, s.end)}`
          + ` (${s.ongoing ? t("tl_ongoing") : f.duration((s.end - s.start) / 1000)})${s.basis === "inferred" ? ` · ${t("basis_inferred")}` : ""}`,
        markLabel: (m) => `${f.when(new Date(m.t))} · ${R.eventPlain(m, f, admin)}${m.basis === "inferred" ? ` (${t("basis_inferred")})` : ""}`,
        onSelect: (text) => { if (info) info.textContent = text; },
      }));
    }
    if (legend) {
      const names = [...slots.keys()];
      legend.replaceChildren(...names.map((name) => {
        const slot = slots.get(name);
        const ap = apOf(spans.find((s) => apName(s.ap) === name)?.ap);
        return R.h("li", {}, R.h("i", { class: `chart-key ap-${slot}` }), f.room(ap));
      }));
      legend.hidden = !names.length;
    }
    hist.timeline = payload.timeline || [];
    hist.truncated = Boolean(payload.timeline_truncated);
    drawEvents();
  }

  /** The event list below the timeline, as the filter chips say. */
  function drawEvents() {
    const events = document.querySelector("[data-events]");
    if (!events) return;
    events.replaceChildren(...R.eventList(R.filterEvents(hist.timeline, hist.filter), f, Date.now(), 50, admin));
    if (hist.truncated) events.appendChild(R.h("li", { class: "ev ev-more muted" }, t("tl_more")));
  }

  async function loadHistory(range, { quiet = false } = {}) {
    if (!historyBox || !config.history) return;
    const ticket = ++hist.request;
    hist.range = range;
    const status = historyBox.querySelector("[data-history-status]");
    historyBox.dataset.range = range;
    for (const a of historyBox.querySelectorAll("[data-range]")) {
      if (a.dataset.range === range) a.setAttribute("aria-current", "true"); else a.removeAttribute("aria-current");
    }
    if (!quiet) {
      historyBox.setAttribute("aria-busy", "true");
      if (status) status.replaceChildren(R.h("span", { class: "loading" }, t("ch_loading")));
    }
    try {
      const payload = await requestJson(`${config.history}?range=${encodeURIComponent(range)}`);
      if (ticket !== hist.request) return;              // a newer range was asked for meanwhile
      hist.loadedAt = Date.now();
      drawCharts(payload);
      drawTimeline(payload);
      if (raw.loaded && !quiet) loadRaw();
      if (status) {
        const note = payload.telemetry === "off" ? t("telemetry_off") : payload.telemetry === "unavailable" ? t("telemetry_unavailable") : "";
        status.replaceChildren(...(note ? [R.icon("info"), note] : []));
        status.classList.toggle("tone-warn", Boolean(note));
      }
    } catch (err) {
      if (ticket !== hist.request) return;
      if (err instanceof LoginEnded) { problem = "login"; poller.stop(); drawStatus(); }
      if (status) {
        const retry = R.h("button", { type: "button", class: "pill" }, t("retry"));
        retry.addEventListener("click", () => loadHistory(hist.range));
        status.replaceChildren(R.icon("warn"), err instanceof LoginEnded ? t("live_login") : t("ch_error"), " ", retry);
        status.classList.add("tone-warn");
      }
    } finally {
      if (ticket === hist.request) historyBox.removeAttribute("aria-busy");
    }
  }

  if (historyBox) {
    for (const a of historyBox.querySelectorAll("nav [data-range]")) {
      a.addEventListener("click", (e) => {
        e.preventDefault();
        const params = new URLSearchParams(location.search);
        params.set("range", a.dataset.range);
        window.history.replaceState(null, "", `${location.pathname}?${params}`);
        loadHistory(a.dataset.range);
      });
    }
    const inline = data.history;
    if (inline && inline.range === hist.range && inline.series) {
      hist.loadedAt = Date.now();
      drawCharts(inline);
      drawTimeline(inline);
    } else {
      loadHistory(hist.range);
    }
  }

  // --- the deep view's raw data ------------------------------------------------------------
  const rawBox = document.querySelector("[data-raw]");
  const raw = { loaded: Boolean(data.raw), request: 0, tab: "auth" };

  function selectTab(part, focus = false) {
    raw.tab = part;
    for (const tab of rawBox.querySelectorAll("[data-raw-tab]")) {
      const on = tab.dataset.rawTab === part;
      tab.setAttribute("aria-selected", String(on));
      tab.tabIndex = on ? 0 : -1;
      if (on && focus) tab.focus();
    }
    for (const panel of rawBox.querySelectorAll("[data-raw-part]")) panel.hidden = panel.dataset.rawPart !== part;
  }

  function drawRaw(payload) {
    for (const panel of rawBox.querySelectorAll("[data-raw-part]")) {
      const part = panel.dataset.rawPart, rows = A.rawRows(payload, part);
      const cut = payload.truncated && payload.truncated[part];
      panel.querySelector("[data-raw-body]").replaceChildren(
        ...(cut ? [R.h("p", { class: "muted small" }, f.fill(t("raw_truncated"), { n: (payload.limits || {})[part] ?? rows.length }))] : []),
        A.rawTable(part, rows, f));
      const count = rawBox.querySelector(`[data-raw-count="${part}"]`);
      if (count) count.textContent = String(rows.length);
    }
    rawBox.querySelector("[data-raw-tabs]").hidden = false;
    rawBox.querySelector("[data-raw-parts]").hidden = false;
    selectTab(raw.tab);
  }

  async function loadRaw() {
    if (!rawBox || !config.raw) return;
    const ticket = ++raw.request;
    const status = rawBox.querySelector("[data-raw-status]");
    const button = rawBox.querySelector("[data-raw-load]");
    status.replaceChildren(R.h("span", { class: "loading" }, t("raw_loading")));
    try {
      // the history's range, at most what the API gives at once (31 days)
      const to = new Date(), from = new Date(to.getTime() - Math.min(RAW_MAX_MS, RANGE_MS[hist.range] || RAW_MAX_MS));
      const params = new URLSearchParams({ range: hist.range, from: from.toISOString(), to: to.toISOString() });
      const payload = await requestJson(`${config.raw}?${params}`);
      if (ticket !== raw.request) return;
      raw.loaded = true;
      drawRaw(payload);
      status.replaceChildren(...(payload.from ? R.fillNodes(t("raw_span"), { start: R.timeEl(f, payload.from), end: R.timeEl(f, payload.to || payload.until || to.toISOString()) }) : []));
      if (button) button.hidden = true;
    } catch (err) {
      if (ticket !== raw.request) return;
      if (err instanceof LoginEnded) { problem = "login"; poller.stop(); drawStatus(); }
      const retry = R.h("button", { type: "button", class: "pill" }, t("retry"));
      retry.addEventListener("click", () => loadRaw());
      status.replaceChildren(R.icon("warn"), err instanceof LoginEnded ? t("live_login") : t("raw_error"), " ", retry);
    }
  }

  if (rawBox) {
    rawBox.querySelector("[data-raw-load]")?.addEventListener("click", () => loadRaw());
    const tabs = [...rawBox.querySelectorAll("[data-raw-tab]")];
    tabs.forEach((tab, i) => {
      tab.addEventListener("click", () => selectTab(tab.dataset.rawTab));
      tab.addEventListener("keydown", (e) => {
        const next = e.key === "ArrowRight" ? i + 1 : e.key === "ArrowLeft" ? i - 1 : e.key === "Home" ? 0 : e.key === "End" ? tabs.length - 1 : null;
        if (next === null) return;
        e.preventDefault();
        selectTab(tabs[(next + tabs.length) % tabs.length].dataset.rawTab, true);
      });
    });
    if (raw.loaded) selectTab("auth");
  }

  // --- the admin overview ---------------------------------------------------------------------
  function drawOverview() {
    const ov = view.overview;
    if (!ov) return;
    replacePart(document, "ov-incidents", A.overviewIncidents(ov, f, ctx.now));
    replacePart(document, "ov-aps", A.overviewAps(ov, f));
    replacePart(document, "ov-auth", A.authFailures(ov.auth, f, ctx.now));
    replacePart(document, "ov-fresh", A.freshness(ov.freshness, ov.jobs, f, ov.jobs_available));
  }

  // --- the access point page: live values, day charts, search and sorting ---------------------
  const apFilters = document.querySelector("form[data-ap-filters]");
  const apCharts = new Map();          // card id -> {metric, chart}

  function apList() {
    return Array.isArray(data.aps) ? data.aps : [];
  }

  function drawAps() {
    for (const ap of apList()) {
      const card = document.getElementById(`ap-${String(ap.mac || ap.name || "").replaceAll(":", "")}`);
      if (!card) continue;
      const st = A.apState(ap);
      const n = A.apClients(ap), load = A.apLoad(ap), weak = A.apWeakShare(ap);
      card.className = `card ap-card ap-${st}`;
      Object.assign(card.dataset, { clients: n ?? "", load: load ?? -1, weak: weak ?? -1 });
      const state = card.querySelector("[data-part=ap-state]");
      if (state) {
        state.className = `dev-state state-${st === "up" ? "online" : "offline"}`;
        state.replaceChildren(R.icon({ up: "check", down: "bad", unknown: "help" }[st]), R.h("strong", {}, t(`ap_state_${st}`)),
          ...(ap.uptime_s ? [" ", R.h("span", { class: "state-more" }, f.fill(t("ap_uptime"), { duration: f.duration(ap.uptime_s) }))] : []));
      }
      const facts = card.querySelector("[data-part=ap-facts]");
      if (facts) {
        const fact = (label, ...dd) => R.h("div", { class: "fact" }, R.h("dt", {}, label), R.h("dd", {}, ...dd));
        const sub = (text) => R.h("span", { class: "sub" }, text);
        const days = ap.days || [];
        const restarts = days.reduce((sum, d) => sum + (typeof d.restarts === "number" ? d.restarts : 0), 0);
        const has = (v) => v !== null && v !== undefined;
        facts.replaceChildren(
          fact(t("ap_clients_label"), has(n) ? String(n) : "–", has(ap.clients_house) ? sub(f.fill(t("ap_clients_house"), { n: ap.clients_house })) : null),
          fact(t("ap_weak_label"), weak !== null ? f.percent(weak) : "–", has(ap.weak_clients) ? sub(f.fill(t("ap_weak_count"), { n: ap.weak_clients })) : null),
          fact(t("ap_signal_label"), has(ap.signal_avg_dbm) ? f.dbm(ap.signal_avg_dbm) : "–"),
          fact(t("ap_restarts_label"), days.length ? f.fill(t("ap_restarts_7d"), { n: restarts }) : "–"),
          fact(t("ap_uplink_label"), has(ap.uplink_mbps) ? R.h("span", { class: ap.uplink_mbps < 1000 ? "tone-text-warn" : null }, f.fill(t("ap_uplink"), { n: ap.uplink_mbps })) : "–"),
          R.h("div", { class: "fact wide" }, R.h("dt", {}, t("ap_load_label")), R.h("dd", {}, A.radios(ap, f) || "–")));
      }
      const warns = card.querySelector(".ap-warns");
      const fresh = A.apWarnings(ap, f);
      if (warns && fresh) warns.replaceWith(fresh); else if (warns) warns.remove(); else if (fresh) facts?.after(fresh);
      drawApChart(card, ap);
    }
    applyApFilters();
  }

  const AP_METRICS = {
    clients: (days) => ({ series: [{ label: t("ch_average"), points: days.map((d) => ({ t: d.t, v: d.clients_avg ?? null })), cls: "series-1" }],
      marks: { label: t("ap_peak"), points: days.map((d) => ({ t: d.t, v: d.clients_max ?? null })) },
      value: (v) => f.number(v, v % 1 ? 1 : 0), axisValue: (v) => f.number(v), sub: t("ch_ap_clients_sub") }),
    util: (days) => {
      const radios = [...new Set(days.flatMap((d) => Object.keys(d.channel_util_avg || {})))].sort();
      return { series: radios.map((r, i) => ({ label: t(`radio_${r}`) === `radio_${r}` ? r : t(`radio_${r}`),
        points: days.map((d) => ({ t: d.t, v: (d.channel_util_avg || {})[r] ?? null })), cls: `series-${(i % 2) + 1}` })),
      y: { min: 0, max: 1, ticks: [0, 0.5, 1] }, legend: radios.length > 1, value: (v) => f.percent(v), axisValue: (v) => f.percent(v),
      sub: t("ch_ap_util_sub") };
    },
    weak: (days) => ({ series: [{ label: t("ch_ap_weak"), points: days.map((d) => ({ t: d.t, v: d.weak_client_share ?? null })), cls: "series-2" }],
      value: (v) => f.percent(v), axisValue: (v) => f.percent(v), sub: t("ch_ap_weak_sub") }),
    restarts: (days) => ({ series: [{ label: t("ap_restarts_label"), points: days.map((d) => ({ t: d.t, v: d.restarts ?? null })), cls: "series-1" }],
      minSpan: 2, value: (v) => f.number(v), axisValue: (v) => f.number(v), sub: t("ch_ap_restarts_sub") }),
  };

  function drawApChart(card, ap) {
    const box = card.querySelector("[data-ap-chart]");
    if (!box) return;
    const days = (ap.days || []).map((d) => ({ ...d, t: toMs(d.day) })).filter((d) => d.t !== null).sort((a, b) => a.t - b.t);
    const state = apCharts.get(card.id) || { metric: "clients", chart: null };
    apCharts.set(card.id, state);
    if (state.chart) state.chart.destroy();
    if (!days.length) return;
    const spec = AP_METRICS[state.metric](days);
    const start = days[0].t, end = days[days.length - 1].t + 86400e3, span = (end - start) / 1000;
    box.querySelector("[data-sub]").textContent = spec.sub;
    const legend = box.querySelector("[data-legend]");
    legend.hidden = !spec.legend;
    legend.replaceChildren(...spec.series.map((x) => R.h("li", {}, R.h("i", { class: `chart-key ${x.cls}` }), x.label)));
    const known = spec.series.flatMap((x) => x.points).filter((p) => p.v !== null);
    const sumNode = box.querySelector("[data-summary]");
    if (sumNode) {
      const x = summary(spec.series[0].points);
      sumNode.textContent = x ? f.fill(t("ch_summary"), { min: spec.value(x.min), avg: spec.value(x.avg), max: spec.value(x.max) }) : "";
    }
    const host = box.querySelector("[data-host]");
    if (!known.length) { host.replaceChildren(R.h("p", { class: "chart-empty" }, t("ch_nodata"))); state.chart = null; return; }
    state.chart = barChart(host, { ...spec, start, end, stepMs: 86400e3, height: 150, label: `${apRoomText(ap)}: ${t(`ch_ap_${state.metric}`)}`,
      axisTime: (ms) => f.axisTime(new Date(ms), span), tipTime: (ms) => f.day(new Date(ms)), noValue: "–" });
  }
  const apRoomText = (ap) => A.apRoom(ap, f);

  for (const card of document.querySelectorAll(".ap-card")) {
    for (const chip of card.querySelectorAll("[data-metric]")) {
      chip.addEventListener("click", () => {
        const ap = apList().find((a) => `ap-${String(a.mac || a.name || "").replaceAll(":", "")}` === card.id);
        if (!ap) return;
        const state = apCharts.get(card.id) || { metric: "clients", chart: null };
        state.metric = chip.dataset.metric;
        apCharts.set(card.id, state);
        for (const c of card.querySelectorAll("[data-metric]")) c.setAttribute("aria-pressed", String(c === chip));
        drawApChart(card, ap);
      });
    }
  }

  function applyApFilters() {
    if (!apFilters) return;
    const q = (apFilters.elements.namedItem("q").value || "").trim().toLowerCase();
    const sort = apFilters.elements.namedItem("sort").value;
    const list = document.querySelector(".ap-list");
    const items = [...list.querySelectorAll(".ap-card")];
    let shown = 0;
    for (const item of items) {
      const match = !q || item.dataset.name.includes(q) || item.dataset.name.includes(q.replaceAll("-", ":"));
      item.hidden = !match;
      if (match) shown += 1;
    }
    const num = (v) => (v === "" || v === undefined ? -1 : Number(v));
    const key = { clients: (ds) => -num(ds.clients), load: (ds) => -num(ds.load), weak: (ds) => -num(ds.weak) }[sort] || ((ds) => ds.room);
    const sorted = [...items].sort((a, b) => { const ka = key(a.dataset), kb = key(b.dataset); return ka < kb ? -1 : ka > kb ? 1 : a.dataset.room.localeCompare(b.dataset.room); });
    if (sorted.some((item, i) => item !== items[i])) list.append(...sorted);
    const count = document.querySelector("[data-shown]");
    if (count) count.textContent = f.fill(t("adm_shown"), { shown, total: items.length });
    const none = document.querySelector("[data-none]");
    if (none) none.hidden = shown > 0;
    followAddress(apFilters, ["q", "sort"], { sort: "name" });
  }
  if (apFilters) liveForm(apFilters, applyApFilters);

  // --- the incident page: the chart, kind and state in place -------------------------------
  const incFilters = document.querySelector("form[data-inc-filters]");
  let incChart = null;

  function incidentList() {
    return Array.isArray(data.incidents) ? data.incidents : [];
  }

  function drawIncidents() {
    const list = [...incidentList()].sort((a, b) => Date.parse(b.started) - Date.parse(a.started));
    const box = document.querySelector("[data-part=incidents]");
    if (box) box.replaceChildren(...list.map((i) => A.incidentItem(i, f, { full: true, now: ctx.now })));
    const host = document.querySelector("[data-inc-chart]");
    if (host) {
      if (incChart) incChart.destroy();
      const end = toMs(data.to) || Date.now();
      const start = toMs(data.from) || end - (RANGE_MS[config.range] || RANGE_MS["7d"]);
      const { lanes, items } = incidentLanes(list, start, end, (end - start) / 400);
      const info = document.querySelector("[data-inc-info]");
      host.closest("figure").hidden = !items.length;
      incChart = items.length ? laneChart(host, { lanes, items, start, end, label: t("inc_chart"),
        laneLabel: (l) => `${t(`inc_${l.kind}`) === `inc_${l.kind}` ? t("inc_other") : t(`inc_${l.kind}`)} · ${f.scope(l)}`,
        itemLabel: (it) => `${f.incidentText(it.inc)} · ${f.when(it.inc.started)}${it.open ? ` · ${t("inc_open")}` : ` – ${f.when(it.inc.ended)}`}`,
        axisTime: (ms) => f.axisTime(new Date(ms), (end - start) / 1000),
        onSelect: (text, it) => {
          if (info) info.textContent = text;
          document.getElementById(`incident-${it.inc.id}`)?.scrollIntoView({ block: "nearest" });
        } }) : null;
    }
    applyIncFilters();
  }

  function applyIncFilters() {
    if (!incFilters) return;
    const kind = incFilters.elements.namedItem("kind").value, state = incFilters.elements.namedItem("state").value;
    const items = [...document.querySelectorAll("[data-part=incidents] .inc")];
    let shown = 0;
    for (const item of items) {
      const match = (!kind || item.dataset.kind === kind) && (!state || item.dataset.state === state);
      item.hidden = !match;
      if (match) shown += 1;
    }
    const count = document.querySelector("[data-shown]");
    if (count) count.textContent = f.fill(t("inc_shown"), { shown, total: items.length });
    const none = document.querySelector("[data-none]");
    if (none) none.hidden = shown > 0;
    followAddress(incFilters, ["range", "from", "kind", "state"], {});
  }
  if (incFilters) {
    liveForm(incFilters, applyIncFilters);
    // the server filters by kind (the list holds only that kind): a new kind is a new page
    incFilters.elements.namedItem("kind")?.addEventListener("change", () => incFilters.submit());
  }

  /** A GET form that applies itself while typing (its button only without the script). */
  function liveForm(form, apply) {
    form.classList.add("live");
    form.querySelector("[data-apply]")?.setAttribute("hidden", "");
    form.addEventListener("input", apply);
    form.addEventListener("change", apply);
    form.addEventListener("submit", (e) => { e.preventDefault(); apply(); });
  }

  /** The address follows a form's fields (a reload or a shared link shows the same). */
  function followAddress(form, names, defaults) {
    const params = new URLSearchParams();
    for (const name of names) {
      const v = form.elements.namedItem(name)?.value;
      if (v && defaults[name] !== v) params.set(name, v);
    }
    const url = location.pathname + (params.toString() ? `?${params}` : "") + location.hash;
    if (url !== location.pathname + location.search + location.hash) window.history.replaceState(null, "", url);
  }

  // --- start --------------------------------------------------------------------------------
  document.documentElement.classList.add("js");
  if (Date.now() - lastOkAt > REFRESH_MS) poller.poll();      // a page from the back/forward cache, or old data
  else { drawAll(); poller.start(pollMs(data, REFRESH_MS)); }
  window.addEventListener("pageshow", (e) => { if (e.persisted) poller.poll(); });
}

main();
