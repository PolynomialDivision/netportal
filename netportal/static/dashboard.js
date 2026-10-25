// The "My devices" pages come alive: a refresh every 30 seconds from the JSON API (paused while
// the tab is hidden), honest states (updating, offline, portal unreachable, stale data, login
// ended), the inline rename, the admin list's search, filters and sorting, and the device page's
// charts and connection timeline. Without this script every page is complete as the server sent
// it. No libraries, no inline code, no eval, same-origin requests only (the CSP allows nothing else).

import { createFormatter, toDate } from "./format.js";
import * as R from "./render.js";
import { apName, apSlots, availability, lineChart, summary, timelineChart, timelineSegments, toMs, toPoints } from "./charts.js";

const REFRESH_MS = 30e3;          // the live data
const TIMEOUT_MS = 15e3;          // a request that takes longer counts as unreachable
const HISTORY_EVERY_MS = 5 * 60e3; // the 24-hour charts follow along every 5 minutes
const STALE_AFTER_MS = 3 * REFRESH_MS;

function readJson(id) {
  const node = document.getElementById(id);
  if (!node) return null;
  try { return JSON.parse(node.textContent); } catch { return null; }
}

class LoginEnded extends Error {}
class HttpError extends Error {
  constructor(status) { super(`HTTP ${status}`); this.status = status; }
}

/** GET (or POST) JSON from the portal. An ended session answers 401, or (from an older
 *  portal) a redirect to the login, which is not followed: both throw LoginEnded. */
async function requestJson(url, options = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, { credentials: "same-origin", redirect: "manual", cache: "no-store", ...options,
      headers: { Accept: "application/json", ...(options.headers || {}) }, signal: ctrl.signal });
    if (res.type === "opaqueredirect" || res.status === 401) throw new LoginEnded();
    const body = (res.headers.get("Content-Type") || "").includes("json") ? await res.json() : null;
    if (!res.ok) { const e = new HttpError(res.status); e.body = body; throw e; }
    return body;
  } finally {
    clearTimeout(timer);
  }
}

function main() {
  const texts = readJson("np-texts"), config = readJson("np-config");
  if (!texts || !config) return;
  const f = createFormatter(config.lang || document.documentElement.lang || "en", texts);
  const t = f.t;
  const page = config.page;
  let data = readJson("np-data") || {};
  const ctx = { ssid: config.ssid, now: Date.now() };

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
    if (problem && problem !== "login" && Date.now() - lastOkAt > STALE_AFTER_MS && !data.stale) {
      out.push(R.bannerNodes("warn", ...R.fillNodes(t("live_stale"), { when: R.timeEl(f, new Date(lastOkAt).toISOString(), "when") })));
    }
    if (changed) {
      out.push(R.bannerNodes("info", t("live_changed"), " ", R.h("a", { href: location.pathname + location.search }, t("live_reload"))));
    }
    return out;
  }

  function drawStatus() {
    const box = document.querySelector("[data-part=banners]");
    if (box) box.replaceWith(R.banners(data, f, connectionBanners()));
    if (liveText) {
      const when = data.generated_at ? R.timeEl(f, data.generated_at, "when") : null;
      liveText.replaceChildren(...(busy ? [t("live_updating")]
        : when ? [...R.fillNodes(t("live_updated"), { when }), " · ", t("live_auto")] : [t("live_auto")]));
    }
    if (liveLine) liveLine.classList.toggle("busy", busy);
    const list = document.querySelector("[data-part=devices]");
    if (list) list.setAttribute("aria-busy", busy ? "true" : "false");
  }

  // --- drawing the devices ----------------------------------------------------------------
  const previous = new Map((data.devices || []).map((d) => [d.id, d.state]));

  function replacePart(root, part, node) {
    const old = root.querySelector(`[data-part="${part}"]`);
    if (old) old.replaceWith(node);
  }

  function drawCard(root, d, full, limit = 0) {
    const admin = page === "admin" || Boolean(config.admin);
    replacePart(root, "state", R.stateLine(d, f, ctx));
    replacePart(root, "live", R.live(d, f));
    replacePart(root, "diag", R.findings(d, f, { full, telemetry: data.telemetry, limit, admin }));
    const box = root.querySelector("[data-name-box]");
    if (box && !box.querySelector("details").open) showName(box, d.name);
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
    Object.assign(item.dataset, {
      name: (d.name || "").toLowerCase(), state: d.state, mac: d.mac || "",
      owner: `${d.owner?.display || ""} ${d.owner?.username || ""}`.toLowerCase(),
      codes: (d.diagnostics || []).map((x) => x.code).join(" "), problems: String(R.problemsOf(d).length),
      signal: d.signal_dbm ?? "", health: d.health ?? "", seen: d.state === "online" ? "~" : d.last_seen || "",
    });
  }

  function drawAll() {
    ctx.now = Date.now();
    const devices = data.devices || [];
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
    if (data.house && document.querySelector("[data-part=house]")) {
      const strip = R.houseStrip(data.house, f);
      strip.hidden = data.telemetry !== "ok";
      replacePart(document, "house", strip);
    }
    for (const d of devices) {
      if (previous.has(d.id) && previous.get(d.id) !== d.state) {
        announce(f.fill(t("announce_state"), { name: d.name, state: t(`state_${d.state}`) }));
      }
      previous.set(d.id, d.state);
    }
    drawStatus();
  }

  // --- the refresh ------------------------------------------------------------------------
  let timer = 0, lastFetch = 0;
  async function refresh() {
    clearTimeout(timer);
    if (problem === "login") return;
    if (navigator.onLine === false) {
      problem = "offline";
      drawStatus();
      announce(t("live_offline"));
      return;
    }
    busy = true;
    drawStatus();
    lastFetch = Date.now();
    try {
      // the device page asks for its one device (an admin's view of someone else's too)
      const fresh = await requestJson(page === "device" ? `/api/devices/${encodeURIComponent(config.device)}` : config.api);
      data = page === "device" ? { ...fresh, devices: fresh.device ? [fresh.device] : [] } : fresh;
      lastOkAt = Date.now();
      problem = null;
    } catch (err) {
      problem = err instanceof LoginEnded ? "login" : navigator.onLine === false ? "offline" : "unreachable";
      announce(problem === "login" ? t("live_login") : problem === "offline" ? t("live_offline") : t("live_unreachable"));
    } finally {
      busy = false;
    }
    drawAll();
    if (page === "device" && hist.range === "24h" && Date.now() - hist.loadedAt > HISTORY_EVERY_MS && !problem) {
      loadHistory(hist.range, { quiet: true });
    }
    schedule();
  }

  function schedule() {
    clearTimeout(timer);
    if (document.hidden || problem === "login") return;
    timer = setTimeout(refresh, REFRESH_MS);
  }

  document.addEventListener("visibilitychange", () => {
    if (document.hidden) clearTimeout(timer);
    else if (Date.now() - lastFetch >= REFRESH_MS) refresh();
    else schedule();
  });
  window.addEventListener("online", () => refresh());
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
        for (const d of data.devices || []) if (d.id === id) d.name = saved;
        setTimeout(() => { if (status.textContent === t("saved")) say(""); }, 4000);
      } catch (err) {
        // the field stays open with what was typed: nothing is lost
        if (err instanceof LoginEnded) { problem = "login"; drawStatus(); say(t("live_login"), "bad"); }
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
  const STATE_ORDER = { offline: 0, never_connected: 1, unknown: 2, online: 3 };
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
  const hist = { range: config.range || "24h", loadedAt: 0, charts: [], request: 0 };
  const historyBox = document.querySelector("[data-history]");

  function chartSpecs(payload) {
    const s = payload.series || {};
    const start = toMs(payload.start), end = toMs(payload.end), stepMs = (payload.step_s || 300) * 1000;
    const span = (end - start) / 1000;
    const base = { start, end, stepMs, axisTime: (ms) => f.axisTime(new Date(ms), span), tipTime: (ms) => f.when(new Date(ms)) };
    const signal = toPoints(s.signal_dbm), health = toPoints(s.health);
    const sMin = Math.min(-90, ...signal.filter((p) => p.v !== null).map((p) => Math.floor(p.v / 10) * 10));
    return {
      signal: { ...base, kind: "line", series: [{ label: t("ch_signal"), points: signal, cls: "series-1" }],
        y: { min: sMin, max: -30, ticks: signalTicks(sMin) }, bands: [{ from: -67, to: -30, cls: "band-good", label: t("band_good") },
          { from: -200, to: -75, cls: "band-weak", label: t("band_weak") }],
        value: (v) => f.dbm(v), axisValue: (v) => f.number(v), sum: (x) => x && f.fill(t("ch_summary"), { min: f.dbm(x.min), avg: f.dbm(x.avg), max: f.dbm(x.max) }) },
      quality: { ...base, kind: "line", series: [{ label: t("ch_quality"), points: health, cls: "series-1" }],
        y: { min: 0, max: 100, ticks: [0, 50, 100] }, bands: [{ from: 80, to: 100, cls: "band-good", label: t("q_good") }, { from: 0, to: 50, cls: "band-weak", label: t("q_poor") }],
        value: (v) => f.fill(t("quality_fmt"), { n: Math.round(v) }), axisValue: (v) => f.number(v),
        sum: (x) => x && f.fill(t("ch_summary"), { min: f.number(x.min), avg: f.number(x.avg), max: f.number(x.max) }) },
      traffic: { ...base, kind: "area", legend: true, series: [{ label: t("dir_down"), points: toPoints(s.rx_bps), cls: "series-1" },
        { label: t("dir_up"), points: toPoints(s.tx_bps), cls: "series-2" }],
      value: (v) => f.bitrate(v), axisValue: (v) => compactRate(v), axisWidth: 64,
      sum: (x) => x && f.fill(t("ch_summary"), { min: f.bitrate(x.min), avg: f.bitrate(x.avg), max: f.bitrate(x.max) }) },
      link: { ...base, kind: "line", legend: true, series: [{ label: t("dir_down"), points: toPoints(s.link_rx_bps), cls: "series-1" },
        { label: t("dir_up"), points: toPoints(s.link_tx_bps), cls: "series-2" }],
      value: (v) => f.bitrate(v), axisValue: (v) => compactRate(v), axisWidth: 64,
      sum: (x) => x && f.fill(t("ch_summary"), { min: f.bitrate(x.min), avg: f.bitrate(x.avg), max: f.bitrate(x.max) }) },
      online: { ...base, kind: "step-area", height: 96, axisWidth: 12, series: [{ label: t("ch_online"), points: toPoints(s.online), cls: "series-ok" }],
        y: { min: 0, max: 1, ticks: [0, 1] }, value: (v) => t(v > 0 ? "state_online" : "state_offline"), axisValue: () => "",
        sum: (_x, points) => { const a = availability(points); return a === null ? null : f.fill(t("online_pct"), { pct: f.percent(a) }); } },
    };
  }

  // every 20 dB from the top (-30) down to the lowest value's decade
  function signalTicks(min) {
    const ticks = [];
    for (let v = -30; v >= min; v -= 20) ticks.unshift(v);
    return ticks;
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
    let any = false;
    for (const fig of document.querySelectorAll("[data-chart]")) {
      const spec = specs[fig.dataset.chart];
      const host = fig.querySelector("[data-host]");
      const sumNode = fig.querySelector("[data-summary]");
      const legend = fig.querySelector("[data-legend]");
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
      const sumText = spec.series.length > 1
        ? spec.series.map((x) => { const one = summary(x.points); return one ? `${x.label}: ${spec.sum(one, x.points)}` : null; })
          .filter(Boolean).join(". ")
        : spec.sum(sum, all) || "";
      if (sumNode) sumNode.textContent = sumText;
      if (legend) {
        legend.hidden = !spec.legend;
        legend.replaceChildren(...spec.series.map((s) => R.h("li", {}, R.h("i", { class: `chart-key ${s.cls}` }), s.label)));
      }
      const caption = fig.querySelector("h3")?.textContent || "";
      hist.charts.push(lineChart(host, { ...spec, label: `${caption}. ${sumText}`, noValue: "–" }));
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
          + ` (${s.ongoing ? t("tl_ongoing") : f.duration((s.end - s.start) / 1000)})`,
        markLabel: (m) => `${f.when(new Date(m.t))} · ${R.eventText(m, f).map((n) => (typeof n === "string" ? n : n ? n.textContent : "")).join("")}`,
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
    if (events) {
      events.replaceChildren(...R.eventList(payload.timeline || [], f));
      if (payload.timeline_truncated) events.appendChild(R.h("li", { class: "ev ev-more muted" }, t("tl_more")));
    }
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
      if (status) {
        const note = payload.telemetry === "off" ? t("telemetry_off") : payload.telemetry === "unavailable" ? t("telemetry_unavailable") : "";
        status.replaceChildren(...(note ? [R.icon("info"), note] : []));
        status.classList.toggle("tone-warn", Boolean(note));
      }
    } catch (err) {
      if (ticket !== hist.request) return;
      if (err instanceof LoginEnded) { problem = "login"; drawStatus(); }
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

  // --- start --------------------------------------------------------------------------------
  document.documentElement.classList.add("js");
  if (Date.now() - lastOkAt > REFRESH_MS) refresh();      // a page from the back/forward cache, or old data
  else { drawAll(); schedule(); }
  window.addEventListener("pageshow", (e) => { if (e.persisted) refresh(); });
}

main();
