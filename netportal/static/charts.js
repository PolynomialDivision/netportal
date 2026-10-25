// Small SVG charts for the device page: line, area and step charts with axes, gaps where data is
// missing (never a made-up zero), a crosshair tooltip for mouse, touch and keyboard, and the
// connection timeline. No libraries, no inline styles (the CSP has no 'unsafe-inline': colours
// come from classes in style.css, positions from SVG attributes).
// The pure helpers at the top are exported for tests/js/charts.test.mjs.

const SVG = "http://www.w3.org/2000/svg";
export const AP_SLOTS = 6;            // categorical colours for access points (style.css .ap-0 … .ap-5)

// --- pure helpers ---------------------------------------------------------------------------

/** A timestamp from the API (unix seconds, milliseconds or ISO) -> milliseconds. */
export function toMs(t) {
  if (t === null || t === undefined) return null;
  if (typeof t === "number") return t < 1e11 ? t * 1000 : t;
  const ms = Date.parse(t);
  return Number.isNaN(ms) ? null : ms;
}

/** [[t, v|null], …] -> [{t: ms, v: number|null}], sorted by time. */
export function toPoints(series) {
  return (series || [])
    .map(([t, v]) => ({ t: toMs(t), v: v === null || v === undefined || Number.isNaN(Number(v)) ? null : Number(v) }))
    .filter((p) => p.t !== null)
    .sort((a, b) => a.t - b.t);
}

/** Runs of consecutive known values. A null, or a jump in time longer than maxGapMs (points
 *  missing altogether), ends a run: the chart draws a gap there, not a line through nothing. */
export function segments(points, maxGapMs = Infinity) {
  const runs = [];
  let run = [];
  let last = null;
  for (const p of points) {
    if (p.v === null || (last && p.t - last.t > maxGapMs)) {
      if (run.length) runs.push(run);
      run = [];
    }
    if (p.v !== null) run.push(p);
    last = p;
  }
  if (run.length) runs.push(run);
  return runs;
}

/** [min, max] of the known values, or null. */
export function extent(points) {
  let min = Infinity, max = -Infinity;
  for (const p of points) {
    if (p.v === null) continue;
    if (p.v < min) min = p.v;
    if (p.v > max) max = p.v;
  }
  return min === Infinity ? null : [min, max];
}

/** lowest, average, highest and latest known value (null when there is none). */
export function summary(points) {
  const known = points.filter((p) => p.v !== null);
  if (!known.length) return null;
  const sum = known.reduce((s, p) => s + p.v, 0);
  return { min: Math.min(...known.map((p) => p.v)), max: Math.max(...known.map((p) => p.v)),
    avg: sum / known.length, last: known[known.length - 1].v, count: known.length };
}

/** The share of known samples with the device online (0-1), or null. */
export function availability(points) {
  const known = points.filter((p) => p.v !== null);
  if (!known.length) return null;
  return known.filter((p) => p.v > 0).length / known.length;
}

/** A round step (1, 2, 2.5, 5 × 10^n) that cuts the span into about `count` parts. */
export function niceStep(span, count = 4) {
  if (!(span > 0)) return 1;
  const raw = span / Math.max(1, count);
  const power = 10 ** Math.floor(Math.log10(raw));
  const unit = raw / power;
  const nice = unit <= 1 ? 1 : unit <= 2 ? 2 : unit <= 2.5 ? 2.5 : unit <= 5 ? 5 : 10;
  return nice * power;
}

/** Round ticks covering [min, max]: {min, max, ticks} with the domain widened to whole steps. */
export function niceTicks(min, max, count = 4) {
  if (min === max) {
    const pad = Math.abs(min) > 0 ? Math.abs(min) * 0.1 : 1;
    min -= pad; max += pad;
  }
  const step = niceStep(max - min, count);
  const lo = Math.floor(min / step + 1e-9) * step, hi = Math.ceil(max / step - 1e-9) * step;
  const ticks = [];
  for (let v = lo; v <= hi + step / 2; v += step) ticks.push(Math.round(v / step) * step);
  return { min: lo, max: hi, ticks, step };
}

/** A linear scale with invert, clamping nothing. */
export function scaleLinear([d0, d1], [r0, r1]) {
  const k = d1 === d0 ? 0 : (r1 - r0) / (d1 - d0);
  const scale = (v) => r0 + (v - d0) * k;
  scale.invert = (r) => (k === 0 ? d0 : d0 + (r - r0) / k);
  return scale;
}

const fixed = (n) => Math.round(n * 10) / 10;

export function linePath(run, x, y) {
  return run.map((p, i) => `${i ? "L" : "M"}${fixed(x(p.t))},${fixed(y(p.v))}`).join("");
}

export function areaPath(run, x, y, y0) {
  if (!run.length) return "";
  const first = run[0], last = run[run.length - 1];
  return `${linePath(run, x, y)}L${fixed(x(last.t))},${fixed(y0)}L${fixed(x(first.t))},${fixed(y0)}Z`;
}

/** A step line: each value holds until the next sample (the last one for one step more). */
export function stepPath(run, x, y, stepMs = 0) {
  let d = "";
  run.forEach((p, i) => {
    const next = run[i + 1] ? run[i + 1].t : p.t + stepMs;
    d += `${i ? "L" : "M"}${fixed(x(p.t))},${fixed(y(p.v))}H${fixed(x(next))}`;
  });
  return d;
}

/** Index of the sample nearest to time t (binary search), or -1. */
export function nearestIndex(points, t) {
  if (!points.length) return -1;
  let lo = 0, hi = points.length - 1;
  while (hi - lo > 1) {
    const mid = (lo + hi) >> 1;
    if (points[mid].t <= t) lo = mid; else hi = mid;
  }
  return Math.abs(points[hi].t - t) < Math.abs(points[lo].t - t) ? hi : lo;
}

/** The house's UTC offset (ms) at a moment: day ticks fall on its midnight. */
export function zoneOffsetMs(ms, timeZone) {
  const parts = {};
  const f = new Intl.DateTimeFormat("en-GB", { timeZone, hourCycle: "h23", year: "numeric", month: "numeric",
    day: "numeric", hour: "numeric", minute: "numeric", second: "numeric" });
  for (const { type, value } of f.formatToParts(new Date(ms))) parts[type] = Number(value);
  const wall = Date.UTC(parts.year, parts.month - 1, parts.day, parts.hour % 24, parts.minute, parts.second);
  return wall - Math.floor(ms / 1000) * 1000;
}

const HOUR = 3600e3, DAY = 86400e3;
/** A wall-clock time of the house (ms as if UTC) -> the real moment. */
function fromWall(wallMs, timeZone) {
  const guess = wallMs - zoneOffsetMs(wallMs, timeZone);
  return wallMs - zoneOffsetMs(guess, timeZone);
}

/** Time ticks at round wall-clock times of the house (summer time included): hours for a day,
 *  midnights for a week, Mondays for a month. */
export function timeTicks(startMs, endMs, maxTicks = 6, timeZone = "Europe/Berlin") {
  const steps = [HOUR, 2 * HOUR, 3 * HOUR, 6 * HOUR, 12 * HOUR, DAY, 2 * DAY, 7 * DAY, 14 * DAY];
  const span = endMs - startMs;
  if (!(span > 0)) return [];
  if (span / (14 * DAY) > maxTicks) return monthTicks(startMs, endMs, maxTicks, timeZone);
  const step = steps.find((s) => span / s <= maxTicks) || steps[steps.length - 1];
  let wall = Math.ceil((startMs + zoneOffsetMs(startMs, timeZone)) / Math.min(step, DAY)) * Math.min(step, DAY);
  if (step >= 7 * DAY) wall += ((8 - new Date(wall).getUTCDay()) % 7) * DAY;       // to a Monday
  const ticks = [];
  for (; ticks.length < 100; wall += step) {
    const t = fromWall(wall, timeZone);
    if (t > endMs) break;
    if (t >= startMs) ticks.push(t);
  }
  return ticks;
}

/** Ticks on the first of a month (every 1, 2, 3, 6 or 12 months: at most maxTicks), at the
 *  house's midnight: the long ranges (1 year, all). */
export function monthTicks(startMs, endMs, maxTicks = 6, timeZone = "Europe/Berlin") {
  const first = new Date(startMs + zoneOffsetMs(startMs, timeZone));
  const months = (new Date(endMs).getUTCFullYear() - first.getUTCFullYear()) * 12 + new Date(endMs).getUTCMonth() - first.getUTCMonth() + 1;
  const every = [1, 2, 3, 6, 12].find((n) => months / n <= maxTicks) || 12;
  const ticks = [];
  for (let y = first.getUTCFullYear(), m = first.getUTCMonth(); ticks.length < 100; m += 1) {
    const wall = Date.UTC(y, m, 1);
    const t = fromWall(wall, timeZone);
    if (t > endMs) break;
    const month = new Date(wall).getUTCMonth();
    if (t >= startMs && month % every === 0) ticks.push(t);
  }
  return ticks;
}

/** The connection timeline from the API's events, clipped to [startMs, endMs]:
 *  {spans: [{start, end, ap, band, ongoing, basis}], marks: [{t, kind, ...event}]}.
 *  "connected" opens a span (its duration_s, when given, closes it); "reconnected", "roamed"
 *  and "band_changed" close the span and open the next one on the (new) access point or band;
 *  "disconnected" and "session_ended" close it. A span still open at the end is ongoing. A
 *  device that was already connected when the range began shows from the start (its first
 *  event is then a roam or a disconnect, not a connect). A span is as certain as the event that
 *  opened it (basis: measured or inferred). Marks: every event but connections and logins
 *  (authenticated: a login comes with every connection and roam, the list has them). */
const OPENS = new Set(["connected", "reconnected"]);
const MOVES = new Set(["roamed", "band_changed"]);
const CLOSES = new Set(["disconnected", "session_ended"]);
const MARKS = new Set(["roamed", "band_changed", "reconnected", "disconnected", "session_ended", "auth_rejected",
  "mac_changed", "incident"]);
export function timelineSegments(events, startMs, endMs) {
  const list = (events || []).map((e) => ({ ...e, t: toMs(e.at) })).filter((e) => e.t !== null)
    .sort((a, b) => a.t - b.t);
  const spans = [], marks = [];
  let open = null;
  const close = (t) => {
    if (!open) return;
    const end = Math.min(t, open.until ?? Infinity);
    if (end > open.start) spans.push({ start: open.start, end, ap: open.ap, band: open.band, ongoing: false, basis: open.basis });
    open = null;
  };
  const basisOf = (e) => (e.basis === "inferred" ? "inferred" : "measured");
  for (const e of list) {
    if (e.kind === "connected" || (e.kind === "reconnected" && !open)) {
      close(e.t);
      open = { start: e.t, ap: e.ap ?? null, band: e.band ?? null, basis: basisOf(e),
        until: e.kind === "connected" && e.duration_s !== null && e.duration_s !== undefined ? e.t + e.duration_s * 1000 : null };
    } else if (e.kind === "reconnected" || MOVES.has(e.kind)) {
      // already connected when the range began (nothing before it): from the start
      if (!open && !spans.length) open = { start: startMs, ap: e.from_ap ?? e.ap ?? null, band: e.from_band ?? e.band ?? null, until: null, basis: basisOf(e) };
      const until = e.kind === "reconnected" || !open ? null : open.until;
      close(e.t);
      open = { start: e.t, ap: e.ap ?? null, band: e.band ?? null, until, basis: basisOf(e) };
    } else if (CLOSES.has(e.kind)) {
      if (!open && !spans.length && e.t > startMs) {
        open = { start: startMs, ap: e.ap ?? null, band: e.band ?? null, until: null, basis: basisOf(e) };
      }
      close(e.t);
    }
    if (MARKS.has(e.kind)) marks.push(e);
    if (open && open.until !== null && open.until !== undefined && open.until <= e.t) close(open.until);
  }
  if (open) {
    const end = Math.min(endMs, open.until ?? Infinity);
    if (end > open.start) spans.push({ start: open.start, end, ap: open.ap, band: open.band, ongoing: end >= endMs, basis: open.basis });
  }
  const clipped = spans
    .map((s) => ({ ...s, start: Math.max(s.start, startMs), end: Math.min(s.end, endMs) }))
    .filter((s) => s.end > s.start);
  return { spans: clipped, marks: marks.filter((m) => m.t >= startMs && m.t <= endMs) };
}

/** Day bars: [{t, v}] (one point per day, as the API sends day steps) -> [{t0, t1, v}], each
 *  day ending where the next begins (23 or 25 hours across a clock change), the last one a
 *  step long. */
export function dayBars(points, stepMs = 86400e3) {
  return points.map((p, i) => ({ t0: p.t, t1: points[i + 1] ? points[i + 1].t : p.t + stepMs, v: p.v }));
}

/** An average rate per day (bit/s) as the bytes of that day. */
export function bytesPerDay(points, stepMs = 86400e3) {
  return dayBars(points, stepMs).map((b) => ({ t: b.t0, v: b.v === null ? null : (b.v * (b.t1 - b.t0)) / 1000 / 8 }));
}

/** Where the bars of slot i go: slot width w over `count` slots in [x0, x1], `groups` bars per
 *  slot side by side, with a gap of a fifth of the slot (at least 1 px, at most 6). */
export function barGeometry(count, x0, x1, groups = 1) {
  const slot = count > 0 ? (x1 - x0) / count : 0;
  const gap = Math.min(6, Math.max(1, slot / 5));
  const bar = Math.max(1, (slot - gap) / Math.max(1, groups));
  return { slot, gap, bar, x: (i, g = 0) => x0 + i * slot + gap / 2 + g * bar };
}

/** Incidents as lanes (one per kind and subject) clipped to [startMs, endMs]:
 *  {lanes: [{key, kind, subject, subject_name}], items: [{lane, start, end, open, inc}]}. An
 *  open incident lasts to the end; one shorter than minMs shows minMs wide. */
export function incidentLanes(incidents, startMs, endMs, minMs = 0) {
  const lanes = [], index = new Map(), items = [];
  const sorted = [...(incidents || [])].sort((a, b) => String(a.kind).localeCompare(String(b.kind))
    || String(a.subject_name || a.subject || "").localeCompare(String(b.subject_name || b.subject || "")));
  for (const inc of sorted) {
    const s = toMs(inc.started);
    if (s === null) continue;
    const e = inc.ended ? toMs(inc.ended) : endMs;
    if (e < startMs || s > endMs) continue;
    const key = `${inc.kind}|${inc.subject || ""}`;
    if (!index.has(key)) {
      index.set(key, lanes.length);
      lanes.push({ key, kind: inc.kind, subject: inc.subject || "", subject_name: inc.subject_name || null, ap: inc.ap || null });
    }
    const start = Math.max(s, startMs);
    items.push({ lane: index.get(key), start, end: Math.min(endMs, Math.max(e, start + minMs)), open: !inc.ended, inc });
  }
  return { lanes, items };
}

/** A colour slot per access point, by name (stable whatever the range shows); beyond the
 *  palette's slots, "other". */
export function apSlots(spans) {
  const names = [...new Set(spans.map((s) => s.ap?.name ?? s.ap ?? "").filter(Boolean))].sort();
  const slots = new Map();
  names.forEach((name, i) => slots.set(name, i < AP_SLOTS ? i : "other"));
  return slots;
}

export const apName = (ap) => (ap && typeof ap === "object" ? ap.name : ap) || "";

// --- DOM ------------------------------------------------------------------------------------

function el(name, attrs = {}, parent = null) {
  const node = document.createElementNS(SVG, name);
  for (const [k, v] of Object.entries(attrs)) if (v !== null && v !== undefined) node.setAttribute(k, String(v));
  if (parent) parent.appendChild(node);
  return node;
}

/** Draw a chart into `host` (a div): spec = {
 *    series: [{label, points, cls}], kind: "line"|"area"|"step", start, end (ms), stepMs,
 *    y: {min, max, ticks?} (fixed) or nothing (from the data), bands: [{from, to, cls, label}],
 *    value(v) -> text, axisValue(v) -> text, axisTime(ms) -> text, tipTime(ms) -> text,
 *    label (for screen readers), height }.
 *  Redraws on resize; returns {destroy}. */
export function lineChart(host, spec) {
  const height = spec.height || 180;
  const pad = { top: 10, right: 12, bottom: 24, left: spec.axisWidth || 52 };
  const maxGap = (spec.stepMs || 60e3) * 2.5;
  const series = spec.series.map((s) => ({ ...s, runs: segments(s.points, maxGap) }));
  let cursor = -1;            // index into the first series' points (the time grid)
  let svg = null, tip = null, rule = null, dots = [];
  let x = null, y = null, width = 0;
  const grid = series[0]?.points || [];

  function domainY() {
    if (spec.y && spec.y.min !== undefined) {
      // a fixed domain: its own ticks, or round ones inside it (never a label outside the plot)
      const ticks = spec.y.ticks || niceTicks(spec.y.min, spec.y.max, 4).ticks.filter((v) => v >= spec.y.min && v <= spec.y.max);
      return { min: spec.y.min, max: spec.y.max, ticks };
    }
    const all = series.flatMap((s) => s.points);
    const e = extent(all) || [0, 1];
    const lo = spec.zeroBased === false ? e[0] : Math.min(0, e[0]);
    return niceTicks(lo, Math.max(e[1], lo + (spec.minSpan || 0)), 4);
  }

  function draw() {
    width = Math.max(240, Math.floor(host.clientWidth || 320));
    host.replaceChildren();
    const d = domainY();
    x = scaleLinear([spec.start, spec.end], [pad.left, width - pad.right]);
    y = scaleLinear([d.min, d.max], [height - pad.bottom, pad.top]);
    svg = el("svg", { viewBox: `0 0 ${width} ${height}`, width, height, class: "chart-svg", role: "img",
      "aria-label": spec.label || "", focusable: "false" });
    host.appendChild(svg);

    for (const band of spec.bands || []) {
      const top = y(Math.min(band.to, d.max)), bottom = y(Math.max(band.from, d.min));
      if (bottom - top <= 0) continue;
      el("rect", { x: pad.left, y: top, width: width - pad.left - pad.right, height: bottom - top, class: `chart-band ${band.cls}` }, svg);
      if (band.label) {
        const text = el("text", { x: width - pad.right - 4, y: top + 13, class: "chart-band-label", "text-anchor": "end" }, svg);
        text.textContent = band.label;
      }
    }
    const axis = el("g", { class: "chart-axis", "aria-hidden": "true" }, svg);
    for (const v of d.ticks) {
      el("line", { x1: pad.left, x2: width - pad.right, y1: y(v), y2: y(v), class: "chart-grid" }, axis);
      const label = el("text", { x: pad.left - 6, y: y(v) + 4, "text-anchor": "end" }, axis);
      label.textContent = spec.axisValue ? spec.axisValue(v) : String(v);
    }
    const ticks = timeTicks(spec.start, spec.end, Math.max(3, Math.floor((width - pad.left) / 64)), spec.timeZone);
    for (const t of ticks) {
      el("line", { x1: x(t), x2: x(t), y1: height - pad.bottom, y2: height - pad.bottom + 4, class: "chart-tick" }, axis);
      const label = el("text", { x: x(t), y: height - 6, "text-anchor": "middle" }, axis);
      label.textContent = spec.axisTime ? spec.axisTime(t) : new Date(t).toISOString();
    }
    el("line", { x1: pad.left, x2: width - pad.right, y1: height - pad.bottom, y2: height - pad.bottom, class: "chart-base" }, axis);

    const y0 = y(Math.max(d.min, Math.min(0, d.max)));
    series.forEach((s, i) => {
      const g = el("g", { class: `chart-series ${s.cls || `series-${i + 1}`}` }, svg);
      for (const run of s.runs) {
        if (spec.kind === "area" || spec.kind === "step-area") {
          const area = spec.kind === "step-area" ? `${stepPath(run, x, y, spec.stepMs)}V${fixed(y0)}H${fixed(x(run[0].t))}Z` : areaPath(run, x, y, y0);
          el("path", { d: area, class: "chart-area" }, g);
        }
        if (run.length === 1 && spec.kind !== "step" && spec.kind !== "step-area") {
          el("circle", { cx: x(run[0].t), cy: y(run[0].v), r: 2.5, class: "chart-dot" }, g);
        } else {
          const path = spec.kind === "step" || spec.kind === "step-area" ? stepPath(run, x, y, spec.stepMs) : linePath(run, x, y);
          el("path", { d: path, class: "chart-line" }, g);
        }
      }
    });

    rule = el("line", { y1: pad.top, y2: height - pad.bottom, class: "chart-rule", visibility: "hidden" }, svg);
    dots = series.map((s, i) => el("circle", { r: 4.5, class: `chart-cursor ${s.cls || `series-${i + 1}`}`, visibility: "hidden" }, svg));
    // A wide transparent target: the whole plot answers the pointer, not only the thin line.
    const hit = el("rect", { x: pad.left, y: 0, width: width - pad.left - pad.right, height, class: "chart-hit" }, svg);
    hit.addEventListener("pointermove", (e) => point(e));
    hit.addEventListener("pointerdown", (e) => point(e));
    hit.addEventListener("pointerleave", (e) => { if (e.pointerType === "mouse") hide(); });

    tip = document.createElement("div");
    tip.className = "chart-tip";
    tip.hidden = true;
    tip.setAttribute("aria-hidden", "true");
    host.appendChild(tip);
    if (cursor >= 0) show(cursor);
  }

  function point(e) {
    const box = svg.getBoundingClientRect();
    const px = ((e.clientX - box.left) / box.width) * width;
    show(nearestIndex(grid, x.invert(px)));
  }

  function hide() {
    cursor = -1;
    if (rule) rule.setAttribute("visibility", "hidden");
    dots.forEach((dot) => dot.setAttribute("visibility", "hidden"));
    if (tip) tip.hidden = true;
  }

  function show(index) {
    if (index < 0 || !grid[index]) return hide();
    cursor = index;
    const t = grid[index].t;
    const cx = x(t);
    rule.setAttribute("x1", fixed(cx));
    rule.setAttribute("x2", fixed(cx));
    rule.setAttribute("visibility", "visible");
    const lines = [];
    series.forEach((s, i) => {
      const p = s.points[nearestIndex(s.points, t)];
      const known = p && p.v !== null && Math.abs(p.t - t) <= maxGap;
      if (known) {
        dots[i].setAttribute("cx", fixed(cx));
        dots[i].setAttribute("cy", fixed(y(p.v)));
        dots[i].setAttribute("visibility", "visible");
      } else {
        dots[i].setAttribute("visibility", "hidden");
      }
      lines.push({ label: s.label, cls: s.cls || `series-${i + 1}`, text: known ? spec.value(p.v, s) : (spec.noValue || "–") });
    });
    const head = document.createElement("strong");
    head.textContent = spec.tipTime ? spec.tipTime(t) : new Date(t).toISOString();
    const rows = lines.map((line) => {
      const row = document.createElement("span");
      row.className = "chart-tip-row";
      if (series.length > 1) {
        const key = document.createElement("i");
        key.className = `chart-key ${line.cls}`;
        row.appendChild(key);
        row.appendChild(document.createTextNode(`${line.label}: `));
      }
      const value = document.createElement("b");
      value.textContent = line.text;
      row.appendChild(value);
      return row;
    });
    tip.replaceChildren(head, ...rows);
    tip.hidden = false;
    // Positioned with the CSSOM (allowed by the CSP, unlike style attributes): beside the
    // cursor, flipped to the left in the right half so it never leaves the chart.
    const left = cx / width;
    tip.style.left = `${(left * 100).toFixed(2)}%`;
    tip.classList.toggle("flip", left > 0.5);
  }

  function key(e) {
    if (!grid.length) return;
    const step = e.shiftKey ? 10 : 1;
    let next = cursor < 0 ? grid.length - 1 : cursor;
    if (e.key === "ArrowLeft") next = Math.max(0, next - step);
    else if (e.key === "ArrowRight") next = Math.min(grid.length - 1, next + step);
    else if (e.key === "Home") next = 0;
    else if (e.key === "End") next = grid.length - 1;
    else if (e.key === "Escape") { hide(); return; }
    else return;
    e.preventDefault();
    show(next);
  }

  host.tabIndex = 0;
  host.addEventListener("keydown", key);
  host.addEventListener("blur", hide);
  draw();
  let frame = 0;
  const observer = typeof ResizeObserver === "function" ? new ResizeObserver(() => {
    if (Math.floor(host.clientWidth) === width) return;
    cancelAnimationFrame(frame);
    frame = requestAnimationFrame(draw);
  }) : null;
  if (observer) observer.observe(host);
  return { destroy() { if (observer) observer.disconnect(); host.removeEventListener("keydown", key); host.replaceChildren(); } };
}

/** Draw the connection timeline: one bar, a coloured span per access point connection, gaps
 *  for the time offline, ticks for roams, band changes and disconnects. spec = {spans, marks,
 *  start, end, slots, spanLabel(span) -> text, markLabel(mark) -> text, axisTime, timeZone,
 *  label, onSelect(text)}. Each span is focusable and has its own title for hover; a tap or
 *  focus calls onSelect with the same text (the page shows it below the bar). */
export function timelineChart(host, spec) {
  const height = 64, bar = { top: 8, height: 26 };
  const pad = { left: 4, right: 4 };
  let width = 0;
  function draw() {
    width = Math.max(240, Math.floor(host.clientWidth || 320));
    host.replaceChildren();
    const x = scaleLinear([spec.start, spec.end], [pad.left, width - pad.right]);
    const svg = el("svg", { viewBox: `0 0 ${width} ${height}`, width, height, class: "timeline-svg", role: "img",
      "aria-label": spec.label || "" });
    host.appendChild(svg);
    el("rect", { x: pad.left, y: bar.top, width: width - pad.left - pad.right, height: bar.height, rx: 4, class: "timeline-off" }, svg);
    for (const span of spec.spans) {
      const slot = spec.slots.get(apName(span.ap));
      const x0 = x(span.start), x1 = x(span.end);
      // a 2px surface gap between touching spans (a roam), and at least 2px of colour
      const w = Math.max(2, x1 - x0 - 2);
      const rect = el("rect", { x: fixed(x0 + 1), y: bar.top, width: fixed(w), height: bar.height, rx: Math.min(4, w / 2),
        class: `timeline-span ap-${slot === undefined ? "other" : slot}${span.ongoing ? " ongoing" : ""}${span.basis === "inferred" ? " inferred" : ""}` }, svg);
      const label = spec.spanLabel(span);
      const title = el("title", {}, rect);
      title.textContent = label;
      // touch has no hover title: a tap (or focus) hands the text to the page
      rect.setAttribute("tabindex", "0");
      rect.setAttribute("role", "button");
      rect.setAttribute("aria-label", label);
      if (spec.onSelect) {
        rect.addEventListener("click", () => spec.onSelect(label, rect));
        rect.addEventListener("focus", () => spec.onSelect(label, rect));
      }
    }
    for (const mark of spec.marks) {
      const cx = fixed(x(mark.t));
      const g = el("g", { class: `timeline-mark mark-${mark.kind}${mark.basis === "inferred" ? " inferred" : ""}` }, svg);
      if (mark.kind === "incident") {
        // the incident's time as a band over the bar (an open one to the end), its start as a line
        const end = mark.detail && mark.detail.open ? spec.end : mark.t + (mark.duration_s || 0) * 1000;
        el("rect", { x: cx, y: bar.top - 3, width: fixed(Math.max(2, x(Math.min(end, spec.end)) - x(mark.t))),
          height: bar.height + 6, class: "mark-band" }, g);
        el("line", { x1: cx, x2: cx, y1: bar.top - 4, y2: bar.top + bar.height + 4, class: "mark-line" }, g);
      } else if (mark.kind === "disconnected" || mark.kind === "session_ended") {
        el("line", { x1: cx, x2: cx, y1: bar.top - 3, y2: bar.top + bar.height + 3, class: "mark-line" }, g);
      } else if (mark.kind === "auth_rejected" || mark.kind === "mac_changed") {
        el("circle", { cx, cy: bar.top + bar.height + 6, r: 3.2, class: "mark-dot" }, g);
      } else {
        el("path", { d: `M${cx},${bar.top + bar.height + 2}l4,6h-8z`, class: "mark-tri" }, g);
      }
      const title = el("title", {}, g);
      title.textContent = spec.markLabel(mark);
    }
    const axis = el("g", { class: "chart-axis", "aria-hidden": "true" }, svg);
    for (const t of timeTicks(spec.start, spec.end, Math.max(3, Math.floor(width / 72)), spec.timeZone)) {
      const label = el("text", { x: fixed(x(t)), y: height - 4, "text-anchor": "middle" }, axis);
      label.textContent = spec.axisTime(t);
      el("line", { x1: fixed(x(t)), x2: fixed(x(t)), y1: bar.top + bar.height + 8, y2: bar.top + bar.height + 12, class: "chart-tick" }, axis);
    }
  }
  draw();
  const observer = typeof ResizeObserver === "function" ? new ResizeObserver(() => {
    if (Math.floor(host.clientWidth) !== width) requestAnimationFrame(draw);
  }) : null;
  if (observer) observer.observe(host);
  return { destroy() { if (observer) observer.disconnect(); host.replaceChildren(); } };
}

/** Day bars: one bar per day (grouped when there are two series), an optional mark per day
 *  (a thin line: the weakest tenth, the peak), a tooltip for mouse, touch and keyboard as the
 *  line chart's. spec = { series: [{label, points, cls}], start, end (ms), stepMs, y: {min,
 *  max, ticks?} or nothing (from the data, from zero), baseline: "min" (bars from the axis's
 *  bottom, not from zero), marks: {label, points, cls} | null,
 *  value(v, s) -> text, axisValue(v), axisTime(ms), tipTime(ms), label, height, axisWidth }. */
export function barChart(host, spec) {
  const height = spec.height || 180;
  const pad = { top: 10, right: 12, bottom: 24, left: spec.axisWidth || 52 };
  const series = spec.series.map((s) => ({ ...s, bars: dayBars(s.points, spec.stepMs) }));
  const grid = series[0]?.bars || [];
  const marks = spec.marks ? dayBars(spec.marks.points, spec.stepMs) : null;
  let cursor = -1, svg = null, tip = null, width = 0, geo = null, y = null, x = null, hl = [];

  function domainY() {
    if (spec.y && spec.y.min !== undefined) {
      const ticks = spec.y.ticks || niceTicks(spec.y.min, spec.y.max, 4).ticks.filter((v) => v >= spec.y.min && v <= spec.y.max);
      return { min: spec.y.min, max: spec.y.max, ticks };
    }
    const all = series.flatMap((s) => s.points).concat(marks ? spec.marks.points : []);
    const e = extent(all) || [0, 1];
    return niceTicks(Math.min(0, e[0]), Math.max(e[1], spec.minSpan || 0), 4);
  }

  function draw() {
    width = Math.max(240, Math.floor(host.clientWidth || 320));
    host.replaceChildren();
    const d = domainY();
    const end = grid.length ? grid[grid.length - 1].t1 : spec.end;
    x = scaleLinear([spec.start, end], [pad.left, width - pad.right]);
    y = scaleLinear([d.min, d.max], [height - pad.bottom, pad.top]);
    geo = barGeometry(grid.length, pad.left, width - pad.right, series.length);
    svg = el("svg", { viewBox: `0 0 ${width} ${height}`, width, height, class: "chart-svg", role: "img",
      "aria-label": spec.label || "", focusable: "false" });
    host.appendChild(svg);
    const axis = el("g", { class: "chart-axis", "aria-hidden": "true" }, svg);
    for (const v of d.ticks) {
      el("line", { x1: pad.left, x2: width - pad.right, y1: y(v), y2: y(v), class: "chart-grid" }, axis);
      const label = el("text", { x: pad.left - 6, y: y(v) + 4, "text-anchor": "end" }, axis);
      label.textContent = spec.axisValue ? spec.axisValue(v) : String(v);
    }
    for (const t of timeTicks(spec.start, end, Math.max(3, Math.floor((width - pad.left) / 64)), spec.timeZone)) {
      el("line", { x1: x(t), x2: x(t), y1: height - pad.bottom, y2: height - pad.bottom + 4, class: "chart-tick" }, axis);
      const label = el("text", { x: x(t), y: height - 6, "text-anchor": "middle" }, axis);
      label.textContent = spec.axisTime ? spec.axisTime(t) : new Date(t).toISOString();
    }
    el("line", { x1: pad.left, x2: width - pad.right, y1: height - pad.bottom, y2: height - pad.bottom, class: "chart-base" }, axis);
    // bars grow from zero, or from the bottom of the axis (spec.baseline "min": a signal in dBm)
    const base = y(spec.baseline === "min" ? d.min : Math.max(d.min, Math.min(0, d.max)));
    hl = [];
    series.forEach((s, gi) => {
      const g = el("g", { class: `chart-series ${s.cls || `series-${gi + 1}`}` }, svg);
      s.bars.forEach((b, i) => {
        if (b.v === null) return;
        const top = y(Math.min(d.max, Math.max(d.min, b.v)));
        const r = el("rect", { x: fixed(geo.x(i, gi)), y: fixed(Math.min(top, base)), width: fixed(geo.bar),
          height: fixed(Math.max(1, Math.abs(base - top))), rx: Math.min(2, geo.bar / 3), class: "chart-bar" }, g);
        (hl[i] ||= []).push(r);
      });
    });
    if (marks) {
      const g = el("g", { class: `chart-marks ${spec.marks.cls || ""}` }, svg);
      marks.forEach((m, i) => {
        if (m.v === null) return;
        const my = fixed(y(Math.min(d.max, Math.max(d.min, m.v))));
        el("line", { x1: fixed(geo.x(i) - 1), x2: fixed(geo.x(i, series.length) + 1), y1: my, y2: my, class: "chart-mark" }, g);
      });
    }
    const hit = el("rect", { x: pad.left, y: 0, width: width - pad.left - pad.right, height, class: "chart-bar-hit" }, svg);
    hit.addEventListener("pointermove", (e) => point(e));
    hit.addEventListener("pointerdown", (e) => point(e));
    hit.addEventListener("pointerleave", (e) => { if (e.pointerType === "mouse") hide(); });
    tip = document.createElement("div");
    tip.className = "chart-tip";
    tip.hidden = true;
    tip.setAttribute("aria-hidden", "true");
    host.appendChild(tip);
    if (cursor >= 0) show(cursor);
  }

  function point(e) {
    const box = svg.getBoundingClientRect();
    const px = ((e.clientX - box.left) / box.width) * width;
    const i = Math.floor((px - pad.left) / (geo.slot || 1));
    show(Math.max(0, Math.min(grid.length - 1, i)));
  }
  function hide() {
    cursor = -1;
    for (const list of hl) for (const r of list || []) r.classList.remove("active");
    if (tip) tip.hidden = true;
  }
  function show(i) {
    if (i < 0 || !grid[i]) return hide();
    hide();
    cursor = i;
    for (const r of hl[i] || []) r.classList.add("active");
    const head = document.createElement("strong");
    head.textContent = spec.tipTime ? spec.tipTime(grid[i].t0) : new Date(grid[i].t0).toISOString();
    const rows = series.map((s, gi) => {
      const row = document.createElement("span");
      row.className = "chart-tip-row";
      if (series.length > 1) {
        const key = document.createElement("i");
        key.className = `chart-key ${s.cls || `series-${gi + 1}`}`;
        row.appendChild(key);
        row.appendChild(document.createTextNode(`${s.label}: `));
      }
      const value = document.createElement("b");
      value.textContent = s.bars[i] && s.bars[i].v !== null ? spec.value(s.bars[i].v, s) : (spec.noValue || "–");
      row.appendChild(value);
      return row;
    });
    if (marks && marks[i] && marks[i].v !== null) {
      const row = document.createElement("span");
      row.className = "chart-tip-row";
      row.appendChild(document.createTextNode(`${spec.marks.label}: `));
      const value = document.createElement("b");
      value.textContent = spec.value(marks[i].v, spec.marks);
      row.appendChild(value);
      rows.push(row);
    }
    tip.replaceChildren(head, ...rows);
    tip.hidden = false;
    const left = (geo.x(i) + geo.slot / 2) / width;
    tip.style.left = `${(left * 100).toFixed(2)}%`;
    tip.classList.toggle("flip", left > 0.5);
  }
  function key(e) {
    if (!grid.length) return;
    const step = e.shiftKey ? 7 : 1;
    let next = cursor < 0 ? grid.length - 1 : cursor;
    if (e.key === "ArrowLeft") next = Math.max(0, next - step);
    else if (e.key === "ArrowRight") next = Math.min(grid.length - 1, next + step);
    else if (e.key === "Home") next = 0;
    else if (e.key === "End") next = grid.length - 1;
    else if (e.key === "Escape") { hide(); return; }
    else return;
    e.preventDefault();
    show(next);
  }
  host.tabIndex = 0;
  host.addEventListener("keydown", key);
  host.addEventListener("blur", hide);
  draw();
  let frame = 0;
  const observer = typeof ResizeObserver === "function" ? new ResizeObserver(() => {
    if (Math.floor(host.clientWidth) === width) return;
    cancelAnimationFrame(frame);
    frame = requestAnimationFrame(draw);
  }) : null;
  if (observer) observer.observe(host);
  return { destroy() { if (observer) observer.disconnect(); host.removeEventListener("keydown", key); host.replaceChildren(); } };
}

/** Incidents over time: a lane per kind and subject (its label above it), a bar per incident
 *  (an open one to the end; estimated ones dashed). Each bar is focusable with its own title;
 *  a tap or focus hands the text to the page (onSelect). spec = { lanes, items, start, end,
 *  laneLabel(lane), itemLabel(item), axisTime, timeZone, label, onSelect }. */
export function laneChart(host, spec) {
  const lane = { label: 14, bar: 12, gap: 8 };
  const pad = { left: 4, right: 4, bottom: 18 };
  let width = 0;
  function draw() {
    width = Math.max(240, Math.floor(host.clientWidth || 320));
    host.replaceChildren();
    const rowH = lane.label + lane.bar + lane.gap;
    const height = spec.lanes.length * rowH + pad.bottom;
    const x = scaleLinear([spec.start, spec.end], [pad.left, width - pad.right]);
    const svg = el("svg", { viewBox: `0 0 ${width} ${height}`, width, height, class: "timeline-svg", role: "img",
      "aria-label": spec.label || "" });
    host.appendChild(svg);
    spec.lanes.forEach((l, i) => {
      const top = i * rowH;
      const text = el("text", { x: pad.left, y: top + 11, class: "lane-label" }, svg);
      text.textContent = spec.laneLabel(l);
      el("rect", { x: pad.left, y: top + lane.label, width: width - pad.left - pad.right, height: lane.bar, rx: 3, class: "lane-track" }, svg);
    });
    for (const item of spec.items) {
      const top = item.lane * rowH + lane.label;
      const x0 = x(item.start), w = Math.max(3, x(item.end) - x0);
      const rect = el("rect", { x: fixed(x0), y: top, width: fixed(w), height: lane.bar, rx: Math.min(3, w / 2),
        class: `lane-item${item.open ? " open" : ""}${item.inc.basis === "inferred" ? " inferred" : ""}`, tabindex: 0, role: "button" }, svg);
      const label = spec.itemLabel(item);
      rect.setAttribute("aria-label", label);
      const title = el("title", {}, rect);
      title.textContent = label;
      if (spec.onSelect) {
        rect.addEventListener("click", () => spec.onSelect(label, item));
        rect.addEventListener("focus", () => spec.onSelect(label, item));
      }
    }
    const axis = el("g", { class: "chart-axis", "aria-hidden": "true" }, svg);
    for (const t of timeTicks(spec.start, spec.end, Math.max(3, Math.floor(width / 80)), spec.timeZone)) {
      const label = el("text", { x: fixed(x(t)), y: height - 4, "text-anchor": "middle" }, axis);
      label.textContent = spec.axisTime(t);
    }
  }
  draw();
  const observer = typeof ResizeObserver === "function" ? new ResizeObserver(() => {
    if (Math.floor(host.clientWidth) !== width) requestAnimationFrame(draw);
  }) : null;
  if (observer) observer.observe(host);
  return { destroy() { if (observer) observer.disconnect(); host.replaceChildren(); } };
}
