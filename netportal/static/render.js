// The dashboard's live parts as DOM, for the refresh: the same markup as templates/_dash.html
// (state line, facts, findings, house strip, banners, the admin row's summary). Change both.
// Text goes in as text nodes only (never innerHTML): names and AP names come from users.

const SVG = "http://www.w3.org/2000/svg";
export const STATE_ICON = { online: "wifi", offline: "wifi-off", never_connected: "never", unknown: "help" };
export const TONE_ICON = { ok: "check", warn: "warn", bad: "bad", info: "info", unknown: "help" };
const HOUSE_TONE = { ok: "ok", degraded: "warn", down: "bad" };
// The data a finding rests on: its params, else the device's own value (as in _dash.html).
const EVIDENCE = {
  weak_signal: ["signal_dbm", "dbm"], low_snr: ["snr_db", "db"], high_retries: ["retry_ratio", "percent"],
  busy_channel: ["channel_util", "percent"], unstable_roaming: ["roams_1h", "per_hour"],
  frequent_disconnects: ["reconnects_24h", "times_24h"], slow_link: ["link_rx_bps", "bitrate"],
  stale_data: ["age_s", "duration"],
};

/** h("p", {class: "x"}, "text", node, …): an element with attributes and children. */
export function h(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    node.setAttribute(k, v === true ? "" : String(v));
  }
  append(node, children);
  return node;
}

function append(node, children) {
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false || child === "") continue;
    node.appendChild(typeof child === "string" || typeof child === "number" ? document.createTextNode(String(child)) : child);
  }
  return node;
}

export function icon(name, cls = "") {
  const svg = document.createElementNS(SVG, "svg");
  svg.setAttribute("class", cls ? `icon ${cls}` : "icon");
  svg.setAttribute("aria-hidden", "true");
  const use = document.createElementNS(SVG, "use");
  use.setAttribute("href", `#i-${name}`);
  svg.appendChild(use);
  return svg;
}

/** A text with placeholders, some of them nodes: "since {time} ({duration})". */
export function fillNodes(template, values) {
  const out = [];
  let last = 0;
  String(template).replace(/\{(\w+)\}/g, (all, key, at) => {
    out.push(template.slice(last, at));
    out.push(key in values ? values[key] : all);
    last = at + all.length;
    return all;
  });
  out.push(template.slice(last));
  return out.filter((x) => x !== "");
}

const known = (v) => v !== null && v !== undefined;

export function timeEl(f, iso, kind = "when", now = Date.now()) {
  const text = kind === "ago" ? f.ago(iso, now) : kind === "date" ? f.date(iso) : f.when(iso, now);
  return h("time", { datetime: iso }, text);
}

export function stateLine(d, f, ctx) {
  const t = f.t, state = d.state || "unknown";
  const more = (...nodes) => [" ", h("span", { class: "state-more" }, ...nodes)];
  let extra = [];
  if (state === "online" && d.since) {
    const seconds = (ctx.now - Date.parse(d.since)) / 1000;
    extra = more(fillNodes(t("since_line"), { time: timeEl(f, d.since, "when", ctx.now), duration: f.duration(seconds) }));
  } else if (state === "never_connected") {
    extra = more(f.fill(t("never_line"), { ssid: ctx.ssid || "" }));
  } else if (d.last_seen) {
    extra = more(fillNodes(t("seen_line"), { when: timeEl(f, d.last_seen, "ago", ctx.now) }));
  } else if (state === "unknown" && !(d.diagnostics || []).length) {
    extra = more(t("unknown_line"));
  }
  return h("p", { class: `dev-state state-${state}`, "data-part": "state" },
    icon(STATE_ICON[state] || "help"), h("strong", {}, t(`state_${state}`)), extra);
}

export function bars(n, tone) {
  const svg = document.createElementNS(SVG, "svg");
  svg.setAttribute("class", `bars tone-${tone}`);
  svg.setAttribute("viewBox", "0 0 20 16");
  svg.setAttribute("aria-hidden", "true");
  for (let i = 0; i < 4; i++) {
    const r = document.createElementNS(SVG, "rect");
    r.setAttribute("x", String(i * 5 + 0.5));
    r.setAttribute("y", String(12 - i * 4));
    r.setAttribute("width", "3.5");
    r.setAttribute("height", String(4 + i * 4));
    r.setAttribute("rx", "1");
    if (i < n) r.setAttribute("class", "on");
    svg.appendChild(r);
  }
  return svg;
}

export function meter(score, tone) {
  const svg = document.createElementNS(SVG, "svg");
  svg.setAttribute("class", `meter tone-${tone}`);
  svg.setAttribute("viewBox", "0 0 100 8");
  svg.setAttribute("preserveAspectRatio", "none");
  svg.setAttribute("aria-hidden", "true");
  for (const [cls, width] of [["track", 100], ["fill", Math.max(0, Math.min(100, score))]]) {
    const r = document.createElementNS(SVG, "rect");
    r.setAttribute("class", cls);
    r.setAttribute("width", String(width));
    r.setAttribute("height", "8");
    r.setAttribute("rx", "4");
    svg.appendChild(r);
  }
  return svg;
}

function dirPair(f, down, up, format) {
  return [
    h("span", { class: "dir" }, h("span", { "aria-hidden": "true" }, "↓"), h("span", { class: "sr" }, f.t("dir_down")), " ", format(down)),
    "\n",
    h("span", { class: "dir" }, h("span", { "aria-hidden": "true" }, "↑"), h("span", { class: "sr" }, f.t("dir_up")), " ", format(up)),
  ];
}

const fact = (label, dd, wide = false) => h("div", { class: wide ? "fact wide" : "fact" }, h("dt", {}, label), dd);

export function live(d, f) {
  const t = f.t, out = [];
  if (d.ap) {
    const wifi = d.band || d.channel || d.proto ? h("span", { class: "sub" }, f.wifi(d)) : null;
    out.push(fact(t("f_room"), h("dd", {}, f.room(d.ap), wifi), true));
  }
  if (known(d.signal_dbm)) {
    const lvl = f.signalLevel(d.signal_dbm);
    out.push(fact(t("f_signal"), h("dd", { class: "with-mark" }, bars(lvl.bars, lvl.tone),
      h("span", {}, f.dbm(d.signal_dbm), h("span", { class: `sub tone-text-${lvl.tone}` }, t(lvl.key))))));
  }
  if (known(d.health)) {
    const q = f.healthLevel(d.health);
    out.push(fact(t("f_quality"), h("dd", { class: "with-mark" }, meter(d.health, q.tone),
      h("span", {}, f.fill(t("quality_fmt"), { n: Math.round(d.health) }), h("span", { class: `sub tone-text-${q.tone}` }, t(q.key))))));
  }
  if (known(d.rx_bps) || known(d.tx_bps)) out.push(fact(t("f_now"), h("dd", { class: "pair" }, dirPair(f, d.rx_bps, d.tx_bps, f.bitrate))));
  if (known(d.rx_24h_bytes) || known(d.tx_24h_bytes)) {
    out.push(fact(t("f_24h"), h("dd", { class: "pair" }, dirPair(f, d.rx_24h_bytes, d.tx_24h_bytes, f.bytes))));
  }
  if (known(d.link_rx_bps) || known(d.link_tx_bps)) {
    out.push(h("div", { class: "fact" }, h("dt", {}, h("abbr", { title: t("f_link_hint") }, t("f_link"))),
      h("dd", { class: "pair" }, dirPair(f, d.link_rx_bps, d.link_tx_bps, f.bitrate), h("span", { class: "sub" }, t("f_link_note")))));
  }
  return h("dl", { class: "facts", "data-part": "live" }, out);
}

export function evidence(finding, d, f) {
  const e = EVIDENCE[finding.code];
  if (!e) return null;
  const params = finding.params || {};
  const v = e[0] in params ? params[e[0]] : d[e[0]];
  if (!known(v)) return null;
  const text = e[1] === "per_hour" ? f.fill(f.t("per_hour"), { n: f.number(v) })
    : e[1] === "times_24h" ? f.fill(f.t("times_24h"), { n: v })
      : f[e[1]](v);
  return h("span", { class: "evidence" }, text);
}

export function findings(d, f, { full = false, telemetry = "ok", limit = 0, admin = false } = {}) {
  const t = f.t, texts = (key) => (f.t(key) === key ? null : f.t(key));
  const all = d.diagnostics || [];
  const list = limit ? all.slice(0, limit) : all;
  const box = h("div", { class: "diag", "data-part": "diag" });
  if (list.length) {
    box.appendChild(h("ul", { class: "findings" }, list.map((finding) => {
      const sev = ["info", "warn", "bad"].includes(finding.severity) ? finding.severity : "info";
      const key = `diag_${finding.code}`;
      // an admin's own texts (with {n} from the params), when the finding has them
      const n = finding.params?.owners;
      const adminWhy = admin && n !== undefined && n !== null ? texts(`${key}_admin_why`) : null;
      const why = full || admin ? (adminWhy ? f.fill(adminWhy, { n }) : texts(`${key}_why`)) : null;
      const todo = (admin && texts(`${key}_admin_do`)) || texts(`${key}_do`);
      return h("li", { class: `finding sev-${sev}` }, icon(TONE_ICON[sev]), h("div", {},
        h("p", { class: "finding-title" }, h("span", { class: "sr" }, `${t(`sev_${sev}`)}: `), texts(key) || finding.code, " ", evidence(finding, d, f)),
        why ? h("p", { class: "finding-why" }, why) : null,
        todo ? h("p", { class: "finding-do" }, h("strong", {}, t("diag_do_label")), " ", todo) : null));
    })));
    if (all.length > list.length) {
      box.appendChild(h("p", { class: "diag-more" }, h("a", { href: `/devices/${encodeURIComponent(d.id)}` },
        f.fill(t("diag_more"), { n: all.length - list.length }))));
    }
  } else if (d.state === "online" && telemetry === "ok") {
    box.appendChild(h("p", { class: "all-good" }, icon("check"), t("all_good")));
  }
  return box;
}

export function houseStrip(house, f, now = Date.now()) {
  const t = f.t, hs = house || {};
  const tile = (status, iconName, label, extra) => {
    const tone = HOUSE_TONE[status || "unknown"] || "unknown";
    return h("li", { class: `hs tone-${tone}` }, icon(iconName, "hs-icon"), h("span", { class: "hs-label" }, label),
      h("strong", { class: "hs-value" }, icon(TONE_ICON[tone]), t(`st_${status || "unknown"}`)), extra);
  };
  let ping = null;
  if (known(hs.internet_rtt_ms)) {
    ping = h("span", { class: "hs-sub" }, f.fill(t("house_ping"), { ms: f.ms(hs.internet_rtt_ms) }),
      hs.internet_loss_ratio ? ` · ${f.fill(t("house_loss"), { pct: f.percent(hs.internet_loss_ratio) })}` : "");
  }
  const st = hs.speedtest;
  const speed = h("li", { class: "hs speed" }, icon("speed", "hs-icon"), h("span", { class: "hs-label" }, t("house_speed")),
    st ? [h("strong", { class: "hs-value" }, f.fill(t("house_speed_value"), { down: f.bitrate(st.download_bps), up: f.bitrate(st.upload_bps) })),
      h("span", { class: "hs-sub" }, fillNodes(t("house_speed_at"), { when: timeEl(f, st.at, "when", now) }),
        known(st.ping_ms) ? ` · ${f.fill(t("house_ping"), { ms: f.ms(st.ping_ms) })}` : "")]
      : h("strong", { class: "hs-value" }, t("house_speed_none")));
  return h("section", { class: "card house", "aria-labelledby": "house-h", "data-part": "house" },
    h("h2", { id: "house-h" }, t("house_title")),
    h("ul", { class: "house-grid" },
      tile(hs.internet, "globe", t("house_internet"), ping),
      tile(hs.dns, "signpost", t("house_dns")),
      tile(hs.router, "router", t("house_router")),
      speed),
    h("p", { class: "hs-note" }, t("house_speed_note")));
}

/** The data's own banners (telemetry, staleness) plus the script's (`extra`: [{tone, nodes}]). */
export function banners(dash, f, extra = [], now = Date.now()) {
  const t = f.t, out = [];
  const banner = (tone, ...nodes) => h("p", { class: `banner tone-${tone}` }, icon(TONE_ICON[tone]), h("span", {}, ...nodes));
  for (const b of extra) out.push(banner(b.tone, ...b.nodes));
  if (dash) {
    if (dash.telemetry === "off") out.push(banner("info", t("telemetry_off")));
    else if (dash.telemetry === "unavailable") out.push(banner("warn", t("telemetry_unavailable")));
    if (dash.stale) out.push(banner("warn", fillNodes(t("live_stale"), { when: timeEl(f, dash.generated_at, "when", now) })));
    const age = dash.house && dash.house.wifi_data_age_s;
    if (age && age > 300) out.push(banner("warn", f.fill(t("house_wifi_age"), { age: f.duration(age) })));
  }
  return h("div", { class: "banners", "data-part": "banners" }, out);
}

export function bannerNodes(tone, ...nodes) {
  return { tone, nodes };
}

// --- the admin list's row summary ----------------------------------------------------------

export function problemsOf(d) {
  return (d.diagnostics || []).filter((x) => x.severity === "warn" || x.severity === "bad");
}

export function summaryParts(d, f) {
  const t = f.t, problems = problemsOf(d);
  const lvl = known(d.signal_dbm) ? f.signalLevel(d.signal_dbm) : null;
  const worst = problems.some((x) => x.severity === "bad") ? "bad" : "warn";
  return {
    "sum-state": h("span", { class: `adm-state state-${d.state}`, "data-part": "sum-state" }, icon(STATE_ICON[d.state] || "help"),
      h("span", { class: "sr" }, t(`state_${d.state}`))),
    "sum-name": h("strong", { class: "adm-name", "data-part": "sum-name" }, d.name),
    "sum-room": h("span", { class: "adm-room", "data-part": "sum-room" }, d.ap ? f.room(d.ap) : t(`state_${d.state}`)),
    "sum-signal": h("span", { class: "adm-signal", "data-part": "sum-signal" }, lvl ? [bars(lvl.bars, lvl.tone), f.dbm(d.signal_dbm)] : null),
    "sum-badge": h("span", { class: "adm-badge", "data-part": "sum-badge" }, problems.length
      ? h("span", { class: `badge sev-${worst}` }, icon(TONE_ICON[worst]), f.fill(t("adm_problems_n"), { n: problems.length })) : null),
  };
}

// --- the connection list -------------------------------------------------------------------

export function eventText(e, f) {
  const t = f.t;
  const where = (ap) => f.room(ap && typeof ap === "object" ? ap : ap ? { name: ap } : null);
  const band = (b) => (b ? f.bandName(b) : "–");
  if (e.kind === "connected") {
    return [f.fill(t("tl_connected"), { where: where(e.ap) + (e.band ? ` (${band(e.band)})` : "") }),
      e.duration_s ? h("span", { class: "muted" }, " ", f.fill(t("tl_for"), { duration: f.duration(e.duration_s) })) : null];
  }
  if (e.kind === "disconnected") {
    return [t("tl_disconnected"), e.duration_s ? h("span", { class: "muted" }, " ", f.fill(t("tl_for"), { duration: f.duration(e.duration_s) })) : null];
  }
  if (e.kind === "roamed") return [f.fill(t("tl_roamed"), { old: where(e.from_ap), new: where(e.ap) })];
  if (e.kind === "band_changed") return [f.fill(t("tl_band"), { old: band(e.from_band), new: band(e.band) })];
  return [e.kind];
}

export function eventList(events, f, now = Date.now(), limit = 50) {
  const sorted = [...(events || [])].sort((a, b) => Date.parse(b.at) - Date.parse(a.at)).slice(0, limit);
  if (!sorted.length) return [h("li", { class: "ev ev-none" }, f.t("tl_none"))];
  return sorted.map((e) => h("li", { class: `ev ev-${e.kind}` },
    h("span", { class: "ev-time" }, timeEl(f, e.at, "when", now)), h("span", { class: "ev-text" }, eventText(e, f))));
}
