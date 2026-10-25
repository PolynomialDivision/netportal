// The dashboard's live parts as DOM, for the refresh: the same markup as templates/_dash.html
// (state line, facts, findings, house strip, banners, the admin row's summary). Change both.
// Text goes in as text nodes only (never innerHTML): names and AP names come from users.

import { findingsShown, PRESENCE_ICON, presenceOf, presenceView, RELATIVE_KINDS, relText, segmentParts, stateOf } from "./presence.js";

const SVG = "http://www.w3.org/2000/svg";
export const STATE_ICON = PRESENCE_ICON;
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

/** <time>: "when" (14:05), "date", or "ago" (5 min ago, kept current by the page: data-rel). */
export function timeEl(f, iso, kind = "when", now = Date.now()) {
  const text = kind === "ago" ? f.ago(iso, now) : kind === "date" ? f.date(iso) : f.when(iso, now);
  return h("time", { datetime: iso, "data-rel": kind === "ago" ? "ago" : null }, text);
}

/** A presence moment ({time, kind, text, title}): the time to the second in its title; the
 *  relative ones carry data-rel (the page updates their text without a request). */
export function momentEl(m) {
  return h("time", { datetime: m.time, title: m.title, "data-rel": RELATIVE_KINDS.includes(m.kind) ? m.kind : null }, m.text);
}

/** Every <time data-rel> under root, as of `now` (no request: between two polls). */
export function tickTimes(root, f, now = Date.now()) {
  let changed = 0;
  for (const node of root.querySelectorAll("time[data-rel]")) {
    const text = relText(f, node.getAttribute("data-rel"), node.getAttribute("datetime"), now);
    if (node.textContent !== text) { node.textContent = text; changed += 1; }
  }
  return changed;
}

export function segmentNodes(segment) {
  return segmentParts(segment).map(([kind, v]) => (kind === "time" ? momentEl(v) : v)).filter((x) => x !== "");
}

/** The state under the name: icon, the word, since when or why (presence.js presenceView),
 *  and which source confirmed it when (templates/_dash.html state_line). */
export function stateLine(d, f, ctx) {
  const v = presenceView(d, f, ctx.now, { ssid: ctx.ssid || "" });
  const more = v.more.flatMap((seg, i) => [i ? " · " : "", ...segmentNodes(seg)]);
  return h("p", { class: `dev-state state-${v.state}`, "data-part": "state" },
    icon(v.icon), h("strong", {}, v.label),
    more.length ? [" ", h("span", { class: "state-more" }, more)] : null,
    v.confirmed ? [" ", h("span", { class: "state-confirmed" }, segmentNodes(v.confirmed))] : null);
}

const atMs = (e) => { const v = Date.parse(e && e.at); return Number.isNaN(v) ? -Infinity : v; };
const newestFirst = (list) => list.filter((e) => e && typeof e === "object").sort((a, b) => (atMs(b) > atMs(a) ? 1 : atMs(b) < atMs(a) ? -1 : 0));

/** An admin's view of how the state was decided: reason code, basis, the session (AP, started,
 *  updated), when it counts as stale, the poll hint and the evidence (templates/_dash.html
 *  presence_admin). */
export function presenceAdmin(d, f, now = Date.now()) {
  const t = f.t, p = presenceOf(d);
  const box = h("div", { class: "presence-admin", "data-part": "presence" });
  if (p.derived) return box;
  const when = (v) => (v ? momentEl({ time: v, kind: "recent", text: f.recent(v, now), title: f.stamp(v) }) : "–");
  const src = (s) => { const k = `src_admin_${s}`; return t(k) === k ? String(s ?? "–") : t(k); };
  const row = (label, ...dd) => h("div", {}, h("dt", {}, label), h("dd", {}, ...dd));
  const s = p.session;
  const apOf = (ap) => (ap && typeof ap === "object" ? f.room(ap) : ap ? f.room(f.apFromName(ap)) : null);
  const rows = [
    row(t("pr_admin_state"), h("span", { class: "mono" }, p.state),
      p.basis ? [" · ", t(`basis_${p.basis}`) === `basis_${p.basis}` ? p.basis : t(`basis_${p.basis}`)] : null),
    row(t("pr_admin_reason"), h("span", { class: "mono" }, p.reason || "–"),
      p.reason ? [" ", h("span", { class: "muted" }, t(`pr_reason_${p.reason}`) === `pr_reason_${p.reason}` ? t("pr_reason_other") : t(`pr_reason_${p.reason}`))] : null),
    row(t("pr_admin_since"), when(p.since)),
    row(t("pr_admin_confirmed"), when(p.confirmed_at), p.confirmed_by ? [" · ", src(p.confirmed_by)] : null),
    row(t("pr_admin_session"), s ? [
      apOf(s.ap) ? [apOf(s.ap), " "] : null,
      s.nas_ip ? h("span", { class: "mono muted" }, s.nas_ip) : null,
      s.acct_session_id ? [" ", h("span", { class: "mono muted" }, s.acct_session_id)] : null,
      h("br"),
      s.started ? fillNodes(t("pr_admin_started"), { when: when(s.started) }) : null,
      s.updated ? [s.started ? " · " : "", fillNodes(t("pr_admin_updated"), { when: when(s.updated) })] : null,
      s.stopped ? [" · ", fillNodes(t("pr_admin_stopped"), { when: when(s.stopped) })] : null,
      s.cause ? [" ", h("span", { class: "mono muted" }, String(s.cause))] : null,
      s.interim_s ? [" · ", f.fill(t("pr_admin_interim"), { duration: f.duration(s.interim_s) }),
        s.interim_basis ? [" ", h("span", { class: "muted" }, `(${t(`basis_${s.interim_basis}`) === `basis_${s.interim_basis}` ? s.interim_basis : t(`basis_${s.interim_basis}`)})`)] : null] : null,
    ] : h("span", { class: "muted" }, t("pr_admin_session_none"))),
    p.stale_after_s ? row(t("pr_admin_stale_after"), f.fill(t("pr_admin_stale_value"), { duration: f.duration(p.stale_after_s) }),
      " ", h("span", { class: "mono muted" }, `${p.stale_after_s} s`)) : null,
    p.poll_s ? row(t("pr_admin_poll"), f.duration(p.poll_s)) : null,
    row(t("pr_admin_evidence"), p.evidence.length
      ? h("ol", { class: "pr-evidence" }, newestFirst(p.evidence).slice(0, 20).map((e) =>
        h("li", {}, when(e.at), " · ", src(e.source), " · ", h("span", { class: "mono" }, String(e.kind ?? "–")))))
      : h("span", { class: "muted" }, t("pr_admin_evidence_none"))),
  ];
  box.appendChild(h("details", { class: "pr-admin" }, h("summary", {}, icon("list"), t("pr_admin_title")),
    h("dl", { class: "mini-kv" }, rows)));
  return box;
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

/** "estimated": a value or event worked out from other data, with its meaning. */
export function basisTag(basis, f) {
  if (basis !== "inferred") return null;
  return h("span", { class: "basis-tag", title: f.t("basis_inferred_hint") }, f.t("basis_inferred"),
    h("span", { class: "sr" }, `: ${f.t("basis_inferred_hint")}`));
}

/** A v2 finding's whole "based on" line (detail page, admins). */
export function evidenceLine(finding, f, admin = false) {
  const t = f.t;
  const { items, window } = f.evidenceItems(finding, admin);
  if (!items.length && !window && finding.basis !== "inferred") return null;
  const parts = [];
  items.forEach(([label, value], i) => parts.push(i ? " · " : " ", `${label} `, h("b", {}, value)));
  if (window) parts.push(` ${window}`);
  if (finding.basis === "inferred") parts.push(" ", h("span", { class: "basis-note" }, `(${t("basis_inferred")}: ${t("basis_inferred_hint")})`));
  else if (finding.basis === "measured" && admin) parts.push(" ", h("span", { class: "basis-note" }, `(${t("basis_measured")})`));
  return h("p", { class: "finding-basis" }, icon("info"), h("span", {}, h("strong", {}, t("ev_based_on")), parts));
}

/** The number an admin text's {n} stands for (owners, count, macs_30d). */
function adminN(finding) {
  const p = finding.params || {};
  for (const key of ["owners", "count", "macs_30d", "n"]) if (known(p[key])) return p[key];
  return null;
}

export function findings(d, f, { full = false, telemetry = "ok", limit = 0, admin = false } = {}) {
  const t = f.t, texts = (key) => (f.t(key) === key ? null : f.t(key));
  const all = findingsShown(d);
  const list = limit ? all.slice(0, limit) : all;
  const box = h("div", { class: "diag", "data-part": "diag" });
  if (list.length) {
    box.appendChild(h("ul", { class: "findings" }, list.map((finding) => {
      const sev = ["info", "warn", "bad"].includes(finding.severity) ? finding.severity : "info";
      const key = `diag_${finding.code}`;
      // an admin's own texts (with {n} from the params), when the finding has them
      const n = adminN(finding);
      const adminWhy = admin && n !== null ? texts(`${key}_admin_why`) : null;
      const why = full || admin ? (adminWhy ? f.fill(adminWhy, { n }) : texts(`${key}_why`)) : null;
      const todo = (admin && texts(`${key}_admin_do`)) || texts(`${key}_do`);
      let inline = null;
      if (finding.evidence) {
        if (!(full || admin)) {
          const short = f.evidenceShort(finding);
          inline = short ? h("span", { class: "evidence" }, short) : null;
        }
      } else {
        inline = evidence(finding, d, f);
      }
      return h("li", { class: `finding sev-${sev}${finding.basis === "inferred" ? " inferred" : ""}` }, icon(TONE_ICON[sev]), h("div", {},
        h("p", { class: "finding-title" }, h("span", { class: "sr" }, `${t(`sev_${sev}`)}: `), texts(key) || finding.code, " ", inline,
          basisTag(finding.basis, f)),
        why ? h("p", { class: "finding-why" }, why) : null,
        (full || admin) && finding.evidence ? evidenceLine(finding, f, admin) : null,
        todo ? h("p", { class: "finding-do" }, h("strong", {}, t("diag_do_label")), " ", todo) : null));
    })));
    if (all.length > list.length) {
      box.appendChild(h("p", { class: "diag-more" }, h("a", { href: `/devices/${encodeURIComponent(d.id)}` },
        f.fill(t("diag_more"), { n: all.length - list.length }))));
    }
  } else if (stateOf(d) === "online" && telemetry === "ok") {
    box.appendChild(h("p", { class: "all-good" }, icon("check"), t("all_good")));
  }
  return box;
}

// --- how the device connects (telemetry v2) ------------------------------------------------

const MM_ICON = { hardware: "fingerprint", random_fixed: "check", rotating: "refresh" };
export const EVENT_ICON = { authenticated: "login", auth_rejected: "reject", connected: "wifi", disconnected: "wifi-off",
  reconnected: "refresh", roamed: "roam", band_changed: "band", mac_changed: "tag", session_ended: "stop", incident: "bolt" };

/** The latest login was rejected: what it means and what to do. */
export function authAlert(d, f, ctx, admin = false) {
  const t = f.t, la = d.last_auth;
  const box = h("div", { class: "auth-alert", "data-part": "auth-alert" });
  if (!la || la.result !== "reject") return box;
  const rk = f.reasonKey(la.reason);
  const todo = t(`rr_${rk}_do`);
  box.appendChild(h("div", { class: "alert tone-bad" }, icon("reject"), h("div", {},
    h("p", { class: "alert-title" }, t("la_rejected_title")),
    h("p", {}, h("strong", {}, t("la_reason")), " ", t(`rr_${rk}`),
      admin ? [" ", h("span", { class: "mono muted" }, `${la.reason} · ${t(`rr_${rk}_admin`)}`)] : null),
    todo && todo !== `rr_${rk}_do` ? h("p", {}, h("strong", {}, t("la_do")), " ", f.fill(todo, { ssid: ctx.ssid || "" })) : null,
    h("p", { class: "alert-when" }, fillNodes(t("la_rejected_when"), { when: timeEl(f, la.at, "when", ctx.now) })))));
  return box;
}

/** The Wi-Fi address it uses and the last login; for a changing address how to choose "fixed". */
export function howConnects(d, f, ctx, { full = false, admin = false } = {}) {
  const t = f.t;
  const mode = MM_ICON[d.mac_mode] ? d.mac_mode : null;
  const la = d.last_auth || null;
  const box = h("div", { class: "conn", "data-part": "conn" });
  if (!mode && !la) return box;
  const lines = [];
  if (mode) {
    lines.push(h("div", { class: `conn-line mm-${mode}` }, h("dt", {}, t("mm_label")), h("dd", {}, icon(MM_ICON[mode]), h("span", {},
      h("strong", {}, t(`mm_${mode}`)),
      full || mode === "rotating" ? h("span", { class: "sub" }, t(`mm_${mode}_sub`)) : null,
      admin ? h("span", { class: "sub mono" }, t(`mm_admin_${mode}`),
        d.macs && d.macs.length ? ` · ${f.fill(t("mm_addresses"), { n: d.macs.length })}` : "") : null))));
  }
  if (la) {
    const rejected = la.result === "reject";
    lines.push(h("div", { class: `conn-line la-${rejected ? "reject" : "accept"}` }, h("dt", {}, t("la_label")),
      h("dd", {}, icon(rejected ? "reject" : "login"),
        h("span", {}, fillNodes(t(rejected ? "la_reject" : "la_accept"), { when: timeEl(f, la.at, "ago", ctx.now) })))));
  }
  box.appendChild(h("dl", { class: "conn-lines" }, lines));
  if (mode === "rotating") {
    const how = t(`mm_how_${ctx.platform || d.platform}`);
    const text = how === `mm_how_${ctx.platform || d.platform}` ? t("mm_how_other") : how;
    box.appendChild(h("div", { class: "advice" }, h("p", {}, h("strong", {}, t("mm_rotating_do")), " ", f.fill(text, { ssid: ctx.ssid || "" })),
      full ? h("p", { class: "advice-why" }, t("mm_why")) : null));
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
  const t = f.t, problems = problemsOf(d), state = stateOf(d);
  const lvl = known(d.signal_dbm) ? f.signalLevel(d.signal_dbm) : null;
  const worst = problems.some((x) => x.severity === "bad") ? "bad" : "warn";
  return {
    "sum-state": h("span", { class: `adm-state state-${state}`, "data-part": "sum-state" }, icon(STATE_ICON[state] || "help"),
      h("span", { class: "sr" }, t(`state_${state}`))),
    "sum-name": h("strong", { class: "adm-name", "data-part": "sum-name" }, d.name),
    "sum-room": h("span", { class: "adm-room", "data-part": "sum-room" }, d.ap ? f.room(d.ap) : t(`state_${state}`)),
    "sum-signal": h("span", { class: "adm-signal", "data-part": "sum-signal" }, lvl ? [bars(lvl.bars, lvl.tone), f.dbm(d.signal_dbm)] : null),
    "sum-badge": h("span", { class: "adm-badge", "data-part": "sum-badge" }, problems.length
      ? h("span", { class: `badge sev-${worst}` }, icon(TONE_ICON[worst]), f.fill(t("adm_problems_n"), { n: problems.length })) : null),
  };
}

// --- the connection list -------------------------------------------------------------------

const apOf = (ap) => (ap && typeof ap === "object" ? ap : ap ? { name: ap } : null);

export function eventText(e, f, admin = false) {
  const t = f.t;
  const where = (ap, band) => (ap ? f.room(apOf(ap)) : "–") + (band ? ` (${f.bandName(band)})` : "");
  const band = (b) => (b ? f.bandName(b) : "–");
  const dt = e.detail && typeof e.detail === "object" ? e.detail : {};
  const lasted = (s) => (s ? h("span", { class: "muted" }, " ", f.fill(t("tl_for"), { duration: f.duration(s) })) : null);
  switch (e.kind) {
    case "connected": return [f.fill(t("tl_connected"), { where: where(e.ap, e.band) }), lasted(e.duration_s)];
    case "disconnected": return [t("tl_disconnected"), lasted(e.duration_s)];
    case "roamed": return [f.fill(t("tl_roamed"), { old: where(e.from_ap), new: where(e.ap) })];
    case "band_changed": return [f.fill(t("tl_band"), { old: band(e.from_band), new: band(e.band) })];
    case "authenticated": return [e.ap ? f.fill(t("tl_authenticated"), { where: where(e.ap, e.band) }) : t("tl_authenticated_plain")];
    case "auth_rejected": {
      const reason = dt.reason ?? e.reason;
      const rk = f.reasonKey(reason);
      return [f.fill(t("tl_auth_rejected"), { reason: t(admin ? `rr_${rk}_admin` : `rr_${rk}`) })];
    }
    case "reconnected": return [f.fill(t("tl_reconnected"), { where: where(e.ap, e.band) })];
    case "mac_changed": return [t("tl_mac_changed"), admin && e.mac ? [" ", h("span", { class: "mono muted" }, f.fill(t("tl_mac_changed_admin"), { mac: e.mac }))] : null];
    case "session_ended": {
      const cause = dt.cause ?? dt.terminate_cause ?? e.cause;
      const st = dt.session_time_s || e.duration_s;
      return [cause ? f.fill(t("tl_session_ended"), { cause: t(`cause_${f.causeKey(cause)}`) }) : t("tl_session_ended_plain"),
        cause && admin ? [" ", h("span", { class: "mono muted" }, String(cause))] : null, lasted(st)];
    }
    case "incident": {
      const inc = { kind: dt.incident ?? dt.kind, subject: dt.subject, subject_name: dt.subject_name, ap: apOf(e.ap) };
      return [f.fill(t("tl_incident"), { what: f.incidentText(inc) }),
        dt.open ? [" ", h("span", { class: "badge sev-bad" }, t("inc_open"))]
          : e.duration_s ? h("span", { class: "muted" }, " ", f.fill(t("inc_lasted"), { duration: f.duration(e.duration_s) })) : null];
    }
    default: return [t(`tl_kind_${e.kind}`)];
  }
}

/** The plain text of an event (tooltips, the timeline's labels). */
export function eventPlain(e, f, admin = false) {
  return eventText(e, f, admin).flat(Infinity).map((n) => (typeof n === "string" ? n : n ? n.textContent : "")).join("");
}

// which kinds each filter of the event list shows
export const EVENT_FILTERS = {
  all: null,
  wifi: ["connected", "disconnected", "reconnected", "roamed", "band_changed", "session_ended"],
  logins: ["authenticated", "auth_rejected", "mac_changed"],
  problems: ["auth_rejected", "disconnected", "session_ended", "incident", "reconnected"],
};

export function filterEvents(events, filter) {
  const kinds = EVENT_FILTERS[filter];
  return kinds ? (events || []).filter((e) => kinds.includes(e.kind)) : (events || []);
}

export function eventItem(e, f, now = Date.now(), admin = false) {
  const t = f.t;
  const srcs = e.sources && e.sources.length ? e.sources : e.source ? [e.source] : [];
  const src = (s) => { const key = `${admin ? "src_admin_" : "src_"}${s}`; const v = t(key); return v === key ? s : v; };
  return h("li", { class: `ev ev-${e.kind}${e.basis === "inferred" ? " ev-inferred" : ""}` },
    h("span", { class: "ev-icon" }, icon(EVENT_ICON[e.kind] || "info")),
    h("span", { class: "ev-time" }, timeEl(f, e.at, "when", now)),
    h("span", { class: "ev-text" }, eventText(e, f, admin), " ", basisTag(e.basis, f),
      srcs.length ? h("span", { class: "ev-src" }, `${t("ev_sources")} ${srcs.map(src).join(", ")}`) : null));
}

export function eventList(events, f, now = Date.now(), limit = 50, admin = false) {
  const sorted = [...(events || [])].sort((a, b) => Date.parse(b.at) - Date.parse(a.at)).slice(0, limit);
  if (!sorted.length) return [h("li", { class: "ev ev-none" }, f.t("tl_none"))];
  return sorted.map((e) => eventItem(e, f, now, admin));
}
