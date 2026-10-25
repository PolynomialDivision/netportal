// The admin pages' parts as DOM, for the refresh: the same markup as templates/_admin.html
// (incidents, access points, rejected logins, data freshness and jobs, raw data). Change both.
// Text goes in as text nodes only (names, errors and AP names come from outside).

import { basisTag, fillNodes, h, icon, meter, timeEl, TONE_ICON } from "./render.js";

const known = (v) => v !== null && v !== undefined && v !== "";
const textOr = (f, key, fallback) => { const v = f.t(key); return v === key ? fallback : v; };

/** An AP (API shape: name, house, floor, spot) as a room; else from its name. */
export function apRoom(ap, f) {
  const info = ap.ap && typeof ap.ap === "object" ? ap.ap : "house" in ap ? ap : f.apFromName(ap.name ?? ap.ap_name);
  return f.room(info);
}

// --- what the admin pages point out about an AP (i18n.Format.ap_*; the diagnostics' limits) ---
export const AP_LIMITS = { clients: 25, util: 0.8, minClients: 10, busy: 0.6, weakShare: 0.25, weakMinClients: 4,
  restartedS: 86400, uplinkMbps: 1000 };
export const apState = (ap) => (["ok", "up"].includes(ap && ap.state) ? "up" : ap && ap.state === "down" ? "down" : "unknown");
export function apWeakShare(ap) {
  if (known(ap.weak_share)) return ap.weak_share;
  return known(ap.weak_clients) && ap.clients ? ap.weak_clients / ap.clients : null;
}
export function apLoad(ap) {
  const loads = (ap.radios || []).map((r) => utilOf(r)).filter((u) => u !== null);
  return loads.length ? Math.max(...loads) : null;
}
/** down | overloaded | busy_channel | poor_coverage | restarted | uplink, from the live values. */
export function apWarningCodes(ap) {
  if (Array.isArray(ap.warnings)) return ap.warnings;
  if (apState(ap) === "down") return ["down"];
  const out = [], n = ap.clients, load = apLoad(ap), weak = apWeakShare(ap);
  if (known(n) && (n >= AP_LIMITS.clients || (load !== null && load >= AP_LIMITS.util && n >= AP_LIMITS.minClients))) out.push("overloaded");
  else if (load !== null && load >= AP_LIMITS.busy) out.push("busy_channel");
  if (weak !== null && weak >= AP_LIMITS.weakShare && (n || 0) >= AP_LIMITS.weakMinClients) out.push("poor_coverage");
  if (known(ap.uptime_s) && ap.uptime_s < AP_LIMITS.restartedS) out.push("restarted");
  if (known(ap.uplink_mbps) && ap.uplink_mbps < AP_LIMITS.uplinkMbps) out.push("uplink");
  return out;
}

function between(f, start, end) {
  const a = Date.parse(start), b = end ? Date.parse(end) : Date.now();
  return Number.isNaN(a) || Number.isNaN(b) ? "–" : f.duration((b - a) / 1000);
}

// --- incidents ---------------------------------------------------------------------------------

export function incidentItem(inc, f, { full = false, now = Date.now(), hidden = false } = {}) {
  const t = f.t, open = inc.open !== undefined ? Boolean(inc.open) : !inc.ended;
  const lasted = known(inc.duration_s) ? f.duration(inc.duration_s) : between(f, inc.started, open ? null : inc.ended);
  const devices = inc.devices || [];
  const affected = known(inc.affected) ? inc.affected : devices.length;
  const max = full ? 50 : 4;
  const owner = (o) => (o && typeof o === "object" ? o.display || o.username : o);
  const deviceLinks = devices.slice(0, max).flatMap((d, i) => [i ? ", " : "", h("a", { href: `/admin/devices/${encodeURIComponent(d.id)}` }, d.name),
    full && d.owner ? [" ", h("span", { class: "muted" }, `(${owner(d.owner)})`)] : null]);
  return h("li", { class: `inc ${open ? "inc-open" : "inc-closed"}${inc.basis === "inferred" ? " inferred" : ""}`, "data-kind": inc.kind,
    "data-state": open ? "open" : "closed", id: `incident-${inc.id}`, hidden },
  h("span", { class: "inc-icon" }, icon("bolt")),
  h("div", { class: "inc-main" },
    h("p", { class: "inc-title" }, h("strong", {}, textOr(f, `inc_${inc.kind}`, t("inc_other"))), " ",
      h("span", { class: "inc-scope" }, f.scope(inc)), " ", basisTag(inc.basis, f)),
    h("p", { class: "inc-when" }, open
      ? [h("span", { class: "badge sev-bad" }, t("inc_open")), " ", fillNodes(t("inc_since"), { when: timeEl(f, inc.started, "when", now) }),
        ` · ${lasted}`]
      : [fillNodes(t("inc_span"), { start: timeEl(f, inc.started, "when", now), end: timeEl(f, inc.ended, "when", now) }),
        ` · ${f.fill(t("inc_lasted"), { duration: lasted })}`]),
    affected ? h("p", { class: "inc-devices" },
      devices.length ? [h("span", {}, t("inc_affected_list")), " ", deviceLinks, devices.length > max ? " …" : ""]
        : h("span", {}, f.fill(t("inc_affected"), { n: affected })))
      : full && (inc.devices || known(inc.affected)) ? h("p", { class: "inc-devices muted" }, t("inc_affected_none")) : null,
    full && inc.detail && Object.keys(inc.detail).length ? h("details", { class: "inc-detail" }, h("summary", {}, t("inc_detail")),
      h("dl", { class: "mini-kv" }, Object.entries(inc.detail).map(([k, v]) => h("div", {}, h("dt", {}, k), h("dd", { class: "mono" }, plainOf(v)))),
        inc.subject ? h("div", {}, h("dt", {}, "subject"), h("dd", { class: "mono" }, inc.subject)) : null)) : null));
}

function plainOf(v) {
  if (Array.isArray(v)) return v.map(plainOf).join(", ");
  if (v && typeof v === "object") return Object.entries(v).map(([k, x]) => `${k} ${plainOf(x)}`).join(", ");
  return String(v);
}

/** {open, recent} from the API's incidents (an object with both, or one list). */
export function splitIncidents(incidents) {
  if (!incidents) return { open: [], recent: [] };
  if (Array.isArray(incidents)) return { open: incidents.filter((i) => !i.ended), recent: incidents.filter((i) => i.ended) };
  return { open: incidents.open || [], recent: incidents.recent || [] };
}

export function overviewIncidents(ov, f, now = Date.now()) {
  const t = f.t;
  const { open, recent } = splitIncidents(ov.incidents);
  const unavailable = ov.incidents && ov.incidents.available === false;
  return h("section", { class: "card ov-inc", "aria-labelledby": "ov-inc-h", "data-part": "ov-incidents" },
    h("h2", { id: "ov-inc-h" }, icon("bolt"), t("ov_incidents"), open.length ? [" ", h("span", { class: "count tone-bad" }, String(open.length))] : null),
    unavailable ? h("p", { class: "muted" }, icon("warn"), " ", t("ov_unavailable"))
      : open.length ? [h("h3", { class: "ov-sub" }, t("ov_open")), h("ul", { class: "inc-list" }, open.map((i) => incidentItem(i, f, { now })))]
        : h("p", { class: "all-good" }, icon("check"), t("inc_open_none")),
    recent.length ? [h("h3", { class: "ov-sub" }, t("ov_recent")), h("ul", { class: "inc-list" }, recent.slice(0, 5).map((i) => incidentItem(i, f, { now })))] : null,
    h("a", { class: "more", href: "/admin/incidents" }, icon("bolt"), h("span", {}, t("ov_all_incidents")), icon("next")));
}

// --- access points -------------------------------------------------------------------------

export const apClients = (ap) => (known(ap.clients) ? ap.clients : known(ap.num_clients) ? ap.num_clients : null);
export const utilOf = (r) => (known(r.channel_util) ? r.channel_util : known(r.utilization) ? r.utilization : null);
export const utilTone = (u) => (u >= 0.8 ? "bad" : u >= 0.6 ? "warn" : "ok");
const AP_STATE_ICON = { up: "check", down: "bad", unknown: "help" };

export function radios(ap, f) {
  const list = ap.radios || [];
  if (!list.length) return null;
  return h("ul", { class: "ap-radios" }, list.map((r) => {
    const u = utilOf(r);
    const tone = known(u) ? utilTone(u) : "ok";
    return h("li", {}, h("span", { class: "ap-radio-name" }, (r.band ? f.bandName(r.band) : r.radio) + (r.channel ? ` · ${r.channel}` : "")),
      known(u) ? [meter(Math.round(u * 100), tone), h("span", { class: `tone-text-${tone}` }, f.percent(u))] : null,
      known(r.clients) ? h("span", { class: "muted" }, f.fill(f.t("ap_clients"), { n: r.clients })) : null);
  }));
}

export function apWarnings(ap, f) {
  const w = apWarningCodes(ap);
  const open = (ap.open_incidents || []).filter((i) => i.kind !== "ap_down" || !w.includes("down"));
  if (!w.length && !open.length) return null;
  return h("span", { class: "ap-warns" },
    w.map((code) => h("span", { class: `badge sev-${["down", "overloaded"].includes(code) ? "bad" : "warn"}` }, icon("warn"), textOr(f, `ap_warn_${code}`, code))),
    open.map((i) => h("a", { class: "badge sev-bad", href: `/admin/incidents#incident-${i.id}` }, icon("bolt"), textOr(f, `inc_${i.kind}`, f.t("inc_other")))));
}

export function apTile(ap, f) {
  const t = f.t;
  const st = apState(ap);
  const n = apClients(ap), weak = apWeakShare(ap);
  const sub = [known(n) ? f.fill(t("ap_clients"), { n }) : null,
    weak !== null ? f.fill(t("ap_weak"), { pct: f.percent(weak) }) : null].filter(Boolean).join(" · ");
  return h("li", { class: `ap-tile ap-${st}`, "data-ap": ap.mac },
    h("a", { class: "ap-link", href: `/admin/aps#ap-${String(ap.mac || ap.name || "").replaceAll(":", "")}` },
      h("span", { class: "ap-head" }, icon("ap"), h("strong", {}, apRoom(ap, f)),
        h("span", { class: `ap-state tone-text-${{ up: "ok", down: "bad" }[st] || "muted"}` }, icon(AP_STATE_ICON[st]), h("span", { class: "sr" }, t(`ap_state_${st}`)))),
      h("span", { class: "ap-sub" }, sub)),
    radios(ap, f), apWarnings(ap, f));
}

export function overviewAps(ov, f) {
  const t = f.t, aps = ov.aps || [];
  return h("section", { class: "card ov-aps", "aria-labelledby": "ov-aps-h", "data-part": "ov-aps" },
    h("h2", { id: "ov-aps-h" }, icon("ap"), t("ov_aps"), aps.length ? [" ", h("span", { class: "count" }, String(aps.length))] : null),
    aps.length ? h("ul", { class: "ap-grid" }, aps.map((a) => apTile(a, f))) : h("p", { class: "muted" }, t("aps_empty")),
    h("a", { class: "more", href: "/admin/aps" }, icon("chart"), h("span", {}, t("ov_all_aps")), icon("next")));
}

// --- rejected logins -----------------------------------------------------------------------

/** OVERVIEW["auth"] (or a list of rows): {rows, total, byReason, truncated, available, devices, macs}. */
export function normaliseFailures(af) {
  const a = Array.isArray(af) ? { recent: af } : af || {};
  const rows = a.recent || a.latest || a.events || [];
  let byReason = a.by_reason && Object.keys(a.by_reason).length ? a.by_reason : null;
  if (!byReason) {
    byReason = {};
    for (const r of rows) byReason[r.reason] = (byReason[r.reason] || 0) + (r.count > 1 ? r.count : 1);
  }
  return { rows, total: known(a.count) ? a.count : rows.length, byReason, truncated: Boolean(a.truncated),
    available: a.available !== false, devices: a.devices, macs: a.macs };
}

export function authFailures(af, f, now = Date.now()) {
  const t = f.t, n = normaliseFailures(af);
  const reasonText = (r) => textOr(f, `rr_${f.reasonKey(r)}_admin`, r);
  const owner = (o) => (o && typeof o === "object" ? o.display || o.username : o);
  return h("section", { class: "card ov-auth", "aria-labelledby": "ov-auth-h", "data-part": "ov-auth" },
    h("h2", { id: "ov-auth-h" }, icon("reject"), t("ov_auth"), n.total ? [" ", h("span", { class: "count" }, `${n.total}${n.truncated ? "+" : ""}`)] : null),
    !n.available ? h("p", { class: "muted" }, icon("warn"), " ", t("ov_unavailable"))
      : !n.total ? h("p", { class: "all-good" }, icon("check"), t("ov_auth_none")) : [
        known(n.devices) ? h("p", { class: "muted small" }, f.fill(t("ov_auth_spread"), { devices: n.devices, macs: n.macs ?? "–" })) : null,
        h("ul", { class: "reason-bars" }, Object.entries(n.byReason).sort((a, b) => b[1] - a[1]).map(([r, c]) =>
          h("li", {}, h("span", { class: "rb-label" }, reasonText(r), " ", h("span", { class: "mono muted" }, r)), h("b", {}, String(c))))),
        h("div", { class: "table-wrap" }, h("table", { class: "data" },
          h("thead", {}, h("tr", {}, ["th_at", "th_device", "th_reason", "th_mac", "th_ap"].map((k) => h("th", { scope: "col" }, t(k))))),
          h("tbody", {}, n.rows.slice(0, 12).map((r) => h("tr", {},
            h("td", {}, timeEl(f, r.at, "when", now)),
            h("td", {}, r.device_id ? h("a", { href: `/admin/devices/${encodeURIComponent(r.device_id)}` }, r.device_name || `${String(r.device_id).slice(0, 7)}…`)
              : h("span", { class: "muted" }, t("ov_auth_unknown")),
            r.owner ? [" ", h("span", { class: "muted" }, owner(r.owner))] : null,
            r.serial && !r.device_id ? [" ", h("span", { class: "mono muted" }, String(r.serial).length > 14 ? `${String(r.serial).slice(0, 13)}…` : r.serial)] : null),
            h("td", {}, reasonText(r.reason), r.count > 1 ? [" ", h("span", { class: "badge tone-info" }, f.fill(t("ov_auth_repeats"), { n: r.count }))] : null),
            h("td", { class: "mono" }, r.mac || "–"),
            h("td", {}, r.ap ? apRoom(r.ap, f) : r.bssid ? h("span", { class: "mono" }, r.bssid) : "–")))))),
      ]);
}

// --- data freshness and the collector's jobs (OVERVIEW["freshness"], OVERVIEW["jobs"]) -------

// how often each job should succeed; older than three intervals is overdue (as _admin.html)
export const JOB_EVERY_S = { unifi_events: 120, incidents: 120, rollup: 1800, prune: 86400, offboarding: 86400 };
const JOB_TONE = { ok: "ok", failed: "bad", never: "warn", late: "warn", running: "info" };
export const WIFI_STALE_S = 600;

/** ok | failed | never | late, from a JOB. */
export function jobState(j) {
  if (!j.last_attempt && !j.last_success) return "never";
  if (j.ok === false || (j.ok === undefined && j.last_error)) return "failed";
  if (known(j.age_s) && JOB_EVERY_S[j.name] && j.age_s > 3 * JOB_EVERY_S[j.name]) return "late";
  return "ok";
}

export function freshness(fr, jobs, f, available = true) {
  const t = f.t, x = fr || {};
  const items = Array.isArray(jobs) ? jobs : [];
  const dur = (s) => (!known(s) ? "–" : s >= 1 ? f.duration(s) : f.ms(s * 1000));
  const line = (ok, name, ...value) => h("li", { class: `fresh tone-${ok ? "ok" : "warn"}` }, icon(ok ? "check" : "warn"),
    h("span", { class: "fresh-name" }, name), h("span", { class: "fresh-age" }, ...value));
  const age = x.wifi_data_age_s, stale = !known(age) || age > WIFI_STALE_S, p = x.prometheus || "off";
  return h("section", { class: "card ov-fresh", "aria-labelledby": "ov-fresh-h", "data-part": "ov-fresh" },
    h("h2", { id: "ov-fresh-h" }, icon("db"), t("ov_fresh")),
    h("p", { class: "muted small" }, t("ov_fresh_intro")),
    h("ul", { class: "fresh-list" },
      line(!stale, t("fresh_wifi"), known(age) ? f.fill(t("fresh_age"), { age: f.duration(age) }) : t("fresh_none"),
        stale && known(age) ? [" · ", h("strong", {}, t("fresh_stale"))] : null),
      line(p === "ok", t("fresh_prometheus"), textOr(f, `fresh_state_${p}`, p)),
      line(Boolean(x.jobs_ok), t("fresh_jobs"), x.jobs_ok ? t("fresh_jobs_ok") : x.jobs_ok === null || x.jobs_ok === undefined ? t("fresh_jobs_none") : t("fresh_jobs_failed"),
        known(x.oldest_job_success_age_s) ? ` · ${f.fill(t("fresh_oldest"), { age: f.duration(x.oldest_job_success_age_s) })}` : null)),
    available === false ? h("p", { class: "muted" }, icon("warn"), " ", t("ov_unavailable"))
      : items.length ? h("div", { class: "table-wrap" }, h("table", { class: "data jobs" },
        h("thead", {}, h("tr", {}, ["th_job", "th_state", "th_last_success", "th_last_attempt", "th_duration"].map((k) => h("th", { scope: "col" }, t(k))))),
        h("tbody", {}, items.flatMap((j) => {
          const st = jobState(j), tone = JOB_TONE[st];
          const row = h("tr", { class: `job-${st}` },
            h("th", { scope: "row" }, textOr(f, `job_${j.name}`, j.name), " ", h("span", { class: "mono muted" }, j.name)),
            h("td", {}, h("span", { class: `badge tone-${tone}` }, icon(TONE_ICON[tone]), t(`job_${st}`))),
            h("td", {}, j.last_success ? timeEl(f, j.last_success, "ago") : "–"),
            h("td", {}, j.last_attempt ? timeEl(f, j.last_attempt, "ago") : "–"),
            h("td", {}, dur(j.duration_s)));
          return j.last_error && st === "failed"
            ? [row, h("tr", { class: "job-error" }, h("td", { colspan: "5" }, h("span", { class: "mono" }, String(j.last_error).slice(0, 300))))]
            : [row];
        })))) : null);
}

// --- raw data of a device ----------------------------------------------------------------

export const RAW_PARTS = ["auth", "acct", "events", "macs", "days", "incidents"];
export const RAW_COLUMNS = {
  auth: [["at", "th_at", "when"], ["result", "th_result", "result"], ["reason", "th_reason", "reason"], ["mac", "th_mac", "mono"],
    ["ssid", "th_ssid", "text"], ["bssid", "th_bssid", "mono"], ["nas_ip", "th_nas", "mono"]],
  acct: [["started", "th_started", "when"], ["stopped", "th_stopped", "when"], ["session_time_s", "th_session_time", "duration"],
    ["output_octets", "th_down", "bytes"], ["input_octets", "th_up", "bytes"], ["terminate_cause", "th_cause", "cause"],
    ["mac", "th_mac", "mono"], ["bssid", "th_bssid", "mono"], ["framed_ip", "th_ip", "mono"], ["link", "th_link", "mono"],
    ["nas_ip", "th_nas", "mono"], ["acct_session_id", "th_session", "mono"]],
  events: [["at", "th_at", "when"], ["kind", "th_kind", "text"], ["ap_name", "th_ap", "text"], ["from_ap_name", "th_from_ap", "text"],
    ["radio", "th_radio", "text"], ["channel", "th_channel", "text"], ["rssi", "th_rssi", "text"],
    ["duration_s", "th_duration", "duration"], ["rx_bytes", "th_rx", "bytes"], ["tx_bytes", "th_tx", "bytes"],
    ["mac", "th_mac", "mono"], ["source", "th_source", "mono"]],
  macs: [["mac", "th_mac", "mono"], ["randomized", "th_randomized", "bool"], ["current", "th_current", "bool"],
    ["first_seen", "th_first_seen", "when"], ["last_seen", "th_last_seen", "when"], ["auth_count", "th_logins", "number"],
    ["start", "th_window", "window"], ["other_owners", "th_conflict", "conflict"]],
  days: [["day", "th_day", "day"], ["online_s", "th_online", "duration"], ["signal_avg_dbm", "th_signal", "dbm"],
    ["health_avg", "th_health", "number"], ["rx_bytes", "th_down", "bytes"], ["tx_bytes", "th_up", "bytes"],
    ["roams", "th_roams", "number"], ["reconnects", "th_reconnects", "number"], ["disconnects", "th_disconnects", "number"],
    ["macs", "th_macs", "number"], ["auth_ok", "th_auth_ok", "number"], ["auth_failed", "th_auth_failed", "number"]],
  incidents: [["started", "th_started", "when"], ["ended", "th_ended", "when"], ["kind", "th_kind", "incident"],
    ["subject_name", "th_subject", "text"], ["duration_s", "th_duration", "duration"], ["basis", "th_basis", "basis"]],
};
export const RAW_ALIASES = { auth: ["auth", "radius_auth", "auth_events"], acct: ["acct", "radius_acct", "acct_sessions"],
  events: ["events", "connection_events"], macs: ["windows", "macs", "mac_windows"], days: ["days"], incidents: ["incidents"] };

/** The rows of one part of a RAW payload (whichever name it uses); MAC windows get their
 *  conflict's other owners. */
export function rawRows(raw, part) {
  let rows = [];
  for (const alias of RAW_ALIASES[part]) if (raw && Array.isArray(raw[alias])) { rows = raw[alias]; break; }
  if (part === "macs" && raw && Array.isArray(raw.conflicts)) {
    const by = new Map(raw.conflicts.map((c) => [c.mac, c.other_owners]));
    rows = rows.map((r) => (r.other_owners === undefined ? { ...r, other_owners: by.get(r.mac) ?? null } : r));
  }
  return rows;
}

function cell(kind, v, f, now) {
  const t = f.t;
  if (!known(v)) return h("span", { class: "muted" }, "–");
  switch (kind) {
    case "when": return timeEl(f, v, "when", now);
    case "result": return h("span", { class: `badge tone-${v === "accept" ? "ok" : "bad"}` }, textOr(f, `res_${v}`, v));
    case "cause": return [String(v), " ", h("span", { class: "muted" }, t(`cause_${f.causeKey(v)}`))];
    case "bool": return v ? t("yes") : t("no");
    case "day": return f.day(v);
    case "dbm": return f.dbm(v);
    case "incident": return [textOr(f, `inc_${v}`, v), " ", h("span", { class: "mono muted" }, String(v))];
    case "basis": return textOr(f, `basis_${v}`, v);
    case "conflict": return v ? h("span", { class: "badge sev-warn" }, f.fill(t("raw_conflict"), { n: v })) : h("span", { class: "muted" }, "–");
    case "duration": return f.duration(v);
    case "bytes": return f.bytes(v);
    case "number": return f.number(v);
    case "mono": return h("span", { class: "mono" }, String(v));
    default: return String(v);
  }
}

export function rawTable(part, rows, f, now = Date.now()) {
  if (!rows || !rows.length) return h("p", { class: "muted raw-empty" }, f.t("raw_empty"));
  const cols = RAW_COLUMNS[part];
  return h("div", { class: "table-wrap" }, h("table", { class: "data raw-table" },
    h("thead", {}, h("tr", {}, cols.map(([, th]) => h("th", { scope: "col" }, f.t(th))))),
    h("tbody", {}, rows.map((r) => h("tr", part === "auth" && r.result === "reject" ? { class: "row-bad" } : {},
      cols.map(([key, , kind]) => h("td", {}, kind === "window"
        ? [r.start ? timeEl(f, r.start, "when", now) : h("span", { class: "muted" }, "…"), " – ",
          r.end ? timeEl(f, r.end, "when", now) : h("span", { class: "muted" }, f.t("inc_open"))]
        : cell(kind, r[key], f, now))))))));
}
