// A device's presence (DEVICE.presence, netportal/presence.py) as the state line says it: one
// state, since when, which source confirmed it and when, and why it is unknown. The same rules
// as netportal/i18n.py (Format.presence, presence_view, findings_shown), with the same texts:
// what the script redraws reads like what the server sent. Pure functions only, no DOM:
// tests/js/presence.test.mjs runs them under node.

export const PRESENCE_STATES = ["online", "connecting", "offline", "unknown", "never_connected"];
export const PRESENCE_SOURCES = ["prometheus", "radius_acct", "radius_auth", "unifi_syslog"];
export const PRESENCE_REASONS = ["association", "acct_start", "acct_interim", "accept_pending", "acct_stop",
  "association_gone", "unifi_disconnect", "session_stale", "ap_down", "telemetry_unavailable", "no_data", "mac_conflict",
  "sources_disagree", "other"];
export const PRESENCE_ICON = { online: "wifi", connecting: "refresh", offline: "wifi-off", unknown: "help",
  never_connected: "never" };
// the moments a page keeps current by itself (<time data-rel>), between two requests
export const RELATIVE_KINDS = ["recent", "ago", "elapsed"];

const FIELDS = ["since", "confirmed_at", "confirmed_by", "basis", "reason", "session", "stale_after_s", "poll_s", "evidence"];
const isTime = (v) => v !== null && v !== undefined && v !== "" && !Number.isNaN(Date.parse(v));

/** The device's presence with its state checked; without one (an older payload, a registry-only
 *  card) one from v1's `state` alone, marked derived: then nothing is claimed about when or by
 *  what it was confirmed. */
export function presenceOf(d) {
  const p = d && d.presence && typeof d.presence === "object" ? d.presence : null;
  let state = p ? p.state : null;
  if (!PRESENCE_STATES.includes(state)) state = d && PRESENCE_STATES.includes(d.state) ? d.state : "unknown";
  const out = { state, since: null, confirmed_at: null, confirmed_by: null, basis: null, reason: null, session: null,
    stale_after_s: null, poll_s: null, evidence: [], derived: !p };
  if (p) for (const key of FIELDS) if (p[key] !== null && p[key] !== undefined) out[key] = p[key];
  if (!Array.isArray(out.evidence)) out.evidence = [];
  if (!out.session || typeof out.session !== "object") out.session = null;
  return out;
}

/** The one state every part of a page shows for a device. */
export const stateOf = (d) => presenceOf(d).state;

/** A moment's text as the page shows it (kind: when | recent | ago | elapsed). */
export function relText(f, kind, value, now = Date.now()) {
  if (kind === "recent") return f.recent(value, now);
  if (kind === "ago") return f.ago(value, now);
  if (kind === "elapsed") return f.elapsed(value, now);
  return f.when(value, now);
}

export function moment(f, value, kind, now = Date.now()) {
  return { time: value, kind, text: relText(f, kind, value, now), title: f.stamp(value) };
}

/** What the state line says: {state, icon, label, more: [segment], confirmed: segment|null};
 *  a segment is {text: a text with {placeholders}, values: {name: string | moment}}. */
export function presenceView(d, f, now = Date.now(), { ssid = "" } = {}) {
  const t = f.t;
  const p = presenceOf(d);
  const state = p.state;
  const has = (key) => t(key) !== key;
  const seg = (key, values = {}) => ({ text: t(key), values });
  const at = (value, kind) => moment(f, value, kind, now);
  const more = [];
  if (state === "online") {
    const since = p.since || d.since;
    if (isTime(since)) more.push(seg("since_line", { time: at(since, "when"), duration: at(since, "elapsed") }));
  } else if (state === "connecting") {
    more.push(seg("pr_connecting_line"));
  } else if (state === "never_connected") {
    more.push(seg("never_line", { ssid: ssid || "" }));
  } else if (state === "offline") {
    if (!p.derived && isTime(p.since)) more.push(seg("pr_offline_since", { when: at(p.since, "recent") }));
    else if (isTime(d.last_seen)) more.push(seg("seen_line", { when: at(d.last_seen, "ago") }));
  } else {
    const codes = (d.diagnostics || []).map((x) => x && x.code);
    const reason = p.reason;
    if (!p.derived && reason && !(reason === "mac_conflict" && codes.includes("mac_conflict"))) {
      more.push(seg(`pr_reason_${PRESENCE_REASONS.includes(reason) ? reason : "other"}`));
    }
    if (isTime(d.last_seen)) more.push(seg("seen_line", { when: at(d.last_seen, "ago") }));
    else if (!more.length && !(d.diagnostics || []).length) more.push(seg("unknown_line"));
  }
  let confirmed = null;
  if (!p.derived && ["online", "connecting", "offline"].includes(state) && isTime(p.confirmed_at)) {
    const src = p.confirmed_by;
    const words = has(`pr_src_${src}`) ? t(`pr_src_${src}`) : has(`src_${src}`) ? t(`src_${src}`) : src ? String(src) : null;
    confirmed = words ? seg("pr_confirmed", { when: at(p.confirmed_at, "recent"), source: words })
      : seg("pr_confirmed_plain", { when: at(p.confirmed_at, "recent") });
  }
  return { state, icon: PRESENCE_ICON[state], label: t(`state_${state}`), more, confirmed };
}

/** A segment as [["text", string] | ["time", moment]] (i18n.Format.parts). */
export function segmentParts(segment) {
  const text = String(segment.text ?? ""), values = segment.values || {};
  const out = [];
  let last = 0;
  for (const m of text.matchAll(/\{(\w+)\}/g)) {
    if (m.index > last) out.push(["text", text.slice(last, m.index)]);
    const v = m[1] in values ? values[m[1]] : m[0];
    out.push(v && typeof v === "object" ? ["time", v] : ["text", v === null || v === undefined ? "" : String(v)]);
    last = m.index + m[0].length;
  }
  if (last < text.length) out.push(["text", text.slice(last)]);
  return out;
}

/** A view's plain text (announcements, tests). */
export function viewText(view) {
  const seg = (s) => segmentParts(s).map(([kind, v]) => (kind === "time" ? v.text : v)).join("");
  return [view.label, ...view.more.map(seg), view.confirmed ? seg(view.confirmed) : null].filter(Boolean).join(" · ");
}

/** The findings a page shows: "Not connected" (offline) only while the state is offline. */
export function findingsShown(d) {
  const state = stateOf(d);
  return (d.diagnostics || []).filter((x) => !(x && x.code === "offline" && state !== "offline"));
}
