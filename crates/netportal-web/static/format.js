// Formatting for the dashboard: numbers, sizes, rates, durations, times and places per language.
// The same rules as netportal/i18n.py (Format), with the same texts (TEXT[lang], handed to the
// page as JSON): what the script redraws reads like what the server sent. Pure functions only,
// no DOM: tests/js/format.test.mjs runs them under node.

export const HOUSE_TZ = "Europe/Berlin";
export const NONE = "–";
// At or above each threshold (dBm): bars and a word. Below the last: 0 bars, very weak.
export const SIGNAL_LEVELS = [[-60, 4, "sig_excellent"], [-67, 3, "sig_good"], [-75, 2, "sig_fair"], [-82, 1, "sig_weak"]];
// Wi-Fi quality (0-100): word and tone.
export const HEALTH_LEVELS = [[80, "q_good", "ok"], [50, "q_fair", "warn"]];
export const DIAGNOSES = ["weak_signal", "low_snr", "high_retries", "busy_channel", "unstable_roaming",
  "frequent_disconnects", "stuck_on_2ghz", "slow_link", "stale_data", "offline", "never_connected", "mac_conflict",
  "auth_failures", "cert_expiring", "cert_expired", "rotating_mac", "ap_overloaded", "poor_coverage", "incident_correlated"];

// Telemetry v2's codes, as in i18n.py (EVENT_KINDS, REJECT_REASONS, TERMINATE_CAUSES, ...).
export const EVENT_KINDS = ["authenticated", "auth_rejected", "connected", "disconnected", "reconnected", "roamed",
  "band_changed", "mac_changed", "session_ended", "incident"];
export const REJECT_REASONS = ["ok", "unknown_cert", "revoked", "expired", "retired", "no_cert", "bad_chain", "not_eap",
  "db_error", "other"];
// Acct-Terminate-Cause by number (RFC 2866 5.10, RFC 3580 3.33), as text-key suffixes.
export const TERMINATE_CAUSES = ["user_request", "lost_carrier", "lost_service", "idle_timeout", "session_timeout",
  "admin_reset", "admin_reboot", "port_error", "nas_error", "nas_request", "nas_reboot", "port_unneeded",
  "port_preempted", "port_suspended", "service_unavailable", "callback", "user_error", "host_request",
  "supplicant_restart", "reauthentication_failure", "port_reinitialized", "port_administratively_disabled"];
export const INCIDENT_KINDS = ["internet_down", "internet_degraded", "router_down", "dns_down", "ap_down", "ap_restarted",
  "switch_down", "switch_port_down", "unifi_data_stale", "radius_down"];
export const MAC_MODES = ["hardware", "random_fixed", "rotating"];

// A finding's evidence per code: [key, how it is shown] in order (i18n.EVIDENCE_SPEC), the
// fallback per key (EVIDENCE_FORMAT) and the span a finding looks at (EVIDENCE_WINDOW).
export const EVIDENCE_SPEC = {
  weak_signal: [["signal_dbm", "dbm"], ["warn_dbm", "limit_dbm"]],
  low_snr: [["snr_db", "db"], ["noise_dbm", "dbm"], ["warn_db", "limit_db"]],
  high_retries: [["retry_ratio", "percent"], ["warn", "limit_percent"], ["tx_attempts_per_s", "rate"]],
  busy_channel: [["channel_util", "percent"], ["channel", "plain"]],
  slow_link: [["link_rx_bps", "bitrate"], ["signal_dbm", "dbm"], ["throughput_bps", "bitrate"]],
  unstable_roaming: [["roams_1h", "per_hour"], ["roams_1h_measured", "per_hour"], ["warn", "limit_per_hour"]],
  frequent_disconnects: [["reconnects_24h", "count"], ["disconnects_24h_measured", "count"], ["causes", "causes"],
    ["warn", "limit_count"]],
  stuck_on_2ghz: [["bands_7d", "bands"], ["signal_dbm", "dbm"], ["associated_s", "duration"]],
  auth_failures: [["count_24h", "count"], ["reasons", "reasons"], ["last_at", "when"], ["last_accept", "when"]],
  cert_expiring: [["expires", "date"], ["days_left", "days"]],
  cert_expired: [["expires", "date"]],
  rotating_mac: [["macs_30d", "count"]],
  ap_overloaded: [["ap", "room"], ["clients", "count"], ["channel_util", "percent"], ["band", "band"]],
  poor_coverage: [["aps", "ap_signals"]],
  incident_correlated: [["incident", "incident"], ["disconnects", "times"]],
  stale_data: [["age_s", "duration"], ["threshold_s", "limit_duration"]],
  offline: [["confirmed_at", "recent"], ["confirmed_by", "source"], ["last_seen", "ago"]],
  mac_conflict: [["owners", "count"]],
  never_connected: [],
};
export const EVIDENCE_FORMAT = {
  signal_dbm: "dbm", noise_dbm: "dbm", snr_db: "db", retry_ratio: "percent", channel_util: "percent", roams_1h: "per_hour",
  reconnects_24h: "count", link_rx_bps: "bitrate", throughput_bps: "bitrate", age_s: "duration", associated_s: "duration",
  last_at: "when", last_accept: "when", last_seen: "ago", expires: "date", days_left: "days", count_24h: "count",
  macs_30d: "count", clients: "count", owners: "count", reasons: "reasons", causes: "causes", ap: "room",
  aps: "ap_signals", band: "band", bands_7d: "bands", incident: "incident", disconnects: "times", confirmed_at: "recent",
  confirmed_by: "source",
};
export const EVIDENCE_SHORT = {
  frequent_disconnects: ["reconnects_24h", "times_24h"], auth_failures: ["count_24h", "times_24h"],
  rotating_mac: ["macs_30d", "addresses"], cert_expiring: ["days_left", "days"], cert_expired: ["expires", "date"],
  ap_overloaded: ["clients", "devices"], poor_coverage: ["best_signal_dbm", "dbm"],
  incident_correlated: ["incident", "incident"], never_connected: ["none", "count"],
};
const SHORT_TEXTS = { times_24h: "times_24h", addresses: "mm_addresses", days: "days_n", devices: "ap_clients" };
export const EVIDENCE_WINDOW = { unstable_roaming: "1h", frequent_disconnects: "24h", auth_failures: "24h",
  poor_coverage: "24h", stuck_on_2ghz: "7d", rotating_mac: "30d" };

const AP_NAME_RE = /^ap-([a-z0-9]+)-(\d{1,2})-([a-z0-9][a-z0-9-]*)$/;
/** An AP name as the backend splits it: ap-<house>-<floor>-<spot>. */
export function apFromName(name) {
  const m = AP_NAME_RE.exec(String(name ?? ""));
  return m ? { name, house: m[1], floor: Number(m[2]), spot: m[3] } : { name: name ?? null, house: null, floor: null, spot: null };
}

/** "Lost-Carrier", "lost_carrier" or "2" -> "lost_carrier"; anything else -> "unknown". */
export function causeKey(cause) {
  if (cause === null || cause === undefined || cause === "") return "unknown";
  const text = String(cause).trim();
  if (/^\d+$/.test(text)) return TERMINATE_CAUSES[Number(text) - 1] || "unknown";
  const key = text.toLowerCase().replace(/[- ]/g, "_");
  return TERMINATE_CAUSES.includes(key) ? key : "unknown";
}

/** A reject reason's text-key suffix (unknown ones: "other"). */
export function reasonKey(reason) {
  return REJECT_REASONS.includes(reason) ? reason : "other";
}

const empty = (v) => v === null || v === undefined || v === "" || (Array.isArray(v) && !v.length)
  || (typeof v === "object" && !Array.isArray(v) && !Object.keys(v).length);

/** A value as plain text (an admin's view of evidence without a text). */
export function plain(value) {
  if (Array.isArray(value)) return value.map(plain).join(", ");
  if (value && typeof value === "object") return Object.entries(value).map(([k, v]) => `${k} ${plain(v)}`).join(", ");
  if (typeof value === "number" && !Number.isInteger(value)) return String(Math.round(value * 1000) / 1000);
  return String(value);
}

/** "{n} min" with {n: 5} -> "5 min"; unknown placeholders stay as they are. */
export function fill(template, values) {
  return String(template ?? "").replace(/\{(\w+)\}/g, (all, key) => (key in values ? String(values[key]) : all));
}

/** An ISO 8601 string, a Date or epoch milliseconds -> a Date, or null. */
export function toDate(value) {
  if (value === null || value === undefined || value === "") return null;
  const d = value instanceof Date ? value : new Date(typeof value === "number" ? value : String(value));
  return Number.isNaN(d.getTime()) ? null : d;
}

export function signalLevel(dbm) {
  if (dbm === null || dbm === undefined) return null;
  for (const [threshold, bars, key] of SIGNAL_LEVELS) {
    if (dbm >= threshold) return { bars, key, tone: bars >= 3 ? "ok" : "warn" };
  }
  return { bars: 0, key: "sig_very_weak", tone: "bad" };
}

export function healthLevel(score) {
  if (score === null || score === undefined) return null;
  for (const [threshold, key, tone] of HEALTH_LEVELS) {
    if (score >= threshold) return { key, tone };
  }
  return { key: "q_poor", tone: "bad" };
}

/** A formatter for one language: createFormatter("de", TEXT.de). */
export function createFormatter(lang, texts, { timeZone = HOUSE_TZ } = {}) {
  const t = (key) => (texts && key in texts ? texts[key] : key);
  const numberFormats = new Map();

  function number(value, digits = 0) {
    if (value === null || value === undefined || Number.isNaN(Number(value))) return NONE;
    if (!numberFormats.has(digits)) {
      numberFormats.set(digits, new Intl.NumberFormat(lang, { minimumFractionDigits: digits, maximumFractionDigits: digits }));
    }
    return numberFormats.get(digits).format(Number(value)).replace(/^-/, "−").replace(/ /g, " ");
  }

  function scaled(value, units) {
    if (value === null || value === undefined) return NONE;
    let v = Number(value), unit = 0;
    while (Math.abs(v) >= 1000 && unit < units.length - 1) { v /= 1000; unit += 1; }
    const digits = unit && Math.abs(v) < 10 ? 1 : 0;
    return `${number(v, digits)} ${t(units[unit])}`;
  }

  const bytes = (v) => scaled(v, ["u_b", "u_kb", "u_mb", "u_gb", "u_tb"]);
  const bitrate = (v) => scaled(v, ["u_bit", "u_kbit", "u_mbit", "u_gbit"]);
  const percent = (ratio, digits = 0) => (ratio === null || ratio === undefined ? NONE
    : number(ratio * 100, digits) + (lang === "de" || lang === "uk" ? " %" : "%"));
  const dbm = (v) => (v === null || v === undefined ? NONE : fill(t("dbm_fmt"), { n: number(v) }));
  const db = (v) => (v === null || v === undefined ? NONE : fill(t("db_fmt"), { n: number(v) }));
  const ms = (v) => (v === null || v === undefined ? NONE : fill(t("ms_fmt"), { n: number(v, v < 10 ? 1 : 0) }));

  /** The largest units: "2 h 15 min", "3 d 4 h", "40 s". */
  function duration(seconds, parts = 2) {
    if (seconds === null || seconds === undefined) return NONE;
    let rest = Math.max(0, Math.floor(seconds));
    const out = [];
    for (const [key, size] of [["dur_d", 86400], ["dur_h", 3600], ["dur_min", 60], ["dur_s", 1]]) {
      const n = Math.floor(rest / size);
      rest -= n * size;
      if (n && out.length < parts) out.push(fill(t(key), { n }));
      else if (out.length) break;
      if (key === "dur_min" && out.length) break;
    }
    return out.join(" ") || fill(t("dur_s"), { n: 0 });
  }

  function ago(value, now = Date.now()) {
    const when = toDate(value);
    if (!when) return NONE;
    const seconds = ((toDate(now) || new Date()).getTime() - when.getTime()) / 1000;
    if (seconds < 60) return t("ago_now");
    return fill(t("ago_fmt"), { when: duration(seconds, 1) });
  }

  /** A moment to the second, for what was just confirmed: "just now" (under 5 s), "12 s ago",
   *  beyond a minute as ago() (i18n.Format.recent). */
  function recent(value, now = Date.now()) {
    const when = toDate(value);
    if (!when) return NONE;
    const seconds = ((toDate(now) || new Date()).getTime() - when.getTime()) / 1000;
    if (seconds < 5) return t("ago_now");
    if (seconds < 60) return fill(t("ago_fmt"), { when: fill(t("dur_s"), { n: Math.floor(seconds) }) });
    return ago(value, now);
  }

  /** How long since `start` ("2 h 15 min"; i18n.Format.elapsed). */
  function elapsed(start, now = Date.now()) {
    const begin = toDate(start);
    if (!begin) return NONE;
    return duration(((toDate(now) || new Date()).getTime() - begin.getTime()) / 1000);
  }

  // The house's wall clock for a moment, without depending on the browser's own zone.
  const partsFormat = new Intl.DateTimeFormat("en-GB", {
    timeZone, year: "numeric", month: "numeric", day: "numeric", hour: "numeric", minute: "numeric", second: "numeric",
    hourCycle: "h23",
  });
  function wall(date) {
    const p = {};
    for (const { type, value } of partsFormat.formatToParts(date)) p[type] = Number(value);
    return { year: p.year, month: p.month, day: p.day, hour: p.hour % 24, minute: p.minute, second: p.second };
  }
  function strftime(w, pattern) {
    const pad = (n) => String(n).padStart(2, "0");
    const months = texts && Array.isArray(texts.months) ? texts.months : [];
    return pattern.replace(/%[YmdeHMSb]/g, (code) => ({
      "%Y": String(w.year).padStart(4, "0"), "%m": pad(w.month), "%d": pad(w.day), "%e": String(w.day),
      "%H": pad(w.hour), "%M": pad(w.minute), "%S": pad(w.second ?? 0), "%b": months[w.month - 1] || pad(w.month),
    })[code]);
  }
  const dayNumber = (w) => Date.UTC(w.year, w.month - 1, w.day) / 86400000;

  /** "14:05" today, "yesterday 14:05", else "24 Oct 14:05" (the full date in another year). */
  function when(value, now = Date.now()) {
    const date = toDate(value);
    if (!date) return NONE;
    const w = wall(date), today = wall(toDate(now) || new Date());
    const clock = strftime(w, t("time_format"));
    const diff = dayNumber(today) - dayNumber(w);
    if (diff === 0) return clock;
    if (diff === 1) return fill(t("yesterday_at"), { time: clock });
    return `${strftime(w, w.year === today.year ? t("day_format") : t("date_format"))} ${clock}`;
  }
  function date(value) {
    const d = toDate(value);
    return d ? strftime(wall(d), t("date_format")) : NONE;
  }
  /** The full moment with seconds in the house's time (a tooltip; i18n.Format.stamp). */
  function stamp(value) {
    const d = toDate(value);
    return d ? strftime(wall(d), `${t("date_format")} %H:%M:%S`) : NONE;
  }
  /** A chart axis label: the clock for short spans, the day for long ones. */
  function axisTime(value, spanSeconds) {
    const d = toDate(value);
    if (!d) return "";
    const w = wall(d);
    // a year or more: months (January with its year); a few days and more: days; else the clock
    if (spanSeconds > 120 * 86400) return w.month === 1 ? String(w.year) : strftime(w, "%b");
    return spanSeconds > 2 * 86400 ? strftime(w, t("day_format")) : strftime(w, t("time_format"));
  }

  function room(ap) {
    if (!ap) return NONE;
    if (!ap.house) return ap.name || NONE;
    const parts = [texts?.[`room_${ap.house}`] ?? String(ap.house).charAt(0).toUpperCase() + String(ap.house).slice(1)];
    if (ap.floor !== null && ap.floor !== undefined && String(ap.floor) !== "") {
      parts.push(texts?.[`room_floor_${ap.floor}`] ?? fill(t("room_floor_n"), { n: ap.floor }));
    }
    if (ap.spot) parts.push(texts?.[`room_spot_${ap.spot}`] ?? String(ap.spot));
    return parts.join(" · ");
  }

  function proto(p, band) {
    if (!p) return null;
    const key = p === "ax" && String(band) === "6" ? "proto_ax6" : `proto_${p}`;
    return texts && key in texts ? texts[key] : t("proto_old");
  }
  function bandName(band) {
    return band ? fill(t("band_fmt"), { band: number(Number(band), String(band) === "2.4" ? 1 : 0) }) : null;
  }
  function wifi(device) {
    const parts = [];
    if (device.band) parts.push(bandName(device.band));
    if (device.channel) parts.push(fill(t("channel_fmt"), { channel: device.channel }));
    const p = proto(device.proto, device.band);
    if (p) parts.push(p);
    return parts.join(" · ") || NONE;
  }

  /** A day of the day bars: "24 Oct". */
  function day(value) {
    const d = toDate(value);
    return d ? strftime(wall(d), t("day_format")).trim() : NONE;
  }

  /** Where an incident is: the AP as a room, a switch or port by name, else the whole house. */
  function scope(incident) {
    const name = incident.subject_name || incident.subject || "";
    if (incident.ap && typeof incident.ap === "object") return room(incident.ap);
    if (!name) return t("inc_house_wide");
    if (String(incident.kind || "").startsWith("ap_")) return room(apFromName(name));
    return name;
  }
  function incidentText(incident) {
    if (!incident) return NONE;
    const inc = typeof incident === "object" ? incident : { kind: incident };
    const what = INCIDENT_KINDS.includes(inc.kind) ? t(`inc_${inc.kind}`) : t("inc_other");
    const where = scope(inc);
    return where ? `${what} (${where})` : what;
  }

  function evidenceValue(kind, value, admin = false) {
    const k = kind.startsWith("limit_") ? kind.slice(6) : kind;
    const pairs = (v) => (Array.isArray(v) ? v.map((x) => [x, null]) : Object.entries(v));
    try {
      switch (k) {
        case "dbm": case "db": case "percent": case "bitrate": case "duration": case "bytes": return api[k](value);
        case "per_hour": return fill(t("per_hour"), { n: number(value) });
        case "count": return number(value);
        case "rate": return `${number(value, 1)}/s`;
        case "days": return fill(t("days_n"), { n: value });
        case "when": return when(value);
        case "ago": return ago(value);
        case "recent": return recent(value);
        case "source": {
          const own = t(admin ? `src_admin_${value}` : `pr_src_${value}`);
          if (!own.startsWith(admin ? "src_admin_" : "pr_src_")) return own;
          const plainKey = t(`src_${value}`);
          return admin || plainKey === `src_${value}` ? String(value) : plainKey;
        }
        case "date": return date(value);
        case "times": return value.slice(0, 3).map((v) => when(v)).join(", ") + (value.length > 3 ? " …" : "");
        case "band": return bandName(value);
        case "bands": return value.map((b) => bandName(b)).join(", ");
        case "reason": return t(admin ? `rr_${reasonKey(value)}_admin` : `rr_${reasonKey(value)}`);
        case "reasons": return pairs(value).map(([r, n]) => (admin ? r : t(`rr_${reasonKey(r)}`)) + (n ? ` ×${n}` : "")).join(", ");
        case "causes": return pairs(value).map(([c, n]) => t(`cause_${causeKey(c)}`) + (admin ? ` (${c})` : "") + (n ? ` ×${n}` : "")).join(", ");
        case "room": return room(typeof value === "object" ? value : apFromName(value));
        case "ap_signals": return Object.entries(value).map(([a, v]) => `${room(apFromName(a))} ${dbm(v)}`).join(", ");
        case "incident": return typeof value === "object" && value.started ? `${incidentText(value)}, ${when(value.started)}` : incidentText(value);
        default: return plain(value);
      }
    } catch {
      return plain(value);
    }
  }

  /** A finding's evidence as [[label, text]] (the spec's order; for admins also the rest, as
   *  it is) and the span it looks at (or null): i18n.Format.evidence_items. */
  function evidenceItems(finding, admin = false) {
    const evidence = finding.evidence || {};
    const spec = EVIDENCE_SPEC[finding.code] || Object.keys(evidence).filter((k) => k in EVIDENCE_FORMAT).map((k) => [k, EVIDENCE_FORMAT[k]]);
    const items = [], used = new Set();
    for (const [key, kind] of spec) {
      used.add(key);
      const value = evidence[key];
      if (empty(value)) continue;
      items.push([kind.startsWith("limit_") ? t("evk_limit") : t(`evk_${key}`), evidenceValue(kind, value, admin)]);
    }
    if (admin) for (const [key, value] of Object.entries(evidence)) if (!used.has(key) && !empty(value)) items.push([key, plain(value)]);
    const span = EVIDENCE_WINDOW[finding.code];
    return { items, window: span ? t(`ev_last_${span}`) : null };
  }

  /** The one value a card shows beside a finding's title (i18n.Format.evidence_short). */
  function evidenceShort(finding) {
    const short = EVIDENCE_SHORT[finding.code];
    if (short) {
      const [key, kind] = short;
      let value = (finding.evidence || {})[key];
      if (value === null || value === undefined) value = (finding.params || {})[key];
      if (value === null || value === undefined || value === "") return null;
      return SHORT_TEXTS[kind] ? fill(t(SHORT_TEXTS[kind]), { n: number(value) }) : evidenceValue(kind, value);
    }
    const first = evidenceItems(finding).items[0];
    return first ? first[1] : null;
  }

  const api = { lang, t, fill, number, evidenceShort, bytes, bitrate, percent, dbm, db, ms, duration, ago, recent, elapsed, stamp,
    when, date, day, axisTime,
    room, proto, bandName, wifi, signalLevel, healthLevel, scope, incidentText, evidenceItems, evidenceValue,
    causeKey, reasonKey, apFromName };
  return api;
}
