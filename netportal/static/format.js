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
  "frequent_disconnects", "stuck_on_2ghz", "slow_link", "stale_data", "offline", "never_connected", "mac_conflict"];

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

  // The house's wall clock for a moment, without depending on the browser's own zone.
  const partsFormat = new Intl.DateTimeFormat("en-GB", {
    timeZone, year: "numeric", month: "numeric", day: "numeric", hour: "numeric", minute: "numeric", hourCycle: "h23",
  });
  function wall(date) {
    const p = {};
    for (const { type, value } of partsFormat.formatToParts(date)) p[type] = Number(value);
    return { year: p.year, month: p.month, day: p.day, hour: p.hour % 24, minute: p.minute };
  }
  function strftime(w, pattern) {
    const pad = (n) => String(n).padStart(2, "0");
    const months = texts && Array.isArray(texts.months) ? texts.months : [];
    return pattern.replace(/%[YmdeHMb]/g, (code) => ({
      "%Y": String(w.year).padStart(4, "0"), "%m": pad(w.month), "%d": pad(w.day), "%e": String(w.day),
      "%H": pad(w.hour), "%M": pad(w.minute), "%b": months[w.month - 1] || pad(w.month),
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
  /** A chart axis label: the clock for short spans, the day for long ones. */
  function axisTime(value, spanSeconds) {
    const d = toDate(value);
    if (!d) return "";
    const w = wall(d);
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

  return { lang, t, fill, number, bytes, bitrate, percent, dbm, db, ms, duration, ago, when, date, axisTime,
    room, proto, bandName, wifi, signalLevel, healthLevel };
}
