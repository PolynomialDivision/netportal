// static/format.js: numbers, sizes, rates, durations, times and rooms per language, and that
// they read exactly like the server's (netportal/i18n.py Format) for the same values.
// node --test tests/js/

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { createFormatter, fill, signalLevel, healthLevel, toDate, DIAGNOSES } from "../../netportal/static/format.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const NOW = "2026-10-25T12:05:00+00:00";

// The cases both formatters get; the server's answers come from python3.
const CASES = [
  ["bytes", [1234567890]], ["bytes", [999]], ["bytes", [42_000_000]], ["bytes", [null]],
  ["bitrate", [86_600_000]], ["bitrate", [950]], ["bitrate", [1_200_000_000]], ["bitrate", [4_200]],
  ["percent", [0.0123, 1]], ["percent", [0.72]], ["dbm", [-58]], ["db", [37]], ["ms", [9.8]], ["ms", [11.4]],
  ["duration", [8130]], ["duration", [3 * 86400 + 4000]], ["duration", [42]], ["duration", [7200]], ["duration", [0]],
  ["ago", ["2026-10-25T10:00:00Z", NOW]], ["ago", ["2026-10-25T12:04:30Z", NOW]],
  ["when", ["2026-10-25T10:00:00Z", NOW]], ["when", ["2026-10-24T10:00:00Z", NOW]], ["when", ["2026-10-02T10:00:00Z", NOW]],
  ["when", ["2025-12-31T23:30:00Z", NOW]], ["date", ["2026-03-29T01:30:00Z"]],
  ["number", [12345.6, 1]], ["number", [-3]],
  ["room", [{ name: "ap-scharni-2-corner", house: "scharni", floor: 2, spot: "corner" }]],
  ["room", [{ name: "ap-colbe-0-schlaglicht", house: "colbe", floor: 0, spot: "schlaglicht" }]],
  ["room", [{ name: "2. stock scharni mitte", house: null, floor: null, spot: null }]],
  ["room", [{ name: "ap-x-7-far", house: "x", floor: 7, spot: "far" }]],
  ["wifi", [{ band: "2.4", channel: 6, proto: "n" }]], ["wifi", [{ band: "6", channel: 37, proto: "ax" }]],
  ["wifi", [{ band: "5", channel: 36, proto: "b" }]], ["band", ["2.4"]],
];

const PY = `
import json, sys
sys.path.insert(0, ${JSON.stringify(root)})
from netportal import i18n
cases = json.loads(sys.stdin.read())
out = {"texts": i18n.TEXT, "answers": {}}
for lang in ("en", "de", "uk"):
    answers = []
    for name, args in cases:
        fn = getattr(i18n.Format, name)
        if name in ("ago", "when"):
            answers.append(fn(args[0], lang, args[1]))
        elif name in ("duration",) or len(args) == 1:
            answers.append(fn(args[0], lang))
        else:
            answers.append(fn(args[0], lang, args[1]))
    out["answers"][lang] = answers
print(json.dumps(out))
`;

let server = null;
try {
  server = JSON.parse(execFileSync("python3", ["-c", PY], { input: JSON.stringify(CASES), encoding: "utf8" }));
} catch {
  server = null;   // no python3: the cross-check is skipped, the rest still runs
}
const texts = server ? server.texts : null;

function call(f, name, args) {
  if (name === "ago" || name === "when") return f[name](args[0], args[1]);
  if (name === "band") return f.bandName(args[0]);
  return f[name](...args);
}

test("the browser formats like the server, in every language", { skip: !server && "python3 not available" }, () => {
  for (const lang of ["en", "de", "uk"]) {
    const f = createFormatter(lang, texts[lang]);
    CASES.forEach(([name, args], i) => {
      assert.equal(call(f, name, args), server.answers[lang][i], `${lang} ${name}(${JSON.stringify(args)})`);
    });
  }
});

test("examples read naturally", { skip: !server && "python3 not available" }, () => {
  const en = createFormatter("en", texts.en), de = createFormatter("de", texts.de), uk = createFormatter("uk", texts.uk);
  assert.equal(en.bytes(1_830_000_000), "1.8 GB");
  assert.equal(de.bytes(1_830_000_000), "1,8 GB");
  assert.equal(uk.bytes(1_830_000_000), "1,8 ГБ");
  assert.equal(en.bitrate(866_000_000), "866 Mbit/s");
  assert.equal(de.duration(8130), "2 Std. 15 Min.");
  assert.equal(en.ago("2026-10-25T09:05:00Z", NOW), "3 h ago");
  assert.equal(de.ago("2026-10-25T09:05:00Z", NOW), "vor 3 Std.");
  assert.equal(en.when("2026-10-24T20:00:00Z", NOW), "yesterday 22:00");    // the house's clock (CEST)
  assert.equal(en.room({ house: "scharni", floor: 2, spot: "corner" }), "Scharni · 2nd floor · corner");
  assert.equal(uk.room({ house: "scharni", floor: 0, spot: "middle" }), "Scharni · перший поверх · середина");
  assert.equal(en.dbm(-58), "−58 dBm");
  assert.equal(en.wifi({ band: "6", channel: 37, proto: "ax" }), "6 GHz · channel 37 · Wi-Fi 6E");
});

test("unknown values are a dash, never a zero", () => {
  const f = createFormatter("en", {});
  for (const fn of [f.bytes, f.bitrate, f.percent, f.dbm, f.ms, f.duration, f.number]) assert.equal(fn(null), "–");
  assert.equal(f.ago(null), "–");
  assert.equal(f.when("not a time"), "–");
  assert.equal(f.room(null), "–");
});

test("signal and quality levels", () => {
  assert.deepEqual(signalLevel(-55), { bars: 4, key: "sig_excellent", tone: "ok" });
  assert.deepEqual(signalLevel(-60), { bars: 4, key: "sig_excellent", tone: "ok" });
  assert.deepEqual(signalLevel(-67), { bars: 3, key: "sig_good", tone: "ok" });
  assert.deepEqual(signalLevel(-70), { bars: 2, key: "sig_fair", tone: "warn" });
  assert.deepEqual(signalLevel(-80), { bars: 1, key: "sig_weak", tone: "warn" });
  assert.deepEqual(signalLevel(-90), { bars: 0, key: "sig_very_weak", tone: "bad" });
  assert.equal(signalLevel(null), null);
  assert.deepEqual(healthLevel(80), { key: "q_good", tone: "ok" });
  assert.deepEqual(healthLevel(79), { key: "q_fair", tone: "warn" });
  assert.deepEqual(healthLevel(10), { key: "q_poor", tone: "bad" });
  assert.equal(healthLevel(undefined), null);
});

test("every diagnosis code has its three texts in every language", { skip: !server && "python3 not available" }, () => {
  for (const lang of ["en", "de", "uk"]) {
    for (const code of DIAGNOSES) {
      for (const suffix of ["", "_why", "_do"]) assert.ok(texts[lang][`diag_${code}${suffix}`], `${lang} diag_${code}${suffix}`);
    }
  }
});

test("fill and toDate", () => {
  assert.equal(fill("{n} of {total}", { n: 1, total: 3 }), "1 of 3");
  assert.equal(fill("{n} {missing}", { n: 1 }), "1 {missing}");
  assert.equal(toDate(1_800_000_000_000).getTime(), 1_800_000_000_000);
  assert.equal(toDate(""), null);
  assert.equal(toDate("2026-10-25T12:00:00Z").toISOString(), "2026-10-25T12:00:00.000Z");
});
