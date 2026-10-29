//! Translations (Python: `netportal/i18n.py` data, INVENTORY 11): `i18n.json`, generated from
//! `netportal/i18n.py` by `rust/tools/export_i18n.py` and embedded at build time, plus
//! `i18n_rust.json`: the few texts only the Rust version has (written by hand in every language;
//! they only add keys, never replace one of `i18n.json`'s).
//!
//! The helper API: [`pick`] (the request's language), [`texts`] / [`text`] / [`list`]
//! (lookup), [`fill`] (interpolation), [`format_number`] (numbers in the language's style),
//! [`tables`] (the code tables of `i18n.py`: `DIAGNOSES`, `PLATFORM_LABEL`, the evidence
//! tables, ...). There are no plural forms: the texts avoid inflection (`"{n} devices"`,
//! Ukrainian `"Пристроїв: {n}"`), as in the Python version.

use std::sync::LazyLock;

use indexmap::IndexMap;
use serde::Deserialize;
use serde_json::Value;

/// One text: a string, or a list of strings (install steps, month names).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum Text {
    One(String),
    List(Vec<String>),
}

#[derive(Debug, Deserialize)]
struct Data {
    languages: Vec<String>,
    texts: IndexMap<String, IndexMap<String, Text>>,
    tables: serde_json::Map<String, Value>,
}

/// The embedded file (also read by the up-to-date test).
pub const I18N_JSON: &str = include_str!("../i18n.json");
/// The Rust version's own texts.
pub const I18N_RUST_JSON: &str = include_str!("../i18n_rust.json");

#[derive(Debug, Deserialize)]
struct Extra {
    texts: IndexMap<String, IndexMap<String, Text>>,
}

static DATA: LazyLock<Data> = LazyLock::new(|| {
    let mut data: Data = serde_json::from_str(I18N_JSON).expect("i18n.json is generated valid by export_i18n.py");
    let extra: Extra = serde_json::from_str(I18N_RUST_JSON).expect("i18n_rust.json is valid (tested)");
    for (lang, texts) in extra.texts {
        if let Some(target) = data.texts.get_mut(&lang) {
            for (key, text) in texts {
                target.entry(key).or_insert(text);
            }
        }
    }
    data
});

/// The languages, the default first: `en`, `de`, `uk`.
pub fn languages() -> &'static [String] {
    &DATA.languages
}

/// The default language.
pub const DEFAULT: &str = "en";

fn known(code: &str) -> Option<&'static str> {
    DATA.languages.iter().find(|l| *l == code).map(String::as_str)
}

/// The request's language: the house's cookie `house_lang` when it is one of ours (exactly,
/// as the house's start page sets it), else the best match of `Accept-Language` by its
/// q-values (RFC 9110 12.5.4; equal weights keep header order; `q=0` excludes) on the primary
/// subtag (`de-AT` -> `de`), with Russian mapped to Ukrainian (the house's choice); else `en`.
pub fn pick(accept_language: Option<&str>, house_lang: Option<&str>) -> &'static str {
    if let Some(lang) = house_lang.and_then(known) {
        return lang;
    }
    let mut ranges: Vec<(f32, usize, String)> = Vec::new();
    for (index, part) in accept_language.unwrap_or("").split(',').enumerate() {
        let mut pieces = part.split(';');
        let tag = pieces.next().unwrap_or("").trim().to_ascii_lowercase();
        let mut q = 1.0f32;
        for param in pieces {
            if let Some((name, value)) = param.split_once('=')
                && name.trim().eq_ignore_ascii_case("q")
            {
                q = value.trim().parse::<f32>().ok().filter(|q| (0.0..=1.0).contains(q)).unwrap_or(0.0);
            }
        }
        let primary = tag.split('-').next().unwrap_or("").to_string();
        if q > 0.0 && !primary.is_empty() && primary != "*" {
            ranges.push((q, index, primary));
        }
    }
    ranges.sort_by(|a, b| b.0.total_cmp(&a.0).then(a.1.cmp(&b.1)));
    for (_, _, primary) in ranges {
        let code = if primary == "ru" { "uk" } else { primary.as_str() };
        if let Some(lang) = known(code) {
            return lang;
        }
    }
    DEFAULT
}

/// Every text of a language (an unknown language gives English).
pub fn texts(lang: &str) -> &'static IndexMap<String, Text> {
    DATA.texts.get(lang).or_else(|| DATA.texts.get(DEFAULT)).unwrap_or_else(|| {
        static EMPTY: LazyLock<IndexMap<String, Text>> = LazyLock::new(IndexMap::new);
        &EMPTY
    })
}

/// A text of a language (`None`: no such key, or the key is a list).
pub fn text(lang: &str, key: &str) -> Option<&'static str> {
    match texts(lang).get(key) {
        Some(Text::One(s)) => Some(s),
        _ => None,
    }
}

/// A list text of a language (`None`: no such key, or the key is a single text).
pub fn list(lang: &str, key: &str) -> Option<&'static [String]> {
    match texts(lang).get(key) {
        Some(Text::List(items)) => Some(items),
        _ => None,
    }
}

/// The code tables of `i18n.py` (`DIAGNOSES`, `PLATFORM_LABEL`, `SEPARATORS`, ...) by name.
pub fn tables() -> &'static serde_json::Map<String, Value> {
    &DATA.tables
}

/// `template` with every `{name}` replaced by its value; unknown names stay as they are (the
/// same rule as the browser's `fill()`, `static/format.js`, so a page reads the same whichever
/// side rendered it). Values are inserted as given (escaping is the template engine's job).
pub fn fill(template: &str, values: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(template.len() + 16);
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let name_len = after.find(|c: char| !(c.is_alphanumeric() || c == '_')).unwrap_or(after.len());
        let name = &after[..name_len];
        if name_len > 0 && after[name_len..].starts_with('}') {
            match values.iter().find(|(k, _)| *k == name) {
                Some((_, v)) => out.push_str(v),
                None => {
                    out.push('{');
                    out.push_str(name);
                    out.push('}');
                }
            }
            rest = &after[name_len + 1..];
        } else {
            out.push('{');
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

/// The `{name}` placeholders of a text, sorted.
pub fn placeholders(template: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        let after = &rest[start + 1..];
        let len = after.find(|c: char| !(c.is_alphanumeric() || c == '_')).unwrap_or(after.len());
        if len > 0 && after[len..].starts_with('}') {
            names.push(after[..len].to_string());
            rest = &after[len + 1..];
        } else {
            rest = after;
        }
    }
    names.sort();
    names
}

/// The language's (thousands, decimal) separators (`SEPARATORS` of `i18n.py`: en `,` `.`, de
/// `.` `,`, uk U+00A0 `,`; English for an unknown language).
pub fn separators(lang: &str) -> (String, String) {
    let table = tables().get("SEPARATORS");
    let pair = |l: &str| {
        table.and_then(|t| t.get(l)).and_then(Value::as_array).and_then(|a| match a.as_slice() {
            [Value::String(t), Value::String(d)] => Some((t.clone(), d.clone())),
            _ => None,
        })
    };
    let (thousands, decimal) = pair(lang).or_else(|| pair(DEFAULT)).unwrap_or_else(|| (",".into(), ".".into()));
    // Python wrote a plain space for Ukrainian; the browser (Intl) and this port use U+00A0
    let thousands = if thousands == " " { "\u{a0}".to_string() } else { thousands };
    (thousands, decimal)
}

/// A number in the language's style with `digits` decimals (rounding of
/// [`crate::conventions::round_to`], U+2212 minus); `FORMAT_NONE` (`–`) for no value.
pub fn format_number(value: Option<f64>, lang: &str, digits: u32) -> String {
    let none = || tables().get("FORMAT_NONE").and_then(Value::as_str).unwrap_or("\u{2013}").to_string();
    let Some(value) = value else {
        return none();
    };
    let (thousands, decimal) = separators(lang);
    crate::conventions::format_fixed(value, digits, &thousands, &decimal).unwrap_or_else(none)
}

#[cfg(test)]
mod tests {
    use super::*;

    // tests/test_units.py LanguageTests, TextTests; tests/test_web.py HouseLookTests (pick)

    #[test]
    fn test_pick() {
        assert_eq!(pick(Some("de-DE,de;q=0.9,en;q=0.8"), None), "de");
        assert_eq!(pick(Some("uk"), None), "uk");
        assert_eq!(pick(Some("ru-RU"), None), "uk");
        assert_eq!(pick(Some("fr"), None), "en");
        assert_eq!(pick(None, None), "en");
        assert_eq!(pick(Some("*"), None), "en");
        assert_eq!(pick(Some("de-AT"), None), "de");
    }

    #[test]
    fn test_pick_honours_q_values() {
        // Python took the header order and ignored q (deliberate deviation)
        assert_eq!(pick(Some("en;q=0.1, de;q=0.9"), None), "de");
        assert_eq!(pick(Some("fr, de;q=0.5, en;q=0.4"), None), "de");
        assert_eq!(pick(Some("de;q=0, en"), None), "en");
        assert_eq!(pick(Some("en, de"), None), "en"); // equal weights: header order
        assert_eq!(pick(Some("english"), None), "en".to_string().as_str()); // no prefix matching
        assert_eq!(pick(Some("ukr"), None), "en");
    }

    #[test]
    fn test_house_cookie_wins() {
        assert_eq!(pick(Some("de"), Some("uk")), "uk");
        assert_eq!(pick(Some("de"), Some("fr")), "de");
        assert_eq!(pick(Some("de"), Some("UK")), "de"); // the house sets lower-case codes
        assert_eq!(pick(None, Some("de")), "de");
    }

    #[test]
    fn test_every_language_has_every_text() {
        assert_eq!(languages(), ["en", "de", "uk"]);
        let en = texts("en");
        assert_eq!(en.len(), 764); // 760 of i18n.json, 4 of i18n_rust.json
        for lang in languages() {
            let other = texts(lang);
            let mut a: Vec<_> = en.keys().collect();
            let mut b: Vec<_> = other.keys().collect();
            a.sort();
            b.sort();
            assert_eq!(a, b, "{lang}");
        }
    }

    #[test]
    fn test_same_keys_and_placeholders() {
        for (key, value) in texts("en") {
            for lang in ["de", "uk"] {
                let other = &texts(lang)[key];
                let (a, b) = match (value, other) {
                    (Text::One(a), Text::One(b)) => (a.clone(), b.clone()),
                    (Text::List(a), Text::List(b)) => {
                        assert_eq!(a.len(), b.len(), "{lang} {key}");
                        (a.join(" "), b.join(" "))
                    }
                    _ => panic!("{lang} {key}: not the same kind of text"),
                };
                assert_eq!(placeholders(&a), placeholders(&b), "{lang} {key}");
            }
        }
        let labels = tables()["PLATFORM_LABEL"].as_object().cloned().unwrap_or_default();
        assert_eq!(labels.len(), 5);
        for label in labels.values() {
            assert!(label.as_str().is_some_and(|k| texts("en").contains_key(k)), "{label}");
        }
    }

    #[test]
    fn test_rust_texts_only_add() {
        let generated: Data = serde_json::from_str(I18N_JSON).expect("i18n.json");
        let extra: Extra = serde_json::from_str(I18N_RUST_JSON).expect("i18n_rust.json");
        let langs: Vec<&String> = extra.texts.keys().collect();
        assert_eq!(langs, languages().iter().collect::<Vec<_>>());
        for (lang, texts) in &extra.texts {
            for key in texts.keys() {
                assert!(!generated.texts[lang].contains_key(key), "{lang} {key} is in i18n.json already");
            }
        }
        assert_eq!(text("de", "consent_app"), Some("App"));
        assert!(text("uk", "too_many_devices").is_some_and(|t| t.contains("{n}")));
    }

    #[test]
    fn test_lookup() {
        assert!(text("de", "error").is_some());
        assert_eq!(text("xx", "error"), text("en", "error"));
        assert_eq!(text("en", "no-such-key"), None);
        assert_eq!(list("en", "months").map(<[String]>::len), Some(12));
        assert_eq!(list("de", "months").and_then(|m| m.get(2)).map(String::as_str), Some("März"));
        assert_eq!(text("en", "months"), None);
        assert_eq!(tables()["HOUSE_TZ"], "Europe/Berlin");
        assert_eq!(tables()["DIAGNOSES"].as_array().map(Vec::len), Some(19));
    }

    #[test]
    fn test_fill() {
        assert_eq!(fill("{n} devices", &[("n", "3")]), "3 devices");
        assert_eq!(fill("{a} and {b}", &[("b", "B")]), "{a} and B");
        assert_eq!(fill("{ x } {} {n", &[("x", "X"), ("n", "N")]), "{ x } {} {n");
        assert_eq!(fill("{n}{n}", &[("n", "1")]), "11");
        assert_eq!(fill("Пристроїв: {n}", &[("n", "2")]), "Пристроїв: 2");
        assert_eq!(placeholders("{b} {a} {a}"), ["a", "a", "b"]);
    }

    #[test]
    fn test_format_number() {
        assert_eq!(format_number(Some(1234567.891), "en", 0), "1,234,568");
        assert_eq!(format_number(Some(1234.5), "de", 1), "1.234,5");
        assert_eq!(format_number(Some(-1234.5), "uk", 1), "\u{2212}1\u{a0}234,5");
        assert_eq!(format_number(Some(2.5), "xx", 0), "3");
        assert_eq!(format_number(None, "en", 0), "\u{2013}");
    }

    #[test]
    fn test_json_is_up_to_date() {
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/export_i18n.py");
        let output = std::process::Command::new("python3").arg("-I").arg(&script).arg("--stdout").output();
        match output {
            Ok(out) if out.status.success() => {
                assert!(
                    String::from_utf8_lossy(&out.stdout) == I18N_JSON,
                    "i18n.json is out of date with netportal/i18n.py: run python3 rust/tools/export_i18n.py"
                );
            }
            Ok(out) => eprintln!(
                "skipped: export_i18n.py failed (is netportal/i18n.py readable?): {}",
                String::from_utf8_lossy(&out.stderr)
            ),
            Err(e) => eprintln!("skipped: python3 is not available ({e})"),
        }
    }
}
