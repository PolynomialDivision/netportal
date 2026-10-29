//! What the browser is (Python `web.py` `no_passpoint_browser`, `platform_of`, `enrol_options`,
//! `default_name`; INVENTORY 3.2 "Enrolment options per User-Agent"). The User-Agent is used for
//! this only and never stored or logged.

/// The downloadable formats of the enrol form.
pub const FORMATS: [&str; 4] = ["apple", "apple-mac", "android", "eap-config"];

/// An Android browser that saves a Passpoint file instead of handing it to Android's installer:
/// Firefox and its kin (Gecko). Only Chromium browsers install it (Firefox 158 on Android 15
/// downloaded the XML, 2026-10-23).
pub fn no_passpoint_browser(ua: &str) -> bool {
    ua.contains("Android") && (ua.contains("Firefox/") || (ua.contains("Gecko/") && !ua.contains("like Gecko")))
}

/// The enrolment options for this browser, best first.
pub fn platform_of(ua: &str) -> Vec<&'static str> {
    if ua.contains("iPhone") || ua.contains("iPad") {
        return vec!["apple"];
    }
    if ua.contains("Macintosh") {
        // a Mac, or an iPad asking for the desktop site
        return vec!["apple-mac", "apple"];
    }
    if no_passpoint_browser(ua) {
        // the app first: the Passpoint file does not install here
        return vec!["android-app", "android"];
    }
    if ua.contains("Android") {
        return vec!["android", "android-app"];
    }
    if ua.contains("Windows") {
        return vec!["windows"];
    }
    if ua.contains("Linux") || ua.contains("X11") {
        return vec!["linux"];
    }
    vec!["apple", "apple-mac", "android", "android-app", "windows", "linux"]
}

/// [`platform_of`] without the Passpoint download while it is off (the app comes first then).
pub fn enrol_options(ua: &str, passpoint: bool) -> Vec<&'static str> {
    platform_of(ua).into_iter().filter(|o| passpoint || *o != "android").collect()
}

/// The name a device gets when none is given.
pub fn default_name(format: &str, username: &str) -> String {
    let base = match format {
        "apple" => "iPhone/iPad",
        "apple-mac" => "Mac",
        "android" | "eap-config" => "Android",
        "letswifi" => "geteduroam",
        _ => "device",
    };
    cut_name(&format!("{base} ({username})")).unwrap_or_else(|| base.to_string())
}

/// Characters that change how text around them is shown without being seen themselves: the
/// bidirectional controls (a name could reverse the text after it on the admin page, U+202A-E,
/// U+2066-9, U+200E/F, U+061C) and the invisible ones (zero-width space, joiners, word joiner and
/// invisible operators, the byte order mark, the soft hyphen, the Mongolian vowel separator, the
/// interlinear annotation marks, the deprecated format characters U+206A-F, tags U+E0000-7F).
pub fn is_invisible_format(c: char) -> bool {
    matches!(c,
        '\u{00AD}' | '\u{061C}' | '\u{180E}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{206F}' | '\u{FEFF}' | '\u{FFF9}'..='\u{FFFB}'
        | '\u{E0000}'..='\u{E007F}')
}

/// Text as people will see it: control characters and [`is_invisible_format`] characters
/// removed (names of devices and people are shown on other people's pages).
pub fn visible_text(raw: &str) -> String {
    raw.chars().filter(|c| !c.is_control() && !is_invisible_format(*c)).collect()
}

/// A device name as entered: control, bidi and zero-width characters removed
/// ([`visible_text`]), whitespace trimmed, then at most 60 characters (the registry's limit);
/// `None` when nothing is left.
pub fn cut_name(raw: &str) -> Option<String> {
    let clean = visible_text(raw);
    let cut: String = clean.trim().chars().take(60).collect();
    (!cut.is_empty()).then_some(cut)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIREFOX: &str = "Mozilla/5.0 (Android 15; Mobile; rv:158.0) Gecko/158.0 Firefox/158.0";
    const CHROME: &str =
        "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Mobile Safari/537.36";

    #[test]
    fn test_detection() {
        // Python PlatformTests.test_detection
        assert_eq!(platform_of("Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)"), ["apple"]);
        assert_eq!(platform_of("Mozilla/5.0 (iPad; CPU OS 18_0 like Mac OS X)"), ["apple"]);
        assert_eq!(platform_of("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"), ["apple-mac", "apple"]);
        assert_eq!(platform_of(CHROME), ["android", "android-app"]);
        assert_eq!(platform_of("Mozilla/5.0 (Windows NT 10.0; Win64; x64)"), ["windows"]);
        assert_eq!(platform_of("Mozilla/5.0 (X11; Linux x86_64)"), ["linux"]);
        assert_eq!(platform_of("curl/8"), ["apple", "apple-mac", "android", "android-app", "windows", "linux"]);
    }

    #[test]
    fn test_firefox_on_android_gets_the_app_first() {
        assert!(no_passpoint_browser(FIREFOX));
        assert!(!no_passpoint_browser(CHROME));
        assert!(!no_passpoint_browser("Mozilla/5.0 (X11; Linux x86_64; rv:144.0) Gecko/20100101 Firefox/144.0"));
        assert_eq!(platform_of(FIREFOX), ["android-app", "android"]);
    }

    #[test]
    fn test_passpoint_off_puts_the_app_first() {
        assert_eq!(enrol_options(CHROME, false), ["android-app"]);
        assert_eq!(enrol_options(CHROME, true), ["android", "android-app"]);
        assert_eq!(enrol_options("curl/8", false), ["apple", "apple-mac", "android-app", "windows", "linux"]);
    }

    #[test]
    fn test_names() {
        assert_eq!(default_name("apple", "res"), "iPhone/iPad (res)");
        assert_eq!(default_name("apple-mac", "res"), "Mac (res)");
        assert_eq!(default_name("eap-config", "res"), "Android (res)");
        assert_eq!(default_name("letswifi", "res"), "geteduroam (res)");
        assert_eq!(default_name("x", "res"), "device (res)");
        assert_eq!(cut_name(&format!("  {}  ", "x".repeat(70))).as_deref(), Some("x".repeat(60).as_str()));
        assert_eq!(cut_name("  Küchen-iPad  ").as_deref(), Some("Küchen-iPad"));
        assert_eq!(cut_name(" \t\n "), None);
        assert_eq!(cut_name("a\u{0}b\nc").as_deref(), Some("abc"));
        assert_eq!(
            cut_name(&format!("{} y", "x".repeat(59))).as_deref(),
            Some(format!("{} ", "x".repeat(59)).as_str())
        );
        assert_eq!(default_name("apple", &"u".repeat(80)).chars().count(), 60);
    }

    #[test]
    fn test_names_lose_bidi_and_zero_width_characters() {
        // security review 2026-10-29 I5: a name must not reverse or hide text on the admin page
        assert_eq!(cut_name("evil\u{202E}gnp.exe").as_deref(), Some("evilgnp.exe"));
        assert_eq!(cut_name("a\u{2066}b\u{2069}c\u{200F}d\u{061C}e").as_deref(), Some("abcde"));
        assert_eq!(cut_name("ad\u{200B}min\u{200D}\u{2060}\u{FEFF}").as_deref(), Some("admin"));
        assert_eq!(cut_name("soft\u{00AD}hyphen\u{E0041}").as_deref(), Some("softhyphen"));
        assert_eq!(cut_name("\u{200B}\u{202E} \u{2060}"), None);
        // visible non-ASCII stays
        assert_eq!(cut_name("Küchen-iPad 📱 Київ").as_deref(), Some("Küchen-iPad 📱 Київ"));
        assert_eq!(visible_text("Anna\u{202E}lisa"), "Annalisa");
    }
}
