//! A home device's Wi-Fi key as a QR code (house-infra docs/IOT-ACCESS.md 6.6): the Wi-Fi
//! network string phones read (`WIFI:T:WPA;S:<ssid>;P:<key>;;`, the ZXing convention every
//! camera app follows), rendered server-side as inline SVG (`qrcode`, error correction M). No
//! image, no script: the SVG is part of the page, so the strict CSP is untouched and the key
//! never leaves the page as a separate request.

use qrcode::render::svg;
use qrcode::{EcLevel, QrCode};

/// The characters the Wi-Fi string escapes with a backslash (ZXing's `WifiParsedResult`).
const ESCAPED: [char; 5] = ['\\', ';', ',', '"', ':'];

fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 4);
    for c in text.chars() {
        if ESCAPED.contains(&c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// `WIFI:T:WPA;S:<ssid>;P:<key>;;` with the network name and key escaped.
pub fn wifi_string(ssid: &str, psk: &str) -> String {
    format!("WIFI:T:WPA;S:{};P:{};;", escape(ssid), escape(psk))
}

/// The text as an inline SVG (`<svg class="qr" ...>`, black on white whatever the page's colour
/// scheme: a scanner needs the contrast), or `None` for a text the encoder refuses.
pub fn svg(text: &str) -> Option<String> {
    let code = QrCode::with_error_correction_level(text.as_bytes(), EcLevel::M).ok()?;
    let xml = code.render::<svg::Color>().min_dimensions(176, 176).build();
    // the renderer's XML declaration has no place inside a page; the attributes after it are
    // the renderer's own (xmlns, viewBox, shape-rendering)
    let rest = xml.strip_prefix(r#"<?xml version="1.0" standalone="yes"?><svg "#)?;
    Some(format!(r#"<svg class="qr" aria-hidden="true" {rest}"#))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wifi_string_escapes() {
        assert_eq!(
            wifi_string("Scharni-IoT", "abcDEF0123456789wxYZ"),
            "WIFI:T:WPA;S:Scharni-IoT;P:abcDEF0123456789wxYZ;;"
        );
        assert_eq!(wifi_string(r#"a;b:c"d\e,f"#, "k"), r#"WIFI:T:WPA;S:a\;b\:c\"d\\e\,f;P:k;;"#);
    }

    #[test]
    fn test_svg_is_inline() {
        let svg = svg(&wifi_string("Scharni-IoT", "abcDEF0123456789wxYZ")).expect("an svg");
        assert!(svg.starts_with(r#"<svg class="qr" aria-hidden="true" xmlns="http://www.w3.org/2000/svg""#), "{svg}");
        assert!(svg.ends_with("</svg>"));
        assert!(!svg.contains("<?xml") && !svg.contains("style="));
        assert!(svg.contains("viewBox="));
    }
}
