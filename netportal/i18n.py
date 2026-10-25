"""The portal's texts in German, English and Ukrainian (the house's languages).

Every key exists in all three languages (tests/test_units.py checks it). Step lists are lists;
{ssid} and {host} are filled by the templates.
"""

TEXT = {
    "en": {
        "title": "Wi-Fi",
        "tagline": "The house Wi-Fi for your devices",
        "login": "Log in with the house account",
        "logout": "Log out",
        "intro": "Connect your devices to the house Wi-Fi. Each device gets its own key; you can remove it here at any time.",
        "landing_1": "Log in once, add your device, done: from then on it connects by itself.",
        "landing_2": "Every device gets its own key. There is no Wi-Fi password that could be passed on.",
        "landing_3": "Lost or sold? Remove the device here and it is out at once.",
        "date_format": "%Y-%m-%d",
        "your_devices": "Your devices",
        "devices_count": "{n} devices",
        "no_devices": "No devices yet.",
        "no_devices_hint": "Start with the device you are using right now.",
        "add_device": "Connect this device",
        "detected": "Detected: {device}",
        "detected_help": "Not your device? Every other kind is listed below.",
        "add_other": "Another device",
        "connect_apple": "Connect this iPhone or iPad",
        "connect_mac": "Connect this Mac",
        "connect_android": "Connect this Android phone",
        "connect_android_app": "Connect with the geteduroam app",
        "other_browser": "Firefox cannot install the Wi-Fi profile on Android, it only saves the file. Open this page in Chrome (or another Chromium browser such as Vanadium or Samsung Internet), or use the geteduroam app.",
        "connect_desktop": "Connect this computer",
        "device_name": "Name of the device",
        "added": "added",
        "expires": "valid until",
        "expires_badge": "expires soon",
        "expires_soon": "expires soon: renew",
        "renew_action": "Renew now",
        "last_seen": "last connected",
        "never": "not connected yet",
        "rename": "Rename",
        "save": "Save",
        "cancel": "Cancel",
        "renew": "Renew",
        "revoke": "Remove",
        "revoke_title": "Remove this device",
        "revoke_confirm": "Remove this device? It loses Wi-Fi access at once.",
        "revoke_note": "Afterwards it cannot join the Wi-Fi anymore. To use it again later, simply add it anew.",
        "revoked": "Removed. The device has no Wi-Fi access anymore.",
        "for_apple": "iPhone or iPad",
        "for_mac": "Mac",
        "for_android": "Android",
        "for_android_app": "Android with the geteduroam app",
        "for_app": "geteduroam app",
        "for_windows": "Windows",
        "for_linux": "Linux",
        "install": "Install",
        "load_profile": "Load profile",
        "steps_apple": [
            "Tap \"Load profile\", then \"Allow\".",
            "Open Settings: at the top it says \"Profile Downloaded\".",
            "Tap it, then \"Install\", and enter your device code.",
            "Done. From now on the device joins {ssid} by itself.",
        ],
        "steps_mac": [
            "Click \"Load profile\".",
            "Open System Settings → Privacy & Security → Profiles and install the profile \"{ssid}\".",
            "Done. From now on the Mac joins {ssid} by itself.",
        ],
        "steps_android": [
            "Tap \"Install\".",
            "Android asks whether to save the Wi-Fi profile: confirm.",
            "Done. From now on the phone joins {ssid} by itself.",
        ],
        "steps_android_app": [
            "Install the geteduroam app (Google Play or F-Droid) if you have not yet.",
            "Tap \"Install\": the file opens in the app.",
            "Confirm in the app. Done: the phone joins {ssid} by itself.",
        ],
        "steps_app": [
            "Download the geteduroam app and open it.",
            "Enter {host} as the server.",
            "Log in with the house account. The app sets up the Wi-Fi {ssid} itself.",
        ],
        "install_apple": "Tap Install, then Allow. Open Settings, tap \"Profile Downloaded\" and Install. Done: the device joins {ssid} by itself.",
        "install_mac": "Click Install. Open System Settings, Privacy & Security, Profiles, and install the profile. Done.",
        "install_android": "Tap Install and confirm. Done: the phone joins {ssid} by itself.",
        "install_android_app": "Install the geteduroam app (Google Play or F-Droid), then tap Install here: the file opens in the app.",
        "install_app": "Install the geteduroam app, open it and enter {host} as the server. Log in when it asks; the app sets up Wi-Fi itself.",
        "get_app": "Get the geteduroam app",
        "link_once": "This link works once and for ten minutes.",
        "back_devices": "Back to your devices",
        "back_home": "Back to the start",
        "consent": "Connect the geteduroam app on this device to the house Wi-Fi?",
        "consent_note": "The app gets a key for this device and sets up the Wi-Fi {ssid}. You can remove the device under \"Your devices\" at any time.",
        "consent_name_help": "This is how the device appears in your list.",
        "allow": "Connect",
        "admin": "All devices",
        "admin_intro": "Every device in the house. Removing a device disconnects it at once.",
        "owner": "Owner",
        "no_access": "Your account has no access to the house Wi-Fi.",
        "error": "Something went wrong. Please try again.",
        "privacy": "Stored: the device's name, when it was added and last connected. Shown from the house's network monitoring (kept 90 days): where and when your devices were connected, their signal and how much data they moved. Never: what you do online. You see only your devices; the house admins see everyone's, to help with Wi-Fi problems.",
        "house_nav": "House",
    },
    "de": {
        "title": "WLAN",
        "tagline": "Das Haus-WLAN für deine Geräte",
        "login": "Mit dem Haus-Konto anmelden",
        "logout": "Abmelden",
        "intro": "Verbinde deine Geräte mit dem Haus-WLAN. Jedes Gerät bekommt einen eigenen Schlüssel; du kannst es hier jederzeit entfernen.",
        "landing_1": "Einmal anmelden, Gerät hinzufügen, fertig: Ab dann verbindet es sich von selbst.",
        "landing_2": "Jedes Gerät bekommt seinen eigenen Schlüssel. Es gibt kein WLAN-Passwort, das jemand weitergeben könnte.",
        "landing_3": "Verloren oder verkauft? Hier entfernen, und das Gerät ist sofort draußen.",
        "date_format": "%d.%m.%Y",
        "your_devices": "Deine Geräte",
        "devices_count": "{n} Geräte",
        "no_devices": "Noch keine Geräte.",
        "no_devices_hint": "Fang mit dem Gerät an, das du gerade benutzt.",
        "add_device": "Dieses Gerät verbinden",
        "detected": "Erkannt: {device}",
        "detected_help": "Nicht dein Gerät? Weiter unten stehen alle anderen.",
        "add_other": "Ein anderes Gerät",
        "connect_apple": "Dieses iPhone oder iPad verbinden",
        "connect_mac": "Diesen Mac verbinden",
        "connect_android": "Dieses Android-Handy verbinden",
        "connect_android_app": "Mit der geteduroam-App verbinden",
        "other_browser": "Firefox kann das WLAN-Profil auf Android nicht installieren, es speichert nur die Datei. Öffne diese Seite in Chrome (oder einem anderen Chromium-Browser wie Vanadium oder Samsung Internet), oder nimm die geteduroam-App.",
        "connect_desktop": "Diesen Computer verbinden",
        "device_name": "Name des Geräts",
        "added": "hinzugefügt am",
        "expires": "gültig bis",
        "expires_badge": "läuft bald ab",
        "expires_soon": "läuft bald ab: erneuern",
        "renew_action": "Jetzt erneuern",
        "last_seen": "zuletzt verbunden",
        "never": "noch nicht verbunden",
        "rename": "Umbenennen",
        "save": "Speichern",
        "cancel": "Abbrechen",
        "renew": "Erneuern",
        "revoke": "Entfernen",
        "revoke_title": "Dieses Gerät entfernen",
        "revoke_confirm": "Dieses Gerät entfernen? Es verliert sofort den WLAN-Zugang.",
        "revoke_note": "Danach kommt es nicht mehr ins WLAN. Willst du es später wieder nutzen, fügst du es einfach neu hinzu.",
        "revoked": "Entfernt. Das Gerät hat keinen WLAN-Zugang mehr.",
        "for_apple": "iPhone oder iPad",
        "for_mac": "Mac",
        "for_android": "Android",
        "for_android_app": "Android mit der geteduroam-App",
        "for_app": "geteduroam-App",
        "for_windows": "Windows",
        "for_linux": "Linux",
        "install": "Installieren",
        "load_profile": "Profil laden",
        "steps_apple": [
            "Tippe auf „Profil laden“ und dann auf „Erlauben“.",
            "Öffne die Einstellungen: ganz oben steht „Profil geladen“.",
            "Tippe darauf, dann auf „Installieren“, und gib den Code deines Geräts ein.",
            "Fertig. Ab jetzt verbindet sich das Gerät von selbst mit {ssid}.",
        ],
        "steps_mac": [
            "Klicke auf „Profil laden“.",
            "Öffne die Systemeinstellungen → Datenschutz & Sicherheit → Profile und installiere das Profil „{ssid}“.",
            "Fertig. Ab jetzt verbindet sich der Mac von selbst mit {ssid}.",
        ],
        "steps_android": [
            "Tippe auf „Installieren“.",
            "Android fragt, ob das WLAN-Profil gespeichert werden soll: bestätige.",
            "Fertig. Ab jetzt verbindet sich das Handy von selbst mit {ssid}.",
        ],
        "steps_android_app": [
            "Installiere die geteduroam-App (Google Play oder F-Droid), falls noch nicht geschehen.",
            "Tippe auf „Installieren“: Die Datei öffnet sich in der App.",
            "Bestätige in der App. Fertig: Das Handy verbindet sich von selbst mit {ssid}.",
        ],
        "steps_app": [
            "Lade die geteduroam-App herunter und öffne sie.",
            "Gib {host} als Server ein.",
            "Melde dich mit dem Haus-Konto an. Die App richtet das WLAN {ssid} selbst ein.",
        ],
        "install_apple": "Tippe auf Installieren, dann auf Erlauben. Öffne die Einstellungen, tippe auf „Profil geladen“ und auf Installieren. Fertig: das Gerät verbindet sich selbst mit {ssid}.",
        "install_mac": "Klicke auf Installieren. Öffne die Systemeinstellungen, Datenschutz & Sicherheit, Profile, und installiere das Profil. Fertig.",
        "install_android": "Tippe auf Installieren und bestätige. Fertig: das Handy verbindet sich selbst mit {ssid}.",
        "install_android_app": "Installiere die geteduroam-App (Google Play oder F-Droid), dann tippe hier auf Installieren: die Datei öffnet sich in der App.",
        "install_app": "Installiere die geteduroam-App, öffne sie und gib {host} als Server ein. Melde dich an, wenn sie fragt; die App richtet das WLAN selbst ein.",
        "get_app": "geteduroam-App holen",
        "link_once": "Dieser Link funktioniert einmal und zehn Minuten lang.",
        "back_devices": "Zurück zu deinen Geräten",
        "back_home": "Zur Startseite",
        "consent": "Die geteduroam-App auf diesem Gerät mit dem Haus-WLAN verbinden?",
        "consent_note": "Die App bekommt einen Schlüssel für dieses Gerät und richtet das WLAN {ssid} ein. Du kannst das Gerät jederzeit unter „Deine Geräte“ entfernen.",
        "consent_name_help": "So erscheint das Gerät in deiner Liste.",
        "allow": "Verbinden",
        "admin": "Alle Geräte",
        "admin_intro": "Alle Geräte im Haus. Entfernen trennt das Gerät sofort.",
        "owner": "Besitzer",
        "no_access": "Dein Konto hat keinen Zugang zum Haus-WLAN.",
        "error": "Etwas ist schiefgegangen. Bitte versuche es noch einmal.",
        "privacy": "Gespeichert: Name des Geräts, wann es hinzugefügt und zuletzt verbunden wurde. Aus der Netzüberwachung des Hauses angezeigt (90 Tage aufbewahrt): wo und wann deine Geräte verbunden waren, ihr Empfang und wie viele Daten sie übertragen haben. Nie: was du im Netz machst. Du siehst nur deine Geräte; die Haus-Admins sehen alle, um bei WLAN-Problemen zu helfen.",
        "house_nav": "Haus",
    },
    "uk": {
        "title": "Wi-Fi",
        "tagline": "Домашній Wi-Fi для ваших пристроїв",
        "login": "Увійти з домашнім акаунтом",
        "logout": "Вийти",
        "intro": "Підключіть свої пристрої до домашнього Wi-Fi. Кожен пристрій отримує власний ключ; його можна будь-коли видалити тут.",
        "landing_1": "Увійдіть один раз, додайте пристрій, готово: далі він підключається сам.",
        "landing_2": "Кожен пристрій отримує власний ключ. Немає пароля Wi-Fi, який хтось міг би передати далі.",
        "landing_3": "Загубили або продали? Видаліть пристрій тут, і він одразу поза мережею.",
        "date_format": "%d.%m.%Y",
        "your_devices": "Ваші пристрої",
        "devices_count": "Пристроїв: {n}",
        "no_devices": "Пристроїв ще немає.",
        "no_devices_hint": "Почніть із пристрою, яким ви зараз користуєтеся.",
        "add_device": "Підключити цей пристрій",
        "detected": "Виявлено: {device}",
        "detected_help": "Не ваш пристрій? Усі інші наведено нижче.",
        "add_other": "Інший пристрій",
        "connect_apple": "Підключити цей iPhone або iPad",
        "connect_mac": "Підключити цей Mac",
        "connect_android": "Підключити цей телефон Android",
        "connect_android_app": "Підключити через застосунок geteduroam",
        "other_browser": "Firefox не може встановити профіль Wi-Fi на Android, він лише зберігає файл. Відкрийте цю сторінку в Chrome (або іншому браузері на основі Chromium, як-от Vanadium чи Samsung Internet) або скористайтеся застосунком geteduroam.",
        "connect_desktop": "Підключити цей комп’ютер",
        "device_name": "Назва пристрою",
        "added": "додано",
        "expires": "дійсний до",
        "expires_badge": "скоро закінчується",
        "expires_soon": "скоро закінчується: оновити",
        "renew_action": "Оновити зараз",
        "last_seen": "востаннє підключено",
        "never": "ще не підключався",
        "rename": "Перейменувати",
        "save": "Зберегти",
        "cancel": "Скасувати",
        "renew": "Оновити",
        "revoke": "Видалити",
        "revoke_title": "Видалити цей пристрій",
        "revoke_confirm": "Видалити цей пристрій? Він одразу втратить доступ до Wi-Fi.",
        "revoke_note": "Після цього він більше не зможе підключитися до Wi-Fi. Щоб користуватися ним знову, просто додайте його заново.",
        "revoked": "Видалено. Пристрій більше не має доступу до Wi-Fi.",
        "for_apple": "iPhone або iPad",
        "for_mac": "Mac",
        "for_android": "Android",
        "for_android_app": "Android із застосунком geteduroam",
        "for_app": "застосунок geteduroam",
        "for_windows": "Windows",
        "for_linux": "Linux",
        "install": "Встановити",
        "load_profile": "Завантажити профіль",
        "steps_apple": [
            "Натисніть «Завантажити профіль», потім «Дозволити».",
            "Відкрийте Параметри: угорі написано «Профіль завантажено».",
            "Натисніть на нього, потім «Встановити», і введіть код свого пристрою.",
            "Готово. Відтепер пристрій сам підключається до {ssid}.",
        ],
        "steps_mac": [
            "Натисніть «Завантажити профіль».",
            "Відкрийте Системні параметри → Приватність і безпека → Профілі та встановіть профіль «{ssid}».",
            "Готово. Відтепер Mac сам підключається до {ssid}.",
        ],
        "steps_android": [
            "Натисніть «Встановити».",
            "Android запитає, чи зберегти профіль Wi-Fi: підтвердьте.",
            "Готово. Відтепер телефон сам підключається до {ssid}.",
        ],
        "steps_android_app": [
            "Встановіть застосунок geteduroam (Google Play або F-Droid), якщо ще не зробили цього.",
            "Натисніть «Встановити»: файл відкриється в застосунку.",
            "Підтвердьте в застосунку. Готово: телефон сам підключається до {ssid}.",
        ],
        "steps_app": [
            "Завантажте застосунок geteduroam і відкрийте його.",
            "Введіть {host} як сервер.",
            "Увійдіть із домашнім акаунтом. Застосунок сам налаштує Wi-Fi {ssid}.",
        ],
        "install_apple": "Натисніть «Встановити», потім «Дозволити». Відкрийте Параметри, натисніть «Профіль завантажено» і «Встановити». Готово: пристрій сам підключиться до {ssid}.",
        "install_mac": "Натисніть «Встановити». Відкрийте Системні параметри, Приватність і безпека, Профілі, і встановіть профіль. Готово.",
        "install_android": "Натисніть «Встановити» і підтвердіть. Готово: телефон сам підключиться до {ssid}.",
        "install_android_app": "Встановіть застосунок geteduroam (Google Play або F-Droid), потім натисніть тут «Встановити»: файл відкриється в застосунку.",
        "install_app": "Встановіть застосунок geteduroam, відкрийте його і введіть {host} як сервер. Увійдіть, коли він попросить; застосунок сам налаштує Wi-Fi.",
        "get_app": "Отримати застосунок geteduroam",
        "link_once": "Це посилання працює один раз і десять хвилин.",
        "back_devices": "Назад до ваших пристроїв",
        "back_home": "На головну",
        "consent": "Підключити застосунок geteduroam на цьому пристрої до домашнього Wi-Fi?",
        "consent_note": "Застосунок отримає ключ для цього пристрою і налаштує Wi-Fi {ssid}. Ви можете будь-коли видалити пристрій у розділі «Ваші пристрої».",
        "consent_name_help": "Так пристрій відображатиметься у вашому списку.",
        "allow": "Підключити",
        "admin": "Усі пристрої",
        "admin_intro": "Усі пристрої в будинку. Видалення одразу від’єднує пристрій.",
        "owner": "Власник",
        "no_access": "Ваш акаунт не має доступу до домашнього Wi-Fi.",
        "error": "Щось пішло не так. Спробуйте ще раз.",
        "privacy": "Зберігається: назва пристрою, коли його додано і востаннє підключено. З моніторингу мережі будинку (зберігається 90 днів) показано: де і коли ваші пристрої були підключені, їхній сигнал і скільки даних вони передали. Ніколи: що ви робите в мережі. Ви бачите лише свої пристрої; адміністратори будинку бачать усі, щоб допомагати з проблемами Wi‑Fi.",
        "house_nav": "Будинок",
    },
}

# The "My devices" dashboard (devices.html, device.html, admin.html and static/*.js): kept apart
# from the portal's texts above and merged into TEXT below. Diagnosis codes (diagnostics.py) have
# three texts each: diag_<code> (what it is), diag_<code>_why (in plain words), diag_<code>_do
# (what the resident can do). The browser gets the whole TEXT[lang] as JSON (no second copy).
DASHBOARD_TEXT = {
    "en": {
        "add_short": "Connect a device",
        "house_title": "The house network",
        "house_internet": "Internet",
        "house_dns": "Website names (DNS)",
        "house_router": "Router",
        "house_speed": "Internet line",
        "st_ok": "Working",
        "st_degraded": "Slow or patchy",
        "st_down": "Not working",
        "st_unknown": "Unknown",
        "house_ping": "{ms} response time",
        "house_loss": "{pct} lost",
        "house_speed_value": "↓ {down} · ↑ {up}",
        "house_speed_at": "last test {when}",
        "house_speed_none": "No speed test yet",
        "house_speed_note": "Speed of the house's internet line, measured at the router. Not the speed of a single device.",
        "house_wifi_age": "The Wi-Fi system's data is {age} old.",
        "live_updated": "Updated {when}",
        "live_auto": "updates by itself every 30 seconds",
        "live_updating": "Updating…",
        "live_offline": "You are offline. The page updates again when your connection is back.",
        "live_unreachable": "The portal cannot be reached right now. Trying again in 30 seconds.",
        "live_login": "Your login has ended.",
        "live_login_link": "Log in again",
        "live_stale": "This data may be out of date (from {when}).",
        "live_changed": "Your list of devices has changed.",
        "live_reload": "Reload the page",
        "telemetry_off": "Live Wi-Fi data is not switched on here. You see what the device registry knows: when each device last logged in.",
        "telemetry_unavailable": "Live Wi-Fi data cannot be loaded right now. You see what the device registry knows. Try again in a few minutes.",
        "announce_state": "{name}: {state}",
        "state_online": "Online",
        "state_offline": "Offline",
        "state_never_connected": "Not connected yet",
        "state_unknown": "Status unknown",
        "since_line": "connected since {time} ({duration})",
        "seen_line": "last seen {when}",
        "never_line": "Install the profile on the device, then choose the Wi-Fi {ssid}.",
        "unknown_line": "No live data at the moment.",
        "f_room": "Where",
        "f_wifi": "Wi-Fi",
        "f_signal": "Signal",
        "f_quality": "Wi-Fi quality",
        "f_link": "Radio link rate",
        "f_link_hint": "How fast the device and the access point talk over the air. This is not your internet speed.",
        "diag_mac_conflict": "Wi-Fi address claimed twice",
        "diag_mac_conflict_why": "Another registered device uses the same Wi-Fi address as this one. To protect everyone's privacy, its live data is hidden.",
        "diag_mac_conflict_do": "Tell the house admins. It can mean the device was passed on without being removed here, or that someone imitates its address.",
        "diag_mac_conflict_admin_why": "Devices of other people claim the same Wi-Fi address too ({n}), so the live data is hidden.",
        "diag_mac_conflict_admin_do": "Check whether one of them is old (then remove it) or whether the address is spoofed.",
        "ch_needs_js_all": "The charts and the list of connections need JavaScript.",
        "diag_more": "{n} more on the details page",
        "saved": "Saved",
        "save_failed": "Could not save. Please try again.",
        "tl_more": "Only the latest connections are listed.",
        "f_link_note": "over the air, not the internet speed",
        "per_hour": "{n} per hour",
        "times_24h": "{n} times in 24 hours",
        "live_needs_js": "Shown as of {when}. Reload the page for fresh data.",
        "chart_hint": "Touch or hover the chart for values; arrow keys move along it.",
        "f_now": "Data now",
        "f_24h": "Data in 24 hours",
        "f_since": "Connected since",
        "dir_down": "received",
        "dir_up": "sent",
        "band_fmt": "{band} GHz",
        "channel_fmt": "channel {channel}",
        "proto_be": "Wi-Fi 7",
        "proto_ax": "Wi-Fi 6",
        "proto_ax6": "Wi-Fi 6E",
        "proto_ac": "Wi-Fi 5",
        "proto_n": "Wi-Fi 4",
        "proto_old": "older Wi-Fi",
        "sig_excellent": "excellent",
        "sig_good": "good",
        "sig_fair": "okay",
        "sig_weak": "weak",
        "sig_very_weak": "very weak",
        "q_good": "good",
        "q_fair": "so-so",
        "q_poor": "poor",
        "quality_fmt": "{n} of 100",
        "details_link": "Details and history",
        "all_good": "No problems found.",
        "diag_do_label": "What you can do:",
        "sev_info": "Note",
        "sev_warn": "Warning",
        "sev_bad": "Problem",
        "diag_weak_signal": "Weak signal",
        "diag_weak_signal_why": "The device hears the access point only faintly. That makes the Wi-Fi slow and can break the connection.",
        "diag_weak_signal_do": "Move closer to an access point, away from thick walls and metal. If it is always weak in this spot, tell the house admins: an access point may be missing there.",
        "diag_low_snr": "Lots of interference",
        "diag_low_snr_why": "Background noise drowns out the signal, so data has to be sent again and again.",
        "diag_low_snr_do": "Keep the device away from microwaves, baby monitors and other radio devices. If the device can use 5 GHz, that band is usually calmer.",
        "diag_high_retries": "Data often has to be sent twice",
        "diag_high_retries_why": "Many pieces of data did not arrive the first time. That slows things down even when the signal looks fine.",
        "diag_high_retries_do": "Move a little closer to an access point. Switching the device's Wi-Fi off and on often helps. If it stays like this, tell the house admins.",
        "diag_busy_channel": "The Wi-Fi channel is crowded",
        "diag_busy_channel_why": "The radio channel this device uses is busy much of the time, shared with many other devices and the neighbours' networks.",
        "diag_busy_channel_do": "You do not need to change anything on the device. If it keeps happening, the house admins can move the access point to a quieter channel.",
        "diag_unstable_roaming": "Keeps jumping between access points",
        "diag_unstable_roaming_why": "The device switches between access points again and again. Every switch can cause a short dropout.",
        "diag_unstable_roaming_do": "This often happens halfway between two access points. Stay closer to one of them, or switch the device's Wi-Fi off and on.",
        "diag_frequent_disconnects": "Drops out often",
        "diag_frequent_disconnects_why": "The device lost the Wi-Fi several times in the last 24 hours.",
        "diag_frequent_disconnects_do": "Check that no power saving mode switches the Wi-Fi off. Restart the device. If it keeps dropping out, tell the house admins.",
        "diag_stuck_on_2ghz": "Stuck on the slower 2.4 GHz band",
        "diag_stuck_on_2ghz_why": "The device is on 2.4 GHz now, although it used the faster 5 or 6 GHz band before.",
        "diag_stuck_on_2ghz_do": "Switch the Wi-Fi off and on on the device: it usually picks the faster band again. Being closer to the access point helps too.",
        "diag_slow_link": "Slow radio link despite a good signal",
        "diag_slow_link_why": "The signal is good, but the device talks to the access point slowly. Often a power saving setting or old software is the cause.",
        "diag_slow_link_do": "Switch the device's Wi-Fi off and on, or restart it. Install system updates if there are any.",
        "diag_stale_data": "Data not up to date",
        "diag_stale_data_why": "The Wi-Fi system has not sent fresh data for a while. What you see may be old.",
        "diag_stale_data_do": "Nothing to do for you. If it stays like this, tell the house admins.",
        "diag_offline": "Not connected",
        "diag_offline_why": "The device is not connected to the house Wi-Fi right now.",
        "diag_offline_do": "If it should be online: check that its Wi-Fi is on and that it is in the house. Choose the house Wi-Fi in its Wi-Fi list.",
        "diag_never_connected": "Never connected",
        "diag_never_connected_why": "The device has its key but has never logged in to the house Wi-Fi.",
        "diag_never_connected_do": "Finish the setup on the device (install the profile), then choose the house Wi-Fi. If that does not work, remove the device here and add it again.",
        "room_scharni": "Scharni",
        "room_colbe": "Colbe",
        "room_floor_0": "ground floor",
        "room_floor_1": "1st floor",
        "room_floor_2": "2nd floor",
        "room_floor_3": "3rd floor",
        "room_floor_4": "4th floor",
        "room_floor_n": "floor {n}",
        "room_spot_corner": "corner",
        "room_spot_middle": "middle",
        "room_spot_far": "far end",
        "u_bit": "bit/s",
        "u_kbit": "kbit/s",
        "u_mbit": "Mbit/s",
        "u_gbit": "Gbit/s",
        "u_b": "B",
        "u_kb": "kB",
        "u_mb": "MB",
        "u_gb": "GB",
        "u_tb": "TB",
        "dur_d": "{n} d",
        "dur_h": "{n} h",
        "dur_min": "{n} min",
        "dur_s": "{n} s",
        "ago_now": "just now",
        "ago_fmt": "{when} ago",
        "yesterday_at": "yesterday {time}",
        "time_format": "%H:%M",
        "day_format": "%e %b",
        "months": ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
        "dbm_fmt": "{n} dBm",
        "ms_fmt": "{n} ms",
        "db_fmt": "{n} dB",
        "dt_title": "About this device",
        "dt_platform": "Kind",
        "dt_enrolled": "Added",
        "dt_expires": "Key valid until",
        "dt_mac": "Hardware address (MAC)",
        "dt_ip": "IP address",
        "dt_ssid": "Network",
        "dt_ap": "Access point",
        "dt_noise": "Background noise",
        "dt_snr": "Signal above noise",
        "dt_retries": "Sent again",
        "dt_channel_util": "Channel busy",
        "dt_roams": "Access point changes (last hour)",
        "dt_owner": "Owner",
        "history_title": "History",
        "range_label": "Time span",
        "range_24h": "24 hours",
        "range_7d": "7 days",
        "range_30d": "30 days",
        "ch_signal": "Signal strength",
        "ch_signal_sub": "In dBm: closer to 0 is better.",
        "band_good": "good",
        "band_weak": "weak",
        "ch_quality": "Wi-Fi quality",
        "ch_quality_sub": "0 to 100, from signal, interference, repeats and how busy the channel is.",
        "ch_traffic": "Data",
        "ch_traffic_sub": "Received and sent by the device, averaged.",
        "ch_link": "Radio link rate",
        "ch_link_sub": "Speed over the air to the access point. Not the internet speed.",
        "ch_online": "Availability",
        "ch_online_sub": "When the device was connected.",
        "online_pct": "connected {pct} of the time",
        "ch_summary": "lowest {min}, average {avg}, highest {max}",
        "ch_nodata": "No data for this time span.",
        "ch_loading": "Loading the history…",
        "ch_error": "The history could not be loaded.",
        "ch_needs_js": "The charts need JavaScript. The list of connections below works without it.",
        "retry": "Try again",
        "tl_title": "Connections",
        "tl_connected": "Connected: {where}",
        "tl_disconnected": "Disconnected",
        "tl_roamed": "Moved from {old} to {new}",
        "tl_band": "Switched from {old} to {new}",
        "tl_for": "for {duration}",
        "tl_ongoing": "still connected",
        "tl_offline": "not connected",
        "tl_none": "No connections in this time span.",
        "tl_legend": "Access points",
        "tl_other_ap": "other",
        "adm_search": "Search",
        "adm_search_ph": "Name, owner or MAC",
        "adm_state": "State",
        "adm_any": "All",
        "adm_problem": "Problems",
        "adm_with_problems": "With problems",
        "adm_no_problems": "Without problems",
        "adm_sort": "Sort by",
        "sort_name": "Name",
        "sort_owner": "Owner",
        "sort_state": "State",
        "sort_signal": "Signal (weakest first)",
        "sort_health": "Wi-Fi quality (worst first)",
        "sort_seen": "Last seen (newest first)",
        "adm_apply": "Show",
        "adm_reset": "Reset",
        "adm_shown": "{shown} of {total} shown",
        "adm_none": "No device matches.",
        "adm_problems_n": "problems: {n}",
    },
    "de": {
        "add_short": "Gerät verbinden",
        "house_title": "Das Hausnetz",
        "house_internet": "Internet",
        "house_dns": "Webseiten-Namen (DNS)",
        "house_router": "Router",
        "house_speed": "Internetleitung",
        "st_ok": "Läuft",
        "st_degraded": "Langsam oder wackelig",
        "st_down": "Gestört",
        "st_unknown": "Unbekannt",
        "house_ping": "{ms} Antwortzeit",
        "house_loss": "{pct} verloren",
        "house_speed_value": "↓ {down} · ↑ {up}",
        "house_speed_at": "letzte Messung {when}",
        "house_speed_none": "Noch keine Messung",
        "house_speed_note": "Geschwindigkeit der Internetleitung des Hauses, gemessen am Router. Nicht die Geschwindigkeit eines einzelnen Geräts.",
        "house_wifi_age": "Die Daten des WLAN-Systems sind {age} alt.",
        "live_updated": "Aktualisiert {when}",
        "live_auto": "aktualisiert sich alle 30 Sekunden",
        "live_updating": "Wird aktualisiert…",
        "live_offline": "Du bist offline. Die Seite aktualisiert sich wieder, sobald die Verbindung zurück ist.",
        "live_unreachable": "Das Portal ist gerade nicht erreichbar. Neuer Versuch in 30 Sekunden.",
        "live_login": "Deine Anmeldung ist abgelaufen.",
        "live_login_link": "Neu anmelden",
        "live_stale": "Diese Daten sind vielleicht nicht aktuell (Stand {when}).",
        "live_changed": "Deine Geräteliste hat sich geändert.",
        "live_reload": "Seite neu laden",
        "telemetry_off": "Live-Daten aus dem WLAN sind hier nicht eingeschaltet. Du siehst, was das Geräteverzeichnis weiß: wann sich jedes Gerät zuletzt angemeldet hat.",
        "telemetry_unavailable": "Live-Daten aus dem WLAN können gerade nicht geladen werden. Du siehst, was das Geräteverzeichnis weiß. Versuch es in ein paar Minuten noch einmal.",
        "announce_state": "{name}: {state}",
        "state_online": "Online",
        "state_offline": "Offline",
        "state_never_connected": "Noch nie verbunden",
        "state_unknown": "Status unbekannt",
        "since_line": "verbunden seit {time} ({duration})",
        "seen_line": "zuletzt gesehen {when}",
        "never_line": "Installiere das Profil auf dem Gerät und wähle dann das WLAN {ssid}.",
        "unknown_line": "Gerade keine Live-Daten.",
        "f_room": "Wo",
        "f_wifi": "WLAN",
        "f_signal": "Signal",
        "f_quality": "WLAN-Qualität",
        "f_link": "Funk-Verbindungsrate",
        "f_link_hint": "Wie schnell Gerät und Access Point über Funk miteinander reden. Das ist nicht deine Internetgeschwindigkeit.",
        "diag_mac_conflict": "WLAN-Adresse doppelt vergeben",
        "diag_mac_conflict_why": "Ein anderes registriertes Gerät benutzt dieselbe WLAN-Adresse wie dieses. Zum Schutz der Privatsphäre aller werden seine Live-Daten ausgeblendet.",
        "diag_mac_conflict_do": "Sag den Haus-Admins Bescheid. Das kann heißen, dass das Gerät weitergegeben wurde, ohne es hier zu entfernen, oder dass jemand seine Adresse nachahmt.",
        "diag_mac_conflict_admin_why": "Auch Geräte anderer Personen beanspruchen dieselbe WLAN-Adresse ({n}), deshalb sind die Live-Daten ausgeblendet.",
        "diag_mac_conflict_admin_do": "Prüfe, ob eines davon alt ist (dann entfernen) oder ob die Adresse gefälscht ist.",
        "ch_needs_js_all": "Die Diagramme und die Liste der Verbindungen brauchen JavaScript.",
        "diag_more": "{n} weitere auf der Detailseite",
        "saved": "Gespeichert",
        "save_failed": "Konnte nicht gespeichert werden. Bitte versuch es noch einmal.",
        "tl_more": "Es sind nur die letzten Verbindungen aufgeführt.",
        "f_link_note": "über Funk, nicht die Internetgeschwindigkeit",
        "per_hour": "{n} pro Stunde",
        "times_24h": "{n}-mal in 24 Stunden",
        "live_needs_js": "Stand {when}. Lade die Seite neu für frische Daten.",
        "chart_hint": "Tippe auf das Diagramm oder fahre darüber für die Werte; die Pfeiltasten bewegen sich darin.",
        "f_now": "Daten gerade",
        "f_24h": "Daten in 24 Stunden",
        "f_since": "Verbunden seit",
        "dir_down": "empfangen",
        "dir_up": "gesendet",
        "band_fmt": "{band} GHz",
        "channel_fmt": "Kanal {channel}",
        "proto_be": "Wi-Fi 7",
        "proto_ax": "Wi-Fi 6",
        "proto_ax6": "Wi-Fi 6E",
        "proto_ac": "Wi-Fi 5",
        "proto_n": "Wi-Fi 4",
        "proto_old": "älteres WLAN",
        "sig_excellent": "sehr gut",
        "sig_good": "gut",
        "sig_fair": "mittel",
        "sig_weak": "schwach",
        "sig_very_weak": "sehr schwach",
        "q_good": "gut",
        "q_fair": "mittel",
        "q_poor": "schlecht",
        "quality_fmt": "{n} von 100",
        "details_link": "Details und Verlauf",
        "all_good": "Keine Probleme gefunden.",
        "diag_do_label": "Was du tun kannst:",
        "sev_info": "Hinweis",
        "sev_warn": "Warnung",
        "sev_bad": "Problem",
        "diag_weak_signal": "Schwaches Signal",
        "diag_weak_signal_why": "Das Gerät hört den Access Point nur leise. Dadurch wird das WLAN langsam und die Verbindung kann abreißen.",
        "diag_weak_signal_do": "Geh näher an einen Access Point, weg von dicken Wänden und Metall. Ist es an dieser Stelle immer schwach, sag den Haus-Admins Bescheid: Dort fehlt vielleicht ein Access Point.",
        "diag_low_snr": "Viele Störungen",
        "diag_low_snr_why": "Hintergrundrauschen übertönt das Signal, deshalb müssen Daten immer wieder neu gesendet werden.",
        "diag_low_snr_do": "Halte das Gerät von Mikrowellen, Babyfonen und anderen Funkgeräten fern. Kann das Gerät 5 GHz, ist es dort meist ruhiger.",
        "diag_high_retries": "Daten müssen oft doppelt gesendet werden",
        "diag_high_retries_why": "Viele Datenpakete kamen beim ersten Mal nicht an. Das bremst, auch wenn das Signal gut aussieht.",
        "diag_high_retries_do": "Geh etwas näher an einen Access Point. WLAN am Gerät aus- und wieder einschalten hilft oft. Bleibt es so, sag den Haus-Admins Bescheid.",
        "diag_busy_channel": "Der WLAN-Kanal ist voll",
        "diag_busy_channel_why": "Der Funkkanal dieses Geräts ist oft belegt, geteilt mit vielen anderen Geräten und den Netzen der Nachbarn.",
        "diag_busy_channel_do": "Am Gerät musst du nichts ändern. Passiert es öfter, können die Haus-Admins den Access Point auf einen ruhigeren Kanal legen.",
        "diag_unstable_roaming": "Springt zwischen Access Points hin und her",
        "diag_unstable_roaming_why": "Das Gerät wechselt immer wieder den Access Point. Jeder Wechsel kann kurz die Verbindung unterbrechen.",
        "diag_unstable_roaming_do": "Das passiert oft genau zwischen zwei Access Points. Bleib näher an einem davon, oder schalte das WLAN am Gerät aus und wieder ein.",
        "diag_frequent_disconnects": "Fliegt oft raus",
        "diag_frequent_disconnects_why": "Das Gerät hat in den letzten 24 Stunden mehrmals das WLAN verloren.",
        "diag_frequent_disconnects_do": "Prüfe, ob ein Stromsparmodus das WLAN abschaltet. Starte das Gerät neu. Fliegt es weiter raus, sag den Haus-Admins Bescheid.",
        "diag_stuck_on_2ghz": "Hängt im langsameren 2,4-GHz-Band",
        "diag_stuck_on_2ghz_why": "Das Gerät ist gerade im 2,4-GHz-Band, obwohl es vorher das schnellere 5- oder 6-GHz-Band benutzt hat.",
        "diag_stuck_on_2ghz_do": "Schalte das WLAN am Gerät aus und wieder ein: Meist nimmt es dann wieder das schnellere Band. Näher am Access Point hilft auch.",
        "diag_slow_link": "Langsame Funkverbindung trotz gutem Signal",
        "diag_slow_link_why": "Das Signal ist gut, aber das Gerät redet nur langsam mit dem Access Point. Oft liegt das an einer Stromspar-Einstellung oder alter Software.",
        "diag_slow_link_do": "Schalte das WLAN am Gerät aus und wieder ein oder starte es neu. Installiere Systemupdates, falls es welche gibt.",
        "diag_stale_data": "Daten nicht aktuell",
        "diag_stale_data_why": "Das WLAN-System hat eine Weile keine frischen Daten geschickt. Was du siehst, kann alt sein.",
        "diag_stale_data_do": "Du musst nichts tun. Bleibt es so, sag den Haus-Admins Bescheid.",
        "diag_offline": "Nicht verbunden",
        "diag_offline_why": "Das Gerät ist gerade nicht mit dem Haus-WLAN verbunden.",
        "diag_offline_do": "Soll es online sein: Prüfe, ob sein WLAN an ist und ob es im Haus ist. Wähle in seiner WLAN-Liste das Haus-WLAN.",
        "diag_never_connected": "Noch nie verbunden",
        "diag_never_connected_why": "Das Gerät hat seinen Schlüssel, hat sich aber noch nie im Haus-WLAN angemeldet.",
        "diag_never_connected_do": "Schließ die Einrichtung auf dem Gerät ab (Profil installieren) und wähle dann das Haus-WLAN. Klappt das nicht, entferne das Gerät hier und füge es neu hinzu.",
        "room_scharni": "Scharni",
        "room_colbe": "Colbe",
        "room_floor_0": "Erdgeschoss",
        "room_floor_1": "1. Stock",
        "room_floor_2": "2. Stock",
        "room_floor_3": "3. Stock",
        "room_floor_4": "4. Stock",
        "room_floor_n": "Stockwerk {n}",
        "room_spot_corner": "Ecke",
        "room_spot_middle": "Mitte",
        "room_spot_far": "hinten",
        "u_bit": "bit/s",
        "u_kbit": "kbit/s",
        "u_mbit": "Mbit/s",
        "u_gbit": "Gbit/s",
        "u_b": "B",
        "u_kb": "kB",
        "u_mb": "MB",
        "u_gb": "GB",
        "u_tb": "TB",
        "dur_d": "{n} Tg.",
        "dur_h": "{n} Std.",
        "dur_min": "{n} Min.",
        "dur_s": "{n} Sek.",
        "ago_now": "gerade eben",
        "ago_fmt": "vor {when}",
        "yesterday_at": "gestern {time}",
        "time_format": "%H:%M",
        "day_format": "%e. %b",
        "months": ["Jan.", "Feb.", "März", "Apr.", "Mai", "Juni", "Juli", "Aug.", "Sep.", "Okt.", "Nov.", "Dez."],
        "dbm_fmt": "{n} dBm",
        "ms_fmt": "{n} ms",
        "db_fmt": "{n} dB",
        "dt_title": "Über dieses Gerät",
        "dt_platform": "Art",
        "dt_enrolled": "Hinzugefügt",
        "dt_expires": "Schlüssel gültig bis",
        "dt_mac": "Hardware-Adresse (MAC)",
        "dt_ip": "IP-Adresse",
        "dt_ssid": "Netz",
        "dt_ap": "Access Point",
        "dt_noise": "Hintergrundrauschen",
        "dt_snr": "Signal über dem Rauschen",
        "dt_retries": "Neu gesendet",
        "dt_channel_util": "Kanal belegt",
        "dt_roams": "Access-Point-Wechsel (letzte Stunde)",
        "dt_owner": "Besitzer",
        "history_title": "Verlauf",
        "range_label": "Zeitraum",
        "range_24h": "24 Stunden",
        "range_7d": "7 Tage",
        "range_30d": "30 Tage",
        "ch_signal": "Signalstärke",
        "ch_signal_sub": "In dBm: näher an 0 ist besser.",
        "band_good": "gut",
        "band_weak": "schwach",
        "ch_quality": "WLAN-Qualität",
        "ch_quality_sub": "0 bis 100, aus Signal, Störungen, Wiederholungen und wie voll der Kanal ist.",
        "ch_traffic": "Daten",
        "ch_traffic_sub": "Vom Gerät empfangen und gesendet, gemittelt.",
        "ch_link": "Funk-Verbindungsrate",
        "ch_link_sub": "Geschwindigkeit über Funk zum Access Point. Nicht die Internetgeschwindigkeit.",
        "ch_online": "Erreichbarkeit",
        "ch_online_sub": "Wann das Gerät verbunden war.",
        "online_pct": "{pct} der Zeit verbunden",
        "ch_summary": "niedrigster Wert {min}, Durchschnitt {avg}, höchster Wert {max}",
        "ch_nodata": "Keine Daten für diesen Zeitraum.",
        "ch_loading": "Verlauf wird geladen…",
        "ch_error": "Der Verlauf konnte nicht geladen werden.",
        "ch_needs_js": "Die Diagramme brauchen JavaScript. Die Liste der Verbindungen unten geht auch ohne.",
        "retry": "Noch einmal versuchen",
        "tl_title": "Verbindungen",
        "tl_connected": "Verbunden: {where}",
        "tl_disconnected": "Getrennt",
        "tl_roamed": "Gewechselt von {old} zu {new}",
        "tl_band": "Band gewechselt von {old} zu {new}",
        "tl_for": "für {duration}",
        "tl_ongoing": "noch verbunden",
        "tl_offline": "nicht verbunden",
        "tl_none": "Keine Verbindungen in diesem Zeitraum.",
        "tl_legend": "Access Points",
        "tl_other_ap": "andere",
        "adm_search": "Suche",
        "adm_search_ph": "Name, Besitzer oder MAC",
        "adm_state": "Status",
        "adm_any": "Alle",
        "adm_problem": "Probleme",
        "adm_with_problems": "Mit Problemen",
        "adm_no_problems": "Ohne Probleme",
        "adm_sort": "Sortieren nach",
        "sort_name": "Name",
        "sort_owner": "Besitzer",
        "sort_state": "Status",
        "sort_signal": "Signal (schwächstes zuerst)",
        "sort_health": "WLAN-Qualität (schlechteste zuerst)",
        "sort_seen": "Zuletzt gesehen (neueste zuerst)",
        "adm_apply": "Anzeigen",
        "adm_reset": "Zurücksetzen",
        "adm_shown": "{shown} von {total} angezeigt",
        "adm_none": "Kein Gerät passt.",
        "adm_problems_n": "Probleme: {n}",
    },
    "uk": {
        "add_short": "Підключити пристрій",
        "house_title": "Домашня мережа",
        "house_internet": "Інтернет",
        "house_dns": "Назви сайтів (DNS)",
        "house_router": "Роутер",
        "house_speed": "Інтернет-лінія",
        "st_ok": "Працює",
        "st_degraded": "Повільно або з перебоями",
        "st_down": "Не працює",
        "st_unknown": "Невідомо",
        "house_ping": "відгук {ms}",
        "house_loss": "втрачено {pct}",
        "house_speed_value": "↓ {down} · ↑ {up}",
        "house_speed_at": "останній вимір {when}",
        "house_speed_none": "Вимірів ще немає",
        "house_speed_note": "Швидкість інтернет-лінії будинку, виміряна на роутері. Це не швидкість окремого пристрою.",
        "house_wifi_age": "Дані системи Wi-Fi застарілі на {age}.",
        "live_updated": "Оновлено {when}",
        "live_auto": "оновлюється сама кожні 30 секунд",
        "live_updating": "Оновлення…",
        "live_offline": "Ви офлайн. Сторінка знову оновиться, щойно з’явиться з’єднання.",
        "live_unreachable": "Портал зараз недоступний. Нова спроба за 30 секунд.",
        "live_login": "Ваш вхід завершився.",
        "live_login_link": "Увійти знову",
        "live_stale": "Ці дані можуть бути застарілими (станом на {when}).",
        "live_changed": "Ваш список пристроїв змінився.",
        "live_reload": "Оновити сторінку",
        "telemetry_off": "Живі дані з Wi-Fi тут не ввімкнено. Ви бачите те, що знає реєстр пристроїв: коли кожен пристрій востаннє входив у мережу.",
        "telemetry_unavailable": "Живі дані з Wi-Fi зараз не вдається завантажити. Ви бачите те, що знає реєстр пристроїв. Спробуйте за кілька хвилин.",
        "announce_state": "{name}: {state}",
        "state_online": "У мережі",
        "state_offline": "Не в мережі",
        "state_never_connected": "Ще не підключався",
        "state_unknown": "Стан невідомий",
        "since_line": "підключено з {time} ({duration})",
        "seen_line": "востаннє в мережі {when}",
        "never_line": "Встановіть профіль на пристрій, потім виберіть Wi-Fi {ssid}.",
        "unknown_line": "Зараз немає живих даних.",
        "f_room": "Де",
        "f_wifi": "Wi-Fi",
        "f_signal": "Сигнал",
        "f_quality": "Якість Wi-Fi",
        "f_link": "Швидкість радіозв’язку",
        "f_link_hint": "Як швидко пристрій і точка доступу обмінюються даними по радіо. Це не швидкість вашого інтернету.",
        "diag_mac_conflict": "Адресу Wi-Fi заявлено двічі",
        "diag_mac_conflict_why": "Інший зареєстрований пристрій використовує ту саму адресу Wi-Fi, що й цей. Щоб захистити приватність усіх, його живі дані приховано.",
        "diag_mac_conflict_do": "Скажіть адміністраторам будинку. Це може означати, що пристрій передали іншій людині, не видаливши його тут, або що хтось підробляє його адресу.",
        "diag_mac_conflict_admin_why": "Ту саму адресу Wi-Fi заявляють і пристрої інших людей ({n}), тому живі дані приховано.",
        "diag_mac_conflict_admin_do": "Перевірте, чи один із них не застарів (тоді видаліть його), чи адресу не підроблено.",
        "ch_needs_js_all": "Для графіків і списку з’єднань потрібен JavaScript.",
        "diag_more": "Ще {n} на сторінці подробиць",
        "saved": "Збережено",
        "save_failed": "Не вдалося зберегти. Спробуйте ще раз.",
        "tl_more": "Показано лише останні з’єднання.",
        "f_link_note": "по радіо, не швидкість інтернету",
        "per_hour": "{n} на годину",
        "times_24h": "відключень за 24 години: {n}",
        "live_needs_js": "Станом на {when}. Оновіть сторінку, щоб побачити свіжі дані.",
        "chart_hint": "Торкніться графіка або наведіть на нього, щоб побачити значення; стрілки переміщують позначку.",
        "f_now": "Дані зараз",
        "f_24h": "Дані за 24 години",
        "f_since": "Підключено з",
        "dir_down": "отримано",
        "dir_up": "надіслано",
        "band_fmt": "{band} ГГц",
        "channel_fmt": "канал {channel}",
        "proto_be": "Wi-Fi 7",
        "proto_ax": "Wi-Fi 6",
        "proto_ax6": "Wi-Fi 6E",
        "proto_ac": "Wi-Fi 5",
        "proto_n": "Wi-Fi 4",
        "proto_old": "старіший Wi-Fi",
        "sig_excellent": "відмінний",
        "sig_good": "добрий",
        "sig_fair": "середній",
        "sig_weak": "слабкий",
        "sig_very_weak": "дуже слабкий",
        "q_good": "добра",
        "q_fair": "середня",
        "q_poor": "погана",
        "quality_fmt": "{n} зі 100",
        "details_link": "Подробиці та історія",
        "all_good": "Проблем не знайдено.",
        "diag_do_label": "Що можна зробити:",
        "sev_info": "Примітка",
        "sev_warn": "Попередження",
        "sev_bad": "Проблема",
        "diag_weak_signal": "Слабкий сигнал",
        "diag_weak_signal_why": "Пристрій ледве чує точку доступу. Через це Wi-Fi повільний, а з’єднання може обриватися.",
        "diag_weak_signal_do": "Підійдіть ближче до точки доступу, подалі від товстих стін і металу. Якщо в цьому місці сигнал завжди слабкий, скажіть адміністраторам будинку: там, можливо, бракує точки доступу.",
        "diag_low_snr": "Багато перешкод",
        "diag_low_snr_why": "Фоновий шум заглушує сигнал, тому дані доводиться надсилати знову і знову.",
        "diag_low_snr_do": "Тримайте пристрій подалі від мікрохвильовок, радіонянь та інших радіопристроїв. Якщо пристрій підтримує 5 ГГц, там зазвичай спокійніше.",
        "diag_high_retries": "Дані часто надсилаються двічі",
        "diag_high_retries_why": "Багато пакетів даних не дійшли з першого разу. Це гальмує, навіть коли сигнал здається добрим.",
        "diag_high_retries_do": "Підійдіть трохи ближче до точки доступу. Часто допомагає вимкнути й знову ввімкнути Wi-Fi на пристрої. Якщо так і залишиться, скажіть адміністраторам будинку.",
        "diag_busy_channel": "Канал Wi-Fi переповнений",
        "diag_busy_channel_why": "Радіоканал цього пристрою часто зайнятий: його ділять багато інших пристроїв і мережі сусідів.",
        "diag_busy_channel_do": "На пристрої нічого змінювати не треба. Якщо це повторюється, адміністратори будинку можуть перевести точку доступу на спокійніший канал.",
        "diag_unstable_roaming": "Постійно перемикається між точками доступу",
        "diag_unstable_roaming_why": "Пристрій раз у раз змінює точку доступу. Кожне перемикання може ненадовго перервати з’єднання.",
        "diag_unstable_roaming_do": "Так часто буває посередині між двома точками доступу. Залишайтеся ближче до однієї з них або вимкніть і ввімкніть Wi-Fi на пристрої.",
        "diag_frequent_disconnects": "Часто відключається",
        "diag_frequent_disconnects_why": "За останні 24 години пристрій кілька разів втрачав Wi-Fi.",
        "diag_frequent_disconnects_do": "Перевірте, чи не вимикає Wi-Fi режим енергозбереження. Перезапустіть пристрій. Якщо він і далі відключається, скажіть адміністраторам будинку.",
        "diag_stuck_on_2ghz": "Застряг у повільнішому діапазоні 2,4 ГГц",
        "diag_stuck_on_2ghz_why": "Пристрій зараз на 2,4 ГГц, хоча раніше користувався швидшим діапазоном 5 або 6 ГГц.",
        "diag_stuck_on_2ghz_do": "Вимкніть і знову ввімкніть Wi-Fi на пристрої: зазвичай він знову вибирає швидший діапазон. Допомагає й бути ближче до точки доступу.",
        "diag_slow_link": "Повільний радіозв’язок попри добрий сигнал",
        "diag_slow_link_why": "Сигнал добрий, але пристрій обмінюється даними з точкою доступу повільно. Часто причина в енергозбереженні або старому програмному забезпеченні.",
        "diag_slow_link_do": "Вимкніть і ввімкніть Wi-Fi на пристрої або перезапустіть його. Встановіть оновлення системи, якщо вони є.",
        "diag_stale_data": "Дані не актуальні",
        "diag_stale_data_why": "Система Wi-Fi деякий час не надсилала свіжих даних. Те, що ви бачите, може бути застарілим.",
        "diag_stale_data_do": "Вам нічого не треба робити. Якщо так і залишиться, скажіть адміністраторам будинку.",
        "diag_offline": "Не підключено",
        "diag_offline_why": "Пристрій зараз не підключений до домашнього Wi-Fi.",
        "diag_offline_do": "Якщо він має бути в мережі: перевірте, чи ввімкнено на ньому Wi-Fi і чи він у будинку. Виберіть домашній Wi-Fi у його списку мереж.",
        "diag_never_connected": "Жодного разу не підключався",
        "diag_never_connected_why": "Пристрій має свій ключ, але ще жодного разу не входив у домашній Wi-Fi.",
        "diag_never_connected_do": "Завершіть налаштування на пристрої (встановіть профіль), потім виберіть домашній Wi-Fi. Якщо не вийде, видаліть пристрій тут і додайте його заново.",
        "room_scharni": "Scharni",
        "room_colbe": "Colbe",
        "room_floor_0": "перший поверх",
        "room_floor_1": "другий поверх",
        "room_floor_2": "третій поверх",
        "room_floor_3": "четвертий поверх",
        "room_floor_4": "п’ятий поверх",
        "room_floor_n": "поверх {n}",
        "room_spot_corner": "кут",
        "room_spot_middle": "середина",
        "room_spot_far": "дальній край",
        "u_bit": "біт/с",
        "u_kbit": "кбіт/с",
        "u_mbit": "Мбіт/с",
        "u_gbit": "Гбіт/с",
        "u_b": "Б",
        "u_kb": "кБ",
        "u_mb": "МБ",
        "u_gb": "ГБ",
        "u_tb": "ТБ",
        "dur_d": "{n} д",
        "dur_h": "{n} год",
        "dur_min": "{n} хв",
        "dur_s": "{n} с",
        "ago_now": "щойно",
        "ago_fmt": "{when} тому",
        "yesterday_at": "учора {time}",
        "time_format": "%H:%M",
        "day_format": "%e %b",
        "months": ["січ.", "лют.", "бер.", "квіт.", "трав.", "черв.", "лип.", "серп.", "вер.", "жовт.", "лист.", "груд."],
        "dbm_fmt": "{n} дБм",
        "ms_fmt": "{n} мс",
        "db_fmt": "{n} дБ",
        "dt_title": "Про цей пристрій",
        "dt_platform": "Тип",
        "dt_enrolled": "Додано",
        "dt_expires": "Ключ дійсний до",
        "dt_mac": "Апаратна адреса (MAC)",
        "dt_ip": "IP-адреса",
        "dt_ssid": "Мережа",
        "dt_ap": "Точка доступу",
        "dt_noise": "Фоновий шум",
        "dt_snr": "Сигнал понад шум",
        "dt_retries": "Надіслано повторно",
        "dt_channel_util": "Канал зайнятий",
        "dt_roams": "Зміни точки доступу (за годину)",
        "dt_owner": "Власник",
        "history_title": "Історія",
        "range_label": "Період",
        "range_24h": "24 години",
        "range_7d": "7 днів",
        "range_30d": "30 днів",
        "ch_signal": "Сила сигналу",
        "ch_signal_sub": "У дБм: чим ближче до 0, тим краще.",
        "band_good": "добрий",
        "band_weak": "слабкий",
        "ch_quality": "Якість Wi-Fi",
        "ch_quality_sub": "Від 0 до 100: із сигналу, перешкод, повторів і завантаженості каналу.",
        "ch_traffic": "Дані",
        "ch_traffic_sub": "Отримано й надіслано пристроєм, усереднено.",
        "ch_link": "Швидкість радіозв’язку",
        "ch_link_sub": "Швидкість по радіо до точки доступу. Не швидкість інтернету.",
        "ch_online": "Доступність",
        "ch_online_sub": "Коли пристрій був підключений.",
        "online_pct": "підключено {pct} часу",
        "ch_summary": "найменше {min}, у середньому {avg}, найбільше {max}",
        "ch_nodata": "Немає даних за цей період.",
        "ch_loading": "Завантаження історії…",
        "ch_error": "Не вдалося завантажити історію.",
        "ch_needs_js": "Для графіків потрібен JavaScript. Список з’єднань нижче працює і без нього.",
        "retry": "Спробувати ще раз",
        "tl_title": "З’єднання",
        "tl_connected": "Підключено: {where}",
        "tl_disconnected": "Відключено",
        "tl_roamed": "Перейшов з {old} до {new}",
        "tl_band": "Змінив діапазон з {old} на {new}",
        "tl_for": "протягом {duration}",
        "tl_ongoing": "досі підключено",
        "tl_offline": "не підключено",
        "tl_none": "Жодних з’єднань за цей період.",
        "tl_legend": "Точки доступу",
        "tl_other_ap": "інші",
        "adm_search": "Пошук",
        "adm_search_ph": "Назва, власник або MAC",
        "adm_state": "Стан",
        "adm_any": "Усі",
        "adm_problem": "Проблеми",
        "adm_with_problems": "З проблемами",
        "adm_no_problems": "Без проблем",
        "adm_sort": "Сортувати за",
        "sort_name": "Назва",
        "sort_owner": "Власник",
        "sort_state": "Стан",
        "sort_signal": "Сигнал (найслабший спершу)",
        "sort_health": "Якість Wi-Fi (найгірша спершу)",
        "sort_seen": "Востаннє в мережі (найновіші спершу)",
        "adm_apply": "Показати",
        "adm_reset": "Скинути",
        "adm_shown": "Показано {shown} з {total}",
        "adm_none": "Жоден пристрій не підходить.",
        "adm_problems_n": "проблем: {n}",
    },
}
for _lang, _texts in DASHBOARD_TEXT.items():
    TEXT[_lang].update(_texts)

# The findings diagnostics.py can report (each has diag_<code>, diag_<code>_why, diag_<code>_do;
# a finding with other texts for admins also has diag_<code>_admin_why/_admin_do, with {n} from
# its params).
DIAGNOSES = ("weak_signal", "low_snr", "high_retries", "busy_channel", "unstable_roaming", "frequent_disconnects",
             "stuck_on_2ghz", "slow_link", "stale_data", "offline", "never_connected", "mac_conflict")

# The device list's label per stored platform (web.py FORMATS plus letswifi).
PLATFORM_LABEL = {"apple": "for_apple", "apple-mac": "for_mac", "android": "for_android",
                  "eap-config": "for_android_app", "letswifi": "for_app"}


def pick(accept_language, house_lang=None):
    """The language the resident chose on the house's start page (cookie house_lang on the base
    domain: de, en or uk), else the best one for the Accept-Language header (ru -> uk, default en)."""
    if house_lang in TEXT:
        return house_lang
    for part in (accept_language or "").split(","):
        code = part.split(";")[0].strip().lower()[:2]
        if code in TEXT:
            return code
        if code == "ru":
            return "uk"
    return "en"


# --- formatting for the dashboard templates ---------------------------------------------------
# static/format.js does the same in the browser, with the same texts and thresholds: the page a
# script refreshes reads like the page the server sent.

HOUSE_TZ = "Europe/Berlin"
# Signal (dBm) -> bars and a word; at or above each threshold. Below the last: 0 bars, very weak.
SIGNAL_LEVELS = ((-60, 4, "sig_excellent"), (-67, 3, "sig_good"), (-75, 2, "sig_fair"), (-82, 1, "sig_weak"))
# Wi-Fi quality (wifi_client_health_score, 0-100) -> a word and a tone.
HEALTH_LEVELS = ((80, "q_good", "ok"), (50, "q_fair", "warn"))
_SEPARATORS = {"en": (",", "."), "de": (".", ","), "uk": (" ", ",")}   # (thousands, decimal)


def _texts(lang):
    return TEXT.get(lang) or TEXT["en"]


def parse_time(value):
    """An ISO 8601 string (as the JSON API sends it) or a datetime -> an aware datetime; None stays."""
    import datetime as dt
    if value is None or value == "":
        return None
    if isinstance(value, str):
        try:
            value = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    if isinstance(value, dt.datetime) and value.tzinfo is None:
        value = value.replace(tzinfo=dt.UTC)
    return value


class Format:
    """The dashboard's number, size, rate, time and place formatting per language, for Jinja
    (registered as the template global `fmt`). Every method returns "–" for an unknown value."""

    NONE = "–"

    @staticmethod
    def number(value, lang, digits=0):
        if value is None:
            return Format.NONE
        thousands, decimal = _SEPARATORS.get(lang, _SEPARATORS["en"])
        text = "{:,.{d}f}".format(float(value), d=digits)
        text = text.replace(",", "\0").replace(".", decimal).replace("\0", thousands)
        return text.replace("-", "−")                     # a real minus sign, as Intl writes it

    @staticmethod
    def _scaled(value, lang, units):
        """1-2 significant decimals: 4.2 MB, 42 MB, 420 MB."""
        if value is None:
            return Format.NONE
        value, unit = float(value), 0
        while abs(value) >= 1000 and unit < len(units) - 1:
            value, unit = value / 1000, unit + 1
        digits = 1 if unit and abs(value) < 10 else 0
        return "%s %s" % (Format.number(value, lang, digits), _texts(lang)[units[unit]])

    @staticmethod
    def bytes(value, lang):
        return Format._scaled(value, lang, ("u_b", "u_kb", "u_mb", "u_gb", "u_tb"))

    @staticmethod
    def bitrate(value, lang):
        return Format._scaled(value, lang, ("u_bit", "u_kbit", "u_mbit", "u_gbit"))

    @staticmethod
    def percent(ratio, lang, digits=0):
        if ratio is None:
            return Format.NONE
        return Format.number(ratio * 100, lang, digits) + (" %" if lang in ("de", "uk") else "%")

    @staticmethod
    def dbm(value, lang):
        return Format.NONE if value is None else _texts(lang)["dbm_fmt"].format(n=Format.number(value, lang))

    @staticmethod
    def db(value, lang):
        return Format.NONE if value is None else _texts(lang)["db_fmt"].format(n=Format.number(value, lang))

    @staticmethod
    def ms(value, lang):
        return Format.NONE if value is None else _texts(lang)["ms_fmt"].format(
            n=Format.number(value, lang, 1 if value < 10 else 0))

    @staticmethod
    def duration(seconds, lang, parts=2):
        """The largest units: "2 h 15 min", "3 d 4 h", "40 s"."""
        if seconds is None:
            return Format.NONE
        t, seconds = _texts(lang), max(0, int(seconds))
        units = (("dur_d", 86400), ("dur_h", 3600), ("dur_min", 60), ("dur_s", 1))
        out = []
        for key, size in units:
            n, seconds = divmod(seconds, size)
            if n and len(out) < parts:
                out.append(t[key].format(n=n))
            elif out:
                break                                          # "2 h", not "2 h 0 min 5 s"
            if key == "dur_min" and out:
                break                                          # seconds only below a minute
        return " ".join(out) or t["dur_s"].format(n=0)

    @staticmethod
    def ago(value, lang, now=None):
        """"5 min ago", "just now" (under a minute)."""
        import datetime as dt
        when = parse_time(value)
        if when is None:
            return Format.NONE
        now = parse_time(now) or dt.datetime.now(dt.UTC)
        seconds = (now - when).total_seconds()
        t = _texts(lang)
        if seconds < 60:
            return t["ago_now"]
        return t["ago_fmt"].format(when=Format.duration(seconds, lang, parts=1))

    @staticmethod
    def elapsed(start, lang, now=None):
        """How long since `start`, as a duration ("2 h 15 min")."""
        import datetime as dt
        begin = parse_time(start)
        if begin is None:
            return Format.NONE
        now = parse_time(now) or dt.datetime.now(dt.UTC)
        return Format.duration((now - begin).total_seconds(), lang)

    @staticmethod
    def strftime(when, pattern, lang):
        """%Y %m %d %e (day without a leading zero) %H %M %b (the language's short month); no locale needed."""
        months = _texts(lang)["months"]
        return (pattern.replace("%Y", "%04d" % when.year).replace("%m", "%02d" % when.month)
                .replace("%d", "%02d" % when.day).replace("%e", str(when.day)).replace("%H", "%02d" % when.hour)
                .replace("%M", "%02d" % when.minute).replace("%b", months[when.month - 1]))

    @staticmethod
    def when(value, lang, now=None):
        """A moment in the house's time: "14:05" today, "yesterday 14:05", else "24 Oct 14:05"
        (with the year when it is not this year)."""
        import datetime as dt
        from zoneinfo import ZoneInfo
        moment = parse_time(value)
        if moment is None:
            return Format.NONE
        zone = ZoneInfo(HOUSE_TZ)
        moment = moment.astimezone(zone)
        today = (parse_time(now) or dt.datetime.now(dt.UTC)).astimezone(zone).date()
        t = _texts(lang)
        clock = Format.strftime(moment, t["time_format"], lang)
        if moment.date() == today:
            return clock
        if moment.date() == today - dt.timedelta(days=1):
            return t["yesterday_at"].format(time=clock)
        day = Format.strftime(moment, t["day_format"] if moment.year == today.year else t["date_format"], lang)
        return "%s %s" % (day, clock)

    @staticmethod
    def date(value, lang):
        moment = parse_time(value)
        if moment is None:
            return Format.NONE
        from zoneinfo import ZoneInfo
        return Format.strftime(moment.astimezone(ZoneInfo(HOUSE_TZ)), _texts(lang)["date_format"], lang)

    @staticmethod
    def iso(value):
        """For <time datetime>: ISO 8601 in UTC."""
        moment = parse_time(value)
        return moment.isoformat() if moment else ""

    @staticmethod
    def room(ap, lang):
        """ap-scharni-2-corner as {"house", "floor", "spot"} -> "Scharni · 2nd floor · corner";
        a name outside the scheme as it is."""
        if not ap:
            return Format.NONE
        t = _texts(lang)
        if not ap.get("house"):
            return ap.get("name") or Format.NONE
        parts = [t.get("room_" + str(ap["house"]), str(ap["house"]).capitalize())]
        floor = ap.get("floor")
        if floor is not None and str(floor) != "":
            parts.append(t.get("room_floor_%s" % floor) or t["room_floor_n"].format(n=floor))
        if ap.get("spot"):
            parts.append(t.get("room_spot_" + str(ap["spot"]), str(ap["spot"])))
        return " · ".join(parts)

    @staticmethod
    def proto(proto, band, lang):
        if not proto:
            return None
        t = _texts(lang)
        key = "proto_ax6" if proto == "ax" and str(band) == "6" else "proto_" + str(proto)
        return t.get(key) or t["proto_old"]

    @staticmethod
    def band(band, lang):
        """"2.4" -> "2,4 GHz" (de)."""
        if not band:
            return Format.NONE
        return _texts(lang)["band_fmt"].format(band=Format.number(float(band), lang, 1 if str(band) == "2.4" else 0))

    @staticmethod
    def wifi(device, lang):
        """"5 GHz · channel 36 · Wi-Fi 6" from what is known."""
        t = _texts(lang)
        parts = []
        if device.get("band"):
            parts.append(Format.band(device["band"], lang))
        if device.get("channel"):
            parts.append(t["channel_fmt"].format(channel=device["channel"]))
        proto = Format.proto(device.get("proto"), device.get("band"), lang)
        if proto:
            parts.append(proto)
        return " · ".join(parts) or Format.NONE

    @staticmethod
    def signal(dbm):
        """(bars 0-4, text key, tone ok|warn|bad), or None when unknown."""
        if dbm is None:
            return None
        for threshold, bars, key in SIGNAL_LEVELS:
            if dbm >= threshold:
                return bars, key, "ok" if bars >= 3 else "warn"
        return 0, "sig_very_weak", "bad"

    @staticmethod
    def health(score):
        """(text key, tone ok|warn|bad), or None when unknown."""
        if score is None:
            return None
        for threshold, key, tone in HEALTH_LEVELS:
            if score >= threshold:
                return key, tone
        return "q_poor", "bad"


def template_globals():
    """What the dashboard templates need besides the context processor's values: web.py adds it
    with app.jinja_env.globals.update(i18n.template_globals())."""
    return {"fmt": Format, "diagnoses": DIAGNOSES}
