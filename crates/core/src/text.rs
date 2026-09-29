//! Words for a person, in one place for the whole project.
//!
//! The core's dictionaries live at the root of the repository (`i18n/ru.json`,
//! `i18n/en.json`) and are the only place any of its wording is written down.
//! The window reads them as JSON; the daemon reads the same files, compiled in.
//!
//! A plugin's words live with the plugin and travel inside its package
//! (`<package>/i18n/<lang>.json`). The core cannot compile them in — it does
//! not know which plugins exist — so whoever draws a plugin's sentence loads
//! them from disk with [`load_dictionaries`] and they lie on top of the
//! core's.
//!
//! The daemon mostly does not need them: what it answers over the socket is a
//! key, and the window that asked knows its own language. But some of what the
//! daemon says is drawn by the system, not by a window -- the reason under a
//! Touch ID prompt, the body of a notification -- and there the daemon has to
//! produce the sentence itself. That is what this is for, and the point is
//! that it is the *same* sentence: one wording, one home.

use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};

const RU: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../i18n/ru.json"));
const EN: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../i18n/en.json"));

/// Which language the daemon speaks when it has to speak at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    Ru,
    En,
}

impl Lang {
    /// The language behind a settings value: `ru`, `en`, or anything else for
    /// "as the system has it".
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "ru" => Self::Ru,
            "en" => Self::En,
            _ => Self::system(),
        }
    }

    /// What the system is set to. macOS answers through `AppleLanguages`; a
    /// machine that answers nothing gets English.
    pub fn system() -> Self {
        for var in ["LC_ALL", "LC_MESSAGES", "LANG"] {
            if let Ok(v) = std::env::var(var) {
                if v.to_ascii_lowercase().starts_with("ru") {
                    return Self::Ru;
                }
                if !v.is_empty() {
                    return Self::En;
                }
            }
        }
        #[cfg(target_os = "macos")]
        {
            let out = std::process::Command::new("/usr/bin/defaults")
                .args(["read", "-g", "AppleLanguages"])
                .output();
            if let Ok(out) = out {
                if String::from_utf8_lossy(&out.stdout).to_lowercase().contains("\"ru") {
                    return Self::Ru;
                }
            }
        }
        Self::En
    }
}

static CHOSEN: RwLock<Option<Lang>> = RwLock::new(None);

/// Say which language to speak. The daemon calls this when settings are read
/// and whenever they change; until then the system's own answer is used.
pub fn set_lang(lang: Lang) {
    *CHOSEN.write().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(lang);
}

pub fn lang() -> Lang {
    match *CHOSEN.read().unwrap_or_else(std::sync::PoisonError::into_inner) {
        Some(l) => l,
        None => Lang::system(),
    }
}

/// The words that came with the plugins: loaded from disk rather than compiled
/// in, because which plugins there are is not known until they are installed.
static EXTRA_RU: RwLock<Option<HashMap<String, String>>> = RwLock::new(None);
static EXTRA_EN: RwLock<Option<HashMap<String, String>>> = RwLock::new(None);

/// Add a dictionary to the ones already known. The words lie on top of the
/// core's: a plugin may not quietly replace a core wording, so a key that is
/// already compiled in wins.
pub fn add_dictionary(lang: Lang, json: &str) -> usize {
    let Ok(words) = serde_json::from_str::<HashMap<String, String>>(json) else {
        return 0;
    };
    let cell = match lang {
        Lang::Ru => &EXTRA_RU,
        Lang::En => &EXTRA_EN,
    };
    let mut guard = cell.write().unwrap_or_else(std::sync::PoisonError::into_inner);
    let store = guard.get_or_insert_with(HashMap::new);
    let mut added = 0;
    for (key, text) in words {
        if table(lang).contains_key(&key) {
            continue;
        }
        store.insert(key, text);
        added += 1;
    }
    added
}

/// Load every plugin's dictionaries out of the directory the packages live in:
/// `<dir>/<id>/i18n/<lang>.json`. Missing files are no error — a plugin need
/// not say anything to a person.
pub fn load_dictionaries(dir: &std::path::Path) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut added = 0;
    for entry in entries.flatten() {
        let i18n = entry.path().join("i18n");
        for (lang, file) in [(Lang::Ru, "ru.json"), (Lang::En, "en.json")] {
            if let Ok(raw) = std::fs::read_to_string(i18n.join(file)) {
                added += add_dictionary(lang, &raw);
            }
        }
    }
    added
}

/// What a language says for a key: the compiled-in words first, then whatever
/// the plugins brought.
/// Every key is camelCase, segment by segment (`err.vaultLocked`). A key in
/// the old snake_case (`err.vault_locked`) — kept in an edit's saved error, or
/// sent by a plugin not rebuilt yet — is the same key, and is read as such.
fn normal(key: &str) -> std::borrow::Cow<'_, str> {
    if !key.contains('_') || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.') {
        return std::borrow::Cow::Borrowed(key);
    }
    let mut out = String::with_capacity(key.len());
    let mut upper = false;
    for c in key.chars() {
        match c {
            '_' => upper = true,
            '.' => {
                upper = false;
                out.push('.');
            }
            c if upper => {
                out.extend(c.to_uppercase());
                upper = false;
            }
            c => out.push(c),
        }
    }
    std::borrow::Cow::Owned(out)
}

fn look(lang: Lang, key: &str) -> Option<String> {
    let key = &*normal(key);
    if let Some(text) = table(lang).get(key) {
        return Some(text.clone());
    }
    let cell = match lang {
        Lang::Ru => &EXTRA_RU,
        Lang::En => &EXTRA_EN,
    };
    let guard = cell.read().unwrap_or_else(std::sync::PoisonError::into_inner);
    guard.as_ref()?.get(key).cloned()
}

/// Whether a key is known at all: compiled in or brought by a plugin.
fn known(lang: Lang, key: &str) -> bool {
    look(lang, key).is_some()
}

fn table(lang: Lang) -> &'static HashMap<String, String> {
    static RU_MAP: OnceLock<HashMap<String, String>> = OnceLock::new();
    static EN_MAP: OnceLock<HashMap<String, String>> = OnceLock::new();
    let (cell, raw) = match lang {
        Lang::Ru => (&RU_MAP, RU),
        Lang::En => (&EN_MAP, EN),
    };
    cell.get_or_init(|| serde_json::from_str(raw).unwrap_or_default())
}

/// The sentence behind a key, with `{name}` filled in from the pairs given.
///
/// A key the dictionary does not know comes back as itself: a message must
/// never vanish because a translation is late.
pub fn t(key: &str, args: &[(&str, &str)]) -> String {
    let mut out = match look(lang(), key).or_else(|| look(Lang::En, key)) {
        Some(text) => text,
        None => return key.to_string(),
    };
    for (name, value) in args {
        out = out.replace(&format!("{{{name}}}"), value);
    }
    out
}

/// A message for the wire: a key and the values that fill it, in the form
/// [`render`] and the window's `tError` understand.
///
/// Used where the daemon has something to say to a person but is not the one
/// who will draw it: a notification is drawn by whoever has a window, and that
/// window knows its own language.
pub fn message(code: &str, args: &[(&str, &str)]) -> String {
    let mut out = crate::fault::Fault::new(code);
    for (name, value) in args {
        out = out.with(*name, value);
    }
    out.to_string()
}

/// A message from the wire turned into a sentence.
///
/// What travels over the socket is either a bare key (`err.badPassword`) or a
/// key followed by the values that fill it
/// (`err.totpSeedTruncated {"total":"13"}`). This is the Rust twin of
/// `tError` in the window, for the two places that draw text themselves: the
/// body of a system notification and the reason under a Touch ID prompt.
///
/// Anything that is not a key comes back untouched: a message must never vanish
/// because it was written before this existed.
pub fn render(message: &str) -> String {
    let message = message.trim();
    if known(lang(), message) || known(Lang::En, message) {
        return t(message, &[]);
    }
    let Some((code, rest)) = message.split_once(char::is_whitespace) else {
        return message.to_string();
    };
    let rest = rest.trim();
    if !rest.starts_with('{') {
        return message.to_string();
    }
    if !(known(lang(), code) || known(Lang::En, code)) {
        return message.to_string();
    }
    let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(rest) else {
        return message.to_string();
    };
    let values: Vec<(String, String)> = map
        .into_iter()
        .map(|(name, value)| {
            let text = value.as_str().map(str::to_string).unwrap_or_else(|| value.to_string());
            // A value that is itself a key becomes its sentence: that is how the
            // name of a permission travels.
            let text = if known(lang(), &text) { t(&text, &[]) } else { text };
            (name, text)
        })
        .collect();
    let args: Vec<(&str, &str)> = values.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect();
    t(code, &args)
}

/// Check a pair of dictionaries against each other: the same keys in both
/// languages, and the same `{name}` values inside a sentence. Any dictionary
/// shipped with the project is held to this — the core's and every plugin's —
/// so the rule lives in one place.
///
/// Returns every complaint it has; an empty list means the pair is sound.
pub fn audit(ru: &str, en: &str) -> Vec<String> {
    let mut wrong = Vec::new();
    let ru: HashMap<String, String> = match serde_json::from_str(ru) {
        Ok(map) => map,
        Err(e) => return vec![format!("ru.json does not parse: {e}")],
    };
    let en: HashMap<String, String> = match serde_json::from_str(en) {
        Ok(map) => map,
        Err(e) => return vec![format!("en.json does not parse: {e}")],
    };
    let mut lonely: Vec<&String> = ru.keys().filter(|k| !en.contains_key(*k)).collect();
    lonely.extend(en.keys().filter(|k| !ru.contains_key(*k)));
    lonely.sort();
    for key in lonely {
        wrong.push(format!("the key {key} exists in one language only"));
    }
    let names = |text: &str| -> Vec<String> {
        let mut out: Vec<String> = text
            .split('{')
            .skip(1)
            .filter_map(|tail| tail.split_once('}').map(|(name, _)| name.to_string()))
            .collect();
        out.sort();
        out
    };
    let mut keys: Vec<&String> = ru.keys().collect();
    keys.sort();
    for key in keys {
        let (Some(a), Some(b)) = (ru.get(key), en.get(key)) else { continue };
        if names(a) != names(b) {
            wrong.push(format!("the values differ for the key {key}: {:?} against {:?}", names(a), names(b)));
        }
    }
    wrong
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_key_is_camel_case_and_an_old_snake_one_still_reads() {
        for (name, raw) in [("ru", RU), ("en", EN)] {
            let dict: HashMap<String, String> = serde_json::from_str(raw).unwrap();
            let snake: Vec<&String> = dict.keys().filter(|k| k.contains('_')).collect();
            assert!(snake.is_empty(), "{name}: snake_case keys {snake:?}");
        }
        assert_eq!(t("err.vault_locked", &[]), t("err.vaultLocked", &[])); // compatibility: an old key
        assert_ne!(t("err.vaultLocked", &[]), "err.vaultLocked");
        assert_eq!(normal("plugin.perm.items_write"), "plugin.perm.itemsWrite");
        assert_eq!(normal("not a key_with spaces"), "not a key_with spaces");
    }

    #[test]
    fn the_core_dictionaries_agree() {
        let wrong = audit(RU, EN);
        assert!(wrong.is_empty(), "{wrong:#?}");
    }

    #[test]
    fn a_value_is_substituted_and_an_unknown_key_survives() {
        set_lang(Lang::En);
        let text = t("err.totpSeedTruncated", &[("total", "13")]);
        assert!(text.contains("13"), "the value was not substituted: {text}");
        assert!(!text.contains("{total}"), "the placeholder was left in: {text}");
        assert_eq!(t("no.such.key", &[]), "no.such.key");
    }

    #[test]
    fn a_wire_message_becomes_a_sentence() {
        set_lang(Lang::En);
        assert_eq!(render("err.vaultLocked"), t("err.vaultLocked", &[]));
        let out = render(r#"err.totpSeedTruncated {"total":"13"}"#);
        assert!(out.contains("13") && !out.contains("{total}"), "{out}");
        // Anything that is not a key passes through as it is.
        assert_eq!(render("the server answered 500"), "the server answered 500");
        assert_eq!(render("err.no.such.key {\"a\":\"b\"}"), "err.no.such.key {\"a\":\"b\"}");
    }

    #[test]
    fn a_plugin_may_add_words_but_not_replace_them() {
        set_lang(Lang::En);
        let was = t("err.vaultLocked", &[]);
        let added = add_dictionary(
            Lang::En,
            r#"{"plugin.test.hello":"a word of its own","err.vaultLocked":"a word of ours"}"#,
        );
        assert_eq!(added, 1, "only the new key is taken");
        assert_eq!(t("plugin.test.hello", &[]), "a word of its own");
        assert_eq!(t("err.vaultLocked", &[]), was, "the core's wording stands");
        assert_eq!(render("plugin.test.hello"), "a word of its own");
    }
}
