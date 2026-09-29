//! Every message key the code raises is in the dictionaries, and every key is
//! camelCase.
//!
//! A key missing from the dictionary reaches a person as `err.somethingRaw`;
//! a key in another case than the rest makes the dictionary a mix nobody can
//! keep straight. Both used to happen quietly: this test makes them loud.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap()
}

fn dictionary(path: &Path) -> BTreeMap<String, String> {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn dictionaries() -> Vec<PathBuf> {
    let root = root();
    let mut out = vec![root.join("i18n/en.json"), root.join("i18n/ru.json")];
    for plugin in std::fs::read_dir(root.join("crates/plugins")).unwrap().flatten() {
        for lang in ["en", "ru"] {
            let p = plugin.path().join(format!("i18n/{lang}.json"));
            if p.exists() {
                out.push(p);
            }
        }
    }
    out
}

fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        let p = entry.path();
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        if name == "target" || name == "node_modules" || name == "dist" {
            continue;
        }
        if p.is_dir() {
            sources(&p, out);
        } else if ["rs", "ts", "tsx", "js"].iter().any(|x| name.ends_with(&format!(".{x}"))) {
            out.push(p);
        }
    }
}

#[test]
fn every_key_is_camel_case() {
    for path in dictionaries() {
        let snake: Vec<String> = dictionary(&path).into_keys().filter(|k| k.contains('_')).collect();
        assert!(snake.is_empty(), "{}: snake_case keys {snake:?}", path.display());
    }
}

#[test]
fn every_raised_key_is_in_the_dictionary() {
    let root = root();
    let mut known = HashSet::new();
    for path in dictionaries() {
        known.extend(dictionary(&path).into_keys());
    }
    let mut files = Vec::new();
    for dir in ["crates", "gui/src", "gui/src-tauri/src", "extension"] {
        sources(&root.join(dir), &mut files);
    }
    let mut missing = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file).unwrap();
        for (n, line) in text.lines().enumerate() {
            // A string literal that is a whole key of the error or Touch ID
            // families.
            for part in line.split('"').skip(1).step_by(2) {
                let is_key = (part.starts_with("err.") || part.starts_with("touch."))
                    && part.len() > 6
                    && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_')
                    && !part.ends_with('.');
                // This very file names keys that must not exist, and the
                // compatibility test reads an old snake_case one on purpose.
                let exempt = file.ends_with("i18n_keys.rs") || line.contains("compatibility: an old key");
                // A family checked by its prefix (`err.generator` for every
                // generator error) is fine as long as the family exists.
                let family = known.iter().any(|k| k.starts_with(part) && k.len() > part.len());
                if is_key && !exempt && !family && !known.contains(part) {
                    missing.push(format!("{}:{}: {part}", file.strip_prefix(&root).unwrap().display(), n + 1));
                }
            }
        }
    }
    assert!(missing.is_empty(), "keys raised in code but absent from the dictionaries:\n{}", missing.join("\n"));
}
