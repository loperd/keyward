//! The server's settings as the panel has them.
//!
//! Vaultwarden keeps its settings in groups — general, advanced, SMTP, SSO,
//! push, jobs, Yubikey, Duo and the rest — each setting with a caption, a
//! description, a type, a default, and whether it may be edited or is set by
//! the environment. None of that has a JSON endpoint: the panel renders it
//! into its settings page, and the page is where it is read from.
//!
//! Saving is the page's own protocol: `POST /admin/config` with every
//! editable setting, not only the changed ones — the server replaces the
//! whole of its user config with what it gets, and a partial answer would
//! wipe the rest.

use std::collections::BTreeMap;

use scraper::{ElementRef, Html, Selector};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// What kind of field a setting is, as the page draws it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettingKind {
    Text,
    Number,
    Password,
    Checkbox,
}

impl SettingKind {
    fn of(input_type: &str) -> Self {
        match input_type {
            "number" => Self::Number,
            "password" => Self::Password,
            "checkbox" => Self::Checkbox,
            _ => Self::Text,
        }
    }
}

/// A setting whose value is a choice among what the server knows, rather than
/// free text — so the window can offer a picker.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Choice {
    /// Some of the server's users, by email, joined with `separator`; `all`
    /// and `none` are the words the server reads as everyone and nobody.
    Users { options: Vec<String>, all: String, none: String, separator: String },
}

/// The settings that name users, by the server's own rule: blank or `all`
/// is everyone, `none` is nobody, anything else a list of emails.
const USER_LISTS: &[&str] = &["org_creation_users"];

/// Offer a picker where a setting names users.
pub fn attach_users(groups: &mut [SettingsGroup], emails: &[String]) {
    for s in groups.iter_mut().flat_map(|g| g.settings.iter_mut()) {
        if USER_LISTS.contains(&s.name.as_str()) {
            s.choice = Some(Choice::Users {
                options: emails.to_vec(),
                all: "all".into(),
                none: "none".into(),
                separator: ",".into(),
            });
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Setting {
    pub name: String,
    pub label: String,
    pub description: String,
    pub kind: SettingKind,
    /// A bool for a checkbox, a number, a string — or null when empty.
    pub value: Value,
    pub default: Option<String>,
    pub editable: bool,
    /// The value set here overrides what the environment says.
    pub overridden: bool,
    pub choice: Option<Choice>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SettingsGroup {
    pub id: String,
    pub title: String,
    pub settings: Vec<Setting>,
}

fn sel(s: &str) -> Selector {
    Selector::parse(s).expect("a fixed selector parses")
}

fn text(e: ElementRef<'_>) -> String {
    e.text().collect::<String>().split_whitespace().collect::<Vec<_>>().join(" ")
}

/// A value the way the page's own script reads its form: a checkbox is
/// whether it is ticked, a number is a number or nothing, text is text or
/// nothing.
fn value_of(kind: SettingKind, input: ElementRef<'_>) -> Value {
    let raw = input.value().attr("value").unwrap_or_default().trim();
    match kind {
        SettingKind::Checkbox => Value::Bool(input.value().attr("checked").is_some()),
        SettingKind::Number => raw.parse::<i64>().map(Value::from).or_else(|_| raw.parse::<f64>().map(Value::from)).unwrap_or(Value::Null),
        _ if raw.is_empty() => Value::Null,
        _ => Value::String(raw.to_string()),
    }
}

/// One setting's row: `title="[name] description"`, a caption, an input.
fn setting_of(row: ElementRef<'_>, editable: bool) -> Option<Setting> {
    let title = row.value().attr("title").unwrap_or_default();
    let (name, description) = title.strip_prefix('[')?.split_once(']')?;
    let input = row.select(&sel("input")).next()?;
    let kind = SettingKind::of(input.value().attr("type").unwrap_or("text"));
    // The database's address is drawn as a password on the read-only side,
    // and it is one: it may carry credentials.
    let label = row
        .select(&sel("label.col-form-label, div.col-form-label"))
        .next()
        .map(text)
        .unwrap_or_else(|| name.to_string());
    let default = match kind {
        SettingKind::Checkbox => row.select(&sel("label.form-check-label")).next().map(text),
        _ => input.value().attr("placeholder").map(str::to_string),
    }
    .and_then(|d| d.strip_prefix("Default:").map(|d| d.trim().to_string()))
    .filter(|d| !d.is_empty());
    Some(Setting {
        name: name.trim().to_string(),
        label,
        description: description.trim().to_string(),
        kind,
        value: value_of(kind, input),
        default,
        editable,
        overridden: row.value().classes().any(|c| c == "is-overridden-true"),
        choice: None,
    })
}

/// Read the settings page. The editable groups come as they are on the
/// server; everything that cannot be edited here comes last, as one group.
pub fn parse(html: &str) -> Vec<SettingsGroup> {
    let doc = Html::parse_document(html);
    let mut groups = Vec::new();
    for card in doc.select(&sel("#config-form .card")) {
        let Some(head) = card.select(&sel("button.card-header")).next() else { continue };
        let id = head.value().attr("id").unwrap_or_default().trim_start_matches("b_").to_string();
        let editable = id != "readonly";
        let settings: Vec<Setting> = card.select(&sel(".alert-row")).filter_map(|row| setting_of(row, editable)).collect();
        if settings.is_empty() {
            continue;
        }
        groups.push(SettingsGroup { id, title: text(head), settings });
    }
    groups
}

/// The whole editable set to post, from what the page has now with `changes`
/// laid over it. A change to a setting that may not be edited, or that does
/// not exist, is refused rather than slipped in.
pub fn to_save(groups: &[SettingsGroup], changes: &BTreeMap<String, Value>) -> anyhow::Result<Value> {
    let editable: BTreeMap<&str, &Setting> =
        groups.iter().flat_map(|g| &g.settings).filter(|s| s.editable).map(|s| (s.name.as_str(), s)).collect();
    if let Some(bad) = changes.keys().find(|k| !editable.contains_key(k.as_str())) {
        return Err(keyward_core::fault!("err.vwadminSettingNotEditable", "name" => bad));
    }
    let mut out = serde_json::Map::new();
    for (name, s) in editable {
        let v = changes.get(name).cloned().unwrap_or_else(|| s.value.clone());
        let v = match (s.kind, v) {
            (SettingKind::Checkbox, Value::Bool(b)) => Value::Bool(b),
            (SettingKind::Checkbox, _) => Value::Bool(false),
            (SettingKind::Number, Value::Number(n)) => Value::Number(n),
            (SettingKind::Number, Value::String(t)) if !t.trim().is_empty() => {
                t.trim().parse::<i64>().map(Value::from).map_err(|_| keyward_core::fault!("err.vwadminSettingNumber", "name" => name))?
            }
            (SettingKind::Number, _) => Value::Null,
            (_, Value::String(t)) if !t.is_empty() => Value::String(t),
            _ => Value::Null,
        };
        out.insert(name.to_string(), v);
    }
    Ok(Value::Object(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: &str = r#"<form id="config-form">
      <div class="card mb-3"><button id="b_smtp" class="card-header">SMTP Email Settings</button>
        <div id="g_smtp" class="card-body">
          <div class="row alert-row is-overridden-true" title="[smtp_host] SMTP host">
            <label for="input_smtp_host" class="col-sm-3 col-form-label">Host</label>
            <input class="conf-text" type="text" name="smtp_host" value="smtp.example.com"></div>
          <div class="row alert-row is-overridden-false" title="[smtp_port] Port">
            <label class="col-sm-3 col-form-label">Port</label>
            <input class="conf-number" type="number" name="smtp_port" value="587" placeholder="Default: 587"></div>
          <div class="row alert-row is-overridden-false" title="[smtp_password] Password">
            <label class="col-sm-3 col-form-label">Password</label>
            <input class="conf-password" type="password" name="smtp_password" value="s3cret"></div>
          <div class="row alert-row is-overridden-false" title="[smtp_accept_invalid_certs] Accept invalid certs">
            <div class="col-sm-3 col-form-label">Accept Invalid Certs (Know the risks!)</div>
            <input class="conf-checkbox" type="checkbox" name="smtp_accept_invalid_certs">
            <label class="form-check-label"> Default: false </label></div>
        </div></div>
      <div class="card mb-3"><button id="b_readonly" class="card-header">Read-Only Config</button>
        <div id="g_readonly" class="card-body">
          <div class="row alert-row" title="[database_url] Database URL">
            <label class="col-sm-3 col-form-label">Database URL</label>
            <input readonly type="password" value="data/db.sqlite3"></div>
        </div></div>
    </form>"#;

    #[test]
    fn the_settings_page_reads_into_groups() {
        let g = parse(PAGE);
        assert_eq!(g.len(), 2);
        assert_eq!((g[0].id.as_str(), g[0].title.as_str()), ("smtp", "SMTP Email Settings"));
        let host = &g[0].settings[0];
        assert_eq!((host.name.as_str(), host.label.as_str(), host.kind), ("smtp_host", "Host", SettingKind::Text));
        assert!(host.overridden && host.editable);
        assert_eq!(g[0].settings[1].value, Value::from(587));
        assert_eq!(g[0].settings[1].default.as_deref(), Some("587"));
        assert_eq!(g[0].settings[2].kind, SettingKind::Password);
        assert_eq!((g[0].settings[3].value.clone(), g[0].settings[3].default.as_deref()), (Value::Bool(false), Some("false")));
        assert!(!g[1].settings[0].editable);
    }

    #[test]
    fn saving_sends_every_editable_setting_and_refuses_the_rest() {
        let g = parse(PAGE);
        let mut changes = BTreeMap::new();
        changes.insert("smtp_port".to_string(), Value::from("2525"));
        let body = to_save(&g, &changes).unwrap();
        assert_eq!(body["smtp_port"], 2525);
        // Untouched ones go as they are, or the server would forget them.
        assert_eq!(body["smtp_host"], "smtp.example.com");
        assert_eq!(body["smtp_password"], "s3cret");
        assert_eq!(body["smtp_accept_invalid_certs"], false);
        assert!(body.get("database_url").is_none());
        let mut bad = BTreeMap::new();
        bad.insert("database_url".to_string(), Value::from("x"));
        assert!(to_save(&g, &bad).is_err());
    }
}
