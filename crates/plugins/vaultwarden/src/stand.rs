//! The panel's screens on made-up data, recorded for the stand. The screens
//! are built by the same functions the plugin answers the window with; only
//! the data is invented. `KEYWARD_STAND_OUT=<dir>` writes
//! `<dir>/vaultwarden.json`, which the stand serves.

use keyward_core::items::{MemberStatus, OrgRole};
use serde_json::{json, Value};

use crate::api::UserAction;
use crate::settings::{Setting, SettingKind, SettingsGroup};
use crate::ui;
use crate::{orgs_of, panel_roles, ActionView, MembershipView, UserState, UserView};

const PANEL: &str = "https://vault.demo.example/admin";

fn user(id: &str, name: Option<&str>, email: &str, state: UserState, tfa: bool, orgs: &[(&str, &str, OrgRole, MemberStatus)]) -> UserView {
    let actions = state_actions(state, tfa);
    UserView {
        id: id.into(),
        name: name.map(Into::into),
        email: email.into(),
        state,
        two_factor: tfa,
        email_verified: state != UserState::Invited,
        created_at: Some("2025-11-03 09:12:00".into()),
        last_active: (state == UserState::Enabled).then(|| "2026-10-06 18:40:00".into()),
        memberships: orgs.iter().map(|(oid, oname, role, status)| MembershipView { org_id: (*oid).into(), org_name: (*oname).into(), role: *role, status: *status }).collect(),
        actions,
    }
}

fn state_actions(state: UserState, tfa: bool) -> Vec<ActionView> {
    let mut out = match state {
        UserState::Invited => vec![UserAction::ResendInvite],
        UserState::Enabled => vec![UserAction::Deauth, UserAction::Disable],
        UserState::Disabled => vec![UserAction::Enable],
    };
    if tfa {
        out.push(UserAction::RemoveTwoFactor);
    }
    out.push(UserAction::Delete);
    out.into_iter().map(ActionView::from).collect()
}

fn users() -> Vec<UserView> {
    vec![
        user("u1", Some("Alex Morgan"), "alex@acme.example", UserState::Enabled, true, &[("o1", "Acme", OrgRole::Owner, MemberStatus::Confirmed)]),
        user("u2", Some("Dana Whitfield"), "dana@acme.example", UserState::Enabled, false, &[("o1", "Acme", OrgRole::Admin, MemberStatus::Confirmed), ("o2", "Globex", OrgRole::User, MemberStatus::Accepted)]),
        user("u3", None, "new.hire@acme.example", UserState::Invited, false, &[]),
        user("u4", Some("Old Contractor"), "contractor@demo.example", UserState::Disabled, true, &[("o2", "Globex", OrgRole::User, MemberStatus::Confirmed)]),
    ]
}

fn setting(name: &str, label: &str, kind: SettingKind, value: Value, editable: bool) -> Setting {
    Setting { name: name.into(), label: label.into(), description: String::new(), kind, value, default: None, editable, overridden: false, choice: None }
}

fn groups() -> Vec<SettingsGroup> {
    let mut port = setting("smtp_port", "Port", SettingKind::Number, json!(587), true);
    port.default = Some("587".into());
    vec![
        SettingsGroup {
            id: "general".into(),
            title: "General settings".into(),
            settings: vec![
                setting("domain", "Domain URL", SettingKind::Text, json!("https://vault.demo.example"), true),
                setting("signups_allowed", "Allow new signups", SettingKind::Checkbox, json!(false), true),
            ],
        },
        SettingsGroup {
            id: "smtp".into(),
            title: "SMTP Email Settings".into(),
            settings: vec![setting("smtp_host", "Host", SettingKind::Text, json!("smtp.demo.example"), true), port, setting("smtp_password", "Password", SettingKind::Password, json!("made-up"), true)],
        },
        SettingsGroup { id: "readonly".into(), title: "Read-Only Config".into(), settings: vec![setting("database_url", "Database URL", SettingKind::Password, json!("data/db.sqlite3"), false), setting("web_vault_enabled", "Web vault", SettingKind::Checkbox, json!(true), false)] },
    ]
}

fn reply(r: anyhow::Result<keyward_ui::Reply>) -> Option<Value> {
    r.ok().and_then(|r| serde_json::to_value(r).ok())
}

fn act(op: &str, p: &Value) -> Option<Value> {
    let users = users();
    let s = |key: &str| p.get(key).and_then(Value::as_str).unwrap_or_default().to_string();
    match op {
        "users_body" => reply(keyward_ui::Reply::data(json!({ "body": [ui::users_table(&users)] }))),
        "orgs_body" => reply(keyward_ui::Reply::data(json!({ "body": [ui::orgs_table(&orgs_of(&users))] }))),
        "settings_body" => reply(keyward_ui::Reply::data(json!({ "body": ui::settings_body(&groups()) }))),
        "user" => users.iter().find(|u| u.id == s("user_id")).and_then(|u| reply(Ok(keyward_ui::Reply::drawer(ui::user_drawer(u, &panel_roles()))))),
        "org" => orgs_of(&users).iter().find(|o| o.id == s("org_id")).and_then(|o| reply(Ok(keyward_ui::Reply::drawer(ui::org_drawer(o, &panel_roles()))))),
        "invite_dialog" => reply(Ok(keyward_ui::Reply::dialog(ui::invite_dialog()))),
        "refresh" => reply(Ok(keyward_ui::Reply::refresh())),
        _ => None,
    }
}

/// Every page and dialogue keeps to one main action.
fn primaries(v: &Value) -> usize {
    match v {
        Value::Object(o) => usize::from(o.get("primary") == Some(&Value::Bool(true))) + o.iter().filter(|(k, _)| !matches!(k.as_str(), "drawer" | "dialog")).map(|(_, x)| primaries(x)).sum::<usize>(),
        Value::Array(a) => a.iter().map(primaries).sum(),
        _ => 0,
    }
}

/// The words a declared value says: every `{key, args?}`.
fn words(v: &Value, out: &mut std::collections::BTreeSet<String>) {
    match v {
        Value::Object(o) => {
            if let Some(Value::String(k)) = o.get("key") {
                if o.keys().all(|x| x == "key" || x == "args") {
                    out.insert(k.clone());
                }
            }
            o.values().for_each(|x| words(x, out));
        }
        Value::Array(a) => a.iter().for_each(|x| words(x, out)),
        _ => {}
    }
}

#[test]
fn the_screens_on_made_up_data() {
    let record = keyward_ui::stand::crawl(|route| (route.is_empty()).then(|| serde_json::to_value(ui::panel_page(PANEL)).unwrap()), act);
    assert!(record.acts().iter().any(|a| a["op"] == "user"), "a user's row opens their drawer");
    assert!(record.acts().iter().any(|a| a["op"] == "org"), "an organisation's row opens its drawer");
    for (route, page) in record.views() {
        assert!(primaries(page) <= 1, "{route}: more than one main action");
    }
    for a in record.acts() {
        for key in ["drawer", "dialog"] {
            assert!(primaries(&a["reply"][key]) <= 1, "{} {}: more than one main action", a["op"], a["payload"]);
        }
    }
    // No secret of the server is echoed: the password setting goes empty,
    // the read-only one is said to be set, never shown.
    let all = record.to_json().to_string();
    assert!(!all.contains("made-up") && !all.contains("db.sqlite3"), "a secret setting reached the window");

    let places = ui::declare(Some(PANEL), true);
    places.check().unwrap();
    let locked = ui::declare(Some(PANEL), false);
    locked.check().unwrap();
    let mut out = record.to_json();
    out["places"] = serde_json::to_value(&places).unwrap();
    out["views"]["locked"] = serde_json::to_value(ui::locked_page(PANEL)).unwrap();

    // Every word on every screen, and every word the screens' code names, is
    // in both of the plugin's dictionaries.
    let mut said = std::collections::BTreeSet::new();
    words(&out, &mut said);
    let code = include_str!("ui.rs");
    for part in code.split('"').skip(1).step_by(2) {
        if part.starts_with("vwadmin.") || part.starts_with("err.") {
            said.insert(part.to_string());
        }
    }
    for (lang, file) in [("en", include_str!("../i18n/en.json")), ("ru", include_str!("../i18n/ru.json"))] {
        let words: std::collections::BTreeMap<String, Value> = serde_json::from_str(file).unwrap();
        let missing: Vec<&String> = said.iter().filter(|k| !words.contains_key(k.as_str())).collect();
        assert!(missing.is_empty(), "{lang}.json lacks {missing:?}");
    }
    if let Some(dir) = std::env::var_os("KEYWARD_STAND_OUT") {
        out["manifest"] = serde_json::to_value(keyward_plugin::Plugin::manifest(&crate::VaultwardenPlugin::new())).unwrap();
        std::fs::write(std::path::Path::new(&dir).join("vaultwarden.json"), serde_json::to_vec_pretty(&out).unwrap()).unwrap();
    }
}

#[test]
fn a_form_becomes_the_changes_the_panel_takes() {
    let g = groups();
    let form = |pairs: &[(&str, &str)]| pairs.iter().map(|(k, v)| ((*k).to_string(), (*v).to_string())).collect();
    let c = ui::changes_of(&g, "smtp", &form(&[("smtp_host", "mail.demo.example"), ("smtp_port", "2525"), ("smtp_password", "")])).unwrap();
    assert_eq!(c["smtp_host"], "mail.demo.example");
    assert_eq!(c["smtp_port"], 2525);
    assert!(!c.contains_key("smtp_password"), "a secret left empty stays as it is");
    let c = ui::changes_of(&g, "general", &form(&[("signups_allowed", "true")])).unwrap();
    assert_eq!(c["signups_allowed"], true);
    assert!(ui::changes_of(&g, "general", &form(&[("signups_allowed", "yes")])).is_err());
    assert!(ui::changes_of(&g, "smtp", &form(&[("database_url", "x")])).is_err(), "a read-only setting is refused");
    assert!(ui::changes_of(&g, "smtp", &form(&[("smtp_port", "many")])).is_err());
}
