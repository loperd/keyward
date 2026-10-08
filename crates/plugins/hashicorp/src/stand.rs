//! The broker's screens on made-up data, recorded for the stand. The screens
//! are built by the same functions the plugin answers the window with; only
//! the data is invented. `KEYWARD_STAND_OUT=<dir>` writes `<dir>/hashicorp.json`.

use serde_json::{json, Value};

use crate::link::Link;
use crate::model::{FieldView, Health, IssueState, Issued, KvConfig, Mount, Recipient, RootToken, SealStatus, SecretMeta, SecretVersion, SecretView, TokenInfo};
use crate::ui;

/// The record is made now, so its times read as they will on the stand.
fn now() -> u64 {
    crate::api::now_secs()
}

fn link(id: &str, name: &str, addr: &str) -> Link {
    Link { entry_id: id.into(), entry_name: name.into(), addr: addr.into(), has_role_id: false, has_root: true, unseal_keys: 3, unseal_fields: vec!["share 1".into(), "share 2".into(), "share 3".into()] }
}

fn links() -> Vec<Link> {
    // The demo vault's notes, so the stand finds the items they point at.
    vec![link("pv-notes", "Prod Vault", "https://vault.prod.demo.example"), link("wifi", "Lab Vault", "https://vault.lab.demo.example")]
}

fn mount(path: &str, kind: &str, kv2: bool, auth: bool) -> Mount {
    Mount { path: path.into(), kind: kind.into(), description: String::new(), kv2, accessor: String::new(), default_lease_ttl: 0, max_lease_ttl: 0, auth }
}

fn mounts() -> Vec<Mount> {
    vec![mount("secret/", "kv", true, false), mount("legacy/", "kv", false, false), mount("transit/", "transit", false, false)]
}

fn auth() -> Vec<Mount> {
    vec![mount("token/", "token", false, true), mount("approle/", "approle", false, true)]
}

fn issued() -> Vec<Issued> {
    let one = |acc: &str, note: &str, ttl: u32, ago: u64, state: IssueState| Issued { accessor: acc.into(), recipient: Recipient::Agent, policies: vec!["ro-dev".into()], ttl_seconds: ttl, num_uses: 0, note: note.into(), created_at: now() - ago, wrapped: false, state };
    vec![one("acc1", "ci deploy", 900, 60, IssueState::Active), one("acc2", "", 3600, 7200, IssueState::Expired), one("acc3", "debug", 900, 300, IssueState::Revoked)]
}

fn secret() -> SecretView {
    SecretView { mount: "secret/".into(), path: "prod/db".into(), fields: vec![FieldView { key: "user".into(), length: 3 }, FieldView { key: "password".into(), length: 24 }], version: Some(3), updated: None }
}

fn meta() -> SecretMeta {
    let v = |n: u64, deleted: bool, destroyed: bool| SecretVersion { version: n, created: Some(format!("2026-10-0{n}T10:00:00Z")), deleted: deleted.then(|| "2026-10-05T10:00:00Z".into()), destroyed };
    SecretMeta {
        mount: "secret/".into(),
        path: "prod/db".into(),
        current_version: 3,
        oldest_version: 1,
        max_versions: 10,
        cas_required: false,
        delete_version_after: String::new(),
        custom_metadata: Default::default(),
        created: None,
        updated: None,
        versions: vec![v(1, false, true), v(2, true, false), v(3, false, false)],
    }
}

fn reply(r: anyhow::Result<keyward_ui::Reply>) -> Option<Value> {
    r.ok().and_then(|r| serde_json::to_value(r).ok())
}

fn data(nodes: Vec<keyward_ui::Node>) -> Option<Value> {
    reply(keyward_ui::Reply::data(json!({ "body": nodes })))
}

fn act(op: &str, p: &Value) -> Option<Value> {
    use keyward_ui::Reply;
    let s = |key: &str| p.get(key).and_then(Value::as_str).unwrap_or_default().to_string();
    let l = links().remove(0);
    match op {
        "issued_body" => data(vec![ui::issued_table(&issued(), now())]),
        "mounts_body" => data(vec![ui::mounts_table(&mounts())]),
        "engines_body" => data(ui::engines_body(&mounts(), &auth())),
        "policies_body" => data(ui::policies_body(&["default".into(), "root".into(), "ro-dev".into(), "keyward-policy-admin".into()])),
        "roots_body" => data(ui::roots_body(&l, &[RootToken { entry_id: "r1".into(), addr: l.addr.clone(), issued_at: now() - 86_400, info: Some(TokenInfo::default()) }])),
        "dir" if s("path").is_empty() => reply(Ok(Reply::drawer(ui::dir_page(&s("mount"), "", &["prod/".into(), "shared-key".into()])))),
        "dir" => reply(Ok(Reply::drawer(ui::dir_page(&s("mount"), &s("path"), &["db".into()])))),
        "secret" => reply(Ok(Reply::drawer(ui::secret_page(&secret(), Some(&meta()), true)))),
        "secret_edit" => reply(Ok(Reply::dialog(ui::secret_edit(&secret(), true)))),
        "secret_new" => reply(Ok(Reply::dialog(ui::secret_new(&s("mount"), &s("path"))))),
        "mount" => {
            let all: Vec<Mount> = mounts().into_iter().chain(auth()).collect();
            let m = all.into_iter().find(|m| m.path == s("path"))?;
            let cfg = (m.kv2).then(|| KvConfig { max_versions: 10, cas_required: false, delete_version_after: String::new() });
            reply(Ok(Reply::drawer(ui::mount_page(&m, cfg.as_ref()))))
        }
        "enable_dialog" => reply(Ok(Reply::dialog(ui::enable_dialog(p.get("auth").and_then(Value::as_bool).unwrap_or(false))))),
        "policy" => reply(Ok(Reply::dialog(ui::policy_page(&s("name"), "path \"secret/data/dev/*\" {\n  capabilities = [\"read\"]\n}\n", true)))),
        "policy_new" => reply(Ok(Reply::dialog(ui::policy_new()))),
        "issue_dialog" => reply(Ok(Reply::dialog(ui::issue_dialog(&["ro-dev".into(), "deploy".into()])))),
        "connect_dialog" => reply(Ok(Reply::dialog(ui::connect_address()))),
        "edit_dialog" => reply(Ok(Reply::dialog(ui::connect_fields(&l.addr, &l.entry_id, &["share 1".into(), "share 2".into(), "share 3".into(), "notes".into()], 3, Some(&l))))),
        "go" | "refresh" => reply(Ok(if op == "go" { Reply::go(s("route")) } else { Reply::refresh() })),
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
    let ls = links();
    let health = Health { initialized: true, sealed: true, standby: false, version: Some("1.17.2".into()) };
    let seal = SealStatus { kind: "shamir".into(), initialized: true, sealed: true, t: 3, n: 5, progress: 1, version: Some("1.17.2".into()) };
    let record = keyward_ui::stand::crawl(
        |route| {
            let page = match route {
                "" => ui::overview(&ls, Some("pv-notes")),
                "settings" => ui::settings_page(true),
                "conn/pv-notes" => ui::console(&ls[0], Ok(&health), Some(&seal)),
                "conn/wifi" => ui::not_in_use(&ls[1]),
                _ => return None,
            };
            serde_json::to_value(page).ok()
        },
        act,
    );
    for (route, page) in record.views() {
        assert!(primaries(page) <= 1, "{route}: more than one main action");
    }
    for a in record.acts() {
        for key in ["drawer", "dialog"] {
            assert!(primaries(&a["reply"][key]) <= 1, "{} {}: more than one main action", a["op"], a["payload"]);
        }
    }
    assert!(record.acts().iter().any(|a| a["op"] == "secret"), "a secret opens its drawer");
    // The console's unseal is filled in by the daemon, by the fields' names.
    let console = serde_json::to_string(record.views().find(|(r, _)| r.as_str() == "conn/pv-notes").unwrap().1).unwrap();
    assert!(console.contains("\"fill\""), "the unseal does not ask the daemon for the shares");

    let places = ui::declare(&ls, Some("pv-notes"));
    places.check().unwrap();
    let mut out = record.to_json();
    out["places"] = serde_json::to_value(&places).unwrap();
    // The settings screen is opened from Settings › Plugins, not from a route.
    out["views"]["settings"] = serde_json::to_value(ui::settings_page(true)).unwrap();
    out["views"]["connect"] = serde_json::to_value(ui::connect_note("https://vault.new.demo.example", &seal)).unwrap();

    let mut said = std::collections::BTreeSet::new();
    words(&out, &mut said);
    for part in include_str!("ui.rs").split('"').skip(1).step_by(2) {
        if ["hc.", "vault.", "secret.", "engine.", "policy.", "root.", "connect.", "hashicorp.", "settings.", "plugin.hashicorp", "step.", "ttl.", "choice.", "common."].iter().any(|p| part.starts_with(p)) && !part.contains(' ') {
            said.insert(part.to_string());
        }
    }
    for (lang, file) in [("en", include_str!("../i18n/en.json")), ("ru", include_str!("../i18n/ru.json"))] {
        let w: std::collections::BTreeMap<String, Value> = serde_json::from_str(file).unwrap();
        let missing: Vec<&String> = said.iter().filter(|k| !w.contains_key(k.as_str())).collect();
        assert!(missing.is_empty(), "{lang}.json lacks {missing:?}");
    }
    if let Some(dir) = std::env::var_os("KEYWARD_STAND_OUT") {
        out["manifest"] = serde_json::to_value(keyward_plugin::Plugin::manifest(&crate::HashicorpPlugin::new())).unwrap();
        std::fs::write(std::path::Path::new(&dir).join("hashicorp.json"), serde_json::to_vec_pretty(&out).unwrap()).unwrap();
    }
}
