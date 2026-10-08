//! The terminal's screens on made-up data, recorded for the stand. The
//! screens are built by the same functions the plugin answers the window
//! with; only the data is invented. `KEYWARD_STAND_OUT=<dir>` writes
//! `<dir>/ssh.json`. The stand plays its shells with an echo of its own.

use serde_json::Value;

use crate::places::declare;
use crate::terminal::health::{Check, KeyHealth, Report, Status};
use crate::terminal::session::{Info, State};
use crate::ui;
use crate::{Ask, SshKeyEntry, SshSettings};

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).expect("the clock is past 1970")
}

fn check(host: &str, port: u16, user: &str, status: Status) -> Check {
    Check { host: host.into(), port, user: Some(user.into()), status, latency_ms: Some(14), detail: None, fingerprint: Some("SHA256:Hc2m0aWe".into()), checked_at: Some(now() - 240), checking: false, note: None, aliases: Vec::new(), server: None }
}

/// The demo vault's keys, so the stand finds the items they point at.
fn report() -> Report {
    Report {
        keys: vec![
            KeyHealth { entry_id: "key-prod".into(), entry_name: "Prod deploy key".into(), status: Status::Rejected, checks: vec![check("db-1.prod.demo.example", 2222, "root", Status::Rejected), check("api-1.prod.demo.example", 22, "ubuntu", Status::Ok)] },
            KeyHealth { entry_id: "key-staging".into(), entry_name: "Staging key".into(), status: Status::Ok, checks: vec![check("bastion.staging.demo.example", 22, "ubuntu", Status::Ok)] },
        ],
        running: false,
        checked_at: Some(now() - 240),
    }
}

fn info(id: &str, host: &str, port: u16, user: &str) -> Info {
    Info { id: id.into(), entry_id: "key-prod".into(), entry_name: "Prod deploy key".into(), host: host.into(), address: host.into(), port, user: user.into(), opened_at: now() - 300 }
}

fn sessions() -> Vec<(Info, State)> {
    vec![(info("s1", "api-1.prod.demo.example", 22, "ubuntu"), State::Open), (info("s2", "bastion.staging.demo.example", 22, "ubuntu"), State::Open)]
}

fn keys() -> Vec<SshKeyEntry> {
    vec![
        SshKeyEntry { id: "key-prod".into(), name: "Prod deploy key".into(), hosts: "*.prod.demo.example".into(), user: "ubuntu".into(), port: String::new() },
        SshKeyEntry { id: "key-staging".into(), name: "Staging key".into(), hosts: String::new(), user: String::new(), port: String::new() },
    ]
}

fn reply(r: anyhow::Result<keyward_ui::Reply>) -> Option<Value> {
    r.ok().and_then(|r| serde_json::to_value(r).ok())
}

fn act(op: &str, p: &Value) -> Option<Value> {
    use keyward_ui::Reply;
    let s = |key: &str| p.get(key).and_then(Value::as_str).unwrap_or_default().to_string();
    match op {
        "connect_dialog" => reply(Ok(Reply::dialog(ui::connect_dialog(&keys())))),
        "route" => keys().iter().find(|k| k.id == s("entry_id")).and_then(|k| reply(Ok(Reply::drawer(ui::route_drawer(k))))),
        _ => None,
    }
}

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
    let ss = sessions();
    let settings = SshSettings { agent_enabled: true, ask: Ask::Never, shared_socket: true, health_minutes: 30 };
    let record = keyward_ui::stand::crawl(
        |route| {
            let page = match route {
                "" => ui::sessions_page(&ss),
                "keys" => ui::routes_page(&keys()),
                "settings" => ui::settings_page(&settings, Some("~/.keyward/agent.sock"), "Host *\n  IdentityAgent ~/.keyward/agent.sock\n", 3, 1, 1),
                r => {
                    let (h, port) = ui::host_of_route(r)?;
                    ui::host_page(&h, port, Some("ubuntu"), &ss, None)
                }
            };
            serde_json::to_value(page).ok()
        },
        act,
    );
    for (route, page) in record.views() {
        assert!(primaries(page) <= 1, "{route}: more than one main action");
    }
    let mut out = record.to_json();
    let places = declare(&report());
    places.check().unwrap();
    out["places"] = serde_json::to_value(&places).unwrap();
    // The routes the crawl does not reach by itself: the screens the places open.
    for p in &places.places {
        if let Some(route) = &p.screen {
            if let Some((h, port)) = ui::host_of_route(route) {
                out["views"][route] = serde_json::to_value(ui::host_page(&h, port, Some("ubuntu"), &ss, None)).unwrap();
            }
        }
    }
    out["views"]["keys"] = serde_json::to_value(ui::routes_page(&keys())).unwrap();
    out["views"]["settings"] = serde_json::to_value(ui::settings_page(&settings, Some("~/.keyward/agent.sock"), "Host *\n  IdentityAgent ~/.keyward/agent.sock\n", 3, 1, 1)).unwrap();

    let mut said = std::collections::BTreeSet::new();
    words(&out, &mut said);
    for part in include_str!("ui.rs").split('"').skip(1).step_by(2) {
        if ["ssh.", "term.", "routes.", "settings.ssh", "plugin.ssh"].iter().any(|p| part.starts_with(p)) && !part.contains(' ') {
            said.insert(part.to_string());
        }
    }
    for (lang, file) in [("en", include_str!("../i18n/en.json")), ("ru", include_str!("../i18n/ru.json"))] {
        let w: std::collections::BTreeMap<String, Value> = serde_json::from_str(file).unwrap();
        let missing: Vec<&String> = said.iter().filter(|k| !w.contains_key(k.as_str())).collect();
        assert!(missing.is_empty(), "{lang}.json lacks {missing:?}");
    }
    if let Some(dir) = std::env::var_os("KEYWARD_STAND_OUT") {
        out["manifest"] = serde_json::to_value(keyward_plugin::Plugin::manifest(&crate::SshPlugin::new())).unwrap();
        std::fs::write(std::path::Path::new(&dir).join("ssh.json"), serde_json::to_vec_pretty(&out).unwrap()).unwrap();
    }
}
