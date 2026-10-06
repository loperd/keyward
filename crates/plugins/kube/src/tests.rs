use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use keyward_plugin::testing::StrictHost;
use keyward_plugin::{Host, Plugin};
use serde_json::{json, Value};

use super::*;
use detect::Access;

const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ";

/// Every `fault!("err.…")` a source tree can raise.
fn raised(dir: &Path, into: &mut BTreeSet<String>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            raised(&path, into);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let text = std::fs::read_to_string(&path).unwrap();
            for part in text.split("fault!(\"").skip(1) {
                let key = part.split('"').next().unwrap();
                // A key picked at run time is spelled out where it is picked.
                if key.strip_prefix("err.").is_some_and(|k| !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric())) {
                    into.insert(key.to_string());
                }
            }
        }
    }
}

#[test]
fn every_word_this_plugin_can_say_is_in_its_own_dictionaries() {
    // The ssh plugin may not be installed: the words of the library it shares
    // with it have to travel with this one too.
    let here = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut keys = BTreeSet::new();
    raised(&here.join("src"), &mut keys);
    raised(&here.join("../../ssh-client/src"), &mut keys);
    keys.insert("plugin.kube.description".to_string());
    for lang in ["en", "ru"] {
        let read = |p: std::path::PathBuf| -> Value { serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap() };
        let dict = read(here.join(format!("i18n/{lang}.json")));
        // The core's words are always there.
        let core = read(here.join(format!("../../../i18n/{lang}.json")));
        let missing: Vec<&String> = keys.iter().filter(|k| dict.get(k.as_str()).is_none() && core.get(k.as_str()).is_none()).collect();
        assert!(missing.is_empty(), "{lang}.json lacks {missing:?}");
    }
}

#[test]
fn the_manifest_is_the_package_s() {
    let here = Path::new(env!("CARGO_MANIFEST_DIR"));
    let package: Value = serde_json::from_str(&std::fs::read_to_string(here.join("plugin.json")).unwrap()).unwrap();
    let m = KubePlugin::new().manifest();
    assert_eq!(package["id"], m.id);
    assert_eq!(package["icon"], m.icon);
    let perms: Vec<String> = m.permissions.iter().map(|p| p.name().to_string()).collect();
    assert_eq!(package["permissions"], json!(perms));
}

#[test]
fn a_cluster_is_named_by_where_it_lives() {
    assert_eq!(
        ClusterId::parse("ssh|k1|db.example.com|2222|k3s").unwrap(),
        ClusterId::Remote { place: Place { entry_id: "k1".into(), host: "db.example.com".into(), port: 2222 }, kind: detect::Kind::K3s }
    );
    assert_eq!(ClusterId::parse("note|n1").unwrap(), ClusterId::Note { entry_id: "n1".into() });
    for bad in ["", "ssh|k1|h|x|k3s", "ssh|k1|h|22|openshift", "cloud|eks", "local|minikube", "note|"] {
        assert!(ClusterId::parse(bad).is_err(), "{bad}");
    }
}

#[tokio::test]
async fn the_overview_lists_the_servers_the_keys_reach_and_what_was_seen_there() {
    let host = Arc::new(
        StrictHost::new().item("k1", "Deploy", &[("kw-host", "root@db.example.com, *.lab", false)]),
    );
    // The strict host keeps no public keys; the plugin reads the items as
    // the core gives them.
    let p = KubePlugin::new();
    let core: Arc<dyn Host> = host.clone();
    p.attach(Arc::clone(&core));

    let mut r = Remembered::default();
    r.set(
        Place { entry_id: "k1".into(), host: "db.example.com".into(), port: 22 },
        Look::Seen { found: vec![Found { kind: detect::Kind::K3s, access: Access::Sudo }], at: 1, machine: None, peer: None },
    );
    r.write(core.as_ref()).unwrap();
    let v = p.call(core.as_ref(), "overview", Value::Null).await.unwrap();
    assert_eq!(v["scanning"], false);
    // Without a public half there is nothing to log in with, so no server.
    assert_eq!(v["servers"], json!([]));
    assert!(host.refused().is_empty());
}

#[tokio::test]
async fn a_request_that_does_not_open_is_refused_and_a_lock_forgets_the_links() {
    use keyward_ssh_client::link::testing::Page;
    let host = StrictHost::new();
    let p = KubePlugin::new();
    let page = Page::new();
    let linked = p.call(&host, "ui_link", json!({ "public": page.hello })).await.unwrap();
    let (mut input, _) = page.finish(linked["public"].as_str().unwrap());
    let link = linked["link"].as_str().unwrap().to_string();

    let sealed = input.seal(br#"{"kind":"act","op":"state","payload":{"cluster":"note|x"}}"#);
    let answer = p.call(&host, "ui", json!({ "link": link, "lane": "input", "sealed": sealed })).await.unwrap();
    let opened: Value = serde_json::from_slice(&input.open(answer["sealed"].as_str().unwrap())).unwrap();
    assert_eq!(opened["data"]["state"], "closed");

    assert!(p.call(&host, "ui", json!({ "link": link, "lane": "input", "sealed": "Zm9yZ2Vk" })).await.is_err());

    p.on_event(&host, HostEvent::Locked).await;
    let sealed = input.seal(br#"{"kind":"act","op":"state","payload":{"cluster":"note|x"}}"#);
    assert!(p.call(&host, "ui", json!({ "link": link, "lane": "input", "sealed": sealed })).await.is_err());
    let _ = KEY;
}

fn row(host: &str, look: Option<Look>) -> ServerRow {
    ServerRow {
        machine: keyward_ssh_client::targets::Machine {
            entry_id: "k".into(),
            entry_name: "K".into(),
            host: host.into(),
            address: host.into(),
            port: 29012,
            user: Some("root".into()),
            pin: None,
            proxy: None,
            missing: Vec::new(),
        },
        look,
        looking: false,
        aliases: Vec::new(),
    }
}

#[test]
fn one_machine_under_two_names_is_one_row_and_two_machines_stay_two() {
    let seen = |machine: &str, peer: &str| Some(Look::Seen { found: Vec::new(), at: 1, machine: Some(machine.into()), peer: Some(peer.into()) });
    let unknown = |peer: &str| Some(Look::HostUnknown { fingerprint: "SHA256:x".into(), algorithm: "ssh-ed25519".into(), at: 1, peer: Some(peer.into()) });
    let rows = merge(vec![
        row("51.83.4.43", seen("aa", "51.83.4.43:29012")),
        // The same machine by name, its key not trusted yet: the address joins it.
        row("ns3153822.ip-51-83-4.eu", unknown("51.83.4.43:29012")),
        row("vps.example", seen("bb", "10.0.0.2:29012")),
        // Another name, the same machine id behind another address.
        row("vps-internal", seen("bb", "192.168.1.2:29012")),
        row("never-looked", None),
    ]);
    let got: Vec<(&str, Vec<String>)> = rows.iter().map(|r| (r.machine.host.as_str(), r.aliases.clone())).collect();
    assert_eq!(
        got,
        vec![
            ("51.83.4.43", vec!["ns3153822.ip-51-83-4.eu".to_string()]),
            ("vps.example", vec!["vps-internal".to_string()]),
            ("never-looked", vec![]),
        ]
    );
    assert!(matches!(rows[0].look, Some(Look::Seen { .. })), "the look that says most stands for the machine");
}

#[test]
fn looks_of_an_older_format_are_dropped_not_misread() {
    let old = json!({ "looks": [[{ "entry_id": "k", "host": "h", "port": 22 }, { "status": "seen", "found": [{ "kind": "kubeconfig", "access": "readable" }], "at": 1 }]] });
    assert!(Remembered::from(old).unwrap().looks.is_empty());
    let mut r = Remembered::default();
    r.set(Place { entry_id: "k".into(), host: "h".into(), port: 22 }, Look::CommandOnly { at: 1, peer: None });
    let host = StrictHost::new();
    r.write(&host).unwrap();
    assert_eq!(Remembered::read(&host).unwrap().looks.len(), 1, "the current format reads back");
}
