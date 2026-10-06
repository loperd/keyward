//! A look at a real ssh server: the host key stops it before anything is
//! signed, a yes to exactly that fingerprint lets it in, and what the script
//! found lands in the overview.

mod common;

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use common::{core, serve, settle, sandbox, user_public, Answers};
use keyward_plugin::{Host, Plugin};
use keyward_plugin_kube::KubePlugin;
use serde_json::{json, Value};

#[tokio::test(flavor = "multi_thread")]
async fn a_look_stops_at_an_unknown_host_trusts_exactly_its_fingerprint_and_finds_k3s() {
    let home = sandbox("scan");
    let ran = Arc::new(Mutex::new(Vec::new()));
    // A server with k3s behind sudo, after a banner a shell's rc file might
    // print.
    let answers: Answers = Arc::new(|command: &str| {
        if command.contains("kw_check") { (b"Welcome!\nkw-kube k3s sudo\nkw-kube-done\n".to_vec(), 0) } else { (b"unexpected\n".to_vec(), 127) }
    });
    let port = serve(user_public(), Arc::clone(&ran), answers).await;
    let core = core(&home, port);
    let p = KubePlugin::new();
    p.attach(core.clone());

    let o = p.call(core.as_ref(), "overview", Value::Null).await.unwrap();
    assert_eq!(o["servers"][0]["host"], "127.0.0.1");
    assert_eq!(o["servers"][0]["look"], Value::Null);

    // Nobody vouched for the host: the look stops at its key.
    p.call(core.as_ref(), "scan", Value::Null).await.unwrap();
    let o = settle(&p, &core).await;
    let look = &o["servers"][0]["look"];
    assert_eq!(look["status"], "host_unknown", "{o}");
    let fingerprint = look["fingerprint"].as_str().unwrap().to_string();
    assert_eq!(core.signed.load(Ordering::SeqCst), 0, "nothing is signed for a host nobody trusts");

    // A yes to another fingerprint lets nothing in.
    let place = json!({ "entry_id": "key-1", "host": "127.0.0.1", "port": port });
    p.call(core.as_ref(), "scan", json!({ "only": place, "trust": "SHA256:someone-else" })).await.unwrap();
    let o = settle(&p, &core).await;
    assert_eq!(o["servers"][0]["look"]["status"], "host_unknown", "{o}");
    assert_eq!(core.signed.load(Ordering::SeqCst), 0);

    // A yes to exactly that one: in, the script runs, k3s behind sudo.
    p.call(core.as_ref(), "scan", json!({ "only": place, "trust": fingerprint })).await.unwrap();
    let o = settle(&p, &core).await;
    let look = &o["servers"][0]["look"];
    assert_eq!(look["status"], "seen", "{o}");
    assert_eq!(look["found"], json!([{ "kind": "k3s", "access": "sudo" }]));
    assert_eq!(core.signed.load(Ordering::SeqCst), 1, "one look, one signature");
    let known = core.entries()[0].field("kw-knownhosts").map(str::to_string).unwrap_or_default();
    assert!(known.starts_with(&format!("[127.0.0.1]:{port} ssh-ed25519 ")), "trusted in the item: {known:?}");
    assert_eq!(ran.lock().unwrap().len(), 1, "the script, and nothing else, ran on the server");

    // The host is known now: the next look asks nobody.
    p.call(core.as_ref(), "scan", Value::Null).await.unwrap();
    let o = settle(&p, &core).await;
    assert_eq!(o["servers"][0]["look"]["status"], "seen");
    assert_eq!(core.signed.load(Ordering::SeqCst), 2);

    // What was found survives the plugin: it is in its settings.
    let again = KubePlugin::new();
    let o = again.call(core.as_ref(), "overview", Value::Null).await.unwrap();
    assert_eq!(o["servers"][0]["look"]["found"][0]["kind"], "k3s");
    let _ = std::fs::remove_dir_all(&home);
}
