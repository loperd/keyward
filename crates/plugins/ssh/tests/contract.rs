//! The ssh plugin against a host that refuses it exactly as the daemon does.
//!
//! The agent works from the daemon's items and its own `kw-` fields; a private
//! key is signed with by the core and never handed over. None of its
//! operations or events may reach for a field it does not own.

use std::sync::Once;

use keyward_plugin::testing::StrictHost;
use keyward_plugin::{HostEvent, Plugin};
use keyward_plugin_ssh::SshPlugin;
use serde_json::{json, Value};

const OPS: &[&str] = &["keys", "inspect_key", "set_hosts", "hosts", "resolve", "status", "settings", "set_settings", "snippet"];

/// The agent's sockets go under `KEYWARD_HOME`: a test must not open or remove
/// the real ones in `~/.keyward`. Short, because a socket's path has a length
/// limit.
fn sandbox() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let dir = format!("/tmp/kw-ssh-{}", std::process::id());
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("KEYWARD_HOME", dir);
    });
}

fn vault() -> StrictHost {
    StrictHost::new()
        .item("k1", "gitlab key", &[("kw-host", "gitlab.example.com", false), ("notes of mine", "private", true)])
        .item("k2", "unbound key", &[("kw-confirm", "true", false)])
}

const KEY: &str = include_str!("../../../sshkey/tests/fixtures/ssh/ed25519");

fn payload() -> Value {
    json!({
        "entry_id": "k1",
        "hosts": "gitlab.example.com, *.corp",
        "host": "gitlab.example.com",
        "user": "git",
        "port": 22,
        "private_key": KEY,
    })
}

#[tokio::test]
async fn no_operation_reaches_for_a_foreign_field() {
    sandbox();
    for op in OPS {
        let host = vault();
        let plugin = SshPlugin::new();
        let _ = plugin.call(&host, op, payload()).await;
        let _ = plugin.call(&host, op, Value::Null).await;
        assert!(host.refused().is_empty(), "`{op}` reached for foreign fields: {:?}", host.refused());
    }
}

#[tokio::test]
async fn events_reach_for_nothing_foreign() {
    sandbox();
    let host = vault();
    let plugin = SshPlugin::new();
    for event in [HostEvent::Unlocked, HostEvent::EntriesChanged, HostEvent::Tick, HostEvent::Locked] {
        plugin.on_event(&host, event).await;
    }
    assert!(host.refused().is_empty(), "the events reached for foreign fields: {:?}", host.refused());
}

#[tokio::test]
async fn inspecting_a_key_gives_back_only_its_public_half() {
    sandbox();
    let host = vault();
    let plugin = SshPlugin::new();
    let out = plugin.call(&host, "inspect_key", json!({ "private_key": KEY })).await.unwrap();
    let text = out.to_string();
    assert!(text.contains("SHA256:"), "a fingerprint: {text}");
    assert!(!text.contains("PRIVATE KEY"), "the private key must not come back: {text}");
}
