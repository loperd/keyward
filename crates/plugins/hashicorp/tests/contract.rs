//! The Vault plugin against a host that refuses it exactly as the daemon does.
//!
//! These guard what broke once already: the plugin read the unseal shares from
//! fields a person had named, the daemon began refusing that, and the section
//! said "Vault is not connected". Whatever the plugin does of its own accord —
//! any operation, the minute tick — it must find its connection by its own
//! `kw-` fields and never reach for anybody else's.

use keyward_plugin::testing::StrictHost;
use keyward_plugin::{HostEvent, Plugin};
use keyward_plugin_hashicorp::HashicorpPlugin;
use serde_json::{json, Value};

/// Every operation the plugin answers; a new one belongs here too.
const OPS: &[&str] = &[
    "settings", "set_settings", "connections", "status", "connect", "select", "forget", "health", "seal_status",
    "unseal", "probe", "generate_root", "root_tokens", "revoke_root", "issue", "issues", "revoke", "policies",
    "policy", "put_policy", "delete_policy", "ensure_policy_admin", "mounts", "auth_mounts", "mount_enable",
    "mount_disable", "mount_tune", "kv_config", "kv_config_write", "secret_list", "secret_read", "secret_read_full", "secret_value", "secret_copy", "secret_rollback", "secret_write",
    "secret_delete", "secret_undelete", "secret_destroy", "secret_meta", "secret_meta_write",
];

/// A connection as a person makes one: the address in the plugin's own field,
/// the shares of the unseal key in fields they named themselves.
///
/// The address is a closed local port: every request to the server fails at
/// once, which is all a sweep needs — it is about what the plugin reads here,
/// not what the server says.
fn vault() -> StrictHost {
    StrictHost::new().item(
        "conn",
        "Vault prod",
        &[
            ("kw-vault-addr", "https://127.0.0.1:1", false),
            ("kw-vault-unseal-fields", "unseal 1, unseal 2", false),
            ("unseal 1", "share-one", true),
            ("unseal 2", "share-two", true),
            ("root token", "a person's own note", true),
        ],
    )
}

/// One payload that every operation can take what it needs from.
fn payload() -> Value {
    json!({
        "entry_id": "conn",
        "addr": "https://127.0.0.1:1",
        "fields": ["unseal 1", "unseal 2"],
        "shares": ["share-one", "share-two"],
        "name": "kw-test",
        "mount": "secret",
        "path": "app/db",
        "version": 1,
        "permanent": false,
        "accessor": "acc",
        "policy": "path \"secret/*\" { capabilities = [\"read\"] }",
        "form": { "name": "", "entry_id": "conn", "addr": "https://127.0.0.1:1", "unseal_fields": ["unseal 1"] },
        "request": { "recipient": "me", "ttl": 30, "uses": 0, "wrap": false, "policies": ["default"] },
    })
}

#[tokio::test]
async fn the_connection_is_found_by_its_own_fields_alone() {
    let host = vault();
    let plugin = HashicorpPlugin::new();
    let link = plugin.call(&host, "status", Value::Null).await.expect("status answers");
    assert_eq!(link["entry_id"], "conn");
    assert_eq!(link["addr"], "https://127.0.0.1:1");
    // The window reads the shares by these names; the plugin does not.
    assert_eq!(link["unseal_fields"], json!(["unseal 1", "unseal 2"]));
    assert_eq!(link["unseal_keys"], 2);
    let all = plugin.call(&host, "connections", Value::Null).await.unwrap();
    assert_eq!(all.as_array().map(Vec::len), Some(1));
    assert!(host.refused().is_empty(), "reached for foreign fields: {:?}", host.refused());
}

#[tokio::test]
async fn no_operation_reaches_for_a_foreign_field() {
    for op in OPS {
        // A fresh vault for each: `forget` takes the connection away, and every
        // operation after it would have nothing to reach for.
        let host = vault();
        let plugin = HashicorpPlugin::new();
        // Errors are expected — the server is unreachable. A panic is not, and
        // a refusal is not.
        let _ = plugin.call(&host, op, payload()).await;
        let _ = plugin.call(&host, op, Value::Null).await;
        assert!(host.refused().is_empty(), "`{op}` reached for foreign fields: {:?}", host.refused());
    }
}

#[tokio::test]
async fn the_minute_tick_reaches_for_nothing_foreign() {
    // This is what filled the daemon's log with refusals once a minute.
    let host = vault();
    let plugin = HashicorpPlugin::new();
    for event in [HostEvent::Unlocked, HostEvent::EntriesChanged, HostEvent::Tick, HostEvent::Locked] {
        plugin.on_event(&host, event).await;
    }
    assert!(host.refused().is_empty(), "the events reached for foreign fields: {:?}", host.refused());
}
