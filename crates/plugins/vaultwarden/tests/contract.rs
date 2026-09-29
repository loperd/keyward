//! The Vaultwarden admin plugin against a host that refuses it exactly as the
//! daemon does. Its token lives in the keychain and nowhere else: whatever it
//! is asked, it neither reads a vault field nor writes an item.

use keyward_plugin::testing::StrictHost;
use keyward_plugin::Plugin;
use keyward_plugin_vaultwarden::VaultwardenPlugin;
use serde_json::{json, Value};

const OPS: &[&str] = &[
    "available", "status", "unlock", "forget", "users", "invite", "user_action", "set_org_role", "orgs",
    "delete_org", "settings", "save_settings", "reset_settings", "backup_db", "test_smtp",
];

/// An account on a closed local port: every request fails at once, which is
/// all this needs. A person's own item lies in the vault, to be left alone.
fn vault() -> StrictHost {
    StrictHost::new()
        .server("https://127.0.0.1:1")
        .keychain("admin-token", "token")
        .item("mine", "A person's note", &[("admin password", "their own", true)])
}

fn payload() -> Value {
    json!({ "token": "token", "email": "a@example.com", "user_id": "u1", "org_id": "o1", "action": "disable", "role": "user", "changes": { "smtp_port": 25 } })
}

#[tokio::test]
async fn the_panel_is_the_accounts_server_and_the_vault_is_left_alone() {
    let host = vault();
    let plugin = VaultwardenPlugin::new();
    let status = plugin.call(&host, "status", Value::Null).await.unwrap();
    assert_eq!(status, json!({ "panel": "https://127.0.0.1:1/admin", "unlocked": true }));
    for op in OPS {
        let host = vault();
        let _ = plugin.call(&host, op, payload()).await;
        let _ = plugin.call(&host, op, Value::Null).await;
        assert!(host.refused().is_empty(), "`{op}` reached for vault fields: {:?}", host.refused());
        assert_eq!(host.field("mine", "admin password").as_deref(), Some("their own"), "`{op}` touched a person's item");
    }
}
