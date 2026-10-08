//! The HashiCorp Vault plugin: a broker for temporary access.
//!
//! This has nothing to do with storing passwords, so it has no place in the
//! core. The core knows exactly two things about the plugin: its card
//! (`Manifest`) and one envelope, `call(op, payload)`. Everything else —
//! connections, the ledger of issues, policies, engines, secrets — lives here.
//!
//! The plugin keeps no state of its own on disk: the connections and the ledger
//! lie as vault items (`store`), and the chosen connection lies in the plugin's
//! settings, which the core keeps.

pub mod api;
pub mod broker;
pub mod link;
pub mod model;
mod store;
pub mod ui;
#[cfg(test)]
mod stand;

use std::collections::BTreeMap;
use std::collections::HashSet;
use std::sync::Mutex;

use keyward_plugin::{arg, out, Host, HostEvent, Manifest, Origin, Permission, Plugin, Result};
use serde::Deserialize;
use serde_json::Value;

use crate::model::{
    IssueRequest, KvConfig, MountForm, MountTune, SecretMetaPatch, POLICY_ADMIN, POLICY_ADMIN_RULES,
};

/// What a person has already been told. The same "the access is expiring"
/// every minute is not care but noise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Stage {
    Soon,
    Gone,
}

#[derive(Default)]
pub struct HashicorpPlugin {
    notified: Mutex<HashSet<(String, Stage)>>,
    /// The sealed road to the window's declared screens (ui.rs).
    ui: keyward_ui::UiServer,
}

impl HashicorpPlugin {
    pub fn new() -> Self {
        Self::default()
    }

    /// Notifications about the deadlines of issued tokens.
    ///
    /// The point of a broker is short access, and a person has to learn that
    /// it is about to run out without looking into the application: an agent
    /// given a five-minute token usually works with no window on the screen.
    async fn notify_expiring(&self, host: &dyn Host) {
        if !store::expiry_notices(host) {
            return;
        }
        let now = api::now_secs();
        for issued in broker::all(host).await {
            if issued.state != model::IssueState::Active {
                continue;
            }
            let left = issued.remaining(now);
            // Two events per token: "running out soon" and "run out".
            let stage = if left <= 0 {
                Stage::Gone
            } else if left <= 120 {
                Stage::Soon
            } else {
                continue;
            };

            {
                let mut seen = self.notified.lock().unwrap();
                if !seen.insert((issued.accessor.clone(), stage)) {
                    continue;
                }
            }

            let what = issued.policies.join(", ");
            let body = match stage {
                Stage::Soon => model::key(
                    "notice.leaseSoon",
                    &[("what", &what), ("minutes", &left.div_euclid(60).max(1).to_string())],
                ),
                Stage::Gone => model::key("notice.leaseGone", &[("what", &what)]),
            };
            host.notice("keyward", &body);
        }
    }

    /// The minute tick: what the daemon itself used to do.
    async fn tick(&self, host: &dyn Host) {
        if !host.unlocked() {
            // With the vault locked the ledger is out of sight, and rightly
            // so.
            return;
        }
        // The notifications come first: `refresh_expired` will mark what has
        // expired as expired, and then we would say nothing about it — a person
        // learns "the access has run out" only from whoever managed to see it
        // still active.
        self.notify_expiring(host).await;
        let _ = broker::refresh_expired(host).await;
        if let Err(e) = broker::sweep_policy_admin(host).await {
            tracing::debug!(error = %e, "the check of the keyward-policy-admin policy failed");
        }
    }
}

#[async_trait::async_trait]
impl Plugin for HashicorpPlugin {
    fn manifest(&self) -> Manifest {
        Manifest {
            id: "hashicorp".into(),
            title: "HashiCorp Vault".into(),
            icon: "vault".into(),
            section: true,
            // Everything here starts with a vault item: with the vault locked
            // there is nothing to show.
            needs_unlocked: true,
            // A built-in plugin has the application's version: it is the
            // application.
            version: env!("CARGO_PKG_VERSION").into(),
            // The key, not the words: the showcase and the card are drawn by
            // the window, which knows its own language.
            description: "plugin.hashicorp.description".into(),
            origin: Origin::Builtin,
            // The card's initial state; whether the plugin is on is the
            // daemon's register's business.
            enabled: true,
            // The connections and the ledger are vault items (`tagged_items`,
            // `create_note`, `set_fields`), the root token is read with
            // `secret`, the deadlines go out as notifications, and Vault itself
            // is on the network.
            permissions: vec![
                Permission::Entries,
                Permission::Items,
                Permission::ItemsWrite,
                Permission::Secrets,
                Permission::Notices,
                Permission::Network,
                // A secret's value is copied by the plugin, not the window.
                Permission::Clipboard,
            ],
            probe: false,
            declared: true,
            places: true,
        }
    }

    async fn call(&self, host: &dyn Host, op: &str, payload: Value) -> Result<Value> {
        match op {
            "ui_link" | "ui" => match self.ui.call(self, host, op, payload).await {
                Some(answer) => answer,
                None => anyhow::bail!("the hashicorp plugin's sealed road does not know \"{op}\""),
            },
            // What the daemon filled in with an item's fields comes here, past
            // the sealed road, and answers as it does.
            "ui_unseal" | "ui_generate_root" => self.filled(host, op, payload).await,
            _ => dispatch(host, op, payload).await,
        }
    }

    async fn on_event(&self, host: &dyn Host, event: HostEvent) {
        match event {
            HostEvent::Tick => self.tick(host).await,
            // The links to the window were made while the vault was open.
            HostEvent::Locked => self.ui.lock(),
            _ => {}
        }
    }
}

// -- unpacking the envelope ------------------------------------------------
//
// The field names are the ones the `Request` variants had in the protocol: the
// plugin moved, and the interface must not have to change its requests over
// it.

#[derive(Deserialize)]
struct EntryArg {
    entry_id: String,
}

#[derive(Deserialize)]
struct FormArg {
    form: link::Form,
}

#[derive(Deserialize)]
struct AddrArg {
    addr: String,
}

#[derive(Deserialize)]
struct RootArg {
    entry_id: String,
    #[serde(default)]
    fields: Vec<String>,
    /// The shares' values, read by the window: see `broker::unseal`.
    #[serde(default)]
    shares: Vec<String>,
}

#[derive(Deserialize, Default)]
struct SharesArg {
    #[serde(default)]
    shares: Vec<String>,
}

#[derive(Deserialize)]
struct IssueArg {
    request: IssueRequest,
}

#[derive(Deserialize)]
struct AccessorArg {
    accessor: String,
}

#[derive(Deserialize)]
struct NameArg {
    name: String,
}

#[derive(Deserialize)]
struct PutPolicyArg {
    name: String,
    rules: String,
}

#[derive(Deserialize)]
struct MountFormArg {
    form: MountForm,
}

#[derive(Deserialize)]
struct MountPathArg {
    path: String,
    #[serde(default)]
    auth: bool,
}

#[derive(Deserialize)]
struct MountTuneArg {
    path: String,
    #[serde(default)]
    auth: bool,
    tune: MountTune,
}

#[derive(Deserialize)]
struct MountArg {
    mount: String,
}

#[derive(Deserialize)]
struct KvConfigArg {
    mount: String,
    config: KvConfig,
}

#[derive(Deserialize)]
struct PathArg {
    mount: String,
    #[serde(default)]
    path: String,
}

#[derive(Deserialize)]
struct ReadArg {
    mount: String,
    path: String,
    #[serde(default)]
    version: Option<u64>,
}

#[derive(Deserialize)]
struct ValueArg {
    mount: String,
    path: String,
    #[serde(default)]
    version: Option<u64>,
    key: String,
}

#[derive(Deserialize)]
struct RollbackArg {
    mount: String,
    path: String,
    version: u64,
    #[serde(default)]
    cas: Option<u64>,
}

#[derive(Deserialize)]
struct WriteArg {
    mount: String,
    path: String,
    data: BTreeMap<String, String>,
    /// Check-and-set: without it a parallel edit silently writes over
    /// somebody else's.
    #[serde(default)]
    cas: Option<u64>,
}

#[derive(Deserialize)]
struct DeleteArg {
    mount: String,
    path: String,
    #[serde(default)]
    permanent: bool,
}

#[derive(Deserialize)]
struct VersionArg {
    mount: String,
    path: String,
    version: u64,
}

#[derive(Deserialize)]
struct MetaWriteArg {
    mount: String,
    path: String,
    patch: SecretMetaPatch,
}

/// The engines after an edit: auth methods have a list of their own, and what
/// has to be shown after mounting is the list it was mounted into.
async fn mount_list(host: &dyn Host, auth: bool) -> Result<Value> {
    if auth {
        out(broker::auth_mounts(host).await?)
    } else {
        out(broker::mounts(host).await?)
    }
}

async fn dispatch(host: &dyn Host, op: &str, payload: Value) -> Result<Value> {
    match op {
        // -- the plugin's own settings --
        "settings" => Ok(store::settings(host)),
        "set_settings" => {
            store::set_settings(host, payload)?;
            Ok(store::settings(host))
        }

        // -- connections --
        "connections" => out(store::connections(host).await),
        "status" => out(store::connection(host).await),
        "connect" => {
            let a: FormArg = arg(payload)?;
            store::connect(host, &a.form).await?;
            out(store::connection(host).await)
        }
        "select" => {
            let a: EntryArg = arg(payload)?;
            store::set_active(host, &a.entry_id)?;
            out(store::connection(host).await)
        }
        "forget" => {
            let a: EntryArg = arg(payload)?;
            store::forget(host, &a.entry_id).await?;
            out(store::connection(host).await)
        }

        // -- the server's state --
        "health" => out(broker::health(host).await?),
        "seal_status" => out(broker::seal_status(host).await?),
        "unseal" => {
            // No payload at all is an old window: it sends no shares.
            let a: SharesArg = if payload.is_null() { SharesArg::default() } else { arg(payload)? };
            out(broker::unseal(host, &a.shares).await?)
        }
        "probe" => {
            let a: AddrArg = arg(payload)?;
            out(broker::probe(&a.addr).await?)
        }

        // -- the root token --
        "generate_root" => {
            let a: RootArg = arg(payload)?;
            out(broker::generate_root(host, &a.entry_id, &a.fields, &a.shares).await?)
        }
        "root_tokens" => out(broker::root_tokens(host).await?),
        "revoke_root" => {
            let a: AddrArg = arg(payload)?;
            broker::revoke_root(host, &a.addr).await?;
            out(broker::root_tokens(host).await?)
        }

        // -- issues --
        "issue" => {
            let a: IssueArg = arg(payload)?;
            out(broker::issue(host, &a.request).await?)
        }
        "issues" => out(broker::refresh_expired(host).await),
        "revoke" => {
            let a: AccessorArg = arg(payload)?;
            broker::revoke(host, &a.accessor).await?;
            out(broker::refresh_expired(host).await)
        }

        // -- policies --
        "policies" => out(broker::policies(host).await?),
        "policy" => {
            let a: NameArg = arg(payload)?;
            out(broker::policy(host, &a.name).await?)
        }
        "put_policy" => {
            let a: PutPolicyArg = arg(payload)?;
            broker::put_policy(host, &a.name, &a.rules).await?;
            out(broker::policies(host).await?)
        }
        "delete_policy" => {
            let a: NameArg = arg(payload)?;
            broker::delete_policy(host, &a.name).await?;
            out(broker::policies(host).await?)
        }
        "ensure_policy_admin" => {
            // The body is written whole every time: if the policy was edited
            // by hand it returns to its canonical form.
            broker::put_policy(host, POLICY_ADMIN, POLICY_ADMIN_RULES).await?;
            out(broker::policies(host).await?)
        }

        // -- engines --
        "mounts" => out(broker::mounts(host).await?),
        "auth_mounts" => out(broker::auth_mounts(host).await?),
        "mount_enable" => {
            let a: MountFormArg = arg(payload)?;
            let auth = a.form.auth;
            broker::mount_enable(host, &a.form).await?;
            mount_list(host, auth).await
        }
        "mount_disable" => {
            let a: MountPathArg = arg(payload)?;
            broker::mount_disable(host, &a.path, a.auth).await?;
            mount_list(host, a.auth).await
        }
        "mount_tune" => {
            let a: MountTuneArg = arg(payload)?;
            broker::mount_tune(host, &a.path, a.auth, &a.tune).await?;
            mount_list(host, a.auth).await
        }
        "kv_config" => {
            let a: MountArg = arg(payload)?;
            out(broker::kv_config(host, &a.mount).await?)
        }
        "kv_config_write" => {
            let a: KvConfigArg = arg(payload)?;
            broker::kv_config_write(host, &a.mount, &a.config).await?;
            out(broker::kv_config(host, &a.mount).await?)
        }

        // -- secrets --
        "secret_list" => {
            let a: PathArg = arg(payload)?;
            out(broker::secret_list(host, &a.mount, &a.path).await?)
        }
        // The window is given the keys and the lengths, never the values: a
        // value is fetched on "show", one at a time, or copied here.
        "secret_read" => {
            let a: ReadArg = arg(payload)?;
            out(broker::secret_read(host, &a.mount, &a.path, a.version).await?.view())
        }
        // Every value, for the editor alone: a person is changing them.
        "secret_read_full" => {
            let a: ReadArg = arg(payload)?;
            out(broker::secret_read(host, &a.mount, &a.path, a.version).await?)
        }
        "secret_value" => {
            let a: ValueArg = arg(payload)?;
            let s = broker::secret_read(host, &a.mount, &a.path, a.version).await?;
            let v = s.data.get(&a.key).cloned().ok_or_else(|| anyhow::anyhow!("err.secretNoKey"))?;
            out(v)
        }
        // Copied by the plugin, through the core: the value goes from Vault
        // to the clipboard without passing the window.
        "secret_copy" => {
            let a: ValueArg = arg(payload)?;
            let s = broker::secret_read(host, &a.mount, &a.path, a.version).await?;
            let v = s.data.get(&a.key).ok_or_else(|| anyhow::anyhow!("err.secretNoKey"))?;
            out(host.copy_text(v).await?)
        }
        // A rollback is a new version with an old one's data, made here: the
        // old values do not travel to the window and back.
        "secret_rollback" => {
            let a: RollbackArg = arg(payload)?;
            let old = broker::secret_read(host, &a.mount, &a.path, Some(a.version)).await?;
            broker::secret_write(host, &a.mount, &a.path, &old.data, a.cas).await?;
            out(broker::secret_read(host, &a.mount, &a.path, None).await?.view())
        }
        "secret_write" => {
            let a: WriteArg = arg(payload)?;
            broker::secret_write(host, &a.mount, &a.path, &a.data, a.cas).await?;
            // Read back: in kv v2 the version changes after a write, and what
            // has to be shown is what is on the server rather than what was
            // sent.
            out(broker::secret_read(host, &a.mount, &a.path, None).await?.view())
        }
        "secret_delete" => {
            let a: DeleteArg = arg(payload)?;
            broker::secret_delete(host, &a.mount, &a.path, a.permanent).await?;
            // The answer is the contents of the folder the secret lay in: the
            // interface would re-read it anyway.
            out(broker::secret_list(host, &a.mount, &broker::parent_of(&a.path)).await?)
        }
        "secret_undelete" => {
            let a: VersionArg = arg(payload)?;
            broker::secret_undelete(host, &a.mount, &a.path, a.version).await?;
            out(broker::secret_meta(host, &a.mount, &a.path).await?)
        }
        "secret_destroy" => {
            let a: VersionArg = arg(payload)?;
            broker::secret_destroy(host, &a.mount, &a.path, a.version).await?;
            out(broker::secret_meta(host, &a.mount, &a.path).await?)
        }
        "secret_meta" => {
            let a: PathArg = arg(payload)?;
            out(broker::secret_meta(host, &a.mount, &a.path).await?)
        }
        "secret_meta_write" => {
            let a: MetaWriteArg = arg(payload)?;
            broker::secret_meta_write(host, &a.mount, &a.path, &a.patch).await?;
            out(broker::secret_meta(host, &a.mount, &a.path).await?)
        }

        // The operation is named aloud: an "unknown operation" error without
        // it tells nothing to a person nor to whoever is mending the
        // interface.
        other => anyhow::bail!("the hashicorp plugin does not know the operation \"{other}\""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::testing::Fake;
    use serde_json::json;

    fn vault() -> Fake {
        Fake::with(vec![
            Fake::item("b", "Prod", &[(store::ADDR, "https://vault.prod")]),
            Fake::item("a", "Dev", &[(store::ADDR, "https://vault.dev")]),
        ])
    }

    #[tokio::test]
    async fn an_unknown_operation_names_itself() {
        let e = dispatch(&Fake::default(), "give_me_root", Value::Null).await.unwrap_err();
        assert!(e.to_string().contains("give_me_root"), "the error does not name the operation: {e}");
    }

    #[tokio::test]
    async fn the_plugins_card_does_not_change() {
        let m = HashicorpPlugin::new().manifest();
        assert_eq!(m.id, "hashicorp");
        assert_eq!(m.icon, "vault");
        assert!(m.section && m.needs_unlocked);
    }


    /// The showcase promises what the plugin does.
    ///
    /// The daemon reads `plugin.json` and draws the card and asks for consent
    /// by it; the `Manifest` in the code is what the plugin actually is. If they
    /// differ, a person consents to the wrong thing. There is no version in the
    /// file on purpose: the package build puts it there out of `Cargo.toml`.
    #[test]
    fn the_package_manifest_matches_the_code() {
        let declared: Value = serde_json::from_str(include_str!("../plugin.json")).unwrap();
        let m = HashicorpPlugin::new().manifest();

        assert_eq!(declared["id"], Value::String(m.id.clone()), "the id differs");
        assert_eq!(declared["title"], Value::String(m.title.clone()), "the title differs");
        assert_eq!(declared["icon"], Value::String(m.icon.clone()), "the icon differs");
        assert_eq!(declared["description"], Value::String(m.description.clone()), "the description differs");
        assert_eq!(declared["section"], Value::Bool(m.section), "the section differs");
        assert_eq!(declared["needs_unlocked"], Value::Bool(m.needs_unlocked), "\"needs an open vault\" differs");
        assert_eq!(declared["exec"], "keyward-plugin-hashicorp", "the wrong program");
        assert!(declared.get("version").is_none(), "a version does not live in plugin.json: the package build puts it there");

        let mut promised: Vec<String> = declared["permissions"]
            .as_array()
            .expect("plugin.json has no permissions")
            .iter()
            .map(|p| p.as_str().unwrap_or_default().to_string())
            .collect();
        let mut real: Vec<String> = m
            .permissions
            .iter()
            .map(|p| serde_json::to_value(p).unwrap().as_str().unwrap().to_string())
            .collect();
        promised.sort();
        real.sort();
        assert_eq!(promised, real, "the showcase promises the wrong permissions");
    }

    #[tokio::test]
    async fn connections_and_the_choice_travel_in_one_envelope() {
        let host = vault();
        let links = dispatch(&host, "connections", Value::Null).await.unwrap();
        assert_eq!(links.as_array().unwrap().len(), 2);

        // The choice returns the same as `status`: the interface need not go
        // a second time to learn how it ended.
        let chosen = dispatch(&host, "select", json!({ "entry_id": "b" })).await.unwrap();
        assert_eq!(chosen["entry_id"], "b");
        assert_eq!(dispatch(&host, "status", Value::Null).await.unwrap(), chosen);
    }

    #[tokio::test]
    async fn a_foreign_envelope_is_an_error_not_a_panic() {
        let e = dispatch(&vault(), "select", json!({ "no": "fields" })).await.unwrap_err();
        assert!(e.to_string().contains("other than what it expected"), "{e}");
    }

    #[tokio::test]
    async fn a_forgotten_connection_leaves_the_list() {
        let host = vault();
        dispatch(&host, "forget", json!({ "entry_id": "a" })).await.unwrap();
        let links = dispatch(&host, "connections", Value::Null).await.unwrap();
        assert_eq!(links.as_array().unwrap().len(), 1);
        assert_eq!(links[0]["entry_id"], "b");
    }

    #[tokio::test]
    async fn a_deadline_is_mentioned_once() {
        let host = vault();
        let issued = model::Issued {
            accessor: "ac".into(),
            recipient: model::Recipient::Agent,
            policies: vec!["ro-dev".into()],
            ttl_seconds: 900,
            num_uses: 0,
            note: String::new(),
            // Running out in a minute counts as "soon".
            created_at: api::now_secs() + 60 - 900,
            wrapped: false,
            state: model::IssueState::Active,
        };
        store::store_issued(&host, "https://vault.dev", &serde_json::to_string(&[issued]).unwrap())
            .await
            .unwrap();

        let plugin = HashicorpPlugin::new();
        plugin.notify_expiring(&host).await;
        plugin.notify_expiring(&host).await;
        let notices = host.notices.lock().unwrap();
        assert_eq!(notices.len(), 1, "the same thing every minute is noise");
        assert!(notices[0].1.contains("notice.leaseSoon"), "{:?}", notices[0]);
    }

    #[tokio::test]
    async fn settings_are_readable_and_writable() {
        // The settings screen asks the plugin for them: the core no longer has
        // those fields.
        let host = store::testing::Fake::default();
        let p = HashicorpPlugin::new();
        let got = p.call(&host, "settings", Value::Null).await.unwrap();
        assert_eq!(got["expiry_notices"], serde_json::json!(true));
        assert!(got["active"].is_null());

        let back = p
            .call(&host, "set_settings", serde_json::json!({ "expiry_notices": false }))
            .await
            .unwrap();
        assert_eq!(back["expiry_notices"], serde_json::json!(false));
        assert!(!store::expiry_notices(&host));
    }

    #[tokio::test]
    async fn notifications_that_are_off_keep_quiet() {
        let host = vault();
        host.set_settings(json!({ "expiry_notices": false })).unwrap();
        store::store_issued(
            &host,
            "https://vault.dev",
            &serde_json::to_string(&[model::Issued {
                accessor: "ac".into(),
                recipient: model::Recipient::Me,
                policies: vec!["ro".into()],
                ttl_seconds: 10,
                num_uses: 0,
                note: String::new(),
                created_at: api::now_secs(),
                wrapped: false,
                state: model::IssueState::Active,
            }])
            .unwrap(),
        )
        .await
        .unwrap();

        HashicorpPlugin::new().notify_expiring(&host).await;
        assert!(host.notices.lock().unwrap().is_empty());
    }
}

#[cfg(test)]
mod dictionary {
    /// The plugin's words live with the plugin, and the window merges them into
    /// the dictionary. They are held to the same rule as the core's: both
    /// languages cover the same keys, with the same values inside a sentence.
    #[test]
    fn both_languages_agree() {
        let ru = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/i18n/ru.json"));
        let en = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/i18n/en.json"));
        let wrong = keyward_core::text::audit(ru, en);
        assert!(wrong.is_empty(), "{wrong:#?}");
    }
}
