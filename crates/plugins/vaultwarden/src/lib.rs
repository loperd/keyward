//! Vaultwarden's admin panel as a keyward section: the server's users, its
//! organisations and the server itself, managed from the window rather than
//! from a browser tab on `/admin`.
//!
//! The panel is part of the server the account is on, so the section appears
//! by itself: the plugin looks at that server, and when it is a Vaultwarden
//! with `/admin` switched on it tells the window so. Nobody types an address.
//!
//! The panel is unlocked by pasting the admin token. The token is kept in the
//! macOS keychain only — as a ciphertext under a key from the vault, read back
//! behind Touch ID — and nowhere else: not in the vault, not on disk, not in
//! this process longer than one login.
//!
//! What the window may do to whom is worked out here, from what the panel
//! returns: a user's state and the actions it allows, the roles one may give.
//! The window draws what it is handed and decides nothing itself.

pub mod api;
pub mod settings;

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use keyward_core::items::{MemberStatus, OrgRole};
use keyward_plugin::{arg, ok, out, Host, Manifest, Origin, Permission, Plugin, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Mutex;

use api::{Session, UserAction};

/// The admin token's name in the plugin's keychain.
const TOKEN: &str = "admin-token";

#[derive(Default)]
pub struct VaultwardenPlugin {
    /// The last session, by the address it was opened on: the panel's JWT
    /// lives a while, and logging in on every call would run into its rate
    /// limit.
    session: Mutex<Option<(String, Session)>>,
    /// Whether the account's server has the panel, by server, with when it
    /// was found out: the window asks often, the server is asked seldom.
    probed: Mutex<Option<(String, bool, Instant)>>,
}

/// How long an answer about the server holds.
const PROBE_TTL: Duration = Duration::from_secs(300);

impl VaultwardenPlugin {
    pub fn new() -> Self {
        Self::default()
    }

    /// Run `work` in a session with the connected panel. A session that ran
    /// out is replaced once; a second refusal is the answer.
    async fn with_session<T, F, Fut>(&self, host: &dyn Host, work: F) -> Result<T>
    where
        F: Fn(Session) -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let panel = panel(host).ok_or_else(|| keyward_core::fault!("err.vwadminNoServer"))?;
        for fresh in [false, true] {
            let session = self.session(host, &panel, fresh).await?;
            match work(session).await {
                Err(e) if !fresh && e.to_string() == api::SESSION_EXPIRED => continue,
                other => return other,
            }
        }
        Err(keyward_core::fault!(api::SESSION_EXPIRED))
    }

    /// Is the panel there on the account's server? Asked of the server at most
    /// once in `PROBE_TTL` per server.
    async fn available(&self, host: &dyn Host) -> bool {
        let Some(server) = host.server() else { return false };
        let mut slot = self.probed.lock().await;
        if let Some((s, yes, at)) = slot.as_ref() {
            if *s == server && at.elapsed() < PROBE_TTL {
                return *yes;
            }
        }
        let yes = api::detect(&server).await;
        *slot = Some((server, yes, Instant::now()));
        yes
    }

    /// A session with the panel: the one there is, or a new one — and only
    /// then is the token read, from the keychain, behind the person's finger.
    async fn session(&self, host: &dyn Host, panel: &str, fresh: bool) -> Result<Session> {
        let mut slot = self.session.lock().await;
        if let (false, Some((addr, s))) = (fresh, slot.as_ref()) {
            if addr == panel {
                return Ok(s.clone());
            }
        }
        if !host.keychain_has(TOKEN).await {
            return Err(keyward_core::fault!("err.vwadminLocked"));
        }
        let token = host.keychain_get(TOKEN).await?;
        let s = api::login(panel, &token).await?;
        *slot = Some((panel.to_string(), s.clone()));
        Ok(s)
    }
}

// -- The panel --------------------------------------------------------------

/// The account's server's panel: where it is, from the server the account is
/// on.
fn panel(host: &dyn Host) -> Option<String> {
    host.server().and_then(|s| api::panel_url(&s).ok())
}

/// What the section shows before anything else: the panel, and whether it is
/// unlocked — a token is kept for it in the keychain.
#[derive(Debug, Serialize)]
struct StatusOut {
    panel: Option<String>,
    unlocked: bool,
}

#[derive(Deserialize)]
struct UnlockArg {
    token: String,
}

// -- What the window gets ---------------------------------------------------

/// Where a user stands on the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UserState {
    Enabled,
    Invited,
    Disabled,
}

impl UserState {
    fn of(u: &api::User) -> Self {
        match (u.status, u.user_enabled) {
            (_, Some(false)) | (2, _) => Self::Disabled,
            (1, _) => Self::Invited,
            _ => Self::Enabled,
        }
    }

    /// What can be done to a user in this state, in the order it is offered.
    fn actions(self, two_factor: bool) -> Vec<UserAction> {
        let mut out = match self {
            Self::Invited => vec![UserAction::ResendInvite],
            Self::Enabled => vec![UserAction::Deauth, UserAction::Disable],
            Self::Disabled => vec![UserAction::Enable],
        };
        if two_factor {
            out.push(UserAction::RemoveTwoFactor);
        }
        out.push(UserAction::Delete);
        out
    }
}

/// An action as the window offers it: what it is, and how carefully.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ActionView {
    pub action: UserAction,
    pub danger: bool,
    pub confirm: bool,
}

impl From<UserAction> for ActionView {
    fn from(action: UserAction) -> Self {
        Self { action, danger: action.danger(), confirm: action.confirm() }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct MembershipView {
    pub org_id: String,
    pub org_name: String,
    pub role: OrgRole,
    pub status: MemberStatus,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserView {
    pub id: String,
    pub name: Option<String>,
    pub email: String,
    pub state: UserState,
    pub two_factor: bool,
    pub email_verified: bool,
    pub created_at: Option<String>,
    pub last_active: Option<String>,
    pub memberships: Vec<MembershipView>,
    /// What the window may offer for this user.
    pub actions: Vec<ActionView>,
}

impl From<api::User> for UserView {
    fn from(u: api::User) -> Self {
        let state = UserState::of(&u);
        let actions = state.actions(u.two_factor_enabled).into_iter().map(ActionView::from).collect();
        // The accepted ones as well as the confirmed: a member waiting for
        // confirmation is in the organisation all the same.
        let list = if u.organizations_new.is_empty() { &u.organizations } else { &u.organizations_new };
        let memberships = list
            .iter()
            .map(|m| MembershipView {
                org_id: m.id.clone(),
                org_name: m.name.clone(),
                role: OrgRole::from_code(m.kind),
                status: MemberStatus::from_code(m.status),
            })
            .collect();
        Self {
            id: u.id,
            name: u.name.filter(|n| !n.trim().is_empty() && !n.eq_ignore_ascii_case(&u.email)),
            email: u.email,
            state,
            two_factor: u.two_factor_enabled,
            email_verified: u.email_verified,
            created_at: u.created_at,
            last_active: u.last_active,
            memberships,
            actions,
        }
    }
}

/// The panel sets any role — it stands above every organisation — but not
/// one the server names no number for.
fn panel_roles() -> Vec<OrgRole> {
    [OrgRole::User, OrgRole::Manager, OrgRole::Admin, OrgRole::Owner].into_iter().filter(|r| r.code().is_some()).collect()
}

#[derive(Debug, Serialize)]
struct UsersOut {
    users: Vec<UserView>,
    assignable_roles: Vec<OrgRole>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OrgMemberView {
    pub user_id: String,
    pub email: String,
    pub name: Option<String>,
    pub role: OrgRole,
    pub status: MemberStatus,
}

/// An organisation as the users' memberships show it. The panel's own list is
/// an HTML page; the memberships carry everything the section needs.
#[derive(Debug, Clone, Serialize)]
pub struct OrgView {
    pub id: String,
    pub name: String,
    pub members: Vec<OrgMemberView>,
    pub owners: usize,
}

fn orgs_of(users: &[UserView]) -> Vec<OrgView> {
    let mut by_id: BTreeMap<String, OrgView> = BTreeMap::new();
    for u in users {
        for m in &u.memberships {
            let org = by_id.entry(m.org_id.clone()).or_insert_with(|| OrgView {
                id: m.org_id.clone(),
                name: m.org_name.clone(),
                members: Vec::new(),
                owners: 0,
            });
            if m.role == OrgRole::Owner {
                org.owners += 1;
            }
            org.members.push(OrgMemberView {
                user_id: u.id.clone(),
                email: u.email.clone(),
                name: u.name.clone(),
                role: m.role,
                status: m.status,
            });
        }
    }
    let mut out: Vec<OrgView> = by_id.into_values().collect();
    out.sort_by_key(|o| o.name.to_lowercase());
    out
}

// -- The operations' envelopes ----------------------------------------------

#[derive(Deserialize)]
struct EmailArg {
    email: String,
}

#[derive(Deserialize)]
struct ActArg {
    user_id: String,
    action: UserAction,
}

#[derive(Deserialize)]
struct RoleArg {
    user_id: String,
    org_id: String,
    role: OrgRole,
}

#[derive(Deserialize)]
struct SaveArg {
    changes: BTreeMap<String, Value>,
}

#[derive(Deserialize)]
struct OrgArg {
    org_id: String,
}

#[async_trait::async_trait]
impl Plugin for VaultwardenPlugin {
    fn manifest(&self) -> Manifest {
        Manifest {
            id: "vaultwarden".into(),
            title: "Vaultwarden".into(),
            icon: "shield".into(),
            section: true,
            needs_unlocked: true,
            version: env!("CARGO_PKG_VERSION").into(),
            description: "plugin.vaultwarden.description".into(),
            origin: Origin::Builtin,
            enabled: true,
            // Its token in the keychain, and the network to reach the panel.
            permissions: vec![Permission::Keychain, Permission::Network],
            probe: true,
            declared: false,
            places: false,
        }
    }

    async fn call(&self, host: &dyn Host, op: &str, payload: Value) -> Result<Value> {
        match op {
            // -- whether the section applies at all --
            "available" => out(serde_json::json!({ "available": self.available(host).await })),

            // -- unlocking --
            "status" => out(StatusOut { panel: panel(host), unlocked: host.keychain_has(TOKEN).await }),
            "unlock" => {
                let a: UnlockArg = arg(payload)?;
                let addr = panel(host).ok_or_else(|| keyward_core::fault!("err.vwadminNoServer"))?;
                // The token is tried before anything is written: a wrong one
                // must not end up in the vault.
                let session = api::login(&addr, &a.token).await?;
                host.keychain_set(TOKEN, a.token.trim()).await?;
                *self.session.lock().await = Some((addr, session));
                tracing::info!("the Vaultwarden panel was unlocked");
                ok()
            }
            // Lock the panel again: the token leaves the keychain.
            "forget" => {
                host.keychain_forget(TOKEN).await?;
                *self.session.lock().await = None;
                ok()
            }

            // -- users --
            "users" => {
                let users = self.with_session(host, |s| async move { s.users().await }).await?;
                out(UsersOut { users: users.into_iter().map(UserView::from).collect(), assignable_roles: panel_roles() })
            }
            "invite" => {
                let a: EmailArg = arg(payload)?;
                if !a.email.contains('@') {
                    return Err(keyward_core::fault!("err.memberEmailRequired"));
                }
                self.with_session(host, |s| {
                    let email = a.email.clone();
                    async move { s.invite(&email).await }
                })
                .await?;
                ok()
            }
            "user_action" => {
                let a: ActArg = arg(payload)?;
                self.with_session(host, |s| {
                    let id = a.user_id.clone();
                    async move { s.act(&id, a.action).await }
                })
                .await?;
                ok()
            }
            "set_org_role" => {
                let a: RoleArg = arg(payload)?;
                if !panel_roles().contains(&a.role) {
                    return Err(keyward_core::fault!("err.orgRoleNotYours"));
                }
                self.with_session(host, |s| {
                    let (user, org) = (a.user_id.clone(), a.org_id.clone());
                    async move { s.set_org_role(&user, &org, a.role).await }
                })
                .await?;
                ok()
            }

            // -- organisations --
            "orgs" => {
                let users = self.with_session(host, |s| async move { s.users().await }).await?;
                let views: Vec<UserView> = users.into_iter().map(UserView::from).collect();
                out(orgs_of(&views))
            }
            "delete_org" => {
                let a: OrgArg = arg(payload)?;
                self.with_session(host, |s| {
                    let id = a.org_id.clone();
                    async move { s.delete_org(&id).await }
                })
                .await?;
                ok()
            }

            // -- the server --
            "settings" => {
                let groups = self
                    .with_session(host, |s| async move {
                        let mut groups = s.settings().await?;
                        // A setting that names users gets the server's users
                        // to pick from.
                        let emails: Vec<String> = s.users().await?.into_iter().map(|u| u.email).collect();
                        settings::attach_users(&mut groups, &emails);
                        Ok(groups)
                    })
                    .await?;
                out(groups)
            }
            "save_settings" => {
                let a: SaveArg = arg(payload)?;
                self.with_session(host, |s| {
                    let changes = a.changes.clone();
                    async move {
                        // Laid over what the server has this very moment, not
                        // over what the window saw a while ago.
                        let groups = s.settings().await?;
                        let body = settings::to_save(&groups, &changes)?;
                        s.save_settings(body).await
                    }
                })
                .await?;
                ok()
            }
            "reset_settings" => {
                self.with_session(host, |s| async move { s.reset_settings().await }).await?;
                ok()
            }
            "backup_db" => out(self.with_session(host, |s| async move { s.backup_db().await }).await?),
            "test_smtp" => {
                let a: EmailArg = arg(payload)?;
                self.with_session(host, |s| {
                    let email = a.email.clone();
                    async move { s.test_smtp(&email).await }
                })
                .await?;
                ok()
            }

            other => Err(keyward_core::fault!("err.pluginUnknownOp", "op" => other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(status: i32, enabled: Option<bool>, two_factor: bool) -> api::User {
        serde_json::from_value(serde_json::json!({
            "id": "u", "email": "a@x", "_status": status, "userEnabled": enabled, "twoFactorEnabled": two_factor,
            "organizations": [{ "id": "o", "name": "Acme", "type": 0, "status": 2 }],
        }))
        .unwrap()
    }

    #[test]
    fn what_can_be_done_follows_the_users_state() {
        let invited = UserView::from(user(1, Some(true), false));
        assert_eq!(invited.state, UserState::Invited);
        let kinds = |v: &UserView| v.actions.iter().map(|a| a.action).collect::<Vec<_>>();
        assert_eq!(kinds(&invited), vec![UserAction::ResendInvite, UserAction::Delete]);
        let disabled = UserView::from(user(0, Some(false), true));
        assert_eq!(disabled.state, UserState::Disabled);
        assert!(kinds(&disabled).contains(&UserAction::Enable) && !kinds(&disabled).contains(&UserAction::Disable));
        assert!(disabled.actions.iter().any(|a| a.action == UserAction::RemoveTwoFactor && a.danger && a.confirm));
    }

    #[test]
    fn organisations_are_gathered_from_memberships() {
        let users = vec![UserView::from(user(0, Some(true), false))];
        let orgs = orgs_of(&users);
        assert_eq!(orgs.len(), 1);
        assert_eq!((orgs[0].owners, orgs[0].members[0].role), (1, OrgRole::Owner));
    }
}
