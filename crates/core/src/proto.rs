//! The control socket's protocol: lines of JSON, one per message.
//! Deliberately simple — the CLI sits on it, and so do the GUI and the `keyward
//! resolve` helper that ssh calls on every connection.

use serde::{Deserialize, Serialize};

use crate::accounts::Account;
use crate::detail::{ItemDetail, SecretField};
use crate::edits::{ItemEdit, PendingEdit};
use crate::items::Catalog;
use crate::account::{AccountProfile, AuthenticatorSetup, Device, EmailTwoFactorSetup, ExportFormat, KdfInfo, TwoFactorStatus};
use crate::settings::Settings as AppSettings;
use crate::two_factor::TwoFactorProvider;
use crate::vault_state::VaultState;


/// A value that must not outlive its use: a master password, a PIN, a
/// revealed or generated password. Its memory is wiped when it is dropped,
/// rather than left in the heap for whatever reads it next.
pub type Secret = zeroize::Zeroizing<String>;
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// A check that it is alive.
    Ping,
    /// The daemon's state, for the GUI and for `keyward status`.
    Status,
    /// Re-read the source of mappings.
    Reload,
    /// A full shutdown: lock every vault, take the sockets down, forget
    /// everything that was decrypted and kill the process.
    Shutdown,
    /// The vault's state.
    Vault,
    /// Set the server address and the login. A login need not be an email:
    /// self-hosted servers have plain user names too.
    Setup {
        base_url: String,
        email: String,
        /// A separate address for the identity server. In Vaultwarden it is
        /// the same as the main one; in the official Bitwarden and in some
        /// installations it is not.
        #[serde(default)]
        identity_url: Option<String>,
    },
    /// The current settings, so that the form can open already filled in.
    Config,
    /// The active account's catalogue of items: kinds, folders, counts.
    Items,
    /// An item's card: the visible fields and the signs of secrets.
    ItemDetail { entry_id: String },
    /// An organisation's members. The server gives the list, and only to those
    /// with the right to it.
    OrgMembers { org_id: String },
    /// One's own folders. Deleting one leaves its items without a folder.
    CreateFolder { name: String },
    RenameFolder { folder_id: String, name: String },
    DeleteFolder { folder_id: String },
    /// An organisation's collections.
    CreateCollection { org_id: String, name: String },
    RenameCollection { org_id: String, collection_id: String, name: String },
    DeleteCollection { org_id: String, collection_id: String },
    /// An organisation's members.
    InviteMember { org_id: String, email: String, role: crate::items::OrgRole },
    SetMemberRole { org_id: String, member_id: String, role: crate::items::OrgRole },
    RemoveMember { org_id: String, member_id: String },
    /// `fingerprint` is the five words the person was shown
    /// (`MemberFingerprint`): the daemon seals to the member's key only while
    /// it still makes them.
    ConfirmMember { org_id: String, member_id: String, user_id: String, fingerprint: Vec<String> },
    /// A member's fingerprint phrase, to compare with them before confirming.
    MemberFingerprint { org_id: String, member_id: String, user_id: String },
    /// Invite people with a role and their access: to every collection, or
    /// to the named ones at their levels.
    InviteMembers {
        org_id: String,
        emails: Vec<String>,
        role: crate::items::OrgRole,
        access_all: bool,
        access: Vec<crate::items::CollectionAccess>,
    },
    /// Change a member's role and access in one step.
    SetMember {
        org_id: String,
        member_id: String,
        role: crate::items::OrgRole,
        access_all: bool,
        access: Vec<crate::items::CollectionAccess>,
    },
    /// Folders and collections made with an answer that names them:
    /// `Created { id }`.
    NewFolder { name: String },
    NewCollection { org_id: String, name: String },
    /// Create an item in one's own vault or in an organisation's
    /// collections; the answer is `Created { id }`.
    NewItem {
        kind: u8,
        folder_id: Option<String>,
        org_id: Option<String>,
        collection_ids: Vec<String>,
        edit: ItemEdit,
    },
    /// Put an organisation's item into these collections, and only these.
    SetItemCollections { entry_id: String, collection_ids: Vec<String> },
    /// Whether this is the master password, checked against the open vault
    /// and changing nothing: what an item marked for a re-prompt asks. The
    /// answer is `PasswordChecked`.
    VerifyPassword { password: Secret },
    /// Generate a passphrase out of the EFF list, here in the daemon.
    GeneratePassphrase { spec: crate::generator::PassphraseSpec },
    /// Create an organisation.
    CreateOrg { name: String, billing_email: String },
    /// Rename an organisation.
    UpdateOrg { org_id: String, name: String, billing_email: String },
    /// Delete an organisation. The server asks for the master password:
    /// deleting takes its items away from every member.
    DeleteOrg { org_id: String, master_password: String },
    /// Create a new item.
    CreateItem { kind: u8, folder_id: Option<String>, edit: ItemEdit },
    /// Move an item into the trash.
    TrashItem { entry_id: String },
    /// Bring an item back out of the trash.
    RestoreItem { entry_id: String },
    /// Delete for good. An empty list means the whole trash.
    PurgeItems { entry_ids: Vec<String> },
    /// The generator's history: readable only while the vault is open, because
    /// it lies encrypted with the vault's own key.
    GeneratorHistory,
    /// Add a password to the history. `taken` means it was carried off to the
    /// clipboard.
    RememberGenerated { taken: bool, value: Secret },
    /// Copy a password from the generator's history, by its place in a list:
    /// the value goes from the daemon to the clipboard, not through the window.
    CopyGenerated { taken: bool, index: usize },
    /// Show one password of the history, by its place.
    RevealGenerated { taken: bool, index: usize },
    /// Make or read an ssh key into a draft the daemon holds.
    SshKeyDraft { source: crate::edits::SshDraftSource },
    /// Copy a draft's private key: from the daemon to the clipboard.
    CopySshDraft { id: String },
    /// Erase one of the lists.
    ForgetGenerated { taken: bool },
    /// Remember that an item was opened, for the recent ones in the search.
    RememberOpened { entry_id: String },
    /// The recent items alone. Apart from the generator's history: there is no
    /// reason for the interface to receive the generated passwords along with
    /// them.
    RecentItems,
    /// Generate a password. The randomness comes from the system in the
    /// daemon, not in the webview.
    GeneratePassword { spec: crate::generator::Spec },
    /// Make a new password for a login and save it in one step, here in the
    /// daemon: the password never travels to the window. The old one goes
    /// into the item's history.
    RegeneratePassword { entry_id: String, spec: crate::generator::Spec },
    /// Put an arbitrary string on the clipboard, with the same clearing timer
    /// the vault's passwords get.
    CopyText { value: Secret },
    /// Take the gathered notifications. The answer empties the queue.
    TakeNotices,
    /// Put a notification into the queue. It exists so that the whole path can
    /// be tested without waiting for a real lease to expire.
    PushNotice { body: String },
    /// A site icon for a domain, through our own server's icon service.
    /// Vaultwarden's placeholder (a grey planet) is thrown away and a monogram
    /// takes its place.
    SiteIcon { domain: String },
    /// Copy a secret to the clipboard. The value does not come back: the fewer
    /// places a password passes through, the better.
    CopySecret { entry_id: String, field: SecretField },
    /// Show a secret on the screen, at an explicit press of "show".
    RevealSecret { entry_id: String, field: SecretField },
    /// Change an item. It goes to the server at once; if the server is
    /// unreachable, the edit stays in the queue.
    UpdateItem { entry_id: String, edit: ItemEdit },
    /// Which of the records hold each field of a login and which agree on
    /// it — never the values.
    MergeCompare { entry_ids: Vec<String> },
    /// Merge records into one, here where the keys are: the kept record
    /// takes the plan's fields, the others go to the trash.
    MergeItems { plan: crate::merge::MergePlan },
    /// The queue of edits: what did not reach the server.
    Edits,
    /// Send it again.
    RetryEdit { id: String },
    /// Put the former value back.
    RollbackEdit { id: String },
    /// Put back the TOTP secret an item had before a code was saved over it,
    /// out of the journal of edits.
    RestoreTotp { entry_id: String },
    /// Forget an edit without sending it.
    DiscardEdit { id: String },
    /// The application's settings.
    GetSettings,
    /// Save the settings. The daemon applies them at once.
    SetSettings { settings: AppSettings },
    /// The names of an item's custom fields: one picks from them where the
    /// unseal keys lie.
    NoteFields { entry_id: String },
    /// The list of accounts and which of them is active.
    Accounts,
    /// Switch to another account.
    SwitchAccount { id: String },
    /// Log out of an account: forget its keys and tokens. The others are left
    /// alone.
    Logout { id: String },
    /// Logging in with the master password. The password travels over a local
    /// socket with mode 0600 and is saved nowhere: the keys are derived from it
    /// and after that the tokens live on. If the server asks for a second
    /// factor, the answer is `TwoFactorRequired`.
    Login { password: Secret },
    /// The second step of logging in: the code from the chosen method. The
    /// password does not travel again — it waits in the daemon's memory.
    /// `remember`: the server is asked to remember this device, and the token
    /// it hands out is kept sealed in the daemon's store for the next login.
    LoginTwoFactor {
        provider: u8,
        token: Secret,
        #[serde(default)]
        remember: bool,
    },
    /// The active account's saved session does not read
    /// (`VaultState::Damaged`): forget it, so the person can sign in again.
    /// Refused for a session that reads.
    ResetSession,
    /// Ask the server to send a code by email.
    SendTwoFactorEmail,
    /// Unlocking with the master password.
    Unlock { password: Secret },
    /// Forget the keys, keeping the tokens.
    Lock,
    /// Syncing with the server.
    Sync,
    /// Unlocking with Touch ID: the password comes from the keychain, whose
    /// reading the system guards with biometrics.
    BiometricUnlock,
    /// Remember the master password under a biometric ACL. The password is
    /// checked by unlocking before it is saved, so that a wrong one is not
    /// remembered.
    BiometricRemember { password: Secret },
    /// Forget the saved password.
    BiometricForget,

    // -- The Bitwarden account ---------------------------------------------
    /// The active account's profile: name, email, KDF, fingerprint, second
    /// factor.
    AccountProfile,
    /// The name and the master password hint.
    AccountSetProfile { name: String, hint: Option<String> },
    /// The avatar's colour, `#rrggbb`; `None` clears it.
    AccountSetAvatar { color: Option<String> },
    /// Changing the master password. The user key is re-encrypted with the new
    /// master key; the server resets every device, so the daemon logs in again
    /// at once with the new password — the answer is as for `Login`.
    AccountChangePassword { current: Secret, new: Secret, hint: Option<String> },
    /// The first step of changing the email: the server sends a code to the
    /// new address.
    AccountEmailToken { master_password: Secret, new_email: String },
    /// The second step: the code from the new address. The key is re-encrypted
    /// — the master key's salt changes with the address. The answer is as for
    /// `Login`.
    AccountChangeEmail { master_password: Secret, new_email: String, token: Secret },
    /// Changing the key derivation function. The answer is as for `Login`.
    AccountChangeKdf { master_password: Secret, kdf: KdfInfo },
    /// Log every device out (reset the security stamp). The answer is as for
    /// `Login`.
    AccountDeauthorize { master_password: Secret },
    /// Delete the account on the server and forget it locally.
    AccountDelete { master_password: Secret },
    /// Delete every item and folder of one's own (organisations are left
    /// alone).
    AccountPurge { master_password: Secret },

    // -- The second factor --------------------------------------------------
    TwoFactorStatus,
    /// The secret for an authenticator app (a new one or the current one).
    TwoFactorAuthenticatorSetup { master_password: Secret },
    /// Turn the authenticator on, confirming with a code.
    TwoFactorAuthenticatorEnable { master_password: Secret, key: Secret, token: Secret },
    TwoFactorEmailSetup { master_password: Secret },
    /// Send a check code to the second factor's email.
    TwoFactorEmailSend { master_password: Secret, email: String },
    TwoFactorEmailEnable { master_password: Secret, email: String, token: Secret },
    /// Turn a method off by Bitwarden's provider identifier.
    TwoFactorDisable { master_password: Secret, provider: u8 },
    /// The recovery code, in case the second factor is lost.
    TwoFactorRecoveryCode { master_password: Secret },

    // -- Devices and export --------------------------------------------------
    Devices,
    /// Exporting the vault in the clear. It asks for the master password, as
    /// Bitwarden does.
    ExportVault { master_password: Secret, format: ExportFormat },

    // ── PIN ──────────────────────────────────────────────────────────────
    /// Remember the master password under a PIN. The password is checked
    /// before it is saved.
    PinSet { pin: Secret, master_password: Secret },
    PinClear,
    /// Unlocking with a PIN. After five mistakes the PIN is dropped.
    PinUnlock { pin: Secret },

    // -- Plugins ---------------------------------------------------------------
    /// The cards of the installed plugins: the interface draws its sections
    /// from them.
    Plugins,
    /// A request to a plugin. The core does not read `op` and `payload`:
    /// adding a plugin does not touch the protocol.
    Plugin { plugin: String, action: String, payload: serde_json::Value },
    /// A request to a plugin that needs values from an item's own fields — an
    /// unseal key a person put in a note. The window names the fields; the
    /// daemon reads them, under the same Touch ID rules as revealing a field,
    /// and puts them into `payload[into]` as a list. The values go from here to
    /// the plugin and never through the window.
    PluginWithFields {
        plugin: String,
        action: String,
        payload: serde_json::Value,
        entry_id: String,
        fields: Vec<String>,
        into: String,
    },
    /// Install a plugin: a path to a directory, to an archive, or an `https://`
    /// address. The answer is its card; until the permissions are consented to,
    /// the plugin is off.
    PluginInstall { path: String },
    /// The showcase: what can be installed at all. `refresh` goes to the
    /// sources again rather than making do with the cache.
    PluginCatalog { refresh: bool },
    /// Where to take the showcase from. An empty list returns the current
    /// one.
    PluginSources { set: Option<Vec<String>> },
    /// Trust a publisher or strip them of trust. The decision covers all their
    /// packages at once: a person checked the five words of the fingerprint and
    /// said yes.
    PluginTrust { publisher: String, trust: bool },
    /// Remove a plugin. A built-in one cannot be removed, only switched off.
    PluginRemove { id: String },
    /// Switch on or off. One that is off appears in no section, receives no
    /// events and answers no calls.
    PluginEnable { id: String, on: bool },

    /// The vault's passkeys a page may be offered at a sign-in. Names of
    /// accounts, no keys; an outsider process is refused even this.
    PasskeyOffers { sign_in: crate::passkey::SignIn },
    /// Sign in with a passkey. Touch ID every time, with the site and the
    /// account in the prompt; the private key never leaves the daemon.
    PasskeySignIn { request: crate::passkey::SignInWith },
    /// The logins of a site a new passkey may be saved into.
    PasskeyHomes { sign_in: crate::passkey::SignIn },
    /// Register a new passkey in the vault. Touch ID every time.
    PasskeyRegister { request: crate::passkey::Register },
    /// A passkey request as the browser extension signed it, passed on by the
    /// bridge untouched: `signed` is the extension's JSON
    /// (`crate::passkey::Signed`), `sig` its ECDSA P-256 signature, `key` the
    /// extension's public key. The daemon checks the signature and that the
    /// key is paired before it reads a word of the request — the bridge
    /// decides nothing.
    PasskeyBridge { key: String, signed: String, sig: String },

    // -- Browser extensions ---------------------------------------------------
    /// The paired extensions, and those that asked lately without being
    /// paired.
    Extensions,
    /// Pair an extension that asked lately: its key may sign passkey
    /// requests from now on. The finger, every time.
    ExtensionPair { key: String },
    /// Unpair one.
    ExtensionUnpair { key: String },
}

/// `Debug` for `Request` is written by hand: a derived one would print the
/// master password into the logs at the first parsing error.
impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ping => write!(f, "Ping"),
            Self::Shutdown => write!(f, "Shutdown"),
            Self::Status => write!(f, "Status"),
            Self::Reload => write!(f, "Reload"),
            Self::Vault => write!(f, "Vault"),
            Self::Sync => write!(f, "Sync"),
            Self::Lock => write!(f, "Lock"),
            Self::Config => write!(f, "Config"),
            Self::Items => write!(f, "Items"),
            Self::OrgMembers { org_id } => write!(f, "OrgMembers({org_id})"),
            // A folder's name is one's own business: only ids reach a log.
            Self::CreateFolder { .. } => write!(f, "CreateFolder"),
            Self::RenameFolder { folder_id, .. } => write!(f, "RenameFolder({folder_id})"),
            Self::DeleteFolder { folder_id } => write!(f, "DeleteFolder({folder_id})"),
            Self::CreateCollection { name, .. } => write!(f, "CreateCollection({name})"),
            Self::RenameCollection { collection_id, .. } => {
                write!(f, "RenameCollection({collection_id})")
            }
            Self::DeleteCollection { collection_id, .. } => {
                write!(f, "DeleteCollection({collection_id})")
            }
            Self::InviteMember { email, role, .. } => write!(f, "InviteMember({email}, {role:?})"),
            Self::SetMemberRole { member_id, role, .. } => {
                write!(f, "SetMemberRole({member_id}, {role:?})")
            }
            Self::RemoveMember { member_id, .. } => write!(f, "RemoveMember({member_id})"),
            Self::ConfirmMember { member_id, .. } => write!(f, "ConfirmMember({member_id})"),
            Self::MemberFingerprint { member_id, .. } => write!(f, "MemberFingerprint({member_id})"),
            // Addresses are people's: a count is what a log needs.
            Self::InviteMembers { emails, role, access_all, access, .. } => write!(
                f,
                "InviteMembers({} of them, {role:?}, all={access_all}, {} collections)",
                emails.len(),
                access.len()
            ),
            Self::SetMember { member_id, role, access_all, access, .. } => write!(
                f,
                "SetMember({member_id}, {role:?}, all={access_all}, {} collections)",
                access.len()
            ),
            Self::NewFolder { .. } => write!(f, "NewFolder"),
            Self::NewCollection { org_id, .. } => write!(f, "NewCollection({org_id})"),
            Self::NewItem { kind, org_id, collection_ids, edit, .. } => write!(
                f,
                "NewItem(kind {kind}, org {org_id:?}, {} collections, fields {:?})",
                collection_ids.len(),
                edit.labels()
            ),
            Self::SetItemCollections { entry_id, collection_ids } => {
                write!(f, "SetItemCollections({entry_id}, {} of them)", collection_ids.len())
            }
            Self::VerifyPassword { .. } => write!(f, "VerifyPassword {{ password: <hidden> }}"),
            Self::GeneratePassphrase { spec } => write!(f, "GeneratePassphrase({} words)", spec.words),
            Self::CreateOrg { name, .. } => write!(f, "CreateOrg({name})"),
            Self::UpdateOrg { org_id, .. } => write!(f, "UpdateOrg({org_id})"),
            // The password will not travel into a log.
            Self::DeleteOrg { org_id, .. } => write!(f, "DeleteOrg({org_id})"),
            Self::GeneratorHistory => write!(f, "GeneratorHistory"),
            Self::RememberGenerated { taken, .. } => write!(f, "RememberGenerated(taken={taken})"),
            Self::ForgetGenerated { taken } => write!(f, "ForgetGenerated(taken={taken})"),
            Self::CopyGenerated { taken, index } => write!(f, "CopyGenerated(taken={taken}, #{index})"),
            Self::RevealGenerated { taken, index } => write!(f, "RevealGenerated(taken={taken}, #{index})"),
            Self::SshKeyDraft { source } => write!(f, "SshKeyDraft({source:?})"),
            Self::CopySshDraft { id } => write!(f, "CopySshDraft({id})"),
            Self::RememberOpened { entry_id } => write!(f, "RememberOpened({entry_id})"),
            Self::RecentItems => write!(f, "RecentItems"),
            Self::CreateItem { kind, .. } => write!(f, "CreateItem(kind {kind})"),
            Self::TrashItem { entry_id } => write!(f, "TrashItem({entry_id})"),
            Self::RestoreItem { entry_id } => write!(f, "RestoreItem({entry_id})"),
            Self::PurgeItems { entry_ids } => write!(f, "PurgeItems({} of them)", entry_ids.len()),
            Self::GeneratePassword { spec } => write!(f, "GeneratePassword({} chars)", spec.length),
            Self::RegeneratePassword { entry_id, spec } => {
                write!(f, "RegeneratePassword({entry_id:?}, {} chars)", spec.length)
            }
            // The value will not travel into a log.
            Self::CopyText { .. } => write!(f, "CopyText"),
            Self::TakeNotices => write!(f, "TakeNotices"),
            Self::PushNotice { body } => write!(f, "PushNotice({body:?})"),
            Self::SiteIcon { domain } => write!(f, "SiteIcon({domain})"),
            Self::ItemDetail { entry_id } => write!(f, "ItemDetail {{ entry_id: {entry_id:?} }}"),
            Self::CopySecret { entry_id, field } => {
                write!(f, "CopySecret {{ entry_id: {entry_id:?}, field: {field:?} }}")
            }
            Self::RevealSecret { entry_id, field } => {
                write!(f, "RevealSecret {{ entry_id: {entry_id:?}, field: {field:?} }}")
            }
            // An edit holds the fields' new values, and they will not travel
            // into a log.
            Self::UpdateItem { entry_id, edit } => {
                write!(f, "UpdateItem {{ entry_id: {entry_id:?}, fields: {:?} }}", edit.labels())
            }
            Self::MergeCompare { entry_ids } => write!(f, "MergeCompare {{ entry_ids: {entry_ids:?} }}"),
            // A plan names records and fields, never a value.
            Self::MergeItems { plan } => write!(f, "MergeItems {{ plan: {plan:?} }}"),
            Self::Edits => write!(f, "Edits"),
            Self::RetryEdit { id } => write!(f, "RetryEdit {{ id: {id:?} }}"),
            Self::RollbackEdit { id } => write!(f, "RollbackEdit {{ id: {id:?} }}"),
            Self::RestoreTotp { entry_id } => write!(f, "RestoreTotp {{ entry_id: {entry_id:?} }}"),
            Self::DiscardEdit { id } => write!(f, "DiscardEdit {{ id: {id:?} }}"),
            Self::GetSettings => write!(f, "GetSettings"),
            Self::SetSettings { .. } => write!(f, "SetSettings"),
            Self::NoteFields { entry_id } => write!(f, "NoteFields {{ entry_id: {entry_id:?} }}"),
            // The form holds a recovery key and a secret_id, and they will not
            // travel into a log.
            Self::Accounts => write!(f, "Accounts"),
            Self::SwitchAccount { id } => write!(f, "SwitchAccount {{ id: {id:?} }}"),
            Self::Logout { id } => write!(f, "Logout {{ id: {id:?} }}"),
            Self::Setup { base_url, email, identity_url } => write!(
                f,
                "Setup {{ base_url: {base_url:?}, email: {email:?}, identity_url: {identity_url:?} }}"
            ),
            Self::Login { .. } => write!(f, "Login {{ password: <hidden> }}"),
            Self::LoginTwoFactor { provider, remember, .. } => {
                write!(f, "LoginTwoFactor {{ provider: {provider}, token: <hidden>, remember: {remember} }}")
            }
            Self::ResetSession => write!(f, "ResetSession"),
            Self::SendTwoFactorEmail => write!(f, "SendTwoFactorEmail"),
            Self::Unlock { .. } => write!(f, "Unlock {{ password: <hidden> }}"),
            Self::BiometricUnlock => write!(f, "BiometricUnlock"),
            Self::BiometricRemember { .. } => write!(f, "BiometricRemember {{ password: <hidden> }}"),
            Self::BiometricForget => write!(f, "BiometricForget"),
            Self::AccountProfile => write!(f, "AccountProfile"),
            Self::AccountSetProfile { name, .. } => write!(f, "AccountSetProfile {{ name: {name:?} }}"),
            Self::AccountSetAvatar { color } => write!(f, "AccountSetAvatar {{ color: {color:?} }}"),
            Self::AccountChangePassword { .. } => write!(f, "AccountChangePassword {{ <hidden> }}"),
            Self::AccountEmailToken { new_email, .. } => write!(f, "AccountEmailToken {{ new_email: {new_email:?} }}"),
            Self::AccountChangeEmail { new_email, .. } => write!(f, "AccountChangeEmail {{ new_email: {new_email:?} }}"),
            Self::AccountChangeKdf { kdf, .. } => write!(f, "AccountChangeKdf {{ kdf: {kdf:?} }}"),
            Self::AccountDeauthorize { .. } => write!(f, "AccountDeauthorize"),
            Self::AccountDelete { .. } => write!(f, "AccountDelete"),
            Self::AccountPurge { .. } => write!(f, "AccountPurge"),
            Self::TwoFactorStatus => write!(f, "TwoFactorStatus"),
            Self::TwoFactorAuthenticatorSetup { .. } => write!(f, "TwoFactorAuthenticatorSetup"),
            Self::TwoFactorAuthenticatorEnable { .. } => write!(f, "TwoFactorAuthenticatorEnable {{ <hidden> }}"),
            Self::TwoFactorEmailSetup { .. } => write!(f, "TwoFactorEmailSetup"),
            Self::TwoFactorEmailSend { email, .. } => write!(f, "TwoFactorEmailSend {{ email: {email:?} }}"),
            Self::TwoFactorEmailEnable { email, .. } => write!(f, "TwoFactorEmailEnable {{ email: {email:?} }}"),
            Self::TwoFactorDisable { provider, .. } => write!(f, "TwoFactorDisable {{ provider: {provider} }}"),
            Self::TwoFactorRecoveryCode { .. } => write!(f, "TwoFactorRecoveryCode"),
            Self::Devices => write!(f, "Devices"),
            Self::ExportVault { format, .. } => write!(f, "ExportVault {{ format: {format:?} }}"),
            Self::PinSet { .. } => write!(f, "PinSet {{ <hidden> }}"),
            Self::PinClear => write!(f, "PinClear"),
            Self::PinUnlock { .. } => write!(f, "PinUnlock {{ pin: <hidden> }}"),
            Self::Plugins => write!(f, "Plugins"),
            Self::Plugin { plugin, action, .. } => write!(f, "Plugin {{ {plugin}.{action} }}"),
            Self::PluginWithFields { plugin, action, fields, .. } => {
                write!(f, "PluginWithFields {{ {plugin}.{action}, {} fields }}", fields.len())
            }
            Self::PluginInstall { path } => write!(f, "PluginInstall {{ path: {path:?} }}"),
            Self::PluginCatalog { refresh } => write!(f, "PluginCatalog {{ refresh: {refresh} }}"),
            Self::PluginSources { set } => write!(f, "PluginSources {{ set: {} }}", set.as_ref().map_or(0, Vec::len)),
            Self::PluginTrust { publisher, trust } => write!(f, "PluginTrust {{ {publisher:?}, trust: {trust} }}"),
            Self::PluginRemove { id } => write!(f, "PluginRemove {{ id: {id:?} }}"),
            Self::PluginEnable { id, on } => write!(f, "PluginEnable {{ id: {id:?}, on: {on} }}"),
            // The origin alone: which site asked is what a log needs, and
            // accounts, challenges and item ids are nobody's business there.
            Self::PasskeyOffers { sign_in } => write!(f, "PasskeyOffers {{ {:?} }}", sign_in.origin),
            Self::PasskeySignIn { request } => write!(f, "PasskeySignIn {{ {:?} }}", request.sign_in.origin),
            Self::PasskeyRegister { request } => write!(f, "PasskeyRegister {{ {:?} }}", request.origin),
            Self::PasskeyHomes { sign_in } => write!(f, "PasskeyHomes {{ {:?} }}", sign_in.origin),
            Self::PasskeyBridge { .. } => write!(f, "PasskeyBridge"),
            Self::Extensions => write!(f, "Extensions"),
            Self::ExtensionPair { .. } => write!(f, "ExtensionPair"),
            Self::ExtensionUnpair { .. } => write!(f, "ExtensionUnpair"),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Response {
    Pong,
    Status(Status),
    /// The vault's state after the operation.
    Vault { state: VaultState },
    /// The catalogue of items.
    Items { catalog: Catalog },
    /// An organisation's members.
    OrgMembers { members: Vec<crate::items::OrgMember> },
    /// A member's fingerprint phrase: five words of the EFF list.
    MemberFingerprint { words: Vec<String> },
    /// The picture's `data:` URL, or nothing when there is no icon or it is a
    /// placeholder.
    SiteIcon { data_url: Option<String> },
    /// The generator's history.
    History { history: crate::generator::HistoryView },
    /// A draft of an ssh key: its number and the public half.
    SshDraft { draft: crate::edits::SshDraftView },
    /// The identifiers of recently opened items.
    Recent { ids: Vec<String> },
    /// An item's card.
    Detail { detail: ItemDetail },
    /// The secret was copied, and in how many seconds the clipboard will be
    /// cleared.
    Copied { clears_in: u64 },
    /// Passkeys that fit a sign-in.
    PasskeyOffers { offers: Vec<crate::passkey::PasskeyOffer> },
    /// Logins a new passkey may go into.
    PasskeyHomes { homes: Vec<crate::passkey::PasskeyHome> },
    /// A signed sign-in: a signature and public data, never a key.
    PasskeySignedIn { signed: crate::passkey::SignedIn },
    /// A registered passkey: the public key and the attestation.
    PasskeyRegistered { registered: crate::passkey::Registered },
    /// The browser extensions: paired, and asking.
    Extensions { paired: Vec<crate::passkey::ExtensionRow>, pending: Vec<crate::passkey::ExtensionRow> },
    /// A secret that was shown. Its `Debug` is not derived: the value will not
    /// travel into a log.
    Secret { value: Secret },
    /// An edit's outcome.
    Edit { edit: PendingEdit },
    /// The records to merge, compared.
    MergeComparison { comparison: crate::merge::MergeComparison },
    /// The queue of edits.
    Edits { edits: Vec<PendingEdit> },
    /// The application's settings.
    Settings { settings: AppSettings },
    /// The names of an item's fields.
    Fields { names: Vec<String> },
    /// The gathered notifications. Taken once: whoever has a window shows
    /// them.
    Notices { notices: Vec<Notice> },
    /// The accounts and their states.
    Accounts { accounts: Vec<AccountView>, active: Option<String> },
    /// The server asks for a second factor. Which methods are available is
    /// its decision.
    TwoFactorRequired { providers: Vec<TwoFactorProvider> },
    /// A code was sent by email.
    TwoFactorEmailSent,
    /// The connection's current settings.
    Config {
        base_url: String,
        email: String,
        identity_url: Option<String>,
    },
    // -- The account -----------------------------------------------------------
    AccountProfile { profile: AccountProfile },
    TwoFactorStatus { status: TwoFactorStatus },
    AuthenticatorSetup { setup: AuthenticatorSetup },
    EmailTwoFactorSetup { setup: EmailTwoFactorSetup },
    /// The recovery code. It will not travel into a log.
    RecoveryCode { code: String },
    Devices { devices: Vec<Device> },
    /// The finished export file: a name and its contents. It will not travel
    /// into a log.
    Export { filename: String, content: String },
    /// The plugins' cards.
    Plugins { plugins: Vec<serde_json::Value> },
    /// The plugins' showcase: what can be installed and what already is.
    PluginCatalog { entries: Vec<serde_json::Value> },
    /// The addresses of the showcase's sources.
    PluginSources { sources: Vec<String> },
    /// The plugin's answer as it is.
    Plugin { payload: serde_json::Value },
    /// Something was made, and this is its identifier.
    Created { id: String },
    /// Whether the password was the master password.
    PasswordChecked { ok: bool },
    /// Done; there is nothing more to say.
    Done,
    Error {
        message: String,
    },
}

/// An account together with its state: the interface needs both at once in
/// order to draw the switcher with its locks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountView {
    pub account: Account,
    pub state: VaultState,
    /// Whether this account's master password lies in the keychain.
    pub biometric: bool,
    /// Whether a PIN for unlocking is set.
    #[serde(default)]
    pub pin: bool,
}

/// `Debug` for the answer is written by hand too: a password lies in
/// `Secret`.
impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pong => write!(f, "Pong"),
            Self::Status(s) => write!(f, "Status({s:?})"),
            Self::Vault { state } => write!(f, "Vault({state:?})"),
            Self::TwoFactorRequired { providers } => write!(f, "TwoFactorRequired({} of them)", providers.len()),
            Self::TwoFactorEmailSent => write!(f, "TwoFactorEmailSent"),
            Self::Config { base_url, email, .. } => {
                write!(f, "Config {{ {base_url:?}, {email:?} }}")
            }
            Self::Items { catalog } => write!(f, "Items({} of them)", catalog.items.len()),
            Self::OrgMembers { members } => write!(f, "OrgMembers({} of them)", members.len()),
            Self::MemberFingerprint { words } => write!(f, "MemberFingerprint({} words)", words.len()),
            Self::SiteIcon { data_url } => write!(f, "SiteIcon({})", if data_url.is_some() { "there is one" } else { "none" }),
            Self::Recent { ids } => write!(f, "Recent({} of them)", ids.len()),
            Self::SshDraft { draft } => write!(f, "SshDraft({})", draft.id),
            Self::History { history } => {
                write!(f, "History({}+{})", history.made.len(), history.taken.len())
            }
            Self::Accounts { accounts, active } => {
                write!(f, "Accounts({} of them, active {active:?})", accounts.len())
            }
            Self::Detail { detail } => write!(f, "Detail({:?})", detail.id),
            Self::Copied { clears_in } => write!(f, "Copied {{ clears_in: {clears_in} }}"),
            Self::PasskeyOffers { offers } => write!(f, "PasskeyOffers({})", offers.len()),
            Self::PasskeySignedIn { .. } => write!(f, "PasskeySignedIn"),
            Self::PasskeyHomes { homes } => write!(f, "PasskeyHomes({})", homes.len()),
            Self::PasskeyRegistered { .. } => write!(f, "PasskeyRegistered"),
            Self::Extensions { paired, pending } => write!(f, "Extensions({} paired, {} pending)", paired.len(), pending.len()),
            Self::Secret { .. } => write!(f, "Secret {{ value: <hidden> }}"),
            Self::Edit { edit } => write!(f, "Edit({:?}, {:?})", edit.id, edit.state),
            Self::MergeComparison { comparison } => write!(f, "MergeComparison({} rows)", comparison.rows.len()),
            Self::Edits { edits } => write!(f, "Edits({} of them)", edits.len()),
            Self::Settings { .. } => write!(f, "Settings"),
            Self::Fields { names } => write!(f, "Fields({} of them)", names.len()),
            // A token lies in the result and will not travel into a log.
            Self::Notices { notices } => write!(f, "Notices({} of them)", notices.len()),
            Self::AccountProfile { profile } => write!(f, "AccountProfile({:?})", profile.email),
            Self::TwoFactorStatus { status } => write!(f, "TwoFactorStatus({status:?})"),
            Self::AuthenticatorSetup { setup } => write!(f, "AuthenticatorSetup({setup:?})"),
            Self::EmailTwoFactorSetup { setup } => write!(f, "EmailTwoFactorSetup({setup:?})"),
            Self::RecoveryCode { .. } => write!(f, "RecoveryCode(<hidden>)"),
            Self::Devices { devices } => write!(f, "Devices({} of them)", devices.len()),
            Self::Export { filename, content } => write!(f, "Export({filename:?}, {} bytes)", content.len()),
            Self::Plugins { plugins } => write!(f, "Plugins({} of them)", plugins.len()),
            Self::PluginCatalog { entries } => write!(f, "PluginCatalog({} of them)", entries.len()),
            Self::PluginSources { sources } => write!(f, "PluginSources({} of them)", sources.len()),
            Self::Plugin { .. } => write!(f, "Plugin(<the plugin's answer>)"),
            Self::Created { id } => write!(f, "Created({id})"),
            Self::PasswordChecked { ok } => write!(f, "PasswordChecked({ok})"),
            Self::Done => write!(f, "Done"),
            Self::Error { message } => write!(f, "Error({message:?})"),
        }
    }
}

/// A notification for a person. The title and the text kept apart: the
/// system's notification centre shows them differently, and one glued string
/// would look wrong.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notice {
    pub title: String,
    pub body: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Status {
    pub version: String,
    /// Where the mappings came from: `file` or `rbw`.
    pub source: String,
    /// How many edits are waiting to be sent. Zero means the queue is empty.
    #[serde(default)]
    pub pending_edits: usize,
    /// The vault's state: set up, logged in, unlocked.
    pub vault: VaultState,
    /// Whether the master password lies in the keychain under Touch ID.
    pub biometric: bool,
    /// Whether a PIN is set for unlocking the active account.
    #[serde(default)]
    pub pin: bool,
}

impl Response {
    pub fn error(message: impl std::fmt::Display) -> Self {
        Self::Error { message: message.to_string() }
    }

    /// What kind of answer this is, for the log of actions: the name only,
    /// never the contents — an answer may carry a revealed password or a
    /// freshly generated one. An error is its message: those are keys with
    /// counts and names, written never to hold a value.
    pub fn kind(&self) -> String {
        if let Self::Error { message } = self {
            return format!("error: {message}");
        }
        serde_json::to_value(self)
            .ok()
            .and_then(|v| v.get("result").and_then(|r| r.as_str()).map(str::to_string))
            .unwrap_or_else(|| "?".into())
    }
}

impl Request {
    /// A request the window makes on its own, over and over — a poll, a
    /// refresh of what is on screen — rather than something a person did.
    /// The log of actions keeps these out of the way.
    pub fn is_routine(&self) -> bool {
        matches!(
            self,
            Self::Ping
                | Self::Status
                | Self::Vault
                | Self::Items
                | Self::Config
                | Self::TakeNotices
                | Self::SiteIcon { .. }
                | Self::Edits
                | Self::GetSettings
                | Self::Accounts
                | Self::Plugins
                | Self::RecentItems
                | Self::GeneratorHistory
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_new_writes_keep_their_secrets_and_addresses_out_of_a_log() {
        let r = Request::VerifyPassword { password: "very-secret".to_string().into() };
        assert!(!format!("{r:?}").contains("very-secret"));
        let r = Request::NewItem {
            kind: 1,
            folder_id: None,
            org_id: Some("o".into()),
            collection_ids: vec!["c".into()],
            edit: ItemEdit { password: Some("hunter2".to_string().into()), ..Default::default() },
        };
        assert!(!format!("{r:?}").contains("hunter2"));
        let r = Request::InviteMembers {
            org_id: "o".into(),
            emails: vec!["someone@example.com".into()],
            role: crate::items::OrgRole::User,
            access_all: false,
            access: vec![],
        };
        assert!(!format!("{r:?}").contains("someone@"));
        // The wire shape the window sends.
        let parsed: Request = serde_json::from_str(
            r#"{"op":"set_member","org_id":"o","member_id":"m","role":"user","access_all":false,
                "access":[{"id":"c","permission":"read_hidden"}]}"#,
        )
        .expect("parses");
        assert!(matches!(parsed, Request::SetMember { access, .. } if access[0].permission == crate::items::CollectionPermission::ReadHidden));
    }

    #[test]
    fn debug_never_prints_a_revealed_secret() {
        let r = Response::Secret { value: "very-secret".to_string().into() };
        assert!(!format!("{r:?}").contains("very-secret"));
    }

    #[test]
    fn the_log_names_an_answer_without_its_contents() {
        let r = Response::Secret { value: "very-secret".to_string().into() };
        assert_eq!(r.kind(), "secret");
        assert!(!r.kind().contains("very-secret"));
    }

    #[test]
    fn debug_never_prints_the_master_password() {
        let r = Request::Unlock { password: "very-secret".to_string().into() };
        let shown = format!("{r:?}");
        assert!(!shown.contains("very-secret"), "the password leaked into Debug: {shown}");
        let r = Request::Login { password: "very-secret".to_string().into() };
        let shown = format!("{r:?}");
        assert!(!shown.contains("very-secret"), "the password leaked into Debug: {shown}");
        let r = Request::BiometricRemember { password: "very-secret".to_string().into() };
        let shown = format!("{r:?}");
        assert!(!shown.contains("very-secret"), "the password leaked into Debug: {shown}");
    }

    #[test]
    fn a_second_factor_remembers_only_when_asked() {
        // An older window sends no `remember`: the device is not remembered.
        let old: Request = serde_json::from_str(r#"{"op":"login_two_factor","provider":0,"token":"123456"}"#).unwrap();
        assert!(matches!(old, Request::LoginTwoFactor { remember: false, .. }));
        let asked: Request = serde_json::from_str(r#"{"op":"login_two_factor","provider":0,"token":"123456","remember":true}"#).unwrap();
        assert!(matches!(asked, Request::LoginTwoFactor { remember: true, .. }));
        let shown = format!("{asked:?}");
        assert!(!shown.contains("123456"), "the code leaked into Debug: {shown}");
        let reset: Request = serde_json::from_str(r#"{"op":"reset_session"}"#).unwrap();
        assert!(matches!(reset, Request::ResetSession));
    }

    #[test]
    fn a_damaged_session_travels_with_its_reason() {
        let s = VaultState::Damaged { email: "a@x".into(), server: "https://x".into(), reason: "err.sessionTampered".into() };
        let line = serde_json::to_string(&Response::Vault { state: s.clone() }).unwrap();
        assert!(line.contains(r#""state":"damaged""#), "{line}");
        let Response::Vault { state } = serde_json::from_str(&line).unwrap() else { panic!("a vault answer") };
        assert_eq!(state, s);
    }

    #[test]
    fn request_roundtrips_through_json() {
        let r = Request::Plugin { plugin: "ssh".into(), action: "resolve".into(), payload: serde_json::json!({"host": "node1.example.net"}) };
        let line = serde_json::to_string(&r).unwrap();
        let back: Request = serde_json::from_str(&line).unwrap();
        assert!(matches!(back, Request::Plugin { .. }));
    }

    #[test]
    fn every_response_variant_survives_json() {
        // An internally tagged enum plus a newtype around a list is a panic in
        // serde for no reason at all. Every variant is checked, not only the
        // convenient ones.
        let variants = vec![
            Response::Pong,
            Response::Status(Status {
                version: "0".into(), source: "file".into(), pending_edits: 0,
                vault: VaultState::Disabled, biometric: false, pin: false,
            }),
            Response::Vault { state: VaultState::Disabled },
            Response::Plugins { plugins: vec![serde_json::json!({"id": "ssh"})] },
            Response::Plugin { payload: serde_json::json!({"ok": true}) },
            Response::Done,
            Response::Error { message: "no".into() },
        ];
        for v in variants {
            let line = serde_json::to_string(&v).unwrap_or_else(|e| panic!("{v:?} will not serialise: {e}"));
            let _: Response = serde_json::from_str(&line).unwrap_or_else(|e| panic!("{line} will not read: {e}"));
        }
    }

    #[test]
    fn plugin_envelope_carries_anything() {
        // The core does not read the envelope's contents: the plugin parses
        // it.
        let back: Request =
            serde_json::from_str(r#"{"op":"plugin","plugin":"ssh","action":"resolve","payload":{"host":"h"}}"#).unwrap();
        match back {
            Request::Plugin { plugin, action, payload } => {
                assert_eq!((plugin.as_str(), action.as_str()), ("ssh", "resolve"));
                assert_eq!(payload["host"], "h");
            }
            other => panic!("a plugin envelope was expected, got {other:?}"),
        }
    }

    #[test]
    fn plugin_payload_never_reaches_the_log() {
        // Anything at all can lie in the payload, a secret included.
        let r = Request::Plugin {
            plugin: "hashicorp".into(),
            action: "issue".into(),
            payload: serde_json::json!({"token": "very-secret"}),
        };
        assert!(!format!("{r:?}").contains("very-secret"));
    }
}
