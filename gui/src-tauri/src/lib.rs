//! keyward's GUI: it lives in the menu bar and shows the daemon's state and
//! the table of hosts and keys. It sees no secrets — only the models that come
//! over the control socket.

mod actionlog;
mod autofill;
mod card;
#[cfg(target_os = "macos")]
mod ax;

use keyward_core::account::{
    AccountProfile, AuthenticatorSetup, Device, EmailTwoFactorSetup, ExportFormat, KdfInfo, TwoFactorStatus,
};
use keyward_core::generator::{HistoryView as GeneratorHistory, Spec as GeneratorSpec};
use keyward_core::proto::Secret;
use keyward_core::detail::{ItemDetail, SecretField};
use keyward_core::edits::{ItemEdit, PendingEdit};
use keyward_core::items::{Catalog, OrgMember};
use keyward_core::merge::{MergeComparison, MergePlan};
use keyward_core::settings::Settings as AppSettings;
use keyward_core::proto::AccountView;
use keyward_core::proto::{Request, Response, Status};
use keyward_core::two_factor::TwoFactorProvider;
use keyward_core::vault_state::VaultState;
use tauri::menu::{Menu, MenuItem};
mod notices;
mod probe;
mod seal;

use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{Manager, WindowEvent};

/// One request to the daemon on a blocking thread: the socket is synchronous
/// and must not hold the UI thread.
pub(crate) async fn ask(req: Request) -> Result<Response, String> {
    let started = std::time::Instant::now();
    let (req, out) = tauri::async_runtime::spawn_blocking(move || {
        let out = keyward_core::client::call(&req).map_err(|e| e.to_string());
        (req, out)
    })
    .await
    .map_err(|e| format!("an internal error: {e}"))?;
    actionlog::daemon(&req, &out, started.elapsed().as_millis());
    out
}

#[tauri::command]
async fn daemon_status() -> Result<Status, String> {
    match ask(Request::Status).await? {
        Response::Status(s) => Ok(s),
        Response::Error { message } => Err(message),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

/// Why the daemon did not answer: coming up (a loader) or not (its reason).
#[tauri::command]
async fn daemon_probe() -> Result<probe::Probe, String> {
    tauri::async_runtime::spawn_blocking(probe::probe).await.map_err(|e| format!("an internal error: {e}"))
}

/// The plugins' cards: the interface draws its sections from them.
#[tauri::command]
async fn plugins() -> Result<Vec<serde_json::Value>, String> {
    match ask(Request::Plugins).await? {
        Response::Plugins { plugins } => Ok(plugins),
        Response::Error { message } => Err(humanize(&message)),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

/// A request to a plugin. The shell does not read the contents: what `action`
/// and `payload` mean is known only to the plugin and its screen.
#[tauri::command]
async fn plugin_call(
    plugin: String,
    action: String,
    payload: Option<serde_json::Value>,
) -> Result<serde_json::Value, String> {
    let payload = payload.unwrap_or(serde_json::Value::Null);
    match ask(Request::Plugin { plugin, action, payload }).await? {
        Response::Plugin { payload } => Ok(payload),
        Response::Error { message } => Err(humanize(&message)),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

/// A request to a plugin with values of an item's fields put in by the
/// daemon: the window names the fields and never sees what is in them.
#[tauri::command]
async fn plugin_call_with_fields(
    plugin: String,
    action: String,
    payload: Option<serde_json::Value>,
    entry_id: String,
    fields: Vec<String>,
    into: String,
) -> Result<serde_json::Value, String> {
    let payload = payload.unwrap_or_else(|| serde_json::json!({}));
    match ask(Request::PluginWithFields { plugin, action, payload, entry_id, fields, into }).await? {
        Response::Plugin { payload } => Ok(payload),
        Response::Error { message } => Err(humanize(&message)),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

/// Choosing a plugin package: a directory with a `plugin.json`, or an
/// archive.
///
/// Rust opens the dialogue rather than the web layer: the system's
/// directory-picker and file-picker are different windows, and which to show is
/// decided by the button that was pressed. `None` means the dialogue was closed
/// and there is nothing to install.
#[tauri::command]
async fn plugin_pick(app: tauri::AppHandle, archive: bool) -> Result<Option<String>, String> {
    // The dialogue blocks: it is waited for on a thread of its own rather than
    // on the runtime.
    let picked = tauri::async_runtime::spawn_blocking(move || {
        use tauri_plugin_dialog::DialogExt as _;
        let dialog = app.dialog().file();
        if archive {
            // The system sees `.tar.gz` as the extension `gz`: the filter
            // lists what it can really match.
            dialog.add_filter("zip, tar.gz", &["zip", "gz", "tgz"]).blocking_pick_file()
        } else {
            dialog.blocking_pick_folder()
        }
    })
    .await
    .map_err(|e| format!("an internal error: {e}"))?;
    let Some(path) = picked else { return Ok(None) };
    Ok(Some(path.into_path().map_err(|e| e.to_string())?.display().to_string()))
}

/// Install a plugin. The daemon checks the manifest, copies the package to
/// itself and installs it **switched off**: the interface asks for consent to
/// the permissions separately, and that consent is `plugin_enable`.
#[tauri::command]
async fn plugin_install(path: String) -> Result<serde_json::Value, String> {
    match ask(Request::PluginInstall { path }).await? {
        Response::Plugin { payload } => Ok(payload),
        // The daemon may answer with a list: the freshly installed one is
        // taken out of it.
        Response::Plugins { plugins } => plugins
            .into_iter()
            .next_back()
            .ok_or_else(|| "err.noPluginCard".to_string()),
        Response::Error { message } => Err(humanize(&message)),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

/// The showcase: what can be installed at all. The daemon gives the entries
/// already matched against what is on disk, and the interface is left to draw
/// the button.
///
/// `refresh` means go to the network without fail. Without it the daemon may
/// answer out of its cache, and the entries are then marked `stale`: the
/// showcase is unreachable, but showing the list still beats showing
/// nothing.
#[tauri::command]
async fn plugin_catalog(refresh: bool) -> Result<Vec<serde_json::Value>, String> {
    match ask(Request::PluginCatalog { refresh }).await? {
        Response::PluginCatalog { entries } => Ok(entries),
        Response::Error { message } => Err(humanize(&message)),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

/// The showcases' addresses. `set: None` reads them, `Some(list)` replaces
/// them; either way the daemon answers with what is now written and checks the
/// scheme itself — the window checks the same thing in advance, so that it can
/// point at a typo without a trip to the daemon.
#[tauri::command]
async fn plugin_sources(set: Option<Vec<String>>) -> Result<Vec<String>, String> {
    match ask(Request::PluginSources { set }).await? {
        Response::PluginSources { sources } => Ok(sources),
        Response::Error { message } => Err(humanize(&message)),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

/// Trusting a publisher: their key goes into `publishers.json`, and from that
/// moment packages under their signature install. A separate action rather than
/// a checkbox in the installation: a person confirms five words of a
/// fingerprint after seeing them with their own eyes.
///
/// The request does not exist in the protocol yet — a neighbour on the
/// showcase is writing it (`Request::PluginTrust { publisher }`). Until it does,
/// an honest refusal with an explanation beats pretending the key was added:
/// the window can already show a fingerprint and call this command.
#[tauri::command]
async fn plugin_trust(publisher: String) -> Result<(), String> {
    let _ = publisher;
    Err("err.daemonCannotTrustYet".to_string())
}

/// The browser extensions: paired, and those that asked lately without being
/// paired.
#[derive(serde::Serialize)]
struct Extensions {
    paired: Vec<keyward_core::passkey::ExtensionRow>,
    pending: Vec<keyward_core::passkey::ExtensionRow>,
}

fn extensions_of(r: Response) -> Result<Extensions, String> {
    match r {
        Response::Extensions { paired, pending } => Ok(Extensions { paired, pending }),
        Response::Error { message } => Err(humanize(&message)),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

#[tauri::command]
async fn extensions() -> Result<Extensions, String> {
    extensions_of(ask(Request::Extensions).await?)
}

/// Pairing: the daemon asks for the finger itself, with the key's five words
/// in the prompt.
#[tauri::command]
async fn extension_pair(key: String) -> Result<Extensions, String> {
    extensions_of(ask(Request::ExtensionPair { key }).await?)
}

#[tauri::command]
async fn extension_unpair(key: String) -> Result<Extensions, String> {
    extensions_of(ask(Request::ExtensionUnpair { key }).await?)
}

/// Remove a plugin along with its settings and its state. An external one
/// only: a built-in one is built with the daemon and there is nothing to
/// delete.
#[tauri::command]
async fn plugin_remove(id: String) -> Result<(), String> {
    match ask(Request::PluginRemove { id }).await? {
        // The daemon answers with a fresh list; the shell will re-read it
        // itself anyway, so all that matters here is that it is done.
        Response::Plugins { .. } | Response::Done => Ok(()),
        Response::Error { message } => Err(humanize(&message)),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

/// Switch a plugin on or off. Switching on is the person's consent to what the
/// plugin asks for.
#[tauri::command]
async fn plugin_enable(id: String, on: bool) -> Result<(), String> {
    match ask(Request::PluginEnable { id, on }).await? {
        // The daemon answers with a fresh list; the shell will re-read it
        // itself anyway, so all that matters here is that it is done.
        Response::Plugins { .. } | Response::Done => Ok(()),
        Response::Error { message } => Err(humanize(&message)),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

/// The shared path for every operation on the vault: each of them answers
/// with a state.
async fn vault_op(req: Request) -> Result<VaultState, String> {
    match ask(req).await? {
        Response::Vault { state } => Ok(state),
        Response::Error { message } => Err(humanize(&message)),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

/// Messages out of `rbw`'s depths come in English. What goes outwards is a
/// **code** rather than finished text: the translation is the interface's
/// business, and it has the person's language. An unfamiliar message passes
/// through as it is, so that no diagnosis is lost.
pub(crate) fn humanize(message: &str) -> String {
    const TABLE: &[(&str, &str)] = &[
        ("Password is incorrect", "err.badPassword"),
        // This is how Vaultwarden answers a wrong `masterPasswordHash` in
        // account operations (a password change, the second factor, an export);
        // the key is the same as the daemon's on a local check.
        ("Invalid password", "err.badPassword"),
        ("Username or password is incorrect", "err.badCredentials"),
        ("Two-step token is invalid", "err.badTwoFactor"),
        ("two factor required", "err.twoFactorRequired"),
        ("error connecting to server", "err.unreachable"),
        ("failed to connect", "err.unreachable"),
        ("invalid or expired", "err.sessionExpired"),
    ];
    for (needle, code) in TABLE {
        if message.contains(needle) {
            return (*code).to_string();
        }
    }
    message.to_string()
}

#[tauri::command]
async fn vault_setup(
    base_url: String,
    email: String,
    identity_url: Option<String>,
) -> Result<VaultState, String> {
    vault_op(Request::Setup { base_url, email, identity_url }).await
}

#[tauri::command]
async fn vault_config() -> Result<serde_json::Value, String> {
    match ask(Request::Config).await? {
        Response::Config { base_url, email, identity_url } => Ok(serde_json::json!({
            "base_url": base_url,
            "email": email,
            "identity_url": identity_url,
        })),
        Response::Error { message } => Err(message),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

/// The answer to an attempt at logging in: either we are in, or the server
/// asks for a second factor.
#[derive(serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum LoginReply {
    Done { state: VaultState },
    TwoFactor { providers: Vec<TwoFactorProvider> },
}

/// The shared path for everything that ends in a login: logging in itself, and
/// the account operations after which the server resets the tokens and the
/// daemon logs in again.
async fn login_op(req: Request) -> Result<LoginReply, String> {
    match ask(req).await? {
        Response::Vault { state } => Ok(LoginReply::Done { state }),
        Response::TwoFactorRequired { providers } => Ok(LoginReply::TwoFactor { providers }),
        Response::Error { message } => Err(humanize(&message)),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

/// The operations whose only useful answer is "done".
async fn done_op(req: Request) -> Result<(), String> {
    match ask(req).await? {
        Response::Done => Ok(()),
        Response::Error { message } => Err(humanize(&message)),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

#[tauri::command]
async fn vault_login(password: Secret) -> Result<LoginReply, String> {
    login_op(Request::Login { password }).await
}

// -- The account ------------------------------------------------------------

#[tauri::command]
async fn account_profile() -> Result<AccountProfile, String> {
    match ask(Request::AccountProfile).await? {
        Response::AccountProfile { profile } => Ok(profile),
        Response::Error { message } => Err(humanize(&message)),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

#[tauri::command]
async fn account_set_profile(name: String, hint: Option<String>) -> Result<(), String> {
    done_op(Request::AccountSetProfile { name, hint }).await
}

#[tauri::command]
async fn account_set_avatar(color: Option<String>) -> Result<(), String> {
    done_op(Request::AccountSetAvatar { color }).await
}

#[tauri::command]
async fn account_change_password(current: Secret, new: Secret, hint: Option<String>) -> Result<LoginReply, String> {
    login_op(Request::AccountChangePassword { current, new, hint }).await
}

#[tauri::command]
async fn account_email_token(master_password: Secret, new_email: String) -> Result<(), String> {
    done_op(Request::AccountEmailToken { master_password, new_email }).await
}

#[tauri::command]
async fn account_change_email(master_password: Secret, new_email: String, token: Secret) -> Result<LoginReply, String> {
    login_op(Request::AccountChangeEmail { master_password, new_email, token }).await
}

#[tauri::command]
async fn account_change_kdf(master_password: Secret, kdf: KdfInfo) -> Result<LoginReply, String> {
    login_op(Request::AccountChangeKdf { master_password, kdf }).await
}

#[tauri::command]
async fn account_deauthorize(master_password: Secret) -> Result<LoginReply, String> {
    login_op(Request::AccountDeauthorize { master_password }).await
}

#[tauri::command]
async fn account_delete(master_password: Secret) -> Result<VaultState, String> {
    vault_op(Request::AccountDelete { master_password }).await
}

#[tauri::command]
async fn account_purge(master_password: Secret) -> Result<VaultState, String> {
    vault_op(Request::AccountPurge { master_password }).await
}

async fn two_factor_op(req: Request) -> Result<TwoFactorStatus, String> {
    match ask(req).await? {
        Response::TwoFactorStatus { status } => Ok(status),
        Response::Error { message } => Err(humanize(&message)),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

#[tauri::command]
async fn two_factor_status() -> Result<TwoFactorStatus, String> {
    two_factor_op(Request::TwoFactorStatus).await
}

#[tauri::command]
async fn two_factor_authenticator_setup(master_password: Secret) -> Result<AuthenticatorSetup, String> {
    match ask(Request::TwoFactorAuthenticatorSetup { master_password }).await? {
        Response::AuthenticatorSetup { setup } => Ok(setup),
        Response::Error { message } => Err(humanize(&message)),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

#[tauri::command]
async fn two_factor_authenticator_enable(master_password: Secret, key: Secret, token: Secret) -> Result<TwoFactorStatus, String> {
    two_factor_op(Request::TwoFactorAuthenticatorEnable { master_password, key, token }).await
}

#[tauri::command]
async fn two_factor_email_setup(master_password: Secret) -> Result<EmailTwoFactorSetup, String> {
    match ask(Request::TwoFactorEmailSetup { master_password }).await? {
        Response::EmailTwoFactorSetup { setup } => Ok(setup),
        Response::Error { message } => Err(humanize(&message)),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

#[tauri::command]
async fn two_factor_email_send(master_password: Secret, email: String) -> Result<(), String> {
    done_op(Request::TwoFactorEmailSend { master_password, email }).await
}

#[tauri::command]
async fn two_factor_email_enable(master_password: Secret, email: String, token: Secret) -> Result<TwoFactorStatus, String> {
    two_factor_op(Request::TwoFactorEmailEnable { master_password, email, token }).await
}

#[tauri::command]
async fn two_factor_disable(master_password: Secret, provider: u8) -> Result<TwoFactorStatus, String> {
    two_factor_op(Request::TwoFactorDisable { master_password, provider }).await
}

#[tauri::command]
async fn two_factor_recovery_code(window: tauri::WebviewWindow, master_password: Secret) -> Result<seal::Sealed, String> {
    match ask(Request::TwoFactorRecoveryCode { master_password }).await? {
        Response::RecoveryCode { code } => seal::seal(window.label(), &zeroize::Zeroizing::new(code)),
        Response::Error { message } => Err(humanize(&message)),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

#[tauri::command]
async fn devices() -> Result<Vec<Device>, String> {
    match ask(Request::Devices).await? {
        Response::Devices { devices } => Ok(devices),
        Response::Error { message } => Err(humanize(&message)),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

/// Exporting the vault into a file a person chooses.
///
/// The contents do not enter the web layer: there they would settle in the
/// page's memory and in a debugger's snapshots. The daemon gives the text here,
/// and from here it goes straight to disk under mode 0600 — these are
/// unencrypted passwords. `None` means the dialogue was closed and nothing was
/// written.
#[tauri::command]
async fn export_vault(app: tauri::AppHandle, master_password: Secret, format: ExportFormat) -> Result<Option<String>, String> {
    let (filename, content) = match ask(Request::ExportVault { master_password, format }).await? {
        Response::Export { filename, content } => (filename, content),
        Response::Error { message } => return Err(humanize(&message)),
        other => return Err(format!("an unexpected answer from the daemon: {other:?}")),
    };
    let ext = match format {
        ExportFormat::Json => "json",
        ExportFormat::Csv => "csv",
    };
    // The dialogue blocks: it is waited for on a thread of its own rather than
    // on the runtime.
    let picked = tauri::async_runtime::spawn_blocking(move || {
        use tauri_plugin_dialog::DialogExt as _;
        app.dialog().file().set_file_name(&filename).add_filter(ext.to_uppercase(), &[ext]).blocking_save_file()
    })
    .await
    .map_err(|e| format!("an internal error: {e}"))?;
    let Some(path) = picked else { return Ok(None) };
    let path = path.into_path().map_err(|e| e.to_string())?;
    write_private(&path, content.as_bytes()).map_err(|e| format!("the file would not write: {e}"))?;
    Ok(Some(path.display().to_string()))
}

/// Writes a file only its owner can read.
fn write_private(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    opts.open(path)?.write_all(bytes)
}

#[tauri::command]
async fn pin_set(pin: Secret, master_password: Secret) -> Result<VaultState, String> {
    vault_op(Request::PinSet { pin, master_password }).await
}

#[tauri::command]
async fn pin_clear() -> Result<VaultState, String> {
    vault_op(Request::PinClear).await
}

#[tauri::command]
async fn pin_unlock(pin: Secret) -> Result<VaultState, String> {
    vault_op(Request::PinUnlock { pin }).await
}

/// `remember`: "remember this device" — the daemon keeps the server's token
/// sealed and the next login skips the second factor. Absent from an older
/// window, it is no.
#[tauri::command]
async fn vault_login_two_factor(provider: u8, token: Secret, remember: Option<bool>) -> Result<VaultState, String> {
    vault_op(Request::LoginTwoFactor { provider, token, remember: remember.unwrap_or(false) }).await
}

/// Forgets the active account's damaged session (`VaultState::Damaged`) so
/// the person can sign in again; the daemon refuses it for a session that
/// reads.
#[tauri::command]
async fn vault_reset_session() -> Result<VaultState, String> {
    vault_op(Request::ResetSession).await
}

#[tauri::command]
async fn vault_send_two_factor_email() -> Result<(), String> {
    match ask(Request::SendTwoFactorEmail).await? {
        Response::TwoFactorEmailSent => Ok(()),
        Response::Error { message } => Err(humanize(&message)),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

#[tauri::command]
async fn vault_unlock(password: Secret) -> Result<VaultState, String> {
    vault_op(Request::Unlock { password }).await
}

#[tauri::command]
async fn vault_lock() -> Result<VaultState, String> {
    vault_op(Request::Lock).await
}

#[tauri::command]
async fn vault_sync() -> Result<VaultState, String> {
    vault_op(Request::Sync).await
}

#[tauri::command]
async fn biometric_unlock() -> Result<VaultState, String> {
    vault_op(Request::BiometricUnlock).await
}

#[tauri::command]
async fn biometric_remember(password: Secret) -> Result<VaultState, String> {
    vault_op(Request::BiometricRemember { password }).await
}

#[tauri::command]
async fn biometric_forget() -> Result<VaultState, String> {
    vault_op(Request::BiometricForget).await
}

#[tauri::command]
async fn vault_items() -> Result<Catalog, String> {
    match ask(Request::Items).await? {
        Response::Items { catalog } => Ok(catalog),
        Response::Error { message } => Err(humanize(&message)),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

#[derive(serde::Serialize)]
struct AccountList {
    accounts: Vec<AccountView>,
    active: Option<String>,
}

#[tauri::command]
async fn vault_accounts() -> Result<AccountList, String> {
    match ask(Request::Accounts).await? {
        Response::Accounts { accounts, active } => Ok(AccountList { accounts, active }),
        Response::Error { message } => Err(humanize(&message)),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

#[tauri::command]
async fn vault_switch_account(id: String) -> Result<VaultState, String> {
    vault_op(Request::SwitchAccount { id }).await
}

#[tauri::command]
async fn vault_logout(id: String) -> Result<VaultState, String> {
    vault_op(Request::Logout { id }).await
}

#[tauri::command]
async fn item_detail(entry_id: String) -> Result<ItemDetail, String> {
    match ask(Request::ItemDetail { entry_id }).await? {
        Response::Detail { detail } => Ok(detail),
        Response::Error { message } => Err(humanize(&message)),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

#[tauri::command]
async fn trash_item(entry_id: String) -> Result<VaultState, String> {
    vault_op(Request::TrashItem { entry_id }).await
}

#[tauri::command]
async fn restore_item(entry_id: String) -> Result<VaultState, String> {
    vault_op(Request::RestoreItem { entry_id }).await
}

#[tauri::command]
async fn purge_items(entry_ids: Vec<String>) -> Result<VaultState, String> {
    vault_op(Request::PurgeItems { entry_ids }).await
}

#[tauri::command]
async fn recent_items() -> Result<Vec<String>, String> {
    match ask(Request::RecentItems).await? {
        Response::Recent { ids } => Ok(ids),
        Response::Error { message } => Err(humanize(&message)),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

#[tauri::command]
async fn generator_history() -> Result<GeneratorHistory, String> {
    match ask(Request::GeneratorHistory).await? {
        Response::History { history } => Ok(history),
        Response::Error { message } => Err(humanize(&message)),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

#[tauri::command]
async fn forget_generated(taken: bool) -> Result<GeneratorHistory, String> {
    match ask(Request::ForgetGenerated { taken }).await? {
        Response::History { history } => Ok(history),
        Response::Error { message } => Err(humanize(&message)),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

#[tauri::command]
async fn remember_opened(entry_id: String) -> Result<(), String> {
    match ask(Request::RememberOpened { entry_id }).await? {
        Response::Pong => Ok(()),
        Response::Error { message } => Err(humanize(&message)),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

/// Copies a password of the generator's history by its place: the daemon puts
/// it on the clipboard; the window never holds it.
#[tauri::command]
async fn copy_generated(taken: bool, index: usize) -> Result<u64, String> {
    match ask(Request::CopyGenerated { taken, index }).await? {
        Response::Copied { clears_in } => Ok(clears_in),
        Response::Error { message } => Err(humanize(&message)),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

#[tauri::command]
async fn reveal_generated(window: tauri::WebviewWindow, taken: bool, index: usize) -> Result<seal::Sealed, String> {
    match ask(Request::RevealGenerated { taken, index }).await? {
        Response::Secret { value } => seal::seal(window.label(), &value),
        Response::Error { message } => Err(humanize(&message)),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

#[tauri::command]
async fn generate_password(window: tauri::WebviewWindow, spec: GeneratorSpec) -> Result<seal::Sealed, String> {
    match ask(Request::GeneratePassword { spec }).await? {
        Response::Secret { value } => seal::seal(window.label(), &value),
        Response::Error { message } => Err(humanize(&message)),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

/// Opens a site or a mail in the person's own apps: only an `https`, `http`
/// or `mailto` address, the rest is refused rather than handed to the system.
#[tauri::command]
fn open_link(url: String) -> Result<(), String> {
    let scheme = url.split_once(':').map(|(s, _)| s.to_ascii_lowercase()).unwrap_or_default();
    if !matches!(scheme.as_str(), "https" | "http" | "mailto") || url.chars().any(char::is_control) {
        return Err(format!("not a site or a mail address: {url:?}"));
    }
    std::process::Command::new("/usr/bin/open").arg(&url).status().map_err(|e| format!("open would not start: {e}")).and_then(|s| if s.success() { Ok(()) } else { Err(format!("open could not open {url:?}")) })
}

#[tauri::command]
async fn copy_text(value: Secret) -> Result<u64, String> {
    match ask(Request::CopyText { value }).await? {
        Response::Copied { clears_in } => Ok(clears_in),
        Response::Error { message } => Err(humanize(&message)),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

#[tauri::command]
async fn rename_folder(folder_id: String, name: String) -> Result<VaultState, String> {
    vault_op(Request::RenameFolder { folder_id, name }).await
}

#[tauri::command]
async fn delete_folder(folder_id: String) -> Result<VaultState, String> {
    vault_op(Request::DeleteFolder { folder_id }).await
}

#[tauri::command]
async fn rename_collection(
    org_id: String,
    collection_id: String,
    name: String,
) -> Result<VaultState, String> {
    vault_op(Request::RenameCollection { org_id, collection_id, name }).await
}

#[tauri::command]
async fn delete_collection(org_id: String, collection_id: String) -> Result<VaultState, String> {
    vault_op(Request::DeleteCollection { org_id, collection_id }).await
}

#[tauri::command]
async fn remove_member(org_id: String, member_id: String) -> Result<VaultState, String> {
    vault_op(Request::RemoveMember { org_id, member_id }).await
}

/// `fingerprint` is the words the person was shown (`member_fingerprint`):
/// the daemon refuses if the member's key no longer makes them.
#[tauri::command]
async fn confirm_member(
    org_id: String,
    member_id: String,
    user_id: String,
    fingerprint: Vec<String>,
) -> Result<VaultState, String> {
    vault_op(Request::ConfirmMember { org_id, member_id, user_id, fingerprint }).await
}

/// A member's fingerprint phrase, to compare with them before confirming.
#[tauri::command]
async fn member_fingerprint(org_id: String, member_id: String, user_id: String) -> Result<Vec<String>, String> {
    match ask(Request::MemberFingerprint { org_id, member_id, user_id }).await? {
        Response::MemberFingerprint { words } => Ok(words),
        Response::Error { message } => Err(humanize(&message)),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

// -- The window's writes -------------------------------------------------------
//
// What the shared UI core asks of the desktop app (`gui/app/writes.ts`): the
// operations with an answer that names what was made, an access to
// collections that is said per collection, and two checks.

/// The answer to an operation that makes something: its identifier.
async fn created_op(req: Request) -> Result<String, String> {
    match ask(req).await? {
        Response::Created { id } => Ok(id),
        Response::Error { message } => Err(humanize(&message)),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

#[tauri::command]
async fn folder_create(name: String) -> Result<String, String> {
    created_op(Request::NewFolder { name }).await
}

#[tauri::command]
async fn collection_create(org_id: String, name: String) -> Result<String, String> {
    created_op(Request::NewCollection { org_id, name }).await
}

/// An item, in one's own vault or in an organisation's collections. The
/// draft's typed secrets are in `edit` as `Secret`s: wiped here once the
/// request is sent, and sealed on the way to the daemon.
#[tauri::command]
async fn item_create(
    kind: u8,
    folder_id: Option<String>,
    org_id: Option<String>,
    collection_ids: Vec<String>,
    edit: ItemEdit,
) -> Result<String, String> {
    created_op(Request::NewItem { kind, folder_id, org_id, collection_ids, edit }).await
}

#[tauri::command]
async fn item_set_collections(entry_id: String, collection_ids: Vec<String>) -> Result<VaultState, String> {
    vault_op(Request::SetItemCollections { entry_id, collection_ids }).await
}

#[tauri::command]
async fn members_invite(
    org_id: String,
    emails: Vec<String>,
    role: keyward_core::items::OrgRole,
    access_all: bool,
    access: Vec<keyward_core::items::CollectionAccess>,
) -> Result<VaultState, String> {
    vault_op(Request::InviteMembers { org_id, emails, role, access_all, access }).await
}

#[tauri::command]
async fn member_set(
    org_id: String,
    member_id: String,
    role: keyward_core::items::OrgRole,
    access_all: bool,
    access: Vec<keyward_core::items::CollectionAccess>,
) -> Result<VaultState, String> {
    vault_op(Request::SetMember { org_id, member_id, role, access_all, access }).await
}

/// The master password checked against the open vault; nothing changes.
#[tauri::command]
async fn verify_password(password: Secret) -> Result<bool, String> {
    match ask(Request::VerifyPassword { password }).await? {
        Response::PasswordChecked { ok } => Ok(ok),
        Response::Error { message } => Err(humanize(&message)),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

/// A passphrase made in the daemon, sealed for this webview.
#[tauri::command]
async fn generate_passphrase(
    window: tauri::WebviewWindow,
    spec: keyward_core::generator::PassphraseSpec,
) -> Result<seal::Sealed, String> {
    match ask(Request::GeneratePassphrase { spec }).await? {
        Response::Secret { value } => seal::seal(window.label(), &value),
        Response::Error { message } => Err(humanize(&message)),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

#[tauri::command]
async fn create_org(name: String, billing_email: String) -> Result<VaultState, String> {
    vault_op(Request::CreateOrg { name, billing_email }).await
}

#[tauri::command]
async fn update_org(org_id: String, name: String, billing_email: String) -> Result<VaultState, String> {
    vault_op(Request::UpdateOrg { org_id, name, billing_email }).await
}

#[tauri::command]
async fn delete_org(org_id: String, master_password: String) -> Result<VaultState, String> {
    vault_op(Request::DeleteOrg { org_id, master_password }).await
}

#[tauri::command]
fn autofill_trusted() -> bool {
    autofill::trusted()
}

#[tauri::command]
fn autofill_request_access() -> bool {
    autofill::request_access()
}

#[tauri::command]
async fn autofill_fill(app: tauri::AppHandle, entry_id: String, mode: autofill::Mode, submit: bool) -> Result<(), String> {
    autofill::fill(&app, &entry_id, mode, submit).await
}

#[tauri::command]
async fn site_icon(domain: String) -> Result<Option<String>, String> {
    match ask(Request::SiteIcon { domain }).await? {
        Response::SiteIcon { data_url } => Ok(data_url),
        Response::Error { message } => Err(humanize(&message)),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

/// Takes the gathered notifications from the daemon and hands them to the
/// system.
///
/// Polling rather than a subscription: the daemon's socket outlives a restart
/// of the window, and holding a permanent connection to it from the interface
/// means mending its breaks. Twenty seconds is the price of a delay nobody
/// notices.
fn watch_notices(app: tauri::AppHandle) {
    notices::ask_permission();
    // A notice from a plugin carries a key out of the plugin's own dictionary,
    // and the sentence is drawn here. The words come from the installed
    // package: the core has none of them compiled in.
    keyward_core::text::load_dictionaries(&keyward_core::paths::plugins_dir());

    tauri::async_runtime::spawn(async move {
        loop {
            if let Ok(Response::Notices { notices }) = ask(Request::TakeNotices).await {
                for notice in notices {
                    // What the daemon and the plugins send is a key, not a
                    // sentence: this banner is drawn by the system rather than
                    // by the window, so the words are put together here, out of
                    // the same dictionary.
                    let title = keyward_core::text::render(&notice.title);
                    let body = keyward_core::text::render(&notice.body);
                    // The notification centre is touched from the main thread:
                    // it lives bound to NSApplication, and we are on a runtime
                    // thread here.
                    let _ = app.run_on_main_thread(move || notices::show(&title, &body));
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(20)).await;
        }
    });
}

#[tauri::command]
async fn org_members(org_id: String) -> Result<Vec<OrgMember>, String> {
    match ask(Request::OrgMembers { org_id }).await? {
        Response::OrgMembers { members } => Ok(members),
        Response::Error { message } => Err(humanize(&message)),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

#[tauri::command]
async fn copy_secret(entry_id: String, field: SecretField) -> Result<u64, String> {
    match ask(Request::CopySecret { entry_id, field }).await? {
        Response::Copied { clears_in } => Ok(clears_in),
        Response::Error { message } => Err(humanize(&message)),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

/// A draft of an ssh key, made or read by the daemon: the window gets its
/// number and the public half, never the private key. "From the clipboard" is
/// read by the daemon itself — the clipboard does not pass through here.
#[tauri::command]
async fn ssh_key_draft(source: keyward_core::edits::SshDraftSource) -> Result<keyward_core::edits::SshDraftView, String> {
    match ask(Request::SshKeyDraft { source }).await? {
        Response::SshDraft { draft } => Ok(draft),
        Response::Error { message } => Err(humanize(&message)),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

/// A webview opens its sealed session: its public key in, ours out.
#[tauri::command]
fn window_seal_open(window: tauri::WebviewWindow, public: String) -> Result<String, String> {
    seal::open(window.label(), &public)
}

#[tauri::command]
async fn reveal_secret(window: tauri::WebviewWindow, entry_id: String, field: SecretField) -> Result<seal::Sealed, String> {
    match ask(Request::RevealSecret { entry_id, field }).await? {
        Response::Secret { value } => seal::seal(window.label(), &value),
        Response::Error { message } => Err(humanize(&message)),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

#[tauri::command]
async fn update_item(entry_id: String, edit: ItemEdit) -> Result<PendingEdit, String> {
    match ask(Request::UpdateItem { entry_id, edit }).await? {
        Response::Edit { edit } => Ok(edit),
        Response::Error { message } => Err(humanize(&message)),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

#[tauri::command]
async fn merge_compare(entry_ids: Vec<String>) -> Result<MergeComparison, String> {
    match ask(Request::MergeCompare { entry_ids }).await? {
        Response::MergeComparison { comparison } => Ok(comparison),
        Response::Error { message } => Err(humanize(&message)),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

#[tauri::command]
async fn merge_items(plan: MergePlan) -> Result<VaultState, String> {
    vault_op(Request::MergeItems { plan }).await
}

async fn edits_op(req: Request) -> Result<Vec<PendingEdit>, String> {
    match ask(req).await? {
        Response::Edits { edits } => Ok(edits),
        Response::Edit { .. } => Ok(Vec::new()),
        Response::Error { message } => Err(humanize(&message)),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

#[tauri::command]
async fn pending_edits() -> Result<Vec<PendingEdit>, String> {
    edits_op(Request::Edits).await
}

#[tauri::command]
async fn retry_edit(id: String) -> Result<Vec<PendingEdit>, String> {
    let _ = ask(Request::RetryEdit { id }).await?;
    edits_op(Request::Edits).await
}

#[tauri::command]
async fn rollback_edit(id: String) -> Result<Vec<PendingEdit>, String> {
    let _ = ask(Request::RollbackEdit { id }).await?;
    edits_op(Request::Edits).await
}

#[tauri::command]
async fn regenerate_password(entry_id: String, spec: GeneratorSpec) -> Result<PendingEdit, String> {
    match ask(Request::RegeneratePassword { entry_id, spec }).await? {
        Response::Edit { edit } => Ok(edit),
        Response::Error { message } => Err(humanize(&message)),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

#[tauri::command]
async fn restore_totp(entry_id: String) -> Result<PendingEdit, String> {
    match ask(Request::RestoreTotp { entry_id }).await? {
        Response::Edit { edit } => Ok(edit),
        Response::Error { message } => Err(humanize(&message)),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

#[tauri::command]
async fn discard_edit(id: String) -> Result<Vec<PendingEdit>, String> {
    edits_op(Request::DiscardEdit { id }).await
}

#[tauri::command]
async fn get_settings() -> Result<AppSettings, String> {
    match ask(Request::GetSettings).await? {
        Response::Settings { settings } => Ok(settings),
        Response::Error { message } => Err(humanize(&message)),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

#[tauri::command]
async fn set_settings(settings: AppSettings) -> Result<AppSettings, String> {
    match ask(Request::SetSettings { settings }).await? {
        Response::Settings { settings } => Ok(settings),
        Response::Error { message } => Err(humanize(&message)),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

/// What is really the matter with the sensor: whether it is available, and if
/// not, why, plus the last complaint. The settings show this instead of a
/// breezy "set up" over a broken Touch ID.
#[derive(serde::Serialize)]
struct BiometricState {
    available: bool,
    problem: Option<String>,
    last_failure: Option<String>,
}

#[tauri::command]
fn biometric_state() -> BiometricState {
    let problem = keyward_vault::biometric::diagnose();
    BiometricState {
        available: problem.is_none(),
        problem,
        last_failure: keyward_vault::biometric::last_failure(),
    }
}

/// A press in the menu bar hides the window or shows it.
///
/// Checking `is_visible` alone is not enough: a window can be visible and lie
/// under somebody else's, and then "hide" looks like "nothing happened". So
/// only what is both visible and focused is hidden.
fn toggle_window(app: &tauri::AppHandle) {
    let Some(win) = app.get_webview_window("main") else { return };
    let visible = win.is_visible().unwrap_or(false);
    let focused = win.is_focused().unwrap_or(false);
    if visible && focused {
        let _ = win.hide();
    } else {
        bring_to_front(app);
    }
}

/// Show our window above everybody else's and give it the keyboard.
///
/// `show` and `set_focus` are not enough: once the window has been hidden by
/// the close button, or the focus handed back to another application after a
/// fill, the next show put it back where it had been — under somebody else's
/// windows, with the other application still active. The application is
/// activated explicitly, ignoring the others, and the window is ordered to
/// the front regardless of who is active.
fn bring_to_front(app: &tauri::AppHandle) {
    let Some(win) = app.get_webview_window("main") else { return };
    let _ = win.show();
    let _ = win.unminimize();
    #[cfg(target_os = "macos")]
    {
        // Back into the Dock and the Cmd+Tab list, in case the close button
        // took it out.
        let _ = app.set_activation_policy(tauri::ActivationPolicy::Regular);
        let _ = app.show();
        let w = win.clone();
        let _ = app.run_on_main_thread(move || {
            use objc2_app_kit::{NSApplication, NSApplicationActivationOptions, NSRunningApplication, NSWindow};
            let Some(mtm) = objc2::MainThreadMarker::new() else { return };
            let ns_app = NSApplication::sharedApplication(mtm);
            // Every way there is: which of them the system honours depends on
            // the version of macOS, and since 14 "ignoring other apps" alone
            // left the window in front while the keyboard stayed with the
            // other application.
            #[allow(deprecated)]
            ns_app.activateIgnoringOtherApps(true);
            ns_app.activate();
            #[allow(deprecated)]
            NSRunningApplication::currentApplication()
                .activateWithOptions(NSApplicationActivationOptions::ActivateIgnoringOtherApps);
            if let Ok(ptr) = w.ns_window() {
                // SAFETY: tauri hands out the live NSWindow of this webview
                // window, and we are on the main thread.
                let ns: &NSWindow = unsafe { &*(ptr as *const NSWindow) };
                ns.orderFrontRegardless();
                ns.makeKeyAndOrderFront(None);
            }
        });
    }
    let _ = win.set_focus();
}

/// Takes the daemon off its service, so that launchd does not bring it
/// straight back up.
///
/// `KeepAlive` in the plist exists so that the daemon lives on after a crash;
/// on a deliberate quit that same setting gets in the way. `bootout` unloads
/// the service until the next login, and the application brings it back at
/// start-up.
#[cfg(target_os = "macos")]
fn stop_service() -> std::io::Result<()> {
    let uid = unsafe { libc::getuid() };
    std::process::Command::new("/bin/launchctl")
        .args(["bootout", &format!("gui/{uid}/me.loper")])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|_| ())
}

/// Brings the daemon up when it is unloaded: after a deliberate quit the
/// service is off, and without this the application would open onto
/// nothing.
#[cfg(target_os = "macos")]
fn start_service() {
    let uid = unsafe { libc::getuid() };
    let label = format!("gui/{uid}/me.loper");
    let plist = dirs_home().join("Library/LaunchAgents/me.loper.plist");
    if !plist.exists() {
        return;
    }
    let run = |args: &[&str]| {
        let _ = std::process::Command::new("/bin/launchctl")
            .args(args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    };
    run(&["bootstrap", &format!("gui/{uid}"), &plist.to_string_lossy()]);
    run(&["kickstart", &label]);
}

#[cfg(target_os = "macos")]
fn dirs_home() -> std::path::PathBuf {
    std::env::var_os("HOME").map(std::path::PathBuf::from).unwrap_or_default()
}

/// Hides the window from screen recording and screenshots, or allows them.
///
/// `sharingType = none` is what 1Password and the Bitwarden client do: the
/// window goes black in screenshots, in screen recordings and in a Zoom share.
/// Without it a revealed password, a one-time code and the generator's history
/// reach any recording somebody is making alongside, and macOS's history of
/// screenshots. Allowing it is a deliberate setting (`allow_screen_capture`):
/// it is needed to show the window over remote access, or to capture it for
/// documentation.
#[cfg(target_os = "macos")]
fn set_capture(window: &tauri::WebviewWindow, allow: bool) {
    use objc2::rc::Retained;
    use objc2::runtime::AnyObject;
    use objc2_app_kit::{NSWindow, NSWindowSharingType};

    let Ok(handle) = window.ns_window() else { return };
    // SAFETY: Tauri gives a pointer to this window's live NSWindow.
    let ns: Option<Retained<NSWindow>> =
        unsafe { Retained::retain(handle.cast::<AnyObject>().cast::<NSWindow>()) };
    if let Some(ns) = ns {
        let kind = if allow { NSWindowSharingType::ReadOnly } else { NSWindowSharingType::None };
        ns.setSharingType(kind);
    }
}

/// Hides the system's three window buttons: the window draws its own in the
/// strip (ui/core's WindowButtons), placed and coloured as the window is.
/// macOS shows them again after full screen and at times on a resize, so this
/// runs on those events too.
#[cfg(target_os = "macos")]
fn hide_window_buttons(ns_window: tauri::Result<*mut std::ffi::c_void>) {
    use objc2::rc::Retained;
    use objc2::runtime::AnyObject;
    use objc2_app_kit::{NSWindow, NSWindowButton};

    let handle = match ns_window {
        Ok(h) => h,
        Err(e) => {
            eprintln!("the window's own buttons stay: no NSWindow ({e})");
            return;
        }
    };
    // SAFETY: Tauri gives a pointer to this window's live NSWindow.
    let ns: Option<Retained<NSWindow>> =
        unsafe { Retained::retain(handle.cast::<AnyObject>().cast::<NSWindow>()) };
    let Some(ns) = ns else {
        eprintln!("the window's own buttons stay: the NSWindow is gone");
        return;
    };
    for kind in [NSWindowButton::CloseButton, NSWindowButton::MiniaturizeButton, NSWindowButton::ZoomButton] {
        if let Some(button) = ns.standardWindowButton(kind) {
            button.setHidden(true);
        }
    }
}

/// Whether the menu bar icon is what the window comes back from after the
/// close button (together with `KEEP_IN_DOCK`, whether it hides at all).
///
/// An atomic rather than a trip to the settings on every close: the window's
/// event handler is synchronous, and the settings lie in a file the daemon may
/// have open. `apply_window_prefs` updates the value.
static KEEP_IN_TRAY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

/// Whether the Dock icon stays once the window is hidden by the close button.
static KEEP_IN_DOCK: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Applies to the window what belongs to the window rather than the daemon:
/// the screenshot permission and the close button's behaviour. It reads the
/// settings file directly, so it works both before the daemon is up and after a
/// save from the interface.
fn apply_prefs(app: &tauri::AppHandle) {
    let settings = AppSettings::load();
    KEEP_IN_TRAY.store(settings.keep_in_tray, std::sync::atomic::Ordering::Relaxed);
    KEEP_IN_DOCK.store(settings.keep_in_dock, std::sync::atomic::Ordering::Relaxed);
    #[cfg(target_os = "macos")]
    if let Some(win) = app.get_webview_window("main") {
        set_capture(&win, settings.allow_screen_capture);
    }
    #[cfg(not(target_os = "macos"))]
    let _ = app;
}

/// The interface calls this after saving the settings, so that the window
/// changes its behaviour at once and without a restart.
#[tauri::command]
async fn apply_window_prefs(app: tauri::AppHandle) -> Result<(), String> {
    // NSWindow's properties are touched from the main thread.
    let handle = app.clone();
    app.run_on_main_thread(move || apply_prefs(&handle)).map_err(|e| e.to_string())
}

/// The main window is described in tauri.conf.json (`"create": false`) and
/// built here, on the window's one page.
fn open_main_window(app: &tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = app
        .config()
        .app
        .windows
        .iter()
        .find(|w| w.label == "main")
        .ok_or("tauri.conf.json describes no \"main\" window")?
        .clone();
    config.url = tauri::WebviewUrl::App("app.html".into());
    tauri::WebviewWindowBuilder::from_config(app.handle(), &config)?.build()?;
    Ok(())
}

/// Quitting the application altogether: the daemon dies, the keys are
/// forgotten, the agent's sockets come down. The window used to close while the
/// vault stayed open until the automatic lock, and ssh went on signing as if
/// nothing had happened.
fn quit_app(app: tauri::AppHandle) {
    tauri::async_runtime::spawn(async move {
        let _ = ask(Request::Shutdown).await;
        #[cfg(target_os = "macos")]
        let _ = stop_service();
        app.exit(0);
    });
}


pub fn run() {
    // The window types passwords and shows them: no core dump, no debugger.
    keyward_core::harden::process();
    actionlog::init();
    tauri::Builder::default()
        // The autofill hotkey: Cmd+Shift+L in any window. The foreground
        // application's context is taken first, while the focus is still with
        // it, and only then is our own window shown.
        .plugin(
            tauri_plugin_global_shortcut::Builder::new()
                .with_handler(|app, _shortcut, event| {
                    use tauri::Emitter as _;
                    if event.state() != tauri_plugin_global_shortcut::ShortcutState::Pressed {
                        return;
                    }
                    // A held key repeats dozens of times a second, and every
                    // capture of a context means Accessibility and sometimes
                    // AppleScript: the window froze. One capture a second.
                    {
                        static LAST_PRESS: std::sync::Mutex<Option<std::time::Instant>> = std::sync::Mutex::new(None);
                        let mut last = LAST_PRESS.lock().unwrap_or_else(|e| e.into_inner());
                        if last.is_some_and(|t| t.elapsed() < std::time::Duration::from_millis(1000)) {
                            return;
                        }
                        *last = Some(std::time::Instant::now());
                    }
                    let ctx = autofill::capture();
                    // Pressing again inside our own window changes nothing:
                    // the target for typing was chosen earlier.
                    if autofill::is_own(&ctx) {
                        return;
                    }
                    // With no active text field there is nowhere to type: the
                    // key is skipped quietly, so that the window does not jump
                    // out at every Cmd+Shift+L in the middle of other work.
                    if !autofill::field_is_editable(&ctx) {
                        return;
                    }
                    bring_to_front(app);
                    let _ = app.emit("autofill", ctx);
                })
                .build(),
        )
        // The system's save dialogue, for exporting the vault.
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            window_seal_open,
            account_profile,
            account_set_profile,
            account_set_avatar,
            account_change_password,
            account_email_token,
            account_change_email,
            account_change_kdf,
            account_deauthorize,
            account_delete,
            account_purge,
            two_factor_status,
            two_factor_authenticator_setup,
            two_factor_authenticator_enable,
            two_factor_email_setup,
            two_factor_email_send,
            two_factor_email_enable,
            two_factor_disable,
            two_factor_recovery_code,
            devices,
            export_vault,
            pin_set,
            pin_clear,
            pin_unlock,
            apply_window_prefs,
            daemon_status,
            daemon_probe,
            plugins,
            plugin_call,
            plugin_call_with_fields,
            plugin_pick,
            plugin_install,
            plugin_catalog,
            plugin_sources,
            plugin_trust,
            extensions,
            extension_pair,
            extension_unpair,
            plugin_remove,
            plugin_enable,
            vault_setup,
            vault_config,
            vault_items,
            item_detail,
            org_members,
            trash_item,
            restore_item,
            purge_items,
            generator_history,
            recent_items,
            remember_opened,
            forget_generated,
            generate_password,
            copy_generated,
            reveal_generated,
            copy_text,
            open_link,
            rename_folder,
            delete_folder,
            rename_collection,
            delete_collection,
            remove_member,
            confirm_member,
            member_fingerprint,
            folder_create,
            collection_create,
            item_create,
            item_set_collections,
            members_invite,
            member_set,
            verify_password,
            generate_passphrase,
            create_org,
            update_org,
            delete_org,
            site_icon,
            autofill_trusted,
            autofill_request_access,
            autofill_fill,
            copy_secret,
            ssh_key_draft,
            reveal_secret,
            update_item,
            pending_edits,
            retry_edit,
            rollback_edit,
            restore_totp,
            merge_compare,
            merge_items,
            regenerate_password,
            actionlog::ui_log,
            discard_edit,
            get_settings,
            set_settings,
            vault_accounts,
            vault_switch_account,
            vault_logout,
            biometric_state,
            vault_login,
            vault_login_two_factor,
            vault_reset_session,
            vault_send_two_factor_email,
            vault_unlock,
            vault_lock,
            vault_sync,
            biometric_unlock,
            biometric_remember,
            biometric_forget,
        ])
        .setup(|app| {
            // First of all: the rest of the setup reaches for the "main" window.
            open_main_window(app)?;

            {
                use tauri_plugin_global_shortcut::{Code, GlobalShortcutExt as _, Modifiers, Shortcut};
                let fill = Shortcut::new(Some(Modifiers::SUPER | Modifiers::SHIFT), Code::KeyL);
                if let Err(e) = app.global_shortcut().register(fill) {
                    eprintln!("the autofill hotkey was not registered: {e}");
                }
            }
            #[cfg(target_os = "macos")]
            start_service();

            // The window shows the notifications, not the daemon: under
            // launchd the daemon has neither a bundle nor the system's
            // permission, and through the scripting engine it would look like an
            // alert from somebody else.
            watch_notices(app.handle().clone());

            // Real macOS glass: an NSVisualEffectView under the window. An
            // imitation with a CSS blur blurs only what is drawn inside the
            // window, and against a desktop it looks like dirt.
            #[cfg(target_os = "macos")]
            if let Some(win) = app.get_webview_window("main") {
                use window_vibrancy::{apply_vibrancy, NSVisualEffectMaterial, NSVisualEffectState};
                let _ = apply_vibrancy(
                    &win,
                    NSVisualEffectMaterial::Sidebar,
                    Some(NSVisualEffectState::Active),
                    Some(12.0),
                );
                hide_window_buttons(win.ns_window());
            }
            // Screenshots and the close button follow the settings from the
            // first frame.
            apply_prefs(app.handle());

            // The ordinary activation policy: an icon in the Dock and
            // switching with Cmd+Tab. The menu bar item stays — the window hides
            // into it at the close button, but the application does not vanish
            // from the system the way Accessory makes it.

            // The menu bar is drawn by the system, not by the window, so the words
            // are put together here out of the shared dictionary.
            let show = MenuItem::with_id(app, "show", keyward_core::text::t("tray.show", &[]), true, None::<&str>)?;
            let reload = MenuItem::with_id(app, "reload", keyward_core::text::t("tray.reload", &[]), true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", keyward_core::text::t("tray.quit", &[]), true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &reload, &quit])?;

            TrayIconBuilder::with_id("keyward")
                // A template icon of its own: in the menu bar macOS uses the
                // alpha channel alone, so the application's icon turns into a
                // featureless white rectangle there.
                .icon(tauri::image::Image::from_bytes(include_bytes!("../icons/tray.png"))?)
                .icon_as_template(true)
                .tooltip("keyward")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id().as_ref() {
                    "show" => toggle_window(app),
                    "reload" => {
                        let app = app.clone();
                        tauri::async_runtime::spawn(async move {
                            let _ = ask(Request::Reload).await;
                            let _ = app.get_webview_window("main");
                        });
                    }
                    // Quit means quit, see `quit_app`.
                    "quit" => quit_app(app.clone()),
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        toggle_window(tray.app_handle());
                    }
                })
                .build(app)?;

            Ok(())
        })
        .on_window_event(|window, event| {
            #[cfg(target_os = "macos")]
            if matches!(event, WindowEvent::Resized(_) | WindowEvent::Focused(_)) {
                hide_window_buttons(window.ns_window());
            }
            // The close button hides the window rather than switching the
            // agent off: otherwise the ssh sockets would die with it. Keeping
            // it in the menu bar and keeping it in the Dock are two separate
            // choices; the close button means "Quit" only when both are off,
            // since then nothing would be left to bring the window back with.
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let tray = KEEP_IN_TRAY.load(std::sync::atomic::Ordering::Relaxed);
                let dock = KEEP_IN_DOCK.load(std::sync::atomic::Ordering::Relaxed);
                if tray || dock {
                    let _ = window.hide();
                    // The application is hidden along with the window: a
                    // hidden window alone left keyward active with nothing on
                    // the screen, and the keyboard went nowhere until a click.
                    #[cfg(target_os = "macos")]
                    {
                        let app = window.app_handle();
                        // Out of the Dock as well, unless asked to stay: the
                        // icon returns when the window is shown again.
                        if !dock {
                            let _ = app.set_activation_policy(tauri::ActivationPolicy::Accessory);
                        }
                        let _ = app.hide();
                    }
                } else {
                    quit_app(window.app_handle().clone());
                }
            }
        })
        .build(tauri::generate_context!())
        .expect("keyward would not assemble")
        .run(|app, event| {
            // A click on the icon in the Dock or Launchpad while the window is
            // hidden by the close button or Cmd+W: the system asks us to "open
            // again", so the window is shown rather than leaving anybody to hunt
            // for it in the menu bar.
            #[cfg(target_os = "macos")]
            if let tauri::RunEvent::Reopen { has_visible_windows, .. } = event {
                if !has_visible_windows {
                    bring_to_front(app);
                }
            }
            #[cfg(not(target_os = "macos"))]
            let _ = (app, event);
        });
}
