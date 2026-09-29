//! keyward's paths. The socket directory is kept short on purpose: `sun_path`
//! on macOS is limited to 104 bytes, and the host name goes into the socket's
//! file name.

use std::path::PathBuf;

pub fn base_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("KEYWARD_HOME") {
        return PathBuf::from(dir);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".keyward")
}

/// The daemon's public key for this run: clients open the encrypted channel
/// with it. The private half is never on disk.
pub fn daemon_public_key() -> PathBuf {
    base_dir().join("daemon.pub")
}

/// The daemon's control socket.
pub fn control_socket() -> PathBuf {
    base_dir().join("d.sock")
}

/// The directory of ssh-agent sockets, one per mapping.
pub fn agent_socket_dir() -> PathBuf {
    base_dir().join("s")
}

/// The shared agent socket holding every key: what goes into SSH_AUTH_SOCK.
pub fn shared_agent_socket() -> PathBuf {
    base_dir().join("agent.sock")
}

/// The agent socket for one host. The host name is sanitised so that no `../`
/// out of a config can walk the file out of the directory.
pub fn agent_socket(host: &str) -> PathBuf {
    let safe: String = host
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' { c } else { '_' })
        .collect();
    agent_socket_dir().join(format!("{safe}.sock"))
}

/// The file source of mappings: a bridge for the early stages, while access to
/// the vault is not yet on the `rbw` crate.
/// Where the installed plugins live: `~/.keyward/plugins`.
pub fn plugins_dir() -> PathBuf {
    base_dir().join("plugins")
}

/// A plugin's state directory: `~/.keyward/plugins/<id>`.
pub fn plugin_dir(id: &str) -> PathBuf {
    plugins_dir().join(id)
}

/// A plugin's settings, one file next to its directory.
pub fn plugin_settings(id: &str) -> PathBuf {
    base_dir().join("plugins").join(format!("{id}.json"))
}

pub fn mappings_file() -> PathBuf {
    base_dir().join("mappings.json")
}

/// The path to the `keyward` binary for the line in `ssh_config`.
///
/// `IdentityFile` is required here: with `IdentitiesOnly yes`, ssh offers only
/// the keys named in it and offers an agent key with no file not at all. The
/// socket is up, the agent answers, and ssh walks off to its own keys and gets
/// "Permission denied". No private half reaches the disk over this: the file
/// holds the public key alone, and the agent still does the signing.
///
/// It goes at the **end** of `~/.ssh/config`: ssh reads the file top to
/// bottom, and `%h` in `Match exec` is whatever is known at that line. Above
/// the `Host` blocks that is the alias from the command line (`ssh vps`) and
/// not `HostName`, so no route is found and ssh silently walks off to its own
/// keys and gets "Permission denied".
///
/// Absolute on purpose: `Match exec` runs through `/bin/sh`, where `PATH` is
/// not the one from the terminal, and from a GUI git client our binary simply
/// would not be found by its short name.
pub fn cli_path() -> String {
    let home = std::env::var("HOME").unwrap_or_default();
    let installed = PathBuf::from(&home).join(".local/bin/keyward");
    if installed.exists() {
        return installed.to_string_lossy().into_owned();
    }
    std::env::current_exe()
        .ok()
        .filter(|p| p.file_name().is_some_and(|n| n == "keyward"))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| "keyward".to_string())
}

/// Ready-made lines for `~/.ssh/config`.
pub fn ssh_config_snippet() -> String {
    format!(
        "Match exec \"{} resolve %h %r %p\"\n  IdentityAgent {dir}/%h.sock\n  IdentityFile {dir}/%h.pub\n  IdentitiesOnly yes",
        cli_path(),
        dir = agent_socket_dir().display()
    )
}

/// An account's name in file names: a hash of its id. The id is the email and
/// the server, and a file called after them told anyone listing the
/// directory whose vault lies here and where it is kept.
pub fn account_key(account_id: &str) -> String {
    use sha2::{Digest as _, Sha256};
    let digest = Sha256::new_with_prefix(b"keyward account\0").chain_update(account_id.as_bytes()).finalize();
    digest[..16].iter().map(|b| format!("{b:02x}")).collect()
}

fn account_file(prefix: &str, account_id: &str) -> PathBuf {
    base_dir().join(format!("{prefix}-{}.json", account_key(account_id)))
}

/// The name an account's file had before `account_key`: the id itself, made
/// safe for a file name.
fn legacy_account_file(prefix: &str, account_id: &str) -> PathBuf {
    let safe: String = account_id
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' { c } else { '_' })
        .collect();
    base_dir().join(format!("{prefix}-{safe}.json"))
}

const ACCOUNT_FILES: [&str; 3] = ["snapshot", "history", "passkey-uses"];

/// Moves an account's files from the names that carried its email to the
/// hashed ones. A file already under the new name is left as it is.
pub fn migrate_account_files(account_id: &str) {
    for prefix in ACCOUNT_FILES {
        let (old, new) = (legacy_account_file(prefix, account_id), account_file(prefix, account_id));
        if old.exists() && !new.exists() {
            if let Err(e) = std::fs::rename(&old, &new) {
                tracing::error!(error = %e, prefix, "an account file kept its old name, with the email in it");
            }
        }
    }
}

/// The generator's history. It lies next to the snapshot and is tied to the
/// account in the same way: passwords generated under one account have no
/// business being seen under another.
pub fn history_file(account_id: &str) -> PathBuf {
    account_file("history", account_id)
}

/// Writes a file that is ours alone from its first byte: made with 0600
/// under another name and moved into place, so there is neither a moment of
/// wider permissions nor a half-written file. Writing first and tightening
/// afterwards left a window in which the file was readable to others.
pub fn write_private(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    let tmp = path.with_file_name(name);
    let mut file = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&tmp, path)
}

/// When each passkey of the account was last used to sign in: one blob,
/// sealed with the user key, next to the history. Not on the server — a
/// sign-in must not become an edit that syncs.
pub fn passkey_uses_file(account_id: &str) -> PathBuf {
    account_file("passkey-uses", account_id)
}

/// The snapshot of an account's vault. The values in it are encrypted: the
/// same ciphertext that lies on the server.
pub fn snapshot_file(account_id: &str) -> PathBuf {
    account_file("snapshot", account_id)
}

/// The application's settings.
pub fn settings_file() -> PathBuf {
    base_dir().join("settings.json")
}

/// The register of accounts.
pub fn accounts_file() -> PathBuf {
    base_dir().join("accounts.json")
}

/// Local state: host keys remembered on first use.
pub fn known_hostkeys_file() -> PathBuf {
    base_dir().join("hostkeys.json")
}

#[cfg(test)]
mod account_tests {
    #[test]
    fn a_file_name_carries_no_email() {
        let id = "me@example.com@https://vault.example.com";
        let key = super::account_key(id);
        assert_eq!(key.len(), 32);
        assert_eq!(key, super::account_key(id), "stable");
        assert_ne!(key, super::account_key("other@example.com@https://vault.example.com"));
        for f in [super::snapshot_file(id), super::history_file(id), super::passkey_uses_file(id)] {
            let name = f.file_name().unwrap().to_string_lossy().to_string();
            assert!(!name.contains("example"), "{name}");
            assert!(name.ends_with(&format!("{key}.json")));
        }
    }
}

#[cfg(test)]
mod write_tests {
    #[test]
    fn a_private_file_is_ours_from_the_first_byte() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("kw-private-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("f.json");
        super::write_private(&path, b"one").unwrap();
        super::write_private(&path, b"two").unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "two");
        assert!(!dir.join("f.json.tmp").exists(), "nothing half-written left behind");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_name_cannot_escape_directory() {
        // The real invariant is not "the name has no dots" but "the file lies
        // inside the socket directory": no path separator may be in the name.
        let p = agent_socket("../../etc/passwd");
        assert_eq!(p.parent().unwrap(), agent_socket_dir());
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        assert!(!name.contains('/'), "a separator was left in the socket name: {name}");
        assert_eq!(name, ".._.._etc_passwd.sock");
    }

    #[test]
    fn socket_path_stays_within_sun_path_limit() {
        // 104 bytes is the macOS limit; checked on a long but real name.
        let p = agent_socket("very-long-hostname.subdomain.example-company.internal");
        assert!(p.to_string_lossy().len() < 104, "the socket path does not fit sun_path: {p:?}");
    }

    #[test]
    fn distinct_hosts_collapse_onto_one_socket_file() {
        // THE SANITISER'S MAIN TRAP: everything outside [A-Za-z0-9._-]
        // becomes `_`. Different hosts get one and the same socket file, while
        // the daemon keeps its ledger of live agents by the RAW host name
        // (daemon.rs, State::live). The second host then overwrites the first
        // one's socket, and the first keeps being handed that same path as
        // "already live" -- so ssh goes to one host with another one's key.
        assert_eq!(agent_socket("münchen.corp"), agent_socket("mänchen.corp"));
        assert_eq!(agent_socket("a:b.example.com"), agent_socket("a_b.example.com"));
        assert_eq!(agent_socket("2001:db8::1"), agent_socket("2001_db8__1"));
    }

    #[test]
    fn socket_name_is_case_preserving_though_matching_is_not() {
        // Host matching ignores case; a file name does not. On APFS (case
        // insensitive by default) this is the same file, while in the live
        // HashMap they are two different keys: a socket rebuilt for nothing.
        assert_ne!(agent_socket("Git.Example.com"), agent_socket("git.example.com"));
    }

    #[test]
    fn real_long_hostname_overflows_sun_path() {
        // DEFECT: the 104 bytes of sun_path are checked on a short example
        // only. A genuinely long name (DNS allows 253 bytes) will not bring the
        // socket up: bind fails, resolve returns an error, and ssh silently
        // walks past the agent.
        let host = format!("{}.example.com", "a".repeat(200));
        let p = agent_socket(&host);
        assert!(p.to_string_lossy().len() > 104,
                "expected to overrun sun_path, got {} bytes", p.to_string_lossy().len());
    }

    #[test]
    fn empty_host_still_produces_a_socket_path() {
        // DEFECT: an empty %h gives a `.sock` file -- hidden, in the socket directory.
        assert_eq!(agent_socket("").file_name().unwrap(), ".sock");
    }
}
