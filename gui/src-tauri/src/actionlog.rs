//! The window's log of actions: `~/.keyward/gui.log`.
//!
//! Every command the window runs is written down — its name, how it ended and
//! how long it took — so that a bug can be followed back through what a person
//! did. Values never are: not a password, not a code, not a password the
//! generator made. A request to the daemon is written through its Debug, which
//! hides every secret it carries; an answer only by its kind; an error with
//! anything in quotes blanked out, since a parser's complaint quotes the value
//! it choked on.

use std::sync::Mutex;

/// Past this the log is moved aside to `gui.log.1` at start, and a new one
/// begun: enough history to follow a bug, not a file that grows for ever.
const MAX_BYTES: u64 = 5 * 1024 * 1024;

/// Commands the window runs over and over on its own — polls and refreshes.
/// They go to the debug level: the log is for what a person did.
const ROUTINE: &[&str] = &[
    "daemon_status",
    "get_settings",
    "plugins",
    "pending_edits",
    "catalog",
    "items",
    "site_icon",
    "take_notices",
    "recent_items",
    "accounts",
    "account_profile",
    "autofill_trusted",
    "autofill_context",
    "daemon_ping",
    "ui_log",
];

struct File(Mutex<std::fs::File>);

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for File {
    type Writer = FileGuard<'a>;
    fn make_writer(&'a self) -> Self::Writer {
        FileGuard(self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner))
    }
}

struct FileGuard<'a>(std::sync::MutexGuard<'a, std::fs::File>);

impl std::io::Write for FileGuard<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

/// Opens the log and routes the window's tracing into it. Without a log the
/// window still works: a failure here is not a reason to stop.
pub fn init() {
    let path = keyward_core::paths::base_dir().join("gui.log");
    if std::fs::metadata(&path).is_ok_and(|m| m.len() > MAX_BYTES) {
        let _ = std::fs::rename(&path, path.with_extension("log.1"));
    }
    let Ok(file) = std::fs::OpenOptions::new().create(true).append(true).open(&path) else { return };
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    // Other people's crates stay silent: a network crate's trace carries
    // headers, and a token is among them.
    let filter = tracing_subscriber::EnvFilter::try_from_env("KEYWARD_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
        .add_directive("hyper=off".parse().expect("a valid directive"))
        .add_directive("reqwest=off".parse().expect("a valid directive"))
        .add_directive("tao=off".parse().expect("a valid directive"))
        .add_directive("wry=off".parse().expect("a valid directive"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .with_writer(File(Mutex::new(file)))
        .try_init();
    tracing::info!(target: "keyward::gui", version = env!("CARGO_PKG_VERSION"), "the window started");
}

/// Anything in double quotes blanked out. A parser's error quotes the value
/// it could not read — `invalid type: string "hunter2"` — and a log is no
/// place for it. Field names are in backticks and stay.
pub fn scrub(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut inside = false;
    for c in text.chars() {
        if c == '"' {
            if inside {
                out.push_str("\"…\"");
            }
            inside = !inside;
        } else if !inside {
            out.push(c);
        }
    }
    if inside {
        out.push_str("\"…");
    }
    out
}

/// A request to the daemon and how it ended.
pub fn daemon(request: &keyward_core::proto::Request, result: &Result<keyward_core::proto::Response, String>, ms: u128) {
    let what = format!("{request:?}");
    let how = match result {
        Ok(r) => r.kind(),
        Err(e) => format!("unreachable: {}", scrub(e)),
    };
    if request.is_routine() && !how.starts_with("error") && !how.starts_with("unreachable") {
        tracing::debug!(target: "keyward::daemon", request = %what, result = %how, ms);
    } else {
        tracing::info!(target: "keyward::daemon", request = %what, result = %how, ms);
    }
}

/// One command the window ran, as the window saw it — including the ones
/// that never reached their code, refused over their arguments.
#[derive(serde::Deserialize)]
pub struct UiEntry {
    cmd: String,
    ok: bool,
    ms: u64,
    #[serde(default)]
    error: Option<String>,
}

/// The window's record of its commands. The name is checked rather than
/// trusted: it is written into a log file.
#[tauri::command]
pub fn ui_log(entries: Vec<UiEntry>) {
    for e in entries.into_iter().take(200) {
        let cmd: String = e.cmd.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '|')).take(80).collect();
        match e.error {
            Some(err) => tracing::warn!(target: "keyward::ui", cmd = %cmd, ms = e.ms, error = %scrub(&err), "failed"),
            None if ROUTINE.contains(&cmd.as_str()) && e.ok => tracing::debug!(target: "keyward::ui", cmd = %cmd, ms = e.ms, "done"),
            None => tracing::info!(target: "keyward::ui", cmd = %cmd, ms = e.ms, ok = e.ok, "done"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::scrub;

    #[test]
    fn a_quoted_value_never_reaches_the_log() {
        let e = r#"invalid args `settings` for command `set_settings`: invalid type: string "hunter2", expected a bool"#;
        let s = scrub(e);
        assert!(!s.contains("hunter2"), "{s}");
        assert!(s.contains("`settings`") && s.contains("set_settings"), "{s}");
        assert!(!scrub(r#"broken "tail-without-end"#).contains("tail-without-end"));
    }
}
