//! Starting the application at login.
//!
//! The daemon already comes up under its own LaunchAgent; this is about the
//! window. A separate job is installed so that one can be turned off without
//! touching the other: the agent without the window is useful (ssh works), the
//! window without the agent is not.

const LABEL: &str = "me.loper.gui";
const APP: &str = "/Applications/keyward.app";

fn plist_path() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    std::path::PathBuf::from(home).join(format!("Library/LaunchAgents/{LABEL}.plist"))
}

pub fn set(enabled: bool) -> anyhow::Result<()> {
    let path = plist_path();
    let uid = unsafe { libc::getuid() };

    if !enabled {
        let _ = std::process::Command::new("launchctl")
            .args(["bootout", &format!("gui/{uid}/{LABEL}")])
            .status();
        let _ = std::fs::remove_file(&path);
        tracing::info!("the window no longer starts at login");
        return Ok(());
    }

    if !std::path::Path::new(APP).exists() {
        anyhow::bail!("the application is not installed in {APP}");
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(
        &path,
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/bin/open</string>
    <string>-a</string>
    <string>{APP}</string>
  </array>
  <key>RunAtLoad</key><true/>
</dict>
</plist>
"#
        ),
    )?;

    let _ = std::process::Command::new("launchctl")
        .args(["bootout", &format!("gui/{uid}/{LABEL}")])
        .status();
    let status = std::process::Command::new("launchctl")
        .args(["bootstrap", &format!("gui/{uid}"), &path.to_string_lossy()])
        .status()?;
    if !status.success() {
        anyhow::bail!("launchctl did not take the start-at-login job");
    }
    tracing::info!("the window now starts at login");
    Ok(())
}
