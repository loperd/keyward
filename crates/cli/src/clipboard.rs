//! The clipboard. The daemon puts the password there, not the interface: the
//! fewer places a secret passes through, the smaller the surface it leaks
//! from.

use std::time::Duration;

/// The interval from the settings; `None` means do not clear.
pub fn clear_after(settings: &keyward_core::settings::Settings) -> Option<Duration> {
    match settings.clipboard_clear_seconds {
        0 => None,
        s => Some(Duration::from_secs(u64::from(s))),
    }
}

/// Puts a value on the clipboard. Returns the clipboard's change count after
/// it: the clearing timer checks that number, not the value, so the daemon
/// keeps no copy of the secret while it waits.
pub fn put(value: &str) -> anyhow::Result<isize> {
    #[cfg(target_os = "macos")]
    {
        conceal(value)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = value;
        anyhow::bail!("the clipboard is supported on macOS only")
    }
}

/// Puts a value on the clipboard marked as concealed.
///
/// `pbcopy` puts plain text on and nothing else, and that is not enough.
/// Clipboard managers (Raycast, Maccy, Alfred, Paste) file everything into a
/// permanent store of their own, and Universal Clipboard carries a copy off to
/// the other devices of an Apple account. A clearing timer does not save us
/// here: it clears the system clipboard, not somebody else's archive. The type
/// `org.nspasteboard.ConcealedType` is the common agreement about exactly
/// this: "do not keep it". The second type, `TransientType`, asks the system
/// not to keep it either.
#[cfg(target_os = "macos")]
fn conceal(value: &str) -> anyhow::Result<isize> {
    use objc2_app_kit::NSPasteboard;
    use objc2_foundation::{NSString, NSUTF8StringEncoding};

    // SAFETY: working with the shared clipboard; every object lives in the
    // call's autorelease pool.
    unsafe {
        let board = NSPasteboard::generalPasteboard();
        board.clearContents();

        let text = NSString::from_str(value);
        let plain = NSString::from_str("public.utf8-plain-text");
        let concealed = NSString::from_str("org.nspasteboard.ConcealedType");
        let transient = NSString::from_str("org.nspasteboard.TransientType");

        let ok = board.setString_forType(&text, &plain);
        // The marks are the same value under another type: that is how the
        // clipboard managers that honour this agreement read them.
        let _ = board.setString_forType(&text, &concealed);
        let _ = board.setString_forType(&NSString::from_str(""), &transient);
        let _ = NSUTF8StringEncoding;

        if !ok {
            anyhow::bail!("the clipboard did not take the value");
        }
        Ok(board.changeCount())
    }
}

/// The text on the clipboard, read by the daemon for itself — a pasted
/// private key goes from the clipboard straight into a draft, never through
/// the window. Wiped when dropped.
pub fn read_text() -> Option<keyward_core::proto::Secret> {
    #[cfg(target_os = "macos")]
    {
        use objc2_foundation::NSString;
        // SAFETY: a read of the shared clipboard inside the call's pool.
        unsafe {
            let board = objc2_app_kit::NSPasteboard::generalPasteboard();
            let kind = NSString::from_str("public.utf8-plain-text");
            board.stringForType(&kind).map(|s| keyward_core::proto::Secret::new(s.to_string()))
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

/// The clipboard's change count just now: it moves on every copy anybody
/// makes. `None` off macOS.
fn change_count() -> Option<isize> {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: a read of the shared clipboard's counter.
        Some(unsafe { objc2_app_kit::NSPasteboard::generalPasteboard().changeCount() })
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

/// Clears the clipboard after `after`, but only if nothing was copied since
/// ours: wiping what a person copied after us would be sabotage. What is
/// compared is the clipboard's change count, not the value — the secret is
/// neither kept here for the wait nor read back off the clipboard.
pub fn clear_later(count: isize, after: Duration) {
    tokio::spawn(async move {
        tokio::time::sleep(after).await;
        if change_count() == Some(count) {
            let _ = put("");
            tracing::debug!("the clipboard was cleared");
        }
    });
}
