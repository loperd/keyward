//! Notifications through the macOS notification centre.
//!
//! Not through the scripting engine: `osascript display notification` needs
//! permission to control another application, shows the notification under the
//! name "Script Editor", and gives neither an icon of its own nor an entry in
//! the system settings. `UNUserNotificationCenter` is what any proper
//! application uses.
//!
//! It works only from inside a bundle: the notification centre asks a process
//! for its application identifier. So the window is what shows notifications,
//! and the daemon under launchd only gathers them.

#[cfg(target_os = "macos")]
use block2::RcBlock;
#[cfg(target_os = "macos")]
use objc2::runtime::Bool;
#[cfg(target_os = "macos")]
use objc2_foundation::{NSError, NSString};
#[cfg(target_os = "macos")]
use objc2_user_notifications::{
    UNAuthorizationOptions, UNMutableNotificationContent, UNNotificationRequest,
    UNNotificationSound, UNUserNotificationCenter,
};

/// Asks for permission to show notifications.
///
/// The system decides for itself whether to show the prompt or keep quiet: it
/// does not trouble a person twice, so there is no point checking the state in
/// advance.
pub fn ask_permission() {
    #[cfg(target_os = "macos")]
    {
        let center = UNUserNotificationCenter::currentNotificationCenter();
        // We do not need the answer: if it was refused the notifications
        // simply will not appear, and asking again is pointless — that is done
        // in the system settings.
        let done = RcBlock::new(|_granted: Bool, _error: *mut NSError| {});
        center.requestAuthorizationWithOptions_completionHandler(
            UNAuthorizationOptions::Alert | UNAuthorizationOptions::Sound,
            &done,
        );
    }
}

/// Shows one notification.
pub fn show(title: &str, body: &str) {
    #[cfg(target_os = "macos")]
    {
        let content = UNMutableNotificationContent::new();
        content.setTitle(&NSString::from_str(title));
        content.setBody(&NSString::from_str(body));
        content.setSound(Some(&UNNotificationSound::defaultSound()));

        // Every notification has to have an identifier of its own: the same one
        // means "replace what is shown", and instead of a run of messages about
        // expired leases a person would see only the last.
        let id = NSString::from_str(&format!(
            "kw-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        let request = UNNotificationRequest::requestWithIdentifier_content_trigger(&id, &content, None);
        UNUserNotificationCenter::currentNotificationCenter()
            .addNotificationRequest_withCompletionHandler(&request, None);
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = (title, body);
    }
}
