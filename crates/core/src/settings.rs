//! The application's settings.
//!
//! They live in `~/.keyward/settings.json` and the daemon reads them: some of
//! them (automatic locking, clearing the clipboard) are its behaviour rather
//! than decoration of the interface. Plugins' settings do not come here: each
//! has a file of its own in `~/.keyward/plugins/`. The defaults are chosen so
//! that nobody has to switch safety on by hand.

use serde::{Deserialize, Serialize};

/// When to lock the vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LockTimeout {
    /// Only when the daemon restarts, so the keys live until a reboot.
    OnRestart,
    /// After this many minutes with no calls.
    Minutes { minutes: u32 },
    /// Never. It takes a deliberate choice: the keys stay in memory.
    Never,
}

impl LockTimeout {
    pub fn as_minutes(self) -> Option<u32> {
        match self {
            Self::Minutes { minutes } if minutes > 0 => Some(minutes),
            _ => None,
        }
    }
}

/// What to do when the time is up: lock (the keys out of memory, the tokens
/// stay) or log out of the account altogether.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockAction {
    Lock,
    Logout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Theme {
    System,
    Dark,
    Light,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Language {
    /// As the system has it.
    Auto,
    Ru,
    En,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    // Safety
    pub lock_timeout: LockTimeout,
    /// Lock or log out when the time is up.
    #[serde(default = "default_lock_action")]
    pub lock_action: LockAction,
    pub touch_id_on_launch: bool,
    /// Ask the sensor on every showing and copying of a password rather than
    /// only for items marked "ask for the password again". Off: the socket is
    /// already locked to the application's signature, and a finger for every
    /// copy is the kind of nagging that gets the protection switched off
    /// altogether.
    #[serde(default)]
    pub touch_id_for_secrets: bool,
    /// Seconds before the clipboard is cleared; 0 means do not clear it.
    pub clipboard_clear_seconds: u32,
    /// How many seconds after a successful Touch ID not to ask again; 0 means
    /// ask every time. Five minutes is as long as macOS allows one fingerprint
    /// to be reused inside an application.
    #[serde(default = "default_grace")]
    pub biometric_grace_seconds: u32,

    // Behaviour
    pub show_website_icons: bool,
    /// Hide the window after copying to the clipboard.
    #[serde(default)]
    pub hide_on_copy: bool,
    /// The close button hides the window into the menu bar rather than
    /// closing the application.
    #[serde(default = "yes")]
    pub keep_in_tray: bool,
    /// Whether the Dock icon stays after the close button hides the window.
    /// Off by default: a menu-bar application whose window is closed has no
    /// business in the Dock; the icon comes back with the window.
    #[serde(default)]
    pub keep_in_dock: bool,
    /// Allow screenshots and showing the window over remote access.
    #[serde(default)]
    pub allow_screen_capture: bool,
    pub start_on_login: bool,

    // Appearance
    pub theme: Theme,
    /// A person's UI accent. It is independent from their account avatar: the
    /// same vault account can be used in a calm violet app or a blue one.
    #[serde(default)]
    pub accent_color: Option<String>,
    pub language: Language,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            // Fifteen minutes is a compromise: it does not get in the way of
            // work and does not leave an open vault for the whole day.
            lock_timeout: LockTimeout::Minutes { minutes: 15 },
            lock_action: default_lock_action(),
            touch_id_on_launch: true,
            touch_id_for_secrets: false,
            clipboard_clear_seconds: 30,
            biometric_grace_seconds: default_grace(),
            // The icons come from the same server the vault is on, but it is
            // still a request outwards: the choice is left to the person, and
            // the default is yes.
            show_website_icons: true,
            hide_on_copy: false,
            keep_in_tray: yes(),
            keep_in_dock: false,
            allow_screen_capture: false,
            start_on_login: true,
            theme: Theme::System,
            accent_color: None,
            language: Language::Auto,
        }
    }
}

fn yes() -> bool {
    true
}

fn default_lock_action() -> LockAction {
    LockAction::Lock
}

fn default_grace() -> u32 {
    300
}

impl Settings {
    pub fn load() -> Self {
        let path = crate::paths::settings_file();
        std::fs::read_to_string(path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let path = crate::paths::settings_file();
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }

    /// A check before saving: values that make no sense are better refused than
    /// hunted down later when the clipboard clears itself a day on.
    pub fn validate(&self) -> Result<(), String> {
        // An hour is the ceiling for the window of trust. Without it any
        // number could be written into the settings file and the second prompt
        // switched off for ever.
        if self.biometric_grace_seconds > 3600 {
            return Err("err.graceOverAnHour".into());
        }
        if let LockTimeout::Minutes { minutes } = self.lock_timeout {
            if minutes == 0 {
                return Err("err.lockTimeoutZero".into());
            }
            if minutes > 24 * 60 {
                return Err("err.lockTimeoutOverADay".into());
            }
        }
        if self.clipboard_clear_seconds > 3600 {
            return Err("err.clipboardClearOverAnHour".into());
        }
        if let Some(color) = &self.accent_color {
            let valid = color.len() == 7
                && color.starts_with('#')
                && color.as_bytes()[1..].iter().all(u8::is_ascii_hexdigit);
            if !valid {
                return Err("err.accentColorBad".into());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_safe_without_being_annoying() {
        let s = Settings::default();
        assert_eq!(s.lock_timeout.as_minutes(), Some(15));
        assert_eq!(s.clipboard_clear_seconds, 30);
    }

    #[test]
    fn zero_timeout_is_rejected_as_ambiguous() {
        // Zero minutes reads as "at once" and would in fact mean "never": a
        // choice like that has to be explicit.
        let s = Settings { lock_timeout: LockTimeout::Minutes { minutes: 0 }, ..Default::default() };
        assert!(s.validate().is_err());
        assert_eq!(s.lock_timeout.as_minutes(), None);
    }

    #[test]
    fn absurd_values_are_rejected() {
        let s = Settings { clipboard_clear_seconds: 7200, ..Default::default() };
        assert!(s.validate().is_err());
        let s = Settings { lock_timeout: LockTimeout::Minutes { minutes: 5000 }, ..Default::default() };
        assert!(s.validate().is_err());
    }

    #[test]
    fn never_and_on_restart_have_no_minutes() {
        assert_eq!(LockTimeout::Never.as_minutes(), None);
        assert_eq!(LockTimeout::OnRestart.as_minutes(), None);
        assert!(Settings { lock_timeout: LockTimeout::Never, ..Default::default() }.validate().is_ok());
    }

    #[test]
    fn unknown_fields_do_not_break_old_files() {
        // The settings are read from a file another release may have written.
        let s: Settings = serde_json::from_str(r#"{"clipboard_clear_seconds": 10}"#).unwrap();
        assert_eq!(s.clipboard_clear_seconds, 10);
        assert!(s.touch_id_on_launch, "the rest has to come from the defaults");
    }
}
