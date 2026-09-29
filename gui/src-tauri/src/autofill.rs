//! Autofill for anything: at a hotkey we find out what is in front of a
//! person — which application and which address in the tab — let them pick an
//! item, and type the login and the password into the active field with system
//! keyboard events. It works in any browser and any application and needs no
//! extension; all it needs is the Accessibility permission.
//!
//! The password does not pass through the webview: Rust takes it from the
//! daemon itself and types it straight away.

use std::sync::Mutex;
use std::time::Duration;

use keyward_core::detail::SecretField;
use keyward_core::proto::{Request, Response};

#[cfg(target_os = "macos")]
use crate::ax;
use crate::card::{card_slot, digits, month_matches, month_spellings, year_matches, CardSlot};
use serde::Serialize;

/// What was in the foreground at the moment the hotkey was pressed.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Context {
    pub app: String,
    pub bundle_id: String,
    pub pid: i32,
    /// The active tab's address, when what is in front of us is a browser we
    /// know.
    pub url: Option<String>,
    /// The domain out of the address, without `www.`.
    pub domain: Option<String>,
    /// The active input field, if it could be read through Accessibility.
    pub field: Option<Field>,
    /// The title of the window the field lies in: the window is raised by it
    /// before typing. In Arc, small windows do not become key of their own
    /// accord when focus comes back, and without this the text went into
    /// another window.
    #[serde(default)]
    pub window: Option<String>,
}

/// The active field: what kind of field it is and how it is captioned. The
/// field's value is not read — only the role and the captions.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Field {
    /// `password`, `username`, `totp`, `card`, `text` or `unknown`.
    pub kind: String,
    pub role: String,
    pub label: String,
    /// How many cells the code is split across, when the field is one of a
    /// row of one-character boxes (a six-digit code as six inputs); 0 for an
    /// ordinary field.
    #[serde(default)]
    pub cells: usize,
    /// Set only when the form around the field is proven to be a login: one
    /// login field and one password field next to each other. Without it
    /// "the login and the password" is not offered at all.
    #[serde(default)]
    pub login: Option<LoginPair>,
}

/// A proven login form: which field takes the login, as it is captioned, and
/// whether the caption itself says so (`Email`, `Username`) or the field was
/// taken for want of any other.
#[derive(Debug, Clone, Default, Serialize)]
pub struct LoginPair {
    pub label: String,
    pub named: bool,
}

/// What a field of a small form is, for telling whether it is a login form.
pub struct Slot<'a> {
    pub role: &'a str,
    pub secure: bool,
    pub captions: &'a str,
    pub focused: bool,
}

/// A login form, proven step by step rather than guessed: the nearest group
/// of fields holds exactly one password field (a second one means signing
/// up or changing a password), and before it a text field for the login —
/// the one captioned as a login, or the only candidate there is. A search
/// box is never a login, and the focus has to be on one of the two. Returns
/// the login field's index, the password field's and whether the login
/// field was named as one; `None` whenever any step is in doubt.
pub fn login_pair(fields: &[Slot<'_>]) -> Option<(usize, usize, bool)> {
    let mut secure = fields.iter().enumerate().filter(|(_, f)| f.secure);
    let (pass, _) = secure.next()?;
    if secure.next().is_some() {
        return None;
    }
    let searchy = |c: &str| {
        let low = c.to_lowercase();
        SEARCH_WORDS.iter().any(|w| low.contains(w))
    };
    let named = |c: &str| {
        let low = c.to_lowercase();
        LOGIN_WORDS.iter().chain(["name", "identifier"].iter()).any(|w| low.contains(w))
    };
    let candidates: Vec<usize> = fields[..pass]
        .iter()
        .enumerate()
        .filter(|(_, f)| !f.secure && matches!(f.role, "AXTextField" | "AXComboBox") && !searchy(f.captions))
        .map(|(i, _)| i)
        .collect();
    let (user, is_named) = match candidates.iter().rev().find(|&&i| named(fields[i].captions)) {
        Some(&i) => (i, true),
        None if candidates.len() == 1 => (candidates[0], false),
        None => return None,
    };
    (fields[user].focused || fields[pass].focused).then_some((user, pass, is_named))
}

/// The autofill log: what was seen and what was done. There are no secrets
/// here — addresses, field roles and captions.
fn log(line: &str) {
    use std::io::Write as _;
    let Some(home) = std::env::var_os("HOME") else { return };
    let path = std::path::Path::new(&home).join(".keyward").join("autofill.log");
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let _ = writeln!(f, "{ts} {line}");
    }
}

/// The last context taken: it is taken before our window is shown, while the
/// focus is still with somebody else's application.
static LAST: Mutex<Option<Context>> = Mutex::new(None);

/// Words that mark a field by the caption a web form gives it.
///
/// These are not our own text and are not translated: what is matched here is
/// somebody else's page, and the language of that page has nothing to do with
/// the language of our window. Somebody logging into a Russian site wants the
/// password field found there just as much as on an English one, whichever
/// language keyward itself is set to.
const PASSWORD_WORDS: &[&str] = &["password", "\u{43f}\u{430}\u{440}\u{43e}\u{43b}"];
const CODE_WORDS: &[&str] = &["code", "otp", "2fa", "verification", "\u{43a}\u{43e}\u{434}"];
const LOGIN_WORDS: &[&str] = &[
    "mail",
    "login",
    "user",
    "account",
    "phone",
    "\u{43b}\u{43e}\u{433}\u{438}\u{43d}",
    "\u{43f}\u{43e}\u{447}\u{442}",
    "\u{442}\u{435}\u{43b}\u{435}\u{444}\u{43e}\u{43d}",
];

/// Words of a search box: it looks like a text field and must never be taken
/// for a login.
const SEARCH_WORDS: &[&str] = &["search", "filter", "find", "\u{43f}\u{43e}\u{438}\u{441}\u{43a}", "\u{43d}\u{430}\u{439}\u{442}\u{438}"];

/// Browsers whose tab address can be asked for through AppleScript. The tuple
/// is the bundle identifier and what that browser calls a tab.
const BROWSERS: &[(&str, &str)] = &[
    ("com.apple.Safari", "safari"),
    ("com.apple.SafariTechnologyPreview", "safari"),
    ("com.google.Chrome", "chromium"),
    ("com.google.Chrome.canary", "chromium"),
    ("company.thebrowser.Browser", "chromium"),
    ("com.brave.Browser", "chromium"),
    ("com.microsoft.edgemac", "chromium"),
    ("com.vivaldi.Vivaldi", "chromium"),
    ("org.chromium.Chromium", "chromium"),
    ("com.operasoftware.Opera", "chromium"),
];

pub fn domain_of(url: &str) -> Option<String> {
    let rest = url.split("://").nth(1).unwrap_or(url);
    let host = rest.split(['/', '?', '#']).next()?.split('@').last()?.split(':').next()?;
    let host = host.trim_start_matches("www.").to_ascii_lowercase();
    (host.contains('.') && !host.is_empty()).then_some(host)
}

#[cfg(target_os = "macos")]
fn frontmost() -> Option<(String, String, i32)> {
    use objc2_app_kit::NSWorkspace;
    let ws = NSWorkspace::sharedWorkspace();
    let app = ws.frontmostApplication()?;
    let name = app.localizedName().map(|s| s.to_string()).unwrap_or_default();
    let bundle = app.bundleIdentifier().map(|s| s.to_string()).unwrap_or_default();
    Some((name, bundle, app.processIdentifier()))
}

#[cfg(not(target_os = "macos"))]
fn frontmost() -> Option<(String, String, i32)> {
    None
}

/// The active tab's address in a browser we know. AppleScript is the only open
/// path; an address is no secret, so it can travel as an argument.
fn tab_url(bundle: &str) -> Option<String> {
    let kind = BROWSERS.iter().find(|(b, _)| *b == bundle)?.1;
    let script = match kind {
        "safari" => format!("tell application id \"{bundle}\" to get URL of current tab of front window"),
        _ => format!("tell application id \"{bundle}\" to get URL of active tab of front window"),
    };
    let out = match std::process::Command::new("/usr/bin/osascript").arg("-e").arg(&script).output() {
        Ok(o) => o,
        Err(e) => {
            log(&format!("osascript would not start: {e}"));
            return None;
        }
    };
    if !out.status.success() {
        log(&format!("osascript for {bundle} ended with {}: {}", out.status, String::from_utf8_lossy(&out.stderr).trim()));
        return None;
    }
    let url = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!url.is_empty() && url.contains("://")).then_some(url)
}

/// The foreground application's active field through Accessibility: the role,
/// the subrole and the captions. Browsers give the fields of web forms just as
/// native ones do: a password has the AXSecureTextField subrole, the rest have
/// a caption, a placeholder or a title.
#[cfg(target_os = "macos")]
/// The active field, the page's address (when the field is in a web area) and
/// the window's title.
fn focused_field(pid: i32) -> (Option<Field>, Option<String>, Option<String>) {
    use core_foundation::base::{CFType, CFTypeRef, TCFType as _};
    use core_foundation::string::{CFString, CFStringRef};
    use core_foundation::url::CFURL;
    #[repr(C)]
    struct AXUIElement(std::ffi::c_void);
    type AXUIElementRef = *const AXUIElement;
    #[link(name = "ApplicationServices", kind = "framework")]
    extern "C" {
        fn AXUIElementCreateApplication(pid: i32) -> AXUIElementRef;
        fn AXUIElementCopyAttributeValue(element: AXUIElementRef, attribute: CFStringRef, value: *mut CFTypeRef) -> i32;
        fn AXUIElementSetAttributeValue(element: AXUIElementRef, attribute: CFStringRef, value: CFTypeRef) -> i32;
        fn CFRelease(cf: CFTypeRef);
    }
    if pid <= 0 {
        return (None, None, None);
    }
    unsafe {
        let app = AXUIElementCreateApplication(pid);
        if app.is_null() {
            return (None, None, None);
        }
        // Chromium browsers do not build an accessibility tree for a web page
        // until a client asks: without these flags they have "no active
        // field".
        {
            use core_foundation::boolean::CFBoolean;
            let yes = CFBoolean::true_value();
            for name in ["AXEnhancedUserInterface", "AXManualAccessibility"] {
                let key = CFString::new(name);
                let _ = AXUIElementSetAttributeValue(app, key.as_concrete_TypeRef(), yes.as_CFTypeRef());
            }
        }
        let attr = |el: AXUIElementRef, name: &str| -> Option<CFType> {
            let key = CFString::new(name);
            let mut out: CFTypeRef = std::ptr::null();
            let err = AXUIElementCopyAttributeValue(el, key.as_concrete_TypeRef(), &mut out);
            if err != 0 || out.is_null() {
                return None;
            }
            Some(CFType::wrap_under_create_rule(out))
        };
        let string = |el: AXUIElementRef, name: &str| -> String {
            attr(el, name).and_then(|v| v.downcast::<CFString>()).map(|s| s.to_string()).unwrap_or_default()
        };
        // The tree is not built instantly, so it is given a few tries.
        let mut focused = None;
        for _ in 0..6 {
            focused = attr(app, "AXFocusedUIElement");
            if focused.is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(40));
        }
        let Some(focused) = focused else {
            CFRelease(app as CFTypeRef);
            return (None, None, None);
        };
        let el = focused.as_CFTypeRef() as AXUIElementRef;
        // The page's address belongs to the web area the field lies in. That is
        // sounder than AppleScript, which sees only a browser's "front window",
        // and in Arc the small windows do not count as one.
        let mut page_url = None;
        let mut window_title = None;
        {
            let mut chain: Vec<CFType> = Vec::new();
            let mut cur = el;
            for _ in 0..48 {
                let role = string(cur, "AXRole");
                if role == "AXWebArea" && page_url.is_none() {
                    page_url = attr(cur, "AXURL")
                        .and_then(|v| v.downcast::<CFURL>())
                        .map(|u| u.get_string().to_string())
                        .filter(|u| u.contains("://"));
                }
                if role == "AXWindow" {
                    window_title = Some(string(cur, "AXTitle"));
                    break;
                }
                let Some(parent) = attr(cur, "AXParent") else { break };
                cur = parent.as_CFTypeRef() as AXUIElementRef;
                chain.push(parent);
            }
        }
        let role = string(el, "AXRole");
        let subrole = string(el, "AXSubrole");
        let mut label = [string(el, "AXTitle"), string(el, "AXDescription"), string(el, "AXPlaceholderValue"), string(el, "AXRoleDescription")]
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(" · ");
        if label.len() > 120 {
            label.truncate(120);
        }
        CFRelease(app as CFTypeRef);
        let low = label.to_lowercase();
        // First decide whether this is a field at all, and only then read
        // the caption. Otherwise a caption that belongs to something else
        // gets parsed: a web area is captioned with the page title, and
        // "OpenVPN MyAccount" read as a login field on the one-time-code
        // page. The stepper (`input type=number`, where browsers put the
        // code) was not in the old list of fields at all.
        let typable = ax::typable(&role, &subrole);
        // A row of one-character boxes is a code whatever its captions say:
        // on OpenVPN each box is a bare stepper captioned "Required".
        let cells = if typable { ax::code_cells(&focused).len() } else { 0 };
        let any = |words: &[&str]| words.iter().any(|w| low.contains(w));
        let kind = if !typable {
            "unknown"
        } else if cells > 0 {
            "totp"
        } else if card_slot(&ax::captions(&focused)).is_some() {
            "card"
        } else if subrole == "AXSecureTextField" || any(PASSWORD_WORDS) {
            "password"
        } else if any(CODE_WORDS) {
            "totp"
        } else if any(LOGIN_WORDS) {
            "username"
        } else {
            "text"
        };
        (
            Some(Field { kind: kind.to_string(), role: if subrole.is_empty() { role } else { format!("{role}/{subrole}") }, label, cells, login: None }),
            page_url,
            window_title,
        )
    }
}

#[cfg(not(target_os = "macos"))]
fn focused_field(_pid: i32) -> (Option<Field>, Option<String>, Option<String>) {
    (None, None, None)
}

/// Raise the application window with this title and make it the key one.
///
/// Activating an application gives the keyboard back to its key window, and in
/// Arc small windows do not become key after a switch — so the typing went into
/// the main window. The window is found by the title taken at capture.
#[cfg(target_os = "macos")]
fn raise_window(pid: i32, title: &str) -> bool {
    use core_foundation::array::CFArray;
    use core_foundation::base::{CFType, CFTypeRef, TCFType as _};
    use core_foundation::boolean::CFBoolean;
    use core_foundation::string::{CFString, CFStringRef};
    #[repr(C)]
    struct AXUIElement(std::ffi::c_void);
    type AXUIElementRef = *const AXUIElement;
    #[link(name = "ApplicationServices", kind = "framework")]
    extern "C" {
        fn AXUIElementCreateApplication(pid: i32) -> AXUIElementRef;
        fn AXUIElementCopyAttributeValue(element: AXUIElementRef, attribute: CFStringRef, value: *mut CFTypeRef) -> i32;
        fn AXUIElementSetAttributeValue(element: AXUIElementRef, attribute: CFStringRef, value: CFTypeRef) -> i32;
        fn AXUIElementPerformAction(element: AXUIElementRef, action: CFStringRef) -> i32;
        fn CFRelease(cf: CFTypeRef);
    }
    if pid <= 0 || title.is_empty() {
        return false;
    }
    unsafe {
        let app = AXUIElementCreateApplication(pid);
        if app.is_null() {
            return false;
        }
        let attr = |el: AXUIElementRef, name: &str| -> Option<CFType> {
            let key = CFString::new(name);
            let mut out: CFTypeRef = std::ptr::null();
            let err = AXUIElementCopyAttributeValue(el, key.as_concrete_TypeRef(), &mut out);
            if err != 0 || out.is_null() {
                return None;
            }
            Some(CFType::wrap_under_create_rule(out))
        };
        let mut raised = false;
        if let Some(windows) = attr(app, "AXWindows").and_then(|v| v.downcast::<CFArray>()) {
            for i in 0..windows.len() {
                let Some(w) = windows.get(i) else { continue };
                let el = *w as AXUIElementRef;
                let t = attr(el, "AXTitle").and_then(|v| v.downcast::<CFString>()).map(|s| s.to_string()).unwrap_or_default();
                if t == title {
                    let yes = CFBoolean::true_value();
                    for name in ["AXMain", "AXFocused"] {
                        let key = CFString::new(name);
                        let _ = AXUIElementSetAttributeValue(el, key.as_concrete_TypeRef(), yes.as_CFTypeRef());
                    }
                    let raise = CFString::new("AXRaise");
                    raised = AXUIElementPerformAction(el, raise.as_concrete_TypeRef()) == 0;
                    break;
                }
            }
        }
        CFRelease(app as CFTypeRef);
        raised
    }
}

#[cfg(not(target_os = "macos"))]
fn raise_window(_pid: i32, _title: &str) -> bool {
    false
}

/// Is this our own process? A context of "keyward looking at keyward" is of
/// no use.
fn is_self(pid: i32) -> bool {
    pid == std::process::id() as i32
}

/// Take the foreground application's context and remember it.
pub fn capture() -> Context {
    let (app, bundle_id, pid) = frontmost().unwrap_or_default();
    if is_self(pid) {
        // The key was pressed while our own window was already in front: the
        // target for typing is the previous one and it stays. Otherwise the
        // password was typed into keyward itself.
        log("context: keyward is in front; the previous target was kept");
        return Context { app, bundle_id, pid, url: None, domain: None, field: None, window: None };
    }
    let (mut field, page_url, window) = focused_field(pid);
    if let Some(f) = field.as_mut().filter(|f| matches!(f.kind.as_str(), "username" | "password" | "text")) {
        f.login = find_login(pid).map(|(_, _, pair)| pair);
    }
    let url = page_url.or_else(|| if bundle_id.is_empty() { None } else { tab_url(&bundle_id) });
    let domain = url.as_deref().and_then(domain_of);
    let ctx = Context { app, bundle_id, pid, url, domain, field, window };
    log(&format!(
        "context: app={:?} bundle={:?} pid={} url={:?} field={:?} window={:?}",
        ctx.app, ctx.bundle_id, ctx.pid, ctx.url, ctx.field, ctx.window
    ));
    *LAST.lock().unwrap_or_else(|e| e.into_inner()) = Some(ctx.clone());
    ctx
}

/// This is keyward's own context rather than another application's.
pub fn is_own(ctx: &Context) -> bool {
    is_self(ctx.pid)
}

/// Is there anything under the cursor worth typing into?
///
/// The list says "definitely nowhere to type", not "typing is allowed". The
/// key was pressed by hand, and swallowing it over an unfamiliar role is
/// worse than showing the window once too often. This used to be a list of
/// permitted roles, and the one-time-code field — a stepper, in browsers —
/// ate the shortcut silently: from the outside it looked as if autofill
/// worked exactly once and then the key stopped existing.
pub fn field_is_editable(ctx: &Context) -> bool {
    if !trusted() {
        return true;
    }
    const NOT_A_FIELD: &[&str] = &[
        "AXButton",
        "AXPopUpButton",
        "AXMenuButton",
        "AXCheckBox",
        "AXRadioButton",
        "AXMenuItem",
        "AXMenuBarItem",
        "AXLink",
        "AXImage",
        "AXSlider",
        "AXTabGroup",
        "AXScrollBar",
        "AXToolbar",
        "AXDisclosureTriangle",
    ];
    // No field in sight is not "there is no field" but "we could not read
    // one": do not refuse, let the human pick.
    let Some(f) = &ctx.field else { return true };
    let role = f.role.split('/').next().unwrap_or_default();
    let ok = !NOT_A_FIELD.contains(&role);
    if !ok {
        log(&format!("the key was skipped: under the cursor is not a field but {role}"));
    }
    ok
}

pub fn last() -> Option<Context> {
    LAST.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

#[cfg(target_os = "macos")]
#[link(name = "ApplicationServices", kind = "framework")]
extern "C" {
    fn AXIsProcessTrusted() -> bool;
    fn AXIsProcessTrustedWithOptions(options: core_foundation::dictionary::CFDictionaryRef) -> bool;
    static kAXTrustedCheckOptionPrompt: core_foundation::string::CFStringRef;
}

/// Have we the right to type into other applications' windows?
pub fn trusted() -> bool {
    #[cfg(target_os = "macos")]
    unsafe {
        AXIsProcessTrusted()
    }
    #[cfg(not(target_os = "macos"))]
    false
}

/// Ask for the permission: the system's dialogue appears only from this call,
/// and the same call adds the application to the Accessibility list. The
/// settings page is opened as well — the switch is flicked there anyway.
pub fn request_access() -> bool {
    #[cfg(target_os = "macos")]
    let trusted = unsafe {
        use core_foundation::base::TCFType as _;
        use core_foundation::{boolean::CFBoolean, dictionary::CFDictionary, string::CFString};
        let key = CFString::wrap_under_get_rule(kAXTrustedCheckOptionPrompt);
        let dict = CFDictionary::from_CFType_pairs(&[(key.as_CFType(), CFBoolean::true_value().as_CFType())]);
        AXIsProcessTrustedWithOptions(dict.as_concrete_TypeRef())
    };
    #[cfg(not(target_os = "macos"))]
    let trusted = false;
    if !trusted {
        let _ = std::process::Command::new("open")
            .arg("x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility")
            .spawn();
    }
    trusted
}

/// Give the focus back to the application our window took it from.
#[cfg(target_os = "macos")]
fn activate(pid: i32) {
    use objc2_app_kit::{NSApplicationActivationOptions, NSRunningApplication};
    if pid <= 0 {
        return;
    }
    if let Some(app) = NSRunningApplication::runningApplicationWithProcessIdentifier(pid) {
        #[allow(deprecated)]
        app.activateWithOptions(NSApplicationActivationOptions::ActivateIgnoringOtherApps);
    }
}

#[cfg(not(target_os = "macos"))]
fn activate(_pid: i32) {}

#[cfg(target_os = "macos")]
mod keys {
    use core_graphics::event::{CGEvent, CGEventFlags, CGEventTapLocation, CGKeyCode};

    #[link(name = "Carbon", kind = "framework")]
    extern "C" {
        fn EnableSecureEventInput() -> i32;
        fn DisableSecureEventInput() -> i32;
        fn IsSecureEventInputEnabled() -> u8;
    }

    /// Secure event input for as long as it lives: while it is on, other
    /// processes' event taps — a keylogger among them — are not shown the
    /// keystrokes, ours included. Switched off on drop, whatever happens in
    /// between: left on, it would blind every hotkey tool on the machine.
    pub struct SecureInput;

    impl SecureInput {
        pub fn on() -> Self {
            // SAFETY: a counted switch of the system's; balanced in Drop.
            unsafe { EnableSecureEventInput() };
            Self
        }

        pub fn active() -> bool {
            // SAFETY: a read of the system's state.
            unsafe { IsSecureEventInputEnabled() != 0 }
        }
    }

    impl Drop for SecureInput {
        fn drop(&mut self) {
            // SAFETY: balances the Enable in `on`.
            unsafe { DisableSecureEventInput() };
        }
    }
    use core_graphics::event_source::{CGEventSource, CGEventSourceStateID};

    fn source() -> anyhow::Result<CGEventSource> {
        CGEventSource::new(CGEventSourceStateID::HIDSystemState).map_err(|_| anyhow::anyhow!("a keyboard event source will not build"))
    }

    /// Types a string as unicode: the layout does not matter and any
    /// character goes.
    /// One event carries no more than twenty characters: a limit of the
    /// system's.
    pub fn type_text(text: &str) -> anyhow::Result<()> {
        let src = source()?;
        let chars: Vec<char> = text.chars().collect();
        for chunk in chars.chunks(16) {
            let s: String = chunk.iter().collect();
            // The flags are cleared explicitly: an HID source takes the state
            // of the real modifiers, and while a person is still holding
            // Cmd+Shift after the hotkey, the whole text would go out as
            // Cmd+Shift combinations.
            let down = CGEvent::new_keyboard_event(src.clone(), 0, true).map_err(|_| anyhow::anyhow!("a keyboard event"))?;
            down.set_flags(CGEventFlags::empty());
            down.set_string(&s);
            down.post(CGEventTapLocation::HID);
            let up = CGEvent::new_keyboard_event(src.clone(), 0, false).map_err(|_| anyhow::anyhow!("a keyboard event"))?;
            up.set_flags(CGEventFlags::empty());
            up.set_string(&s);
            up.post(CGEventTapLocation::HID);
            std::thread::sleep(std::time::Duration::from_millis(12));
        }
        Ok(())
    }

    /// One character as its own key press. A digit goes out on its own key
    /// of the top row, not as a bare unicode string: code boxes often listen
    /// for `keydown` and look at which key it was.
    pub fn type_char(c: char) -> anyhow::Result<()> {
        const DIGITS: [CGKeyCode; 10] = [29, 18, 19, 20, 21, 23, 22, 26, 28, 25];
        let code = c.to_digit(10).map_or(0, |d| DIGITS[d as usize]);
        let src = source()?;
        let s = c.to_string();
        for down in [true, false] {
            let ev = CGEvent::new_keyboard_event(src.clone(), code, down).map_err(|_| anyhow::anyhow!("a keyboard event"))?;
            ev.set_flags(CGEventFlags::empty());
            ev.set_string(&s);
            ev.post(CGEventTapLocation::HID);
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        Ok(())
    }

    pub fn press(code: CGKeyCode) -> anyhow::Result<()> {
        let src = source()?;
        let down = CGEvent::new_keyboard_event(src.clone(), code, true).map_err(|_| anyhow::anyhow!("a keyboard event"))?;
        down.set_flags(CGEventFlags::empty());
        down.post(CGEventTapLocation::HID);
        std::thread::sleep(std::time::Duration::from_millis(10));
        let up = CGEvent::new_keyboard_event(src, code, false).map_err(|_| anyhow::anyhow!("a keyboard event"))?;
        up.set_flags(CGEventFlags::empty());
        up.post(CGEventTapLocation::HID);
        Ok(())
    }

    /// Cmd+A: whatever lies in the field, the new value replaces it rather
    /// than being appended to its tail.
    pub fn select_all() -> anyhow::Result<()> {
        let src = source()?;
        let down = CGEvent::new_keyboard_event(src.clone(), 0, true).map_err(|_| anyhow::anyhow!("a keyboard event"))?;
        down.set_flags(CGEventFlags::CGEventFlagCommand);
        down.post(CGEventTapLocation::HID);
        std::thread::sleep(std::time::Duration::from_millis(10));
        let up = CGEvent::new_keyboard_event(src, 0, false).map_err(|_| anyhow::anyhow!("a keyboard event"))?;
        up.set_flags(CGEventFlags::CGEventFlagCommand);
        up.post(CGEventTapLocation::HID);
        std::thread::sleep(std::time::Duration::from_millis(30));
        Ok(())
    }

    pub const RETURN: CGKeyCode = 36;
}

#[cfg(not(target_os = "macos"))]
mod keys {
    pub fn type_text(_t: &str) -> anyhow::Result<()> {
        anyhow::bail!("autofill exists on macOS only")
    }
    pub fn press(_c: u16) -> anyhow::Result<()> {
        anyhow::bail!("autofill exists on macOS only")
    }
    pub fn type_char(_c: char) -> anyhow::Result<()> {
        anyhow::bail!("autofill exists on macOS only")
    }
    pub fn select_all() -> anyhow::Result<()> {
        anyhow::bail!("autofill exists on macOS only")
    }
    pub const RETURN: u16 = 36;
}

/// What to fill in. A person picks it explicitly: we cannot guess from a
/// form's field, and typing a password into a login field is the worst thing
/// that could happen here.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Mode {
    /// The login, Tab, the password.
    Both,
    Username,
    Password,
    Totp,
    /// The whole card: each field of the payment form gets its own part.
    Card,
    /// One of the item's own fields, by name.
    Custom { name: String },
}

async fn secret(entry_id: &str, field: SecretField) -> Result<keyward_core::proto::Secret, String> {
    match crate::ask(Request::RevealSecret { entry_id: entry_id.to_string(), field }).await? {
        Response::Secret { value } => Ok(value),
        Response::Error { message } => Err(crate::humanize(&message)),
        other => Err(format!("an unexpected answer from the daemon: {other:?}")),
    }
}

/// The login form around the focus, if it is proven to be one: the login
/// field, the password field and how the login field is captioned.
#[cfg(target_os = "macos")]
fn find_login(pid: i32) -> Option<(core_foundation::base::CFType, core_foundation::base::CFType, LoginPair)> {
    let group = ax::nearest_group(pid);
    let slots: Vec<Slot<'_>> = group
        .iter()
        // A search box says so in its subrole too; it goes in as its own role
        // so that it can never be taken for the login field.
        .map(|(f, on)| Slot {
            role: if f.subrole == "AXSearchField" { "AXSearchField" } else { &f.role },
            secure: f.subrole == "AXSecureTextField",
            captions: &f.captions,
            focused: *on,
        })
        .collect();
    let (user, pass, named) = login_pair(&slots)?;
    let label = group[user].0.captions.split(" · ").next().unwrap_or_default().to_string();
    Some((group[user].0.el.clone(), group[pass].0.el.clone(), LoginPair { label, named }))
}

#[cfg(not(target_os = "macos"))]
fn find_login(_pid: i32) -> Option<((), (), LoginPair)> {
    None
}

/// A card's parts, taken from the daemon before our window is hidden.
struct CardValues {
    number: keyward_core::proto::Secret,
    code: Option<keyward_core::proto::Secret>,
    holder: Option<keyward_core::proto::Secret>,
    /// The month as `MM` and the year as `YYYY`.
    expiry: Option<(keyward_core::proto::Secret, keyward_core::proto::Secret)>,
}

/// Fill a payment form: find the card's fields around the focused one and
/// type each part into its own field, character by character — a provider's
/// fields are masked, and a mask takes keystrokes better than one long
/// string. The expiry is one field or two (month and year, typed or chosen
/// from lists); the name is taken only where both the form and the item
/// have it.
///
/// Returns false when no card field is recognised around the focus: then the
/// number goes into the focused field, as with any other field.
#[cfg(target_os = "macos")]
fn type_card(pid: i32, card: &CardValues) -> anyhow::Result<bool> {
    let slots = |fs: &[ax::FormField]| fs.iter().filter_map(|f| card_slot(&f.captions)).collect::<Vec<_>>();
    let form = ax::form_around(pid, |fs| {
        let s = slots(fs);
        s.contains(&CardSlot::Number)
            && (s.contains(&CardSlot::Code) || s.iter().any(|x| matches!(x, CardSlot::Expiry { .. } | CardSlot::Month)))
    });
    let mut typed = 0;
    for f in &form {
        let Some(slot) = card_slot(&f.captions) else { continue };
        // Every value made here is a secret too, and is wiped when dropped.
        type S = keyward_core::proto::Secret;
        let (mm, yyyy): (Option<S>, Option<S>) = card.expiry.clone().unzip();
        let yy: Option<S> = yyyy.as_ref().map(|y| S::new(y.chars().skip(2).collect()));
        let value: Option<S> = match slot {
            CardSlot::Number => Some(S::new(digits(&card.number))),
            CardSlot::Code => card.code.clone(),
            CardSlot::Holder => card.holder.clone(),
            CardSlot::Expiry { long } => mm
                .as_ref()
                .zip(if long { yyyy.as_ref() } else { yy.as_ref() })
                .map(|(m, y)| S::new(format!("{}/{}", m.as_str(), y.as_str()))),
            CardSlot::Month => mm.clone(),
            CardSlot::Year { short } => if short { yy.clone() } else { yyyy.clone() },
        };
        let Some(value) = value.filter(|v| !v.is_empty()) else {
            log(&format!("card: {slot:?} is on the form but not on the item"));
            continue;
        };
        if f.role == "AXPopUpButton" {
            let ok = match slot {
                CardSlot::Month => pick_from_list(&f.el, &month_spellings(&value), |t| month_matches(t, value.parse().unwrap_or(0))),
                CardSlot::Year { .. } => {
                    let full: u32 = yyyy.as_ref().and_then(|y| y.parse().ok()).unwrap_or(0);
                    pick_from_list(&f.el, &[full.to_string(), format!("{:02}", full % 100)], |t| year_matches(t, full))
                }
                _ => false,
            };
            log(&format!("card: {slot:?} from a list: {}", if ok { "chosen" } else { "no item matched" }));
        } else {
            if !ax::focus(&f.el) {
                log(&format!("card: {slot:?} would not take the focus"));
            }
            // A field in a frame of its own takes the focus a little later.
            std::thread::sleep(Duration::from_millis(80));
            let mut ok = type_masked(&f.el, &value)?;
            // A mask that will not take the slash takes the digits and puts
            // the slash in itself.
            if !ok && matches!(slot, CardSlot::Expiry { .. }) {
                ok = type_masked(&f.el, &digits(&value))?;
            }
            // A year field that said nothing of its length: `2029` cut down
            // to `20` by the field means it wants `29`.
            if let (false, CardSlot::Year { short: false }, Some(yy)) = (ok, slot, yy.as_deref()) {
                ok = type_masked(&f.el, yy)?;
            }
            log(&format!("card: {slot:?} typed, {} characters, {}", value.chars().count(), if ok { "the field agrees" } else { "the field shows something else" }));
        }
        typed += 1;
        std::thread::sleep(Duration::from_millis(60));
    }
    if typed == 0 {
        log(&format!("card: no card field among {} fields around the focus", form.len()));
    }
    Ok(typed > 0)
}

/// Type a value into a field that may be masked, key by key, and see whether
/// it took: a payment provider's field formats as it goes (`4111 1111 …`,
/// `12 / 29`), so what is compared is the digits, not the text. A field that
/// hides what it holds, or holds no digits to speak of, is taken at its word.
#[cfg(target_os = "macos")]
fn type_masked(el: &core_foundation::base::CFType, value: &str) -> anyhow::Result<bool> {
    keys::select_all()?;
    for c in value.chars() {
        keys::type_char(c)?;
        std::thread::sleep(Duration::from_millis(8));
    }
    std::thread::sleep(Duration::from_millis(80));
    let want = digits(value);
    let got = digits(&ax::string(el, "AXValue"));
    Ok(want.is_empty() || ax::string(el, "AXSubrole") == "AXSecureTextField" || got == want)
}

/// Choose an item of a closed drop-down list by typing its beginning, the
/// way a person would. Chromium does not show a closed list's items to
/// Accessibility — only the chosen one — so the spellings are tried in turn,
/// and the list's value says whether one of them hit.
#[cfg(target_os = "macos")]
fn pick_from_list(el: &core_foundation::base::CFType, spellings: &[String], matches: impl Fn(&str) -> bool) -> bool {
    for (i, s) in spellings.iter().enumerate() {
        if i > 0 {
            // A list forgets what was typed after about a second; without the
            // pause the next spelling is read as the tail of the last one.
            std::thread::sleep(Duration::from_millis(1100));
        }
        ax::focus(el);
        std::thread::sleep(Duration::from_millis(80));
        for c in s.chars() {
            if keys::type_char(c).is_err() {
                return false;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        std::thread::sleep(Duration::from_millis(120));
        if matches(&ax::string(el, "AXValue")) {
            return true;
        }
    }
    false
}

#[cfg(not(target_os = "macos"))]
fn type_card(_pid: i32, _card: &CardValues) -> anyhow::Result<bool> {
    Ok(false)
}

/// The login and the password, each into its own field of the proven form:
/// the fields are found again and focused one by one rather than reached
/// with a Tab. If the form is gone by now, nothing is typed.
#[cfg(target_os = "macos")]
fn type_login(pid: i32, username: &str, password: &str) -> anyhow::Result<()> {
    let Some((user, pass, pair)) = find_login(pid) else {
        log("login form: gone by the time of typing; nothing typed");
        anyhow::bail!("err.noLoginForm");
    };
    log(&format!("login form: login field {:?} ({})", pair.label, if pair.named { "named" } else { "the only one" }));
    for (el, value) in [(&user, username), (&pass, password)] {
        if value.is_empty() {
            continue;
        }
        ax::focus(el);
        std::thread::sleep(Duration::from_millis(60));
        keys::select_all()?;
        keys::type_text(value)?;
        std::thread::sleep(Duration::from_millis(40));
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn type_login(_pid: i32, _username: &str, _password: &str) -> anyhow::Result<()> {
    anyhow::bail!("autofill exists on macOS only")
}

/// Type a code into a row of one-character boxes, one character per box.
///
/// Each box is given the focus explicitly, so it does not matter whether the
/// page moves on by itself after a digit or waits for Tab. Returns false when
/// the row is not there any more, or is not as long as the code: then the
/// code is typed the ordinary way.
#[cfg(target_os = "macos")]
fn type_into_cells(pid: i32, code: &str) -> anyhow::Result<bool> {
    let cells = ax::focused_cells(pid);
    let chars: Vec<char> = code.chars().collect();
    if cells.is_empty() || cells.len() != chars.len() {
        log(&format!("code cells: {} boxes for {} characters; typing as one field", cells.len(), chars.len()));
        return Ok(false);
    }
    for (cell, c) in cells.iter().zip(chars) {
        if !ax::focus(cell) {
            // The focus would not move by hand; the page's own hop is all
            // there is.
            log("code cells: a box would not take the focus");
        }
        std::thread::sleep(Duration::from_millis(30));
        keys::select_all()?;
        keys::type_char(c)?;
        std::thread::sleep(Duration::from_millis(40));
    }
    log(&format!("code cells: typed box by box into {}", cells.len()));
    Ok(true)
}

#[cfg(not(target_os = "macos"))]
fn type_into_cells(_pid: i32, _code: &str) -> anyhow::Result<bool> {
    Ok(false)
}

/// Fill an item into another application's active field.
///
/// The order matters: our own window is hidden and the focus given back to
/// whoever it was taken from, and only then is anything typed — otherwise the
/// password goes into our own search box.
pub async fn fill(app: &tauri::AppHandle, entry_id: &str, mode: Mode, submit: bool) -> Result<(), String> {
    use tauri::Manager as _;
    if !trusted() {
        log("the fill was refused: there is no Accessibility permission");
        return Err("err.noAccessibility".into());
    }
    log(&format!("filling: entry={entry_id} mode={mode:?} submit={submit}"));
    // The secrets are fetched first: if the daemon refuses, the window is not
    // hidden yet and there is somewhere to show the error. Every refusal goes
    // into the log: by then the window may be hidden and nobody would see a
    // toast.
    let fetch = |field: SecretField| async move {
        secret(entry_id, field).await.map_err(|e| {
            log(&format!("the secret did not arrive: {e}"));
            e
        })
    };
    let username = if matches!(mode, Mode::Both | Mode::Username) { Some(fetch(SecretField::Username).await?) } else { None };
    let password = if matches!(mode, Mode::Both | Mode::Password) { Some(fetch(SecretField::Password).await?) } else { None };
    let totp = match &mode {
        Mode::Totp => Some(fetch(SecretField::Totp).await?),
        Mode::Custom { name } => Some(fetch(SecretField::Custom(name.clone())).await?),
        _ => None,
    };
    // The number is the card; the rest is taken when the item has it.
    let card = if mode == Mode::Card {
        let optional = |field: SecretField| async move { secret(entry_id, field).await.ok().filter(|v| !v.is_empty()) };
        let month = optional(SecretField::CardExpMonth).await;
        let year = optional(SecretField::CardExpYear).await;
        Some(CardValues {
            number: fetch(SecretField::CardNumber).await?,
            code: optional(SecretField::CardCode).await,
            holder: optional(SecretField::CardHolder).await,
            expiry: month.zip(year),
        })
    } else {
        None
    };
    let nothing = username.as_ref().map(|s| s.as_str()).unwrap_or("").is_empty()
        && password.as_ref().map(|s| s.as_str()).unwrap_or("").is_empty()
        && totp.as_ref().map(|s| s.as_str()).unwrap_or("").is_empty()
        && card.as_ref().is_none_or(|c| c.number.is_empty());
    if nothing {
        log("the chosen field is empty; there is nothing to type");
        return Err("err.chosenFieldEmpty".into());
    }
    log(&format!(
        "to type: username={} password={} value={} characters",
        username.as_ref().map(|s| s.as_str()).map_or(0, |s| s.chars().count()),
        password.as_ref().map(|s| s.as_str()).map_or(0, |s| s.chars().count()),
        totp.as_ref().map(|s| s.as_str()).map_or(0, |s| s.chars().count()),
    ));

    let Some(target) = last().filter(|c| !is_self(c.pid) && c.pid > 0) else {
        log("the typing was called off: there is no target field");
        return Err("err.noTargetField".into());
    };
    // Both values only into a form proven to be a login: typed blindly with a
    // Tab between them, the password went wherever the Tab led — into a
    // search box's neighbour, into the page.
    if mode == Mode::Both && target.field.as_ref().and_then(|f| f.login.as_ref()).is_none() {
        log("the fill was refused: no login form with a password field around the focus");
        return Err("err.noLoginForm".into());
    }
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.hide();
    }
    let pid = target.pid;
    let window = target.window.clone();
    let cells = target.field.as_ref().map_or(0, |f| f.cells);
    let typing = tauri::async_runtime::spawn_blocking(move || -> anyhow::Result<()> {
        // No one else's event tap sees what is typed from here on.
        #[cfg(target_os = "macos")]
        let _secure = keys::SecureInput::on();
        #[cfg(target_os = "macos")]
        log(&format!("secure input: {}", if keys::SecureInput::active() { "on" } else { "could not be switched on" }));
        activate(pid);
        std::thread::sleep(Duration::from_millis(200));
        if let Some(title) = window.as_deref().filter(|t| !t.is_empty()) {
            let ok = raise_window(pid, title);
            log(&format!("the window {title:?}: {}", if ok { "raised" } else { "not found; typing into the key one" }));
            std::thread::sleep(Duration::from_millis(120));
        }
        // Select all before each value: the field may be half filled in, or
        // filled in by the browser, and appending to it is not allowed.
        if let (Some(u), Some(p)) = (username.as_ref().map(|s| s.as_str()), password.as_ref().map(|s| s.as_str())) {
            type_login(pid, u, p)?;
        } else if let Some(v) = username.as_ref().map(|s| s.as_str()).or(password.as_ref().map(|s| s.as_str())).filter(|v| !v.is_empty()) {
            keys::select_all()?;
            keys::type_text(v)?;
        }
        if let Some(c) = totp.as_ref().map(|s| s.as_str()).filter(|c| !c.is_empty()) {
            if cells == 0 || !type_into_cells(pid, c)? {
                keys::select_all()?;
                keys::type_text(c)?;
            }
        }
        if let Some(card) = &card {
            if !type_card(pid, card)? {
                keys::select_all()?;
                keys::type_text(&card.number)?;
            }
        }
        if submit {
            std::thread::sleep(Duration::from_millis(40));
            keys::press(keys::RETURN)?;
        }
        Ok(())
    })
    .await
    .map_err(|e| format!("the typing thread fell over: {e}"))?;
    match typing {
        Ok(()) => {
            log("typed");
            Ok(())
        }
        Err(e) => {
            log(&format!("the typing failed: {e}"));
            Err(e.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{domain_of, login_pair, Slot};

    fn text<'a>(captions: &'a str, focused: bool) -> Slot<'a> {
        Slot { role: "AXTextField", secure: false, captions, focused }
    }
    fn secret(focused: bool) -> Slot<'static> {
        Slot { role: "AXTextField", secure: true, captions: "Password", focused }
    }

    #[test]
    fn a_login_form_is_proven_before_both_values_go_in() {
        // Email and password, the focus on either.
        assert_eq!(login_pair(&[text("Email", true), secret(false)]), Some((0, 1, true)));
        assert_eq!(login_pair(&[text("Email", false), secret(true)]), Some((0, 1, true)));
        // The only text field, captioned with nothing useful.
        assert_eq!(login_pair(&[text("", true), secret(false)]), Some((0, 1, false)));
        // A search box before the form is skipped; the login is the named one.
        assert_eq!(login_pair(&[text("Search or filter", false), text("Username", true), secret(false)]), Some((1, 2, true)));
    }

    #[test]
    fn anything_in_doubt_is_not_a_login_form() {
        // One field and no password: GitLab's search box.
        assert_eq!(login_pair(&[text("Search or filter", true)]), None);
        assert_eq!(login_pair(&[text("Search or filter", true), text("Other", false)]), None);
        // A search box and a password: the search box is no login.
        assert_eq!(login_pair(&[text("Search", true), secret(false)]), None);
        // Two passwords: signing up, or changing one.
        assert_eq!(login_pair(&[text("Email", true), secret(false), secret(false)]), None);
        // Two unnamed text fields: which one is the login is a guess.
        assert_eq!(login_pair(&[text("", true), text("", false), secret(false)]), None);
        // The password comes first: nothing before it to take the login.
        assert_eq!(login_pair(&[secret(true), text("Email", false)]), None);
        // The focus is elsewhere in the form.
        assert_eq!(login_pair(&[text("Company", true), text("Email", false), secret(false)]), None);
    }

    #[test]
    fn domain_is_extracted_from_urls() {
        assert_eq!(domain_of("https://www.github.com/login?x=1").as_deref(), Some("github.com"));
        assert_eq!(domain_of("http://user@accounts.google.com:8443/").as_deref(), Some("accounts.google.com"));
        assert_eq!(domain_of("about:blank"), None);
    }
}
