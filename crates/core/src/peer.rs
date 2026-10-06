//! Who is at the other end of the socket.
//!
//! Mode 0600 on `~/.keyward/d.sock` cuts off another user but not another
//! process under the same uid: `nc -U ~/.keyward/d.sock` used to read the
//! password exactly as the application does. Here the daemon learns the peer's
//! audit token (`getsockopt(SOL_LOCAL, LOCAL_PEERTOKEN)`) and checks its code
//! signature through Security.framework.
//!
//! The audit token rather than the pid: a pid names whatever runs under it
//! now. A process could connect, hand the socket to a child and `exec` a
//! signed keyward binary in its own pid — the pid would then pass the check.
//! The audit token carries the process's version, which `exec` moves on, so
//! the check is of the very program that connected.
//!
//! The requirement is built out of our own signature rather than hard-coded:
//! the `keyward-dev` identity is created afresh on every machine
//! (`scripts/signing.sh`), and a fingerprint written into the code would mean
//! "works for the author only". The daemon reads the certificate it is signed
//! with itself, takes the root of the chain (for a self-signed identity the
//! root is also the leaf) and demands the same root of its peer: the
//! application and the CLI, signed with one identity, get through; an outsider
//! process does not.
//!
//! What this does not give: a peer can be checked only while it is alive, and
//! the system holds a connection's pid for it until the socket closes — so
//! there is no race of "swap the process between accept and the check" here,
//! but a signature does not save us from a hole in the application itself. This
//! is a line against "any process under the same uid", not against a
//! compromised keyward.

use std::os::fd::AsRawFd;

/// What the daemon managed to learn about a peer's signature.
///
/// Our identity alone is not enough: each of our programs has a role of its
/// own, and a program of ours with an identifier the daemon does not know is
/// an outsider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    /// The application (`me.loper`): the window a person works in.
    App,
    /// The CLI (`me.loper.cli`): scripts, the install, ssh's `resolve`. It is
    /// ours, but anything the person runs can run it, so it gets its own,
    /// narrower list.
    Cli,
    /// The signature belongs to somebody else, is ad hoc, or is not there at
    /// all.
    Alien,
    /// Ours, and signed as the browser bridge for passkeys
    /// (`me.loper.passkey-host`). The same identity, but the least
    /// of rights: it may ask for passkeys and nothing else — not a password,
    /// not a lock, not a deletion. A bridge that a browser starts on a page's
    /// behalf must not be a way to the rest of the vault.
    Bridge,
    /// There is nothing to check with: the daemon itself is not signed
    /// (`cargo run`). This is neither "ours" nor "theirs" but "impossible to
    /// say", and in that case the sensor decides, not the signature.
    Unknown,
}

/// The daemon's peer.
///
/// A secret goes either into the socket or into a plugin, and those are three
/// different cases rather than one: a connection has a process with a
/// signature; a built-in plugin's process is the very same one (the secret goes
/// nowhere); an external plugin's is somebody else's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Peer {
    /// A process that came to the control socket.
    Socket {
        pid: i32,
        /// The path to the binary, for the log only: the signature decides,
        /// not the name.
        path: Option<String>,
        trust: Trust,
    },
    /// A built-in plugin on an event of the daemon's (a tick, a change of
    /// items). There is nobody at the sensor, and asking on a timer means
    /// nothing; the secret meanwhile stays in the same process's memory.
    Builtin,
    /// An external plugin on an event of the daemon's: its process is somebody
    /// else's, and a secret fetched at the plugin's own initiative would leave
    /// the machine.
    External,
}

impl Peer {
    /// Learn a connection's peer: its audit token, and from it the pid, the
    /// path and the signature.
    pub fn inspect(stream: &impl AsRawFd) -> Self {
        match token(stream) {
            Ok(t) => {
                let pid = t.pid();
                Self::Socket { pid, path: imp::binary_path(pid), trust: imp::trust(&t) }
            }
            Err(e) => {
                tracing::warn!(error = %e, "a connection's audit token could not be read; it is an outsider");
                Self::Socket { pid: -1, path: None, trust: Trust::Alien }
            }
        }
    }

    /// The pid, for the log. Plugins have no process of their own, so zero.
    pub fn pid(&self) -> i32 {
        match self {
            Self::Socket { pid, .. } => *pid,
            _ => 0,
        }
    }

    /// The path to a peer's binary, for the log.
    pub fn path(&self) -> &str {
        match self {
            Self::Socket { path: Some(p), .. } => p,
            Self::Socket { path: None, .. } => "?",
            Self::Builtin => "<a built-in plugin>",
            Self::External => "<an external plugin>",
        }
    }

    /// Whether the peer was verified, in one word for the log.
    pub fn verdict(&self) -> &'static str {
        match self {
            Self::Socket { trust: Trust::App, .. } => "ours, the application",
            Self::Socket { trust: Trust::Cli, .. } => "ours, the CLI",
            Self::Socket { trust: Trust::Bridge, .. } => "ours, the passkey bridge",
            Self::Socket { trust: Trust::Alien, .. } => "alien",
            Self::Socket { trust: Trust::Unknown, .. } => "nothing to check with",
            Self::Builtin => "a built-in plugin",
            Self::External => "an external plugin",
        }
    }
}

/// Build the requirement in advance, at the daemon's start.
///
/// Building it lazily would work too, but then "the daemon is not signed"
/// would surface in the log in the middle of the work rather than where it is
/// looked for: at start-up.
pub fn init() {
    imp::init();
}

/// Whose signature the program at the other end of the socket carries. The
/// client asks it of the daemon the way the daemon asks it of the client.
pub fn trust_of(stream: &impl AsRawFd) -> Trust {
    match token(stream) {
        Ok(t) => imp::trust(&t),
        Err(_) => Trust::Alien,
    }
}

/// A process's audit token: `audit_token_t`, eight words.
#[derive(Debug, Clone, Copy)]
pub struct AuditToken(pub [u32; 8]);

impl AuditToken {
    /// The pid, where the kernel puts it (`audit_token_to_pid`).
    pub fn pid(&self) -> i32 {
        self.0[5] as i32
    }
}

/// The audit token of whoever connected the socket, taken by the kernel at
/// the connection.
pub fn token(stream: &impl AsRawFd) -> std::io::Result<AuditToken> {
    #[cfg(target_os = "macos")]
    {
        let mut t = [0u32; 8];
        let mut len = std::mem::size_of_val(&t) as libc::socklen_t;
        // SAFETY: the descriptor is alive, the buffer is ours, the length
        // matches `audit_token_t`.
        let ok = unsafe {
            libc::getsockopt(stream.as_raw_fd(), libc::SOL_LOCAL, libc::LOCAL_PEERTOKEN, t.as_mut_ptr().cast(), &mut len)
        };
        if ok != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if len as usize != std::mem::size_of_val(&t) {
            return Err(std::io::Error::other("the audit token came back the wrong size"));
        }
        Ok(AuditToken(t))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let pid = pid(stream)?;
        Ok(AuditToken([0, 0, 0, 0, 0, pid as u32, 0, 0]))
    }
}

/// A browser the passkey bridge may be started by: its name, for the words a
/// person reads, and its developer's Team ID, which is what is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Browser {
    pub name: &'static str,
    pub team: &'static str,
}

/// The browsers whose Team ID was read off a signed build
/// (`codesign -dv`), not written from memory. One that is missing is refused
/// until it is checked and added: a wrong Team ID here would let another
/// developer's program pass for a browser.
pub const BROWSERS: &[Browser] = &[
    Browser { name: "Google Chrome", team: "EQHXZ8M8AV" },
    Browser { name: "Arc", team: "S6N382Y83G" },
];

/// Which browser a process is, by its signature; `None` for anything else.
pub fn browser(pid: i32) -> Option<Browser> {
    imp::browser(pid)
}

/// A process's parent. `None` when the process is gone or its parent is
/// launchd — an orphan was started by nobody.
pub fn parent(pid: i32) -> Option<i32> {
    #[cfg(target_os = "macos")]
    {
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
        // SAFETY: the buffer is ours and its size is honest.
        let n = unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, std::ptr::addr_of_mut!(info).cast(), size) };
        if n != size {
            return None;
        }
        let ppid = info.pbi_ppid as i32;
        (ppid > 1).then_some(ppid)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = pid;
        None
    }
}

/// The process whose window is in front: the owner of the first ordinary
/// window on screen. Read from the window server rather than from
/// `NSWorkspace`, whose idea of the front application is refreshed on a run
/// loop the daemon does not have.
pub fn front() -> Option<i32> {
    imp::front()
}

/// Whose process is at the other end of the socket.
pub fn uid(stream: &impl AsRawFd) -> std::io::Result<u32> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: the descriptor is alive and both pointers lead to our own
    // variables.
    let ok = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if ok != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(uid)
}

/// The pid of the process at the other end. `LOCAL_PEERPID` gives whoever
/// connected the socket, and does not change while the connection lives.
pub fn pid(stream: &impl AsRawFd) -> std::io::Result<i32> {
    let mut pid: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: the descriptor is alive, the buffer is ours, the length matches
    // the type.
    let ok = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            std::ptr::addr_of_mut!(pid).cast(),
            &mut len,
        )
    };
    if ok != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(pid)
}

#[cfg(target_os = "macos")]
mod imp {
    use std::ffi::c_void;
    use std::sync::OnceLock;

    use super::{AuditToken, Trust};

    type CFTypeRef = *const c_void;
    type OSStatus = i32;

    /// `kSecCSDefaultFlags`: none of the calls needed here take flags.
    const DEFAULT_FLAGS: u32 = 0;
    /// `kSecCSSigningInformation`: asking the system for the signing
    /// certificates.
    const SIGNING_INFO: u32 = 1 << 1;
    /// `kCFStringEncodingUTF8`.
    const UTF8: u32 = 0x0800_0100;

    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        fn CFRelease(cf: CFTypeRef);
        fn CFDictionaryCreate(
            allocator: CFTypeRef,
            keys: *const CFTypeRef,
            values: *const CFTypeRef,
            count: isize,
            key_callbacks: *const c_void,
            value_callbacks: *const c_void,
        ) -> CFTypeRef;
        fn CFDictionaryGetValue(dict: CFTypeRef, key: CFTypeRef) -> CFTypeRef;
        fn CFDataCreate(allocator: CFTypeRef, bytes: *const u8, len: isize) -> CFTypeRef;
        fn CFStringCreateWithBytes(
            allocator: CFTypeRef,
            bytes: *const u8,
            len: isize,
            encoding: u32,
            external: u8,
        ) -> CFTypeRef;
        fn CFArrayGetCount(array: CFTypeRef) -> isize;
        fn CFArrayGetValueAtIndex(array: CFTypeRef, index: isize) -> CFTypeRef;
        fn CFDataGetBytePtr(data: CFTypeRef) -> *const u8;
        fn CFDataGetLength(data: CFTypeRef) -> isize;
        static kCFTypeDictionaryKeyCallBacks: c_void;
        static kCFTypeDictionaryValueCallBacks: c_void;
    }

    #[link(name = "CoreGraphics", kind = "framework")]
    extern "C" {
        fn CGWindowListCopyWindowInfo(option: u32, relative_to: u32) -> CFTypeRef;
        static kCGWindowLayer: CFTypeRef;
        static kCGWindowOwnerPID: CFTypeRef;
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        fn CFNumberGetValue(number: CFTypeRef, kind: i32, value: *mut c_void) -> u8;
        fn CFNumberCreate(allocator: CFTypeRef, kind: i32, value: *const c_void) -> CFTypeRef;
    }

    /// `kCGWindowListOptionOnScreenOnly | kCGWindowListExcludeDesktopElements`.
    const ON_SCREEN: u32 = (1 << 0) | (1 << 4);
    /// `kCFNumberSInt32Type`.
    const NUMBER_I32: i32 = 3;

    #[link(name = "Security", kind = "framework")]
    extern "C" {
        static kSecGuestAttributeAudit: CFTypeRef;
        static kSecGuestAttributePid: CFTypeRef;
        static kSecCodeInfoCertificates: CFTypeRef;
        fn SecCodeCopySelf(flags: u32, code: *mut CFTypeRef) -> OSStatus;
        fn SecCodeCopySigningInformation(
            code: CFTypeRef,
            flags: u32,
            information: *mut CFTypeRef,
        ) -> OSStatus;
        fn SecCertificateCopyData(certificate: CFTypeRef) -> CFTypeRef;
        fn SecRequirementCreateWithString(
            text: CFTypeRef,
            flags: u32,
            requirement: *mut CFTypeRef,
        ) -> OSStatus;
        fn SecCodeCopyGuestWithAttributes(
            host: CFTypeRef,
            attributes: CFTypeRef,
            flags: u32,
            guest: *mut CFTypeRef,
        ) -> OSStatus;
        fn SecCodeCheckValidity(code: CFTypeRef, flags: u32, requirement: CFTypeRef) -> OSStatus;
    }

    /// A CF object obtained by the Copy rule: released on the way out. The Get
    /// rule (`CFDictionaryGetValue`, `CFArrayGetValueAtIndex`) is not wrapped
    /// here — such references belong to somebody else, and a `CFRelease` on
    /// them would take the daemon down at the very next collection.
    struct Owned(CFTypeRef);

    impl Drop for Owned {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: the pointer was obtained by the Copy rule and is
                // held by nobody else.
                unsafe { CFRelease(self.0) };
            }
        }
    }

    /// The requirement on a peer's signature. A `SecRequirementRef` is
    /// immutable and lives to the end of the process, so it can be held in
    /// common.
    struct Requirement(CFTypeRef);

    // SAFETY: the object is only read (`SecCodeCheckValidity`), and CF objects
    // are thread-safe as long as they are not mutated.
    unsafe impl Send for Requirement {}
    unsafe impl Sync for Requirement {}

    static REQUIREMENT: OnceLock<Option<Requirement>> = OnceLock::new();
    static BRIDGE: OnceLock<Option<Requirement>> = OnceLock::new();
    static APP: OnceLock<Option<Requirement>> = OnceLock::new();
    static CLI: OnceLock<Option<Requirement>> = OnceLock::new();

    /// The signing identifiers of our programs (`scripts/signing.sh`).
    const BRIDGE_ID: &str = "me.loper.passkey-host";
    const APP_ID: &str = "me.loper";
    const CLI_ID: &str = "me.loper.cli";

    pub fn init() {
        let _ = requirement();
    }

    fn requirement() -> Option<&'static Requirement> {
        REQUIREMENT
            .get_or_init(|| {
                let Some(hash) = own_anchor() else {
                    tracing::warn!(
                        "the daemon is not signed, so there is nothing to check a peer with; \
                         passwords go out on biometrics alone. \
                         Install keyward through scripts/install.sh: it signs the CLI too"
                    );
                    return None;
                };
                // The root of the chain, not a name and not an identifier:
                // anyone can forge a name with a certificate of their own,
                // while the root is what "the same identity" means.
                let text = format!("certificate root = H\"{hash}\"");
                // The bridge: the same root plus its own identifier. The
                // identifier alone proves nothing (anyone can sign anything
                // with it); together with the root it can only be ours.
                let bridge = format!("{text} and identifier \"{BRIDGE_ID}\"");
                let _ = BRIDGE.set(create(&bridge));
                let _ = APP.set(create(&format!("{text} and identifier \"{APP_ID}\"")));
                let _ = CLI.set(create(&format!("{text} and identifier \"{CLI_ID}\"")));
                match create(&text) {
                    Some(req) => {
                        tracing::info!(requirement = %text, "the lock on the socket: passwords to our own only");
                        Some(req)
                    }
                    None => {
                        tracing::warn!(requirement = %text, "the requirement did not parse; peers stay unverified");
                        None
                    }
                }
            })
            .as_ref()
    }

    /// A peer's signature: which of our programs, somebody else's, or
    /// nothing to check with.
    pub fn trust(token: &AuditToken) -> Trust {
        let Some(req) = requirement() else { return Trust::Unknown };
        if token.pid() <= 0 || !matches(token, req) {
            return Trust::Alien;
        }
        // The narrower requirements second: each is ours first.
        let is = |cell: &OnceLock<Option<Requirement>>| cell.get().and_then(Option::as_ref).is_some_and(|r| matches(token, r));
        if is(&BRIDGE) {
            Trust::Bridge
        } else if is(&APP) {
            Trust::App
        } else if is(&CLI) {
            Trust::Cli
        } else {
            // Signed by us, but none of the programs the daemon knows: a role
            // nobody gave it is no role at all.
            tracing::warn!(pid = token.pid(), "a program with our signature but an unknown identifier was refused");
            Trust::Alien
        }
    }

    /// The path to a process's binary, for the log.
    pub fn binary_path(pid: i32) -> Option<String> {
        if pid <= 0 {
            return None;
        }
        // PROC_PIDPATHINFO_MAXSIZE.
        let mut buf = vec![0u8; 4 * libc::PATH_MAX as usize];
        // SAFETY: the buffer is ours and the length is honest.
        let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
        if n <= 0 {
            return None;
        }
        buf.truncate(n as usize);
        String::from_utf8(buf).ok()
    }

    /// The SHA-1 of the root certificate of our own signature.
    ///
    /// `None` means there is no signature (the linker's ad hoc signature
    /// carries no certificates), and then there is nothing to compare a peer
    /// against.
    fn own_anchor() -> Option<String> {
        // SAFETY: every pointer is checked for null; objects from the Copy
        // rule are wrapped in `Owned`, those from the Get rule are not.
        unsafe {
            let mut me: CFTypeRef = std::ptr::null();
            if SecCodeCopySelf(DEFAULT_FLAGS, &mut me) != 0 || me.is_null() {
                return None;
            }
            let me = Owned(me);

            let mut info: CFTypeRef = std::ptr::null();
            if SecCodeCopySigningInformation(me.0, SIGNING_INFO, &mut info) != 0 || info.is_null() {
                return None;
            }
            let info = Owned(info);

            let certs = CFDictionaryGetValue(info.0, kSecCodeInfoCertificates);
            if certs.is_null() {
                return None;
            }
            let count = CFArrayGetCount(certs);
            if count <= 0 {
                return None;
            }
            // The last in the chain is the root. For a self-signed identity it
            // is also the leaf: a chain of one certificate.
            let root = CFArrayGetValueAtIndex(certs, count - 1);
            if root.is_null() {
                return None;
            }

            let der = Owned(SecCertificateCopyData(root));
            if der.0.is_null() {
                return None;
            }
            let ptr = CFDataGetBytePtr(der.0);
            let len = CFDataGetLength(der.0);
            if ptr.is_null() || len <= 0 {
                return None;
            }
            let bytes = std::slice::from_raw_parts(ptr, len as usize);

            use sha1::Digest as _;
            // The same fingerprint `security find-identity` shows: the
            // requirement is written by it.
            Some(sha1::Sha1::digest(bytes).iter().fold(String::new(), |mut s, b| {
                use std::fmt::Write as _;
                let _ = write!(s, "{b:02x}");
                s
            }))
        }
    }

    static BROWSER_REQS: OnceLock<Vec<(super::Browser, Option<Requirement>)>> = OnceLock::new();

    /// A browser by its signature. Checked by pid: a browser's process has no
    /// audit token to hand here, and it is alive for as long as the bridge it
    /// started holds its pipes.
    pub fn browser(pid: i32) -> Option<super::Browser> {
        if pid <= 1 {
            return None;
        }
        let reqs = BROWSER_REQS.get_or_init(|| {
            super::BROWSERS
                .iter()
                .map(|b| (*b, create(&format!("anchor apple generic and certificate leaf[subject.OU] = \"{}\"", b.team))))
                .collect()
        });
        reqs.iter().find(|(_, r)| r.as_ref().is_some_and(|r| matches_pid(pid, r))).map(|(b, _)| *b)
    }

    pub fn front() -> Option<i32> {
        // SAFETY: the array is released by `Owned`; its dictionaries and
        // numbers are borrowed by the Get rule and not released.
        unsafe {
            let list = Owned(CGWindowListCopyWindowInfo(ON_SCREEN, 0));
            if list.0.is_null() {
                return None;
            }
            let n = |dict: CFTypeRef, key: CFTypeRef| -> Option<i32> {
                let v = CFDictionaryGetValue(dict, key);
                if v.is_null() {
                    return None;
                }
                let mut out: i32 = 0;
                (CFNumberGetValue(v, NUMBER_I32, std::ptr::addr_of_mut!(out).cast()) != 0).then_some(out)
            };
            for i in 0..CFArrayGetCount(list.0) {
                let w = CFArrayGetValueAtIndex(list.0, i);
                if w.is_null() {
                    continue;
                }
                // Layer 0 is ordinary windows; menus, the dock and the like
                // lie above it.
                if n(w, kCGWindowLayer) == Some(0) {
                    return n(w, kCGWindowOwnerPID);
                }
            }
            None
        }
    }

    fn matches_pid(pid: i32, req: &Requirement) -> bool {
        // SAFETY: as in `matches`.
        unsafe {
            if kSecGuestAttributePid.is_null() {
                return false;
            }
            let number = Owned(CFNumberCreate(std::ptr::null(), NUMBER_I32, std::ptr::addr_of!(pid).cast()));
            if number.0.is_null() {
                return false;
            }
            let keys = [kSecGuestAttributePid];
            let values = [number.0];
            let attrs = Owned(CFDictionaryCreate(
                std::ptr::null(),
                keys.as_ptr(),
                values.as_ptr(),
                1,
                std::ptr::addr_of!(kCFTypeDictionaryKeyCallBacks),
                std::ptr::addr_of!(kCFTypeDictionaryValueCallBacks),
            ));
            if attrs.0.is_null() {
                return false;
            }
            let mut guest: CFTypeRef = std::ptr::null();
            if SecCodeCopyGuestWithAttributes(std::ptr::null(), attrs.0, DEFAULT_FLAGS, &mut guest) != 0 || guest.is_null() {
                return false;
            }
            let guest = Owned(guest);
            SecCodeCheckValidity(guest.0, DEFAULT_FLAGS, req.0) == 0
        }
    }

    fn create(text: &str) -> Option<Requirement> {
        // SAFETY: the string lives to the end of the call and the result is
        // checked for null.
        unsafe {
            let s = Owned(CFStringCreateWithBytes(
                std::ptr::null(),
                text.as_ptr(),
                text.len() as isize,
                UTF8,
                0,
            ));
            if s.0.is_null() {
                return None;
            }
            let mut req: CFTypeRef = std::ptr::null();
            if SecRequirementCreateWithString(s.0, DEFAULT_FLAGS, &mut req) != 0 || req.is_null() {
                return None;
            }
            Some(Requirement(req))
        }
    }

    /// Does the process satisfy the requirement?
    ///
    /// Any refusal from the system — the process died, there is no code, the
    /// signature did not check out — is a "no" rather than a panic: the daemon
    /// is obliged to outlive its peer.
    fn matches(token: &AuditToken, req: &Requirement) -> bool {
        // SAFETY: the dictionary is built out of our own objects, and every
        // result is checked for null and for a return code.
        unsafe {
            if kSecGuestAttributeAudit.is_null() {
                return false;
            }
            let data = Owned(CFDataCreate(std::ptr::null(), token.0.as_ptr().cast(), std::mem::size_of_val(&token.0) as isize));
            if data.0.is_null() {
                return false;
            }

            let keys = [kSecGuestAttributeAudit];
            let values = [data.0];
            let attrs = Owned(CFDictionaryCreate(
                std::ptr::null(),
                keys.as_ptr(),
                values.as_ptr(),
                1,
                std::ptr::addr_of!(kCFTypeDictionaryKeyCallBacks),
                std::ptr::addr_of!(kCFTypeDictionaryValueCallBacks),
            ));
            if attrs.0.is_null() {
                return false;
            }

            let mut guest: CFTypeRef = std::ptr::null();
            // The host is `NULL`: the system's root of trust.
            if SecCodeCopyGuestWithAttributes(std::ptr::null(), attrs.0, DEFAULT_FLAGS, &mut guest) != 0
                || guest.is_null()
            {
                return false;
            }
            let guest = Owned(guest);

            SecCodeCheckValidity(guest.0, DEFAULT_FLAGS, req.0) == 0
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use super::{AuditToken, Trust};

    pub fn init() {
        tracing::warn!("checking a peer's signature exists on macOS only");
    }

    pub fn trust(_token: &AuditToken) -> Trust {
        Trust::Unknown
    }

    pub fn binary_path(_pid: i32) -> Option<String> {
        None
    }

    pub fn browser(_pid: i32) -> Option<super::Browser> {
        None
    }

    pub fn front() -> Option<i32> {
        None
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    /// Run by hand with a browser open: `cargo test -p keyward-core live_ -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn live_front_window_and_browsers() {
        let front = super::front();
        println!("front window's owner: {front:?} -> {:?}", front.and_then(super::browser));
        for name in ["Arc", "Google Chrome"] {
            if let Ok(out) = std::process::Command::new("pgrep").args(["-x", name]).output() {
                for pid in String::from_utf8_lossy(&out.stdout).split_whitespace().filter_map(|p| p.parse::<i32>().ok()) {
                    println!("{name} {pid} -> {:?}", super::browser(pid));
                }
            }
        }
        println!("this process -> {:?}", super::browser(std::process::id() as i32));
    }
}
