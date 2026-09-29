//! Who is at the other end of the socket.
//!
//! Mode 0600 on `~/.keyward/d.sock` cuts off another user but not another
//! process under the same uid: `nc -U ~/.keyward/d.sock` used to read the
//! password exactly as the application does. Here the daemon learns the peer's
//! pid (`getsockopt(SOL_LOCAL, LOCAL_PEERPID)`) and compares its code signature
//! with its own through Security.framework.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    /// Signed with the same identity as the daemon itself.
    Ours,
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
    /// Learn a connection's peer: pid, path, signature.
    pub fn inspect(stream: &impl AsRawFd) -> Self {
        let pid = pid(stream).unwrap_or(-1);
        Self::Socket { pid, path: imp::binary_path(pid), trust: imp::trust(pid) }
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
            Self::Socket { trust: Trust::Ours, .. } => "ours",
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

/// Whether a process carries our signature. The client asks it of the daemon
/// the way the daemon asks it of the client.
pub fn trust(pid: i32) -> Trust {
    imp::trust(pid)
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

    use super::Trust;

    type CFTypeRef = *const c_void;
    type OSStatus = i32;

    /// `kSecCSDefaultFlags`: none of the calls needed here take flags.
    const DEFAULT_FLAGS: u32 = 0;
    /// `kSecCSSigningInformation`: asking the system for the signing
    /// certificates.
    const SIGNING_INFO: u32 = 1 << 1;
    /// `kCFNumberSInt32Type`: the pid, as `kSecGuestAttributePid` expects it.
    const NUMBER_I32: i32 = 3;
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
        fn CFNumberCreate(allocator: CFTypeRef, kind: i32, value: *const c_void) -> CFTypeRef;
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

    #[link(name = "Security", kind = "framework")]
    extern "C" {
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

    /// The signing identifier of the passkey bridge.
    const BRIDGE_ID: &str = "me.loper.passkey-host";

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

    /// A peer's signature: ours, somebody else's, or nothing to check with.
    pub fn trust(pid: i32) -> Trust {
        let Some(req) = requirement() else { return Trust::Unknown };
        if pid <= 0 {
            return Trust::Alien;
        }
        if !matches(pid, req) {
            return Trust::Alien;
        }
        // The narrower requirement second: a bridge is ours first.
        match BRIDGE.get().and_then(Option::as_ref) {
            Some(bridge) if matches(pid, bridge) => Trust::Bridge,
            _ => Trust::Ours,
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
    fn matches(pid: i32, req: &Requirement) -> bool {
        // SAFETY: the dictionary is built out of our own objects, and every
        // result is checked for null and for a return code.
        unsafe {
            if kSecGuestAttributePid.is_null() {
                return false;
            }
            let number = Owned(CFNumberCreate(
                std::ptr::null(),
                NUMBER_I32,
                std::ptr::addr_of!(pid).cast(),
            ));
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
    use super::Trust;

    pub fn init() {
        tracing::warn!("checking a peer's signature exists on macOS only");
    }

    pub fn trust(_pid: i32) -> Trust {
        Trust::Unknown
    }

    pub fn binary_path(_pid: i32) -> Option<String> {
        None
    }
}
