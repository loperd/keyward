//! Hardening of a process that holds secrets: the daemon, the window and the
//! plugins.
//!
//! A secret has to be in memory to be used — decrypted to be shown, to be
//! typed, to be sent. What can be done is to keep that memory from leaving
//! the process: no core dump that writes it to disk when the process falls,
//! and no debugger that reads it while it lives. macOS encrypts swap on its
//! own, so a page pushed out of memory is not readable on disk either.

/// Called first thing, before any secret is anywhere near.
pub fn process() {
    no_core_dumps();
    no_debugger();
}

/// A falling process must not leave its memory on the disk.
fn no_core_dumps() {
    #[cfg(unix)]
    {
        let none = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        // SAFETY: setrlimit with a valid, fully initialised limit.
        let _ = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &none) };
    }
}

/// No debugger may attach, not even one run by the same user: attaching is
/// the plainest way to read a live process's memory. A debug build is left
/// open — it is the one a developer attaches to.
fn no_debugger() {
    #[cfg(all(target_os = "macos", not(debug_assertions)))]
    {
        const PT_DENY_ATTACH: libc::c_int = 31;
        // SAFETY: PT_DENY_ATTACH takes no address and no data.
        let _ = unsafe { libc::ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) };
    }
}
