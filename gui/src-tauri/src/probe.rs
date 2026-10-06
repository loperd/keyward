//! Why the daemon does not answer: it is coming up, or it will not.
//!
//! Asked only after a request to `~/.keyward/d.sock` failed. The window shows
//! a loader while the daemon starts and an error with its reason when it does
//! not: the LaunchAgent is not there, the process keeps exiting, or it runs
//! and its socket stays silent.

use std::os::unix::net::UnixStream;
use std::process::Command;

use serde::Serialize;

/// The LaunchAgent the daemon runs under.
const LABEL: &str = "me.loper";

/// How long a running daemon may take to open its socket: unlocking the
/// keychain and starting the plugins take a few seconds, not half a minute.
const GRACE_SECS: u64 = 30;

#[derive(Debug, Serialize, PartialEq)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Probe {
    /// The socket takes connections: the failure was the daemon's answer, and
    /// the window shows that error as it is.
    Answers,
    /// The daemon is coming up: a loader.
    Starting,
    /// It will not come up by itself; `reason` is an error code with its
    /// values, in the daemon's own form.
    Down { reason: String },
}

/// What `launchctl print` says about the job.
#[derive(Debug, Default, PartialEq)]
struct Job {
    running: bool,
    pid: Option<u32>,
    /// `None` when it never exited.
    last_exit: Option<i32>,
}

fn parse_job(text: &str) -> Job {
    let mut job = Job::default();
    // Only the job's own lines: nested blocks (`endpoints`, `sockets`) have
    // their own `state =` at a deeper indent.
    for line in text.lines().filter(|l| l.starts_with('\t') && !l.starts_with("\t\t")) {
        let Some((key, value)) = line.trim().split_once(" = ") else { continue };
        match key {
            "state" => job.running = value == "running",
            "pid" => job.pid = value.parse().ok(),
            "last exit code" => job.last_exit = value.parse().ok(),
            _ => {}
        }
    }
    job
}

/// `ps -o etime`: `[[dd-]hh:]mm:ss`.
fn parse_etime(text: &str) -> Option<u64> {
    let text = text.trim();
    let (days, rest) = match text.split_once('-') {
        Some((d, r)) => (d.parse::<u64>().ok()?, r),
        None => (0, text),
    };
    let parts: Vec<u64> = rest.split(':').map(|p| p.parse().ok()).collect::<Option<_>>()?;
    let (h, m, s) = match parts.as_slice() {
        [m, s] => (0, *m, *s),
        [h, m, s] => (*h, *m, *s),
        _ => return None,
    };
    Some(days * 86400 + h * 3600 + m * 60 + s)
}

fn age_of(pid: u32) -> Option<u64> {
    let out = Command::new("/bin/ps").args(["-o", "etime=", "-p", &pid.to_string()]).output().ok()?;
    parse_etime(&String::from_utf8_lossy(&out.stdout))
}

/// The daemon's last error line, for the reason: what it said before it went.
fn last_error() -> Option<String> {
    let log = keyward_core::paths::base_dir().join("daemon.log");
    let text = std::fs::read(&log).ok()?;
    let tail = &text[text.len().saturating_sub(64 * 1024)..];
    let tail = String::from_utf8_lossy(tail);
    let line = tail.lines().rev().find(|l| l.contains("ERROR"))?;
    let plain: String = strip_ansi(line);
    // The message after the target: `… ERROR keyward::daemon: <message>`.
    let message = plain.split_once("ERROR").map(|(_, m)| m.trim()).unwrap_or(&plain);
    let message = message.split_once(": ").map(|(_, m)| m).unwrap_or(message);
    Some(message.chars().take(240).collect())
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            for c in chars.by_ref() {
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn down(code: &str, args: &[(&str, String)]) -> Probe {
    let mut f = keyward_core::fault::Fault::new(code);
    for (k, v) in args {
        f = f.with(*k, v);
    }
    Probe::Down { reason: f.to_string() }
}

/// What the job's state means for the window.
fn verdict(job: Option<Job>, installed: bool, age: impl Fn(u32) -> Option<u64>, log: impl Fn() -> Option<String>) -> Probe {
    let Some(job) = job else {
        return if installed { down("err.daemonNotLoaded", &[]) } else { down("err.daemonNotInstalled", &[]) };
    };
    if job.running {
        let Some(pid) = job.pid else { return Probe::Starting };
        return match age(pid) {
            Some(secs) if secs < GRACE_SECS => Probe::Starting,
            Some(secs) => down("err.daemonSocketSilent", &[("seconds", secs.to_string())]),
            // The process is gone between the two looks: launchd is on it.
            None => Probe::Starting,
        };
    }
    match job.last_exit {
        Some(code) if code != 0 => down("err.daemonExits", &[("code", code.to_string()), ("log", log().unwrap_or_default())]),
        // Never ran yet, or left cleanly and is about to be started again.
        _ => Probe::Starting,
    }
}

pub fn probe() -> Probe {
    if UnixStream::connect(keyward_core::paths::control_socket()).is_ok() {
        return Probe::Answers;
    }
    let uid = unsafe { libc::getuid() };
    let plist = std::env::var_os("HOME").map(std::path::PathBuf::from).map(|h| h.join(format!("Library/LaunchAgents/{LABEL}.plist")));
    let installed = plist.is_some_and(|p| p.exists());
    let job = Command::new("/bin/launchctl")
        .args(["print", &format!("gui/{uid}/{LABEL}")])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| parse_job(&String::from_utf8_lossy(&o.stdout)));
    verdict(job, installed, age_of, last_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RUNNING: &str = "gui/501/me.loper = {\n\tactive count = 1\n\tstate = running\n\truns = 1\n\tpid = 1281\n\tlast exit code = (never exited)\n\tendpoints = {\n\t\tstate = active\n\t}\n}\n";
    const CRASHED: &str = "gui/501/me.loper = {\n\tstate = spawn scheduled\n\truns = 7\n\tlast exit code = 1\n}\n";

    #[test]
    fn the_job_is_read_from_its_own_lines() {
        assert_eq!(parse_job(RUNNING), Job { running: true, pid: Some(1281), last_exit: None });
        assert_eq!(parse_job(CRASHED), Job { running: false, pid: None, last_exit: Some(1) });
    }

    #[test]
    fn elapsed_time_in_every_form() {
        assert_eq!(parse_etime("  00:07\n"), Some(7));
        assert_eq!(parse_etime("01:02:03"), Some(3723));
        assert_eq!(parse_etime("2-00:00:01"), Some(172801));
        assert_eq!(parse_etime(""), None);
    }

    #[test]
    fn starting_is_told_from_down() {
        let log = || Some("the vault would not open".to_string());
        assert_eq!(verdict(Some(parse_job(RUNNING)), true, |_| Some(5), log), Probe::Starting);
        assert!(matches!(verdict(Some(parse_job(RUNNING)), true, |_| Some(120), log), Probe::Down { reason } if reason.starts_with("err.daemonSocketSilent")));
        assert!(matches!(verdict(Some(parse_job(CRASHED)), true, |_| None, log), Probe::Down { reason } if reason.starts_with("err.daemonExits") && reason.contains("would not open")));
        assert!(matches!(verdict(None, true, |_| None, log), Probe::Down { reason } if reason == "err.daemonNotLoaded"));
        assert!(matches!(verdict(None, false, |_| None, log), Probe::Down { reason } if reason == "err.daemonNotInstalled"));
    }

    #[test]
    fn colours_are_taken_out_of_a_log_line() {
        assert_eq!(strip_ansi("\x1b[31mERROR\x1b[0m x"), "ERROR x");
    }
}
