//! What system answers on a host, before any login.
//!
//! An ssh server names itself in the first line it sends, the identification
//! string — `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5` — before a key or a
//! login is exchanged. That is enough to suggest the login a fresh server of
//! that kind is entered with: `ubuntu` on Ubuntu's images, `root` elsewhere.
//! Nothing is offered to the server and nothing is signed.

use std::time::Duration;

use serde::Serialize;
use tokio::io::AsyncReadExt as _;

use super::connect::reach_error;

/// How long the host has to answer with its name.
const WAIT: Duration = Duration::from_secs(6);

/// The identification line is at most 255 bytes; a server may send a few
/// lines of its own before it.
const MAX: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Banner {
    /// The identification line as the server sent it.
    pub banner: String,
    /// The system it names, when it names one.
    pub os: Option<String>,
    /// The login to suggest.
    pub login: String,
}

/// The system and the login to suggest, out of an identification line.
pub fn read(line: &str) -> Banner {
    let lower = line.to_ascii_lowercase();
    let known = [("ubuntu", "Ubuntu", "ubuntu"), ("debian", "Debian", "root"), ("raspbian", "Raspbian", "root"), ("freebsd", "FreeBSD", "root")];
    let (os, login) = known
        .iter()
        .find(|(needle, _, _)| lower.contains(needle))
        .map(|(_, os, login)| (Some((*os).to_string()), (*login).to_string()))
        .unwrap_or((None, "root".to_string()));
    Banner { banner: line.to_string(), os, login }
}

/// Connects, reads the server's identification line and hangs up.
pub async fn banner(host: &str, port: u16) -> anyhow::Result<Banner> {
    if host.is_empty() || host.contains(char::is_whitespace) || host.starts_with('-') {
        anyhow::bail!(keyward_core::fault!("err.sshBadHost"));
    }
    let run = async {
        let mut stream = tokio::net::TcpStream::connect((host, port)).await.map_err(|e| reach_error(host, e))?;
        let mut got = Vec::with_capacity(512);
        let mut chunk = [0u8; 512];
        loop {
            let n = stream.read(&mut chunk).await.map_err(|e| reach_error(host, e))?;
            if n == 0 {
                break;
            }
            got.extend_from_slice(&chunk[..n]);
            let text = String::from_utf8_lossy(&got);
            if let Some(line) = text.lines().find(|l| l.starts_with("SSH-")) {
                if text.contains('\n') {
                    return Ok(read(line.trim_end()));
                }
            }
            if got.len() > MAX {
                break;
            }
        }
        Err(keyward_core::fault!("err.sshNotSsh", "host" => host))
    };
    tokio::time::timeout(WAIT, run).await.unwrap_or_else(|_| Err(reach_error(host, "timed out")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_system_and_its_login_come_from_the_banner() {
        let b = read("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5");
        assert_eq!(b.os.as_deref(), Some("Ubuntu"));
        assert_eq!(b.login, "ubuntu");
        let b = read("SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3");
        assert_eq!((b.os.as_deref(), b.login.as_str()), (Some("Debian"), "root"));
        let b = read("SSH-2.0-OpenSSH_9.8");
        assert_eq!((b.os, b.login.as_str()), (None, "root"));
    }

    #[tokio::test]
    async fn a_server_is_read_before_any_login() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt as _;
            let (mut s, _) = listener.accept().await.unwrap();
            s.write_all(b"a greeting of its own\r\nSSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n").await.unwrap();
            tokio::time::sleep(Duration::from_secs(1)).await;
        });
        let b = banner("127.0.0.1", port).await.unwrap();
        assert_eq!(b.login, "ubuntu");
        assert!(banner("-oProxyCommand=x", 22).await.unwrap_err().to_string().starts_with("err.sshBadHost"));
    }
}
