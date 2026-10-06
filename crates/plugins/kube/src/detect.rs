//! Finding a cluster on a server: one fixed script over a command channel.
//!
//! The script reads nothing: it only says which of the known places hold a
//! kubeconfig and whether the login may read it — as itself, through
//! `sudo -n`, or not at all. The kubeconfig itself is read later, when a
//! person opens the cluster, by a command made here from the kind alone: the
//! server's answer never becomes part of a command.

use serde::{Deserialize, Serialize};

/// Which Kubernetes runs its control plane on the server. Only a master
/// counts: an agent, a worker node, or a kubeconfig lying in some home
/// directory is not a cluster of this server's, and nothing is offered for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    K3s,
    Rke2,
    Kubeadm,
    K0s,
    Microk8s,
    /// minikube's control plane runs in a container on the server, and its
    /// kubeconfig is the login's own.
    Minikube,
}

/// Whether the login may read the master's kubeconfig.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    Readable,
    /// Through `sudo -n`: allowed without a password.
    Sudo,
    /// There, but neither: sudo wants a password, or is not allowed.
    Denied,
}

/// A master the script found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Found {
    pub kind: Kind,
    pub access: Access,
}

/// What the script said about the server.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Detection {
    pub found: Vec<Found>,
    /// `/etc/machine-id`: the same machine under two names is one server.
    pub machine: Option<String>,
}

/// The marker every line of the answer begins with; anything else on stdout —
/// a banner from a shell's rc file — is not the script's.
const MARK: &str = "kw-kube";
/// The script's last line: a server that let the login in but never ran the
/// script — a git host, which takes commands of its own only — does not say
/// it.
const DONE: &str = "kw-kube-done";
const MACHINE: &str = "kw-kube-machine";

/// The script. POSIX sh, nothing interpolated into it. A kind is reported
/// only where its control plane lives: a sign of the master *and* the
/// master's own kubeconfig.
pub const SCRIPT: &str = r#"kw_check() {
  if [ -r "$2" ]; then echo "kw-kube $1 readable"
  elif sudo -n test -r "$2" 2>/dev/null; then echo "kw-kube $1 sudo"
  else echo "kw-kube $1 denied"; fi
}
if [ -e /etc/rancher/k3s/k3s.yaml ]; then kw_check k3s /etc/rancher/k3s/k3s.yaml; fi
if [ -e /etc/rancher/rke2/rke2.yaml ]; then kw_check rke2 /etc/rancher/rke2/rke2.yaml; fi
if [ -e /etc/kubernetes/admin.conf ] && [ -e /etc/kubernetes/manifests/kube-apiserver.yaml ] 2>/dev/null; then kw_check kubeadm /etc/kubernetes/admin.conf; fi
if [ -e /var/lib/k0s/pki/admin.conf ]; then kw_check k0s /var/lib/k0s/pki/admin.conf; fi
if command -v microk8s >/dev/null 2>&1; then
  if microk8s config >/dev/null 2>&1; then echo "kw-kube microk8s readable"
  elif sudo -n microk8s config >/dev/null 2>&1; then echo "kw-kube microk8s sudo"
  else echo "kw-kube microk8s denied"; fi
fi
if command -v minikube >/dev/null 2>&1 && [ -d "$HOME/.minikube/profiles" ] && [ -r "$HOME/.kube/config" ]; then echo "kw-kube minikube readable"; fi
[ -r /etc/machine-id ] && echo "kw-kube-machine $(cat /etc/machine-id)"
echo kw-kube-done"#;

/// Reads the script's answer. A line with the marker that does not parse is
/// an error: the script is ours, and an answer it could not have given means
/// something else answered.
///
/// `None` means the script did not run at all: a server with no shell.
pub fn parse(stdout: &str) -> anyhow::Result<Option<Detection>> {
    if !stdout.lines().any(|l| l.trim() == DONE) {
        return Ok(None);
    }
    let mut out = Detection::default();
    for line in stdout.lines().map(str::trim).filter(|l| l.starts_with(MARK) && *l != DONE) {
        if let Some(id) = line.strip_prefix(MACHINE) {
            let id = id.trim();
            if !id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_hexdigit()) {
                out.machine = Some(id.to_ascii_lowercase());
            }
            continue;
        }
        let mut parts = line.split_whitespace().skip(1);
        let (Some(kind), Some(access), None) = (parts.next(), parts.next(), parts.next()) else {
            anyhow::bail!(keyward_core::fault!("err.kubeDetectGarbled", "line" => line));
        };
        let kind: Kind = serde_json::from_value(serde_json::Value::String(kind.to_string()))
            .map_err(|_| keyward_core::fault!("err.kubeDetectGarbled", "line" => line))?;
        let access: Access = serde_json::from_value(serde_json::Value::String(access.to_string()))
            .map_err(|_| keyward_core::fault!("err.kubeDetectGarbled", "line" => line))?;
        if !out.found.iter().any(|f| f.kind == kind) {
            out.found.push(Found { kind, access });
        }
    }
    Ok(Some(out))
}

/// The command that reads the master's kubeconfig — made from the kind alone.
pub fn read_command(kind: Kind, access: Access) -> anyhow::Result<String> {
    let plain = match kind {
        Kind::K3s => "cat -- /etc/rancher/k3s/k3s.yaml",
        Kind::Rke2 => "cat -- /etc/rancher/rke2/rke2.yaml",
        Kind::Kubeadm => "cat -- /etc/kubernetes/admin.conf",
        Kind::K0s => "cat -- /var/lib/k0s/pki/admin.conf",
        Kind::Minikube => "cat -- \"$HOME/.kube/config\"",
        Kind::Microk8s => "microk8s config",
    };
    match access {
        Access::Readable => Ok(plain.to_string()),
        Access::Sudo => Ok(format!("sudo -n {plain}")),
        Access::Denied => anyhow::bail!(keyward_core::fault!("err.kubeNeedsSudo")),
    }
}

/// The context to take from the kubeconfig: minikube's lives among the
/// login's own, and only it is this server's.
pub fn context_of(kind: Kind) -> Option<&'static str> {
    match kind {
        Kind::Minikube => Some("minikube"),
        _ => None,
    }
}

/// A file a kubeconfig names on the server, read as the kubeconfig was. The
/// path comes from the server, so it is quoted for the shell whole.
pub fn read_file_command(path: &str, access: Access) -> anyhow::Result<String> {
    if path.contains('\0') || path.contains('\n') {
        anyhow::bail!(keyward_core::fault!("err.kubeBadPath"));
    }
    let quoted = format!("'{}'", path.replace('\'', "'\\''"));
    match access {
        Access::Readable => Ok(format!("cat -- {quoted}")),
        Access::Sudo => Ok(format!("sudo -n cat -- {quoted}")),
        Access::Denied => anyhow::bail!(keyward_core::fault!("err.kubeNeedsSudo")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_master_is_read_past_a_banner_with_its_machine() {
        let got = parse("Welcome to Ubuntu\nkw-kube k3s sudo\nkw-kube k3s sudo\nkw-kube-machine 0123abcdEF\nkw-kube-done\n").unwrap().unwrap();
        assert_eq!(got.found, vec![Found { kind: Kind::K3s, access: Access::Sudo }]);
        assert_eq!(got.machine.as_deref(), Some("0123abcdef"));
        assert_eq!(parse("kw-kube-done\n").unwrap().unwrap(), Detection::default(), "no master: nothing");
        // A git host: in, but no shell ran the script.
        assert_eq!(parse("Hi alex! You've successfully authenticated, but GitHub does not provide shell access.").unwrap(), None);
    }

    #[test]
    fn an_answer_the_script_could_not_give_is_an_error() {
        assert!(parse("kw-kube openshift readable\nkw-kube-done").is_err());
        assert!(parse("kw-kube kubeconfig readable\nkw-kube-done").is_err(), "a stray kubeconfig is no kind of ours");
        assert!(parse("kw-kube k3s maybe\nkw-kube-done").is_err());
        assert!(parse("kw-kube k3s readable; rm -rf /\nkw-kube-done").is_err());
        let odd = parse("kw-kube-machine $(reboot)\nkw-kube-done").unwrap().unwrap();
        assert_eq!(odd.machine, None, "a machine id is hex or nothing");
    }

    #[test]
    fn commands_come_from_the_kind_and_a_path_is_quoted_whole() {
        assert_eq!(read_command(Kind::K3s, Access::Sudo).unwrap(), "sudo -n cat -- /etc/rancher/k3s/k3s.yaml");
        assert!(read_command(Kind::K3s, Access::Denied).is_err());
        assert_eq!(context_of(Kind::Minikube), Some("minikube"));
        assert_eq!(read_file_command("/home/u/.minikube/ca.crt", Access::Readable).unwrap(), "cat -- '/home/u/.minikube/ca.crt'");
        assert_eq!(read_file_command("/x/it's; rm -rf ~", Access::Readable).unwrap(), "cat -- '/x/it'\\''s; rm -rf ~'");
        assert!(read_file_command("/x\nrm", Access::Readable).is_err());
    }
}
