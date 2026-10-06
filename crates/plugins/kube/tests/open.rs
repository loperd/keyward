//! Opening a cluster found on a server: the kubeconfig is read over ssh with
//! sudo, the API is reached through the session — not dialled from here — and
//! TLS inside the tunnel is checked against the kubeconfig's authority.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use common::{core, sandbox, serve, settle, user_public, Answers};
use keyward_plugin::Plugin;
use keyward_plugin_kube::KubePlugin;
use keyward_ssh_client::link::testing::{Page, PageLane};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const TOKEN: &str = "k3s-token-for-the-test";

const VERSION: &str = r#"{"major":"1","minor":"30","gitVersion":"v1.30.4+k3s1","gitCommit":"x","gitTreeState":"clean","buildDate":"2026-01-01T00:00:00Z","goVersion":"go1.22","compiler":"gc","platform":"linux/amd64"}"#;
const NAMESPACES: &str = r#"{"kind":"NamespaceList","apiVersion":"v1","metadata":{},"items":[{"metadata":{"name":"default","creationTimestamp":"2026-01-01T00:00:00Z"},"status":{"phase":"Active"}},{"metadata":{"name":"kube-system","creationTimestamp":"2026-01-01T00:00:00Z"},"status":{"phase":"Active"}}]}"#;

/// A client certificate the API server trusts, as k3s gives its admin.
struct ClientCert {
    cert_pem: String,
    key_pem: String,
}

/// An API server on loopback, TLS with a certificate for 127.0.0.1 signed by
/// an authority of the test's own. A request counts as signed in with the
/// token, or with a client certificate from the same authority. Returns its
/// port, the authority's PEM and a client certificate.
async fn api(seen: Arc<Mutex<Vec<String>>>) -> (u16, String, ClientCert) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let issuer = rcgen::Issuer::new(ca_params, ca_key);
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()]).unwrap().signed_by(&key, &issuer).unwrap();
    let client_key = rcgen::KeyPair::generate().unwrap();
    let mut client_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    client_params.distinguished_name.push(rcgen::DnType::CommonName, "system:admin");
    let client = client_params.signed_by(&client_key, &issuer).unwrap();
    let client_cert = ClientCert { cert_pem: client.pem(), key_pem: client_key.serialize_pem() };

    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots)).allow_unauthenticated().build().unwrap();
    let config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else { return };
            let acceptor = acceptor.clone();
            let seen = Arc::clone(&seen);
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else { return };
                let has_cert = tls.get_ref().1.peer_certificates().is_some_and(|c| !c.is_empty());
                let mut buf = Vec::new();
                loop {
                    let mut chunk = [0u8; 4096];
                    let Ok(n) = tls.read(&mut chunk).await else { return };
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    while let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..end]).into_owned();
                        let length: usize = head
                            .lines()
                            .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap_or(0)))
                            .unwrap_or(0);
                        if buf.len() < end + 4 + length {
                            break;
                        }
                        let body = String::from_utf8_lossy(&buf[end + 4..end + 4 + length]).into_owned();
                        buf.drain(..end + 4 + length);
                        let method = head.split_whitespace().next().unwrap_or("").to_string();
                        let path = head.split_whitespace().nth(1).unwrap_or("").to_string();
                        seen.lock().unwrap().push(format!("{method} {path}"));
                        let authorized = has_cert || head.lines().any(|l| l.eq_ignore_ascii_case(&format!("authorization: Bearer {TOKEN}")));
                        let echoed;
                        let (status, body) = if !authorized {
                            ("401 Unauthorized", r#"{"kind":"Status","code":401}"#)
                        } else if path.starts_with("/version") {
                            ("200 OK", VERSION)
                        } else if method == "PATCH" && path.starts_with("/api/v1/namespaces/default/configmaps/app") {
                            // A server-side apply: the object as it would be.
                            echoed = body.clone();
                            ("200 OK", echoed.as_str())
                        } else if method == "DELETE" && path.starts_with("/api/v1/namespaces/default/configmaps/app") {
                            // What a real server answers a delete with at times: a Status, not the object.
                            ("200 OK", r#"{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Success","details":{"name":"app","kind":"configmaps"}}"#)
                        } else if path == "/api/v1/namespaces" || path.starts_with("/api/v1/namespaces?") {
                            ("200 OK", NAMESPACES)
                        } else {
                            ("404 Not Found", r#"{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","reason":"NotFound","code":404,"message":"not here"}"#)
                        };
                        let reply = format!("HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}", body.len());
                        if tls.write_all(reply.as_bytes()).await.is_err() {
                            return;
                        }
                    }
                }
            });
        }
    });
    (port, ca.pem(), client_cert)
}

fn kubeconfig(api_port: u16, ca_pem: &str) -> String {
    kubeconfig_with(api_port, ca_pem, &format!("    token: {TOKEN}\n"))
}

/// As k3s writes its own: a client certificate and its key, no token.
fn kubeconfig_k3s(api_port: u16, ca_pem: &str, client: &ClientCert) -> String {
    let b = |t: &str| base64::engine::general_purpose::STANDARD.encode(t);
    kubeconfig_with(
        api_port,
        ca_pem,
        &format!("    client-certificate-data: {}\n    client-key-data: {}\n", b(&client.cert_pem), b(&client.key_pem)),
    )
}

fn kubeconfig_with(api_port: u16, ca_pem: &str, user: &str) -> String {
    let ca = base64::engine::general_purpose::STANDARD.encode(ca_pem);
    format!(
        "apiVersion: v1\nkind: Config\nclusters:\n- cluster:\n    certificate-authority-data: {ca}\n    server: https://127.0.0.1:{api_port}\n  name: default\ncontexts:\n- context:\n    cluster: default\n    user: default\n  name: default\ncurrent-context: default\nusers:\n- name: default\n  user:\n{user}"
    )
}

struct Tab {
    link: String,
    input: PageLane,
}

impl Tab {
    async fn new(p: &KubePlugin, core: &common::Core) -> Self {
        let page = Page::new();
        let linked = p.call(core, "ui_link", json!({ "public": page.hello })).await.unwrap();
        let (input, _) = page.finish(linked["public"].as_str().unwrap());
        Self { link: linked["link"].as_str().unwrap().to_string(), input }
    }

    async fn ask(&mut self, p: &KubePlugin, core: &common::Core, body: Value) -> Value {
        let answer = self.send(p, core, act(body)).await;
        if answer.get("error").is_some() { answer } else { answer["data"].clone() }
    }

    async fn send(&mut self, p: &KubePlugin, core: &common::Core, request: Value) -> Value {
        let sealed = self.input.seal(request.to_string().as_bytes());
        let answer = p.call(core, "ui", json!({ "link": self.link, "lane": "input", "sealed": sealed })).await.unwrap();
        serde_json::from_slice(&self.input.open(answer["sealed"].as_str().unwrap())).unwrap()
    }
}

/// An engine's operation as the window sends it: an action whose payload is
/// the rest.
fn act(mut body: Value) -> Value {
    let op = body["op"].as_str().unwrap().to_string();
    body.as_object_mut().unwrap().remove("op");
    json!({ "kind": "act", "op": op, "payload": body })
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cluster_behind_sudo_opens_through_the_session_and_lists_its_namespaces() {
    let home = sandbox("open");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let (api_port, ca_pem, _) = api(Arc::clone(&requests)).await;
    let config = kubeconfig(api_port, &ca_pem);

    let ran = Arc::new(Mutex::new(Vec::new()));
    let answers: Answers = Arc::new(move |command: &str| {
        if command.contains("kw_check") {
            (b"kw-kube k3s sudo\nkw-kube-done\n".to_vec(), 0)
        } else if command == "sudo -n cat -- /etc/rancher/k3s/k3s.yaml" {
            (config.clone().into_bytes(), 0)
        } else {
            (format!("unexpected: {command}").into_bytes(), 127)
        }
    });
    let port = serve(user_public(), Arc::clone(&ran), answers).await;
    let core = core(&home, port);
    let p = KubePlugin::new();
    p.attach(core.clone());

    // Found, with the host trusted on the way.
    p.call(core.as_ref(), "scan", Value::Null).await.unwrap();
    let o = settle(&p, &core).await;
    let fingerprint = o["servers"][0]["look"]["fingerprint"].as_str().unwrap().to_string();
    let place = json!({ "entry_id": "key-1", "host": "127.0.0.1", "port": port });
    p.call(core.as_ref(), "scan", json!({ "only": place, "trust": fingerprint })).await.unwrap();
    let o = settle(&p, &core).await;
    assert_eq!(o["servers"][0]["look"]["found"][0]["access"], "sudo", "{o}");

    let cluster = format!("ssh|key-1|127.0.0.1|{port}|k3s");
    let mut tab = Tab::new(&p, &core).await;
    let first = tab.ask(&p, &core, json!({ "op": "open", "cluster": cluster })).await;
    assert_eq!(first["state"], "opening", "{first}");
    let mut state = first;
    for _ in 0..200 {
        state = tab.ask(&p, &core, json!({ "op": "state", "cluster": cluster })).await;
        if state["state"] != "opening" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(state["state"], "open", "{state}");
    assert_eq!(state["summary"]["server"], format!("https://127.0.0.1:{api_port}"));
    assert_eq!(state["summary"]["context"], "default");

    let rows = tab.ask(&p, &core, json!({ "op": "list", "cluster": cluster, "kind": "namespaces" })).await;
    let names: Vec<&str> = rows.as_array().unwrap().iter().map(|r| r["name"].as_str().unwrap()).collect();
    assert_eq!(names, vec!["default", "kube-system"]);
    assert_eq!(rows[0]["info"]["phase"], "Active");

    // The declared screens: the column lists the cluster, its screen is the
    // groups' tabs, and a kind's tab is a table the window filters.
    let catalog = tab.send(&p, &core, json!({ "kind": "view", "route": "" })).await;
    assert_eq!(catalog["body"][0]["type"], "cards", "{catalog}");
    assert_eq!(catalog["body"][0]["cards"][0]["open"]["payload"]["cluster"], cluster, "a card opens its cluster");
    let page = tab.send(&p, &core, json!({ "kind": "view", "route": format!("cluster/{cluster}") })).await;
    assert_eq!(page["body"][0]["type"], "tabs", "{page}");
    assert_eq!(page["switcher"]["current"], cluster, "the head says which cluster");
    assert_eq!(page["switcher"]["all"]["route"], "", "a way back to the catalog");
    let table = tab.ask(&p, &core, json!({ "op": "table", "cluster": cluster, "kind": "namespaces" })).await;
    let table = &table["body"][0];
    assert_eq!(table["type"], "table", "{table}");
    assert_eq!(table["rows"].as_array().unwrap().len(), 2);
    assert_eq!(table["rows"][0]["facets"]["status"], "Active");
    let open = &table["rows"][0]["open"];
    let drawer = tab.send(&p, &core, json!({ "kind": "act", "op": open["op"], "payload": open["payload"] })).await;
    assert_eq!(drawer["data"], Value::Null);
    assert_eq!(drawer["drawer"]["title"]["raw"], "default", "{drawer}");
    let primaries = catalog["actions"].as_array().unwrap().iter().filter(|b| b["primary"] == true).count();
    assert_eq!(primaries, 1, "one main action: adding a cluster");

    // The API was reached through the session, and read with sudo.
    let ran = ran.lock().unwrap().clone();
    assert!(ran.contains(&"sudo -n cat -- /etc/rancher/k3s/k3s.yaml".to_string()), "{ran:?}");
    assert!(ran.contains(&format!("tunnel 127.0.0.1:{api_port}")), "{ran:?}");
    assert!(requests.lock().unwrap().iter().any(|p| p.starts_with("GET /api/v1/namespaces")));

    // A manifest: checked first, applied only after; the check changes
    // nothing on the server.
    let manifest = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: app\n  namespace: default\ndata:\n  mode: fast\n";
    let checked = tab.ask(&p, &core, json!({ "op": "apply", "cluster": cluster, "yaml": manifest, "dry_run": true })).await;
    assert_eq!(checked["dry_run"], true, "{checked}");
    assert_eq!(checked["before"], Value::Null, "a new object");
    assert!(checked["yaml"].as_str().unwrap().contains("mode: fast"), "{checked}");
    let editor = tab.ask(&p, &core, json!({ "op": "editor_check", "cluster": cluster, "text": manifest })).await;
    assert_eq!(editor["before"], Value::Null, "{editor}");
    assert!(editor["after"].as_str().unwrap().contains("mode: fast"));
    let applied = tab.ask(&p, &core, json!({ "op": "apply", "cluster": cluster, "yaml": manifest, "dry_run": false })).await;
    assert_eq!(applied["dry_run"], false, "{applied}");
    let patches: Vec<String> = requests.lock().unwrap().iter().filter(|r| r.starts_with("PATCH")).cloned().collect();
    assert_eq!(patches.len(), 3, "two checks and one apply: {patches:?}");
    assert!(patches[..2].iter().all(|p| p.contains("dryRun=All") && p.contains("fieldManager=keyward")), "{patches:?}");
    assert!(!patches[2].contains("dryRun"), "{}", patches[2]);

    let deleted = tab.ask(&p, &core, json!({ "op": "delete", "cluster": cluster, "kind": "config_maps", "namespace": "default", "name": "app" })).await;
    assert_eq!(deleted["done"], true, "a Status in answer to a delete is a success: {deleted}");

    // A kind keyward does not change is refused before the network.
    let secret = tab.ask(&p, &core, json!({ "op": "apply", "cluster": cluster, "yaml": "apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\n  namespace: default\n", "dry_run": true })).await;
    assert!(secret["error"].as_str().unwrap().starts_with("err.kubeKindNotSupported"), "{secret}");
    // Two logins: the look, and the opening.
    assert_eq!(core.signed.load(std::sync::atomic::Ordering::SeqCst), 2);

    // A secret's manifest is refused before anything is fetched.
    let refused = tab.ask(&p, &core, json!({ "op": "manifest", "cluster": cluster, "kind": "secrets", "namespace": "default", "name": "x" })).await;
    assert!(refused["error"].as_str().unwrap().starts_with("err.kubeSecretNotShown"), "{refused}");

    // Locking takes it all down: the link and the open cluster.
    p.on_event(core.as_ref(), keyward_plugin::HostEvent::Locked).await;
    let sealed = tab.input.seal(br#"{"kind":"view","route":""}"#);
    assert!(p.call(core.as_ref(), "ui", json!({ "link": tab.link, "lane": "input", "sealed": sealed })).await.is_err());
    let mut tab = Tab::new(&p, &core).await;
    let after = tab.ask(&p, &core, json!({ "op": "state", "cluster": cluster })).await;
    assert_eq!(after["state"], "closed");
    let _ = std::fs::remove_dir_all(&home);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_k3s_cluster_signs_in_with_its_client_certificate_through_the_tunnel() {
    let home = sandbox("k3s-cert");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let (api_port, ca_pem, client) = api(Arc::clone(&requests)).await;
    let config = kubeconfig_k3s(api_port, &ca_pem, &client);
    let answers: Answers = Arc::new(move |command: &str| {
        if command.contains("kw_check") {
            (b"kw-kube k3s sudo\nkw-kube-done\n".to_vec(), 0)
        } else if command == "sudo -n cat -- /etc/rancher/k3s/k3s.yaml" {
            (config.clone().into_bytes(), 0)
        } else {
            (format!("unexpected: {command}").into_bytes(), 127)
        }
    });
    let port = serve(user_public(), Arc::new(Mutex::new(Vec::new())), answers).await;
    let core = core(&home, port);
    let p = KubePlugin::new();
    p.attach(core.clone());
    p.call(core.as_ref(), "scan", Value::Null).await.unwrap();
    let o = settle(&p, &core).await;
    let fingerprint = o["servers"][0]["look"]["fingerprint"].as_str().unwrap().to_string();
    let place = json!({ "entry_id": "key-1", "host": "127.0.0.1", "port": port });
    p.call(core.as_ref(), "scan", json!({ "only": place, "trust": fingerprint })).await.unwrap();
    settle(&p, &core).await;

    let cluster = format!("ssh|key-1|127.0.0.1|{port}|k3s");
    let mut tab = Tab::new(&p, &core).await;
    tab.ask(&p, &core, json!({ "op": "open", "cluster": cluster })).await;
    let mut state = Value::Null;
    for _ in 0..200 {
        state = tab.ask(&p, &core, json!({ "op": "state", "cluster": cluster })).await;
        if state["state"] != "opening" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(state["state"], "open", "the client certificate has to reach the API server: {state}");
    let rows = tab.ask(&p, &core, json!({ "op": "list", "cluster": cluster, "kind": "namespaces" })).await;
    assert!(rows.is_array(), "{rows}");
    let _ = std::fs::remove_dir_all(&home);
}
