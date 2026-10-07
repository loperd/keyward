//! The plugin's screens on made-up data, recorded for the stand. The screens
//! are built by the same functions the plugin answers the window with; only
//! the data is invented. `KEYWARD_STAND_OUT=<dir>` writes `<dir>/kube.json`,
//! which the stand serves.

use keyward_ssh_client::targets::{Machine, Missing};
use serde_json::{json, Value};

use crate::detect::{Access, Found, Kind as Distro};
use crate::resources::{Kind, Row};
use crate::ui;
use crate::{Look, NoteRow, Overview, ServerRow};

/// The record is made now, so its "ago" reads as it will on the stand.
fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).expect("the clock is past 1970")
}

fn machine(entry: &str, name: &str, host: &str, port: u16, user: Option<&str>, missing: Vec<Missing>) -> Machine {
    Machine {
        entry_id: entry.into(),
        entry_name: name.into(),
        host: host.into(),
        address: host.into(),
        port,
        user: user.map(Into::into),
        pin: None,
        proxy: None,
        missing,
    }
}

fn overview() -> Overview {
    let server = |m: Machine, look: Option<Look>, aliases: &[&str]| ServerRow { machine: m, look, looking: false, aliases: aliases.iter().map(|a| (*a).to_string()).collect() };
    Overview {
        servers: vec![
            server(
                machine("k1", "Deploy key", "vps.demo.example", 29015, Some("ubuntu"), Vec::new()),
                Some(Look::Seen { found: vec![Found { kind: Distro::K3s, access: Access::Sudo }], at: now() - 600, machine: Some("m1".into()), peer: None }),
                &["vps-internal"],
            ),
            server(
                machine("k2", "Lab", "lab.demo.example", 22, Some("root"), Vec::new()),
                Some(Look::Seen { found: vec![Found { kind: Distro::Kubeadm, access: Access::Readable }], at: now() - 3600, machine: None, peer: None }),
                &[],
            ),
            server(
                machine("k3", "New box", "new.demo.example", 2222, Some("ubuntu"), Vec::new()),
                Some(Look::HostUnknown { fingerprint: "SHA256:k7Qm1vD0demoZ8y2m4Rk1pS9fXcW0uLhTnB3eGdAa5o".into(), algorithm: "ssh-ed25519".into(), at: now() - 60, peer: None }),
                &[],
            ),
            server(
                machine("k4", "Old", "old.demo.example", 22, Some("root"), Vec::new()),
                Some(Look::Failed { error: r#"err.sshUnreachable {"host":"old.demo.example","reason":"connection refused"}"#.into(), at: now() - 7200, peer: None }),
                &[],
            ),
            server(machine("k5", "Worker", "ds.demo.example", 22, Some("ubuntu"), Vec::new()), None, &[]),
            server(machine("k6", "Git", "git.demo.example", 22, Some("git"), Vec::new()), Some(Look::CommandOnly { at: now() - 100, peer: None }), &[]),
            server(machine("k7", "Unset", "bare.demo.example", 0, None, vec![Missing::Login, Missing::Port]), None, &[]),
        ],
        notes: vec![NoteRow { id: "note|n1".into(), entry_id: "n1".into(), name: "EKS staging".into() }],
        local_contexts: vec!["minikube".into(), "docker-desktop".into()],
        local_error: None,
        broken: Vec::new(),
        scanning: false,
    }
}

fn rows(kind: Kind) -> Vec<Row> {
    let at = |ago: i64| Some(now() as i64 - ago);
    let row = |name: &str, ns: Option<&str>, ago: i64, info: Value| Row { name: name.into(), namespace: ns.map(Into::into), created: at(ago), info };
    match kind {
        Kind::Pods => vec![
            row("api-7d9f8c6b5-x2k4l", Some("prod"), 3 * 86400, json!({ "phase": "Running", "ready": 1, "total": 1, "restarts": 0, "node": "vps", "containers": ["api"] })),
            row("api-7d9f8c6b5-q8wz1", Some("prod"), 3 * 86400, json!({ "phase": "Running", "ready": 1, "total": 1, "restarts": 2, "node": "ds", "containers": ["api"] })),
            row("worker-5f6b-ttz9p", Some("prod"), 1800, json!({ "phase": "Pending", "ready": 0, "total": 2, "restarts": 0, "node": "ds", "containers": ["worker", "sidecar"] })),
            row("migrate-28591-abcde", Some("prod"), 40 * 86400, json!({ "phase": "Failed", "ready": 0, "total": 1, "restarts": 5, "node": "vps", "containers": ["migrate"] })),
            row("coredns-ccb96694c-5wq2m", Some("kube-system"), 90 * 86400, json!({ "phase": "Running", "ready": 1, "total": 1, "restarts": 1, "node": "vps", "containers": ["coredns"] })),
            row("traefik-d7c9c5778-hm5vz", Some("kube-system"), 90 * 86400, json!({ "phase": "Running", "ready": 1, "total": 1, "restarts": 0, "node": "vps", "containers": ["traefik"] })),
        ],
        Kind::Deployments => vec![
            row("api", Some("prod"), 30 * 86400, json!({ "ready": 2, "total": 2 })),
            row("worker", Some("prod"), 30 * 86400, json!({ "ready": 0, "total": 1 })),
            row("coredns", Some("kube-system"), 90 * 86400, json!({ "ready": 1, "total": 1 })),
        ],
        Kind::StatefulSets => vec![row("postgres", Some("prod"), 60 * 86400, json!({ "ready": 1, "total": 1 }))],
        Kind::DaemonSets => vec![row("svclb-traefik", Some("kube-system"), 90 * 86400, json!({ "ready": 2, "total": 2 }))],
        Kind::Services => vec![
            row("api", Some("prod"), 30 * 86400, json!({ "type": "ClusterIP", "cluster_ip": "10.43.12.7", "ports": ["80/TCP"] })),
            row("traefik", Some("kube-system"), 90 * 86400, json!({ "type": "LoadBalancer", "cluster_ip": "10.43.0.90", "ports": ["80/TCP", "443/TCP"] })),
        ],
        Kind::Ingresses => vec![row("api", Some("prod"), 30 * 86400, json!({ "hosts": ["api.demo.example"] }))],
        Kind::NetworkPolicies => vec![row("deny-ingress", Some("prod"), 10 * 86400, json!({ "selector": null, "types": ["Ingress"] }))],
        Kind::ConfigMaps => vec![row("api-settings", Some("prod"), 30 * 86400, json!({ "keys": 4 })), row("coredns", Some("kube-system"), 90 * 86400, json!({ "keys": 2 }))],
        Kind::Secrets => vec![row("api-token", Some("prod"), 30 * 86400, Value::Null)],
        Kind::Roles => vec![row("read-only", Some("prod"), 10 * 86400, json!({ "rules": 1 }))],
        Kind::RoleBindings => vec![row("read-only", Some("prod"), 10 * 86400, json!({ "role": "Role/read-only", "subjects": ["User:ci"] }))],
        Kind::ClusterRoles => vec![row("cluster-admin", None, 90 * 86400, json!({ "rules": 2 }))],
        Kind::ClusterRoleBindings => vec![row("cluster-admin", None, 90 * 86400, json!({ "role": "ClusterRole/cluster-admin", "subjects": ["Group:system:masters"] }))],
        Kind::Nodes => vec![row("vps", None, 90 * 86400, json!({ "ready": true, "version": "v1.33.4+k3s1" })), row("ds", None, 80 * 86400, json!({ "ready": false, "version": "v1.33.4+k3s1" }))],
        Kind::Namespaces => vec![row("default", None, 90 * 86400, json!({ "phase": "Active" })), row("kube-system", None, 90 * 86400, json!({ "phase": "Active" })), row("prod", None, 30 * 86400, json!({ "phase": "Active" }))],
        Kind::Events => vec![
            row("worker.1", Some("prod"), 120, json!({ "type": "Warning", "reason": "FailedScheduling", "object": "Pod/worker-5f6b-ttz9p", "message": "0/2 nodes are available: 1 node(s) were not ready." })),
            row("api.2", Some("prod"), 3600, json!({ "type": "Normal", "reason": "Pulled", "object": "Pod/api-7d9f8c6b5-q8wz1", "message": "Container image already present on machine" })),
        ],
    }
}

const MANIFEST: &str = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: api\n  namespace: prod\nspec:\n  replicas: 2\n  selector:\n    matchLabels:\n      app: api\n";

fn reply(r: anyhow::Result<keyward_ui::Reply>) -> Option<Value> {
    serde_json::to_value(r.ok()?).ok()
}

fn act(o: &Overview, op: &str, p: &Value) -> Option<Value> {
    use keyward_ui::Reply;
    let s = |k: &str| p.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let kind = || serde_json::from_value::<Kind>(p["kind"].clone()).ok();
    match op {
        "go" => reply(Ok(Reply::go(s("route")))),
        "open_cluster" => reply(Ok(Reply::go(format!("cluster/{}", s("cluster"))))),
        "close_cluster" => reply(Ok(Reply::go(""))),
        "table" => reply(ui::body(vec![ui::table(&s("cluster"), kind()?, &rows(kind()?))])),
        "object" => {
            let containers: Vec<String> = serde_json::from_value(p.get("containers").cloned().unwrap_or(json!([]))).ok()?;
            reply(Ok(Reply::drawer(ui::object(&s("cluster"), kind()?, p["namespace"].as_str().map(Into::into), &s("name"), &containers, p["tab"].as_str().map(Into::into)))))
        }
        "manifest_node" => reply(ui::body(vec![keyward_ui::Node::Pre { text: MANIFEST.into() }])),
        "logs_node" => reply(ui::body(vec![keyward_ui::Node::Pre { text: "2026-09-30T21:00:01Z listening on :8080\n2026-09-30T21:00:04Z GET /health 200 0.4ms\n".into() }])),
        "edit" => reply(Ok(Reply::dialog(ui::editor(&s("cluster"), p["namespace"].as_str(), MANIFEST, keyward_ui::Text::key_with("kube.editTitle", json!({ "name": s("name") })))))),
        "editor_check" => reply(Ok(Reply { data: json!({ "before": MANIFEST, "after": MANIFEST.replace("replicas: 2", "replicas: 3") }), ..Reply::default() })),
        "add" => reply(Ok(Reply::dialog(ui::add_dialog(o)))),
        "create" => reply(Ok(Reply::dialog(ui::create_dialog(&s("cluster"))))),
        "template" => reply(ui::template_dialog(&s("cluster"), &s("id")).map(Reply::dialog)),
        "scale_dialog" => reply(Ok(Reply::dialog(ui::scale_dialog(p.clone())))),
        _ => None,
    }
}

/// Every page and dialogue keeps to one main action.
fn primaries(v: &Value) -> usize {
    match v {
        Value::Object(o) => usize::from(o.get("primary") == Some(&Value::Bool(true))) + o.iter().filter(|(k, _)| !matches!(k.as_str(), "drawer" | "dialog")).map(|(_, x)| primaries(x)).sum::<usize>(),
        Value::Array(a) => a.iter().map(primaries).sum(),
        _ => 0,
    }
}

/// The words a declared value says: every `{key, args?}`.
fn words(v: &Value, out: &mut std::collections::BTreeSet<String>) {
    match v {
        Value::Object(o) => {
            if let Some(Value::String(k)) = o.get("key") {
                if o.keys().all(|x| x == "key" || x == "args") {
                    out.insert(k.clone());
                }
            }
            o.values().for_each(|x| words(x, out));
        }
        Value::Array(a) => a.iter().for_each(|x| words(x, out)),
        _ => {}
    }
}

#[test]
fn the_screens_on_made_up_data() {
    let o = overview();
    let id = "ssh|k1|vps.demo.example|29015|k3s".to_string();
    let open = json!({ "state": "open", "summary": { "context": "default", "server": "https://127.0.0.1:6443", "namespace": null, "contexts": ["default"] } });
    let record = keyward_ui::stand::crawl(
        |route| match route.strip_prefix("cluster/") {
            None => serde_json::to_value(ui::catalog(&o)).ok(),
            // The note's cluster shows how a failed opening looks.
            Some(c @ "note|n1") => serde_json::to_value(ui::cluster_page(c, ui::label_of(c, Some("EKS staging".into())), &json!({ "state": "failed", "error": "err.kubeUnauthorized" }), ui::switcher(&o, c))).ok(),
            Some(c) => serde_json::to_value(ui::cluster_page(c, ui::label_of(c, None), &open, ui::switcher(&o, c))).ok(),
        },
        |op, p| act(&o, op, p),
    );
    assert!(record.views().any(|(r, _)| r == &format!("cluster/{id}")));
    assert!(record.acts().iter().any(|a| a["op"] == "object"), "a row opens its drawer");
    for (route, page) in record.views() {
        assert!(primaries(page) <= 1, "{route}: more than one main action");
    }
    for a in record.acts() {
        for key in ["drawer", "dialog"] {
            assert!(primaries(&a["reply"][key]) <= 1, "{} {}: more than one main action", a["op"], a["payload"]);
        }
    }
    // Every word on every screen, the ones made up from a value too, is in the
    // dictionaries.
    let mut said = std::collections::BTreeSet::new();
    words(&record.to_json(), &mut said);
    let here = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    for lang in ["en", "ru"] {
        let read = |p: std::path::PathBuf| -> Value { serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap() };
        let (own, core) = (read(here.join(format!("i18n/{lang}.json"))), read(here.join(format!("../../../i18n/{lang}.json"))));
        let missing: Vec<&String> = said.iter().filter(|k| own.get(k.as_str()).is_none() && core.get(k.as_str()).is_none()).collect();
        assert!(missing.is_empty(), "{lang}.json lacks {missing:?}");
    }
    if let Some(dir) = std::env::var_os("KEYWARD_STAND_OUT") {
        let path = std::path::Path::new(&dir).join("kube.json");
        let mut out = record.to_json();
        out["places"] = serde_json::to_value(crate::places::declare(&o)).unwrap();
        out["manifest"] = serde_json::to_value(keyward_plugin::Plugin::manifest(&crate::KubePlugin::new())).unwrap();
        std::fs::write(&path, serde_json::to_vec_pretty(&out).unwrap()).unwrap();
    }
}
