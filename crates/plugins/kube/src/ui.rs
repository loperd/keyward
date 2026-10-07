//! The plugin's screens, declared: what each shows and what each action does.
//! The window draws them with its own kit and keeps what it can — the
//! filters, the sort, the tab on view, a form's fields; it comes here only
//! for the data and for what an action does.

use keyward_plugin::Host;
use keyward_ui::{
    Action, Button, Cell, Chip, Column, Facet, Field, FieldKind, ListRow, Node, Page, Reply, SwitchItem, Switcher, Tab, TableRow, Text, Tone,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::detect::{Access, Kind as Distro};
use crate::resources::{Kind, Row};
use crate::{KubePlugin, Look, Overview, ServerRow};
use keyward_ssh_client::targets::Missing;

fn k(key: &str) -> Text {
    Text::key(key)
}

fn kind_word(kind: Kind) -> Text {
    let id = serde_json::to_value(kind).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default();
    let camel: String = id
        .split('_')
        .enumerate()
        .map(|(i, p)| if i == 0 { p.to_string() } else { p[..1].to_uppercase() + &p[1..] })
        .collect();
    k(&format!("kube.res.{camel}"))
}

fn kind_id(kind: Kind) -> String {
    serde_json::to_value(kind).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default()
}

fn kind_icon(kind: Kind) -> &'static str {
    match kind {
        Kind::Pods => "pod",
        Kind::Deployments => "layers",
        Kind::StatefulSets => "database",
        Kind::DaemonSets => "grid",
        Kind::Services => "plug",
        Kind::Ingresses => "globe",
        Kind::NetworkPolicies => "shield",
        Kind::ConfigMaps => "sliders",
        Kind::Secrets => "lock",
        Kind::Roles | Kind::ClusterRoles => "identity",
        Kind::RoleBindings | Kind::ClusterRoleBindings => "link",
        Kind::Nodes => "server",
        Kind::Namespaces => "folder",
        Kind::Events => "bolt",
    }
}

/// How often a kind's table is asked again while it is shown: a list call a
/// cluster answers in milliseconds, often enough to see a pod come up.
const TABLE_REFRESH_MS: u64 = 5000;

/// How often a pod's log is read again while it is shown.
const LOGS_REFRESH_MS: u64 = 3000;

const GROUPS: &[(&str, &str, &[Kind])] = &[
    ("workloads", "layers", &[Kind::Pods, Kind::Deployments, Kind::StatefulSets, Kind::DaemonSets]),
    ("network", "globe", &[Kind::Services, Kind::Ingresses, Kind::NetworkPolicies]),
    ("config", "sliders", &[Kind::ConfigMaps, Kind::Secrets]),
    ("access", "shield", &[Kind::Roles, Kind::RoleBindings, Kind::ClusterRoles, Kind::ClusterRoleBindings]),
    ("cluster", "cluster", &[Kind::Nodes, Kind::Namespaces, Kind::Events]),
];

pub(crate) fn distro_word(d: Distro) -> Text {
    let id = serde_json::to_value(d).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default();
    k(&format!("kube.kind.{id}"))
}

pub(crate) fn cluster_id(s: &ServerRow, d: Distro) -> String {
    let kind = serde_json::to_value(d).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default();
    format!("ssh|{}|{}|{}|{kind}", s.machine.entry_id, s.machine.host, s.machine.port)
}

pub(crate) fn place_json(s: &ServerRow) -> Value {
    json!({ "entry_id": s.machine.entry_id, "host": s.machine.host, "port": s.machine.port })
}

/// What group a server falls in, as the person sorts them by what can be
/// done: a cluster of ours, attention, broken, not looked at, no cluster, not
/// set up.
pub(crate) fn group_of(s: &ServerRow) -> &'static str {
    if !s.machine.missing.is_empty() || s.machine.proxy.is_some() {
        return "unset";
    }
    match &s.look {
        None => "unchecked",
        Some(Look::Seen { found, .. }) if !found.is_empty() => "ready",
        Some(Look::Seen { .. }) | Some(Look::CommandOnly { .. }) => "none",
        Some(Look::HostUnknown { .. }) => "attention",
        Some(Look::Failed { .. }) => "broken",
    }
}

fn server_row(s: &ServerRow, busy: bool) -> ListRow {
    let group = group_of(s);
    let tone = if s.looking {
        Tone::Plain
    } else {
        match group {
            "ready" => Tone::Ok,
            "attention" => Tone::Warn,
            "broken" => Tone::Bad,
            _ => Tone::Plain,
        }
    };
    let port = if s.machine.port != 0 && s.machine.port != 22 { format!(":{}", s.machine.port) } else { String::new() };
    let name = format!("{}{}{port}", s.machine.user.as_deref().map(|u| format!("{u}@")).unwrap_or_default(), s.machine.host);
    let mut subtitle = s.machine.entry_name.clone();
    if !s.aliases.is_empty() {
        subtitle = format!("{subtitle} · {}", s.aliases.join(", "));
    }
    let mut row = ListRow::new(format!("{}|{}|{}", s.machine.entry_id, s.machine.host, s.machine.port), "server", Text::raw(name));
    row.tone = tone;
    row.busy = s.looking;
    row.mono = true;
    row.subtitle = Some(Text::raw(subtitle));
    let unset = !s.machine.missing.is_empty();
    if unset {
        row.note = Some(k(match s.machine.missing.as_slice() {
            [Missing::Login] => "kube.missing.login",
            [Missing::Port] => "kube.missing.port",
            _ => "kube.missing.both",
        }));
        row.tone = Tone::Warn;
        return row;
    }
    if s.machine.proxy.is_some() {
        row.note = Some(k("kube.status.proxied"));
        return row;
    }
    if s.looking {
        row.note = Some(k("kube.status.looking"));
    }
    match &s.look {
        None if !s.looking => row.note = Some(k("kube.status.notChecked")),
        Some(Look::Seen { found, at, .. }) => {
            row.at = Some(*at);
            if found.is_empty() {
                row.note = Some(k("kube.status.none"));
            }
            for f in found {
                let mut chip = Chip::state(distro_word(f.kind), Tone::Ok).title(k(&format!("kube.access.{}", access_id(f.access))));
                if f.access == Access::Sudo {
                    chip = chip.icon("bolt");
                }
                row.chips.push(chip);
                row.actions.push(
                    Button::labelled(k("kube.open"), Action::with("open_cluster", json!({ "cluster": cluster_id(s, f.kind) })))
                        .with_icon("chevron")
                        .disabled(f.access == Access::Denied),
                );
            }
        }
        Some(Look::CommandOnly { at, .. }) => {
            row.at = Some(*at);
            row.note = Some(k("kube.status.commandOnly"));
        }
        Some(Look::HostUnknown { fingerprint, at, .. }) => {
            row.at = Some(*at);
            row.note = Some(k("kube.status.hostUnknown"));
            row.code = Some(fingerprint.clone());
            row.actions.push(
                Button::icon("shield-check", Text::key_with("kube.trustExplain", json!({ "host": s.machine.host })), Action::with("trust", json!({ "place": place_json(s), "fingerprint": fingerprint })))
                    .disabled(busy),
            );
        }
        Some(Look::Failed { error, at, .. }) => {
            row.at = Some(*at);
            row.note = Some(error_text(error));
        }
        _ => {}
    }
    row.actions.insert(0, Button::icon("sync", k("kube.look"), Action::with("look", json!({ "place": place_json(s) }))).disabled(busy));
    row
}

fn access_id(a: Access) -> &'static str {
    match a {
        Access::Readable => "readable",
        Access::Sudo => "sudo",
        Access::Denied => "denied",
    }
}

/// An error as it travels (`err.key {"args"}`), as a declared text. A code
/// the plugin's dictionary does not know (the daemon's, a library's) is said
/// as it came: a screen never names a word the window has no text for.
pub(crate) fn error_text(e: &str) -> Text {
    static KEYS: std::sync::OnceLock<std::collections::BTreeSet<String>> = std::sync::OnceLock::new();
    let keys = KEYS.get_or_init(|| {
        let words: std::collections::BTreeMap<String, Value> = serde_json::from_str(include_str!("../i18n/en.json")).expect("the plugin's dictionary is JSON");
        words.into_keys().collect()
    });
    match e.split_once(' ') {
        Some((key, args)) if key.starts_with("err.") && keys.contains(key) => match serde_json::from_str::<Value>(args) {
            Ok(args) => Text::key_with(key, args),
            Err(_) => Text::raw(e),
        },
        None if e.starts_with("err.") && keys.contains(e) => k(e),
        _ => Text::raw(e),
    }
}

// -- The screens --------------------------------------------------------------

/// The servers' screen, from what was gathered.
/// One cluster the section can open: a note's kubeconfig or a master an ssh
/// login reached.
pub(crate) struct Cluster {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) kind: Text,
    pub(crate) icon: &'static str,
    pub(crate) tone: Tone,
    /// Where it lives, for the card: the login, the vault item.
    pub(crate) place: String,
    pub(crate) at: Option<u64>,
}

pub(crate) fn clusters(o: &Overview) -> Vec<Cluster> {
    let mut out: Vec<Cluster> = o
        .notes
        .iter()
        .map(|n| Cluster { id: n.id.clone(), name: n.name.clone(), kind: k("kube.kind.kubeconfig"), icon: "lock", tone: Tone::Ok, place: String::new(), at: None })
        .collect();
    for s in &o.servers {
        if let Some(Look::Seen { found, at, .. }) = &s.look {
            for f in found {
                let tone = match f.access {
                    Access::Readable => Tone::Ok,
                    Access::Sudo => Tone::Warn,
                    Access::Denied => Tone::Bad,
                };
                let login = s.machine.user.as_deref().map(|u| format!("{u}@")).unwrap_or_default();
                out.push(Cluster { id: cluster_id(s, f.kind), name: s.machine.host.clone(), kind: distro_word(f.kind), icon: "terminal", tone, place: format!("{login}{} · {}", s.machine.host, s.machine.entry_name), at: Some(*at) });
            }
        }
    }
    out
}

/// The section's first screen: the catalog of clusters as cards, and below
/// it the servers that have something to say — one to trust, one that fails,
/// one not looked at.
pub(crate) fn catalog(o: &Overview) -> Page {
        let mut body = Vec::new();
        for b in &o.broken {
            body.push(Node::Alert { text: error_text(b), tone: Tone::Warn });
        }
        let cards: Vec<ListRow> = clusters(o)
            .into_iter()
            .map(|c| {
                let mut card = ListRow::new(c.id.clone(), c.icon, Text::raw(&c.name));
                card.mono = true;
                card.tone = c.tone;
                card.chips.push(Chip::new(c.kind).icon("cluster"));
                if !c.place.is_empty() {
                    card.subtitle = Some(Text::raw(c.place));
                }
                card.at = c.at;
                card.open = Some(Action::with("open_cluster", json!({ "cluster": c.id })));
                card
            })
            .collect();
        if cards.is_empty() {
            body.push(Node::Empty { icon: "cluster".into(), title: k("kube.noClustersYet"), body: Some(k("kube.noServers.body")) });
        } else {
            body.push(Node::Cards { cards });
        }
        for (group, icon, tone, folded) in [
            ("attention", "shield", Tone::Warn, false),
            ("broken", "warn", Tone::Bad, false),
            ("unchecked", "clock", Tone::Plain, false),
            ("none", "server", Tone::Plain, true),
            ("unset", "edit", Tone::Plain, true),
        ] {
            let rows: Vec<ListRow> = o.servers.iter().filter(|s| group_of(s) == group).map(|s| server_row(s, o.scanning)).collect();
            if rows.is_empty() {
                continue;
            }
            body.push(Node::Section {
                title: k(&format!("kube.group.{group}")),
                icon: icon.into(),
                tone,
                count: Some(rows.len()),
                folded,
                hint: (group == "unset").then(|| k("kube.unsetHint")),
                body: vec![Node::List { rows }],
            });
        }
        let settable = o.servers.iter().any(|s| group_of(s) != "unset");
        Page {
            title: Some(k("kube.clusters")),
            icon: Some("cluster".into()),
            actions: vec![
                Button::icon("sync", if o.scanning { k("kube.scanning") } else { k("kube.scan") }, Action::op("scan")).busy(o.scanning).disabled(!settable),
                Button::labelled(k("kube.add"), Action::op("add")).with_icon("plus").primary(),
            ],
            body,
            refresh_ms: Some(if o.scanning { 1200 } else { 10_000 }),
            ..Page::default()
        }
}

/// The switcher in a cluster's head: the others, adding one, the catalog.
pub(crate) fn switcher(o: &Overview, current: &str) -> Switcher {
    Switcher {
        current: current.to_string(),
        items: clusters(o)
            .into_iter()
            .map(|c| SwitchItem { route: format!("cluster/{}", c.id), key: c.id, label: Text::raw(c.name), hint: Some(c.kind), icon: Some(c.icon.into()), dot: Some(c.tone) })
            .collect(),
        add: Some(Button::labelled(k("kube.add"), Action::op("add")).with_icon("plus")),
        all: Some(SwitchItem { key: String::new(), label: k("kube.allClusters"), hint: None, icon: Some("grid".into()), dot: None, route: String::new() }),
    }
}

/// A cluster's screen in the state it is in: opening, failed or open.
pub(crate) fn cluster_page(id: &str, label: Label, state: &Value, switcher: Switcher) -> Page {
        // The head is the switcher: the cluster on screen, the others, the catalog.
        let switcher = Some(switcher);
        match state.get("state").and_then(Value::as_str).unwrap_or("closed") {
            "closed" | "opening" => Page {
                title: Some(Text::raw(label.0.clone())),
                icon: Some(label.1.into()),
                switcher: switcher.clone(),
                body: vec![Node::Busy { text: if id.starts_with("ssh|") { k("kube.openingSsh") } else { Text::key_with("kube.opening", json!({ "name": label.0 })) } }],
                refresh_ms: Some(800),
                ..Page::default()
            },
            "failed" => Page {
                title: Some(Text::raw(label.0.clone())),
                icon: Some(label.1.into()),
                switcher: switcher.clone(),
                body: vec![
                    Node::Alert { text: error_text(state.get("error").and_then(Value::as_str).unwrap_or("")), tone: Tone::Bad },
                    Node::Actions { buttons: vec![Button::labelled(k("kube.again"), Action::with("reopen", json!({ "cluster": id }))).with_icon("sync")] },
                ],
                ..Page::default()
            },
            _ => {
                let summary = &state["summary"];
                let tabs = GROUPS
                    .iter()
                    .map(|(g, icon, kinds)| Tab {
                        id: (*g).to_string(),
                        title: k(&format!("kube.group.{g}")),
                        icon: Some((*icon).to_string()),
                        load: None,
                        refresh_ms: None,
                        body: vec![Node::Tabs {
                            id: format!("{id}|{g}"),
                            on: None,
                            icons_only: false,
                            tabs: kinds
                                .iter()
                                .map(|kind| Tab {
                                    id: kind_id(*kind),
                                    title: kind_word(*kind),
                                    icon: Some(kind_icon(*kind).to_string()),
                                    load: Some(Action::with("table", json!({ "cluster": id, "kind": kind }))),
                                    // The cluster changes under the person's eyes: pods come and go.
                                    refresh_ms: Some(TABLE_REFRESH_MS),
                                    body: Vec::new(),
                                })
                                .collect(),
                        }],
                    })
                    .collect();
                Page {
                    title: Some(Text::raw(label.0)),
                    icon: Some(label.1.into()),
                    subtitle: Some(Text::raw(format!(
                        "{} · {}",
                        summary.get("server").and_then(Value::as_str).unwrap_or(""),
                        summary.get("context").and_then(Value::as_str).unwrap_or("")
                    ))),
                    switcher,
                    // Asked again now and then: the switcher's dots follow the
                    // other clusters; the tabs keep their own pace.
                    refresh_ms: Some(10_000),
                    actions: vec![
                        Button::icon("plus", k("kube.create"), Action::with("create", json!({ "cluster": id }))),
                        Button::icon("sync", k("kube.refresh"), Action::op("refresh")),
                        Button::icon("close", k("kube.disconnect"), Action::with("close_cluster", json!({ "cluster": id }))),
                    ],
                    body: vec![Node::Tabs { id: format!("{id}|groups"), icons_only: true, on: None, tabs }],
                    ..Page::default()
                }
            }
        }
}

/// A cluster's name, icon and source for its head.
pub(crate) type Label = (String, &'static str, Option<Chip>);

/// `note_name` is the note's name, for a cluster kept in a note.
pub(crate) fn label_of(id: &str, note_name: Option<String>) -> Label {
        let parts: Vec<&str> = id.split('|').collect();
        match parts.as_slice() {
            ["ssh", _, h, _, kind] => {
                let d: Option<Distro> = serde_json::from_value(Value::String((*kind).to_string())).ok();
                ((*h).to_string(), "terminal", d.map(|d| Chip::new(distro_word(d)).icon("cluster")))
            }
            ["note", entry] => (note_name.unwrap_or_else(|| (*entry).to_string()), "lock", Some(Chip::new(k("kube.source.note")).icon("lock"))),
            _ => (id.to_string(), "cluster", None),
        }
}

/// A kind's table: every namespace at once; the window filters.
pub(crate) fn table(cluster: &str, kind: Kind, rows: &[Row]) -> Node {
        let namespaced = rows.iter().any(|r| r.namespace.is_some());
        let mut columns = vec![Column { id: "name".into(), title: k("kube.col.name"), sortable: true, mono: true }];
        if namespaced {
            columns.push(Column { id: "ns".into(), title: k("kube.col.namespace"), sortable: true, mono: false });
        }
        for (id, key) in extra_columns(kind) {
            columns.push(Column { id: (*id).into(), title: k(key), sortable: true, mono: false });
        }
        columns.push(Column { id: "age".into(), title: k("kube.col.age"), sortable: true, mono: false });

        let mut facets = Vec::new();
        if namespaced {
            facets.push(Facet { id: "ns".into(), title: k("kube.facet.ns"), icon: "folder".into() });
        }
        if kind == Kind::Pods {
            facets.push(Facet { id: "node".into(), title: k("kube.facet.node"), icon: "server".into() });
        }
        if matches!(kind, Kind::Pods | Kind::Nodes | Kind::Events | Kind::Services | Kind::Namespaces) {
            facets.push(Facet { id: "status".into(), title: k("kube.facet.status"), icon: "check".into() });
        }
        if matches!(kind, Kind::Pods | Kind::Deployments | Kind::StatefulSets | Kind::DaemonSets) {
            facets.push(Facet { id: "ready".into(), title: k("kube.facet.ready"), icon: "layers".into() });
        }
        facets.push(Facet { id: "age".into(), title: k("kube.facet.age"), icon: "clock".into() });

        // A row says only what its table has a column for: a status is a
        // facet of every kind that has one, a cell of those that show it.
        let shown: std::collections::BTreeSet<String> = columns.iter().map(|c| c.id.clone()).collect();
        let table_rows = rows
            .iter()
            .map(|r| {
                let mut row = table_row(cluster, kind, r);
                row.cells.retain(|id, _| shown.contains(id));
                row.sort.retain(|id, _| shown.contains(id));
                row
            })
            .collect();
        Node::Table { id: format!("{cluster}|{}", kind_id(kind)), columns, facets, rows: table_rows, empty: Some(k("kube.emptyTable")) }
}

/// An object's drawer.
/// Whether a person must type the name to delete one: what takes much with it
/// or is not brought back. A pod, a config map, a policy go with a second
/// press — a controller brings a pod back, and a manifest is applied again.
fn weighty(kind: Kind) -> bool {
    matches!(kind, Kind::Namespaces | Kind::Deployments | Kind::StatefulSets | Kind::DaemonSets | Kind::ClusterRoles | Kind::ClusterRoleBindings | Kind::Nodes)
}

/// Delete with a second press, for a row or a drawer's head.
fn delete_button(at: &Value) -> Button {
    Button::icon("trash", k("kube.deleteNow"), Action::with("delete_object", at.clone()).pressed_twice()).tone(Tone::Bad)
}

/// An object's drawer; `tab` is the one shown first (a row's logs or shell).
pub(crate) fn object(cluster: &str, kind: Kind, namespace: Option<String>, name: &str, containers: &[String], tab: Option<String>) -> Page {
        let at = json!({ "cluster": cluster, "kind": kind, "namespace": namespace, "name": name });
        let mut tabs = Vec::new();
        if kind == Kind::Pods {
            tabs.push(Tab { id: "logs".into(), title: k("kube.logs"), icon: Some("logs".into()), load: Some(Action::with("logs_node", json!({ "cluster": cluster, "namespace": namespace, "pod": name, "container": containers.first() }))), refresh_ms: Some(LOGS_REFRESH_MS), body: Vec::new() });
            tabs.push(Tab {
                id: "shell".into(),
                title: k("kube.shell"),
                icon: Some("terminal".into()),
                load: None,
                refresh_ms: None,
                body: vec![Node::Terminal {
                    open: Action::with("shell_open", json!({ "cluster": cluster, "namespace": namespace, "pod": name, "container": containers.first() })),
                    read: "shell_read".into(),
                    write: "shell_write".into(),
                    resize: "shell_resize".into(),
                    close: "shell_close".into(),
                }],
            });
        }
        if kind != Kind::Secrets {
            tabs.push(Tab { id: "manifest".into(), title: k("kube.manifest"), icon: Some("code".into()), load: Some(Action::with("manifest_node", at.clone())), refresh_ms: None, body: Vec::new() });
        }
        let mut body = if tabs.is_empty() {
            vec![Node::Empty { icon: "lock".into(), title: k("kube.secretHidden"), body: None }]
        } else {
            vec![Node::Tabs { id: format!("{cluster}|object|{}", kind_id(kind)), icons_only: true, on: tab, tabs }]
        };
        if weighty(kind) && kind != Kind::Nodes {
            body.push(Node::Danger {
                title: Text::key_with("kube.deleteTitle", json!({ "name": name })),
                hint: k("kube.deleteHint"),
                button: Button::labelled(k("kube.delete"), Action::with("delete_object", at.clone()).confirmed_by(name)).with_icon("trash").tone(Tone::Bad),
            });
        }
        let mut actions = Vec::new();
        if matches!(kind, Kind::Deployments | Kind::StatefulSets) {
            actions.push(Button::icon("layers", k("kube.scale"), Action::with("scale_dialog", at.clone())));
        }
        if matches!(kind, Kind::Deployments | Kind::StatefulSets | Kind::DaemonSets) {
            actions.push(Button::icon("undo", k("kube.restart"), Action::with("restart_object", at.clone()).pressed_twice()));
        }
        if !matches!(kind, Kind::Secrets | Kind::Events) {
            actions.push(Button::icon("edit", k("kube.edit"), Action::with("edit", at.clone())));
        }
        if !weighty(kind) && kind != Kind::Events {
            actions.push(delete_button(&at));
        }
        Page {
            title: Some(Text::raw(name)),
            icon: Some(kind_icon(kind).into()),
            subtitle: namespace.map(Text::raw),
            actions,
            body,
            ..Page::default()
        }
}

fn extra_columns(kind: Kind) -> &'static [(&'static str, &'static str)] {
    match kind {
        Kind::Pods => &[("ready", "kube.col.ready"), ("status", "kube.col.status"), ("restarts", "kube.col.restarts"), ("node", "kube.col.node")],
        Kind::Deployments | Kind::StatefulSets | Kind::DaemonSets => &[("ready", "kube.col.ready")],
        Kind::Services => &[("type", "kube.col.type"), ("ip", "kube.col.clusterIp"), ("ports", "kube.col.ports")],
        Kind::Ingresses => &[("hosts", "kube.col.hosts")],
        Kind::Nodes => &[("status", "kube.col.status"), ("version", "kube.col.version")],
        Kind::Namespaces => &[("status", "kube.col.status")],
        Kind::ConfigMaps => &[("keys", "kube.col.keys")],
        Kind::Events => &[("type", "kube.col.type"), ("reason", "kube.col.reason"), ("object", "kube.col.object"), ("message", "kube.col.message")],
        Kind::Roles | Kind::ClusterRoles => &[("rules", "kube.col.rules")],
        Kind::RoleBindings | Kind::ClusterRoleBindings => &[("role", "kube.col.role"), ("subjects", "kube.col.subjects")],
        Kind::NetworkPolicies => &[("selector", "kube.col.selector"), ("types", "kube.col.policyTypes")],
        Kind::Secrets => &[],
    }
}

fn s_of(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        Value::Array(a) => a.iter().map(s_of).collect::<Vec<_>>().join(", "),
        Value::Object(o) => o.iter().map(|(k, v)| format!("{k}={}", s_of(v))).collect::<Vec<_>>().join(", "),
        other => other.to_string(),
    }
}

fn phase_tone(p: &str) -> Tone {
    match p {
        "Running" | "Succeeded" | "Active" | "Ready" | "Normal" => Tone::Ok,
        "Pending" | "Warning" => Tone::Warn,
        "" => Tone::Plain,
        _ => Tone::Bad,
    }
}

fn table_row(cluster: &str, kind: Kind, r: &Row) -> TableRow {
    let i = r.info.clone();
    let get = |key: &str| i.get(key).cloned().unwrap_or(Value::Null);
    let mut row = TableRow::new(format!("{}/{}", r.namespace.clone().unwrap_or_default(), r.name))
        .cell("name", Cell::Text { text: Text::raw(&r.name) })
        .facet("ns", r.namespace.as_deref());
    if let Some(ns) = &r.namespace {
        row = row.cell("ns", Cell::Text { text: Text::raw(ns) });
    }
    match r.created {
        Some(at) => {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
            let age = now - at;
            let bucket = if age < 3600 { "<1h" } else if age < 86400 { "<1d" } else if age < 7 * 86400 { "<7d" } else { "older" };
            row = row.cell("age", Cell::Ago { at: at as u64 }).sort("age", -at).facet("age", Some(bucket));
        }
        None => row = row.cell("age", Cell::Empty),
    }
    if let (Some(ready), Some(total)) = (get("ready").as_i64(), get("total").as_i64()) {
        let tone = if total > 0 && ready >= total { Tone::Ok } else if ready > 0 { Tone::Warn } else { Tone::Bad };
        row = row
            .cell("ready", Cell::Chip { chip: Chip::state(Text::raw(format!("{ready}/{total}")), tone) })
            .sort("ready", if total > 0 { ready as f64 / total as f64 } else { -1.0 })
            .facet("ready", Some(if total > 0 && ready >= total { "yes" } else { "no" }));
    }
    let status = match kind {
        Kind::Pods | Kind::Namespaces => s_of(&get("phase")),
        Kind::Nodes => if get("ready") == Value::Bool(true) { "Ready".into() } else { "NotReady".into() },
        Kind::Events | Kind::Services => s_of(&get("type")),
        _ => String::new(),
    };
    if !status.is_empty() {
        row = row.facet("status", Some(&status)).cell("status", Cell::Chip { chip: Chip::state(Text::raw(&status), phase_tone(&status)) });
    }
    for (id, key) in [("restarts", "restarts"), ("node", "node"), ("version", "version"), ("keys", "keys"), ("reason", "reason"), ("object", "object"), ("message", "message"), ("rules", "rules"), ("role", "role"), ("subjects", "subjects"), ("selector", "selector"), ("types", "types"), ("hosts", "hosts"), ("ports", "ports")] {
        let v = get(key);
        if !v.is_null() {
            row = row.cell(id, Cell::Text { text: Text::raw(s_of(&v)) });
        }
    }
    if kind == Kind::Services {
        row = row.cell("type", Cell::Text { text: Text::raw(s_of(&get("type"))) }).cell("ip", Cell::Text { text: Text::raw(s_of(&get("cluster_ip"))) });
    }
    if kind == Kind::Events {
        row = row.cell("type", Cell::Chip { chip: Chip::state(Text::raw(s_of(&get("type"))), phase_tone(&s_of(&get("type")))) });
    }
    if let Some(n) = get("restarts").as_i64() {
        row = row.sort("restarts", n);
    }
    if kind == Kind::Pods {
        row = row.facet("node", get("node").as_str());
    }
    let mut open = json!({ "cluster": cluster, "kind": kind, "namespace": r.namespace, "name": r.name });
    // A pod's containers: its logs and its shell are of one of them.
    if let containers @ Value::Array(_) = get("containers") {
        open["containers"] = containers;
    }
    let at = json!({ "cluster": cluster, "kind": kind, "namespace": r.namespace, "name": r.name });
    // What a person does to a row most, without opening it.
    let with_tab = |tab: &str| {
        let mut o = open.clone();
        o["tab"] = json!(tab);
        Action::with("object", o)
    };
    if kind == Kind::Pods {
        row = row.action(Button::icon("logs", k("kube.logs"), with_tab("logs"))).action(Button::icon("terminal", k("kube.shell"), with_tab("shell")));
    }
    if matches!(kind, Kind::Deployments | Kind::StatefulSets | Kind::DaemonSets) {
        row = row.action(Button::icon("undo", k("kube.restart"), Action::with("restart_object", at.clone()).pressed_twice()));
    }
    if !weighty(kind) && !matches!(kind, Kind::Events) {
        row = row.action(delete_button(&at));
    }
    row.open(Action::with("object", open))
}

// -- Declared -----------------------------------------------------------------

#[derive(Deserialize)]
struct At {
    cluster: String,
    kind: Kind,
    #[serde(default)]
    namespace: Option<String>,
    name: String,
    #[serde(default)]
    containers: Vec<String>,
    #[serde(default)]
    tab: Option<String>,
}

#[derive(Deserialize)]
struct ClusterArg {
    cluster: String,
}

fn arg<T: serde::de::DeserializeOwned>(v: Value) -> anyhow::Result<T> {
    serde_json::from_value(v).map_err(|e| anyhow::anyhow!("an action came with something else: {e}"))
}



/// Where a cluster comes from: a kubeconfig of this computer's, or pasted.
pub(crate) fn add_dialog(o: &Overview) -> Page {
                let mut body = Vec::new();
                if !o.local_contexts.is_empty() {
                    body.push(Node::Section {
                        title: k("kube.import"),
                        icon: "desktop".into(),
                        tone: Tone::Plain,
                        count: None,
                        folded: false,
                        hint: None,
                        body: vec![Node::Form {
                            fields: vec![
                                Field { id: "context".into(), label: k("kube.importContext"), kind: FieldKind::Select { options: o.local_contexts.iter().map(|c| (c.clone(), Text::raw(c))).collect() }, hint: None, value: None },
                                Field { id: "name".into(), label: k("kube.addName"), kind: FieldKind::Text, hint: None, value: None },
                            ],
                            submit: Button::labelled(k("kube.addSave"), Action::op("import")).with_icon("lock").primary(),
                        }],
                    });
                }
                body.push(Node::Section {
                    title: k("kube.addYaml"),
                    icon: "code".into(),
                    tone: Tone::Plain,
                    count: None,
                    folded: !o.local_contexts.is_empty(),
                    hint: None,
                    body: vec![Node::Form {
                        fields: vec![
                            Field { id: "name".into(), label: k("kube.addName"), kind: FieldKind::Text, hint: None, value: None },
                            Field { id: "yaml".into(), label: k("kube.addYaml"), kind: FieldKind::Area, hint: Some(k("kube.addYamlHint")), value: None },
                        ],
                        // The screen's one main action: the import when there is one.
                        submit: if o.local_contexts.is_empty() {
                            Button::labelled(k("kube.addSave"), Action::op("add_yaml")).with_icon("lock").primary()
                        } else {
                            Button::labelled(k("kube.addSave"), Action::op("add_yaml")).with_icon("lock")
                        },
                    }],
                });
                Page { title: Some(k("kube.addTitle")), body, ..Page::default() }
}

#[async_trait::async_trait]
impl keyward_ui::Ui for KubePlugin {
    async fn places(&self, host: &dyn Host) -> anyhow::Result<keyward_ui::places::Places> {
        Ok(crate::places::declare(&self.gather(host)?))
    }

    async fn view(&self, host: &dyn Host, route: &str) -> anyhow::Result<Page> {
        match route.strip_prefix("cluster/") {
            Some(id) => {
                let state = self.run(host, crate::Op::State { cluster: id.to_string() }).await?;
                // A cluster is opened when its screen is first asked for; while it
                // opens the screen waits and asks again.
                let state = if state.get("state").and_then(Value::as_str) == Some("closed") { self.run(host, crate::Op::Open { cluster: id.to_string() }).await? } else { state };
                let note = id.strip_prefix("note|").and_then(|entry| host.tagged_items(crate::KUBECONFIG_FIELD).into_iter().find(|i| i.id == entry)).map(|i| i.name);
                Ok(cluster_page(id, label_of(id, note), &state, switcher(&self.gather(host)?, id)))
            }
            None => Ok(catalog(&self.gather(host)?)),
        }
    }

    async fn act(&self, host: &dyn Host, op: &str, payload: Value, form: Value) -> anyhow::Result<Reply> {
        let form_str = |key: &str| form.get(key).and_then(Value::as_str).unwrap_or("").to_string();
        match op {
            "go" => Ok(Reply::go(payload.get("route").and_then(Value::as_str).unwrap_or(""))),
            "refresh" => Ok(Reply::refresh()),
            "scan" => {
                self.scan(host, Value::Null)?;
                Ok(Reply::refresh())
            }
            "look" => {
                self.scan(host, json!({ "only": payload["place"] }))?;
                Ok(Reply::refresh())
            }
            "trust" => {
                self.scan(host, json!({ "only": payload["place"], "trust": payload["fingerprint"] }))?;
                Ok(Reply::refresh())
            }
            "open_cluster" => Ok(Reply::go(format!("cluster/{}", arg::<ClusterArg>(payload)?.cluster))),
            "reopen" => {
                let c = arg::<ClusterArg>(payload)?.cluster;
                self.run(host, crate::Op::Close { cluster: c }).await?;
                Ok(Reply::refresh())
            }
            "close_cluster" => {
                let c = arg::<ClusterArg>(payload)?.cluster;
                self.run(host, crate::Op::Close { cluster: c }).await?;
                Ok(Reply::go(""))
            }
            "table" => {
                #[derive(Deserialize)]
                struct A {
                    cluster: String,
                    kind: Kind,
                }
                let a: A = arg(payload)?;
                let client = self.client(&a.cluster)?;
                let rows = crate::within(crate::resources::list(&client, a.kind, None)).await?;
                body(vec![table(&a.cluster, a.kind, &rows)])
            }
            "object" => {
                let a: At = arg(payload)?;
                Ok(Reply::drawer(object(&a.cluster, a.kind, a.namespace, &a.name, &a.containers, a.tab)))
            }
            "logs_node" => {
                let text = self.run(host, crate::Op::Logs { cluster: str_of(&payload, "cluster"), namespace: str_of(&payload, "namespace"), pod: str_of(&payload, "pod"), container: payload.get("container").and_then(Value::as_str).map(str::to_string), tail: Some(500) }).await?;
                body(vec![Node::Pre { text: text.get("text").and_then(Value::as_str).unwrap_or("").to_string() }])
            }
            "manifest_node" => {
                let a: At = arg(payload)?;
                let yaml = self.run(host, crate::Op::Manifest { cluster: a.cluster, kind: a.kind, namespace: a.namespace, name: a.name }).await?;
                body(vec![Node::Pre { text: yaml.get("yaml").and_then(Value::as_str).unwrap_or("").to_string() }])
            }
            "edit" => {
                let a: At = arg(payload)?;
                let yaml = self.run(host, crate::Op::Manifest { cluster: a.cluster.clone(), kind: a.kind, namespace: a.namespace.clone(), name: a.name.clone() }).await?;
                Ok(Reply::dialog(editor(&a.cluster, a.namespace.as_deref(), yaml.get("yaml").and_then(Value::as_str).unwrap_or(""), Text::key_with("kube.editTitle", json!({ "name": a.name })))))
            }
            "create" => Ok(Reply::dialog(create_dialog(&arg::<ClusterArg>(payload)?.cluster))),
            "template" => Ok(Reply::dialog(template_dialog(&str_of(&payload, "cluster"), &str_of(&payload, "id"))?)),
            "editor_check" | "editor_apply" => {
                let yaml = str_of(&payload, "text");
                let applied = self.run(host, crate::Op::Apply { cluster: str_of(&payload, "cluster"), yaml, namespace: payload.get("namespace").and_then(Value::as_str).map(str::to_string), dry_run: op == "editor_check" }).await?;
                if op == "editor_check" {
                    Reply::data(json!({ "before": applied["before"], "after": applied["yaml"] }))
                } else {
                    Ok(Reply { close_dialog: true, close_drawer: true, refresh: true, toast: Some(k("kube.applied")), ..Reply::default() })
                }
            }
            "delete_object" => {
                let a: At = arg(payload)?;
                self.run(host, crate::Op::Delete { cluster: a.cluster, kind: a.kind, namespace: a.namespace, name: a.name }).await?;
                Ok(Reply { close_drawer: true, refresh: true, toast: Some(k("kube.deleted")), ..Reply::default() })
            }
            "restart_object" => {
                let a: At = arg(payload)?;
                self.run(host, crate::Op::Restart { cluster: a.cluster, kind: a.kind, namespace: a.namespace.unwrap_or_default(), name: a.name }).await?;
                Ok(Reply { toast: Some(k("kube.restarted")), refresh: true, ..Reply::default() })
            }
            "scale_dialog" => Ok(Reply::dialog(scale_dialog(payload))),
            "scale_object" => {
                let a: At = arg(payload)?;
                let replicas: i32 = form_str("replicas").trim().parse().map_err(|_| keyward_core::fault!("err.kubeBadScale"))?;
                self.run(host, crate::Op::Scale { cluster: a.cluster, kind: a.kind, namespace: a.namespace.unwrap_or_default(), name: a.name, replicas }).await?;
                Ok(Reply { close_dialog: true, refresh: true, toast: Some(k("kube.applied")), ..Reply::default() })
            }
            "add" => Ok(Reply::dialog(add_dialog(&self.gather(host)?))),
            "import" => {
                self.import_local(host, json!({ "context": form_str("context"), "name": form_str("name") })).await?;
                Ok(Reply { close_dialog: true, refresh: true, ..Reply::default() })
            }
            "add_yaml" => {
                self.run(host, crate::Op::Add { name: form_str("name"), yaml: form_str("yaml") }).await?;
                Ok(Reply { close_dialog: true, refresh: true, ..Reply::default() })
            }
            "shell_open" => {
                let v = self
                    .run(host, crate::Op::ShellOpen {
                        cluster: str_of(&payload, "cluster"),
                        namespace: str_of(&payload, "namespace"),
                        pod: str_of(&payload, "pod"),
                        container: payload.get("container").and_then(Value::as_str).map(str::to_string),
                        cols: payload.get("cols").and_then(Value::as_u64).unwrap_or(80) as u16,
                        rows: payload.get("rows").and_then(Value::as_u64).unwrap_or(24) as u16,
                    })
                    .await?;
                Reply::data(json!({ "stream": v["shell"] }))
            }
            "shell_read" => {
                let v = self.run(host, crate::Op::ShellRead { shell: str_of(&payload, "stream"), cursor: payload.get("cursor").and_then(Value::as_u64).unwrap_or(0), wait_ms: payload.get("wait_ms").and_then(Value::as_u64).unwrap_or(0) }).await?;
                Reply::data(v)
            }
            "shell_write" => Reply::data(self.run(host, crate::Op::ShellWrite { shell: str_of(&payload, "stream"), data: str_of(&payload, "data") }).await?),
            "shell_resize" => Reply::data(
                self.run(host, crate::Op::ShellResize { shell: str_of(&payload, "stream"), cols: payload.get("cols").and_then(Value::as_u64).unwrap_or(80) as u16, rows: payload.get("rows").and_then(Value::as_u64).unwrap_or(24) as u16 }).await?,
            ),
            "shell_close" => Reply::data(self.run(host, crate::Op::ShellClose { shell: str_of(&payload, "stream") }).await?),
            // The engine's own operations, for whoever speaks them directly:
            // the tests do.
            other => {
                let mut v = if payload.is_object() { payload } else { json!({}) };
                v["op"] = Value::String(other.to_string());
                let op: crate::Op = serde_json::from_value(v).map_err(|_| anyhow::anyhow!("the kube plugin does not know the action \"{other}\""))?;
                Reply::data(self.run(host, op).await?)
            }
        }
    }
}

/// A tab's body, loaded when it is shown.
pub(crate) fn body(nodes: Vec<Node>) -> anyhow::Result<Reply> {
    #[derive(serde::Serialize)]
    struct Body {
        body: Vec<Node>,
    }
    Reply::data(Body { body: nodes })
}

fn str_of(v: &Value, key: &str) -> String {
    v.get(key).and_then(Value::as_str).unwrap_or("").to_string()
}

/// The checked editor as a dialogue.
pub(crate) fn editor(cluster: &str, namespace: Option<&str>, yaml: &str, title: Text) -> Page {
    let at = json!({ "cluster": cluster, "namespace": namespace });
    Page {
        title: Some(title),
        body: vec![Node::Editor { text: yaml.to_string(), check: Action::with("editor_check", at.clone()), apply: Action::with("editor_apply", at) }],
        ..Page::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_server_with_a_master_offers_one_open_and_no_primary() {
        let s = ServerRow {
            machine: keyward_ssh_client::targets::Machine {
                entry_id: "k".into(),
                entry_name: "Deploy".into(),
                host: "vps".into(),
                address: "vps".into(),
                port: 29015,
                user: Some("ubuntu".into()),
                pin: None,
                proxy: None,
                missing: Vec::new(),
            },
            look: Some(Look::Seen { found: vec![crate::detect::Found { kind: Distro::K3s, access: Access::Sudo }], at: 1, machine: None, peer: None }),
            looking: false,
            aliases: vec!["vps-internal".into()],
        };
        let row = server_row(&s, false);
        assert_eq!(row.tone, Tone::Ok);
        let opens: Vec<&Button> = row.actions.iter().filter(|b| b.action.op == "open_cluster").collect();
        assert_eq!(opens.len(), 1);
        assert!(row.actions.iter().all(|b| !b.primary), "the screen's one main action is the scan");
        assert!(matches!(&row.subtitle, Some(Text::Raw { raw }) if raw.contains("vps-internal")));
    }
}

/// A new object: which template it starts from.
pub(crate) fn create_dialog(c: &str) -> Page {
    let rows = crate::templates::TEMPLATES
        .iter()
        .map(|(id, label, _)| {
            let mut r = ListRow::new(*id, "plus", k(label));
            r.actions.push(Button::icon("chevron", k("kube.template"), Action::with("template", json!({ "cluster": c, "id": id }))));
            r
        })
        .collect();
    Page { title: Some(k("kube.create")), body: vec![Node::List { rows }], ..Page::default() }
}

/// A template in the checked editor.
pub(crate) fn template_dialog(c: &str, id: &str) -> anyhow::Result<Page> {
    let (_, _, yaml) = crate::templates::TEMPLATES.iter().find(|(t, _, _)| *t == id).ok_or_else(|| anyhow::anyhow!("no template \"{id}\""))?;
    Ok(editor(c, None, yaml, k("kube.newObject")))
}

/// How many replicas: a number, sent with the object it is for.
pub(crate) fn scale_dialog(at: Value) -> Page {
    Page {
        title: Some(k("kube.scale")),
        body: vec![Node::Form {
            fields: vec![Field { id: "replicas".into(), label: k("kube.scale"), kind: FieldKind::Number { min: 0, max: 1000 }, hint: None, value: None }],
            submit: Button::labelled(k("kube.apply"), Action::with("scale_object", at)).with_icon("check").primary(),
        }],
        ..Page::default()
    }
}
