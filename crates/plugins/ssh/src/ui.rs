//! The terminal and the routes as the window draws them, from the core's
//! vocabulary: the shells open now, a host's shells and a new one, which key
//! goes where, and the agent's settings. The plugin brings no code for any of
//! it: the window's own terminal carries a shell over the plugin's sealed
//! road, naming the session it means, and the shells outlive the screen —
//! closed only by the person, attached again with their scrollback.
//!
//! The private key never leaves the daemon: the core signs the login, behind
//! the person's finger. An unknown host's key is asked about in the
//! terminal, with its fingerprint; a changed one is refused.

use std::time::Duration;

use keyward_plugin::Host;
use keyward_ui::{Action, Button, Cell, Chip, Column, Field, FieldKind, Node, Page, Reply, Tab, TableRow, Text, Tone};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::places::{declare, CHECK_OP};
use crate::terminal::session::{Info, State};
use crate::{keys, shared_socket, Ask, SshKeyEntry, SshPlugin, SshSettings};

fn k(key: &str) -> Text {
    Text::key(key)
}

/// How long a read waits for output, at most.
const READ_WAIT: Duration = Duration::from_secs(15);

/// How often the agent may check the keys' health, in minutes.
const HEALTH_EVERY: [u32; 5] = [0, 15, 30, 60, 180];

/// A host place's route: `host/<host>:<port>`.
pub fn host_of_route(route: &str) -> Option<(String, u16)> {
    let rest = route.strip_prefix("host/")?;
    let (h, p) = rest.rsplit_once(':')?;
    Some((h.to_string(), p.parse().ok()?))
}

fn where_of(i: &Info) -> String {
    let port = if i.port == 22 { String::new() } else { format!(":{}", i.port) };
    format!("{}@{}{port}", i.user, i.host)
}

/// A shell's terminal: attached to its session, kept when the screen goes.
fn terminal(i: &Info) -> Node {
    Node::Terminal {
        open: Action::with("term_attach", json!({ "session": i.id })),
        read: "term_read".into(),
        write: "term_write".into(),
        resize: "term_resize".into(),
        close: "term_close".into(),
        trust: Some("term_trust".into()),
        keep: true,
    }
}

/// Shells as tabs, the newest shown first unless one is named.
fn shells(sessions: &[(Info, State)], on: Option<&str>) -> Node {
    let newest = sessions.last().map(|(i, _)| i.id.clone());
    Node::Tabs {
        id: "ssh|shells".into(),
        icons_only: false,
        on: on.map(str::to_string).filter(|id| sessions.iter().any(|(i, _)| &i.id == id)).or(newest),
        tabs: sessions.iter().map(|(i, _)| Tab { id: i.id.clone(), title: Text::raw(where_of(i)), icon: Some("terminal".into()), load: None, refresh_ms: None, body: vec![terminal(i)] }).collect(),
    }
}

/// The shells open now, and connecting to a host.
pub fn sessions_page(sessions: &[(Info, State)]) -> Page {
    let body = if sessions.is_empty() {
        vec![Node::Empty { icon: "terminal".into(), title: k("ssh.noSessions"), body: Some(k("term.connectHint")) }]
    } else {
        vec![shells(sessions, None)]
    };
    Page {
        title: Some(k("ssh.sessions")),
        icon: Some("terminal".into()),
        chips: if sessions.is_empty() { Vec::new() } else { vec![Chip::new(Text::key_with("ssh.sessionsN", json!({ "n": sessions.len() })))] },
        actions: vec![Button::labelled(k("term.connectMore"), Action::op("connect_dialog")).with_icon("plus").primary()],
        body,
        ..Page::default()
    }
}

/// A host's shells, and a new one with the key its routes give it.
pub fn host_page(host: &str, port: u16, user: Option<&str>, sessions: &[(Info, State)], on: Option<&str>) -> Page {
    let here: Vec<(Info, State)> = sessions.iter().filter(|(i, _)| i.host == host && i.port == port).cloned().collect();
    let body = if here.is_empty() {
        vec![Node::Empty { icon: "terminal".into(), title: k("ssh.noShellsHere"), body: Some(k("term.connectHint")) }]
    } else {
        vec![shells(&here, on)]
    };
    Page {
        title: Some(Text::raw(host)),
        icon: Some("server".into()),
        subtitle: Some(Text::raw(match user {
            Some(u) => format!("{u}@{host}:{port}"),
            None => format!("{host}:{port}"),
        })),
        actions: vec![Button::labelled(k("term.connect"), Action::with("session_new", json!({ "host": host, "port": port, "user": user }))).with_icon("terminal").primary()],
        body,
        ..Page::default()
    }
}

/// Connecting to a host the routes may not name: where, as whom, and with
/// which key.
pub fn connect_dialog(keys: &[SshKeyEntry]) -> Page {
    let options = std::iter::once((String::new(), k("term.keyByRoute"))).chain(keys.iter().map(|k| (k.id.clone(), Text::raw(&k.name)))).collect();
    Page {
        title: Some(k("term.connectTitle")),
        body: vec![
            Node::Alert { text: k("term.connectHint"), tone: Tone::Plain },
            Node::Form {
                fields: vec![
                    Field { id: "host".into(), label: k("term.host"), kind: FieldKind::Text, hint: None, value: None },
                    Field { id: "user".into(), label: k("term.login"), kind: FieldKind::Text, hint: None, value: None },
                    Field { id: "port".into(), label: k("term.port"), kind: FieldKind::Number { min: 1, max: 65_535 }, hint: None, value: Some("22".into()) },
                    Field { id: "entry_id".into(), label: k("term.key"), kind: FieldKind::Select { options }, hint: None, value: Some(String::new()) },
                ],
                submit: Button::labelled(k("term.connect"), Action::op("session_new")).with_icon("terminal").primary(),
            },
        ],
        ..Page::default()
    }
}

/// Which key goes where: each key's hosts, login and port.
pub fn routes_page(keys: &[SshKeyEntry]) -> Page {
    let rows = keys
        .iter()
        .map(|e| {
            TableRow::new(e.id.clone())
                .cell("key", Cell::Text { text: Text::raw(&e.name) })
                .cell("hosts", if e.hosts.trim().is_empty() { Cell::Chip { chip: Chip::state(k("ssh.unbound"), Tone::Warn) } } else { Cell::Text { text: Text::raw(&e.hosts) } })
                .cell("user", if e.user.is_empty() { Cell::Empty } else { Cell::Text { text: Text::raw(&e.user) } })
                .cell("port", if e.port.is_empty() { Cell::Empty } else { Cell::Text { text: Text::raw(&e.port) } })
                .facet("bound", Some(if e.hosts.trim().is_empty() { "no" } else { "yes" }))
                .open(Action::with("route", json!({ "entry_id": e.id })))
        })
        .collect();
    Page {
        title: Some(k("routes.title")),
        icon: Some("key".into()),
        body: vec![Node::Table {
            id: "ssh|routes".into(),
            columns: vec![
                Column { id: "key".into(), title: k("term.key"), sortable: true, mono: false },
                Column { id: "hosts".into(), title: k("routes.hosts"), sortable: true, mono: true },
                Column { id: "user".into(), title: k("routes.login"), sortable: true, mono: true },
                Column { id: "port".into(), title: k("routes.port"), sortable: true, mono: true },
            ],
            facets: vec![keyward_ui::Facet { id: "bound".into(), title: k("ssh.bound"), icon: "server".into() }],
            rows,
            empty: Some(k("routes.empty.body")),
        }],
        ..Page::default()
    }
}

/// One key's routes, to change.
pub fn route_drawer(e: &SshKeyEntry) -> Page {
    Page {
        title: Some(Text::raw(&e.name)),
        icon: Some("key".into()),
        body: vec![Node::Form {
            fields: vec![
                Field { id: "hosts".into(), label: k("routes.hosts"), kind: FieldKind::Text, hint: Some(k("routes.hostsHint")), value: Some(e.hosts.clone()) },
                Field { id: "user".into(), label: k("routes.login"), kind: FieldKind::Text, hint: Some(k("routes.loginHint")), value: Some(e.user.clone()) },
                Field { id: "port".into(), label: k("routes.port"), kind: FieldKind::Text, hint: None, value: Some(e.port.clone()) },
            ],
            submit: Button::labelled(k("routes.bind"), Action::with("route_save", json!({ "entry_id": e.id }))).with_icon("check").primary(),
        }],
        ..Page::default()
    }
}

fn ask_id(a: Ask) -> String {
    serde_json::to_value(a).ok().and_then(|v| v.as_str().map(str::to_string)).expect("a choice is a word")
}

/// The agent's settings, its state and the lines for `~/.ssh/config`.
pub fn settings_page(s: &SshSettings, socket: Option<&str>, snippet: &str, mappings: usize, live: usize, unmapped: usize) -> Page {
    let health = HEALTH_EVERY.iter().map(|n| (n.to_string(), if *n == 0 { k("settings.sshHealth.off") } else { Text::key_with("settings.sshHealth.every", json!({ "n": n })) })).collect();
    let mut body = vec![Node::Section {
        title: k("plugin.ssh.agent"),
        icon: "key".into(),
        tone: Tone::Plain,
        count: None,
        folded: false,
        hint: None,
        body: vec![Node::Form {
            fields: vec![
                Field { id: "agent_enabled".into(), label: k("settings.sshAgent"), kind: FieldKind::Toggle, hint: Some(k("settings.sshAgentHint")), value: Some(s.agent_enabled.to_string()) },
                Field { id: "ask".into(), label: k("settings.sshAsk"), kind: FieldKind::Select { options: vec![(ask_id(Ask::Never), k("settings.sshAsk.never")), (ask_id(Ask::Always), k("settings.sshAsk.always"))] }, hint: Some(k("settings.sshAskHint")), value: Some(ask_id(s.ask)) },
                Field { id: "health_minutes".into(), label: k("settings.sshHealth"), kind: FieldKind::Select { options: health }, hint: Some(k("settings.sshHealthHint")), value: Some(s.health_minutes.to_string()) },
                Field { id: "shared_socket".into(), label: k("settings.sshSocket"), kind: FieldKind::Toggle, hint: Some(k("settings.sshSocketHint")), value: Some(s.shared_socket.to_string()) },
            ],
            submit: Button::labelled(k("ssh.save"), Action::op("save_settings")).with_icon("check"),
        }],
    }];
    if let (true, Some(path)) = (s.shared_socket, socket) {
        body.push(Node::Section { title: k("settings.sshSocketPath"), icon: "terminal".into(), tone: Tone::Plain, count: None, folded: false, hint: Some(k("settings.sshSocketPathHint")), body: vec![Node::Pre { text: format!("export SSH_AUTH_SOCK={path}") }] });
    }
    body.push(Node::Section { title: k("settings.sshConfig"), icon: "code".into(), tone: Tone::Plain, count: None, folded: false, hint: Some(k("settings.sshConfigHint")), body: vec![Node::Pre { text: snippet.to_string() }] });
    body.push(Node::Chips {
        chips: vec![
            Chip::new(Text::key_with("ssh.routesN", json!({ "n": mappings }))).icon("server"),
            Chip::new(Text::key_with("ssh.socketsN", json!({ "n": live }))).icon("key"),
            if unmapped > 0 { Chip::state(Text::key_with("ssh.unmappedN", json!({ "n": unmapped })), Tone::Warn) } else { Chip::state(k("ssh.allBound"), Tone::Ok) },
        ],
    });
    Page { title: Some(k("plugin.ssh.title")), icon: Some("settings".into()), body, ..Page::default() }
}

// -- What a form and a stream send -------------------------------------------------

fn form_of(form: Value) -> anyhow::Result<std::collections::BTreeMap<String, String>> {
    if form.is_null() {
        return Ok(Default::default());
    }
    serde_json::from_value(form).map_err(|e| anyhow::anyhow!("a form came with something other than text: {e}"))
}

fn arg<T: serde::de::DeserializeOwned>(v: Value) -> anyhow::Result<T> {
    serde_json::from_value(v).map_err(|e| anyhow::anyhow!("an action came with something else: {e}"))
}

fn flag(form: &std::collections::BTreeMap<String, String>, id: &str) -> anyhow::Result<bool> {
    match form.get(id).map(String::as_str) {
        Some("true") => Ok(true),
        Some("false") => Ok(false),
        other => anyhow::bail!("the switch \"{id}\" came as {other:?}"),
    }
}

/// A read's cursor: where the output was read to, in which run of it.
#[derive(Deserialize, Default)]
struct Cursor {
    #[serde(default)]
    at: u64,
    #[serde(default)]
    version: u64,
}

#[derive(Deserialize)]
struct Stream {
    stream: String,
}

#[derive(Deserialize)]
struct Read {
    stream: String,
    #[serde(default)]
    cursor: Value,
    #[serde(default)]
    wait_ms: u64,
}

/// A session's state as the window's terminal reads it.
fn chunk_state(s: &State) -> Value {
    match s {
        State::Connecting => json!({ "state": "connecting" }),
        State::Authenticating => json!({ "state": "authenticating" }),
        State::Open => json!({ "state": "open" }),
        State::Verify { prompt } => json!({
            "state": "verify",
            "ask": {
                "text": Text::key_with(if prompt.others { "ssh.verifyOthers" } else { "ssh.verify" }, json!({ "host": prompt.host, "algorithm": prompt.algorithm })),
                "code": prompt.fingerprint,
            },
        }),
        State::Closed { error, exit } => json!({ "state": "closed", "error": error.clone().or_else(|| exit.filter(|c| *c != 0).map(|c| format!("err.sshExit {}", json!({ "code": c })))) }),
    }
}

impl SshPlugin {
    async fn sessions_now(&self) -> anyhow::Result<Vec<(Info, State)>> {
        self.terminals.live()
    }
}

#[async_trait::async_trait]
impl keyward_ui::Ui for SshPlugin {
    async fn places(&self, _host: &dyn Host) -> anyhow::Result<keyward_ui::places::Places> {
        let report = self.with_view(|view| self.terminals.health(&view)).await?;
        Ok(declare(&report))
    }

    async fn view(&self, host: &dyn Host, route: &str) -> anyhow::Result<Page> {
        let sessions = self.sessions_now().await?;
        if route.is_empty() {
            return Ok(sessions_page(&sessions));
        }
        if route == "keys" {
            return Ok(routes_page(&keys(host)));
        }
        if route == "settings" {
            let inner = self.inner.lock().await;
            let (mappings, live, socket) = (inner.table.len(), inner.live.len(), shared_socket(&inner));
            drop(inner);
            let unmapped = keys(host).iter().filter(|k| k.hosts.trim().is_empty()).count();
            return Ok(settings_page(&SshSettings::read(host), socket.as_deref(), &keyward_core::paths::ssh_config_snippet(), mappings, live, unmapped));
        }
        let (h, port) = host_of_route(route).ok_or_else(|| anyhow::anyhow!("the ssh plugin has no screen \"{route}\""))?;
        // The login the keys' checks went in with, where they say one.
        let report = self.with_view(|view| self.terminals.health(&view)).await?;
        let user = report.keys.iter().flat_map(|kh| &kh.checks).find(|c| c.host == h && c.port == port).and_then(|c| c.user.clone());
        Ok(host_page(&h, port, user.as_deref(), &sessions, None))
    }

    async fn act(&self, host: &dyn Host, op: &str, payload: Value, form: Value) -> anyhow::Result<Reply> {
        let form = form_of(form)?;
        let field = |id: &str| form.get(id).map(|s| s.trim().to_string()).unwrap_or_default();
        match op {
            CHECK_OP => {
                let inner = self.inner.lock().await;
                let (entries, table) = (inner.entries.clone(), inner.table.clone());
                drop(inner);
                let ssh = crate::terminal::sshconfig::shared().await?;
                let view = crate::terminal::View { entries: &entries, table: &table, ssh: &ssh };
                match self.terminals.call(host, self.core(), view, "health_run", payload).await {
                    Some(answer) => answer.map(|_| Reply::refresh()),
                    None => anyhow::bail!("the terminal no longer checks keys"),
                }
            }
            // -- shells --
            "connect_dialog" => Ok(Reply::dialog(connect_dialog(&keys(host)))),
            "session_new" => {
                // From a host's page (its payload) or the connect dialogue
                // (its form).
                let h = payload.get("host").and_then(Value::as_str).map(str::to_string).unwrap_or_else(|| field("host"));
                let port = match payload.get("port").and_then(Value::as_u64) {
                    Some(p) => Some(u16::try_from(p).map_err(|_| keyward_core::fault!("err.sshBadPortField", "port" => p.to_string().as_str(), "key" => ""))?),
                    None if field("port").is_empty() => None,
                    None => Some(field("port").parse::<u16>().map_err(|_| keyward_core::fault!("err.sshBadPortField", "port" => field("port").as_str(), "key" => ""))?),
                };
                let user = payload.get("user").and_then(Value::as_str).map(str::to_string).or_else(|| Some(field("user"))).filter(|u| !u.is_empty());
                let entry = Some(field("entry_id")).filter(|e| !e.is_empty());
                let dir = host.state_dir();
                let core = self.core();
                let info = {
                    let inner = self.inner.lock().await;
                    let (entries, table) = (inner.entries.clone(), inner.table.clone());
                    drop(inner);
                    let ssh = crate::terminal::sshconfig::shared().await?;
                    let view = crate::terminal::View { entries: &entries, table: &table, ssh: &ssh };
                    self.terminals.start(&view, core, &dir, entry, h, port, user)?
                };
                // The new shell stands on its host's page, its tab shown.
                Ok(Reply { close_dialog: true, refresh: true, ..Reply::go(format!("host/{}:{}", info.host, info.port)) })
            }
            "term_attach" => {
                let session = payload.get("session").and_then(Value::as_str).ok_or_else(|| anyhow::anyhow!("an attach to no session"))?;
                let info = self.terminals.attach(session)?;
                Reply::data(json!({ "stream": info.id }))
            }
            "term_read" => {
                let a: Read = arg(payload)?;
                let c: Cursor = if a.cursor.is_object() { arg(a.cursor)? } else { Cursor::default() };
                let chunk = self.terminals.read(&a.stream, c.at, c.version, Duration::from_millis(a.wait_ms).min(READ_WAIT)).await?;
                let mut out = chunk_state(&chunk.state);
                out["data"] = json!(crate::terminal::Terminals::encode(&chunk.data[..]));
                out["cursor"] = json!({ "at": chunk.cursor, "version": chunk.version });
                Reply::data(out)
            }
            "term_write" => {
                let a: Stream = arg(payload.clone())?;
                let data = payload.get("data").and_then(Value::as_str).ok_or_else(|| anyhow::anyhow!("keystrokes with no data"))?;
                self.terminals.write(&a.stream, data)?;
                Ok(Reply::default())
            }
            "term_resize" => {
                let a: Stream = arg(payload.clone())?;
                let n = |key: &str| payload.get(key).and_then(Value::as_u64).and_then(|v| u32::try_from(v).ok()).ok_or_else(|| anyhow::anyhow!("a size with no {key}"));
                self.terminals.resize(&a.stream, n("cols")?, n("rows")?)?;
                Ok(Reply::default())
            }
            "term_trust" => {
                let a: Stream = arg(payload.clone())?;
                let yes = payload.get("answer").and_then(Value::as_bool).ok_or_else(|| anyhow::anyhow!("an answer that is not a yes or a no"))?;
                self.terminals.trust(&a.stream, yes)?;
                Ok(Reply::default())
            }
            "term_close" => {
                let a: Stream = arg(payload)?;
                self.terminals.end(&a.stream)?;
                Ok(Reply::refresh())
            }
            // -- routes --
            "route" => {
                let id = payload.get("entry_id").and_then(Value::as_str).ok_or_else(|| anyhow::anyhow!("a route of no key"))?;
                let e = keys(host).into_iter().find(|k| k.id == id).ok_or_else(|| keyward_core::fault!("err.sshKeyGone"))?;
                Ok(Reply::drawer(route_drawer(&e)))
            }
            "route_save" => {
                let id = payload.get("entry_id").and_then(Value::as_str).ok_or_else(|| anyhow::anyhow!("a route of no key"))?;
                keyward_plugin::Plugin::call(self, host, "set_hosts", json!({ "entry_id": id, "hosts": field("hosts"), "user": field("user"), "port": field("port") })).await?;
                Ok(Reply { close_drawer: true, refresh: true, toast: Some(k("ssh.saved")), ..Reply::default() })
            }
            // -- settings --
            "save_settings" => {
                let ask: Ask = serde_json::from_value(Value::String(field("ask"))).map_err(|_| anyhow::anyhow!("the choice \"{}\" is not one", field("ask")))?;
                let health_minutes: u32 = field("health_minutes").parse().map_err(|_| anyhow::anyhow!("the health interval \"{}\" is not a number", field("health_minutes")))?;
                let s = SshSettings { agent_enabled: flag(&form, "agent_enabled")?, ask, shared_socket: flag(&form, "shared_socket")?, health_minutes };
                keyward_plugin::Plugin::call(self, host, "set_settings", serde_json::to_value(&s)?).await?;
                Ok(Reply { refresh: true, toast: Some(k("ssh.saved")), ..Reply::default() })
            }
            other => anyhow::bail!("the ssh plugin's screens have no action \"{other}\""),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_host_route_reads_back() {
        assert_eq!(host_of_route("host/db-1.prod.example:2222"), Some(("db-1.prod.example".to_string(), 2222)));
        assert_eq!(host_of_route("host/nope"), None);
        assert_eq!(host_of_route("keys"), None);
    }
}
