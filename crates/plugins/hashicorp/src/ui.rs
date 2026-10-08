//! The broker as the window draws it, from the core's vocabulary: the Vaults
//! connected, each a place on the path, and a console for the one in use —
//! its seal, the access issued, the secrets, the engines, the policies, the
//! root tokens. The plugin brings no code for any of it.
//!
//! The places cost no request to a Vault: they are built from the vault
//! items that hold the connections. A Vault is asked only from its console.
//!
//! Nothing secret travels to the window: a secret's values stay in the
//! plugin (a value is copied through the core, a field is changed by typing
//! a new value into a field that is never filled back), an issued token goes
//! straight to the clipboard, a root token never leaves its hidden item, and
//! the shares of an unseal key are read by the daemon into the call that
//! needs them (`Action::filled`).

use std::collections::BTreeMap;

use keyward_plugin::Host;
use keyward_ui::places::{Block, Doc, Kid, Level, Mark, Place, Places, Preview, Section as DocSection, Target, Use, Verb};
use keyward_ui::{Action, Button, Cell, Chip, Column, Crumb, Facet, Field, FieldKind, ItemPick, ListRow, Node, Page, Reply, Tab, TableRow, Text, Tone};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::link::{Form, Link};
use crate::model::{Health, IssueRequest, IssueState, Issued, KvConfig, Mount, MountForm, MountTune, Recipient, RootToken, SealStatus, SecretMeta, SecretMetaPatch, SecretView, POLICY_ADMIN};
use crate::{broker, store, HashicorpPlugin};

fn k(key: &str) -> Text {
    Text::key(key)
}

fn kw(key: &str, args: Value) -> Text {
    Text::key_with(key, args)
}

/// The verbs a connection's page offers.
pub const USE: &str = "use vault";
pub const FORGET: &str = "disconnect vault";

/// The route of a connection's console.
pub fn conn_route(entry_id: &str) -> String {
    format!("conn/{entry_id}")
}

/// Seconds as the person reads a lifetime.
fn ttl_text(secs: u64) -> Text {
    if secs >= 3600 && secs % 3600 == 0 {
        kw("ttl.hours", json!({ "n": secs / 3600 }))
    } else {
        kw("ttl.minutes", json!({ "n": (secs / 60).max(1) }))
    }
}

// -- The places -------------------------------------------------------------------

/// The connected Vaults, the one in use marked.
pub fn declare(links: &[Link], active: Option<&str>) -> Places {
    let mut root = Place::root("vault", Text::raw("HashiCorp Vault"), if links.is_empty() { Level::Unknown } else { Level::Healthy });
    root.hue = Some("amber".into());
    root.screen = Some(String::new());
    root.subtitle = Some(if links.is_empty() { k("hashicorp.absent") } else { kw("hc.connections", json!({ "n": links.len() })) });
    root.kids = links.iter().map(|l| Kid::Place { id: conn_route(&l.entry_id), sub: None }).collect();
    root.page = Some(Doc {
        what: Some(k("plugin.hashicorp.description")),
        sections: vec![DocSection {
            title: k("hashicorp.connections"),
            count: Some(links.len()),
            blocks: if links.is_empty() {
                vec![Block::Para { text: k("hashicorp.absentBody") }]
            } else {
                links.iter().map(|l| Block::Ref { to: Target::Place(conn_route(&l.entry_id)), title: None, context: Some(Text::raw(&l.addr)), mark: None, mono: false }).collect()
            },
        }],
        note: Some(k("hc.noteSecrets")),
        ..Doc::default()
    });
    let mut places = Vec::new();
    let mut uses = Vec::new();
    let mut forgets = Vec::new();
    for l in links {
        let id = conn_route(&l.entry_id);
        let on = active == Some(l.entry_id.as_str());
        let (level, why) = if on { (Level::Healthy, k("vault.active")) } else { (Level::Unknown, k("hc.notInUse")) };
        let mut p = Place::under(None, id.clone(), "vault", Text::raw(if l.entry_name.is_empty() { &l.addr } else { &l.entry_name }), level);
        p.subtitle = Some(Text::raw(&l.addr));
        p.sub_mono = true;
        p.why = Some(why.clone());
        p.short = Some(why.clone());
        p.screen = Some(id.clone());
        p.page = Some(Doc {
            what: Some(Text::raw(&l.addr)),
            state: Some(Mark { level, text: why }),
            more: if on { vec![FORGET.into()] } else { vec![USE.into(), FORGET.into()] },
            sections: vec![DocSection {
                title: k("hc.connection"),
                count: None,
                blocks: vec![
                    Block::Field { label: k("hashicorp.addr"), value: Text::raw(&l.addr), mono: true, mark: None },
                    Block::Field { label: k("vault.unsealKeys"), value: kw("hc.fieldsChosen", json!({ "n": l.unseal_keys })), mono: false, mark: None },
                    Block::Field {
                        label: k("vault.tab.root"),
                        value: k(if l.has_root { "hc.rootKept" } else { "hc.rootNone" }),
                        mono: false,
                        mark: Some(if l.has_root { Mark { level: Level::Warning, text: k("hc.rootKeptShort") } } else { Mark { level: Level::Healthy, text: k("hc.rootNoneShort") } }),
                    },
                    Block::Field { label: k("hc.approle"), value: k(if l.has_role_id { "common.yes" } else { "common.no" }), mono: false, mark: None },
                    Block::Ref { to: Target::Item(l.entry_id.clone()), title: None, context: Some(k("hashicorp.entry")), mark: None, mono: false },
                ],
            }],
            ..Doc::default()
        });
        places.push(p);
        let target = Target::Place(id);
        if !on {
            uses.push(Use { on: target.clone(), action: Action::with("use", json!({ "entry_id": l.entry_id })) });
        }
        forgets.push(Use { on: target, action: Action::with("forget", json!({ "entry_id": l.entry_id })) });
    }
    let mut out = Places::new(root);
    out.places = places;
    if !uses.is_empty() {
        out.verbs.push(Verb { id: USE.into(), name: k("hc.use"), icon: Some("check".into()), uses, preview: Preview { lede: k("hashicorp.pickVaultHint"), steps: Vec::new(), go: k("hc.use"), note: None, danger: false } });
    }
    if !forgets.is_empty() {
        out.verbs.push(Verb {
            id: FORGET.into(),
            name: k("hashicorp.forget"),
            icon: Some("trash".into()),
            uses: forgets,
            preview: Preview { lede: k("hashicorp.forgetWarn"), steps: vec![(k("hc.forgetStep"), k("hc.forgetStepSub"))], go: k("hashicorp.forget"), note: None, danger: true },
        });
    }
    out.settings = Some("settings".into());
    out
}

// -- The screens --------------------------------------------------------------------

/// The plugin's own settings.
pub fn settings_page(expiry_notices: bool) -> Page {
    Page {
        title: Some(Text::raw("HashiCorp Vault")),
        icon: Some("settings".into()),
        body: vec![Node::Section {
            title: k("plugin.hashicorp.notices"),
            icon: "clock".into(),
            tone: Tone::Plain,
            count: None,
            folded: false,
            hint: None,
            body: vec![Node::Form {
                fields: vec![Field { id: "expiry_notices".into(), label: k("settings.expiryNotices"), kind: FieldKind::Toggle, hint: Some(k("settings.expiryNoticesHint")), value: Some(expiry_notices.to_string()) }],
                submit: Button::labelled(k("hc.save"), Action::op("save_settings")).with_icon("check"),
            }],
        }],
        ..Page::default()
    }
}

/// The connections, and connecting another.
pub fn overview(links: &[Link], active: Option<&str>) -> Page {
    let body = if links.is_empty() {
        vec![Node::Empty { icon: "vault".into(), title: k("hashicorp.absent"), body: Some(k("hashicorp.absentBody")) }]
    } else {
        vec![Node::Cards {
            cards: links
                .iter()
                .map(|l| {
                    let mut c = ListRow::new(l.entry_id.clone(), "vault", Text::raw(if l.entry_name.is_empty() { &l.addr } else { &l.entry_name }));
                    c.subtitle = Some(Text::raw(&l.addr));
                    if active == Some(l.entry_id.as_str()) {
                        c.tone = Tone::Ok;
                        c.chips.push(Chip::state(k("vault.active"), Tone::Ok));
                    }
                    c.open = Some(Action::with("go", json!({ "route": conn_route(&l.entry_id) })));
                    c
                })
                .collect(),
        }]
    };
    Page {
        title: Some(k("hashicorp.connections")),
        icon: Some("vault".into()),
        actions: vec![Button::labelled(k("hc.connect"), Action::op("connect_dialog")).with_icon("plus").primary()],
        body,
        ..Page::default()
    }
}

/// A connection that is not the one in use: the broker works with one at a
/// time, so opening another is choosing it.
pub fn not_in_use(l: &Link) -> Page {
    Page {
        title: Some(Text::raw(if l.entry_name.is_empty() { &l.addr } else { &l.entry_name })),
        icon: Some("vault".into()),
        subtitle: Some(Text::raw(&l.addr)),
        body: vec![
            Node::Alert { text: k("hashicorp.pickVaultHint"), tone: Tone::Plain },
            Node::Actions { buttons: vec![Button::labelled(k("hc.use"), Action::with("use", json!({ "entry_id": l.entry_id }))).with_icon("check").primary()] },
        ],
        ..Page::default()
    }
}

/// The console of the Vault in use: its state, and its parts in tabs.
pub fn console(l: &Link, health: Result<&Health, Text>, seal: Option<&SealStatus>) -> Page {
    let mut chips = Vec::new();
    let mut body = Vec::new();
    match health {
        Ok(h) => {
            chips.push(if h.sealed { Chip::state(k("vault.sealed"), Tone::Bad) } else { Chip::state(k("hc.unsealed"), Tone::Ok) });
            if h.standby {
                chips.push(Chip::new(k("hc.standby")));
            }
            if let Some(v) = &h.version {
                chips.push(Chip::new(Text::raw(v)));
            }
        }
        Err(why) => body.push(Node::Alert { text: why, tone: Tone::Bad }),
    }
    if let Some(s) = seal.filter(|s| s.sealed) {
        let unseal = if l.unseal_fields.is_empty() { Action::op("unseal_stored") } else { Action::op("ui_unseal").filled(&l.entry_id, l.unseal_fields.clone(), "shares") };
        body.push(Node::Section {
            title: k("vault.sealedTitle"),
            icon: "lock".into(),
            tone: Tone::Bad,
            count: None,
            folded: false,
            hint: Some(kw("vault.threshold", json!({ "t": s.t, "n": s.n }))),
            body: vec![
                Node::Alert { text: kw("vault.sealedBody", json!({ "p": s.progress, "t": s.t })), tone: Tone::Warn },
                Node::Actions { buttons: vec![Button::labelled(k("hc.unseal"), unseal).with_icon("lock")] },
            ],
        });
    }
    let tab = |id: &str, title: &str, icon: &str, load: &str| Tab { id: id.into(), title: k(title), icon: Some(icon.into()), load: Some(Action::op(load)), refresh_ms: None, body: Vec::new() };
    body.push(Node::Tabs {
        id: "hashicorp|parts".into(),
        icons_only: false,
        on: None,
        tabs: vec![
            tab("issued", "vault.tab.issued", "clock", "issued_body"),
            tab("secrets", "vault.tab.secrets", "key", "mounts_body"),
            tab("engines", "vault.tab.engines", "stack", "engines_body"),
            tab("policies", "vault.tab.policies", "policy", "policies_body"),
            tab("root", "vault.tab.root", "shield", "roots_body"),
        ],
    });
    Page {
        title: Some(Text::raw(if l.entry_name.is_empty() { &l.addr } else { &l.entry_name })),
        icon: Some("vault".into()),
        subtitle: Some(Text::raw(&l.addr)),
        chips,
        actions: vec![
            Button::labelled(k("vault.issue"), Action::op("issue_dialog")).with_icon("plus").primary(),
            Button::icon("edit", k("secret.edit"), Action::op("edit_dialog")),
            Button::icon("refresh", k("hc.refresh"), Action::op("refresh")),
        ],
        body,
        ..Page::default()
    }
}

// -- Connecting ----------------------------------------------------------------------

/// The first step: the address, checked before anything is written.
pub fn connect_address() -> Page {
    Page {
        title: k("hc.connectTitle").into(),
        body: vec![
            Node::Alert { text: k("connect.addrHint"), tone: Tone::Plain },
            Node::Form {
                fields: vec![Field { id: "addr".into(), label: k("hashicorp.addr"), kind: FieldKind::Text, hint: None, value: None }],
                submit: Button::labelled(k("hashicorp.probe"), Action::op("probe")).with_icon("check").primary(),
            },
        ],
        ..Page::default()
    }
}

/// The second: the note the shares live in, and, with Shamir, which of its
/// fields hold them — by name; the values stay where they are.
pub fn connect_note(addr: &str, seal: &SealStatus) -> Page {
    Page {
        title: k("hc.connectTitle").into(),
        subtitle: Some(Text::raw(addr)),
        body: vec![
            Node::Alert { text: if seal.t > 0 { kw("hashicorp.threshold", json!({ "t": seal.t, "n": seal.n })) } else { k("hashicorp.sealAuto") }, tone: Tone::Plain },
            Node::Form {
                fields: vec![Field { id: "entry_id".into(), label: k("hashicorp.entry"), kind: FieldKind::Item { item_kind: ItemPick::Note }, hint: Some(k("connect.noteHint")), value: None }],
                submit: Button::labelled(k("step.next"), Action::with("note_chosen", json!({ "addr": addr, "needed": seal.t }))).with_icon("chev").primary(),
            },
        ],
        ..Page::default()
    }
}

/// The last: the shares' fields, and AppRole if there is one. `link` is the
/// connection being edited, whose choices stand.
pub fn connect_fields(addr: &str, entry_id: &str, fields: &[String], needed: u32, link: Option<&Link>) -> Page {
    let options: Vec<(String, Text)> = std::iter::once((String::new(), k("hc.noField"))).chain(fields.iter().map(|f| (f.clone(), Text::raw(f)))).collect();
    let slots = needed.max(link.map(|l| l.unseal_fields.len() as u32).unwrap_or(0));
    let mut form = vec![Field { id: "addr".into(), label: k("hashicorp.addr"), kind: FieldKind::Text, hint: None, value: Some(addr.to_string()) }];
    if fields.is_empty() && slots > 0 {
        form.push(Field { id: "note".into(), label: k("vault.unsealKeys"), kind: FieldKind::Text, hint: Some(k("hashicorp.noFields")), value: None });
    }
    for i in 0..slots {
        let chosen = link.and_then(|l| l.unseal_fields.get(i as usize)).cloned();
        if !fields.is_empty() {
            form.push(Field { id: format!("share{i}"), label: kw("hashicorp.shareSlot", json!({ "n": i + 1 })), kind: FieldKind::Select { options: options.clone() }, hint: None, value: chosen });
        }
    }
    form.push(Field { id: "role_id".into(), label: Text::raw("role_id"), kind: FieldKind::Text, hint: Some(k("hashicorp.approleHint")), value: None });
    form.push(Field { id: "secret_id".into(), label: Text::raw("secret_id"), kind: FieldKind::Secret, hint: Some(k(if link.is_some() { "hc.keepEmpty" } else { "hashicorp.optional" })), value: None });
    form.push(Field { id: "namespace".into(), label: k("hashicorp.namespace"), kind: FieldKind::Text, hint: Some(k("hashicorp.namespaceHint")), value: None });
    Page {
        title: if link.is_some() { k("hc.editTitle") } else { k("hc.connectTitle") }.into(),
        subtitle: Some(Text::raw(addr)),
        body: vec![
            Node::Alert { text: k("connect.sharesHint"), tone: Tone::Plain },
            Node::Form { fields: form, submit: Button::labelled(k("connect.finish"), Action::with("connect", json!({ "entry_id": entry_id }))).with_icon("check").primary() },
        ],
        ..Page::default()
    }
}

// -- Issuing -------------------------------------------------------------------------

const TTLS: &[u64] = &[300, 900, 1800, 3600, 14_400, 86_400];

pub fn issue_dialog(policies: &[String]) -> Page {
    let recipients = [(Recipient::Agent, "vault.recipient.agent"), (Recipient::Person, "vault.recipient.person"), (Recipient::Me, "vault.recipient.me")]
        .iter()
        .map(|(r, key)| (serde_json::to_value(r).ok().and_then(|v| v.as_str().map(str::to_string)).expect("a recipient is a word"), k(key)))
        .collect();
    let known = if policies.is_empty() { k("hc.policiesNone") } else { kw("hc.policiesKnown", json!({ "names": policies.join(", ") })) };
    Page {
        title: k("vault.issue").into(),
        body: vec![
            Node::Alert { text: k("vault.defaultPolicy"), tone: Tone::Plain },
            Node::Form {
                fields: vec![
                    Field { id: "recipient".into(), label: k("vault.recipient"), kind: FieldKind::Select { options: recipients }, hint: None, value: None },
                    Field { id: "policies".into(), label: k("vault.policies"), kind: FieldKind::Text, hint: Some(known), value: None },
                    Field { id: "ttl".into(), label: k("hc.ttl"), kind: FieldKind::Select { options: TTLS.iter().map(|s| (s.to_string(), ttl_text(*s))).collect() }, hint: None, value: Some("900".into()) },
                    Field { id: "num_uses".into(), label: k("hc.uses"), kind: FieldKind::Number { min: 0, max: 1000 }, hint: Some(kw("choice.min", json!({ "n": 0 }))), value: Some("0".into()) },
                    Field { id: "wrap".into(), label: k("vault.byWrap"), kind: FieldKind::Toggle, hint: Some(k("hc.wrapHint")), value: Some("false".into()) },
                    Field { id: "wide_ok".into(), label: k("hc.wide"), kind: FieldKind::Toggle, hint: Some(k("hc.wideHint")), value: Some("false".into()) },
                    Field { id: "note".into(), label: k("vault.note"), kind: FieldKind::Text, hint: None, value: None },
                ],
                submit: Button::labelled(k("vault.issue"), Action::op("issue")).with_icon("plus").primary(),
            },
        ],
        ..Page::default()
    }
}

fn recipient_word(r: Recipient) -> Text {
    k(match r {
        Recipient::Agent => "vault.recipient.agent",
        Recipient::Person => "vault.recipient.person",
        Recipient::Me => "vault.recipient.me",
    })
}

/// The ledger: what was issued, how long it has, revoking it.
pub fn issued_table(list: &[Issued], now: u64) -> Node {
    let rows = list
        .iter()
        .map(|i| {
            let ends = i.created_at + u64::from(i.ttl_seconds);
            let (state, word, tone) = match i.state {
                IssueState::Active if ends > now => ("active", k("vault.active"), Tone::Ok),
                IssueState::Active | IssueState::Expired => ("expired", k("vault.expired"), Tone::Plain),
                IssueState::Revoked => ("revoked", k("vault.revoked"), Tone::Bad),
            };
            let mut row = TableRow::new(i.accessor.clone())
                .cell("note", Cell::Text { text: if i.note.is_empty() { recipient_word(i.recipient) } else { Text::raw(&i.note) } })
                .cell("policies", Cell::Text { text: Text::raw(i.policies.join(", ")) })
                .cell("ends", Cell::Ago { at: ends })
                .cell("state", Cell::Chip { chip: Chip::state(word, tone) })
                .facet("state", Some(state))
                .sort("ends", ends);
            if state == "active" {
                row = row.action(Button::icon("close", k("vault.revoke"), Action::with("revoke", json!({ "accessor": i.accessor })).pressed_twice()).tone(Tone::Bad));
            }
            row
        })
        .collect();
    Node::Table {
        id: "hashicorp|issued".into(),
        columns: vec![
            Column { id: "note".into(), title: k("vault.note"), sortable: true, mono: false },
            Column { id: "policies".into(), title: k("vault.policies"), sortable: true, mono: true },
            Column { id: "ends".into(), title: k("hc.ends"), sortable: true, mono: false },
            Column { id: "state".into(), title: k("hc.state"), sortable: true, mono: false },
        ],
        facets: vec![Facet { id: "state".into(), title: k("hc.state"), icon: "state".into() }],
        rows,
        empty: Some(k("vault.noIssues")),
    }
}

// -- Secrets ----------------------------------------------------------------------------

fn kv(mounts: &[Mount]) -> Vec<&Mount> {
    mounts.iter().filter(|m| !m.auth && (m.kind == "kv" || m.kind == "generic")).collect()
}

pub fn mounts_table(mounts: &[Mount]) -> Node {
    let rows = kv(mounts)
        .into_iter()
        .map(|m| {
            TableRow::new(m.path.clone())
                .cell("path", Cell::Text { text: Text::raw(&m.path) })
                .cell("kind", Cell::Chip { chip: Chip::new(Text::raw(if m.kv2 { "kv v2" } else { "kv v1" })) })
                .cell("description", if m.description.is_empty() { Cell::Empty } else { Cell::Text { text: Text::raw(&m.description) } })
                .open(Action::with("dir", json!({ "mount": m.path, "path": "" })))
        })
        .collect();
    Node::Table {
        id: "hashicorp|kv".into(),
        columns: vec![
            Column { id: "path".into(), title: k("secret.engine"), sortable: true, mono: true },
            Column { id: "kind".into(), title: k("engine.type"), sortable: true, mono: false },
            Column { id: "description".into(), title: k("engine.description"), sortable: false, mono: false },
        ],
        facets: Vec::new(),
        rows,
        empty: Some(k("secret.noMountsHint")),
    }
}

/// The folder above a path ("" at the engine's root).
fn parent(path: &str) -> String {
    broker::parent_of(path)
}

/// A folder of an engine: its folders and its secrets.
pub fn dir_page(mount: &str, path: &str, entries: &[String]) -> Page {
    let rows: Vec<ListRow> = entries
        .iter()
        .map(|e| {
            let full = format!("{path}{e}");
            let folder = e.ends_with('/');
            let mut r = ListRow::new(full.clone(), if folder { "folder" } else { "key" }, Text::raw(e.trim_end_matches('/')));
            r.mono = true;
            r.open = Some(if folder { Action::with("dir", json!({ "mount": mount, "path": full })) } else { Action::with("secret", json!({ "mount": mount, "path": full })) });
            r
        })
        .collect();
    let body = if rows.is_empty() { vec![Node::Empty { icon: "folder".into(), title: k("secret.empty"), body: Some(k("secret.emptyHint")) }] } else { vec![Node::List { rows }] };
    Page {
        title: Some(Text::raw(format!("{mount}{path}"))),
        icon: Some("folder".into()),
        subtitle: Some(kw("secret.count", json!({ "n": entries.len() }))),
        crumb: (!path.is_empty()).then(|| Crumb { label: k("secret.folder"), action: Action::with("dir", json!({ "mount": mount, "path": parent(path) })) }),
        actions: vec![Button::labelled(k("secret.new"), Action::with("secret_new", json!({ "mount": mount, "path": path }))).with_icon("plus")],
        body,
        ..Page::default()
    }
}

/// A secret: its keys and how long each value is, copied through the core;
/// for kv v2 its versions and metadata. No value is in it.
pub fn secret_page(view: &SecretView, meta: Option<&SecretMeta>, kv2: bool) -> Page {
    let at = json!({ "mount": view.mount, "path": view.path, "version": view.version });
    let fields = if view.fields.is_empty() {
        vec![Node::Empty { icon: "key".into(), title: k("secret.noFields"), body: None }]
    } else {
        vec![Node::List {
            rows: view
                .fields
                .iter()
                .map(|f| {
                    let mut r = ListRow::new(f.key.clone(), "key", Text::raw(&f.key));
                    r.mono = true;
                    r.subtitle = Some(Text::raw("•".repeat(f.length.clamp(4, 24))));
                    let mut copy = at.clone();
                    copy["key"] = json!(f.key);
                    r.actions.push(Button::icon("copy", k("hc.copy"), Action::with("copy", copy.clone())));
                    let mut drop = copy;
                    drop["cas"] = json!(view.version);
                    r.actions.push(Button::icon("trash", k("secret.removeField"), Action::with("remove_key", drop).pressed_twice()).tone(Tone::Bad));
                    r
                })
                .collect(),
        }]
    };
    let mut body = vec![Node::Section { title: kw("secret.fieldsCount", json!({ "n": view.fields.len() })), icon: "key".into(), tone: Tone::Plain, count: None, folded: false, hint: None, body: fields }];
    if let Some(m) = meta {
        let current = m.current_version;
        let rows = m
            .versions
            .iter()
            .rev()
            .map(|v| {
                let mut r = ListRow::new(v.version.to_string(), "clock", Text::raw(format!("v{}", v.version)));
                r.subtitle = v.created.clone().map(Text::raw);
                let pin = json!({ "mount": m.mount, "path": m.path, "version": v.version });
                if v.destroyed {
                    r.chips.push(Chip::state(k("secret.state.destroyed"), Tone::Bad));
                } else if v.deleted.is_some() {
                    r.chips.push(Chip::state(k("secret.state.deleted"), Tone::Warn));
                    r.actions.push(Button::icon("undo", k("secret.undelete"), Action::with("undelete", pin.clone())));
                } else if v.version == current {
                    r.chips.push(Chip::state(k("secret.state.current"), Tone::Ok));
                } else {
                    r.actions.push(Button::icon("undo", kw("secret.rollback", json!({ "v": v.version })), Action::with("rollback", json!({ "mount": m.mount, "path": m.path, "version": v.version, "cas": current })).pressed_twice()));
                }
                if !v.destroyed {
                    r.actions.push(Button::icon("trash", kw("secret.destroyVersion", json!({ "v": v.version })), Action::with("destroy", pin).pressed_twice()).tone(Tone::Bad));
                }
                r
            })
            .collect();
        body.push(Node::Section { title: kw("secret.versions", json!({ "n": m.versions.len() })), icon: "clock".into(), tone: Tone::Plain, count: None, folded: false, hint: None, body: vec![Node::List { rows }] });
        body.push(Node::Section {
            title: k("secret.metadata"),
            icon: "tune".into(),
            tone: Tone::Plain,
            count: None,
            folded: true,
            hint: None,
            body: vec![Node::Form {
                fields: vec![
                    Field { id: "max_versions".into(), label: k("secret.maxVersions"), kind: FieldKind::Number { min: 0, max: 10_000 }, hint: Some(k("secret.maxVersionsHint")), value: Some(m.max_versions.to_string()) },
                    Field { id: "cas_required".into(), label: k("secret.casRequired"), kind: FieldKind::Toggle, hint: Some(k("secret.casRequiredHint")), value: Some(m.cas_required.to_string()) },
                    Field { id: "delete_version_after".into(), label: k("secret.deleteAfter"), kind: FieldKind::Text, hint: Some(k("secret.deleteAfterHint")), value: Some(m.delete_version_after.clone()) },
                ],
                submit: Button::labelled(k("hc.save"), Action::with("meta_save", json!({ "mount": m.mount, "path": m.path }))).with_icon("check"),
            }],
        });
    }
    body.push(Node::Danger {
        title: k("secret.delete"),
        hint: k(if kv2 { "secret.deleteZoneV2" } else { "secret.deleteZoneV1" }),
        button: Button::labelled(k("secret.delete"), Action::with("secret_delete", json!({ "mount": view.mount, "path": view.path, "permanent": !kv2 })).confirmed_by(&view.path)).with_icon("trash").tone(Tone::Bad),
    });
    if kv2 {
        body.push(Node::Danger {
            title: k("secret.purge"),
            hint: k("secret.purgeZone"),
            button: Button::labelled(k("secret.purge"), Action::with("secret_delete", json!({ "mount": view.mount, "path": view.path, "permanent": true })).confirmed_by(&view.path)).with_icon("trash").tone(Tone::Bad),
        });
    }
    let mut subtitle = view.mount.clone();
    if let Some(v) = view.version {
        subtitle = format!("{subtitle} · v{v}");
    }
    Page {
        title: Some(Text::raw(&view.path)),
        icon: Some("key".into()),
        subtitle: Some(Text::raw(subtitle)),
        crumb: Some(Crumb { label: k("secret.folder"), action: Action::with("dir", json!({ "mount": view.mount, "path": parent(&view.path) })) }),
        actions: vec![Button::icon("edit", k("secret.edit"), Action::with("secret_edit", json!({ "mount": view.mount, "path": view.path })))],
        body,
        ..Page::default()
    }
}

/// Changing a secret: each value typed anew or left empty to stay, and a key
/// to add. The values are never filled back into the form.
pub fn secret_edit(view: &SecretView, kv2: bool) -> Page {
    let mut fields: Vec<Field> = view.fields.iter().map(|f| Field { id: format!("value:{}", f.key), label: Text::raw(&f.key), kind: FieldKind::Secret, hint: Some(k("hc.keepEmpty")), value: None }).collect();
    fields.push(Field { id: "new_key".into(), label: k("secret.addField"), kind: FieldKind::Text, hint: None, value: None });
    fields.push(Field { id: "new_value".into(), label: k("secret.value"), kind: FieldKind::Secret, hint: None, value: None });
    Page {
        title: Some(Text::raw(&view.path)),
        subtitle: Some(k(if kv2 { "secret.writeHintV2" } else { "secret.writeHintV1" })),
        body: vec![Node::Form { fields, submit: Button::labelled(k("hc.save"), Action::with("secret_write", json!({ "mount": view.mount, "path": view.path, "version": view.version }))).with_icon("check").primary() }],
        ..Page::default()
    }
}

/// A new secret in a folder: its path, its first key and value.
pub fn secret_new(mount: &str, path: &str) -> Page {
    Page {
        title: k("secret.newTitle").into(),
        subtitle: Some(Text::raw(format!("{mount}{path}"))),
        body: vec![Node::Form {
            fields: vec![
                Field { id: "path".into(), label: k("secret.path"), kind: FieldKind::Text, hint: Some(k("secret.pathHint")), value: Some(path.to_string()) },
                Field { id: "new_key".into(), label: k("secret.key"), kind: FieldKind::Text, hint: None, value: None },
                Field { id: "new_value".into(), label: k("secret.value"), kind: FieldKind::Secret, hint: None, value: None },
            ],
            submit: Button::labelled(k("secret.create"), Action::with("secret_create", json!({ "mount": mount }))).with_icon("plus").primary(),
        }],
        ..Page::default()
    }
}

// -- Engines --------------------------------------------------------------------------------

fn mount_rows(mounts: &[&Mount]) -> Vec<TableRow> {
    mounts
        .iter()
        .map(|m| {
            TableRow::new(m.path.clone())
                .cell("path", Cell::Text { text: Text::raw(&m.path) })
                .cell("kind", Cell::Chip { chip: Chip::new(Text::raw(if m.kind == "kv" { if m.kv2 { "kv v2".to_string() } else { "kv v1".to_string() } } else { m.kind.clone() })) })
                .cell("description", if m.description.is_empty() { Cell::Empty } else { Cell::Text { text: Text::raw(&m.description) } })
                .open(Action::with("mount", json!({ "path": m.path, "auth": m.auth })))
        })
        .collect()
}

fn mount_columns() -> Vec<Column> {
    vec![
        Column { id: "path".into(), title: k("engine.path"), sortable: true, mono: true },
        Column { id: "kind".into(), title: k("engine.type"), sortable: true, mono: false },
        Column { id: "description".into(), title: k("engine.description"), sortable: false, mono: false },
    ]
}

pub fn engines_body(secrets: &[Mount], auth: &[Mount]) -> Vec<Node> {
    let s: Vec<&Mount> = secrets.iter().filter(|m| !m.auth).collect();
    let a: Vec<&Mount> = auth.iter().collect();
    vec![
        Node::Section {
            title: k("engine.secrets"),
            icon: "stack".into(),
            tone: Tone::Plain,
            count: Some(s.len()),
            folded: false,
            hint: None,
            body: vec![
                Node::Actions { buttons: vec![Button::labelled(k("engine.enable"), Action::with("enable_dialog", json!({ "auth": false }))).with_icon("plus")] },
                Node::Table { id: "hashicorp|engines".into(), columns: mount_columns(), facets: Vec::new(), rows: mount_rows(&s), empty: Some(k("engine.noneHint")) },
            ],
        },
        Node::Section {
            title: k("engine.auth"),
            icon: "login".into(),
            tone: Tone::Plain,
            count: Some(a.len()),
            folded: false,
            hint: None,
            body: vec![
                Node::Actions { buttons: vec![Button::labelled(k("engine.enableAuth"), Action::with("enable_dialog", json!({ "auth": true }))).with_icon("plus")] },
                Node::Table { id: "hashicorp|auth".into(), columns: mount_columns(), facets: Vec::new(), rows: mount_rows(&a), empty: Some(k("engine.noneAuthHint")) },
            ],
        },
    ]
}

fn secs_field(id: &str, label: &str, secs: u64) -> Field {
    Field { id: id.into(), label: k(label), kind: FieldKind::Text, hint: Some(k("engine.ttlHint")), value: Some(if secs == 0 { String::new() } else { format!("{}s", secs) }) }
}

/// An engine's drawer: what it is, its leases, kv v2's own settings,
/// upgrading kv v1, disabling it.
pub fn mount_page(m: &Mount, cfg: Option<&KvConfig>) -> Page {
    let at = json!({ "path": m.path, "auth": m.auth });
    let mut body = vec![Node::Section {
        title: k("engine.tune"),
        icon: "tune".into(),
        tone: Tone::Plain,
        count: None,
        folded: false,
        hint: None,
        body: vec![Node::Form {
            fields: vec![
                Field { id: "description".into(), label: k("engine.description"), kind: FieldKind::Text, hint: None, value: Some(m.description.clone()) },
                secs_field("default_lease_ttl", "engine.defaultTtl", m.default_lease_ttl),
                secs_field("max_lease_ttl", "engine.maxTtl", m.max_lease_ttl),
            ],
            submit: Button::labelled(k("hc.save"), Action::with("mount_tune", at.clone())).with_icon("check"),
        }],
    }];
    if let Some(c) = cfg {
        body.push(Node::Section {
            title: k("engine.kvConfig"),
            icon: "clock".into(),
            tone: Tone::Plain,
            count: None,
            folded: false,
            hint: None,
            body: vec![Node::Form {
                fields: vec![
                    Field { id: "max_versions".into(), label: k("secret.maxVersions"), kind: FieldKind::Number { min: 0, max: 10_000 }, hint: Some(k("engine.maxVersionsHint")), value: Some(c.max_versions.to_string()) },
                    Field { id: "cas_required".into(), label: k("secret.casRequired"), kind: FieldKind::Toggle, hint: Some(k("engine.casHint")), value: Some(c.cas_required.to_string()) },
                    Field { id: "delete_version_after".into(), label: k("secret.deleteAfter"), kind: FieldKind::Text, hint: Some(k("secret.deleteAfterHint")), value: Some(c.delete_version_after.clone()) },
                ],
                submit: Button::labelled(k("hc.save"), Action::with("kv_config_write", json!({ "mount": m.path }))).with_icon("check"),
            }],
        });
    }
    if m.kind == "kv" && !m.kv2 && !m.auth {
        body.push(Node::Danger { title: k("engine.upgradeTitle"), hint: k("engine.upgradeConfirm"), button: Button::labelled(k("engine.upgrade"), Action::with("mount_upgrade", json!({ "path": m.path })).confirmed_by(&m.path)).with_icon("undo").tone(Tone::Bad) });
    }
    if m.kind != "token" {
        body.push(Node::Danger {
            title: kw("engine.disableTitle", json!({ "p": m.path })),
            hint: k(if m.auth { "engine.disableAuthConfirm" } else { "engine.disableConfirm" }),
            button: Button::labelled(k("engine.disable"), Action::with("mount_disable", at).confirmed_by(&m.path)).with_icon("trash").tone(Tone::Bad),
        });
    }
    Page { title: Some(Text::raw(&m.path)), icon: Some(if m.auth { "login" } else { "stack" }.into()), subtitle: Some(Text::raw(&m.kind)), body, ..Page::default() }
}

pub fn enable_dialog(auth: bool) -> Page {
    let mut fields = vec![
        Field { id: "path".into(), label: k("engine.path"), kind: FieldKind::Text, hint: Some(k(if auth { "engine.pathHintAuth" } else { "engine.pathHint" })), value: None },
        Field { id: "kind".into(), label: k("engine.type"), kind: FieldKind::Text, hint: Some(k(if auth { "hc.kindHintAuth" } else { "hc.kindHint" })), value: Some(if auth { "approle" } else { "kv" }.into()) },
        Field { id: "description".into(), label: k("engine.description"), kind: FieldKind::Text, hint: None, value: None },
    ];
    if !auth {
        fields.push(Field { id: "kv_version".into(), label: k("engine.kvVersion"), kind: FieldKind::Select { options: vec![("2".into(), Text::raw("kv v2")), ("1".into(), Text::raw("kv v1"))] }, hint: Some(k("engine.kvV2Hint")), value: Some("2".into()) });
    }
    fields.push(Field { id: "default_lease_ttl".into(), label: k("engine.defaultTtl"), kind: FieldKind::Text, hint: Some(k("engine.ttlHint")), value: None });
    fields.push(Field { id: "max_lease_ttl".into(), label: k("engine.maxTtl"), kind: FieldKind::Text, hint: Some(k("engine.maxTtlHint")), value: None });
    Page {
        title: k(if auth { "engine.enableAuth" } else { "engine.enable" }).into(),
        body: vec![Node::Form { fields, submit: Button::labelled(k("engine.enableDo"), Action::with("mount_enable", json!({ "auth": auth }))).with_icon("plus").primary() }],
        ..Page::default()
    }
}

// -- Policies --------------------------------------------------------------------------------

pub fn policies_body(names: &[String]) -> Vec<Node> {
    let rows = names
        .iter()
        .map(|n| {
            let builtin = n == "root" || n == "default";
            let mut row = TableRow::new(n.clone()).cell("name", Cell::Text { text: Text::raw(n) });
            row = row.cell("kind", if builtin { Cell::Chip { chip: Chip::new(k("policy.builtin")) } } else if crate::model::is_wide(n) { Cell::Chip { chip: Chip::state(k("policy.wideRow"), Tone::Warn) } } else { Cell::Empty });
            if n != "root" {
                row = row.open(Action::with("policy", json!({ "name": n })));
            }
            row
        })
        .collect();
    vec![
        Node::Alert { text: k("policy.what"), tone: Tone::Plain },
        Node::Actions {
            buttons: vec![
                Button::labelled(k("policy.add"), Action::op("policy_new")).with_icon("plus"),
                Button::labelled(k("policy.admin"), Action::op("ensure_policy_admin")).with_icon("policy"),
            ],
        },
        Node::Table {
            id: "hashicorp|policies".into(),
            columns: vec![Column { id: "name".into(), title: k("hc.policy"), sortable: true, mono: true }, Column { id: "kind".into(), title: k("engine.type"), sortable: true, mono: false }],
            facets: Vec::new(),
            rows,
            empty: Some(k("hc.policiesNone")),
        },
    ]
}

/// A policy in the checked editor: what changes is shown before it is
/// written; deleting it in the danger zone, by its name.
pub fn policy_page(name: &str, rules: &str, exists: bool) -> Page {
    let at = json!({ "name": name });
    let mut body = vec![Node::Editor { text: rules.to_string(), check: Action::with("policy_check", at.clone()), apply: Action::with("policy_apply", at.clone()) }];
    if exists && name != "default" && name != POLICY_ADMIN {
        body.push(Node::Danger { title: kw("policy.deleteTitle", json!({ "name": name })), hint: k("policy.deleteConfirm"), button: Button::labelled(k("policy.delete"), Action::with("policy_delete", at).confirmed_by(name)).with_icon("trash").tone(Tone::Bad) });
    }
    Page { title: Some(kw("policy.editTitle", json!({ "name": name }))), body, ..Page::default() }
}

pub fn policy_new() -> Page {
    Page {
        title: k("policy.add").into(),
        body: vec![Node::Form {
            fields: vec![Field { id: "name".into(), label: k("hc.policy"), kind: FieldKind::Text, hint: Some(k("hc.policyNameHint")), value: None }],
            submit: Button::labelled(k("step.next"), Action::op("policy_create")).with_icon("chev").primary(),
        }],
        ..Page::default()
    }
}

// -- Root tokens ------------------------------------------------------------------------------

pub fn roots_body(l: &Link, tokens: &[RootToken]) -> Vec<Node> {
    let mine: Vec<&RootToken> = tokens.iter().filter(|t| t.addr.trim_end_matches('/') == l.addr.trim_end_matches('/')).collect();
    let mut body = vec![Node::Alert { text: k("root.warn"), tone: Tone::Warn }];
    if mine.is_empty() {
        let generate = if l.unseal_fields.is_empty() {
            Button::labelled(k("connect.generate"), Action::op("ui_generate_root")).with_icon("shield").disabled(true)
        } else {
            Button::labelled(k("connect.generate"), Action::with("ui_generate_root", json!({ "entry_id": l.entry_id, "fields": l.unseal_fields })).filled(&l.entry_id, l.unseal_fields.clone(), "shares")).with_icon("shield")
        };
        body.push(Node::Empty { icon: "shield".into(), title: k("root.none"), body: Some(kw("root.noneHint", json!({ "addr": l.addr }))) });
        body.push(Node::Actions { buttons: vec![generate] });
        if l.unseal_fields.is_empty() {
            body.push(Node::Alert { text: k("hc.rootNeedsShares"), tone: Tone::Plain });
        }
        return body;
    }
    let rows = mine
        .iter()
        .map(|t| {
            let mut r = ListRow::new(t.addr.clone(), "shield", Text::raw(&t.addr));
            r.mono = true;
            if t.issued_at == 0 {
                r.subtitle = Some(k("root.issuedUnknown"));
            }
            if t.issued_at > 0 {
                r.at = Some(t.issued_at);
            }
            r.tone = if t.info.is_some() { Tone::Warn } else { Tone::Plain };
            r.chips.push(if t.info.is_some() { Chip::state(k("root.alive"), Tone::Warn) } else { Chip::state(k("root.dead"), Tone::Plain) });
            r
        })
        .collect();
    body.push(Node::List { rows });
    body.push(Node::Danger {
        title: k("root.revokeTitle"),
        hint: kw("root.revokeBody", json!({ "addr": l.addr })),
        button: Button::labelled(k("root.revoke"), Action::with("revoke_root", json!({ "addr": l.addr })).confirmed_by(host_of(&l.addr))).with_icon("trash").tone(Tone::Bad),
    });
    body
}

fn host_of(addr: &str) -> String {
    addr.trim_start_matches("https://").trim_start_matches("http://").trim_end_matches('/').to_string()
}

// -- What a form sends --------------------------------------------------------------------------

fn form_of(form: Value) -> anyhow::Result<BTreeMap<String, String>> {
    if form.is_null() {
        return Ok(BTreeMap::new());
    }
    serde_json::from_value(form).map_err(|e| anyhow::anyhow!("a form came with something other than text: {e}"))
}

fn arg<T: serde::de::DeserializeOwned>(v: Value) -> anyhow::Result<T> {
    serde_json::from_value(v).map_err(|e| anyhow::anyhow!("an action came with something else: {e}"))
}

fn flag(form: &BTreeMap<String, String>, id: &str) -> anyhow::Result<bool> {
    match form.get(id).map(String::as_str) {
        Some("true") => Ok(true),
        Some("false") | None => Ok(false),
        Some(other) => anyhow::bail!("the switch \"{id}\" came as \"{other}\""),
    }
}

fn number(form: &BTreeMap<String, String>, id: &str) -> anyhow::Result<Option<u64>> {
    match form.get(id).map(|s| s.trim()) {
        None | Some("") => Ok(None),
        Some(v) => v.parse().map(Some).map_err(|_| anyhow::anyhow!(crate::model::key("err.numberField", &[("field", id)]))),
    }
}

/// What the issue form asks of Vault.
pub fn issue_request(form: &BTreeMap<String, String>) -> anyhow::Result<IssueRequest> {
    let recipient: Recipient = serde_json::from_value(Value::String(form.get("recipient").cloned().unwrap_or_default())).map_err(|_| anyhow::anyhow!("the issue form came with no recipient"))?;
    let policies: Vec<String> = form.get("policies").map(|p| p.split(',').map(str::trim).filter(|p| !p.is_empty()).map(str::to_string).collect()).unwrap_or_default();
    let ttl = number(form, "ttl")?.ok_or_else(|| anyhow::anyhow!("err.ttlRequired"))?;
    Ok(IssueRequest {
        recipient,
        policies,
        ttl_seconds: u32::try_from(ttl).map_err(|_| anyhow::anyhow!("err.ttlOverADay"))?,
        num_uses: u32::try_from(number(form, "num_uses")?.unwrap_or(0)).map_err(|_| anyhow::anyhow!(crate::model::key("err.numberField", &[("field", "num_uses")])))?,
        wrap: flag(form, "wrap")?,
        note: form.get("note").cloned().unwrap_or_default().trim().to_string(),
        wide_ok: flag(form, "wide_ok")?,
    })
}

/// A secret's data with the form laid over it: a value typed replaces one,
/// an empty one stays, a new key is added.
pub fn edited(mut data: BTreeMap<String, String>, form: &BTreeMap<String, String>) -> anyhow::Result<BTreeMap<String, String>> {
    for (id, v) in form {
        if let Some(key) = id.strip_prefix("value:") {
            anyhow::ensure!(data.contains_key(key), "the secret has no key \"{key}\"");
            if !v.is_empty() {
                data.insert(key.to_string(), v.clone());
            }
        }
    }
    let key = form.get("new_key").map(|s| s.trim().to_string()).unwrap_or_default();
    let value = form.get("new_value").cloned().unwrap_or_default();
    match (key.is_empty(), value.is_empty()) {
        (true, true) => {}
        (true, false) => anyhow::bail!("err.fieldNeedsName"),
        (false, _) => {
            data.insert(key, value);
        }
    }
    Ok(data)
}

fn ttl_of(form: &BTreeMap<String, String>, id: &str) -> String {
    form.get(id).map(|s| s.trim().to_string()).unwrap_or_default()
}

fn body(nodes: Vec<Node>) -> anyhow::Result<Reply> {
    Reply::data(json!({ "body": nodes }))
}

fn toast(key: &str) -> Reply {
    Reply { toast: Some(k(key)), refresh: true, ..Reply::default() }
}

fn said(e: &anyhow::Error) -> Text {
    let s = e.to_string();
    match s.split_once(' ') {
        Some((key, args)) if key.starts_with("err.") => serde_json::from_str::<Value>(args).map(|a| Text::key_with(key, a)).unwrap_or_else(|_| Text::raw(&s)),
        None if s.starts_with("err.") => k(&s),
        _ => Text::raw(&s),
    }
}

#[derive(Deserialize)]
struct EntryArg {
    entry_id: String,
}

#[derive(Deserialize)]
struct NoteArg {
    addr: String,
    #[serde(default)]
    needed: u32,
}

#[derive(Deserialize)]
struct At {
    mount: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    version: Option<u64>,
}

#[derive(Deserialize)]
struct KeyAt {
    mount: String,
    path: String,
    #[serde(default)]
    version: Option<u64>,
    key: String,
    #[serde(default)]
    cas: Option<u64>,
}

#[derive(Deserialize)]
struct Pin {
    mount: String,
    path: String,
    version: u64,
    #[serde(default)]
    cas: Option<u64>,
}

#[derive(Deserialize)]
struct MountAt {
    path: String,
    #[serde(default)]
    auth: bool,
}

#[derive(Deserialize)]
struct Named {
    name: String,
}

/// The connection in use, or why there is none.
async fn in_use(host: &dyn Host) -> anyhow::Result<Link> {
    store::connection(host).await.ok_or_else(|| anyhow::anyhow!("{}", store::why_no_credentials(host)))
}

async fn kv2_of(host: &dyn Host, mount: &str) -> anyhow::Result<bool> {
    Ok(broker::mounts(host).await?.into_iter().find(|m| m.path == mount).map(|m| m.kv2).ok_or_else(|| anyhow::anyhow!("err.noSuchMount"))?)
}

async fn secret_reply(host: &dyn Host, mount: &str, path: &str, version: Option<u64>) -> anyhow::Result<Reply> {
    let kv2 = kv2_of(host, mount).await?;
    let view = broker::secret_read(host, mount, path, version).await?.view();
    let meta = if kv2 { Some(broker::secret_meta(host, mount, path).await?) } else { None };
    Ok(Reply::drawer(secret_page(&view, meta.as_ref(), kv2)))
}

async fn dir_reply(host: &dyn Host, mount: &str, path: &str) -> anyhow::Result<Reply> {
    let entries = broker::secret_list(host, mount, path).await?;
    Ok(Reply::drawer(dir_page(mount, path, &entries)))
}

impl HashicorpPlugin {
    /// The plain operations an action filled by the daemon comes to: they
    /// answer as the sealed road does, with a `Reply`.
    pub(crate) async fn filled(&self, host: &dyn Host, op: &str, payload: Value) -> anyhow::Result<Value> {
        #[derive(Deserialize)]
        struct Shares {
            #[serde(default)]
            shares: Vec<String>,
        }
        #[derive(Deserialize)]
        struct Root {
            entry_id: String,
            fields: Vec<String>,
            #[serde(default)]
            shares: Vec<String>,
        }
        let reply = match op {
            "ui_unseal" => {
                let a: Shares = arg(payload)?;
                let s = broker::unseal(host, &a.shares).await?;
                Reply { toast: Some(if s.sealed { kw("vault.sealedBody", json!({ "p": s.progress, "t": s.t })) } else { k("hc.unsealedDone") }), refresh: true, ..Reply::default() }
            }
            "ui_generate_root" => {
                let a: Root = arg(payload)?;
                broker::generate_root(host, &a.entry_id, &a.fields, &a.shares).await?;
                toast("connect.rootDone")
            }
            other => anyhow::bail!("the hashicorp plugin fills in nothing for \"{other}\""),
        };
        Ok(serde_json::to_value(reply)?)
    }
}

#[async_trait::async_trait]
impl keyward_ui::Ui for HashicorpPlugin {
    async fn places(&self, host: &dyn Host) -> anyhow::Result<Places> {
        let links = store::connections(host).await;
        let active = store::connection(host).await.map(|l| l.entry_id);
        Ok(declare(&links, active.as_deref()))
    }

    async fn view(&self, host: &dyn Host, route: &str) -> anyhow::Result<Page> {
        let links = store::connections(host).await;
        let active = store::connection(host).await.map(|l| l.entry_id);
        if route.is_empty() {
            return Ok(overview(&links, active.as_deref()));
        }
        if route == "settings" {
            return Ok(settings_page(store::expiry_notices(host)));
        }
        let id = route.strip_prefix("conn/").ok_or_else(|| anyhow::anyhow!("the hashicorp plugin has no screen \"{route}\""))?;
        let link = links.iter().find(|l| l.entry_id == id).ok_or_else(|| anyhow::anyhow!("err.connectionItemMissing"))?;
        if active.as_deref() != Some(id) {
            return Ok(not_in_use(link));
        }
        let health = broker::health(host).await;
        let seal = broker::seal_status(host).await.ok();
        Ok(console(link, health.as_ref().map_err(said), seal.as_ref()))
    }

    async fn act(&self, host: &dyn Host, op: &str, payload: Value, form: Value) -> anyhow::Result<Reply> {
        let form = form_of(form)?;
        let field = |id: &str| form.get(id).map(|s| s.trim().to_string()).unwrap_or_default();
        match op {
            "refresh" => Ok(Reply::refresh()),
            "go" => Ok(Reply::go(payload.get("route").and_then(Value::as_str).unwrap_or_default())),
            "save_settings" => {
                store::set_settings(host, json!({ "expiry_notices": flag(&form, "expiry_notices")? }))?;
                Ok(Reply { toast: Some(k("hc.saved")), ..Reply::default() })
            }
            "use" => {
                let a: EntryArg = arg(payload)?;
                store::set_active(host, &a.entry_id)?;
                Ok(Reply { refresh: true, ..Reply::go(conn_route(&a.entry_id)) })
            }
            "forget" => {
                let a: EntryArg = arg(payload)?;
                store::forget(host, &a.entry_id).await?;
                Ok(Reply { refresh: true, toast: Some(k("hc.forgotten")), ..Reply::go("") })
            }
            // -- connecting --
            "connect_dialog" => Ok(Reply::dialog(connect_address())),
            "probe" => {
                let addr = field("addr");
                Form { addr: addr.clone(), ..Form::default() }.validate().map_err(|e| anyhow::anyhow!("{e}"))?;
                let seal = broker::probe(&addr).await?;
                Ok(Reply::dialog(connect_note(&addr, &seal)))
            }
            "note_chosen" => {
                let a: NoteArg = arg(payload)?;
                let entry = field("entry_id");
                anyhow::ensure!(!entry.is_empty(), "err.chooseNoteForConnection");
                let fields = host.note_fields(&entry).await?;
                Ok(Reply::dialog(connect_fields(&a.addr, &entry, &fields, a.needed, None)))
            }
            "edit_dialog" => {
                let l = in_use(host).await?;
                let fields = host.note_fields(&l.entry_id).await?;
                let needed = broker::seal_status(host).await.map(|s| s.t).unwrap_or(0);
                Ok(Reply::dialog(connect_fields(&l.addr, &l.entry_id, &fields, needed, Some(&l))))
            }
            "connect" => {
                let a: EntryArg = arg(payload)?;
                let shares: Vec<String> = form.iter().filter(|(id, _)| id.starts_with("share")).map(|(_, v)| v.clone()).filter(|v| !v.is_empty()).collect();
                let f = Form { name: String::new(), entry_id: Some(a.entry_id.clone()), addr: field("addr"), unseal_fields: shares, role_id: field("role_id"), secret_id: form.get("secret_id").cloned().unwrap_or_default(), namespace: field("namespace") };
                store::connect(host, &f).await?;
                store::set_active(host, &a.entry_id)?;
                Ok(Reply { close_dialog: true, refresh: true, toast: Some(k("hc.connected")), ..Reply::go(conn_route(&a.entry_id)) })
            }
            "unseal_stored" => {
                let s = broker::unseal(host, &[]).await?;
                Ok(Reply { toast: Some(if s.sealed { kw("vault.sealedBody", json!({ "p": s.progress, "t": s.t })) } else { k("hc.unsealedDone") }), refresh: true, ..Reply::default() })
            }
            // -- issuing --
            "issue_dialog" => Ok(Reply::dialog(issue_dialog(&broker::policies(host).await.unwrap_or_default()))),
            "issue" => {
                let req = issue_request(&form)?;
                req.validate().map_err(|e| anyhow::anyhow!("{e}"))?;
                let r = broker::issue(host, &req).await?;
                // The token is shown nowhere: it goes to the clipboard, cleared
                // on time, and lives nowhere else.
                let (token, key) = match (&r.wrapping_token, &r.token) {
                    (Some(w), _) => (w.clone(), "hc.copiedWrap"),
                    (None, Some(t)) => (t.clone(), "hc.copiedToken"),
                    (None, None) => anyhow::bail!("err.issueNoToken"),
                };
                let clears = host.copy_text(&token).await?;
                Ok(Reply { close_dialog: true, refresh: true, toast: Some(kw(key, json!({ "n": clears }))), ..Reply::default() })
            }
            "issued_body" => body(vec![issued_table(&broker::refresh_expired(host).await, crate::api::now_secs())]),
            "revoke" => {
                let accessor = payload.get("accessor").and_then(Value::as_str).ok_or_else(|| anyhow::anyhow!("a revocation with no accessor"))?;
                broker::revoke(host, accessor).await?;
                Ok(toast("hc.revoked"))
            }
            // -- secrets --
            "mounts_body" => body(vec![mounts_table(&broker::mounts(host).await?)]),
            "dir" => {
                let a: At = arg(payload)?;
                dir_reply(host, &a.mount, &a.path).await
            }
            "secret" => {
                let a: At = arg(payload)?;
                secret_reply(host, &a.mount, &a.path, a.version).await
            }
            "copy" => {
                let a: KeyAt = arg(payload)?;
                let s = broker::secret_read(host, &a.mount, &a.path, a.version).await?;
                let v = s.data.get(&a.key).ok_or_else(|| anyhow::anyhow!("err.secretNoKey"))?;
                let clears = host.copy_text(v).await?;
                Ok(Reply { toast: Some(kw("hc.copied", json!({ "key": a.key, "n": clears }))), ..Reply::default() })
            }
            "remove_key" => {
                let a: KeyAt = arg(payload)?;
                let mut s = broker::secret_read(host, &a.mount, &a.path, None).await?;
                anyhow::ensure!(s.data.remove(&a.key).is_some(), "err.secretNoKey");
                broker::secret_write(host, &a.mount, &a.path, &s.data, a.cas).await?;
                let mut r = secret_reply(host, &a.mount, &a.path, None).await?;
                r.toast = Some(k("hc.saved"));
                Ok(r)
            }
            "secret_edit" => {
                let a: At = arg(payload)?;
                let kv2 = kv2_of(host, &a.mount).await?;
                Ok(Reply::dialog(secret_edit(&broker::secret_read(host, &a.mount, &a.path, None).await?.view(), kv2)))
            }
            "secret_write" => {
                let a: At = arg(payload)?;
                let cas = payload_cas(&a);
                let s = broker::secret_read(host, &a.mount, &a.path, None).await?;
                let data = edited(s.data.clone(), &form)?;
                broker::secret_write(host, &a.mount, &a.path, &data, cas).await?;
                let mut r = secret_reply(host, &a.mount, &a.path, None).await?;
                r.close_dialog = true;
                r.toast = Some(k("hc.saved"));
                Ok(r)
            }
            "secret_new" => {
                let a: At = arg(payload)?;
                Ok(Reply::dialog(secret_new(&a.mount, &a.path)))
            }
            "secret_create" => {
                let a: At = arg(payload)?;
                let path = field("path");
                let data = edited(BTreeMap::new(), &form)?;
                broker::secret_write(host, &a.mount, &path, &data, None).await?;
                let mut r = secret_reply(host, &a.mount, &path, None).await?;
                r.close_dialog = true;
                r.toast = Some(k("hc.saved"));
                Ok(r)
            }
            "rollback" => {
                let a: Pin = arg(payload)?;
                let old = broker::secret_read(host, &a.mount, &a.path, Some(a.version)).await?;
                broker::secret_write(host, &a.mount, &a.path, &old.data, a.cas).await?;
                secret_reply(host, &a.mount, &a.path, None).await
            }
            "undelete" => {
                let a: Pin = arg(payload)?;
                broker::secret_undelete(host, &a.mount, &a.path, a.version).await?;
                secret_reply(host, &a.mount, &a.path, None).await
            }
            "destroy" => {
                let a: Pin = arg(payload)?;
                broker::secret_destroy(host, &a.mount, &a.path, a.version).await?;
                secret_reply(host, &a.mount, &a.path, None).await
            }
            "meta_save" => {
                let a: At = arg(payload)?;
                let patch = SecretMetaPatch { max_versions: number(&form, "max_versions")?, cas_required: Some(flag(&form, "cas_required")?), delete_version_after: Some(ttl_of(&form, "delete_version_after")), custom_metadata: None };
                broker::secret_meta_write(host, &a.mount, &a.path, &patch).await?;
                Ok(Reply { toast: Some(k("hc.saved")), ..Reply::default() })
            }
            "secret_delete" => {
                let a: At = arg(payload.clone())?;
                let permanent = payload.get("permanent").and_then(Value::as_bool).unwrap_or(false);
                broker::secret_delete(host, &a.mount, &a.path, permanent).await?;
                let mut r = dir_reply(host, &a.mount, &parent(&a.path)).await?;
                r.toast = Some(k("hc.deleted"));
                Ok(r)
            }
            // -- engines --
            "engines_body" => body(engines_body(&broker::mounts(host).await?, &broker::auth_mounts(host).await?)),
            "mount" => {
                let a: MountAt = arg(payload)?;
                let list = if a.auth { broker::auth_mounts(host).await? } else { broker::mounts(host).await? };
                let m = list.into_iter().find(|m| m.path == a.path).ok_or_else(|| anyhow::anyhow!("err.noSuchMount"))?;
                let cfg = if m.kv2 && !m.auth { Some(broker::kv_config(host, &m.path).await?) } else { None };
                Ok(Reply::drawer(mount_page(&m, cfg.as_ref())))
            }
            "enable_dialog" => Ok(Reply::dialog(enable_dialog(payload.get("auth").and_then(Value::as_bool).unwrap_or(false)))),
            "mount_enable" => {
                let auth = payload.get("auth").and_then(Value::as_bool).unwrap_or(false);
                let kv_version = match form.get("kv_version").map(String::as_str) {
                    Some("1") => Some(1),
                    Some("2") => Some(2),
                    _ => None,
                };
                let f = MountForm { path: field("path"), kind: field("kind"), description: field("description"), kv_version: if field("kind") == "kv" { kv_version } else { None }, default_lease_ttl: ttl_of(&form, "default_lease_ttl"), max_lease_ttl: ttl_of(&form, "max_lease_ttl"), auth };
                f.validate().map_err(|e| anyhow::anyhow!("{e}"))?;
                broker::mount_enable(host, &f).await?;
                Ok(Reply { close_dialog: true, ..toast("hc.enabled") })
            }
            "mount_tune" => {
                let a: MountAt = arg(payload)?;
                let tune = MountTune { description: Some(field("description")), default_lease_ttl: Some(ttl_of(&form, "default_lease_ttl")), max_lease_ttl: Some(ttl_of(&form, "max_lease_ttl")), kv_version: None };
                broker::mount_tune(host, &a.path, a.auth, &tune).await?;
                Ok(toast("hc.saved"))
            }
            "mount_upgrade" => {
                let a: MountAt = arg(payload)?;
                broker::mount_tune(host, &a.path, false, &MountTune { kv_version: Some(2), ..MountTune::default() }).await?;
                Ok(Reply { close_drawer: true, ..toast("hc.saved") })
            }
            "kv_config_write" => {
                let mount = payload.get("mount").and_then(Value::as_str).ok_or_else(|| anyhow::anyhow!("a setting of no engine"))?.to_string();
                let cfg = KvConfig { max_versions: number(&form, "max_versions")?.unwrap_or(0), cas_required: flag(&form, "cas_required")?, delete_version_after: ttl_of(&form, "delete_version_after") };
                broker::kv_config_write(host, &mount, &cfg).await?;
                Ok(toast("hc.saved"))
            }
            "mount_disable" => {
                let a: MountAt = arg(payload)?;
                broker::mount_disable(host, &a.path, a.auth).await?;
                Ok(Reply { close_drawer: true, ..toast("hc.disabled") })
            }
            // -- policies --
            "policies_body" => body(policies_body(&broker::policies(host).await?)),
            "policy" => {
                let a: Named = arg(payload)?;
                let p = broker::policy(host, &a.name).await?;
                Ok(Reply::dialog(policy_page(&p.name, &p.rules, true)))
            }
            "policy_new" => Ok(Reply::dialog(policy_new())),
            "policy_create" => {
                let name = field("name");
                anyhow::ensure!(!name.is_empty(), "err.policyNeedsName");
                anyhow::ensure!(!broker::policies(host).await?.contains(&name), crate::model::key("err.policyExists", &[("name", &name)]));
                Ok(Reply::dialog(policy_page(&name, "", false)))
            }
            "policy_check" => {
                let a: Named = arg(payload.clone())?;
                let text = payload.get("text").and_then(Value::as_str).unwrap_or_default();
                let before = if broker::policies(host).await?.contains(&a.name) { Some(broker::policy(host, &a.name).await?.rules) } else { None };
                Reply::data(json!({ "before": before, "after": text }))
            }
            "policy_apply" => {
                let a: Named = arg(payload.clone())?;
                let text = payload.get("text").and_then(Value::as_str).unwrap_or_default();
                broker::put_policy(host, &a.name, text).await?;
                Ok(Reply { close_dialog: true, ..toast("hc.saved") })
            }
            "policy_delete" => {
                let a: Named = arg(payload)?;
                broker::delete_policy(host, &a.name).await?;
                Ok(Reply { close_dialog: true, ..toast("hc.deleted") })
            }
            "ensure_policy_admin" => {
                broker::put_policy(host, POLICY_ADMIN, crate::model::POLICY_ADMIN_RULES).await?;
                Ok(toast("hc.saved"))
            }
            // -- root --
            "roots_body" => body(roots_body(&in_use(host).await?, &broker::root_tokens(host).await?)),
            "revoke_root" => {
                let addr = payload.get("addr").and_then(Value::as_str).ok_or_else(|| anyhow::anyhow!("a revocation of no server"))?;
                broker::revoke_root(host, addr).await?;
                Ok(toast("hc.revoked"))
            }
            other => anyhow::bail!("the hashicorp plugin's screens have no action \"{other}\""),
        }
    }
}

/// The version a write is to land on top of: what the form was made for.
fn payload_cas(a: &At) -> Option<u64> {
    a.version
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| ((*k).to_string(), (*v).to_string())).collect()
    }

    #[test]
    fn an_edit_replaces_what_is_typed_and_keeps_the_rest() {
        let data: BTreeMap<String, String> = [("user".to_string(), "app".to_string()), ("password".to_string(), "old".to_string())].into_iter().collect();
        let out = edited(data.clone(), &form(&[("value:user", ""), ("value:password", "new"), ("new_key", "port"), ("new_value", "5432")])).unwrap();
        assert_eq!(out["user"], "app");
        assert_eq!(out["password"], "new");
        assert_eq!(out["port"], "5432");
        assert!(edited(data.clone(), &form(&[("value:ghost", "x")])).is_err(), "a key the secret does not have is refused");
        assert!(edited(data, &form(&[("new_value", "x")])).is_err(), "a value without a name is refused");
    }

    #[test]
    fn the_issue_form_reads_into_a_request() {
        let r = issue_request(&form(&[("recipient", "agent"), ("policies", "ro-dev, deploy"), ("ttl", "900"), ("num_uses", "0"), ("wrap", "true"), ("wide_ok", "false"), ("note", " ci ")])).unwrap();
        assert_eq!((r.recipient, r.policies.clone(), r.ttl_seconds, r.wrap, r.note.as_str()), (Recipient::Agent, vec!["ro-dev".to_string(), "deploy".to_string()], 900, true, "ci"));
        assert!(issue_request(&form(&[("recipient", "robot"), ("ttl", "900")])).is_err());
        assert!(issue_request(&form(&[("recipient", "me"), ("ttl", "900"), ("wrap", "maybe")])).is_err());
    }
}
