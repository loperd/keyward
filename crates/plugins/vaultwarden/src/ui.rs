//! The panel as the window draws it: one place on the path — the server's
//! panel, locked or not — whose screen holds the users, the organisations,
//! the server's settings and the tools, built from the core's vocabulary. The
//! plugin brings no code for any of it; the window draws these nodes with its
//! own kit.
//!
//! The place costs nothing to declare: it is built from the keychain's yes or
//! no and the account's server, never from the panel, so the path is drawn
//! without a request and without the person's finger. The panel is asked only
//! from its screen.
//!
//! What the window may do to whom is the plugin's, as before: a user's
//! actions and how carefully each is offered, the roles one may give.

use std::collections::BTreeMap;

use keyward_core::items::{MemberStatus, OrgRole};
use keyward_plugin::Host;
use keyward_ui::places::{Block, Doc, Level, Mark, Place, Places, Preview, Section as DocSection, Target, Use, Verb};
use keyward_ui::{Action, Button, Cell, Chip, Column, Facet, Field, FieldKind, ListRow, Node, Page, Reply, Tab, TableRow, Text, Tone};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::api::UserAction;
use crate::settings::{SettingKind, SettingsGroup};
use crate::{orgs_of, panel, panel_roles, OrgView, UserView, UserState, VaultwardenPlugin, TOKEN};

fn k(key: &str) -> Text {
    Text::key(key)
}

/// The verb that locks the panel again from its place.
pub const LOCK: &str = "lock panel";

/// A host of the panel, for a quiet line.
fn host_of(panel: &str) -> String {
    panel.trim_start_matches("https://").trim_end_matches("/admin").to_string()
}

fn role_word(r: OrgRole) -> Text {
    k(match r {
        OrgRole::Owner => "vwadmin.role.owner",
        OrgRole::Admin => "vwadmin.role.admin",
        OrgRole::Manager => "vwadmin.role.manager",
        OrgRole::User => "vwadmin.role.user",
        OrgRole::Custom => "vwadmin.role.custom",
        OrgRole::Unknown => "vwadmin.role.unknown",
    })
}

fn role_id(r: OrgRole) -> String {
    serde_json::to_value(r).ok().and_then(|v| v.as_str().map(str::to_string)).expect("a role is a word")
}

fn status_word(s: MemberStatus) -> Text {
    status_chip(s).label
}

fn status_chip(s: MemberStatus) -> Chip {
    let (key, tone) = match s {
        MemberStatus::Confirmed => ("vwadmin.status.confirmed", Tone::Ok),
        MemberStatus::Accepted => ("vwadmin.status.accepted", Tone::Warn),
        MemberStatus::Invited => ("vwadmin.status.invited", Tone::Plain),
        MemberStatus::Revoked => ("vwadmin.status.revoked", Tone::Bad),
        MemberStatus::Unknown => ("vwadmin.status.unknown", Tone::Plain),
    };
    Chip::state(k(key), tone)
}

fn state_chip(s: UserState) -> Chip {
    match s {
        UserState::Enabled => Chip::state(k("vwadmin.state.enabled"), Tone::Ok),
        UserState::Invited => Chip::state(k("vwadmin.state.invited"), Tone::Warn),
        UserState::Disabled => Chip::state(k("vwadmin.state.disabled"), Tone::Bad),
    }
}

fn state_id(s: UserState) -> &'static str {
    match s {
        UserState::Enabled => "enabled",
        UserState::Invited => "invited",
        UserState::Disabled => "disabled",
    }
}

fn two_factor_chip(on: bool) -> Chip {
    if on {
        Chip::state(k("vwadmin.twoFactorOn"), Tone::Ok)
    } else {
        Chip::state(k("vwadmin.twoFactorOff"), Tone::Warn)
    }
}

fn action_key(a: UserAction) -> &'static str {
    match a {
        UserAction::ResendInvite => "vwadmin.action.resendInvite",
        UserAction::Disable => "vwadmin.action.disable",
        UserAction::Enable => "vwadmin.action.enable",
        UserAction::Deauth => "vwadmin.action.deauth",
        UserAction::RemoveTwoFactor => "vwadmin.action.removeTwoFactor",
        UserAction::Delete => "vwadmin.action.delete",
    }
}

fn confirm_key(a: UserAction) -> &'static str {
    match a {
        UserAction::Disable => "vwadmin.confirm.disable",
        UserAction::Deauth => "vwadmin.confirm.deauth",
        UserAction::RemoveTwoFactor => "vwadmin.confirm.removeTwoFactor",
        _ => "vwadmin.confirm.delete",
    }
}

fn action_icon(a: UserAction) -> &'static str {
    match a {
        UserAction::ResendInvite => "mail",
        UserAction::Disable => "lock",
        UserAction::Enable => "check",
        UserAction::Deauth => "logout",
        UserAction::RemoveTwoFactor => "shield",
        UserAction::Delete => "trash",
    }
}

/// A date the panel gives (`2026-10-01 12:00:00` or ISO), as its day.
fn day(at: &Option<String>) -> Text {
    match at {
        Some(s) if !s.trim().is_empty() => Text::raw(s.trim().chars().take(10).collect::<String>()),
        _ => k("vwadmin.neverActive"),
    }
}

fn who(u: &UserView) -> String {
    u.name.clone().unwrap_or_else(|| u.email.clone())
}

// -- The place ----------------------------------------------------------------

/// The panel's place, from whether a token is kept and where the panel is.
pub fn declare(panel: Option<&str>, unlocked: bool) -> Places {
    let (level, why) = match (panel, unlocked) {
        (None, _) => (Level::Unknown, k("err.vwadminNoServer")),
        (Some(_), true) => (Level::Healthy, k("vwadmin.unlockedShort")),
        (Some(_), false) => (Level::Action, k("vwadmin.lockedShort")),
    };
    let mut root = Place::root("shield", Text::raw("Vaultwarden"), level);
    root.hue = Some("mint".into());
    root.why = Some(why.clone());
    root.short = Some(why.clone());
    root.screen = panel.map(|_| String::new());
    if let Some(p) = panel {
        root.subtitle = Some(Text::raw(host_of(p)));
    }
    let mut blocks = vec![Block::Para { text: k("plugin.vaultwarden.description") }];
    if let Some(p) = panel {
        blocks.insert(0, Block::Field { label: k("vwadmin.panel"), value: Text::raw(p), mono: true, mark: Some(Mark { level, text: why.clone() }) });
    }
    root.page = Some(Doc {
        what: Some(k("vwadmin.what")),
        state: Some(Mark { level, text: why }),
        more: if unlocked { vec![LOCK.into()] } else { Vec::new() },
        sections: vec![DocSection { title: k("vwadmin.facts"), count: None, blocks }],
        note: Some(k("vwadmin.tokenWhere")),
        ..Doc::default()
    });
    let mut out = Places::new(root);
    if unlocked {
        out.verbs = vec![Verb {
            id: LOCK.into(),
            name: k("vwadmin.forget"),
            icon: Some("lock".into()),
            uses: vec![Use { on: Target::Place(String::new()), action: Action::op("forget") }],
            preview: Preview { lede: k("vwadmin.forgetHint"), steps: vec![(k("vwadmin.forgetStep"), k("vwadmin.forgetStepSub"))], go: k("vwadmin.forgetAction"), note: None, danger: false },
        }];
    }
    out
}

// -- The screens ----------------------------------------------------------------

/// The panel locked: the token is pasted, tried, and only then kept.
pub fn locked_page(panel: &str) -> Page {
    Page {
        title: Some(k("vwadmin.unlockTitle")),
        icon: Some("lock".into()),
        subtitle: Some(Text::raw(host_of(panel))),
        body: vec![
            Node::Alert { text: k("vwadmin.unlockBody"), tone: Tone::Plain },
            Node::Form {
                fields: vec![Field { id: "token".into(), label: k("vwadmin.token"), kind: FieldKind::Secret, hint: Some(k("vwadmin.tokenHint")), value: None }],
                submit: Button::labelled(k("vwadmin.unlock"), Action::op("unlock")).with_icon("lock").primary(),
            },
        ],
        ..Page::default()
    }
}

/// The panel open: its parts in tabs, each read when it is shown.
pub fn panel_page(panel: &str) -> Page {
    Page {
        title: Some(Text::raw("Vaultwarden")),
        icon: Some("shield".into()),
        subtitle: Some(Text::raw(host_of(panel))),
        actions: vec![
            Button::labelled(k("vwadmin.invite"), Action::op("invite_dialog")).with_icon("plus").primary(),
            Button::icon("refresh", k("vwadmin.refresh"), Action::op("refresh")),
        ],
        body: vec![Node::Tabs {
            id: "vaultwarden|parts".into(),
            icons_only: false,
            on: None,
            tabs: vec![
                Tab { id: "users".into(), title: k("vwadmin.users"), icon: Some("people".into()), load: Some(Action::op("users_body")), refresh_ms: None, body: Vec::new() },
                Tab { id: "orgs".into(), title: k("vwadmin.orgs"), icon: Some("org".into()), load: Some(Action::op("orgs_body")), refresh_ms: None, body: Vec::new() },
                Tab { id: "settings".into(), title: k("vwadmin.settings"), icon: Some("tune".into()), load: Some(Action::op("settings_body")), refresh_ms: None, body: Vec::new() },
                Tab { id: "tools".into(), title: k("vwadmin.tools"), icon: Some("settings".into()), load: None, refresh_ms: None, body: tools(panel) },
            ],
        }],
        ..Page::default()
    }
}

/// The users as a table: the window filters by state and second factor.
pub fn users_table(users: &[UserView]) -> Node {
    let rows = users
        .iter()
        .map(|u| {
            let orgs = u.memberships.iter().map(|m| m.org_name.clone()).collect::<Vec<_>>().join(", ");
            TableRow::new(u.id.clone())
                .cell("user", Cell::Text { text: Text::raw(who(u)) })
                .cell("email", Cell::Text { text: Text::raw(&u.email) })
                .cell("state", Cell::Chip { chip: state_chip(u.state) })
                .cell("tfa", Cell::Chip { chip: two_factor_chip(u.two_factor) })
                .cell("orgs", if orgs.is_empty() { Cell::Empty } else { Cell::Text { text: Text::raw(orgs) } })
                .cell("active", Cell::Text { text: day(&u.last_active) })
                .facet("state", Some(state_id(u.state)))
                .facet("tfa", Some(if u.two_factor { "on" } else { "off" }))
                .sort("active", u.last_active.clone().unwrap_or_default())
                .open(Action::with("user", json!({ "user_id": u.id })))
        })
        .collect();
    Node::Table {
        id: "vaultwarden|users".into(),
        columns: vec![
            Column { id: "user".into(), title: k("vwadmin.col.user"), sortable: true, mono: false },
            Column { id: "email".into(), title: k("vwadmin.factEmail"), sortable: true, mono: true },
            Column { id: "state".into(), title: k("vwadmin.col.state"), sortable: true, mono: false },
            Column { id: "tfa".into(), title: k("vwadmin.col.twoFactor"), sortable: true, mono: false },
            Column { id: "orgs".into(), title: k("vwadmin.orgs"), sortable: false, mono: false },
            Column { id: "active".into(), title: k("vwadmin.factActive"), sortable: true, mono: true },
        ],
        facets: vec![
            Facet { id: "state".into(), title: k("vwadmin.col.state"), icon: "state".into() },
            Facet { id: "tfa".into(), title: k("vwadmin.col.twoFactor"), icon: "shield".into() },
        ],
        rows,
        empty: Some(k("vwadmin.noUsers")),
    }
}

/// The roles one may give, as a field's choices.
fn role_options(roles: &[OrgRole]) -> Vec<(String, Text)> {
    roles.iter().map(|r| (role_id(*r), role_word(*r))).collect()
}

/// A user's drawer: what they are, where they are a member and as whom, and
/// what can be done to them — the light things with a second press, what
/// cuts them off in the danger zone, their address typed first.
pub fn user_drawer(u: &UserView, roles: &[OrgRole]) -> Page {
    let at = |a: UserAction| json!({ "user_id": u.id, "action": a });
    let mut chips = vec![state_chip(u.state), two_factor_chip(u.two_factor)];
    if !u.email_verified {
        chips.push(Chip::state(k("vwadmin.unverified"), Tone::Warn));
    }
    let mut facts = ListRow::new("created", "clock", k("vwadmin.factCreated"));
    facts.subtitle = Some(day(&u.created_at));
    let mut active = ListRow::new("active", "pulse", k("vwadmin.factActive"));
    active.subtitle = Some(day(&u.last_active));
    let mut body = vec![Node::Section { title: k("vwadmin.facts"), icon: "info".into(), tone: Tone::Plain, count: None, folded: false, hint: None, body: vec![Node::List { rows: vec![facts, active] }] }];

    let access = if u.memberships.is_empty() {
        vec![Node::Empty { icon: "org".into(), title: k("vwadmin.noMemberships"), body: None }]
    } else {
        // An organisation a row: its name, the role there to change, and
        // where the membership stands.
        vec![Node::Form {
            fields: u
                .memberships
                .iter()
                .map(|m| Field { id: m.org_id.clone(), label: Text::raw(&m.org_name), kind: FieldKind::Select { options: role_options(roles) }, hint: Some(status_word(m.status)), value: Some(role_id(m.role)) })
                .collect(),
            submit: Button::labelled(k("vwadmin.saveRoles"), Action::with("set_roles", json!({ "user_id": u.id }))).with_icon("check"),
        }]
    };
    body.push(Node::Section { title: k("vwadmin.access"), icon: "org".into(), tone: Tone::Plain, count: Some(u.memberships.len()), folded: false, hint: None, body: access });

    let light: Vec<Button> = u
        .actions
        .iter()
        .filter(|a| !a.danger)
        .map(|a| {
            let action = if a.confirm { Action::with("user_action", at(a.action)).pressed_twice() } else { Action::with("user_action", at(a.action)) };
            Button::labelled(k(action_key(a.action)), action).with_icon(action_icon(a.action))
        })
        .collect();
    if !light.is_empty() {
        body.push(Node::Section { title: k("vwadmin.actions"), icon: "verb".into(), tone: Tone::Plain, count: None, folded: false, hint: None, body: vec![Node::Actions { buttons: light }] });
    }
    for a in u.actions.iter().filter(|a| a.danger) {
        body.push(Node::Danger {
            title: k(action_key(a.action)),
            hint: Text::key_with(confirm_key(a.action), json!({ "who": who(u) })),
            button: Button::labelled(k(action_key(a.action)), Action::with("user_action", at(a.action)).confirmed_by(&u.email)).with_icon(action_icon(a.action)).tone(Tone::Bad),
        });
    }
    Page { title: Some(Text::raw(who(u))), icon: Some("person".into()), subtitle: Some(Text::raw(&u.email)), chips, body, ..Page::default() }
}

/// The organisations as a table.
pub fn orgs_table(orgs: &[OrgView]) -> Node {
    Node::Table {
        id: "vaultwarden|orgs".into(),
        columns: vec![
            Column { id: "name".into(), title: k("vwadmin.col.org"), sortable: true, mono: false },
            Column { id: "members".into(), title: k("vwadmin.members"), sortable: true, mono: false },
            Column { id: "owners".into(), title: k("vwadmin.col.owners"), sortable: true, mono: false },
        ],
        facets: Vec::new(),
        rows: orgs
            .iter()
            .map(|o| {
                TableRow::new(o.id.clone())
                    .cell("name", Cell::Text { text: Text::raw(&o.name) })
                    .cell("members", Cell::Text { text: Text::raw(o.members.len().to_string()) })
                    .cell("owners", if o.owners == 0 { Cell::Chip { chip: Chip::state(k("vwadmin.noOwner"), Tone::Bad) } } else { Cell::Text { text: Text::raw(o.owners.to_string()) } })
                    .sort("members", o.members.len() as u64)
                    .sort("owners", o.owners as u64)
                    .open(Action::with("org", json!({ "org_id": o.id })))
            })
            .collect(),
        empty: Some(k("vwadmin.noOrgs")),
    }
}

/// An organisation's drawer: its members and their roles, and deleting it.
pub fn org_drawer(o: &OrgView, roles: &[OrgRole]) -> Page {
    // A member a row: who, the role to change, where the membership stands.
    let form = Node::Form {
        fields: o
            .members
            .iter()
            .map(|m| Field {
                id: m.user_id.clone(),
                label: Text::raw(m.name.clone().unwrap_or_else(|| m.email.clone())),
                kind: FieldKind::Select { options: role_options(roles) },
                hint: Some(Text::key_with("vwadmin.memberHint", json!({ "email": m.email, "status": status_word(m.status) }))),
                value: Some(role_id(m.role)),
            })
            .collect(),
        submit: Button::labelled(k("vwadmin.saveRoles"), Action::with("set_member_roles", json!({ "org_id": o.id }))).with_icon("check"),
    };
    Page {
        title: Some(Text::raw(&o.name)),
        icon: Some("org".into()),
        subtitle: Some(Text::key_with("vwadmin.orgFacts", json!({ "members": o.members.len(), "owners": o.owners }))),
        body: vec![
            Node::Section { title: k("vwadmin.members"), icon: "people".into(), tone: Tone::Plain, count: Some(o.members.len()), folded: false, hint: Some(k("vwadmin.membersNotYours")), body: vec![form] },

            Node::Danger {
                title: k("vwadmin.deleteOrg"),
                hint: Text::key_with("vwadmin.deleteOrgWarn", json!({ "name": o.name })),
                button: Button::labelled(k("vwadmin.deleteOrg"), Action::with("delete_org", json!({ "org_id": o.id })).confirmed_by(&o.name)).with_icon("trash").tone(Tone::Bad),
            },
        ],
        ..Page::default()
    }
}

/// The server's settings: a form for each group that may be changed here, its
/// secrets never echoed — left empty, a secret stays as it is — and what the
/// environment sets, read only, its secrets not shown at all.
pub fn settings_body(groups: &[SettingsGroup]) -> Vec<Node> {
    let mut out = Vec::new();
    for (i, g) in groups.iter().enumerate() {
        let editable: Vec<_> = g.settings.iter().filter(|s| s.editable).collect();
        if editable.is_empty() {
            let rows = g
                .settings
                .iter()
                .map(|s| {
                    let mut r = ListRow::new(s.name.clone(), "lock", Text::raw(&s.label));
                    r.mono = false;
                    r.subtitle = Some(match (s.kind, &s.value) {
                        (SettingKind::Password, Value::Null) => k("vwadmin.notSet"),
                        (SettingKind::Password, _) => k("vwadmin.secretSet"),
                        (_, Value::Null) => k("vwadmin.notSet"),
                        (_, Value::String(t)) => Text::raw(t),
                        (_, v) => Text::raw(v.to_string()),
                    });
                    r.chips.push(Chip::new(k("vwadmin.envChip")).title(k("vwadmin.envHint")));
                    r
                })
                .collect();
            out.push(Node::Section { title: Text::raw(&g.title), icon: "lock".into(), tone: Tone::Plain, count: Some(g.settings.len()), folded: true, hint: Some(k("vwadmin.readonlyHint")), body: vec![Node::List { rows }] });
            continue;
        }
        let fields = editable
            .iter()
            .map(|s| {
                let hint = match (&s.default, s.overridden) {
                    (Some(d), _) => Some(Text::key_with("vwadmin.byDefault", json!({ "value": d }))),
                    (None, _) if !s.description.is_empty() => Some(Text::raw(&s.description)),
                    _ => None,
                };
                let (kind, value) = match s.kind {
                    SettingKind::Checkbox => (FieldKind::Toggle, Some(if s.value == Value::Bool(true) { "true" } else { "false" }.to_string())),
                    SettingKind::Number => (FieldKind::Number { min: 0, max: i64::from(i32::MAX) }, s.value.as_i64().map(|n| n.to_string())),
                    SettingKind::Password => (FieldKind::Secret, None),
                    SettingKind::Text => (FieldKind::Text, s.value.as_str().map(str::to_string)),
                };
                let hint = if s.kind == SettingKind::Password { Some(k("vwadmin.secretKeep")) } else if s.choice.is_some() { Some(k("vwadmin.choiceHint")) } else { hint };
                Field { id: s.name.clone(), label: Text::raw(&s.label), kind, hint, value }
            })
            .collect();
        out.push(Node::Section {
            title: Text::raw(&g.title),
            icon: "tune".into(),
            tone: Tone::Plain,
            count: Some(editable.len()),
            folded: i > 0,
            hint: None,
            body: vec![Node::Form { fields, submit: Button::labelled(k("vwadmin.save"), Action::with("save_settings", json!({ "group": g.id }))).with_icon("check") }],
        });
    }
    if out.is_empty() {
        out.push(Node::Empty { icon: "tune".into(), title: k("vwadmin.noSettings"), body: None });
    }
    out
}

/// The tools: a backup, a test letter, and what is not easily taken back.
pub fn tools(panel: &str) -> Vec<Node> {
    vec![
        Node::Section {
            title: k("vwadmin.backup"),
            icon: "stack".into(),
            tone: Tone::Plain,
            count: None,
            folded: false,
            hint: Some(k("vwadmin.backupHint")),
            body: vec![Node::Actions { buttons: vec![Button::labelled(k("vwadmin.backupAction"), Action::op("backup_db")).with_icon("stack")] }],
        },
        Node::Section {
            title: k("vwadmin.smtp"),
            icon: "mail".into(),
            tone: Tone::Plain,
            count: None,
            folded: false,
            hint: None,
            body: vec![Node::Form {
                fields: vec![Field { id: "email".into(), label: k("vwadmin.factEmail"), kind: FieldKind::Text, hint: None, value: None }],
                submit: Button::labelled(k("vwadmin.smtpAction"), Action::op("test_smtp")).with_icon("mail"),
            }],
        },
        Node::Section {
            title: k("vwadmin.forget"),
            icon: "lock".into(),
            tone: Tone::Plain,
            count: None,
            folded: false,
            hint: Some(k("vwadmin.forgetHint")),
            body: vec![Node::Actions { buttons: vec![Button::labelled(k("vwadmin.forgetAction"), Action::op("forget").pressed_twice()).with_icon("lock")] }],
        },
        Node::Danger {
            title: k("vwadmin.reset"),
            hint: k("vwadmin.resetWarn"),
            button: Button::labelled(k("vwadmin.resetAction"), Action::op("reset_settings").confirmed_by(host_of(panel))).with_icon("undo").tone(Tone::Bad),
        },
    ]
}

/// The invitation: one address.
pub fn invite_dialog() -> Page {
    Page {
        title: Some(k("vwadmin.invite")),
        body: vec![
            Node::Alert { text: k("vwadmin.inviteHint"), tone: Tone::Plain },
            Node::Form {
                fields: vec![Field { id: "email".into(), label: k("vwadmin.factEmail"), kind: FieldKind::Text, hint: None, value: None }],
                submit: Button::labelled(k("vwadmin.invite"), Action::op("invite")).with_icon("mail").primary(),
            },
        ],
        ..Page::default()
    }
}

// -- What a form sends ------------------------------------------------------------

/// A group's form, as the changes the panel takes: a secret left empty is
/// not one; a switch is a yes or no; a number is a number; text is text or
/// nothing. A field that is no setting of the group is refused.
pub fn changes_of(groups: &[SettingsGroup], group: &str, form: &BTreeMap<String, String>) -> anyhow::Result<BTreeMap<String, Value>> {
    let g = groups.iter().find(|g| g.id == group).ok_or_else(|| anyhow::anyhow!("the panel has no settings group \"{group}\""))?;
    let mut out = BTreeMap::new();
    for (name, v) in form {
        let s = g.settings.iter().find(|s| &s.name == name && s.editable).ok_or_else(|| keyward_core::fault!("err.vwadminSettingNotEditable", "name" => name))?;
        let value = match s.kind {
            SettingKind::Password if v.is_empty() => continue,
            SettingKind::Checkbox => match v.as_str() {
                "true" => Value::Bool(true),
                "false" => Value::Bool(false),
                other => anyhow::bail!("the switch \"{name}\" came as \"{other}\""),
            },
            SettingKind::Number if v.trim().is_empty() => Value::Null,
            SettingKind::Number => Value::from(v.trim().parse::<i64>().map_err(|_| keyward_core::fault!("err.vwadminSettingNumber", "name" => name))?),
            _ if v.is_empty() => Value::Null,
            _ => Value::String(v.clone()),
        };
        out.insert(name.clone(), value);
    }
    Ok(out)
}

/// The roles a form chose that differ from what stands, as (whose, role).
fn changed_roles(form: &BTreeMap<String, String>, now: impl Fn(&str) -> Option<OrgRole>) -> anyhow::Result<Vec<(String, OrgRole)>> {
    let mut out = Vec::new();
    for (id, v) in form {
        let role: OrgRole = serde_json::from_value(Value::String(v.clone())).map_err(|_| anyhow::anyhow!("the role \"{v}\" is not one"))?;
        if !panel_roles().contains(&role) {
            return Err(keyward_core::fault!("err.orgRoleNotYours"));
        }
        match now(id) {
            Some(r) if r == role => {}
            Some(_) => out.push((id.clone(), role)),
            None => anyhow::bail!("\"{id}\" is not in this organisation"),
        }
    }
    Ok(out)
}

#[derive(Deserialize)]
struct UserArg {
    user_id: String,
}

#[derive(Deserialize)]
struct OrgArg {
    org_id: String,
}

#[derive(Deserialize)]
struct GroupArg {
    group: String,
}

fn form_of(form: Value) -> anyhow::Result<BTreeMap<String, String>> {
    if form.is_null() {
        return Ok(BTreeMap::new());
    }
    serde_json::from_value(form).map_err(|e| anyhow::anyhow!("a form came with something other than text: {e}"))
}

fn arg<T: serde::de::DeserializeOwned>(v: Value) -> anyhow::Result<T> {
    serde_json::from_value(v).map_err(|e| anyhow::anyhow!("an action came with something else: {e}"))
}

fn body(nodes: Vec<Node>) -> anyhow::Result<Reply> {
    Reply::data(json!({ "body": nodes }))
}

fn toast(key: &str) -> Reply {
    Reply { toast: Some(k(key)), refresh: true, ..Reply::default() }
}

impl VaultwardenPlugin {
    async fn users_view(&self, host: &dyn Host) -> anyhow::Result<Vec<UserView>> {
        let users = self.with_session(host, |s| async move { s.users().await }).await?;
        Ok(users.into_iter().map(UserView::from).collect())
    }
}

#[async_trait::async_trait]
impl keyward_ui::Ui for VaultwardenPlugin {
    async fn places(&self, host: &dyn Host) -> anyhow::Result<Places> {
        Ok(declare(panel(host).as_deref(), host.keychain_has(TOKEN).await))
    }

    async fn view(&self, host: &dyn Host, route: &str) -> anyhow::Result<Page> {
        anyhow::ensure!(route.is_empty(), "the Vaultwarden plugin has no screen \"{route}\"");
        let p = panel(host).ok_or_else(|| keyward_core::fault!("err.vwadminNoServer"))?;
        Ok(if host.keychain_has(TOKEN).await { panel_page(&p) } else { locked_page(&p) })
    }

    async fn act(&self, host: &dyn Host, op: &str, payload: Value, form: Value) -> anyhow::Result<Reply> {
        use keyward_plugin::Plugin as _;
        let form = form_of(form)?;
        let field = |name: &str| form.get(name).cloned().unwrap_or_default();
        match op {
            "refresh" => Ok(Reply::refresh()),
            "unlock" => {
                self.call(host, "unlock", json!({ "token": field("token") })).await?;
                Ok(toast("vwadmin.unlocked"))
            }
            "forget" => {
                self.call(host, "forget", Value::Null).await?;
                Ok(Reply { close_drawer: true, close_dialog: true, ..toast("vwadmin.lockedShort") })
            }
            "users_body" => body(vec![users_table(&self.users_view(host).await?)]),
            "orgs_body" => body(vec![orgs_table(&orgs_of(&self.users_view(host).await?))]),
            "settings_body" => {
                let groups = self
                    .with_session(host, |s| async move {
                        let mut groups = s.settings().await?;
                        let emails: Vec<String> = s.users().await?.into_iter().map(|u| u.email).collect();
                        crate::settings::attach_users(&mut groups, &emails);
                        Ok(groups)
                    })
                    .await?;
                body(settings_body(&groups))
            }
            "user" => {
                let a: UserArg = arg(payload)?;
                let users = self.users_view(host).await?;
                let u = users.iter().find(|u| u.id == a.user_id).ok_or_else(|| anyhow::anyhow!("the panel has no user \"{}\"", a.user_id))?;
                Ok(Reply::drawer(user_drawer(u, &panel_roles())))
            }
            "org" => {
                let a: OrgArg = arg(payload)?;
                let orgs = orgs_of(&self.users_view(host).await?);
                let o = orgs.iter().find(|o| o.id == a.org_id).ok_or_else(|| anyhow::anyhow!("the panel has no organisation \"{}\"", a.org_id))?;
                Ok(Reply::drawer(org_drawer(o, &panel_roles())))
            }
            "user_action" => {
                let action = payload.get("action").cloned().unwrap_or(Value::Null);
                let deleted = action == json!("delete");
                self.call(host, "user_action", payload).await?;
                Ok(Reply { close_drawer: deleted, ..toast("vwadmin.done") })
            }
            "set_roles" => {
                let a: UserArg = arg(payload)?;
                let users = self.users_view(host).await?;
                let u = users.iter().find(|u| u.id == a.user_id).ok_or_else(|| anyhow::anyhow!("the panel has no user \"{}\"", a.user_id))?;
                for (org, role) in changed_roles(&form, |id| u.memberships.iter().find(|m| m.org_id == id).map(|m| m.role))? {
                    self.call(host, "set_org_role", json!({ "user_id": u.id, "org_id": org, "role": role })).await?;
                }
                Ok(Reply { close_drawer: true, ..toast("vwadmin.rolesSaved") })
            }
            "set_member_roles" => {
                let a: OrgArg = arg(payload)?;
                let orgs = orgs_of(&self.users_view(host).await?);
                let o = orgs.iter().find(|o| o.id == a.org_id).ok_or_else(|| anyhow::anyhow!("the panel has no organisation \"{}\"", a.org_id))?;
                for (user, role) in changed_roles(&form, |id| o.members.iter().find(|m| m.user_id == id).map(|m| m.role))? {
                    self.call(host, "set_org_role", json!({ "user_id": user, "org_id": o.id, "role": role })).await?;
                }
                Ok(Reply { close_drawer: true, ..toast("vwadmin.rolesSaved") })
            }
            "delete_org" => {
                self.call(host, "delete_org", payload).await?;
                Ok(Reply { close_drawer: true, ..toast("vwadmin.orgDeleted") })
            }
            "invite_dialog" => Ok(Reply::dialog(invite_dialog())),
            "invite" => {
                let email = field("email");
                self.call(host, "invite", json!({ "email": email.trim() })).await?;
                Ok(Reply { close_dialog: true, toast: Some(Text::key_with("vwadmin.invited", json!({ "email": email.trim() }))), refresh: true, ..Reply::default() })
            }
            "save_settings" => {
                let a: GroupArg = arg(payload)?;
                let groups = self.with_session(host, |s| async move { s.settings().await }).await?;
                let changes = changes_of(&groups, &a.group, &form)?;
                self.call(host, "save_settings", json!({ "changes": changes })).await?;
                Ok(toast("vwadmin.settingsSaved"))
            }
            "reset_settings" => {
                self.call(host, "reset_settings", Value::Null).await?;
                Ok(toast("vwadmin.resetDone"))
            }
            "backup_db" => {
                let said = self.call(host, "backup_db", Value::Null).await?;
                let said = said.as_str().map(str::to_string).unwrap_or_else(|| said.to_string());
                Ok(Reply { toast: Some(Text::key_with("vwadmin.backedUp", json!({ "what": said }))), ..Reply::default() })
            }
            "test_smtp" => {
                let email = field("email");
                self.call(host, "test_smtp", json!({ "email": email.trim() })).await?;
                Ok(Reply { toast: Some(Text::key_with("vwadmin.smtpSent", json!({ "email": email.trim() }))), ..Reply::default() })
            }
            other => anyhow::bail!("the Vaultwarden plugin's screens have no action \"{other}\""),
        }
    }
}
