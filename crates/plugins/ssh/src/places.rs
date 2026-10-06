//! The plugin's places on the window's path: SSH → Hosts → a host, SSH →
//! Keys → the vault's keys, and the map of which key gets in where. Built
//! from the health board — what each key's hosts last said — without
//! signing or connecting anything; the window draws them with its own kit.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use keyward_ui::places::{
    Block, Doc, Edge, EdgeKind, Find, FindGroup, ItemMark, Kid, Level, Line, Loud, Mark, MapFinding, LegendEntry, Place, Places, Point, Preview, Section,
    Target, Topology, Use, Verb,
};
use keyward_ui::{Action, Text};
use serde_json::{json, Value};

use crate::terminal::health::{Check, Report, Status};

/// The verb that checks the keys: the word a person types.
pub const CHECK: &str = "check keys";
/// The plugin's operation behind it.
pub const CHECK_OP: &str = "check";

/// How often the window asks again: soon while a round fills in, and now and
/// then otherwise, for the rounds the minute tick starts.
const RUNNING_MS: u64 = 1500;
const IDLE_MS: u64 = 60_000;

fn k(key: &str) -> Text {
    Text::key(key)
}

/// A check's status as the window's level and its word.
fn level_of(s: Status) -> Level {
    match s {
        Status::Ok => Level::Healthy,
        Status::Reachable => Level::Action,
        Status::HostUnknown | Status::Error | Status::Unreachable => Level::Warning,
        Status::Rejected | Status::HostChanged => Level::Critical,
        Status::Unbound | Status::Wildcard | Status::Pending => Level::Unknown,
    }
}

fn word_of(s: Status) -> Text {
    k(match s {
        Status::Unbound => "term.health.unbound",
        Status::Wildcard => "term.health.wildcard",
        Status::Pending => "term.health.pending",
        Status::Ok => "term.health.ok",
        Status::Reachable => "term.health.reachable",
        Status::HostUnknown => "term.health.hostUnknown",
        Status::Error => "term.health.error",
        Status::Unreachable => "term.health.unreachable",
        Status::Rejected => "term.health.rejected",
        Status::HostChanged => "term.health.hostChanged",
    })
}

/// Why, at more length, where the dictionary says more than the word.
fn why_of(s: Status) -> Text {
    match s {
        Status::Unbound => k("term.health.unboundHint"),
        Status::Wildcard => k("term.health.wildcardHint"),
        Status::Reachable => k("term.health.reachableHint"),
        Status::HostUnknown => k("term.health.hostUnknownHint"),
        Status::HostChanged => k("term.health.changedHint"),
        other => word_of(other),
    }
}

fn loud(l: Level) -> Option<Loud> {
    match l {
        Level::Critical => Some(Loud::Critical),
        Level::Action | Level::Warning => Some(Loud::Warning),
        _ => None,
    }
}

/// The keys of the plugin's dictionary, read from the same file the window
/// registers: a failure's code the dictionary knows is said in words, any
/// other text as it is.
fn known(key: &str) -> bool {
    static KEYS: OnceLock<BTreeSet<String>> = OnceLock::new();
    KEYS.get_or_init(|| {
        let words: BTreeMap<String, Value> = serde_json::from_str(include_str!("../i18n/en.json")).expect("the plugin's dictionary is JSON");
        words.into_keys().collect()
    })
    .contains(key)
}

/// A check's reason as it travels (`err.key {"args"}`), as a declared text.
fn detail_text(d: &str) -> Text {
    let (code, args) = d.split_once(' ').unwrap_or((d, ""));
    if !code.starts_with("err.") || !known(code) {
        return Text::raw(d);
    }
    if args.is_empty() {
        return k(code);
    }
    match serde_json::from_str::<Value>(args) {
        Ok(a @ Value::Object(_)) => Text::key_with(code, a),
        _ => Text::raw(d),
    }
}

fn host_id(c: &Check) -> String {
    format!("host/{}:{}", c.host, c.port)
}

/// One host and every key's check of it.
struct Host<'a> {
    id: String,
    host: &'a str,
    port: u16,
    checks: Vec<(&'a str, &'a str, &'a Check)>,
}

impl Host<'_> {
    fn status(&self) -> Status {
        self.checks.iter().map(|(_, _, c)| c.status).max().unwrap_or(Status::Pending)
    }
    fn level(&self) -> Level {
        Level::worst_of(self.checks.iter().map(|(_, _, c)| level_of(c.status)))
    }
    fn users(&self) -> Vec<&str> {
        let mut u: Vec<&str> = self.checks.iter().filter_map(|(_, _, c)| c.user.as_deref()).collect();
        u.sort();
        u.dedup();
        u
    }
    /// The one key it is checked with, if it is one.
    fn only_key(&self) -> Option<&str> {
        let mut ks: Vec<&str> = self.checks.iter().map(|(id, _, _)| *id).collect();
        ks.dedup();
        match ks.as_slice() {
            [one] => Some(one),
            _ => None,
        }
    }
}

fn check_action(entry: Option<&str>) -> Action {
    match entry {
        Some(id) => Action::with(CHECK_OP, json!({ "entry_id": id })),
        None => Action::op(CHECK_OP),
    }
}

/// The places, from the health board's report.
pub fn declare(report: &Report) -> Places {
    // Hosts, by host and port, in the order of badness, then by name.
    let mut by: BTreeMap<String, Host> = BTreeMap::new();
    for kh in &report.keys {
        for c in &kh.checks {
            by.entry(host_id(c))
                .or_insert_with(|| Host { id: host_id(c), host: &c.host, port: c.port, checks: Vec::new() })
                .checks
                .push((&kh.entry_id, &kh.entry_name, c));
        }
    }
    let mut hosts: Vec<Host> = by.into_values().collect();
    hosts.sort_by(|a, b| a.level().cmp(&b.level()).then_with(|| a.host.cmp(b.host)).then(a.port.cmp(&b.port)));

    let key_level = |s: Status| level_of(s);
    let overall = Level::worst_of(report.keys.iter().map(|kh| key_level(kh.status)));
    let worst_key = report.keys.iter().max_by_key(|kh| kh.status);

    let mut root = Place::root("terminal", k("plugin.ssh.title"), overall);
    root.hue = Some("cyan".into());
    root.subtitle = Some(Text::key_with("path.ssh.sub", json!({ "hosts": hosts.len(), "keys": report.keys.len() })));
    if let Some(kh) = worst_key.filter(|kh| loud(key_level(kh.status)).is_some()) {
        root.why = Some(Text::key_with("path.ssh.keyWhy", json!({ "name": kh.entry_name, "status": word_of(kh.status) })));
        root.short = Some(word_of(kh.status));
    }
    root.kids = vec![Kid::Place { id: "hosts".into(), sub: None }, Kid::Place { id: "keys".into(), sub: None }, Kid::Gap, Kid::Place { id: "map".into(), sub: None }];

    let loud_hosts: Vec<&Host> = hosts.iter().filter(|h| loud(h.level()).is_some()).collect();
    let healthy = hosts.iter().filter(|h| h.level() == Level::Healthy).count();
    let mut overview = vec![if loud_hosts.is_empty() {
        Block::Para { text: Text::key_with("term.health.good", json!({ "n": healthy, "total": hosts.len() })) }
    } else {
        Block::Para { text: Text::key_with("term.health.bad", json!({ "n": loud_hosts.len() })) }
    }];
    overview.extend(loud_hosts.iter().map(|h| Block::Finding { level: h.level(), title: Text::raw(h.host), sub: Some(word_of(h.status())), to: Some(Target::Place(h.id.clone())) }));
    root.page = Some(Doc {
        primary: Some(CHECK.into()),
        map: true,
        sections: vec![
            Section { title: k("term.health.title"), count: None, blocks: overview },
            Section { title: k("path.ssh.map"), count: None, blocks: vec![Block::MapDoor { title: k("path.ssh.mapSub"), sub: k("term.health.explain") }] },
        ],
        note: Some(k("term.health.explain")),
        ..Doc::default()
    });

    let mut places = Vec::new();
    let hosts_level = Level::worst_of(hosts.iter().map(Host::level));
    let mut hp = Place::under(None, "hosts", "server", k("term.hosts"), hosts_level);
    hp.count = Some(hosts.len());
    hp.wide = true;
    hp.kids = hosts.iter().map(|h| Kid::Place { id: h.id.clone(), sub: None }).collect();
    hp.page = Some(Doc { primary: Some(CHECK.into()), map: true, sections: Vec::new(), note: (hosts.is_empty()).then(|| k("term.noHosts")), ..Doc::default() });
    places.push(hp);

    let mut kp = Place::under(None, "keys", "key", k("term.overview"), overall);
    kp.count = Some(report.keys.len());
    kp.wide = true;
    kp.kids = report.keys.iter().map(|kh| Kid::Item { id: kh.entry_id.clone(), sub: Some(word_of(kh.status)) }).collect();
    kp.page = Some(Doc {
        primary: Some(CHECK.into()),
        sections: vec![Section {
            title: k("term.health.title"),
            count: Some(report.keys.len()),
            blocks: report
                .keys
                .iter()
                .map(|kh| Block::Ref { to: Target::Item(kh.entry_id.clone()), title: None, context: None, mark: Some(Mark { level: key_level(kh.status), text: word_of(kh.status) }), mono: false })
                .collect(),
        }],
        note: report.keys.is_empty().then(|| k("term.empty.body")),
        ..Doc::default()
    });
    places.push(kp);

    let mut mp = Place::under(None, "map", "map", k("path.ssh.map"), overall);
    mp.subtitle = Some(k("path.ssh.mapSub"));
    mp.map = true;
    places.push(mp);

    for h in &hosts {
        let lvl = h.level();
        let st = h.status();
        let mut p = Place::under(Some("hosts"), h.id.clone(), "server", Text::raw(h.host), lvl);
        let users = h.users();
        p.subtitle = Some(Text::raw(match users.as_slice() {
            [u] => format!("{u}@ · {}", h.port),
            _ => h.port.to_string(),
        }));
        p.mono = true;
        p.sub_mono = true;
        p.why = Some(why_of(st));
        p.short = Some(word_of(st));
        let aliases: BTreeSet<&str> = h.checks.iter().flat_map(|(_, _, c)| c.aliases.iter().map(String::as_str)).collect();
        let words: Vec<&str> = std::iter::once(h.host).chain(users.iter().copied()).chain(aliases.iter().copied()).collect();
        p.find = Some(Find { group: FindGroup::Hosts, kind: "host".into(), words: words.join(" ") });
        let mut keys = Vec::new();
        for (id, _, c) in &h.checks {
            let context = c.detail.as_deref().map(detail_text).or_else(|| c.latency_ms.map(|ms| Text::key_with("term.health.latency", json!({ "ms": ms }))));
            keys.push(Block::Ref { to: Target::Item((*id).to_string()), title: None, context, mark: Some(Mark { level: level_of(c.status), text: word_of(c.status) }), mono: false });
        }
        let mut about = vec![Block::Field { label: k("term.port"), value: Text::raw(h.port.to_string()), mono: true, mark: None }];
        if !users.is_empty() {
            about.insert(0, Block::Field { label: k("term.login"), value: Text::raw(users.join(", ")), mono: true, mark: None });
        }
        if let Some(fp) = h.checks.iter().find_map(|(_, _, c)| c.fingerprint.as_deref()) {
            about.push(Block::Field { label: k("sshkey.fingerprint"), value: Text::raw(fp), mono: true, mark: None });
        }
        if !aliases.is_empty() {
            about.push(Block::Para { text: Text::key_with("term.aliases", json!({ "names": aliases.iter().copied().collect::<Vec<_>>().join(", ") })) });
        }
        p.page = Some(Doc {
            primary: Some(CHECK.into()),
            map: true,
            sections: vec![Section { title: k("term.overview"), count: Some(h.checks.len()), blocks: keys }, Section { title: k("term.host"), count: None, blocks: about }],
            ..Doc::default()
        });
        places.push(p);
    }

    let marks = report
        .keys
        .iter()
        .map(|kh| ItemMark { item: kh.entry_id.clone(), level: key_level(kh.status), why: why_of(kh.status), short: word_of(kh.status) })
        .collect();

    let mut lines = Vec::new();
    let mut edges = Vec::new();
    for h in &hosts {
        for (id, _, c) in &h.checks {
            let lvl = level_of(c.status);
            let kind = if lvl == Level::Critical { EdgeKind::Refused } else { EdgeKind::Route };
            lines.push(Line { from: h.id.clone(), item: (*id).to_string(), kind, level: loud(lvl), words: word_of(c.status), short: word_of(c.status) });
            edges.push(Edge { a: Target::Item((*id).to_string()), b: Target::Place(h.id.clone()), kind, level: loud(lvl), words: word_of(c.status), chip: lvl == Level::Critical });
        }
    }
    let mut points: Vec<Point> = report.keys.iter().filter(|kh| !kh.checks.is_empty()).map(|kh| Point { at: Target::Item(kh.entry_id.clone()), lane: 0 }).collect();
    points.extend(hosts.iter().map(|h| Point { at: Target::Place(h.id.clone()), lane: 1 }));
    let topology = Topology {
        title: k("path.ssh.map"),
        place: k("plugin.ssh.title"),
        lanes: vec![k("term.overview"), k("term.hosts")],
        pivot: 1,
        points,
        edges,
        findings: loud_hosts.iter().map(|h| MapFinding { level: h.level(), text: Text::key_with("path.ssh.hostFinding", json!({ "host": h.host, "status": word_of(h.status()) })), focus: Target::Place(h.id.clone()) }).collect(),
        legend: vec![
            LegendEntry { kind: EdgeKind::Route, level: None, text: k("term.health.ok") },
            LegendEntry { kind: EdgeKind::Route, level: Some(Loud::Warning), text: k("term.health.unreachable") },
            LegendEntry { kind: EdgeKind::Refused, level: Some(Loud::Critical), text: k("term.health.rejected") },
        ],
    };

    // Checking: everywhere at once from the plugin, its hosts and its keys;
    // one key from the key itself, or from a host only that key reaches.
    let mut uses = vec![Use { on: Target::Place(String::new()), action: check_action(None) }, Use { on: Target::Place("hosts".into()), action: check_action(None) }, Use { on: Target::Place("keys".into()), action: check_action(None) }];
    uses.extend(hosts.iter().map(|h| Use { on: Target::Place(h.id.clone()), action: check_action(h.only_key()) }));
    uses.extend(report.keys.iter().map(|kh| Use { on: Target::Item(kh.entry_id.clone()), action: check_action(Some(&kh.entry_id)) }));
    let verb = Verb {
        id: CHECK.into(),
        name: k("term.health.run"),
        icon: Some("refresh".into()),
        uses,
        preview: Preview { lede: k("term.health.explain"), steps: Vec::new(), go: k("term.health.check"), note: None, danger: false },
    };

    let mut out = Places::new(root);
    out.places = places;
    out.marks = marks;
    out.lines = lines;
    out.verbs = vec![verb];
    out.topology = Some(topology);
    out.refresh_ms = Some(if report.running { RUNNING_MS } else { IDLE_MS });
    out
}

impl crate::SshPlugin {
    /// The vault's keys and routes as the terminal reads them, and `~/.ssh/config`.
    async fn with_view<T>(&self, f: impl FnOnce(crate::terminal::View<'_>) -> T) -> anyhow::Result<T> {
        let inner = self.inner.lock().await;
        let (entries, table) = (inner.entries.clone(), inner.table.clone());
        drop(inner);
        let ssh = crate::terminal::sshconfig::shared().await?;
        Ok(f(crate::terminal::View { entries: &entries, table: &table, ssh: &ssh }))
    }
}

#[async_trait::async_trait]
impl keyward_ui::Ui for crate::SshPlugin {
    /// The section's screens are the window's own TypeScript for now; only the
    /// path is declared.
    async fn view(&self, _host: &dyn keyward_plugin::Host, route: &str) -> anyhow::Result<keyward_ui::Page> {
        anyhow::bail!("the ssh plugin declares no screen \"{route}\": only its places")
    }

    async fn act(&self, host: &dyn keyward_plugin::Host, op: &str, payload: Value, _form: Value) -> anyhow::Result<keyward_ui::Reply> {
        match op {
            CHECK_OP => {
                let inner = self.inner.lock().await;
                let (entries, table) = (inner.entries.clone(), inner.table.clone());
                drop(inner);
                let ssh = crate::terminal::sshconfig::shared().await?;
                let view = crate::terminal::View { entries: &entries, table: &table, ssh: &ssh };
                match self.terminals.call(host, self.core(), view, "health_run", payload).await {
                    Some(answer) => answer.map(|_| keyward_ui::Reply::refresh()),
                    None => anyhow::bail!("the terminal no longer checks keys"),
                }
            }
            other => anyhow::bail!("the ssh plugin's places have no action \"{other}\""),
        }
    }

    async fn places(&self, _host: &dyn keyward_plugin::Host) -> anyhow::Result<Places> {
        let report = self.with_view(|view| self.terminals.health(&view)).await?;
        Ok(declare(&report))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::terminal::health::KeyHealth;

    fn check(host: &str, port: u16, user: Option<&str>, status: Status) -> Check {
        Check { host: host.into(), port, user: user.map(str::to_string), status, latency_ms: Some(12), detail: None, fingerprint: None, checked_at: Some(1), checking: false, note: None, aliases: Vec::new(), server: None }
    }

    /// Made-up data: a prod key one host refuses, a staging key that gets in,
    /// a key bound to nothing.
    fn report() -> Report {
        let mut refused = check("db-1.prod.example", 2222, Some("root"), Status::Rejected);
        refused.detail = Some("err.sshKeyRejected".into());
        refused.fingerprint = Some("SHA256:b81K".into());
        let mut odd = check("api.prod.example", 22, Some("ubuntu"), Status::Unreachable);
        odd.detail = Some("err.sshUnreachable {\"host\":\"api.prod.example\",\"reason\":\"timed out\"}".into());
        Report {
            keys: vec![
                KeyHealth { entry_id: "k-prod".into(), entry_name: "prod".into(), status: Status::Rejected, checks: vec![refused, odd] },
                KeyHealth { entry_id: "k-stage".into(), entry_name: "staging".into(), status: Status::Ok, checks: vec![check("bastion.staging.example", 22, Some("ubuntu"), Status::Ok), check("db-1.prod.example", 2222, Some("root"), Status::Ok)] },
                KeyHealth { entry_id: "k-none".into(), entry_name: "spare".into(), status: Status::Unbound, checks: Vec::new() },
            ],
            running: false,
            checked_at: Some(1),
        }
    }

    #[test]
    fn the_places_hold_together() {
        let p = declare(&report());
        p.check().unwrap();
        // The worst first: the refused host, the unreachable one, the good one.
        let hosts: Vec<&str> = p.places.iter().filter(|x| x.parent.as_deref() == Some("hosts")).map(|x| x.id.as_str()).collect();
        assert_eq!(hosts, ["host/db-1.prod.example:2222", "host/api.prod.example:22", "host/bastion.staging.example:22"]);
        let db = p.places.iter().find(|x| x.id == "host/db-1.prod.example:2222").unwrap();
        assert_eq!(db.level, Level::Critical);
        assert_eq!(db.subtitle, Some(Text::raw("root@ · 2222")));
        assert_eq!(p.root.level, Level::Critical);
        assert_eq!(p.places.iter().find(|x| x.id == "keys").unwrap().kids.len(), 3);
        // Two keys check db-1: the verb there checks both.
        let verb = &p.verbs[0];
        let on_db = verb.uses.iter().find(|u| u.on == Target::Place(db.id.clone())).unwrap();
        assert_eq!(on_db.action.payload, Value::Null);
        let on_bastion = verb.uses.iter().find(|u| u.on == Target::Place("host/bastion.staging.example:22".into())).unwrap();
        assert_eq!(on_bastion.action.payload, json!({ "entry_id": "k-stage" }));
        // The key with no checks is not on the map; the refused line is loud.
        let t = p.topology.as_ref().unwrap();
        assert!(!t.points.iter().any(|x| x.at == Target::Item("k-none".into())));
        assert!(t.edges.iter().any(|e| e.kind == EdgeKind::Refused && e.level == Some(Loud::Critical)));
        assert_eq!(p.marks.iter().find(|m| m.item == "k-prod").unwrap().level, Level::Critical);
        assert_eq!(p.refresh_ms, Some(IDLE_MS));
    }

    #[test]
    fn a_failure_is_said_in_the_dictionary_s_words() {
        assert_eq!(detail_text("err.sshKeyRejected"), k("err.sshKeyRejected"));
        assert_eq!(detail_text("err.sshUnreachable {\"host\":\"h\"}"), Text::key_with("err.sshUnreachable", json!({ "host": "h" })));
        // A code the dictionary does not know, and a plain message, as they are.
        // Built at run time: written whole, the repo's key scanner would take
        // it for a raised key with no words.
        let unknown = ["err", "nobodyKnows"].join(".");
        assert_eq!(detail_text(&unknown), Text::raw(&unknown));
        assert_eq!(detail_text("connection reset"), Text::raw("connection reset"));
    }

    #[test]
    fn every_word_is_in_both_dictionaries() {
        let mut keys = BTreeSet::new();
        keyward_ui::places::keys(&serde_json::to_value(declare(&report())).unwrap(), &mut keys);
        let empty = Report { keys: Vec::new(), running: true, checked_at: None };
        keyward_ui::places::keys(&serde_json::to_value(declare(&empty)).unwrap(), &mut keys);
        for (lang, file) in [("en", include_str!("../i18n/en.json")), ("ru", include_str!("../i18n/ru.json"))] {
            let words: BTreeMap<String, Value> = serde_json::from_str(file).unwrap();
            for key in &keys {
                assert!(words.contains_key(key), "the {lang} dictionary lacks \"{key}\"");
            }
        }
    }

    #[tokio::test]
    async fn the_window_gets_the_places_sealed_and_a_lock_forgets_the_road() {
        use keyward_plugin::{HostEvent, Plugin};
        use keyward_ssh_client::link::testing::Page;
        crate::tests::sandbox();
        let host = keyward_plugin::testing::StrictHost::new();
        let p = crate::SshPlugin::new();
        let page = Page::new();
        let linked = p.call(&host, "ui_link", json!({ "public": page.hello })).await.unwrap();
        let (mut input, _) = page.finish(linked["public"].as_str().unwrap());
        let link = linked["link"].as_str().unwrap().to_string();

        let sealed = input.seal(br#"{"kind":"places"}"#);
        let answer = p.call(&host, "ui", json!({ "link": link, "lane": "input", "sealed": sealed })).await.unwrap();
        assert!(answer.get("root").is_none(), "the places travel sealed, never in the clear");
        let opened: Value = serde_json::from_slice(&input.open(answer["sealed"].as_str().unwrap())).unwrap();
        assert_eq!(opened["root"]["title"], json!({ "key": "plugin.ssh.title" }));
        assert_eq!(opened["verbs"][0]["id"], CHECK);

        // A screen is not declared: asked for, it is refused in words.
        let sealed = input.seal(br#"{"kind":"view","route":""}"#);
        let answer = p.call(&host, "ui", json!({ "link": link, "lane": "input", "sealed": sealed })).await.unwrap();
        let opened = String::from_utf8_lossy(&input.open(answer["sealed"].as_str().unwrap())).to_string();
        assert!(opened.contains("only its places"), "{opened}");

        p.on_event(&host, HostEvent::Locked).await;
        let sealed = input.seal(br#"{"kind":"places"}"#);
        assert!(p.call(&host, "ui", json!({ "link": link, "lane": "input", "sealed": sealed })).await.is_err());
    }

    #[test]
    fn an_empty_vault_still_declares_its_places() {
        let p = declare(&Report { keys: Vec::new(), running: true, checked_at: None });
        p.check().unwrap();
        assert_eq!(p.root.level, Level::Unknown);
        assert_eq!(p.refresh_ms, Some(RUNNING_MS));
    }
}
