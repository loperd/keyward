//! The plugin's places on the window's path: Kubernetes → a cluster, and
//! Kubernetes → Servers → a server the vault's keys reach, with the map of
//! keys → servers → clusters. Built from the overview — what was found when
//! the servers were last looked at — without opening anything; opening a
//! cluster stays the section's declared screen.

use keyward_ui::places::{
    Block, Doc, Edge, EdgeKind, Find, FindGroup, Kid, Level, LegendEntry, Line, Loud, MapFinding, Mark, Place, Places, Point, Preview, Section, Target, Topology, Use, Verb,
};
use keyward_ui::{Action, Text};
use serde_json::json;

use crate::detect::Access;
use crate::ui::{cluster_id, distro_word, error_text, group_of, place_json};
use crate::{Look, Overview, ServerRow};
use keyward_ssh_client::targets::Missing;

/// The verb that looks at the servers for clusters: the word a person types.
pub const LOOK: &str = "find clusters";

/// How often the window asks again while servers are being looked at.
const LOOKING_MS: u64 = 1500;

fn k(key: &str) -> Text {
    Text::key(key)
}

fn server_id(s: &ServerRow) -> String {
    format!("server/{}|{}|{}", s.machine.entry_id, s.machine.host, s.machine.port)
}

fn loud(l: Level) -> Option<Loud> {
    match l {
        Level::Critical => Some(Loud::Critical),
        Level::Action | Level::Warning => Some(Loud::Warning),
        _ => None,
    }
}

fn access_level(a: Access) -> Level {
    match a {
        Access::Readable => Level::Healthy,
        Access::Sudo => Level::Warning,
        Access::Denied => Level::Critical,
    }
}

fn access_word(a: Access) -> Text {
    k(match a {
        Access::Readable => "kube.access.readable",
        Access::Sudo => "kube.access.sudo",
        Access::Denied => "kube.access.denied",
    })
}

/// A server's level and why, by what can be done about it.
fn server_state(s: &ServerRow) -> (Level, Text) {
    let missing = || {
        k(match s.machine.missing.as_slice() {
            [Missing::Login] => "kube.missing.login",
            [Missing::Port] => "kube.missing.port",
            _ => "kube.missing.both",
        })
    };
    if s.looking {
        return (Level::Unknown, k("kube.status.looking"));
    }
    match group_of(s) {
        "unset" if !s.machine.missing.is_empty() => (Level::Action, missing()),
        "unset" => (Level::Unknown, k("kube.status.proxied")),
        "unchecked" => (Level::Unknown, k("kube.status.notChecked")),
        "ready" => match &s.look {
            Some(Look::Seen { found, .. }) => (Level::worst_of(found.iter().map(|f| access_level(f.access))), Text::key_with("kube.status.found", json!({ "n": found.len() }))),
            _ => (Level::Healthy, k("kube.group.ready")),
        },
        "attention" => (Level::Warning, k("kube.status.hostUnknown")),
        "broken" => match &s.look {
            Some(Look::Failed { error, .. }) => (Level::Warning, said(error)),
            _ => (Level::Warning, k("kube.status.failed")),
        },
        _ => match &s.look {
            Some(Look::CommandOnly { .. }) => (Level::Healthy, k("kube.status.commandOnly")),
            _ => (Level::Healthy, k("kube.status.none")),
        },
    }
}

/// A failure's code the dictionary knows, in words; any other text as it is.
fn said(error: &str) -> Text {
    static KEYS: std::sync::OnceLock<std::collections::BTreeSet<String>> = std::sync::OnceLock::new();
    let keys = KEYS.get_or_init(|| {
        let words: std::collections::BTreeMap<String, serde_json::Value> = serde_json::from_str(include_str!("../i18n/en.json")).expect("the plugin's dictionary is JSON");
        words.into_keys().collect()
    });
    match error_text(error) {
        Text::Key { key, .. } if !keys.contains(&key) => Text::raw(error),
        t => t,
    }
}

fn login(s: &ServerRow) -> String {
    let port = if s.machine.port != 0 && s.machine.port != 22 { format!(":{}", s.machine.port) } else { String::new() };
    format!("{}{}{port}", s.machine.user.as_deref().map(|u| format!("{u}@")).unwrap_or_default(), s.machine.host)
}

/// The places, from the overview.
pub(crate) fn declare(o: &Overview) -> Places {
    let mut places = Vec::new();
    let mut clusters: Vec<(String, Level)> = Vec::new();
    let mut lines = Vec::new();
    let mut edges = Vec::new();
    let mut points: Vec<Point> = Vec::new();
    let mut keys_on_map: Vec<String> = Vec::new();

    // Clusters in the vault's notes: a kubeconfig, opened as it is.
    for n in &o.notes {
        let id = format!("cluster/{}", n.id);
        let mut p = Place::under(None, id.clone(), "lock", Text::raw(&n.name), Level::Healthy);
        p.subtitle = Some(k("kube.kind.kubeconfig"));
        p.find = Some(Find { group: FindGroup::Clusters, kind: "cluster".into(), words: n.name.clone() });
        p.page = Some(Doc { what: Some(k("kube.kind.kubeconfig")), sections: vec![Section { title: k("kube.context"), count: None, blocks: vec![Block::Para { text: k("kube.source.note") }] }], ..Doc::default() });
        places.push(p);
        clusters.push((id, Level::Healthy));
    }

    // The servers, and the clusters found on them.
    let mut groups: Vec<(&'static str, Vec<String>)> = ["attention", "broken", "unset", "ready", "unchecked", "none"].iter().map(|g| (*g, Vec::new())).collect();
    let mut server_levels = Vec::new();
    let mut loud_servers = Vec::new();
    for s in &o.servers {
        let sid = server_id(s);
        let (level, why) = server_state(s);
        server_levels.push(level);
        if loud(level).is_some() {
            loud_servers.push((sid.clone(), level, s.machine.host.clone(), why.clone()));
        }
        let group = match group_of(s) {
            "attention" | "broken" | "unset" | "ready" | "unchecked" => group_of(s),
            _ => "none",
        };
        groups.iter_mut().find(|(g, _)| *g == group).expect("every group is listed").1.push(sid.clone());

        let mut p = Place::under(Some("servers"), sid.clone(), "server", Text::raw(login(s)), level);
        let mut sub = s.machine.entry_name.clone();
        if !s.aliases.is_empty() {
            sub = format!("{sub} · {}", s.aliases.join(", "));
        }
        p.subtitle = Some(Text::raw(sub));
        p.mono = true;
        p.why = Some(why.clone());
        p.short = Some(why.clone());
        let mut found_here = Vec::new();
        if let Some(Look::Seen { found, .. }) = &s.look {
            for f in found {
                let cid = format!("cluster/{}", cluster_id(s, f.kind));
                let lvl = access_level(f.access);
                let mut c = Place::under(None, cid.clone(), "cube", Text::raw(&s.machine.host), lvl);
                c.subtitle = Some(distro_word(f.kind));
                c.mono = true;
                c.why = Some(access_word(f.access));
                c.short = Some(access_word(f.access));
                c.find = Some(Find { group: FindGroup::Clusters, kind: "cluster".into(), words: format!("{} {}", s.machine.host, s.machine.entry_name) });
                c.page = Some(Doc {
                    what: Some(distro_word(f.kind)),
                    state: Some(Mark { level: lvl, text: access_word(f.access) }),
                    sections: vec![Section {
                        title: k("kube.viaSsh"),
                        count: None,
                        blocks: vec![
                            Block::Ref { to: Target::Place(sid.clone()), title: None, context: None, mark: None, mono: true },
                            Block::Ref { to: Target::Item(s.machine.entry_id.clone()), title: None, context: None, mark: None, mono: false },
                        ],
                    }],
                    ..Doc::default()
                });
                places.push(c);
                clusters.push((cid.clone(), lvl));
                found_here.push(Block::Ref { to: Target::Place(cid.clone()), title: None, context: Some(distro_word(f.kind)), mark: Some(Mark { level: lvl, text: access_word(f.access) }), mono: true });
                edges.push(Edge { a: Target::Place(sid.clone()), b: Target::Place(cid.clone()), kind: EdgeKind::In, level: loud(lvl), words: distro_word(f.kind), chip: false });
                points.push(Point { at: Target::Place(cid), lane: 2 });
            }
        }
        let mut sections = vec![Section {
            title: k("kube.servers"),
            count: None,
            blocks: vec![
                Block::Field { label: k("kube.col.keys"), value: Text::raw(&s.machine.entry_name), mono: false, mark: None },
                Block::Ref { to: Target::Item(s.machine.entry_id.clone()), title: None, context: None, mark: None, mono: false },
            ],
        }];
        if !found_here.is_empty() {
            sections.insert(0, Section { title: k("kube.clusters"), count: Some(found_here.len()), blocks: found_here });
        }
        p.page = Some(Doc { what: Some(Text::raw(&s.machine.entry_name)), primary: Some(LOOK.into()), sections, map: true, ..Doc::default() });
        places.push(p);

        lines.push(Line { from: sid.clone(), item: s.machine.entry_id.clone(), kind: EdgeKind::Route, level: loud(level), words: k("kube.viaSsh"), short: k("kube.viaSsh") });
        if !keys_on_map.contains(&s.machine.entry_id) {
            keys_on_map.push(s.machine.entry_id.clone());
        }
        edges.push(Edge { a: Target::Item(s.machine.entry_id.clone()), b: Target::Place(sid.clone()), kind: EdgeKind::Route, level: loud(level), words: why, chip: level == Level::Critical });
        points.push(Point { at: Target::Place(sid), lane: 1 });
    }
    points.extend(keys_on_map.iter().map(|id| Point { at: Target::Item(id.clone()), lane: 0 }));

    let servers_level = Level::worst_of(server_levels.iter().copied());
    let mut sp = Place::under(None, "servers", "server", k("kube.servers"), servers_level);
    sp.count = Some(o.servers.len());
    sp.wide = true;
    for (g, ids) in &groups {
        if ids.is_empty() {
            continue;
        }
        sp.kids.push(Kid::Heading { title: k(&format!("kube.group.{g}")) });
        sp.kids.extend(ids.iter().map(|id| Kid::Place { id: id.clone(), sub: None }));
    }
    sp.page = Some(Doc {
        primary: Some(LOOK.into()),
        map: true,
        sections: vec![Section { title: k("kube.servers"), count: Some(o.servers.len()), blocks: vec![Block::Para { text: k(if o.servers.is_empty() { "kube.noServers.body" } else { "kube.serversExplain" }) }] }],
        ..Doc::default()
    });

    let overall = Level::worst_of(clusters.iter().map(|(_, l)| *l).chain(server_levels.iter().copied()));
    let mut root = Place::root("cube", Text::raw("Kubernetes"), overall);
    root.hue = Some("sky".into());
    root.wide = true;
    root.subtitle = Some(Text::key_with("kube.status.found", json!({ "n": clusters.len() })));
    if let Some((_, _, _, why)) = loud_servers.iter().min_by_key(|(_, l, _, _)| *l) {
        root.why = Some(why.clone());
        root.short = Some(why.clone());
    }
    root.kids = clusters.iter().map(|(id, _)| Kid::Place { id: id.clone(), sub: None }).collect();
    root.kids.extend([Kid::Gap, Kid::Place { id: "servers".into(), sub: None }, Kid::Place { id: "map".into(), sub: None }]);
    let mut overview: Vec<Block> = loud_servers.iter().map(|(id, level, host, why)| Block::Finding { level: *level, title: Text::raw(host), sub: Some(why.clone()), to: Some(Target::Place(id.clone())) }).collect();
    if clusters.is_empty() {
        overview.push(Block::Para { text: k("kube.noClustersYet") });
    }
    root.page = Some(Doc {
        primary: Some(LOOK.into()),
        map: true,
        sections: vec![
            Section { title: k("kube.clusters"), count: Some(clusters.len()), blocks: overview },
            Section { title: k("kube.servers"), count: None, blocks: vec![Block::MapDoor { title: k("kube.servers"), sub: k("kube.serversExplain") }] },
        ],
        note: Some(k("plugin.kube.description")),
        ..Doc::default()
    });

    let mut mp = Place::under(None, "map", "map", k("kube.servers"), overall);
    mp.subtitle = Some(k("kube.serversExplain"));
    mp.map = true;
    places.push(sp);
    places.push(mp);

    let mut uses = vec![Use { on: Target::Place(String::new()), action: Action::op("scan") }, Use { on: Target::Place("servers".into()), action: Action::op("scan") }];
    uses.extend(o.servers.iter().map(|s| Use { on: Target::Place(server_id(s)), action: Action::with("look", json!({ "place": place_json(s) })) }));
    let verb = Verb {
        id: LOOK.into(),
        name: k("kube.scan"),
        icon: Some("refresh".into()),
        uses,
        preview: Preview { lede: k("kube.serversExplain"), steps: Vec::new(), go: k("kube.scan"), note: Some(k("kube.openingSsh")), danger: false },
    };

    let topology = Topology {
        title: k("kube.clusters"),
        place: Text::raw("Kubernetes"),
        lanes: vec![k("kube.col.keys"), k("kube.servers"), k("kube.clusters")],
        pivot: 1,
        points,
        edges,
        findings: loud_servers.iter().map(|(id, level, _, why)| MapFinding { level: *level, text: why.clone(), focus: Target::Place(id.clone()) }).collect(),
        legend: vec![LegendEntry { kind: EdgeKind::Route, level: None, text: k("kube.viaSsh") }, LegendEntry { kind: EdgeKind::In, level: None, text: k("kube.clusters") }],
    };

    let mut out = Places::new(root);
    out.places = places;
    out.lines = lines;
    out.verbs = vec![verb];
    out.topology = Some(topology);
    out.refresh_ms = (o.scanning || o.servers.iter().any(|s| s.looking)).then_some(LOOKING_MS);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::{Found, Kind as Distro};
    use crate::NoteRow;
    use std::collections::{BTreeMap, BTreeSet};

    fn server(host: &str, look: Option<Look>) -> ServerRow {
        ServerRow {
            machine: keyward_ssh_client::targets::Machine {
                entry_id: "key-1".into(),
                entry_name: "prod key".into(),
                host: host.into(),
                address: host.into(),
                port: 22,
                user: Some("root".into()),
                pin: None,
                proxy: None,
                missing: Vec::new(),
            },
            look,
            looking: false,
            aliases: Vec::new(),
        }
    }

    /// Made-up data: a master on one server, a server whose key is unknown,
    /// one never looked at, one with no login, and a kubeconfig note.
    fn overview() -> Overview {
        let mut unset = server("bare.example", None);
        unset.machine.missing = vec![Missing::Login];
        Overview {
            servers: vec![
                server("k3s.example", Some(Look::Seen { found: vec![Found { kind: Distro::K3s, access: Access::Readable }, Found { kind: Distro::Kubeadm, access: Access::Denied }], at: 1, machine: None, peer: None })),
                server("new.example", Some(Look::HostUnknown { fingerprint: "SHA256:x".into(), algorithm: "ssh-ed25519".into(), at: 1, peer: None })),
                server("idle.example", None),
                unset,
            ],
            notes: vec![NoteRow { id: "note|n1".into(), entry_id: "n1".into(), name: "staging".into() }],
            local_contexts: Vec::new(),
            local_error: None,
            broken: Vec::new(),
            scanning: false,
        }
    }

    #[test]
    fn the_places_hold_together() {
        let p = declare(&overview());
        p.check().unwrap();
        let ids: Vec<&str> = p.places.iter().map(|x| x.id.as_str()).collect();
        assert!(ids.contains(&"cluster/note|n1"));
        assert!(ids.contains(&"cluster/ssh|key-1|k3s.example|22|k3s"));
        let denied = p.places.iter().find(|x| x.id == "cluster/ssh|key-1|k3s.example|22|kubeadm").unwrap();
        assert_eq!(denied.level, Level::Critical);
        assert_eq!(p.root.level, Level::Critical);
        let unset = p.places.iter().find(|x| x.id == "server/key-1|bare.example|22").unwrap();
        assert_eq!((unset.level, unset.why.clone()), (Level::Action, Some(k("kube.missing.login"))));
        // The servers' column is grouped, the worst first.
        let servers = p.places.iter().find(|x| x.id == "servers").unwrap();
        assert_eq!(servers.kids[0], Kid::Heading { title: k("kube.group.attention") });
        // The map: one key, four servers, two masters.
        let t = p.topology.as_ref().unwrap();
        assert_eq!(t.points.iter().filter(|x| x.lane == 0).count(), 1);
        assert_eq!(t.points.iter().filter(|x| x.lane == 1).count(), 4);
        assert_eq!(t.points.iter().filter(|x| x.lane == 2).count(), 2);
        assert_eq!(p.refresh_ms, None, "nothing is being looked at: no need to ask again");
        let look = p.verbs[0].uses.iter().find(|u| u.on == Target::Place("server/key-1|idle.example|22".into())).unwrap();
        assert_eq!(look.action.op, "look");
    }

    #[test]
    fn every_word_is_in_both_dictionaries() {
        let mut keys = BTreeSet::new();
        keyward_ui::places::keys(&serde_json::to_value(declare(&overview())).unwrap(), &mut keys);
        let empty = Overview { servers: Vec::new(), notes: Vec::new(), local_contexts: Vec::new(), local_error: None, broken: Vec::new(), scanning: true };
        keyward_ui::places::keys(&serde_json::to_value(declare(&empty)).unwrap(), &mut keys);
        for (lang, file) in [("en", include_str!("../i18n/en.json")), ("ru", include_str!("../i18n/ru.json"))] {
            let words: BTreeMap<String, serde_json::Value> = serde_json::from_str(file).unwrap();
            for key in &keys {
                assert!(words.contains_key(key), "the {lang} dictionary lacks \"{key}\"");
            }
        }
    }

    #[test]
    fn an_empty_vault_still_declares_its_places() {
        let p = declare(&Overview { servers: Vec::new(), notes: Vec::new(), local_contexts: Vec::new(), local_error: None, broken: Vec::new(), scanning: true });
        p.check().unwrap();
        assert_eq!(p.refresh_ms, Some(LOOKING_MS));
    }
}
