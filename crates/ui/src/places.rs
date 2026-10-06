//! What a plugin adds to the window's path, said as data.
//!
//! The window is a path of places a person steps through — the vault, an
//! organisation, a folder, an item. A plugin adds places of its own under the
//! root (SSH → Hosts → db-1) and says, for each, what it is called, how it
//! stands, what lies under it and what its page shows; the window builds the
//! steps, the search, the maps and the pages from that with its own kit. The
//! plugin ships no code for any of it.
//!
//! Ids are the plugin's own and stable from one answer to the next: the
//! window keeps a person's path across answers by them. A place's home is the
//! chain of its parents up to the plugin's root.
//!
//! Every word is a key of the plugin's dictionary or a value as it is, the
//! same `Text` the declared screens use.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::view::{Action, Text};

/// How a place stands, in the window's five levels.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord, Default)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    Critical,
    Action,
    Warning,
    Healthy,
    #[default]
    Unknown,
}

impl Level {
    /// The worse of two.
    pub fn worst(self, other: Self) -> Self {
        self.min(other)
    }
    /// The worst of many; `Unknown` for none.
    pub fn worst_of(levels: impl IntoIterator<Item = Self>) -> Self {
        let mut it = levels.into_iter();
        match it.next() {
            Some(first) => it.fold(first, Self::worst),
            None => Self::Unknown,
        }
    }
}

/// A level and its words: the state on a page, a mark on a line.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Mark {
    pub level: Level,
    pub text: Text,
}

/// Something a line, a row or a point is about: one of the plugin's places,
/// or a vault item by its id.
#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Target {
    Place(String),
    Item(String),
}

/// A row under a place.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Kid {
    /// A step to one of the plugin's places; `sub` replaces its second line
    /// here.
    Place {
        id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        sub: Option<Text>,
    },
    /// A step to a vault item.
    Item {
        id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        sub: Option<Text>,
    },
    /// A caption over the rows that follow.
    Heading { title: Text },
    /// A breath between kinds of rows.
    Gap,
}

/// What a search finds a place as.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindGroup {
    Hosts,
    Clusters,
}

/// A place a filter can find: its group, a kind word (`host`, `cluster`) and
/// the words it is found by.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Find {
    pub group: FindGroup,
    pub kind: String,
    pub words: String,
}

/// A line's kind: its weight and dash on a map.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    In,
    Svc,
    Token,
    Route,
    Refused,
}

/// A line's colour where it repeats a mark.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Loud {
    Critical,
    Warning,
}

/// A line from one of the plugin's places to a vault item: what the item's
/// relations show beyond the vault's own (a host takes this key).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Line {
    pub from: String,
    pub item: String,
    pub kind: EdgeKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<Loud>,
    pub words: Text,
    pub short: Text,
}

/// What the plugin found about a vault item: it stands at this level, for
/// this reason (a key a host refused).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ItemMark {
    pub item: String,
    pub level: Level,
    pub why: Text,
    pub short: Text,
}

/// One block of a page.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Block {
    /// A label and a value.
    Field {
        label: Text,
        value: Text,
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        mono: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        mark: Option<Mark>,
    },
    /// A line to a place or an item; its title is the target's name unless
    /// given.
    Ref {
        to: Target,
        #[serde(skip_serializing_if = "Option::is_none")]
        title: Option<Text>,
        #[serde(skip_serializing_if = "Option::is_none")]
        context: Option<Text>,
        #[serde(skip_serializing_if = "Option::is_none")]
        mark: Option<Mark>,
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        mono: bool,
    },
    /// A finding: its level, words, a quiet reason, where it points.
    Finding {
        level: Level,
        title: Text,
        #[serde(skip_serializing_if = "Option::is_none")]
        sub: Option<Text>,
        #[serde(skip_serializing_if = "Option::is_none")]
        to: Option<Target>,
    },
    Para { text: Text },
    /// The door to the plugin's map.
    MapDoor { title: Text, sub: Text },
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Section {
    pub title: Text,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<usize>,
    pub blocks: Vec<Block>,
}

/// A place's page. The head is the window's: the place's tile, name, home and
/// level; the plugin says what it is, its main verb and the rest, and the
/// sections. A place without a page gets the head and its rows.
#[derive(Debug, Clone, Serialize, PartialEq, Default)]
pub struct Doc {
    /// A quiet word of what it is, under the name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub what: Option<Text>,
    /// The state in the head, over the place's own `why`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<Mark>,
    /// The main verb, by its id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary: Option<String>,
    /// Further verbs, by their ids.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub more: Vec<String>,
    /// Offer the plugin's map beside the verbs.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub map: bool,
    pub sections: Vec<Section>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<Text>,
}

/// One place.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Place {
    /// Stable, unique in the plugin; empty for the plugin's root.
    pub id: String,
    /// The place it lives under; `None` is the plugin's root.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    /// The URL's word for it; the window makes one from the title when absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slug: Option<String>,
    pub icon: String,
    pub title: Text,
    /// The shorter name a row shows where its column says the rest.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub row_title: Option<Text>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subtitle: Option<Text>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<usize>,
    pub level: Level,
    /// Why it stands at its level, in words; `short` is the same in a word.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub why: Option<Text>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub short: Option<Text>,
    /// Its name is a machine's word: a host, a cluster.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub mono: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub sub_mono: bool,
    /// Its rows carry a second line worth reading.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub wide: bool,
    /// The tile's colour, for the root: one of the window's hues.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hue: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub kids: Vec<Kid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub find: Option<Find>,
    /// The row is the plugin's map, not a place with rows.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub map: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page: Option<Doc>,
}

impl Place {
    /// The plugin's root.
    pub fn root(icon: &str, title: Text, level: Level) -> Self {
        Self::new("", icon, title, level)
    }
    /// A place under `parent` (`None`: under the root).
    pub fn under(parent: Option<&str>, id: impl Into<String>, icon: &str, title: Text, level: Level) -> Self {
        let mut p = Self::new(id, icon, title, level);
        p.parent = Some(parent.unwrap_or("").to_string());
        p
    }
    fn new(id: impl Into<String>, icon: &str, title: Text, level: Level) -> Self {
        Self {
            id: id.into(),
            parent: None,
            slug: None,
            icon: icon.to_string(),
            title,
            row_title: None,
            subtitle: None,
            count: None,
            level,
            why: None,
            short: None,
            mono: false,
            sub_mono: false,
            wide: false,
            hue: None,
            kids: Vec::new(),
            find: None,
            map: false,
            page: None,
        }
    }
}

/// Where a verb applies, and what it does there.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Use {
    pub on: Target,
    pub action: Action,
}

/// A verb's preview: what will happen, before ↵.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Preview {
    pub lede: Text,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub steps: Vec<(Text, Text)>,
    pub go: Text,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<Text>,
    /// It takes something away.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub danger: bool,
}

/// A verb a line can end with: one of the plugin's actions, previewed.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Verb {
    /// The word a person types: `check keys`.
    pub id: String,
    pub name: Text,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    pub uses: Vec<Use>,
    pub preview: Preview,
}

/// A point of the map.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Point {
    pub at: Target,
    pub lane: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Edge {
    pub a: Target,
    pub b: Target,
    pub kind: EdgeKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<Loud>,
    pub words: Text,
    /// Its words stand on the line always.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub chip: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct MapFinding {
    pub level: Level,
    pub text: Text,
    pub focus: Target,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct LegendEntry {
    pub kind: EdgeKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<Loud>,
    pub text: Text,
}

/// The plugin's map: points in lanes and the lines between them (keys →
/// hosts → clusters).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Topology {
    pub title: Text,
    /// Where it is of, in words.
    pub place: Text,
    pub lanes: Vec<Text>,
    /// The lane spread evenly.
    pub pivot: usize,
    pub points: Vec<Point>,
    pub edges: Vec<Edge>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<MapFinding>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub legend: Vec<LegendEntry>,
}

/// Everything a plugin adds to the path.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Places {
    pub root: Place,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub places: Vec<Place>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub marks: Vec<ItemMark>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub lines: Vec<Line>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub verbs: Vec<Verb>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topology: Option<Topology>,
    /// Ask again in this many milliseconds: a round filling in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_ms: Option<u64>,
}

impl Places {
    pub fn new(root: Place) -> Self {
        Self { root, places: Vec::new(), marks: Vec::new(), lines: Vec::new(), verbs: Vec::new(), topology: None, refresh_ms: None }
    }

    /// Whether the declaration holds together: the root is the root, every id
    /// is unique and lives under a place that exists, without a loop; every
    /// row, line, verb and point names a place that exists; a map row has a
    /// map to show. Checked before an answer goes out, so a broken one fails
    /// in the plugin, by name, rather than as a blank column in the window.
    /// Items are the vault's and are checked by the window.
    pub fn check(&self) -> anyhow::Result<()> {
        let r = &self.root;
        anyhow::ensure!(r.id.is_empty() && r.parent.is_none(), "the root place has an id or a parent");
        let mut parents: BTreeMap<&str, &str> = BTreeMap::new();
        for p in &self.places {
            anyhow::ensure!(!p.id.is_empty(), "a place under the root has no id");
            let parent = p.parent.as_deref().ok_or_else(|| anyhow::anyhow!("the place \"{}\" has no parent", p.id))?;
            anyhow::ensure!(parents.insert(&p.id, parent).is_none(), "the place \"{}\" is declared twice", p.id);
        }
        let known = |id: &str| id.is_empty() || parents.contains_key(id);
        for (id, parent) in &parents {
            anyhow::ensure!(known(parent), "the place \"{id}\" lives under \"{parent}\", which is not declared");
            let mut seen = BTreeSet::new();
            let mut at = *id;
            while !at.is_empty() {
                anyhow::ensure!(seen.insert(at), "the place \"{id}\" lives under itself");
                at = parents[at];
            }
        }
        let place = |t: &Target, what: &str| match t {
            Target::Place(id) if !known(id) => Err(anyhow::anyhow!("{what} names the place \"{id}\", which is not declared")),
            _ => Ok(()),
        };
        for p in std::iter::once(r).chain(&self.places) {
            for k in &p.kids {
                if let Kid::Place { id, .. } = k {
                    place(&Target::Place(id.clone()), &format!("a row of \"{}\"", p.id))?;
                }
            }
            anyhow::ensure!(!p.map || self.topology.is_some(), "the place \"{}\" is a map row and there is no map", p.id);
            if let Some(doc) = &p.page {
                for v in doc.primary.iter().chain(&doc.more) {
                    let verb = self.verbs.iter().find(|x| &x.id == v).ok_or_else(|| anyhow::anyhow!("the page of \"{}\" offers the verb \"{v}\", which is not declared", p.id))?;
                    let here = Target::Place(p.id.clone());
                    anyhow::ensure!(verb.uses.iter().any(|u| u.on == here), "the page of \"{}\" offers the verb \"{v}\", which does not apply there", p.id);
                }
                anyhow::ensure!(!doc.map || self.topology.is_some(), "the page of \"{}\" offers a map and there is none", p.id);
                for s in &doc.sections {
                    for b in &s.blocks {
                        match b {
                            Block::Ref { to, .. } | Block::Finding { to: Some(to), .. } => place(to, &format!("the page of \"{}\"", p.id))?,
                            _ => {}
                        }
                    }
                }
            }
        }
        for l in &self.lines {
            anyhow::ensure!(!l.from.is_empty() && known(&l.from), "a line comes from \"{}\", which is not declared", l.from);
        }
        let mut verbs = BTreeSet::new();
        for v in &self.verbs {
            anyhow::ensure!(!v.id.trim().is_empty() && v.id == v.id.trim(), "a verb's word is empty or padded: \"{}\"", v.id);
            anyhow::ensure!(verbs.insert(&v.id), "the verb \"{}\" is declared twice", v.id);
            let mut on = BTreeSet::new();
            for u in &v.uses {
                place(&u.on, &format!("the verb \"{}\"", v.id))?;
                anyhow::ensure!(on.insert(&u.on), "the verb \"{}\" applies twice to {:?}", v.id, u.on);
            }
        }
        if let Some(t) = &self.topology {
            let mut points = BTreeSet::new();
            for p in &t.points {
                place(&p.at, "a point of the map")?;
                anyhow::ensure!(p.lane < t.lanes.len(), "a point of the map stands in lane {} of {}", p.lane, t.lanes.len());
                anyhow::ensure!(points.insert(&p.at), "the map shows {:?} twice", p.at);
            }
            anyhow::ensure!(t.pivot < t.lanes.len().max(1), "the map's pivot lane {} is not one of its lanes", t.pivot);
            for e in &t.edges {
                anyhow::ensure!(points.contains(&e.a) && points.contains(&e.b), "a line of the map joins {:?} and {:?}, which are not both on it", e.a, e.b);
            }
            for f in &t.findings {
                anyhow::ensure!(points.contains(&f.focus), "a finding of the map points at {:?}, which is not on it", f.focus);
            }
        }
        Ok(())
    }
}

/// Every dictionary key a value declares (`{"key": …}` anywhere in it): what
/// a plugin's test checks against its dictionaries.
pub fn keys(v: &serde_json::Value, out: &mut BTreeSet<String>) {
    match v {
        serde_json::Value::Object(o) => {
            if let Some(serde_json::Value::String(k)) = o.get("key") {
                out.insert(k.clone());
            }
            o.values().for_each(|x| keys(x, out));
        }
        serde_json::Value::Array(a) => a.iter().for_each(|x| keys(x, out)),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample() -> Places {
        let mut root = Place::root("terminal", Text::key("p.title"), Level::Critical);
        root.kids = vec![Kid::Place { id: "hosts".into(), sub: None }, Kid::Gap, Kid::Place { id: "map".into(), sub: None }];
        let mut hosts = Place::under(None, "hosts", "server", Text::key("p.hosts"), Level::Critical);
        hosts.kids = vec![Kid::Heading { title: Text::raw("prod") }, Kid::Place { id: "host/db-1".into(), sub: None }, Kid::Item { id: "key-1".into(), sub: None }];
        let mut db = Place::under(Some("hosts"), "host/db-1", "server", Text::raw("db-1"), Level::Critical);
        db.find = Some(Find { group: FindGroup::Hosts, kind: "host".into(), words: "db-1 root".into() });
        db.page = Some(Doc { primary: Some("check".into()), map: true, ..Doc::default() });
        let mut map = Place::under(None, "map", "map", Text::key("p.map"), Level::Critical);
        map.map = true;
        let mut p = Places::new(root);
        p.places = vec![hosts, db, map];
        p.verbs = vec![Verb {
            id: "check".into(),
            name: Text::key("p.check"),
            icon: Some("refresh".into()),
            uses: vec![Use { on: Target::Place("".into()), action: Action::op("run") }, Use { on: Target::Place("host/db-1".into()), action: Action::op("run") }, Use { on: Target::Item("key-1".into()), action: Action::with("run", json!({ "entry_id": "key-1" })) }],
            preview: Preview { lede: Text::key("p.lede"), steps: vec![], go: Text::key("p.check"), note: None, danger: false },
        }];
        p.lines = vec![Line { from: "host/db-1".into(), item: "key-1".into(), kind: EdgeKind::Refused, level: Some(Loud::Critical), words: Text::raw("refused"), short: Text::raw("refused") }];
        p.topology = Some(Topology {
            title: Text::key("p.map"),
            place: Text::key("p.title"),
            lanes: vec![Text::raw("keys"), Text::raw("hosts")],
            pivot: 1,
            points: vec![Point { at: Target::Item("key-1".into()), lane: 0 }, Point { at: Target::Place("host/db-1".into()), lane: 1 }],
            edges: vec![Edge { a: Target::Item("key-1".into()), b: Target::Place("host/db-1".into()), kind: EdgeKind::Refused, level: Some(Loud::Critical), words: Text::raw("x"), chip: true }],
            findings: vec![],
            legend: vec![],
        });
        p
    }

    #[test]
    fn a_whole_declaration_holds() {
        sample().check().unwrap();
    }

    #[test]
    fn it_rides_the_wire_in_the_shape_the_window_reads() {
        let v = serde_json::to_value(sample()).unwrap();
        assert_eq!(v["root"]["id"], "");
        assert!(v["root"].get("parent").is_none(), "the root has no parent on the wire");
        assert_eq!(v["places"][0]["parent"], "", "a place under the root names the root as \"\"");
        assert_eq!(v["places"][1]["parent"], "hosts");
        assert_eq!(v["places"][0]["kids"][0], json!({ "type": "heading", "title": { "raw": "prod" } }));
        assert_eq!(v["places"][0]["kids"][2], json!({ "type": "item", "id": "key-1" }));
        assert_eq!(v["root"]["kids"][1], json!({ "type": "gap" }));
        assert_eq!(v["places"][1]["level"], "critical");
        assert_eq!(v["places"][1]["find"]["group"], "hosts");
        assert_eq!(v["verbs"][0]["uses"][2]["on"], json!({ "item": "key-1" }));
        assert_eq!(v["verbs"][0]["uses"][0]["on"], json!({ "place": "" }));
        assert_eq!(v["topology"]["edges"][0]["kind"], "refused");
        assert_eq!(v["lines"][0]["level"], "critical");
        let mut ks = BTreeSet::new();
        keys(&v, &mut ks);
        assert!(ks.contains("p.lede") && ks.contains("p.title") && !ks.contains("prod"));
    }

    #[test]
    fn a_broken_declaration_fails_by_name() {
        let cases: Vec<(&str, Box<dyn Fn(&mut Places)>)> = vec![
            ("declared twice", Box::new(|p| p.places.push(p.places[0].clone()))),
            ("not declared", Box::new(|p| p.places[1].parent = Some("nowhere".into()))),
            ("lives under itself", Box::new(|p| p.places[0].parent = Some("host/db-1".into()))),
            ("a row of", Box::new(|p| p.root.kids.push(Kid::Place { id: "ghost".into(), sub: None }))),
            ("offers the verb", Box::new(|p| p.places[1].page.as_mut().unwrap().more.push("ghost".into()))),
            ("does not apply there", Box::new(|p| p.verbs[0].uses.retain(|u| u.on != Target::Place("host/db-1".into())))),
            ("there is n", Box::new(|p| p.topology = None)),
            ("stands in lane", Box::new(|p| p.topology.as_mut().unwrap().points[0].lane = 9)),
            ("not both on it", Box::new(|p| p.topology.as_mut().unwrap().points.pop().map(|_| ()).unwrap_or(()))),
            ("applies twice", Box::new(|p| { let u = p.verbs[0].uses[0].clone(); p.verbs[0].uses.push(u) })),
            ("has an id or a parent", Box::new(|p| p.root.id = "root".into())),
            ("a line comes from", Box::new(|p| p.lines[0].from = "ghost".into())),
        ];
        for (want, spoil) in cases {
            let mut p = sample();
            spoil(&mut p);
            let e = p.check().expect_err(want).to_string();
            assert!(e.contains(want), "expected \"{want}\", got \"{e}\"");
        }
    }

    #[test]
    fn the_worst_level_wins() {
        assert_eq!(Level::worst_of([Level::Healthy, Level::Warning, Level::Unknown]), Level::Warning);
        assert_eq!(Level::worst_of([Level::Healthy, Level::Critical]), Level::Critical);
        assert_eq!(Level::worst_of([]), Level::Unknown);
    }
}
