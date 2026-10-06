//! The stand's record of a plugin's screens: every route and every action
//! reachable from the section's column, each with the answer the plugin gives
//! it on made-up data. The stand in the window answers from this record, so
//! the screens photographed there are the plugin's own — built by its Rust,
//! drawn by the window's kit — and no plugin code lives in the window.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde_json::{json, Value};

/// What the stand serves for one plugin.
#[derive(Debug, Default)]
pub struct Record {
    views: BTreeMap<String, Value>,
    acts: Vec<Value>,
}

impl Record {
    pub fn to_json(&self) -> Value {
        json!({ "views": self.views, "acts": self.acts })
    }

    pub fn views(&self) -> impl Iterator<Item = (&String, &Value)> {
        self.views.iter()
    }

    pub fn acts(&self) -> &[Value] {
        &self.acts
    }
}

/// An action inside a declared value: any object with an `op`.
fn actions(v: &Value, out: &mut Vec<(String, Value)>) {
    match v {
        Value::Object(o) => {
            if let Some(Value::String(op)) = o.get("op") {
                out.push((op.clone(), o.get("payload").cloned().unwrap_or(Value::Null)));
            }
            o.values().for_each(|x| actions(x, out));
        }
        Value::Array(a) => a.iter().for_each(|x| actions(x, out)),
        _ => {}
    }
}

/// Routes a value leads to: the column's entries and the replies' `go`.
fn routes(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Object(o) => {
            for key in ["route", "go"] {
                if let Some(Value::String(r)) = o.get(key) {
                    out.push(r.clone());
                }
            }
            o.values().for_each(|x| routes(x, out));
        }
        Value::Array(a) => a.iter().for_each(|x| routes(x, out)),
        _ => {}
    }
}

/// Walks everything reachable from the section's first screen (`""`). `view` answers a route, `act` an
/// action; `None` is an action the stand does not play (it is left out, and
/// the stand says so when it is pressed).
pub fn crawl(mut view: impl FnMut(&str) -> Option<Value>, mut act: impl FnMut(&str, &Value) -> Option<Value>) -> Record {
    let mut record = Record::default();
    let mut seen_routes = BTreeSet::new();
    let mut seen_acts = BTreeSet::new();
    let mut queue = VecDeque::from([json!({ "route": "" })]);
    while let Some(v) = queue.pop_front() {
        let mut found = Vec::new();
        routes(&v, &mut found);
        for r in found {
            if seen_routes.insert(r.clone()) {
                if let Some(page) = view(&r) {
                    queue.push_back(page.clone());
                    record.views.insert(r, page);
                }
            }
        }
        let mut found = Vec::new();
        actions(&v, &mut found);
        for (op, payload) in found {
            if seen_acts.insert(format!("{op} {payload}")) {
                if let Some(reply) = act(&op, &payload) {
                    queue.push_back(reply.clone());
                    record.acts.push(json!({ "op": op, "payload": payload, "reply": reply }));
                }
            }
        }
    }
    record
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn everything_reachable_is_recorded_once() {
        let record = crawl(
            |_| Some(json!({ "switcher": { "items": [{ "route": "a" }] }, "actions": [{ "op": "open", "payload": { "x": 1 } }, { "op": "open", "payload": { "x": 1 } }] })),
            |op, _| (op == "open").then(|| json!({ "go": "b" })),
        );
        let routes: Vec<&String> = record.views().map(|(r, _)| r).collect();
        assert_eq!(routes, ["", "a", "b"]);
        assert_eq!(record.acts().len(), 1);
    }
}
