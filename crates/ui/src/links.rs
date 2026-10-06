//! The links a plugin keeps with its pages: made, used, forgotten.
//!
//! A page makes a link per screen; the plugin keeps a bounded number of them
//! and drops the one nobody used for longest. What a request carries is opened
//! here and its answer sealed here, so a plugin's own code sees only plain
//! values.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::link::{Lane, Link};

/// How many pages may hold a link at once.
const MAX_LINKS: usize = 32;

/// A link nobody used for this long is dropped.
const LINK_IDLE: Duration = Duration::from_secs(60 * 60);

/// What a page sends to make a link.
#[derive(Deserialize)]
pub struct Hello {
    pub public: String,
}

/// The plugin's answer: the link's name and its public key.
#[derive(Serialize)]
pub struct Linked {
    pub link: String,
    pub public: String,
}

/// A sealed request on a link.
#[derive(Deserialize)]
pub struct Sealed {
    pub link: String,
    pub lane: Lane,
    pub sealed: String,
}

struct Slot {
    link: Link,
    used: Instant,
}

#[derive(Default)]
pub struct Links {
    slots: Mutex<HashMap<String, Slot>>,
}

fn broken() -> anyhow::Error {
    keyward_core::fault!("err.channelFailed")
}

fn new_id() -> String {
    let mut b = [0u8; 16];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl Links {
    /// Makes a link for a page.
    pub fn accept(&self, hello: &Hello) -> anyhow::Result<Linked> {
        let (link, public) = Link::accept(&hello.public)?;
        let id = new_id();
        let mut slots = self.slots.lock().map_err(|_| broken())?;
        slots.retain(|_, s| s.used.elapsed() < LINK_IDLE);
        while slots.len() >= MAX_LINKS {
            let Some(oldest) = slots.iter().min_by_key(|(_, s)| s.used).map(|(k, _)| k.clone()) else { break };
            slots.remove(&oldest);
        }
        slots.insert(id.clone(), Slot { link, used: Instant::now() });
        Ok(Linked { link: id, public })
    }

    /// Opens a request. One that does not open is refused in the clear: there
    /// is no key to seal an answer with that the page could trust.
    pub fn open(&self, a: &Sealed) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        let mut slots = self.slots.lock().map_err(|_| broken())?;
        let slot = slots.get_mut(&a.link).ok_or_else(|| keyward_core::fault!("err.linkGone"))?;
        let plain = slot.link.open(a.lane, &a.sealed)?;
        slot.used = Instant::now();
        Ok(plain)
    }

    /// Seals the answer to the request just opened on that lane.
    pub fn seal(&self, a: &Sealed, value: &impl Serialize) -> anyhow::Result<serde_json::Value> {
        let plain = Zeroizing::new(serde_json::to_vec(value)?);
        let mut slots = self.slots.lock().map_err(|_| broken())?;
        let slot = slots.get_mut(&a.link).ok_or_else(|| keyward_core::fault!("err.linkGone"))?;
        Ok(serde_json::json!({ "sealed": slot.link.seal(a.lane, &plain)? }))
    }

    /// A failure, sealed like any answer so the lane stays in step:
    /// `{"error": key}`.
    pub fn seal_error(&self, a: &Sealed, e: &anyhow::Error) -> anyhow::Result<serde_json::Value> {
        self.seal(a, &serde_json::json!({ "error": e.to_string() }))
    }

    /// Everything forgotten: the vault was locked.
    pub fn clear(&self) {
        if let Ok(mut s) = self.slots.lock() {
            s.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link::testing::Page;

    #[test]
    fn a_request_opens_and_its_answer_is_sealed_for_the_page_alone() {
        let links = Links::default();
        let page = Page::new();
        let linked = links.accept(&Hello { public: page.hello.clone() }).unwrap();
        let (mut input, _) = page.finish(&linked.public);
        let req = Sealed { link: linked.link.clone(), lane: Lane::Input, sealed: input.seal(b"{\"op\":\"x\"}") };
        assert_eq!(&links.open(&req).unwrap()[..], b"{\"op\":\"x\"}");
        let answer = links.seal(&req, &serde_json::json!({ "ok": 1 })).unwrap();
        assert_eq!(input.open(answer["sealed"].as_str().unwrap()), b"{\"ok\":1}");

        links.clear();
        assert!(links.open(&Sealed { link: linked.link, lane: Lane::Input, sealed: input.seal(b"{}") }).is_err());
    }
}
