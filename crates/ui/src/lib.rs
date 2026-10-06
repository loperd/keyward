//! Declared screens: a plugin says what a screen is, keyward draws it.
//!
//! - `view` — the vocabulary: pages, lists, tables with facets, tabs, forms,
//!   the checked editor, the terminal, the danger zone, actions.
//! - `serve` — the road: the sealed link and the requests on it.
//! - `link`, `links` — the sealed link between a page and a plugin (ECDH
//!   P-256, HKDF-SHA256, AES-256-GCM, two lanes with a counter each).
//! - `stand` — a plugin's screens recorded on made-up data, for the stand.
//! - `places` — what a plugin adds to the window's path: its places, their
//!   levels and rows and pages, its verbs and its map.

pub mod link;
pub mod links;
pub mod places;
pub mod serve;
pub mod stand;
pub mod view;

pub use serve::{Ui, UiServer};
pub use view::*;
