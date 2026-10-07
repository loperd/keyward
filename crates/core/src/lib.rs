//! The keyward core: accounts, vault entries, the daemon protocol and
//! settings. It knows nothing of ssh, of HashiCorp or of the GUI: all of that
//! lives in plugins (`crates/plugins`), which the core sees through a single
//! protocol envelope.

pub mod account;
pub mod accounts;
pub mod channel;
pub mod client;
pub mod detail;
pub mod edits;
pub mod fault;
pub mod generator;
pub mod harden;
pub mod items;
pub mod merge;
pub mod passkey;
pub mod paths;
pub mod peer;
pub mod proto;
pub mod region;
pub mod settings;
pub mod source;
pub mod text;
pub mod two_factor;
pub mod vault_state;

pub use vault_state::VaultState;
