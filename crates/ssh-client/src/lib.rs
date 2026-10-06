//! Going to a server over ssh with a key the vault holds, for any plugin that
//! needs to.
//!
//! The private key never leaves the daemon: a login is signed by the core
//! through `sign_ssh`, and this crate only carries the signature to the
//! server. The pieces:
//!
//! - `glob`, `mapping`, `table` — the routes out of the items' `kw-*` fields.
//! - `sshconfig` — `~/.ssh/config`, read and never written.
//! - `hostkeys` — which host keys are trusted, and where that is written.
//! - `connect` — russh, the host key check and signing through the core.
//! - `probe` — what system answers on a port, from its banner alone.
//! - `link`, `links` — a page and its plugin seal what they carry end to end;
//!   the window and the daemon in between see ciphertext.
//! - `targets` — the servers the items reach, by name.
//! - `remote` — a login with an item's key, and commands run over it.
//! - `core` — the core's synchronous methods, safe to call from async code.

pub mod connect;
pub mod core;
pub mod glob;
pub mod hostkeys;
pub use keyward_ui::{link, links};
pub mod mapping;
pub mod probe;
pub mod remote;
pub mod sshconfig;
pub mod table;
pub mod targets;
