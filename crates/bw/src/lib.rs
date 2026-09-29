//! Our own Bitwarden client.
//!
//! It is being written so as not to depend on `rbw` entirely: its model loses
//! the trash, favourites, organisation names and collections, and its api
//! client cannot edit ssh keys. The cryptography still comes from `rbw` — it is
//! common and well tried; everything else moves here bit by bit.

pub mod account;
pub mod client;
pub mod crypto;
pub mod folders;
pub mod model;
pub mod orgs;
pub mod sync;

pub use model::Sync;
