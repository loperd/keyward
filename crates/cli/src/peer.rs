//! Who is at the other end of the socket: the checks live in the core, where
//! the client uses them too — to make sure it is talking to our own daemon.

pub use keyward_core::peer::*;
