//! The core's synchronous methods, for asynchronous code.
//!
//! Over the stdio bridge a synchronous method stands its thread until the
//! daemon answers. The bridge runs each call on a thread of its own for that
//! reason — but a task spawned onto the runtime is not such a thread: were it
//! to stand, the runtime's workers would stop, and with them the reading of
//! the very answer. Hung once: every health check of the ssh plugin waited on
//! `entries()` inside a handshake, and the plugin went silent. From async code
//! the core is asked here, on a blocking thread.

use std::sync::Arc;

use keyward_plugin::{Host, VaultEntry};
use serde_json::Value;

async fn blocking<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> anyhow::Result<T> {
    tokio::task::spawn_blocking(work).await.map_err(|e| anyhow::anyhow!("a call to the core fell over: {e}"))
}

pub async fn entries(core: &Arc<dyn Host>) -> anyhow::Result<Vec<VaultEntry>> {
    let core = Arc::clone(core);
    blocking(move || core.entries()).await
}

pub async fn settings(core: &Arc<dyn Host>) -> anyhow::Result<Value> {
    let core = Arc::clone(core);
    blocking(move || core.settings()).await
}

pub async fn set_settings(core: &Arc<dyn Host>, value: Value) -> anyhow::Result<()> {
    let core = Arc::clone(core);
    blocking(move || core.set_settings(value)).await?
}
