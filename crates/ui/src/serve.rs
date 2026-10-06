//! The road between the window and a plugin's declared screens.
//!
//! Two operations a plugin answers through this server: `ui_link` makes a
//! sealed link with the page, `ui` carries one request on it — a screen, an
//! action, or the plugin's places on the window's path. Everything the
//! window asks — the section's column, a screen, an action — and everything
//! the plugin answers travels sealed: a screen may hold a log, a manifest, a
//! secret field. The plugin itself sees only routes and actions.

use serde::Deserialize;
use serde_json::Value;

use crate::links::{Hello, Links, Sealed};
use crate::places::Places;
use crate::view::{Page, Reply};

/// What a plugin with declared screens implements.
#[async_trait::async_trait]
pub trait Ui: Send + Sync {
    /// A screen by its route. `""` is the section's first screen.
    async fn view(&self, host: &dyn keyward_plugin::Host, route: &str) -> anyhow::Result<Page>;
    /// What an action does. `form` holds what the person filled in, when the
    /// action sends a form.
    async fn act(&self, host: &dyn keyward_plugin::Host, op: &str, payload: Value, form: Value) -> anyhow::Result<Reply>;
    /// What the plugin adds to the window's path. Only a plugin whose
    /// manifest says `places` is asked; the default refuses, so a manifest
    /// that promises places without them fails loudly.
    async fn places(&self, _host: &dyn keyward_plugin::Host) -> anyhow::Result<Places> {
        anyhow::bail!("this plugin declares no places")
    }
}

/// One request inside `ui`.
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Request {
    View { route: String },
    Act {
        op: String,
        #[serde(default)]
        payload: Value,
        #[serde(default)]
        form: Value,
    },
    Places,
}

#[derive(Default)]
pub struct UiServer {
    links: Links,
}

impl UiServer {
    /// Answers `ui_link` and `ui`; `None` for any other operation, which is
    /// the plugin's own.
    pub async fn call(&self, ui: &dyn Ui, host: &dyn keyward_plugin::Host, op: &str, payload: Value) -> Option<anyhow::Result<Value>> {
        match op {
            "ui_link" => Some(
                serde_json::from_value::<Hello>(payload)
                    .map_err(|e| anyhow::anyhow!("a link was asked for with something else: {e}"))
                    .and_then(|h| self.links.accept(&h))
                    .and_then(|l| Ok(serde_json::to_value(l)?)),
            ),
            "ui" => Some(self.sealed(ui, host, payload).await),
            _ => None,
        }
    }

    async fn sealed(&self, ui: &dyn Ui, host: &dyn keyward_plugin::Host, payload: Value) -> anyhow::Result<Value> {
        let a: Sealed = serde_json::from_value(payload).map_err(|e| anyhow::anyhow!("not a sealed request: {e}"))?;
        let plain = self.links.open(&a)?;
        let request: Request = serde_json::from_slice(&plain).map_err(|e| anyhow::anyhow!("the window sent something other than a ui request: {e}"))?;
        drop(plain);
        let answer: anyhow::Result<Value> = match request {
            Request::View { route } => ui.view(host, &route).await.and_then(|v: Page| Ok(serde_json::to_value(v)?)),
            Request::Act { op, payload, form } => ui.act(host, &op, payload, form).await.and_then(|v: Reply| Ok(serde_json::to_value(v)?)),
            Request::Places => match ui.places(host).await {
                Ok(p) => p.check().and_then(|()| Ok(serde_json::to_value(p)?)),
                Err(e) => Err(e),
            },
        };
        match answer {
            Ok(v) => self.links.seal(&a, &v),
            Err(e) => self.links.seal_error(&a, &e),
        }
    }

    /// The vault was locked: every link is forgotten.
    pub fn lock(&self) {
        self.links.clear();
    }
}
