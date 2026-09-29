//! Passkeys over the control socket: offering, signing in, registering.
//!
//! The rules here are stricter than for passwords, and on purpose:
//!
//! - **Touch ID for every use**, with no window of trust and no silent path
//!   for a verified peer. A signature is a sign-in on somebody's behalf; one
//!   touch must never cover two.
//! - The prompt names **the site and the account**. The site is the checked
//!   `rpId`, not whatever the page said; the account name a page sends at a
//!   registration is cleaned of control and direction characters and cut
//!   short, so that it cannot dress itself up as another site.
//! - Everything that can be refused is refused **before** the sensor: a bad
//!   origin, a passkey that does not fit, one the site already knows. Touch ID
//!   that pops up for a request that could never succeed teaches a person to
//!   touch without reading.
//! - **One prompt at a time.** A page that fires requests in a loop gets a
//!   refusal, not a queue of prompts.
//! - After the finger the vault is **taken afresh**: if it was locked or the
//!   account was switched meanwhile, locking wins.
//! - The private key never leaves the daemon; a log gets the origin only.

use std::sync::atomic::{AtomicBool, Ordering};

use keyward_core::passkey::{Register, SignIn, SignInWith, Registered, SignedIn};
use keyward_core::proto::Response;
use keyward_vault::Vault;

use crate::daemon::{decide, Shared, Step};
use crate::peer::Peer;

/// Whether a passkey prompt is on screen right now.
static PROMPT_OPEN: AtomicBool = AtomicBool::new(false);

/// Holds the one prompt slot while it lives.
struct PromptSlot;

impl PromptSlot {
    fn take() -> anyhow::Result<Self> {
        PROMPT_OPEN
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| Self)
            .map_err(|_| keyward_core::fault!("err.passkeyBusy"))
    }
}

impl Drop for PromptSlot {
    fn drop(&mut self) {
        PROMPT_OPEN.store(false, Ordering::Release);
    }
}

/// What a passkey operation demands of the peer: always the sensor, and
/// nobody gets it any other way — not even a peer that would get a password
/// silently.
fn gate(peer: &Peer) -> anyhow::Result<()> {
    match decide(peer, true, false, true, false) {
        Step::Ask => Ok(()),
        Step::Deny(text) => anyhow::bail!("{text}"),
        // A peer that would be let through without a finger (a built-in
        // plugin's event) has no business with passkeys at all.
        Step::Give => Err(keyward_core::fault!("err.passkeyNotForPlugins")),
    }
}

/// A name that came from outside, fit for a system prompt: no control
/// characters, no direction overrides or invisible joiners, at most 64
/// characters.
fn clean(name: &str) -> String {
    let bidi = |c: char| {
        matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}')
    };
    let out: String = name.chars().filter(|c| !c.is_control() && !bidi(*c)).take(64).collect();
    out.trim().to_string()
}

/// The active vault, cloned for one request, with its account's id.
async fn active(shared: &Shared) -> anyhow::Result<(Vault, String)> {
    let st = shared.lock().await;
    let vault = st.active().ok_or_else(|| keyward_core::fault!("err.noAccount"))?;
    Ok((vault.clone(), vault.account().id.clone()))
}


/// Asks the sensor, off the async threads: a finger can take a minute.
async fn touch(peer: &Peer, reason: String) -> anyhow::Result<()> {
    gate(peer)?;
    let _slot = PromptSlot::take()?;
    match tokio::task::spawn_blocking(move || keyward_vault::biometric::confirm(&reason)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(anyhow::anyhow!(
            "{}",
            keyward_core::text::t("err.notConfirmed", &[("reason", &e.to_string())])
        )),
        Err(e) => Err(anyhow::anyhow!("the Touch ID task fell over: {e}")),
    }
}

pub(crate) async fn offers(shared: &Shared, sign_in: SignIn) -> Response {
    let run = async {
        let (req, _) = keyward_vault::passkey::prepare_sign_in(&sign_in)?;
        let (vault, _) = active(shared).await?;
        if !matches!(vault.state(), keyward_core::VaultState::Unlocked { .. }) {
            return Err(keyward_core::fault!("err.vaultLocked"));
        }
        anyhow::Ok(vault.passkey_offers(&req))
    };
    match run.await {
        Ok(offers) => Response::PasskeyOffers { offers },
        Err(e) => Response::error(e),
    }
}

pub(crate) async fn homes(shared: &Shared, sign_in: SignIn) -> Response {
    let run = async {
        let (req, _) = keyward_vault::passkey::prepare_sign_in(&sign_in)?;
        let (vault, _) = active(shared).await?;
        if !matches!(vault.state(), keyward_core::VaultState::Unlocked { .. }) {
            return Err(keyward_core::fault!("err.vaultLocked"));
        }
        anyhow::Ok(vault.passkey_homes(&req.rp_id))
    };
    match run.await {
        Ok(homes) => Response::PasskeyHomes { homes },
        Err(e) => Response::error(e),
    }
}

pub(crate) async fn sign_in(shared: &Shared, peer: &Peer, request: SignInWith) -> Response {
    let run = async {
        gate(peer)?;
        let (req, client_data_json) = keyward_vault::passkey::prepare_sign_in(&request.sign_in)?;
        let (vault, account) = active(shared).await?;
        let offer = vault
            .passkey_offers(&req)
            .into_iter()
            .find(|o| o.entry_id == request.entry_id && o.credential_id == request.credential_id)
            .ok_or_else(|| keyward_core::fault!("err.passkeyGone"))?;
        drop(vault);

        let user = offer.user_name.as_deref().or(offer.user_display_name.as_deref()).map(clean);
        let reason = match user.filter(|u| !u.is_empty()) {
            Some(user) => keyward_core::text::t("touch.passkeySignIn", &[("site", &req.rp_id), ("user", &user)]),
            None => keyward_core::text::t("touch.passkeySignInPlain", &[("site", &req.rp_id)]),
        };
        touch(peer, reason).await?;

        let vault = crate::daemon::vault_after_touch(shared, &account).await?;
        let assertion = vault.passkey_assert(&offer.entry_id, &offer.credential_id, &req, true).await?;
        tracing::info!(site = %req.rp_id, "signed in with a passkey");
        anyhow::Ok(SignedIn { assertion, client_data_json })
    };
    match run.await {
        Ok(signed) => Response::PasskeySignedIn { signed },
        Err(e) => Response::error(e),
    }
}

pub(crate) async fn register(shared: &Shared, peer: &Peer, request: Register) -> Response {
    let run = async {
        gate(peer)?;
        let (req, client_data_json) = keyward_vault::passkey::prepare_register(&request)?;
        let (vault, account) = active(shared).await?;
        vault.passkey_check(&req, &request.target)?;
        drop(vault);

        let user = req.user_name.as_deref().or(req.user_display_name.as_deref()).map(clean);
        let reason = match user.filter(|u| !u.is_empty()) {
            Some(user) => keyward_core::text::t("touch.passkeyRegister", &[("site", &req.rp_id), ("user", &user)]),
            None => keyward_core::text::t("touch.passkeyRegisterPlain", &[("site", &req.rp_id)]),
        };
        touch(peer, reason).await?;

        let vault = crate::daemon::vault_after_touch(shared, &account).await?;
        let attestation = vault.passkey_create(&req, &request.target, true).await?;
        tracing::info!(site = %req.rp_id, "a passkey was registered");
        let _ = shared.lock().await.reload();
        anyhow::Ok(Registered { attestation, client_data_json })
    };
    match run.await {
        Ok(registered) => Response::PasskeyRegistered { registered },
        Err(e) => Response::error(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::Trust;

    fn socket(trust: Trust) -> Peer {
        Peer::Socket { pid: 1, path: None, trust }
    }

    #[test]
    fn every_use_asks_the_sensor_and_nobody_gets_around_it() {
        assert!(gate(&socket(Trust::Ours)).is_ok(), "ours: asked, never given silently");
        assert!(gate(&socket(Trust::Unknown)).is_ok(), "an unsigned build: asked");
        assert!(gate(&socket(Trust::Alien)).is_err(), "an outsider: refused");
        assert!(gate(&Peer::External).is_err(), "an external plugin: refused");
        assert!(gate(&Peer::Builtin).is_err(), "a built-in plugin: refused, not waved through");
    }

    #[test]
    fn only_one_prompt_at_a_time() {
        let first = PromptSlot::take().expect("the slot is free");
        assert!(PromptSlot::take().is_err(), "a second request is refused, not queued");
        drop(first);
        assert!(PromptSlot::take().is_ok(), "freed once the prompt is gone");
    }

    #[test]
    fn a_name_from_a_page_cannot_dress_up_the_prompt() {
        assert_eq!(clean("me@example.com"), "me@example.com");
        assert_eq!(clean("a\nb\tc"), "abc");
        assert_eq!(clean("\u{202e}moc.knab\u{202c}"), "moc.knab");
        assert_eq!(clean("x\u{200b}y"), "xy");
        assert_eq!(clean(&"a".repeat(200)).len(), 64);
    }
}
