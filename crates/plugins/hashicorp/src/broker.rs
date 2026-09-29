//! The broker for access to HashiCorp Vault.
//!
//! The ledger of issues holds **accessors only**: a token can be revoked by one
//! but cannot be used. The token itself is not saved — it goes to whoever asked
//! and lives for minutes.
//!
//! Everything needed from the vault goes through `Host`: the plugin asks for
//! the value of one field of one item, and the core decides whether to hand it
//! over.

use keyward_plugin::Host;

use crate::api::Client;
use crate::model::{
    IssueRequest, IssueResult, IssueState, Issued, KvConfig, Mount, MountForm, MountTune, Policy,
    RootProgress, RootToken, SealStatus, Secret, SecretMeta, SecretMetaPatch, POLICY_ADMIN,
};
use crate::store;

/// The ledger of issues: where it used to lie.
///
/// The local file is left for the sake of the move: the ledger has gone into
/// the vault item itself, so that issued access can be revoked from any
/// machine. The file is read once and removed after the move.
fn legacy_path() -> std::path::PathBuf {
    keyward_core::paths::base_dir().join("issued.json")
}

/// Every issue for the chosen connection.
pub async fn all(host: &dyn Host) -> Vec<Issued> {
    let Some(addr) = store::connection(host).await.map(|l| l.addr) else { return Vec::new() };
    if let Some(json) = store::issued_json(host, &addr).await {
        return serde_json::from_str(&json).unwrap_or_default();
    }
    // The move has not happened yet, so the old file is given out; the move
    // happens on the very first write.
    std::fs::read_to_string(legacy_path())
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

async fn save(host: &dyn Host, list: &[Issued]) -> anyhow::Result<()> {
    let addr = store::connection(host)
        .await
        .map(|l| l.addr)
        .ok_or_else(|| anyhow::anyhow!("{}", store::why_no_credentials(host)))?;
    store::store_issued(host, &addr, &serde_json::to_string(list)?).await?;
    // The move has happened: the local copy is of no further use and only
    // misleads.
    let _ = std::fs::remove_file(legacy_path());
    Ok(())
}

pub async fn remember(host: &dyn Host, issued: Issued) -> anyhow::Result<()> {
    let mut list = all(host).await;
    list.insert(0, issued);
    // The ledger must not grow for ever: expired records are kept for the
    // history, but hundreds of them are of use to nobody.
    list.truncate(200);
    save(host, &list).await
}

pub async fn mark(host: &dyn Host, accessor: &str, state: IssueState) -> anyhow::Result<()> {
    let mut list = all(host).await;
    let mut touched = false;
    for item in &mut list {
        if item.accessor == accessor {
            item.state = state.clone();
            touched = true;
        }
    }
    if !touched {
        return Ok(());
    }
    save(host, &list).await
}

/// Marks what has expired as expired and gives back the list.
pub async fn refresh_expired(host: &dyn Host) -> Vec<Issued> {
    let now = crate::api::now_secs();
    let mut list = all(host).await;
    let mut touched = false;
    for item in list.iter_mut() {
        if item.looks_expired(now) {
            item.state = IssueState::Expired;
            touched = true;
        }
    }
    if touched {
        let _ = save(host, &list).await;
        // The last token with the right to write policies has expired, so it
        // is time the policy itself went too.
        let _ = sweep_policy_admin(host).await;
    }
    list
}

/// The life of the `keyward-policy-admin` policy is tied to tokens: it is
/// needed exactly while a live token carrying it is in the ledger. As soon as
/// the last one has expired or been revoked, the policy is deleted from Vault —
/// Vault gives policies no lifetime, so we set one. Returns whether the policy
/// was deleted.
///
/// Only keyward's own issues are counted: a token with this policy issued by
/// somebody else loses the right at once — which is the intention, the policy is
/// not for outsiders.
pub async fn sweep_policy_admin(host: &dyn Host) -> anyhow::Result<bool> {
    let now = crate::api::now_secs();
    let alive = all(host).await.into_iter().any(|i| {
        i.state == IssueState::Active && !i.looks_expired(now) && i.policies.iter().any(|p| p == POLICY_ADMIN)
    });
    if alive {
        return Ok(false);
    }
    let client = client(host).await?;
    if !client.policies().await?.iter().any(|p| p == POLICY_ADMIN) {
        return Ok(false);
    }
    client.delete_policy(POLICY_ADMIN).await?;
    tracing::info!(policy = POLICY_ADMIN, "the policy was deleted: no live token carries it any more");
    Ok(true)
}

/// Builds a client out of a vault item: AppRole first, then a direct token.
pub async fn client(host: &dyn Host) -> anyhow::Result<Client> {
    let creds = store::credentials(host)
        .await
        .ok_or_else(|| anyhow::anyhow!("{}", store::why_no_credentials(host)))?;

    let mut client = Client::new(&creds.addr, creds.namespace.as_deref())?;

    match (creds.role_id.as_deref(), creds.secret_id.as_deref()) {
        (Some(role), Some(secret)) if !role.is_empty() && !secret.is_empty() => {
            client.login_approle(role, secret).await?;
        }
        _ => {
            let token = creds
                .token
                .filter(|t| !t.trim().is_empty())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "err.noVaultCredentials"
                    )
                })?;
            client = client.with_token(&token);
        }
    }

    Ok(client)
}

/// The server's state: what is visible without special rights.
pub async fn health(host: &dyn Host) -> anyhow::Result<crate::model::Health> {
    client(host).await?.health().await
}

/// Unsealing with the saved keys.
///
/// The keys are fed in one at a time until Vault says the threshold is made
/// up. No more than needed is sent: every extra key is one more chance for it
/// to leak into the server's logs.
///
/// The shares come from the window, read there by the person's own hand: the
/// daemon gives a plugin only its `kw-` fields, and the shares lie in fields a
/// person named. Without them, whatever the plugin could read itself is used.
pub async fn unseal(host: &dyn Host, shares: &[String]) -> anyhow::Result<SealStatus> {
    let creds = store::credentials(host)
        .await
        .ok_or_else(|| anyhow::anyhow!("{}", store::why_no_credentials(host)))?;
    let keys: Vec<String> = if shares.is_empty() {
        creds.unseal_keys.clone()
    } else {
        shares.iter().filter(|s| !s.trim().is_empty()).cloned().collect()
    };
    let client = Client::new(&creds.addr, creds.namespace.as_deref())?;

    let mut status = client.seal_status().await?;
    if !status.sealed {
        return Ok(status);
    }
    if keys.is_empty() {
        return Err(anyhow::anyhow!("err.noUnsealKeys"));
    }

    for key in &keys {
        status = client.unseal(key).await?;
        tracing::info!(progress = status.progress, threshold = status.t, "an unseal key was entered");
        if !status.sealed {
            break;
        }
    }

    if status.sealed {
        anyhow::bail!(
            crate::model::key(
                "err.notEnoughUnsealKeys",
                &[("entered", &status.progress.to_string()), ("needed", &status.t.to_string())],
            )
        );
    }
    Ok(status)
}

/// Checking an address before the connection has been saved.
///
/// With no token: `sys/seal-status` is open to everyone, which makes it
/// possible to learn the threshold before anything has been written into the
/// vault.
pub async fn probe(addr: &str) -> anyhow::Result<SealStatus> {
    Client::new(addr, None)?.seal_status().await
}

/// Generating a root token entirely inside the daemon.
///
/// The one-time key and the shares do not leave the process: the interface
/// gets only the progress. The finished token goes at once into a vault item —
/// the broker takes it from there, and nobody needs it on a screen.
pub async fn generate_root(
    host: &dyn Host,
    entry_id: &str,
    field_names: &[String],
    shares: &[String],
) -> anyhow::Result<RootProgress> {
    if field_names.is_empty() {
        return Err(anyhow::anyhow!("err.noUnsealFieldsChosen"));
    }

    // The address is taken from the connection's own item rather than from the
    // request.
    //
    // It used to arrive over the socket as it was: any process of the user could
    // name its own server, and the daemon would play the root-generation
    // protocol out with it, handing over the real shares of the unseal key in
    // the clear on the way. A threshold of three shares is enough to unseal the
    // Vault for ever, and revoking a root token saves nothing after that.
    let addr = store::connections(host)
        .await
        .into_iter()
        .find(|l| l.entry_id == entry_id)
        .map(|l| l.addr)
        .ok_or_else(|| anyhow::anyhow!("err.noVaultConnectionForItem"))?;
    // The Enterprise namespace: without it the request goes into the root one,
    // and "the server did not recognise the token" would mean something other
    // than it seems.
    let namespace = store::credentials(host).await.and_then(|c| c.namespace);

    // From the window when it sent them (see `unseal`), else what the plugin
    // could read itself.
    let shares: Vec<String> = if shares.is_empty() {
        store::note_values(host, entry_id, field_names).await
    } else {
        shares.iter().filter(|s| !s.trim().is_empty()).cloned().collect()
    };
    if shares.len() != field_names.len() {
        return Err(anyhow::anyhow!("err.someUnsealFieldsEmpty"));
    }

    let client = Client::new(&addr, namespace.as_deref())?;
    let (mut progress, otp) = client.generate_root_start().await?;
    tracing::info!(required = progress.required, "the generation of a root token has begun");

    for share in &shares {
        match client.generate_root_update(share, &progress.nonce, &otp).await {
            Ok(next) => progress = next,
            Err(e) => {
                // An unfinished attempt is not left behind: the next one would
                // run into "attempt already in progress" while this one hung
                // on.
                let _ = client.generate_root_cancel().await;
                return Err(e);
            }
        }
        if progress.complete {
            break;
        }
    }

    let Some(token) = progress.token.clone() else {
        // An unfinished attempt is not left hanging: otherwise the next one
        // runs into "attempt already in progress".
        let _ = client.generate_root_cancel().await;
        anyhow::bail!(
            crate::model::key(
                "err.notEnoughShares",
                &[("taken", &progress.progress.to_string()), ("needed", &progress.required.to_string())],
            )
        );
    };

    // Not into the same note the shares came from: a root token travels into a
    // hidden item of its own, which keyward's list does not show.
    //
    // If the write failed, the token already exists on the server, and a root
    // token has neither a deadline nor an owner: nobody will ever find it
    // again. So it is revoked at once with itself — and only if that failed too
    // do we shout that a live root token is left on the server.
    if let Err(e) = store::store_root_token(host, &addr, &token).await {
        let orphan = Client::new(&addr, namespace.as_deref())?.with_token(&token);
        return match orphan.revoke_self().await {
            Ok(()) => Err(e.context("err.rootNotSavedSoRevoked")),
            Err(second) => Err(anyhow::anyhow!(
                "err.rootStranded"
            )),
        };
    }
    tracing::info!("the root token was obtained and saved into a hidden item");

    // The token is not handed outwards.
    progress.token = None;
    Ok(progress)
}

pub async fn seal_status(host: &dyn Host) -> anyhow::Result<SealStatus> {
    let creds = store::credentials(host)
        .await
        .ok_or_else(|| anyhow::anyhow!("{}", store::why_no_credentials(host)))?;
    Client::new(&creds.addr, creds.namespace.as_deref())?.seal_status().await
}

pub async fn issue(host: &dyn Host, req: &IssueRequest) -> anyhow::Result<IssueResult> {
    let client = client(host).await?;
    let result = client.issue(req).await?;
    remember(host, result.issued.clone()).await?;
    tracing::info!(
        accessor = %result.issued.accessor,
        policies = ?result.issued.policies,
        ttl = result.issued.ttl_seconds,
        "access to Vault was issued"
    );
    Ok(result)
}

/// The root tokens of every connection, together with what the server says
/// about them.
///
/// Each is checked with itself through `lookup-self`: if Vault did not
/// recognise it, it has been revoked or has expired — and that is visible
/// without trying to do anything with it.
pub async fn root_tokens(host: &dyn Host) -> anyhow::Result<Vec<RootToken>> {
    let namespace = store::credentials(host).await.and_then(|c| c.namespace);
    let mut out = Vec::new();
    for (entry_id, addr, issued_at) in store::root_notes(host).await {
        let info = match store::root_token(host, &addr).await {
            Some(token) => match Client::new(&addr, namespace.as_deref()) {
                Ok(client) => client.with_token(&token).lookup_self().await.ok(),
                Err(_) => None,
            },
            None => None,
        };
        out.push(RootToken { entry_id, addr, issued_at, info });
    }
    Ok(out)
}

/// Revokes a root token on the server and takes it out of the item.
///
/// The order matters: the server first, the item after. The other way round
/// would leave a live root token nobody knows about any more.
pub async fn revoke_root(host: &dyn Host, addr: &str) -> anyhow::Result<()> {
    let token = store::root_token(host, addr)
        .await
        .ok_or_else(|| anyhow::anyhow!(crate::model::key("err.noRootTokenFor", &[("addr", addr)])))?;
    let namespace = store::credentials(host).await.and_then(|c| c.namespace);
    let client = Client::new(addr, namespace.as_deref())?.with_token(&token);
    match client.revoke_self().await {
        Ok(()) => {}
        Err(e) => {
            // A token the server no longer knows cannot be revoked with
            // anything — and there is no point keeping it in the item either.
            // The decision goes by the status code: an error's text is half the
            // body, and the server could write anything into it just to have us
            // erase the record of a live root token.
            let gone = matches!(
                crate::api::status_of(&e).map(|s| s.as_u16()),
                Some(400 | 403 | 404)
            );
            if !gone {
                return Err(e);
            }
            tracing::warn!(error = %e, "the server did not recognise the root token; taking the record away");
        }
    }
    store::forget_root(host, addr).await?;
    tracing::info!(%addr, "the root token was revoked");
    Ok(())
}

pub async fn policies(host: &dyn Host) -> anyhow::Result<Vec<String>> {
    client(host).await?.policies().await
}

pub async fn policy(host: &dyn Host, name: &str) -> anyhow::Result<Policy> {
    let name = check_policy_name(name)?;
    client(host).await?.policy(name).await
}

/// A policy name fit to go into a path.
///
/// The client escapes the name as well, but the check is needed here too: `..`
/// is made of permitted characters and in a path means "one level up". With one
/// such string a request would travel off `sys/policies/acl/` to anywhere — and
/// with the rights of whichever token the broker is working under, which is
/// often a root one.
fn check_policy_name(name: &str) -> anyhow::Result<&str> {
    let name = name.trim();
    if name.is_empty() {
        return Err(anyhow::anyhow!("err.policyNeedsName"));
    }
    if name.len() > 128 {
        return Err(anyhow::anyhow!("err.policyNameTooLong"));
    }
    if name.chars().any(|c| c == '/' || c == '\\') || name.split('.').any(|part| part.is_empty()) {
        return Err(anyhow::anyhow!("err.policyNameSlashes"));
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')) {
        return Err(anyhow::anyhow!("err.policyNameCharset"));
    }
    Ok(name)
}

pub async fn put_policy(host: &dyn Host, name: &str, rules: &str) -> anyhow::Result<()> {
    let name = check_policy_name(name)?;
    if rules.trim().is_empty() {
        return Err(anyhow::anyhow!("err.policyBodyEmpty"));
    }
    client(host).await?.put_policy(name, rules).await
}

pub async fn delete_policy(host: &dyn Host, name: &str) -> anyhow::Result<()> {
    let name = check_policy_name(name)?;
    if matches!(name, "root" | "default") {
        return Err(anyhow::anyhow!(crate::model::key("err.policyBuiltin", &[("name", name)])));
    }
    client(host).await?.delete_policy(name).await
}

pub async fn mounts(host: &dyn Host) -> anyhow::Result<Vec<Mount>> {
    client(host).await?.mounts().await
}

pub async fn auth_mounts(host: &dyn Host) -> anyhow::Result<Vec<Mount>> {
    client(host).await?.auth_mounts().await
}

pub async fn mount_enable(host: &dyn Host, form: &MountForm) -> anyhow::Result<()> {
    form.validate().map_err(|e| anyhow::anyhow!("{e}"))?;
    client(host).await?.mount_enable(form).await
}

pub async fn mount_disable(host: &dyn Host, path: &str, auth: bool) -> anyhow::Result<()> {
    let p = path.trim().trim_matches('/');
    if p.is_empty() {
        return Err(anyhow::anyhow!("err.enginePathMissing"));
    }
    if auth && (p == "auth/token" || p == "token") {
        return Err(anyhow::anyhow!("err.tokenAuthUndisableable"));
    }
    if !auth && ["sys", "identity", "cubbyhole"].contains(&p) {
        return Err(anyhow::anyhow!(crate::model::key("err.mountIsPartOfVault", &[("path", p)])));
    }
    client(host).await?.mount_disable(p, auth).await
}

pub async fn mount_tune(host: &dyn Host, path: &str, auth: bool, tune: &MountTune) -> anyhow::Result<()> {
    if path.trim().trim_matches('/').is_empty() {
        return Err(anyhow::anyhow!("err.enginePathMissing"));
    }
    if let Some(v) = tune.kv_version {
        if v != 2 {
            return Err(anyhow::anyhow!("err.kvOnlyToV2"));
        }
    }
    client(host).await?.mount_tune(path, auth, tune).await
}

pub async fn kv_config(host: &dyn Host, mount: &str) -> anyhow::Result<KvConfig> {
    let client = client(host).await?;
    let m = kv_mount(&client, mount).await?;
    if !m.kv2 {
        return Err(anyhow::anyhow!("err.kv1NoVersions"));
    }
    client.kv_config(&m.path).await
}

pub async fn kv_config_write(host: &dyn Host, mount: &str, cfg: &KvConfig) -> anyhow::Result<()> {
    if !cfg.delete_version_after.trim().is_empty()
        && cfg.delete_version_after.trim() != "0s"
        && !crate::model::is_duration(&cfg.delete_version_after)
    {
        return Err(anyhow::anyhow!("err.versionTtlFormat"));
    }
    let client = client(host).await?;
    let m = kv_mount(&client, mount).await?;
    if !m.kv2 {
        return Err(anyhow::anyhow!("err.kv1NoVersions"));
    }
    client.kv_config_write(&m.path, cfg).await
}

/// The engine at a path: whether it is kv and of which version. The daemon
/// decides, not the interface: where to write depends on the version, and there
/// is no reason to trust somebody else's flag here.
async fn kv_mount(client: &Client, mount: &str) -> anyhow::Result<Mount> {
    let mount = mount.trim_matches('/');
    if mount.is_empty() {
        return Err(anyhow::anyhow!("err.engineMissing"));
    }
    let found = client.mounts().await?.into_iter().find(|m| m.path == mount);
    match found {
        Some(m) if m.kind == "kv" || m.kind == "generic" => Ok(m),
        Some(m) => return Err(anyhow::anyhow!(crate::model::key("err.engineNotKv", &[("path", &m.path), ("kind", &m.kind)]))),
        None => return Err(anyhow::anyhow!(crate::model::key("err.engineAbsent", &[("mount", mount)]))),
    }
}

fn check_secret_path(path: &str) -> anyhow::Result<String> {
    let path = path.trim().trim_matches('/');
    if path.split('/').any(|s| s == "..") {
        return Err(anyhow::anyhow!("err.secretPathParent"));
    }
    if path.len() > 512 {
        return Err(anyhow::anyhow!("err.secretPathTooLong"));
    }
    Ok(path.to_string())
}

pub async fn secret_list(host: &dyn Host, mount: &str, path: &str) -> anyhow::Result<Vec<String>> {
    let path = check_secret_path(path)?;
    let client = client(host).await?;
    let m = kv_mount(&client, mount).await?;
    client.kv_list(&m.path, m.kv2, &path).await
}

pub async fn secret_read(
    host: &dyn Host,
    mount: &str,
    path: &str,
    version: Option<u64>,
) -> anyhow::Result<Secret> {
    let path = check_secret_path(path)?;
    if path.is_empty() {
        return Err(anyhow::anyhow!("err.secretNeedsPath"));
    }
    let client = client(host).await?;
    let m = kv_mount(&client, mount).await?;
    client.kv_read(&m.path, m.kv2, &path, version).await
}

async fn named(host: &dyn Host, mount: &str, path: &str) -> anyhow::Result<(Client, Mount, String)> {
    let path = check_secret_path(path)?;
    if path.is_empty() {
        return Err(anyhow::anyhow!("err.secretNeedsPath"));
    }
    let client = client(host).await?;
    let m = kv_mount(&client, mount).await?;
    Ok((client, m, path))
}

pub async fn secret_delete(host: &dyn Host, mount: &str, path: &str, permanent: bool) -> anyhow::Result<()> {
    let (client, m, path) = named(host, mount, path).await?;
    if permanent && m.kv2 {
        client.kv_metadata_delete(&m.path, &path).await
    } else {
        client.kv_delete(&m.path, m.kv2, &path).await
    }
}

pub async fn secret_undelete(host: &dyn Host, mount: &str, path: &str, version: u64) -> anyhow::Result<()> {
    let (client, m, path) = named(host, mount, path).await?;
    if !m.kv2 {
        return Err(anyhow::anyhow!("err.kv1NothingToUndelete"));
    }
    client.kv_undelete(&m.path, &path, &[version]).await
}

pub async fn secret_destroy(host: &dyn Host, mount: &str, path: &str, version: u64) -> anyhow::Result<()> {
    let (client, m, path) = named(host, mount, path).await?;
    if !m.kv2 {
        return Err(anyhow::anyhow!("err.kv1DestroyIsTheSecret"));
    }
    client.kv_destroy(&m.path, &path, &[version]).await
}

pub async fn secret_meta(host: &dyn Host, mount: &str, path: &str) -> anyhow::Result<SecretMeta> {
    let (client, m, path) = named(host, mount, path).await?;
    if !m.kv2 {
        // kv v1 has no metadata: an empty shell is given back so that the
        // interface does not tell "no versions" from "an error".
        return Ok(SecretMeta { mount: m.path, path, ..SecretMeta::default() });
    }
    client.kv_metadata(&m.path, &path).await
}

pub async fn secret_meta_write(
    host: &dyn Host,
    mount: &str,
    path: &str,
    patch: &SecretMetaPatch,
) -> anyhow::Result<()> {
    let (client, m, path) = named(host, mount, path).await?;
    if !m.kv2 {
        return Err(anyhow::anyhow!("err.kv1NoMetadata"));
    }
    if let Some(cm) = &patch.custom_metadata {
        if cm.keys().any(|k| k.trim().is_empty()) {
            return Err(anyhow::anyhow!("err.metadataFieldNeedsName"));
        }
    }
    client.kv_metadata_write(&m.path, &path, patch).await
}

pub async fn secret_write(
    host: &dyn Host,
    mount: &str,
    path: &str,
    data: &std::collections::BTreeMap<String, String>,
    cas: Option<u64>,
) -> anyhow::Result<()> {
    let path = check_secret_path(path)?;
    if path.is_empty() {
        return Err(anyhow::anyhow!("err.secretNeedsPath"));
    }
    if data.is_empty() {
        return Err(anyhow::anyhow!("err.secretEmpty"));
    }
    if data.keys().any(|k| k.trim().is_empty()) {
        return Err(anyhow::anyhow!("err.fieldNeedsName"));
    }
    let client = client(host).await?;
    let m = kv_mount(&client, mount).await?;
    client.kv_write(&m.path, m.kv2, &path, data, cas).await
}

pub async fn revoke(host: &dyn Host, accessor: &str) -> anyhow::Result<()> {
    let client = client(host).await?;
    client.revoke(accessor).await?;
    mark(host, accessor, IssueState::Revoked).await?;
    tracing::info!(accessor = %accessor, "the access was revoked");
    if let Err(e) = sweep_policy_admin(host).await {
        tracing::warn!(error = %e, "the keyward-policy-admin policy could not be checked after the revocation");
    }
    Ok(())
}

/// The folder the secret lay in: after a deletion the interface would re-read
/// it anyway.
pub fn parent_of(path: &str) -> String {
    match path.trim_end_matches('/').rfind('/') {
        Some(i) => path[..=i].to_string(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_policy_name_does_not_take_a_request_out_of_its_folder() {
        // `..` is made of permitted characters but in a path means "up": with
        // one such string a request would travel beyond sys/policies/acl.
        assert!(check_policy_name("..").is_err());
        assert!(check_policy_name("ro/../root").is_err());
        assert!(check_policy_name("a\\b").is_err());
        assert!(check_policy_name(" ").is_err());
        assert!(check_policy_name(&"x".repeat(129)).is_err());
        assert!(check_policy_name("ro-dev").is_ok());
        // Spaces at the edges are an ordinary typo, not a reason to refuse.
        assert_eq!(check_policy_name(" ro.dev_1 ").unwrap(), "ro.dev_1");
    }

    #[test]
    fn a_secrets_path_does_not_climb_either() {
        assert!(check_secret_path("app/../../etc").is_err());
        assert!(check_secret_path(&"x".repeat(513)).is_err());
        // Slashes at the edges are surplus: the path is joined to the engine
        // anyway.
        assert_eq!(check_secret_path("/app/db/").unwrap(), "app/db");
        assert_eq!(check_secret_path("  ").unwrap(), "");
    }

    #[test]
    fn a_secrets_folder_comes_out_of_its_path() {
        assert_eq!(parent_of("app/db/creds"), "app/db/");
        assert_eq!(parent_of("creds"), "");
        // A folder is deleted along with the trailing slash, which does not
        // count.
        assert_eq!(parent_of("app/db/"), "app/");
    }
}
