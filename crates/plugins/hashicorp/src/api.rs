//! A client for HashiCorp Vault.
//!
//! Asynchronous on purpose: a synchronous `reqwest` inside an asynchronous
//! runtime panics, and we burnt ourselves on that once already when writing to
//! Bitwarden.
//!
//! It works over the HTTP API rather than through wrappers around the `vault`
//! CLI: the server is sometimes under BUSL, and moving to OpenBao must cost
//! nothing.

use std::time::Duration;

use crate::model::{
    TokenInfo,
    Health, IssueRequest, IssueResult, IssueState, Issued, Mount, Policy, Recipient, RootProgress,
    SealStatus, Secret, SecretMeta, SecretMetaPatch, SecretVersion, MountForm, MountTune, KvConfig, is_duration,
};
use serde::Deserialize;

/// A refusal from the server, with its status code.
///
/// The caller used to pick the error text apart for substrings, looking for
/// "403" in it. That text is half the response's body, so the server itself
/// could write "403" into it and convince keyward the root token was already
/// revoked — after which the only copy of a live root token was erased from the
/// vault. A status code is not something the server can forge in a body.
#[derive(Debug)]
pub struct Failed {
    pub status: reqwest::StatusCode,
    pub detail: String,
}

impl std::fmt::Display for Failed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Vault answered {}: {}", self.status, self.detail)
    }
}

impl std::error::Error for Failed {}

/// The status code, when the error came from the server.
pub fn status_of(error: &anyhow::Error) -> Option<reqwest::StatusCode> {
    error.downcast_ref::<Failed>().map(|f| f.status)
}

/// A request's timeout. A Vault behind a port-forward answers instantly, while
/// an unreachable one keeps silent: there is no point waiting more than a few
/// seconds for it.
const TIMEOUT: Duration = Duration::from_secs(8);

pub struct Client {
    http: reqwest::Client,
    addr: String,
    namespace: Option<String>,
    token: Option<String>,
}

#[derive(Deserialize)]
struct HealthRes {
    initialized: bool,
    sealed: bool,
    standby: bool,
    version: Option<String>,
}

#[derive(Deserialize)]
struct AuthRes {
    auth: AuthPayload,
}

#[derive(Deserialize)]
struct AuthPayload {
    client_token: String,
    accessor: Option<String>,
}

#[derive(Deserialize)]
struct WrapRes {
    wrap_info: WrapInfo,
}

#[derive(Deserialize)]
struct WrapInfo {
    token: String,
    #[serde(default)]
    wrapped_accessor: Option<String>,
}

#[derive(Deserialize)]
struct LookupRes {
    data: LookupData,
}

#[derive(Deserialize)]
struct LookupData {
    #[serde(default)]
    policies: Vec<String>,
    #[serde(default)]
    ttl: i64,
    #[serde(default)]
    num_uses: i64,
}

/// What Vault knows about an issued token just now.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AccessorInfo {
    pub policies: Vec<String>,
    pub ttl: i64,
    pub num_uses: i64,
}

impl Client {
    pub fn new(addr: &str, namespace: Option<&str>) -> anyhow::Result<Self> {
        let addr = addr.trim().trim_end_matches('/').to_string();
        // https only. Over http both a token and a share of the unseal key
        // travel in the clear, and slipping oneself in as a middleman on such a
        // network is ten minutes' work.
        if !addr.starts_with("https://") {
            return Err(anyhow::anyhow!("err.vaultAddrHttps"));
        }

        let http = reqwest::Client::builder()
            .timeout(TIMEOUT)
            // Not one redirect.
            //
            // On a move to another host reqwest strips only `Authorization`
            // and the cookies. To it, `X-Vault-Token` is an ordinary
            // user-supplied header and travels on with the request's body. So
            // one answer of "307, to my host" and a root token or a share of an
            // unseal key ends up with whoever sent that answer. A Vault in
            // standby answers with a redirect as a matter of course, so nobody
            // would have noticed: the active node's address is taken from the
            // connection, not from the server's answer.
            .redirect(reqwest::redirect::Policy::none())
            .https_only(true)
            .build()
            .map_err(|e| anyhow::anyhow!("the http client will not build: {e}"))?;
        Ok(Self {
            http,
            addr,
            namespace: namespace.map(str::to_string).filter(|s| !s.is_empty()),
            token: None,
        })
    }

    pub fn with_token(mut self, token: &str) -> Self {
        self.token = Some(token.to_string());
        self
    }

    fn url(&self, path: &str) -> String {
        format!("{}/v1/{}", self.addr, path.trim_start_matches('/'))
    }

    /// A piece of a path built out of somebody else's string.
    ///
    /// A policy's name comes from outside and goes into the path. Without
    /// escaping, `../../sys/seal` is collapsed by the url parser and the request
    /// leaves for somewhere quite other than what the code says — and with the
    /// rights of whichever token the broker is working under.
    fn segment(value: &str) -> String {
        percent_encoding::utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC).to_string()
    }

    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let mut req = self.http.request(method, self.url(path));
        if let Some(t) = &self.token {
            req = req.header("X-Vault-Token", t);
        }
        if let Some(n) = &self.namespace {
            req = req.header("X-Vault-Namespace", n);
        }
        req
    }

    /// Parsing a Vault error: it puts the reasons into `errors`, and showing
    /// those to a person is far more use than a bare status code.
    async fn read<T: for<'de> Deserialize<'de>>(res: reqwest::Response) -> anyhow::Result<T> {
        let status = res.status();
        let body = Self::body(res).await;
        if !status.is_success() {
            let detail = serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v.get("errors").cloned())
                .and_then(|e| e.as_array().map(|a| {
                    a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join("; ")
                }))
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| body.chars().take(200).collect());
            return Err(Failed { status, detail }.into());
        }
        serde_json::from_str(&body).map_err(|e| anyhow::anyhow!("Vault's answer will not parse: {e}"))
    }

    /// A response body, with a ceiling.
    ///
    /// Eight seconds of timeout on a fast link is gigabytes into the daemon's
    /// memory if the server decides to pour endlessly. No honest answer from
    /// Vault comes anywhere near a megabyte.
    async fn body(mut res: reqwest::Response) -> String {
        const LIMIT: usize = 1024 * 1024;
        let mut out = Vec::new();
        while let Ok(Some(chunk)) = res.chunk().await {
            out.extend_from_slice(&chunk);
            if out.len() > LIMIT {
                out.truncate(LIMIT);
                break;
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    pub async fn health(&self) -> anyhow::Result<Health> {
        let res = self
            .request(reqwest::Method::GET, "sys/health?standbyok=true&sealedcode=200&uninitcode=200")
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Vault is unreachable: {e}"))?;
        let h: HealthRes = Self::read(res).await?;
        Ok(Health { initialized: h.initialized, sealed: h.sealed, standby: h.standby, version: h.version })
    }

    /// The seal's state: available with no token.
    pub async fn seal_status(&self) -> anyhow::Result<SealStatus> {
        let res = self
            .request(reqwest::Method::GET, "sys/seal-status")
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Vault is unreachable: {e}"))?;
        Self::read(res).await
    }

    /// Entering one key. Vault counts the threshold itself and returns the
    /// progress.
    pub async fn unseal(&self, key: &str) -> anyhow::Result<SealStatus> {
        let res = self
            .request(reqwest::Method::POST, "sys/unseal")
            .json(&serde_json::json!({ "key": key.trim() }))
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Vault is unreachable: {e}"))?;
        Self::read(res).await
    }

    /// Starts generating a root token and returns the one-time key.
    ///
    /// The one-time key (OTP) is there so that the token does not travel the
    /// network in the clear: the server returns it encrypted, and only whoever
    /// started the attempt can decrypt it.
    pub async fn generate_root_start(&self) -> anyhow::Result<(RootProgress, String)> {
        // A previous unfinished attempt is cancelled: otherwise the server
        // refuses with "attempt already in progress" and nobody understands
        // why.
        let _ = self
            .request(reqwest::Method::DELETE, "sys/generate-root/attempt")
            .send()
            .await;

        let res = self
            .request(reqwest::Method::POST, "sys/generate-root/attempt")
            .json(&serde_json::json!({}))
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Vault is unreachable: {e}"))?;
        let v: serde_json::Value = Self::read(res).await?;

        let otp = v.get("otp").and_then(|x| x.as_str()).unwrap_or_default().to_string();
        if otp.is_empty() {
            return Err(anyhow::anyhow!("err.noOtpFromServer"));
        }
        Ok((progress_from(&v), otp))
    }

    /// Feeds one share into an attempt already begun.
    pub async fn generate_root_update(
        &self,
        key: &str,
        nonce: &str,
        otp: &str,
    ) -> anyhow::Result<RootProgress> {
        let res = self
            .request(reqwest::Method::PUT, "sys/generate-root/update")
            .json(&serde_json::json!({ "key": key.trim(), "nonce": nonce }))
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Vault is unreachable: {e}"))?;
        let v: serde_json::Value = Self::read(res).await?;

        let mut progress = progress_from(&v);
        if progress.complete {
            let encoded = v
                .get("encoded_token")
                .or_else(|| v.get("encoded_root_token"))
                .and_then(|x| x.as_str())
                .unwrap_or_default();
            progress.token = Some(decode_root(encoded, otp)?);
        }
        Ok(progress)
    }

    /// Cancels an unfinished attempt.
    pub async fn generate_root_cancel(&self) -> anyhow::Result<()> {
        let _ = self
            .request(reqwest::Method::DELETE, "sys/generate-root/attempt")
            .send()
            .await;
        Ok(())
    }

    /// Logging in by AppRole. This is how a broker ought to go about: a root
    /// token is stored nowhere at rest.
    pub async fn login_approle(&mut self, role_id: &str, secret_id: &str) -> anyhow::Result<()> {
        let res = self
            .request(reqwest::Method::POST, "auth/approle/login")
            .json(&serde_json::json!({ "role_id": role_id, "secret_id": secret_id }))
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Vault is unreachable: {e}"))?;
        let auth: AuthRes = Self::read(res).await?;
        tracing::info!(accessor = ?auth.auth.accessor, "the broker logged in by AppRole");
        self.token = Some(auth.auth.client_token);
        Ok(())
    }

    /// Issuing a child token.
    ///
    /// `num_uses` and a short life are what the whole thing exists for: a
    /// token leaked into an agent's log is useless after its first use. The
    /// wrapper (`wrap`) adds something that can be checked: it can be unwrapped
    /// once, and if somebody else unwrapped it, that is visible.
    pub async fn issue(&self, req: &IssueRequest) -> anyhow::Result<IssueResult> {
        req.validate().map_err(|e| anyhow::anyhow!("{e}"))?;

        let body = serde_json::json!({
            "policies": req.policies,
            "ttl": format!("{}s", req.ttl_seconds),
            "explicit_max_ttl": format!("{}s", req.ttl_seconds),
            "num_uses": req.num_uses,
            "renewable": false,
            "display_name": display_name(req.recipient),
            "meta": { "issued_by": "keyward", "note": req.note.clone() },
        });

        let mut builder = self.request(reqwest::Method::POST, "auth/token/create").json(&body);
        if req.wrap {
            // A wrapper lives noticeably less long than the token: it is meant
            // to be handed over in time, not stored.
            builder = builder.header("X-Vault-Wrap-TTL", "300");
        }

        let res = builder.send().await.map_err(|e| anyhow::anyhow!("Vault is unreachable: {e}"))?;
        let now = now_secs();

        if req.wrap {
            let w: WrapRes = Self::read(res).await?;
            // Without an accessor the token cannot be revoked: the record in
            // the ledger would look live and the "revoke" button would do
            // nothing.
            let accessor = w
                .wrap_info
                .wrapped_accessor
                .filter(|a| !a.trim().is_empty())
                .ok_or_else(|| anyhow::anyhow!("err.noAccessorFromServer"))?;
            Ok(IssueResult {
                issued: record(req, accessor, true, now),
                wrapping_token: Some(w.wrap_info.token),
                token: None,
            })
        } else {
            let a: AuthRes = Self::read(res).await?;
            Ok(IssueResult {
                issued: record(
                    req,
                    a.auth
                        .accessor
                        .filter(|x| !x.trim().is_empty())
                        .ok_or_else(|| anyhow::anyhow!("err.noAccessorFromServer"))?,
                    false,
                    now,
                ),
                wrapping_token: None,
                token: Some(a.auth.client_token),
            })
        }
    }

    /// Revoking by accessor: the token itself is not needed for it — which is
    /// just as well, because we do not have it.
    /// What token we are holding: its accessor, its deadline and its rights.
    ///
    /// Needed so that a root token can be called alive or already revoked
    /// without trying to do anything with it.
    pub async fn lookup_self(&self) -> anyhow::Result<TokenInfo> {
        #[derive(Deserialize)]
        struct Res {
            data: Data,
        }
        #[derive(Deserialize)]
        struct Data {
            #[serde(default)]
            accessor: String,
            #[serde(default)]
            policies: Vec<String>,
            #[serde(default)]
            ttl: u64,
            #[serde(default)]
            num_uses: i64,
            #[serde(default)]
            display_name: String,
        }

        let res = self
            .request(reqwest::Method::GET, "auth/token/lookup-self")
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Vault is unreachable: {e}"))?;
        let parsed: Res = Self::read(res).await?;
        Ok(TokenInfo {
            accessor: parsed.data.accessor,
            policies: parsed.data.policies,
            ttl_seconds: parsed.data.ttl,
            num_uses: parsed.data.num_uses,
            display_name: parsed.data.display_name,
        })
    }

    /// Revokes the token we are presenting ourselves with.
    pub async fn revoke_self(&self) -> anyhow::Result<()> {
        let res = self
            .request(reqwest::Method::POST, "auth/token/revoke-self")
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Vault is unreachable: {e}"))?;
        let _: serde_json::Value = Self::read_or_empty(res).await?;
        Ok(())
    }

    /// The names of every ACL policy.
    ///
    /// The list is there so that a person picks a policy rather than recalling
    /// its name from memory: a misspelt name Vault takes without a word, and the
    /// token comes out with no rights.
    pub async fn policies(&self) -> anyhow::Result<Vec<String>> {
        #[derive(Deserialize)]
        struct Keys {
            #[serde(default)]
            keys: Vec<String>,
        }
        #[derive(Deserialize)]
        struct Res {
            data: Keys,
        }

        let res = self
            .request(reqwest::Method::GET, "sys/policies/acl?list=true")
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Vault is unreachable: {e}"))?;
        let parsed: Res = Self::read(res).await?;
        let mut names = parsed.data.keys;
        names.sort();
        Ok(names)
    }

    /// A policy's text. `root` has no body: it is built into Vault itself.
    pub async fn policy(&self, name: &str) -> anyhow::Result<Policy> {
        #[derive(Deserialize)]
        struct Res {
            data: Body,
        }
        #[derive(Deserialize)]
        struct Body {
            #[serde(default)]
            name: String,
            #[serde(default)]
            policy: String,
        }

        let res = self
            .request(reqwest::Method::GET, &format!("sys/policies/acl/{}", Self::segment(name)))
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Vault is unreachable: {e}"))?;
        let parsed: Res = Self::read(res).await?;
        Ok(Policy {
            name: if parsed.data.name.is_empty() { name.to_string() } else { parsed.data.name },
            rules: parsed.data.policy,
        })
    }

    /// Creates or replaces a policy whole.
    pub async fn put_policy(&self, name: &str, rules: &str) -> anyhow::Result<()> {
        let res = self
            .request(reqwest::Method::PUT, &format!("sys/policies/acl/{}", Self::segment(name)))
            .json(&serde_json::json!({ "policy": rules }))
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Vault is unreachable: {e}"))?;
        let _: serde_json::Value = Self::read_or_empty(res).await?;
        Ok(())
    }

    pub async fn delete_policy(&self, name: &str) -> anyhow::Result<()> {
        let res = self
            .request(reqwest::Method::DELETE, &format!("sys/policies/acl/{}", Self::segment(name)))
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Vault is unreachable: {e}"))?;
        let _: serde_json::Value = Self::read_or_empty(res).await?;
        Ok(())
    }

    /// The mounted secrets engines: the paths for a new policy are taken from
    /// them, so that nobody has to invent them out of their head.
    /// Everything mounted: the secrets engines and the auth methods
    /// together.
    ///
    /// The policy builder needs the auth methods too: a Kubernetes role lives
    /// at `auth/kubernetes/role/...`, and without those paths there was nothing
    /// to build a policy out of for an agent that creates roles. Whoever wants
    /// only the engines looks at the `auth` flag.
    pub async fn mounts(&self) -> anyhow::Result<Vec<Mount>> {
        let mut all = self.mount_table("sys/mounts", false).await?;
        // Without rights on sys/auth the list of engines is still of use.
        if let Ok(auth) = self.mount_table("sys/auth", true).await {
            all.extend(auth);
        }
        all.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(all)
    }

    /// The auth methods: the same table but under `sys/auth`, with the paths
    /// prefixed by `auth/`.
    pub async fn auth_mounts(&self) -> anyhow::Result<Vec<Mount>> {
        self.mount_table("sys/auth", true).await
    }

    async fn mount_table(&self, endpoint: &str, auth: bool) -> anyhow::Result<Vec<Mount>> {
        #[derive(Deserialize)]
        struct Entry {
            #[serde(default, rename = "type")]
            kind: String,
            #[serde(default)]
            description: String,
            #[serde(default)]
            accessor: String,
            #[serde(default)]
            options: Option<std::collections::HashMap<String, String>>,
            #[serde(default)]
            config: Option<serde_json::Value>,
        }

        let res = self
            .request(reqwest::Method::GET, endpoint)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Vault is unreachable: {e}"))?;
        let raw: serde_json::Value = Self::read(res).await?;
        // Vault gives either a flat map or that same map inside `data`.
        let map = raw.get("data").unwrap_or(&raw);
        let Some(obj) = map.as_object() else { return Ok(Vec::new()) };

        let mut mounts: Vec<Mount> = obj
            .iter()
            .filter_map(|(path, value)| {
                let entry: Entry = serde_json::from_value(value.clone()).ok()?;
                if entry.kind.is_empty() || entry.kind == "system" || entry.kind == "identity" {
                    return None;
                }
                let version = entry
                    .options
                    .as_ref()
                    .and_then(|o| o.get("version").cloned())
                    .unwrap_or_default();
                let ttl = |k: &str| entry.config.as_ref().and_then(|c| c.get(k)).and_then(|v| v.as_u64()).unwrap_or(0);
                let path = path.trim_end_matches('/');
                Some(Mount {
                    path: if auth { format!("auth/{path}") } else { path.to_string() },
                    kind: entry.kind,
                    description: entry.description,
                    // In kv of the second version the data lies under data/,
                    // and a policy written without that grants nothing.
                    kv2: version == "2",
                    accessor: entry.accessor,
                    default_lease_ttl: ttl("default_lease_ttl"),
                    max_lease_ttl: ttl("max_lease_ttl"),
                    auth,
                })
            })
            .collect();
        mounts.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(mounts)
    }

    /// Vault gives an answer with no body under status 204, and `serde` falls
    /// over on an empty string, so an empty body is counted a success.
    fn mount_url(form_path: &str, auth: bool) -> String {
        let clean: Vec<String> = form_path.split('/').filter(|s| !s.is_empty() && *s != "..").map(Self::segment).collect();
        format!("{}/{}", if auth { "sys/auth" } else { "sys/mounts" }, clean.join("/"))
    }

    /// Mount a secrets engine or an auth method.
    pub async fn mount_enable(&self, form: &MountForm) -> anyhow::Result<()> {
        form.validate().map_err(|e| anyhow::anyhow!("{e}"))?;
        let mut body = serde_json::json!({ "type": form.kind.trim(), "description": form.description.trim() });
        let mut config = serde_json::Map::new();
        if !form.default_lease_ttl.trim().is_empty() {
            config.insert("default_lease_ttl".into(), serde_json::json!(form.default_lease_ttl.trim()));
        }
        if !form.max_lease_ttl.trim().is_empty() {
            config.insert("max_lease_ttl".into(), serde_json::json!(form.max_lease_ttl.trim()));
        }
        if !config.is_empty() {
            body["config"] = serde_json::Value::Object(config);
        }
        if let (false, Some(v)) = (form.auth, form.kv_version) {
            if form.kind.trim() == "kv" {
                body["options"] = serde_json::json!({ "version": v.to_string() });
            }
        }
        let res = self
            .request(reqwest::Method::POST, &Self::mount_url(form.path.trim().trim_matches('/'), form.auth))
            .json(&body)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Vault is unreachable: {e}"))?;
        let _: serde_json::Value = Self::read_or_empty(res).await?;
        Ok(())
    }

    /// Unmount: an engine's data is erased along with it.
    pub async fn mount_disable(&self, path: &str, auth: bool) -> anyhow::Result<()> {
        let path = path.trim().trim_matches('/');
        let path = if auth { path.strip_prefix("auth/").unwrap_or(path) } else { path };
        let res = self
            .request(reqwest::Method::DELETE, &Self::mount_url(path, auth))
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Vault is unreachable: {e}"))?;
        let _: serde_json::Value = Self::read_or_empty(res).await?;
        Ok(())
    }

    /// Tune a mounted engine: its description, its deadlines, the kv version.
    pub async fn mount_tune(&self, path: &str, auth: bool, tune: &MountTune) -> anyhow::Result<()> {
        let path = path.trim().trim_matches('/');
        let path = if auth { path.strip_prefix("auth/").unwrap_or(path) } else { path };
        let mut body = serde_json::Map::new();
        if let Some(d) = &tune.description {
            body.insert("description".into(), serde_json::json!(d.trim()));
        }
        for (k, v) in [("default_lease_ttl", &tune.default_lease_ttl), ("max_lease_ttl", &tune.max_lease_ttl)] {
            if let Some(v) = v {
                let v = v.trim();
                if !v.is_empty() && !is_duration(v) && v != "0" && v != "system" {
                    return Err(anyhow::anyhow!(crate::model::key("err.durationFormat", &[("field", k)])));
                }
                body.insert(k.into(), serde_json::json!(if v.is_empty() { "0" } else { v }));
            }
        }
        if let Some(v) = tune.kv_version {
            body.insert("options".into(), serde_json::json!({ "version": v.to_string() }));
        }
        if body.is_empty() {
            return Ok(());
        }
        let res = self
            .request(reqwest::Method::POST, &format!("{}/tune", Self::mount_url(path, auth)))
            .json(&serde_json::Value::Object(body))
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Vault is unreachable: {e}"))?;
        let _: serde_json::Value = Self::read_or_empty(res).await?;
        Ok(())
    }

    /// The kv v2 settings for a whole engine.
    pub async fn kv_config(&self, mount: &str) -> anyhow::Result<KvConfig> {
        let res = self
            .request(reqwest::Method::GET, &Self::kv_path(mount, "config", ""))
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Vault is unreachable: {e}"))?;
        let raw: serde_json::Value = Self::read(res).await?;
        let d = raw.get("data").cloned().unwrap_or(serde_json::Value::Null);
        Ok(KvConfig {
            max_versions: d.get("max_versions").and_then(|v| v.as_u64()).unwrap_or(0),
            cas_required: d.get("cas_required").and_then(|v| v.as_bool()).unwrap_or(false),
            delete_version_after: d.get("delete_version_after").and_then(|v| v.as_str()).unwrap_or("0s").to_string(),
        })
    }

    pub async fn kv_config_write(&self, mount: &str, cfg: &KvConfig) -> anyhow::Result<()> {
        let res = self
            .request(reqwest::Method::POST, &Self::kv_path(mount, "config", ""))
            .json(&serde_json::json!({
                "max_versions": cfg.max_versions,
                "cas_required": cfg.cas_required,
                "delete_version_after": if cfg.delete_version_after.trim().is_empty() { "0s" } else { cfg.delete_version_after.trim() },
            }))
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Vault is unreachable: {e}"))?;
        let _: serde_json::Value = Self::read_or_empty(res).await?;
        Ok(())
    }

    /// A path inside an engine out of somebody else's string: the segments are
    /// encoded one at a time and the empty ones and `..` are thrown away —
    /// otherwise `../sys/...` would travel off into the system area with the
    /// broker's rights.
    fn kv_path(mount: &str, middle: &str, path: &str) -> String {
        let mut out: Vec<String> = mount
            .split('/')
            .filter(|s| !s.is_empty() && *s != "..")
            .map(Self::segment)
            .collect();
        if !middle.is_empty() {
            out.push(middle.to_string());
        }
        out.extend(path.split('/').filter(|s| !s.is_empty() && *s != "..").map(Self::segment));
        out.join("/")
    }

    /// The keys at a path. Folders come with a trailing `/`: that is how Vault
    /// itself gives them.
    pub async fn kv_list(&self, mount: &str, kv2: bool, path: &str) -> anyhow::Result<Vec<String>> {
        #[derive(Deserialize, Default)]
        struct Res {
            #[serde(default)]
            data: Data,
        }
        #[derive(Deserialize, Default)]
        struct Data {
            #[serde(default)]
            keys: Vec<String>,
        }
        let url = Self::kv_path(mount, if kv2 { "metadata" } else { "" }, path);
        let list = reqwest::Method::from_bytes(b"LIST").expect("LIST is a valid method name");
        let res = self
            .request(list, &url)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Vault is unreachable: {e}"))?;
        // An empty path is not an error but an empty folder.
        if res.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(Vec::new());
        }
        let parsed: Res = Self::read(res).await?;
        let mut keys = parsed.data.keys;
        keys.sort();
        Ok(keys)
    }

    pub async fn kv_read(&self, mount: &str, kv2: bool, path: &str, version: Option<u64>) -> anyhow::Result<Secret> {
        let url = Self::kv_path(mount, if kv2 { "data" } else { "" }, path);
        let mut req = self.request(reqwest::Method::GET, &url);
        if let (true, Some(v)) = (kv2, version) {
            req = req.query(&[("version", v.to_string())]);
        }
        let res = req
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Vault is unreachable: {e}"))?;
        let raw: serde_json::Value = Self::read(res).await?;
        let (data, meta) = if kv2 {
            (raw.pointer("/data/data").cloned(), raw.pointer("/data/metadata").cloned())
        } else {
            (raw.get("data").cloned(), None)
        };
        let mut out = Secret { mount: mount.to_string(), path: path.to_string(), ..Secret::default() };
        if let Some(serde_json::Value::Object(map)) = data {
            for (k, v) in map {
                let s = match v {
                    serde_json::Value::String(s) => s,
                    serde_json::Value::Null => String::new(),
                    other => other.to_string(),
                };
                out.data.insert(k, s);
            }
        }
        if let Some(meta) = meta {
            out.version = meta.get("version").and_then(|v| v.as_u64());
            out.updated = meta.get("created_time").and_then(|v| v.as_str()).map(str::to_string);
        }
        Ok(out)
    }

    /// Writing whole: in kv v2 that is a new version, in v1 a replacement.
    ///
    /// `cas` is which version we were editing: if another was written
    /// meanwhile, Vault refuses and we do not write over somebody else's.
    pub async fn kv_write(
        &self,
        mount: &str,
        kv2: bool,
        path: &str,
        data: &std::collections::BTreeMap<String, String>,
        cas: Option<u64>,
    ) -> anyhow::Result<()> {
        let url = Self::kv_path(mount, if kv2 { "data" } else { "" }, path);
        let body = if kv2 {
            match cas {
                Some(v) => serde_json::json!({ "data": data, "options": { "cas": v } }),
                None => serde_json::json!({ "data": data }),
            }
        } else {
            serde_json::json!(data)
        };
        let res = self
            .request(reqwest::Method::POST, &url)
            .json(&body)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Vault is unreachable: {e}"))?;
        let _: serde_json::Value = Self::read_or_empty(res).await?;
        Ok(())
    }

    /// Delete: in kv v2 softly, the latest version; in v1 for good.
    pub async fn kv_delete(&self, mount: &str, kv2: bool, path: &str) -> anyhow::Result<()> {
        let url = Self::kv_path(mount, if kv2 { "data" } else { "" }, path);
        let res = self
            .request(reqwest::Method::DELETE, &url)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Vault is unreachable: {e}"))?;
        let _: serde_json::Value = Self::read_or_empty(res).await?;
        Ok(())
    }

    async fn kv_versions_op(&self, mount: &str, op: &str, path: &str, versions: &[u64]) -> anyhow::Result<()> {
        let url = Self::kv_path(mount, op, path);
        let res = self
            .request(reqwest::Method::POST, &url)
            .json(&serde_json::json!({ "versions": versions }))
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Vault is unreachable: {e}"))?;
        let _: serde_json::Value = Self::read_or_empty(res).await?;
        Ok(())
    }

    /// Bring soft-deleted versions back (kv v2).
    pub async fn kv_undelete(&self, mount: &str, path: &str, versions: &[u64]) -> anyhow::Result<()> {
        self.kv_versions_op(mount, "undelete", path, versions).await
    }

    /// Destroy versions with no way back (kv v2).
    pub async fn kv_destroy(&self, mount: &str, path: &str, versions: &[u64]) -> anyhow::Result<()> {
        self.kv_versions_op(mount, "destroy", path, versions).await
    }

    /// Take a secret down whole: every version and the metadata (kv v2).
    pub async fn kv_metadata_delete(&self, mount: &str, path: &str) -> anyhow::Result<()> {
        let url = Self::kv_path(mount, "metadata", path);
        let res = self
            .request(reqwest::Method::DELETE, &url)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Vault is unreachable: {e}"))?;
        let _: serde_json::Value = Self::read_or_empty(res).await?;
        Ok(())
    }

    pub async fn kv_metadata(&self, mount: &str, path: &str) -> anyhow::Result<SecretMeta> {
        let url = Self::kv_path(mount, "metadata", path);
        let res = self
            .request(reqwest::Method::GET, &url)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Vault is unreachable: {e}"))?;
        let raw: serde_json::Value = Self::read(res).await?;
        let d = raw.get("data").cloned().unwrap_or(serde_json::Value::Null);
        let str_of = |v: Option<&serde_json::Value>| v.and_then(|x| x.as_str()).filter(|s| !s.is_empty()).map(str::to_string);
        let mut versions: Vec<SecretVersion> = d
            .get("versions")
            .and_then(|v| v.as_object())
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| {
                        Some(SecretVersion {
                            version: k.parse().ok()?,
                            created: str_of(v.get("created_time")),
                            deleted: str_of(v.get("deletion_time")),
                            destroyed: v.get("destroyed").and_then(|x| x.as_bool()).unwrap_or(false),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        versions.sort_by(|a, b| b.version.cmp(&a.version));
        let mut custom = std::collections::BTreeMap::new();
        if let Some(obj) = d.get("custom_metadata").and_then(|v| v.as_object()) {
            for (k, v) in obj {
                custom.insert(k.clone(), v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string()));
            }
        }
        Ok(SecretMeta {
            mount: mount.to_string(),
            path: path.to_string(),
            current_version: d.get("current_version").and_then(|v| v.as_u64()).unwrap_or(0),
            oldest_version: d.get("oldest_version").and_then(|v| v.as_u64()).unwrap_or(0),
            max_versions: d.get("max_versions").and_then(|v| v.as_u64()).unwrap_or(0),
            cas_required: d.get("cas_required").and_then(|v| v.as_bool()).unwrap_or(false),
            delete_version_after: d.get("delete_version_after").and_then(|v| v.as_str()).unwrap_or("0s").to_string(),
            custom_metadata: custom,
            created: str_of(d.get("created_time")),
            updated: str_of(d.get("updated_time")),
            versions,
        })
    }

    /// Editing the metadata: only what was passed in.
    pub async fn kv_metadata_write(&self, mount: &str, path: &str, patch: &SecretMetaPatch) -> anyhow::Result<()> {
        let url = Self::kv_path(mount, "metadata", path);
        let mut body = serde_json::Map::new();
        if let Some(v) = patch.max_versions {
            body.insert("max_versions".into(), serde_json::json!(v));
        }
        if let Some(v) = patch.cas_required {
            body.insert("cas_required".into(), serde_json::json!(v));
        }
        if let Some(v) = &patch.delete_version_after {
            body.insert("delete_version_after".into(), serde_json::json!(v));
        }
        if let Some(v) = &patch.custom_metadata {
            body.insert("custom_metadata".into(), serde_json::json!(v));
        }
        if body.is_empty() {
            return Ok(());
        }
        let res = self
            .request(reqwest::Method::POST, &url)
            .json(&serde_json::Value::Object(body))
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Vault is unreachable: {e}"))?;
        let _: serde_json::Value = Self::read_or_empty(res).await?;
        Ok(())
    }

    async fn read_or_empty<T: for<'de> Deserialize<'de> + Default>(
        res: reqwest::Response,
    ) -> anyhow::Result<T> {
        let status = res.status();
        let body = Self::body(res).await;
        if !status.is_success() {
            let detail = serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v.get("errors").cloned())
                .and_then(|e| {
                    e.as_array()
                        .map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join("; "))
                })
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| body.chars().take(200).collect());
            return Err(Failed { status, detail }.into());
        }
        if body.trim().is_empty() {
            return Ok(T::default());
        }
        serde_json::from_str(&body).map_err(|e| anyhow::anyhow!("Vault's answer will not parse: {e}"))
    }

    pub async fn revoke(&self, accessor: &str) -> anyhow::Result<()> {
        let res = self
            .request(reqwest::Method::POST, "auth/token/revoke-accessor")
            .json(&serde_json::json!({ "accessor": accessor }))
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Vault is unreachable: {e}"))?;
        if res.status().is_success() {
            return Ok(());
        }
        let _: serde_json::Value = Self::read(res).await?;
        Ok(())
    }

    /// What Vault thinks of a token. `None` means there is no such accessor
    /// any more.
    pub async fn lookup(&self, accessor: &str) -> anyhow::Result<Option<AccessorInfo>> {
        let res = self
            .request(reqwest::Method::POST, "auth/token/lookup-accessor")
            .json(&serde_json::json!({ "accessor": accessor }))
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Vault is unreachable: {e}"))?;
        if res.status() == reqwest::StatusCode::BAD_REQUEST || res.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let l: LookupRes = Self::read(res).await?;
        Ok(Some(AccessorInfo { policies: l.data.policies, ttl: l.data.ttl, num_uses: l.data.num_uses }))
    }
}

fn progress_from(v: &serde_json::Value) -> RootProgress {
    let num = |k: &str| v.get(k).and_then(serde_json::Value::as_u64).unwrap_or(0) as u32;
    RootProgress {
        nonce: v.get("nonce").and_then(|x| x.as_str()).unwrap_or_default().to_string(),
        required: num("required"),
        progress: num("progress"),
        complete: v.get("complete").and_then(serde_json::Value::as_bool).unwrap_or(false),
        token: None,
    }
}

/// Decrypts an issued token with the one-time key.
///
/// Vault gives it as base64 of the token XORed with the OTP, so that the token
/// does not cross the network in the clear even inside a trusted channel.
fn decode_root(encoded: &str, otp: &str) -> anyhow::Result<String> {
    use base64::Engine as _;
    if encoded.is_empty() {
        return Err(anyhow::anyhow!("err.noTokenFromServer"));
    }
    let raw = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(encoded))
        .map_err(|e| anyhow::anyhow!("the token is not base64: {e}"))?;

    let otp = otp.as_bytes();
    if otp.len() < raw.len() {
        return Err(anyhow::anyhow!("err.otpShorterThanToken"));
    }
    let token: Vec<u8> = raw.iter().zip(otp).map(|(a, b)| a ^ b).collect();
    String::from_utf8(token).map_err(|_| anyhow::anyhow!("the decrypted token is not text"))
}

fn display_name(r: Recipient) -> &'static str {
    match r {
        Recipient::Agent => "keyward-agent",
        Recipient::Person => "keyward-person",
        Recipient::Me => "keyward-self",
    }
}

fn record(req: &IssueRequest, accessor: String, wrapped: bool, now: u64) -> Issued {
    Issued {
        accessor,
        recipient: req.recipient,
        policies: req.policies.clone(),
        ttl_seconds: req.ttl_seconds,
        num_uses: req.num_uses,
        note: req.note.clone(),
        created_at: now,
        wrapped,
        state: IssueState::Active,
    }
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
