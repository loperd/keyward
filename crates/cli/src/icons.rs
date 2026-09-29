//! Site icons through the vault server's icon service.
//!
//! For a domain it does not know, Vaultwarden returns not a 404 but a grey
//! "planet" with status 200, which a browser takes for an honest picture. We
//! ask once for the icon of a domain that certainly does not exist, remember
//! its fingerprint, and throw away everything that matches it.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use base64::Engine as _;
use sha2::{Digest as _, Sha256};

const CLOUD: &str = "https://icons.bitwarden.net";
const LIMIT: usize = 512 * 1024;

struct Cache {
    /// The placeholder's fingerprint, one per icon service.
    fallback: HashMap<String, Option<[u8; 32]>>,
    /// Ready answers by domain.
    icons: HashMap<String, Option<String>>,
}

static CACHE: Mutex<Option<Cache>> = Mutex::new(None);

fn with_cache<T>(f: impl FnOnce(&mut Cache) -> T) -> T {
    let mut guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    let cache = guard.get_or_insert_with(|| Cache { fallback: HashMap::new(), icons: HashMap::new() });
    f(cache)
}

/// The icon service's base from the server address, as in the interface.
pub fn icons_base(base_url: &str) -> Option<String> {
    let url = base_url.trim().trim_end_matches('/');
    if url.is_empty() {
        return None;
    }
    if url.ends_with("vault.bitwarden.com") || url.ends_with("vault.bitwarden.eu") {
        return Some(CLOUD.to_string());
    }
    Some(format!("{url}/icons"))
}

fn valid_domain(d: &str) -> bool {
    !d.is_empty()
        && d.len() <= 253
        && d.contains('.')
        && d.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.'))
        && !d.split('.').any(|p| p.is_empty())
}

async fn fetch(client: &reqwest::Client, url: &str) -> Option<(Vec<u8>, String)> {
    let res = client.get(url).send().await.ok()?;
    if !res.status().is_success() {
        return None;
    }
    let mime = res
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("image/png")
        .split(';')
        .next()
        .unwrap_or("image/png")
        .to_string();
    let bytes = res.bytes().await.ok()?;
    if bytes.is_empty() || bytes.len() > LIMIT || !mime.starts_with("image/") {
        return None;
    }
    Some((bytes.to_vec(), mime))
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// The `data:` URL of a domain's icon, or nothing.
pub async fn site_icon(base_url: &str, domain: &str) -> Option<String> {
    let domain = domain.trim().trim_start_matches("www.").to_ascii_lowercase();
    if !valid_domain(&domain) {
        return None;
    }
    let base = icons_base(base_url)?;
    let key = format!("{base}/{domain}");
    if let Some(hit) = with_cache(|c| c.icons.get(&key).cloned()) {
        return hit;
    }

    let client = reqwest::Client::builder().timeout(Duration::from_secs(8)).build().ok()?;

    // The placeholder's fingerprint: asked for once per server.
    let fallback = match with_cache(|c| c.fallback.get(&base).cloned()) {
        Some(v) => v,
        None => {
            let probe = fetch(&client, &format!("{base}/zz-keyward-no-such-domain.invalid/icon.png"))
                .await
                .map(|(b, _)| digest(&b));
            with_cache(|c| c.fallback.insert(base.clone(), probe));
            probe
        }
    };

    let result = match fetch(&client, &format!("{base}/{domain}/icon.png")).await {
        Some((bytes, mime)) => {
            if fallback.is_some_and(|f| f == digest(&bytes)) {
                None
            } else {
                Some(format!("data:{mime};base64,{}", base64::engine::general_purpose::STANDARD.encode(&bytes)))
            }
        }
        None => None,
    };
    with_cache(|c| {
        if c.icons.len() > 2000 {
            c.icons.clear();
        }
        c.icons.insert(key, result.clone());
    });
    result
}
