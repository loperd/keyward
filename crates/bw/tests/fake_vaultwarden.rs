//! Logging in and keeping the session against a make-believe Vaultwarden
//! that answers as 1.37 does: the KDF at prelogin, an error model for a wrong
//! password, the second factor's providers, 429 past its rate limit, and
//! refresh tokens signed for thirty days and rotated on every refresh.
//!
//! This is the ground the tests did not cover: rbw did all of it, and the
//! failures came out as "failed to parse JSON" — on the thirtieth day of a
//! session most of all.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use keyward_bw::crypto::{Kdf, MasterKey};
use keyward_bw::login::{self, Answer, Device, SecondFactor};
use keyward_bw::identity;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const EMAIL: &str = "me@example.net";
const PASSWORD: &str = "correct horse";
/// The lowest count a prelogin answer is accepted with: fewer is refused as a
/// downgrade, and more would only slow the test down.
const ITERATIONS: u32 = *keyward_bw::crypto::PBKDF2_ITERATIONS.start();
const DAY: u64 = 86_400;
/// Vaultwarden's `DEFAULT_REFRESH_VALIDITY`.
const REFRESH_DAYS: u64 = 30;

#[derive(Default)]
struct World {
    /// The server's clock, in seconds.
    now: u64,
    two_factor: bool,
    /// The token a remembered device signs in with.
    remember: Option<String>,
    rate_limited: bool,
    /// Refresh tokens and the moment each runs out.
    refresh: HashMap<String, u64>,
    issued: u32,
    emails_sent: u32,
}

type Shared = Arc<Mutex<World>>;

fn jwt(exp: u64) -> String {
    let e = |v: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v);
    format!("{}.{}.sig", e(br#"{"alg":"RS256"}"#), e(format!(r#"{{"exp":{exp}}}"#).as_bytes()))
}

fn hash() -> String {
    MasterKey::derive(PASSWORD, EMAIL, Kdf::Pbkdf2 { iterations: ITERATIONS }).unwrap().password_hash(PASSWORD)
}

fn form(body: &str) -> HashMap<String, String> {
    body.split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| {
            let v = v.replace('+', " ");
            let mut out = Vec::new();
            let b = v.as_bytes();
            let mut i = 0;
            while i < b.len() {
                if b[i] == b'%' && i + 2 < b.len() {
                    out.push(u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap(), 16).unwrap());
                    i += 3;
                } else {
                    out.push(b[i]);
                    i += 1;
                }
            }
            (k.to_string(), String::from_utf8(out).unwrap())
        })
        .collect()
}

const WRONG_PASSWORD: &str = r#"{"message":"Username or password is incorrect. Try again","validationErrors":{"":["Username or password is incorrect. Try again"]},"errorModel":{"message":"Username or password is incorrect. Try again","object":"error"},"error":"","error_description":"","object":"error"}"#;

fn issue(w: &mut World) -> String {
    w.issued += 1;
    let rt = format!("rt-{}", w.issued);
    w.refresh.insert(rt.clone(), w.now + REFRESH_DAYS * DAY);
    rt
}

fn answer(w: &Shared, method: &str, path: &str, body: &str) -> (u16, String) {
    let mut w = w.lock().unwrap();
    if w.rate_limited {
        return (429, r#"{"message":"Too many login requests","errorModel":{"message":"Too many login requests"}}"#.into());
    }
    match (method, path) {
        ("POST", "/identity/accounts/prelogin") => (200, format!(r#"{{"kdf":0,"kdfIterations":{ITERATIONS},"kdfMemory":null,"kdfParallelism":null,"salt":null}}"#)),
        ("POST", "/identity/connect/token") => {
            let f = form(body);
            match f.get("grant_type").map(String::as_str) {
                Some("password") => {
                    if f.get("username").map(String::as_str) != Some(EMAIL) || f.get("password") != Some(&hash()) {
                        return (400, WRONG_PASSWORD.into());
                    }
                    if f.get("deviceIdentifier").is_none_or(String::is_empty) {
                        return (400, r#"{"message":"No device id provided"}"#.into());
                    }
                    // Vaultwarden's remembered device: provider 5 with the
                    // token it handed out; any other token is asked for the
                    // second factor again.
                    let remembered = f.get("twoFactorProvider").map(String::as_str) == Some("5")
                        && f.get("twoFactorToken").is_some_and(|t| w.remember.as_deref() == Some(t.as_str()));
                    let typed = f.get("twoFactorProvider").map(String::as_str) != Some("5") && f.get("twoFactorToken").map(String::as_str) == Some("123456");
                    if w.two_factor && !remembered && !typed {
                        return (400, r#"{"error":"invalid_grant","error_description":"Two factor required.","TwoFactorProviders":["0","1"],"TwoFactorProviders2":{"0":null,"1":{"Email":"m***@example.net"}}}"#.into());
                    }
                    let remember = if typed && f.get("twoFactorRemember").map(String::as_str) == Some("1") {
                        let t = format!("remember-{}", w.now);
                        w.remember = Some(t.clone());
                        format!(r#","TwoFactorToken":"{t}""#)
                    } else {
                        String::new()
                    };
                    let rt = issue(&mut w);
                    (200, format!(r#"{{"access_token":"{}","expires_in":7200,"token_type":"Bearer","refresh_token":"{rt}","Key":"2.key|iv|mac","PrivateKey":"2.pk|iv|mac","Kdf":0,"KdfIterations":{ITERATIONS}{remember}}}"#, jwt(w.now + 7200)))
                }
                Some("refresh_token") => {
                    let rt = f.get("refresh_token").cloned().unwrap_or_default();
                    match w.refresh.get(&rt) {
                        Some(&exp) if exp > w.now => {
                            let next = issue(&mut w);
                            (200, format!(r#"{{"refresh_token":"{next}","access_token":"{}","expires_in":7200,"token_type":"Bearer"}}"#, jwt(w.now + 7200)))
                        }
                        _ => (400, r#"{"error":"invalid_grant"}"#.into()),
                    }
                }
                _ => (400, r#"{"error":"unsupported_grant_type"}"#.into()),
            }
        }
        ("POST", "/api/two-factor/send-email-login") => {
            let v: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
            if v["masterPasswordHash"].as_str() != Some(hash().as_str()) {
                return (400, WRONG_PASSWORD.into());
            }
            w.emails_sent += 1;
            (200, String::new())
        }
        _ => (404, r#"{"message":"not found"}"#.into()),
    }
}

async fn serve(world: Shared) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else { return };
            let world = world.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                // Head, then as much body as it says.
                let (head_end, length) = loop {
                    let n = sock.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..i]).to_lowercase();
                        let length = head.lines().find_map(|l| l.strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap_or(0))).unwrap_or(0);
                        break (i + 4, length);
                    }
                };
                while buf.len() < head_end + length {
                    let n = sock.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                let mut first = head.lines().next().unwrap_or("").split(' ');
                let (method, path) = (first.next().unwrap_or("").to_string(), first.next().unwrap_or("").to_string());
                let body = String::from_utf8_lossy(&buf[head_end..]).to_string();
                let (status, out) = answer(&world, &method, &path, &body);
                let reply = format!("HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{out}", out.len());
                let _ = sock.write_all(reply.as_bytes()).await;
            });
        }
    });
    format!("http://{addr}")
}

const DEVICE: Device<'static> = Device { id: "0b8e1c1e-0000-4000-8000-000000000001", name: login::DEVICE_NAME, kind: login::DEVICE_KIND };

async fn setup(f: impl FnOnce(&mut World)) -> (Shared, String, String) {
    let world: Shared = Arc::new(Mutex::new(World { now: 1_000_000_000, ..World::default() }));
    f(&mut world.lock().unwrap());
    let base = serve(world.clone()).await;
    let identity = identity::url(&base, None);
    (world, base, identity)
}

async fn hash_for(identity: &str) -> String {
    let kdf = login::prelogin(identity, EMAIL).await.unwrap();
    MasterKey::derive(PASSWORD, EMAIL, kdf).unwrap().password_hash(PASSWORD)
}

#[tokio::test]
async fn a_login_reads_the_kdf_then_brings_tokens_and_the_key() {
    let (_w, _base, identity) = setup(|_| {}).await;
    assert!(matches!(login::prelogin(&identity, EMAIL).await.unwrap(), Kdf::Pbkdf2 { iterations: ITERATIONS }));
    let h = hash_for(&identity).await;
    let Answer::Done { refresh_token, key, private_key, .. } = login::login(&identity, EMAIL, &h, &DEVICE, None, None).await.unwrap() else {
        panic!("logged in")
    };
    assert_eq!((refresh_token.as_str(), key.as_str()), ("rt-1", "2.key|iv|mac"));
    assert_eq!(private_key.as_deref(), Some("2.pk|iv|mac"));
}

#[tokio::test]
async fn a_wrong_password_is_said_as_one() {
    let (_w, _base, identity) = setup(|_| {}).await;
    let e = login::login(&identity, EMAIL, "not-the-hash", &DEVICE, None, None).await.err().unwrap();
    assert_eq!(e.to_string(), "err.badPassword");
}

#[tokio::test]
async fn a_rate_limit_is_said_as_one_at_prelogin_and_login() {
    let (w, _base, identity) = setup(|w| w.rate_limited = true).await;
    assert_eq!(login::prelogin(&identity, EMAIL).await.err().unwrap().to_string(), "err.loginRateLimited");
    assert_eq!(login::login(&identity, EMAIL, "x", &DEVICE, None, None).await.err().unwrap().to_string(), "err.loginRateLimited");
    w.lock().unwrap().rate_limited = false;
    assert!(login::prelogin(&identity, EMAIL).await.is_ok());
}

#[tokio::test]
async fn a_second_factor_is_asked_for_sent_by_email_and_taken() {
    let (w, base, identity) = setup(|w| w.two_factor = true).await;
    let h = hash_for(&identity).await;
    let Answer::TwoFactor { providers, .. } = login::login(&identity, EMAIL, &h, &DEVICE, None, None).await.unwrap() else {
        panic!("a second factor")
    };
    assert_eq!(providers, vec![0, 1]);
    // The email goes only to someone who proves the password again — what rbw
    // did not send, and Vaultwarden 1.37 refused.
    login::send_two_factor_email(&base, EMAIL, &h, DEVICE.id).await.unwrap();
    assert_eq!(w.lock().unwrap().emails_sent, 1);
    assert_eq!(login::send_two_factor_email(&base, EMAIL, "wrong", DEVICE.id).await.err().unwrap().to_string(), "err.badPassword");

    let code = |token| Some(SecondFactor::Code { provider: 0, token, remember: false });
    assert_eq!(login::login(&identity, EMAIL, &h, &DEVICE, code("000000"), None).await.err().unwrap().to_string(), "err.badTwoFactor");
    let Answer::Done { remember_token, .. } = login::login(&identity, EMAIL, &h, &DEVICE, code("123456"), None).await.unwrap() else { panic!("done") };
    assert!(remember_token.is_none(), "not asked to remember, nothing to remember by");
}

/// "Remember this device": the code goes with `twoFactorRemember=1`, the
/// server's `TwoFactorToken` stands in for the code next time (provider 5),
/// and a token the server no longer takes is a second factor asked again —
/// never a wrong code.
#[tokio::test]
async fn a_remembered_device_skips_the_second_factor_until_the_server_forgets_it() {
    let (w, _base, identity) = setup(|w| w.two_factor = true).await;
    let h = hash_for(&identity).await;
    let Answer::Done { remember_token, .. } =
        login::login(&identity, EMAIL, &h, &DEVICE, Some(SecondFactor::Code { provider: 0, token: "123456", remember: true }), None).await.unwrap()
    else {
        panic!("done")
    };
    let token = remember_token.expect("the server remembered the device");
    assert!(matches!(login::login(&identity, EMAIL, &h, &DEVICE, Some(SecondFactor::Remembered(&token)), None).await.unwrap(), Answer::Done { .. }));

    w.lock().unwrap().remember = None;
    assert!(
        matches!(login::login(&identity, EMAIL, &h, &DEVICE, Some(SecondFactor::Remembered(&token)), None).await.unwrap(), Answer::TwoFactor { .. }),
        "a forgotten device is asked for the second factor"
    );
}

/// The thirtieth day. A refresh hands out a new refresh token; the session
/// lives as long as the client keeps the newest — and ends, in words, on the
/// old one's date for a client that does not.
#[tokio::test]
async fn the_rotated_refresh_token_keeps_the_session_past_thirty_days() {
    let (w, _base, identity) = setup(|_| {}).await;
    let h = hash_for(&identity).await;
    let Answer::Done { refresh_token: first, .. } = login::login(&identity, EMAIL, &h, &DEVICE, None, None).await.unwrap() else { panic!() };

    // Day ten: a refresh, and the new refresh token is kept.
    w.lock().unwrap().now += 10 * DAY;
    let t = identity::refresh(&identity, &first).await.unwrap();
    let kept = t.refresh_token.expect("Vaultwarden rotates");
    assert_ne!(kept.as_str(), first.as_str());

    // Day thirty-five: the first one has run out; the kept one has not.
    w.lock().unwrap().now += 25 * DAY;
    let e = identity::refresh(&identity, &first).await.err().unwrap();
    assert_eq!(e.to_string(), "err.sessionEnded", "not a parse error");
    let again = identity::refresh(&identity, &kept).await.unwrap();
    assert!(again.refresh_token.is_some());
}
