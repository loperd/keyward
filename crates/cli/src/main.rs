//! keyward: an ssh agent that does not try key after key, and a broker for
//! access to Vault.

mod autostart;
mod icons;
mod clipboard;
mod daemon;
mod extensions;
mod passkeys;
mod peer;
mod plugins;

use clap::{Parser, Subcommand};
use keyward_core::client;
use keyward_core::proto::{Request, Response};

#[derive(Parser)]
#[command(name = "keyward", version, about = "Keys from the vault, one per host")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// Pairing browser extensions, for passkeys.
#[derive(Subcommand)]
enum ExtensionCommand {
    /// The paired extensions and those asking to be paired, with their words.
    List,
    /// Pair one that is asking: compare its words with the extension's window.
    /// Asks for your finger, with the words in the prompt.
    Pair {
        /// Its number in `keyward extension list`; with one asking, it may be
        /// left out.
        number: Option<usize>,
    },
    /// Unpair one by its number in `keyward extension list`.
    Unpair { number: usize },
}

/// What the CLI may do to items.
#[derive(Subcommand)]
enum ItemCommand {
    /// Add an item. Each write asks for your finger (one touch covers a
    /// minute of writes). A secret is never an argument — arguments are seen
    /// by every process through `ps` — it is typed without echo or read from
    /// stdin.
    Add {
        /// The item's name.
        name: String,
        /// A secure note rather than a login.
        #[arg(long)]
        note_only: bool,
        /// The login's user name.
        #[arg(long)]
        login: Option<String>,
        /// A site address; repeat for several.
        #[arg(long = "url")]
        urls: Vec<String>,
        /// Ask for the password without echo.
        #[arg(long, conflicts_with = "password_stdin")]
        password: bool,
        /// Read the password from stdin: `pass-gen | keyward item add x --password-stdin`.
        #[arg(long, conflicts_with = "stdin_field")]
        password_stdin: bool,
        /// Read a hidden custom field's value from stdin:
        /// `ssh vps 'cat /root/key' | keyward item add backup --note-only --stdin-field KEY`.
        #[arg(long, value_name = "NAME")]
        stdin_field: Option<String>,
        /// A text custom field, `name=value`; for what is not secret.
        #[arg(long = "field", value_name = "NAME=VALUE")]
        fields: Vec<String>,
        /// A hidden custom field: its value is asked for without echo.
        #[arg(long = "secret-field", value_name = "NAME")]
        secret_fields: Vec<String>,
        /// The folder's id.
        #[arg(long)]
        folder: Option<String>,
    },
}

#[derive(Subcommand)]
enum Command {
    /// Start the daemon.
    Daemon {
        /// Where to take items from: `vault` (Bitwarden) or `file` (local JSON for debugging).
        #[arg(long, default_value = "vault")]
        source: String,
    },
    /// Set the server and the login.
    Setup {
        /// The region: `us` (the default), `eu`, or `self` with your own `--url`.
        #[arg(long, default_value = "us")]
        region: String,
        /// The address of your own server. Required with `--region self`.
        #[arg(long)]
        url: Option<String>,
        /// The login: an email, or a user name if the self-hosted server allows it.
        #[arg(long)]
        email: String,
        /// A separate identity server, when it differs from the main one.
        #[arg(long)]
        identity_url: Option<String>,
    },
    /// Log into the vault with the master password. A second factor is asked
    /// for only when the server asks for one.
    Login,
    /// Unlock the vault.
    Unlock {
        /// Take the password from the keychain with Touch ID instead of typing it.
        #[arg(long)]
        touch_id: bool,
    },
    /// Remember the master password under Touch ID.
    Remember,
    /// Items in the vault. Writing only: the CLI never reads a value back.
    #[command(subcommand)]
    Item(ItemCommand),
    /// Browser extensions that may ask for passkeys.
    #[command(subcommand)]
    Extension(ExtensionCommand),
    /// Forget the password saved under Touch ID.
    Forget,
    /// Forget the keys and take down every agent socket.
    Lock,
    /// Sync with the server.
    Sync,
    /// The state of the vault.
    Vault,
    /// The state of the daemon.
    Status,
    /// The table of mappings from pattern to item.
    Hosts,
    /// Resolve a destination. ssh calls this through `Match exec`: an exit
    /// code of 0 means there is a mapping, anything else that there is not.
    Resolve {
        host: String,
        #[arg(default_value = "")]
        user: String,
        #[arg(default_value = "0")]
        port: u16,
    },
    /// Re-read the source of mappings.
    Reload,
    /// Print the lines for ~/.ssh/config.
    SshConfig,
    /// Plugins, for the install scripts: the same operations as Settings →
    /// Plugins, over the encrypted channel like everything else.
    Plugin {
        #[command(subcommand)]
        op: PluginOp,
    },
    /// Test notifications: the application's window shows them, so the banner
    /// appears only while keyward is running.
    Notify {
        #[arg(default_value = "Testing notifications")]
        text: String,
    },
}

#[derive(Subcommand)]
enum PluginOp {
    /// Prints `on`, `off` or `absent`.
    State { id: String },
    /// Installs a package (a directory or an archive). It comes in switched off.
    Install { path: String },
    Remove { id: String },
    /// Switches a plugin on: consent to its permissions.
    Enable { id: String },
    Disable { id: String },
}

/// A wrapper around the real `main`.
///
/// The rbw profile is set here, before the runtime is created: `setenv(3)` is
/// not thread-safe against `getenv(3)`, and tokio's workers read the
/// environment themselves. Editing the environment on the move is a race and a
/// dangling pointer in a process that holds a decrypted vault.
fn main() -> anyhow::Result<()> {
    keyward_vault::init_profile();
    run()
}

#[tokio::main]
async fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if let Command::Daemon { source } = &cli.command {
        // The daemon holds the vault's keys: no core dump, no debugger.
        keyward_core::harden::process();
        // Other people's crates are always silent.
        //
        // KEYWARD_LOG=trace would switch on hyper's and reqwest's tracing too,
        // and their wire log carries headers — with `X-Vault-Token` and the
        // master password in the login body among them. Let a person turn our
        // own level up; the network's innards, no.
        let filter = tracing_subscriber::EnvFilter::try_from_env("KEYWARD_LOG")
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
            .add_directive("hyper=off".parse().expect("a valid directive"))
            .add_directive("hyper_util=off".parse().expect("a valid directive"))
            .add_directive("reqwest=off".parse().expect("a valid directive"))
            .add_directive("rustls=off".parse().expect("a valid directive"))
            .add_directive("h2=off".parse().expect("a valid directive"));
        tracing_subscriber::fmt().with_env_filter(filter).init();

        // A panic in any task takes the whole daemon down.
        //
        // Without this only one task fell over, and the process went on
        // living with a decrypted vault and raised agent sockets, in a state
        // nothing is known about any more. Better to fall: launchd brings the
        // daemon back up, and the vault comes back locked.
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            previous(info);
            tracing::error!("a panic in the daemon: killing the process, the vault will stay locked");
            std::process::abort();
        }));
        let source = match source.as_str() {
            "file" => daemon::Source::File,
            "vault" => daemon::Source::Vault,
            other => anyhow::bail!("unknown source {other:?}; expected vault or file"),
        };
        return daemon::run(source).await;
    }

    match cli.command {
        Command::Daemon { .. } => unreachable!("handled above"),

        Command::Status => match client::call(&Request::Status)? {
            Response::Status(s) => {
                println!("keyward {}  source: {}", s.version, s.source);
                println!("vault: {}{}", s.vault.summary(),
                         if s.biometric { "   [Touch ID is set up]" } else { "" });
                // The ssh plugin knows the routes and the sockets, so we ask
                // it. It may not be there: plugins are installed from the
                // showcase, and a bare machine is an ordinary state rather than
                // a fault. Then the line about mappings simply is not there.
                if let Ok(Response::Plugin { payload }) = client::call(&Request::Plugin {
                    plugin: "ssh".into(),
                    action: "status".into(),
                    payload: serde_json::Value::Null,
                }) {
                    println!(
                        "mappings: {}   live sockets: {}",
                        payload["mappings"].as_u64().unwrap_or(0),
                        payload["live_sockets"].as_u64().unwrap_or(0)
                    );
                    for name in payload["unmapped"].as_array().into_iter().flatten() {
                        println!("  an ssh key with no kw-host: {}", name.as_str().unwrap_or_default());
                    }
                    for w in payload["warnings"].as_array().into_iter().flatten() {
                        println!("  warning: {}", w.as_str().unwrap_or_default());
                    }
                }
            }
            other => print_unexpected(other)?,
        },

        Command::Hosts => match plugin_call("ssh", "hosts", serde_json::Value::Null)? {
            Response::Plugin { payload } => {
                let mappings = payload.as_array().cloned().unwrap_or_default();
                if mappings.is_empty() {
                    println!("no mappings: not one item of the vault has its kw-host field filled in");
                }
                for m in mappings {
                    let cert = m["cert_role"].as_str().map(|r| format!("  cert:{r}")).unwrap_or_default();
                    let confirm = if m["confirm"].as_bool().unwrap_or(false) { "  confirm" } else { "" };
                    println!(
                        "{:<32} -> {}{cert}{confirm}",
                        m["pattern"].as_str().unwrap_or_default(),
                        m["entry_name"].as_str().unwrap_or_default()
                    );
                }
            }
            other => print_unexpected(other)?,
        },

        Command::Notify { text } => match client::call(&Request::PushNotice { body: text })? {
            Response::Pong => println!("the notification is queued; the window will show it within half a minute"),
            other => print_unexpected(other)?,
        },

        Command::Plugin { op } => match op {
            PluginOp::State { id } => match client::call(&Request::Plugins)? {
                Response::Plugins { plugins } => {
                    let state = plugins
                        .iter()
                        .find(|m| m.get("id").and_then(|v| v.as_str()) == Some(id.as_str()))
                        .map(|m| if m.get("enabled").and_then(serde_json::Value::as_bool) == Some(true) { "on" } else { "off" })
                        .unwrap_or("absent");
                    println!("{state}");
                }
                other => print_unexpected(other)?,
            },
            PluginOp::Install { path } => match client::call(&Request::PluginInstall { path })? {
                Response::Error { message } => anyhow::bail!("{}", keyward_core::text::render(&message)),
                _ => {}
            },
            PluginOp::Remove { id } => match client::call(&Request::PluginRemove { id })? {
                Response::Error { message } => anyhow::bail!("{}", keyward_core::text::render(&message)),
                _ => {}
            },
            PluginOp::Enable { id } => match client::call(&Request::PluginEnable { id, on: true })? {
                Response::Error { message } => anyhow::bail!("{}", keyward_core::text::render(&message)),
                _ => {}
            },
            PluginOp::Disable { id } => match client::call(&Request::PluginEnable { id, on: false })? {
                Response::Error { message } => anyhow::bail!("{}", keyward_core::text::render(&message)),
                _ => {}
            },
        },

        Command::Reload => match client::call(&Request::Reload)? {
            Response::Status(s) => println!("re-read from {}", s.source),
            other => print_unexpected(other)?,
        },

        Command::Resolve { host, user, port } => {
            let req = Request::Plugin {
                plugin: "ssh".into(),
                action: "resolve".into(),
                payload: serde_json::json!({
                    "host": host,
                    "user": (!user.is_empty()).then_some(user),
                    "port": (port != 0).then_some(port),
                }),
            };
            // This path lies under every ssh connection. If the daemon is not
            // up, we step aside silently: ssh goes its ordinary way over files
            // rather than getting an error on stderr at every call. The short
            // wait is ours to declare: ssh is standing there while we ask.
            let answer = match client::call_with_timeout(&req, client::IMPATIENT) {
                Ok(a) => a,
                Err(e) => {
                    tracing::debug!(error = %e, "the daemon is unreachable; stepping aside for ssh");
                    std::process::exit(1);
                }
            };
            match answer {
                // `null` is the former `NoMatch`: no pattern was found, the
                // agent is off, or the host is empty. ssh goes its ordinary
                // way.
                Response::Plugin { payload } if payload.is_null() => std::process::exit(1),
                Response::Plugin { payload } => {
                    // stderr, not stdout: ssh runs us as a Match condition,
                    // and has no use for extra output on stdout.
                    let m = &payload["resolution"]["mapping"];
                    eprintln!(
                        "keyward: {} -> {}",
                        m["pattern"].as_str().unwrap_or_default(),
                        m["entry_name"].as_str().unwrap_or_default()
                    );
                    let others: Vec<String> = payload["resolution"]["ambiguous_with"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect();
                    if !others.is_empty() {
                        eprintln!("keyward: ambiguous; these lost: {}", others.join(", "));
                    }
                    std::process::exit(0);
                }
                // The ssh plugin may not be there at all: it is installed
                // from the showcase and does not exist before that. This is not
                // a failure on every connection but "no match" — ssh goes its
                // ordinary way.
                Response::Error { message } => {
                    tracing::debug!(%message, "the ssh plugin did not answer; stepping aside");
                    std::process::exit(1);
                }
                other => {
                    print_unexpected(other)?;
                    std::process::exit(1);
                }
            }
        }

        Command::Vault => match client::call(&Request::Vault)? {
            Response::Vault { state } => println!("{}", state.summary()),
            other => print_unexpected(other)?,
        },

        Command::Setup { region, url, email, identity_url } => {
            use keyward_core::region::Region;
            let region = match region.as_str() {
                "us" => Region::Us,
                "eu" => Region::Eu,
                "self" => Region::SelfHosted {
                    base_url: url.clone().ok_or_else(|| {
                        anyhow::anyhow!("--region self needs a --url with your own address")
                    })?,
                },
                other => anyhow::bail!("unknown region {other:?}; expected us, eu or self"),
            };
            let req = Request::Setup {
                base_url: region.base_url().to_string(),
                email,
                identity_url,
            };
            match client::call(&req)? {
                Response::Vault { state } => println!("set up: {}", state.summary()),
                other => print_unexpected(other)?,
            }
        }

        Command::Login => {
            let password: keyward_core::proto::Secret = rpassword::prompt_password("Master password: ")?.into();
            match client::call(&Request::Login { password })? {
                Response::Vault { state } => println!("{}", state.summary()),
                Response::TwoFactorRequired { providers } => {
                    let usable: Vec<_> = providers.iter().filter(|p| p.is_supported()).collect();
                    let Some(chosen) = usable.first() else {
                        anyhow::bail!(
                            "the server asks for a method keyward cannot do: {}",
                            providers.iter().map(|p| p.name.as_str()).collect::<Vec<_>>().join(", ")
                        );
                    };
                    if chosen.kind == keyward_core::two_factor::TwoFactorKind::EmailCode {
                        match client::call(&Request::SendTwoFactorEmail)? {
                            Response::TwoFactorEmailSent => println!("the code was sent by email"),
                            other => print_unexpected(other)?,
                        }
                    }
                    println!("{}: {}", chosen.name, chosen.prompt);
                    let token: keyward_core::proto::Secret = rpassword::prompt_password("Code: ")?.into();
                    match client::call(&Request::LoginTwoFactor { provider: chosen.id, token, remember: false })? {
                        Response::Vault { state } => println!("{}", state.summary()),
                        other => print_unexpected(other)?,
                    }
                }
                other => print_unexpected(other)?,
            }
        }

        Command::Unlock { touch_id } => {
            let req = if touch_id {
                Request::BiometricUnlock
            } else {
                Request::Unlock { password: rpassword::prompt_password("Master password: ")?.into() }
            };
            match client::call(&req)? {
                Response::Vault { state } => println!("{}", state.summary()),
                other => print_unexpected(other)?,
            }
        }

        Command::Remember => {
            let password: keyward_core::proto::Secret = rpassword::prompt_password("Master password (it will be checked and remembered): ")?.into();
            match client::call(&Request::BiometricRemember { password })? {
                Response::Vault { state } => {
                    println!("remembered; now `keyward unlock --touch-id`");
                    println!("{}", state.summary());
                }
                other => print_unexpected(other)?,
            }
        }

        Command::Item(ItemCommand::Add { name, note_only, login, urls, password, password_stdin, stdin_field, fields, secret_fields, folder }) => {
            /// All of stdin, without the one line end a pipe leaves.
            fn stdin_value() -> anyhow::Result<keyward_core::proto::Secret> {
                let mut raw = String::new();
                std::io::Read::read_to_string(&mut std::io::stdin(), &mut raw)?;
                let value = raw.strip_suffix('\n').map(|v| v.strip_suffix('\r').unwrap_or(v)).unwrap_or(&raw).to_string();
                zeroize::Zeroize::zeroize(&mut raw);
                if value.is_empty() {
                    anyhow::bail!("stdin held nothing");
                }
                Ok(value.into())
            }
            use keyward_core::edits::{CustomEdit, ItemEdit};
            use keyward_core::proto::Secret;
            let mut edit = ItemEdit { name: Some(name.clone()), ..ItemEdit::default() };
            if note_only {
                if login.is_some() || !urls.is_empty() || password || password_stdin {
                    anyhow::bail!("a secure note has no login, address or password");
                }
            } else {
                edit.username = login;
                if !urls.is_empty() {
                    edit.uris = Some(urls);
                }
                if password {
                    edit.password = Some(rpassword::prompt_password("Password: ")?.into());
                } else if password_stdin {
                    edit.password = Some(stdin_value()?);
                }
            }
            for f in fields {
                let (n, v) = f.split_once('=').ok_or_else(|| anyhow::anyhow!("a field is name=value: {f}"))?;
                edit.custom.push(CustomEdit { name: n.to_string(), value: Secret::from(v.to_string()), kind: 0, linked_id: None });
            }
            if let Some(n) = stdin_field {
                edit.custom.push(CustomEdit { name: n, value: stdin_value()?, kind: 1, linked_id: None });
            }
            for n in secret_fields {
                let v: Secret = rpassword::prompt_password(format!("{n}: "))?.into();
                edit.custom.push(CustomEdit { name: n, value: v, kind: 1, linked_id: None });
            }
            // Bitwarden's kinds: 1 a login, 2 a secure note.
            let kind = if note_only { 2 } else { 1 };
            match client::call(&Request::CreateItem { kind, folder_id: folder, edit })? {
                Response::Vault { .. } => println!("added “{name}”"),
                other => print_unexpected(other)?,
            }
        }

        Command::Extension(cmd) => {
            let (paired, pending) = match client::call(&Request::Extensions)? {
                Response::Extensions { paired, pending } => (paired, pending),
                other => return print_unexpected(other),
            };
            let show = |paired: &[keyward_core::passkey::ExtensionRow], pending: &[keyward_core::passkey::ExtensionRow]| {
                for (i, r) in pending.iter().enumerate() {
                    println!("{:>2}  asking   {}", i + 1, r.words.join(" "));
                }
                for (i, r) in paired.iter().enumerate() {
                    println!("{:>2}  paired   {}", pending.len() + i + 1, r.words.join(" "));
                }
                if paired.is_empty() && pending.is_empty() {
                    println!("no browser extension; try a passkey in the browser and it will ask");
                }
            };
            match cmd {
                ExtensionCommand::List => show(&paired, &pending),
                ExtensionCommand::Pair { number } => {
                    let row = match number {
                        Some(n) => pending.get(n.checked_sub(1).ok_or_else(|| anyhow::anyhow!("numbers start at 1"))?),
                        None if pending.len() == 1 => pending.first(),
                        None => anyhow::bail!("{} extensions are asking; give the number from `keyward extension list`", pending.len()),
                    }
                    .ok_or_else(|| anyhow::anyhow!("no extension under that number is asking to be paired"))?;
                    println!("pairing {} — compare with the extension's window, then touch the sensor", row.words.join(" "));
                    match client::call(&Request::ExtensionPair { key: row.key.clone() })? {
                        Response::Extensions { paired, pending } => show(&paired, &pending),
                        other => print_unexpected(other)?,
                    }
                }
                ExtensionCommand::Unpair { number } => {
                    let row = number
                        .checked_sub(1 + pending.len())
                        .and_then(|i| paired.get(i))
                        .ok_or_else(|| anyhow::anyhow!("no paired extension under that number"))?;
                    match client::call(&Request::ExtensionUnpair { key: row.key.clone() })? {
                        Response::Extensions { paired, pending } => show(&paired, &pending),
                        other => print_unexpected(other)?,
                    }
                }
            }
        }

        Command::Forget => match client::call(&Request::BiometricForget)? {
            Response::Vault { state } => println!("forgotten. {}", state.summary()),
            other => print_unexpected(other)?,
        },

        Command::Lock => match client::call(&Request::Lock)? {
            Response::Vault { state } => println!("{}", state.summary()),
            other => print_unexpected(other)?,
        },

        Command::Sync => match client::call(&Request::Sync)? {
            Response::Vault { state } => println!("{}", state.summary()),
            other => print_unexpected(other)?,
        },

        Command::SshConfig => println!("{}", keyward_core::paths::ssh_config_snippet()),
    }

    Ok(())
}

/// The short way to a plugin from the CLI.
fn plugin_call(plugin: &str, action: &str, payload: serde_json::Value) -> anyhow::Result<Response> {
    client::call(&Request::Plugin { plugin: plugin.into(), action: action.into(), payload })
}

fn print_unexpected(r: Response) -> anyhow::Result<()> {
    match r {
        Response::Error { message } => anyhow::bail!("{message}"),
        other => anyhow::bail!("an unexpected answer from the daemon: {other:?}"),
    }
}
