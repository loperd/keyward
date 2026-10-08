<p align="center">
  <img src="gui/src-tauri/icons/128x128@2x.png" width="112" alt="keyward logo">
</p>

<h1 align="center">keyward</h1>

<p align="center">
  <strong>Your vault keys, one host at a time.</strong><br>
  A native macOS vault client, per-host SSH agent, and short-lived Vault access broker.
</p>

<p align="center">
  <a href="https://github.com/loperd/keyward/actions/workflows/ci.yml"><img src="https://github.com/loperd/keyward/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/loperd/keyward/blob/master/LICENSE"><img src="https://img.shields.io/badge/license-MIT-0b8f72.svg" alt="MIT license"></a>
  <img src="https://img.shields.io/badge/platform-macOS%2014%2B-111827.svg" alt="macOS 14 or later">
  <img src="https://img.shields.io/badge/status-experimental-f59e0b.svg" alt="Experimental">
</p>

> **Experimental software.** keyward handles credentials and private keys. Try it against a test vault first; it has not had an independent security audit.

## Why keyward?

An ordinary SSH agent is host-blind: it offers every loaded key and SSH tries them in turn. That can expose more identities than necessary and often ends in `MaxAuthTries`. keyward stores the rule next to the key in your vault and brings up a dedicated agent socket for the destination, so SSH sees exactly one identity.

```text
Bitwarden / Vaultwarden
          │  encrypted vault
          ▼
   keyward daemon ── host → one key ──► per-host SSH socket ──► ssh
          │
          └── macOS app · Touch ID · plugins · Vault access
```

## One place for access

- Bitwarden, Vaultwarden, and self-hosted compatible servers.
- Logins with server-provided favicons, TOTP and passkeys.
- Secure notes, identities, SSH keys and payment cards.
- Card networks inferred locally from the IIN: Visa, Mastercard, AmEx, Discover, JCB, Diners and UnionPay. The list receives only a network label — never a PAN or its prefix.
- A native macOS experience with Touch ID, clipboard expiry, password generation and a menu-bar presence.

<p align="center">
  <a href="docs/assets/shots/inventory.png"><img src="docs/assets/shots/inventory.png" width="900" alt="A rich vault inventory in keyward"></a>
</p>

<p align="center">
  <a href="docs/assets/shots/filters-open.png"><img src="docs/assets/shots/filters-open.png" width="900" alt="Folders and organisation filters expanded in keyward"></a>
</p>

<p align="center"><sub>All screenshots use local, deliberately fake preview data.</sub></p>

### Find anything fast

The built-in command palette keeps navigation out of the way: invoke it with <kbd>⌘</kbd><kbd>K</kbd>, filter the inventory, and open the selected record. The screenshots are made from the app's preview stand with made-up data by `node scripts/readme-shots.mjs`.

<p align="center">
  <a href="docs/assets/shots/command-palette.png"><img src="docs/assets/shots/command-palette.png" width="900" alt="The keyward command palette over a deliberately fake vault inventory"></a>
</p>

### Records, not just passwords

Cards, identities, secure notes and login details use the same fast list and detail model. Card networks are derived locally from the number; sensitive values remain masked until deliberately revealed.

<p align="center">
  <a href="docs/assets/shots/card-detail.png"><img src="docs/assets/shots/card-detail.png" width="900" alt="A Visa card detail in keyward"></a>
</p>

<p align="center">
  <a href="docs/assets/shots/edit-card.png"><img src="docs/assets/shots/edit-card.png" width="900" alt="Editing a payment card in keyward"></a>
</p>

<p align="center">
  <a href="docs/assets/shots/new-item.png"><img src="docs/assets/shots/new-item.png" width="900" alt="Creating a new vault item in keyward"></a>
</p>

## SSH without key sprawl

Assign a `kw-host` custom field to an SSH-key item, for example:

```text
*.example.net, git.example.com, admin@node1.*:2222
```

The most specific pattern wins: exact host, then the glob with the longest literal suffix, then `*`. A tie is a visible warning, never a guess. keyward currently signs with Ed25519 and can request confirmation per key.

<p align="center">
  <a href="docs/assets/shots/ssh-key-detail.png"><img src="docs/assets/shots/ssh-key-detail.png" width="900" alt="An SSH key and its destination rules in keyward"></a>
</p>

## Install

The first public builds target **macOS 14+ on Apple silicon**. Until a signed release is published, build from source:

```sh
git clone https://github.com/loperd/keyward.git
cd keyward
npm ci
make install
```

`make install` builds the app and CLI, installs the app in `/Applications` (or `~/Applications`), puts `keyward` in `~/.local/bin`, and starts a per-user LaunchAgent. It deliberately does **not** edit `~/.ssh/config`.

```sh
make status       # installation and daemon state
make uninstall    # removes the app, CLI, and LaunchAgent
make test         # Rust tests plus an SSH smoke test
```

## First connection

```sh
# Configure one Bitwarden/Vaultwarden account.
keyward setup --region self --url https://vault.example.com --email you@example.com
keyward login

# Optional: keep the verified master password behind Touch ID.
keyward remember
keyward unlock --touch-id

# Inspect routes and print the SSH configuration snippet.
keyward hosts
keyward ssh-config
```

Add the printed snippet to `~/.ssh/config` once:

```sshconfig
Match exec "keyward resolve %h %r %p"
  IdentityAgent ~/.keyward/s/%h.sock
  IdentitiesOnly yes
```

## Vault access and plugins

The bundled HashiCorp Vault plugin connects to Vault, works with policies and engines, issues short-lived access, and manages secrets. The Vaultwarden plugin provides an admin view for compatible servers. Plugins are isolated executables with explicit permissions.

<p align="center">
  <a href="docs/assets/shots/vault-access.png"><img src="docs/assets/shots/vault-access.png" width="900" alt="Short-lived HashiCorp Vault access in keyward"></a>
</p>

<p align="center">
  <a href="docs/assets/shots/vaultwarden.png"><img src="docs/assets/shots/vaultwarden.png" width="900" alt="Vaultwarden administration in keyward"></a>
</p>

Read the [plugin protocol](docs/plugin-protocol.md) and [plugin registry guide](docs/plugin-registry.md) before writing or publishing a plugin.

## Generate and protect

The generator gives passwords and passphrases a dedicated workspace. Preferences collect theme, language, accent colour, clipboard expiry and capture controls; Security is kept separate for Touch ID, PIN and lock policy.

<p align="center">
  <a href="docs/assets/shots/generator.png"><img src="docs/assets/shots/generator.png" width="900" alt="Password generator in keyward"></a>
</p>

<p align="center">
  <a href="docs/assets/shots/preferences.png"><img src="docs/assets/shots/preferences.png" width="900" alt="Keyward preferences including theme accent colours"></a>
</p>

<p align="center">
  <a href="docs/assets/shots/security.png"><img src="docs/assets/shots/security.png" width="900" alt="Keyward security settings for Touch ID and lock controls"></a>
</p>

<p align="center">
  <a href="docs/assets/shots/locked.png"><img src="docs/assets/shots/locked.png" width="900" alt="The locked vault state in keyward"></a>
</p>

## Security boundaries

- keyward sets `RBW_PROFILE=keyward`, so it does not overwrite somebody else's `rbw` profile or cache.
- It relies on the cryptographic core from [`rbw`](https://github.com/doy/rbw) rather than implementing vault crypto itself.
- A remembered master password is stored in the macOS Keychain under an ACL requiring user presence. Locking forgets keys and removes every agent socket.
- Network-library tracing stays off even with `KEYWARD_LOG` enabled, to avoid writing login bodies or authorization headers to logs.

RSA/ECDSA signing, OpenSSH session binding and host-key TOFU are planned but not complete. `kw-cert` is displayed today but does not yet issue Vault SSH certificates.

## Development

```sh
npm ci
cargo test --workspace --locked
./scripts/smoke.sh

# Native development window
make run
```

For UI work, the stand in [`ui/stand`](ui/stand) (`npm -w @keyward/stand run dev`) runs the full interface against rich, fake fixtures—no daemon or vault connection required.

## Licence

[MIT](LICENSE) © keyward contributors.
