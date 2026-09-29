# The plugin protocol

How the daemon talks to a plugin, and what a plugin may ask of the core. The
contract itself is `crates/plugin/src/lib.rs`; the daemon's side of it is
`crates/cli/src/plugins/external.rs`, and the plugin's side is
`crates/plugin-stdio`. Departing from what is written here is not allowed — a
package built against it has to keep working.

For the shape of a package, the catalogue and what is checked at an
installation, see `docs/plugin-registry.md`.

## The process

An external plugin is a program of its own rather than a library: the daemon's
address space holds the vault's keys, and somebody else's code there would read
them directly. A separate process, on the contrary, receives exactly what it was
allowed — and that is the only way to offer "install a plugin" without giving
away the vault along with it.

The process starts at the first call and lives while the plugin is switched on.
JSON messages in both directions: `stdin` from the daemon, `stdout` to the
daemon, `stderr` into the daemon's log marked with the plugin's name.

## The channel (protocol 2)

Nothing on the pipes is in the clear. The manifest says `"protocol": 2`; a
package without it is refused at installation and never started — there is no
fallback to plain text.

- The handshake is `Noise_NN_25519_ChaChaPoly_BLAKE2s` with the prologue
  `keyward plugin v2`. The daemon speaks first; the plugin answers. Neither
  message carries a payload — a handshake with one is another protocol and is
  refused. A plugin that has not answered within ten seconds is taken down.
- On the wire everything is frames: two bytes of length, big-endian, then one
  Noise message (at most 65535 bytes).
- A message is a sealed header — its length, four bytes big-endian, at most
  4 MiB — followed by sealed chunks of at most 65519 bytes, each in a frame of
  its own. The daemon seals with the first key of the split, the plugin with
  the second.
- A frame that does not open ends the conversation, and the daemon takes the
  process down.

A plugin in Rust gets all of this from `keyward-plugin-stdio`. A plugin in
Python finds a complete implementation in the standard library alone next to
the example: `crates/cli/tests/fixtures/probe/noise.py`.

It is started with a clean environment — `PATH`, `HOME` and
`KEYWARD_PLUGIN_DIR`, and nothing else — and with the package's directory as the
working directory.

## The messages

The daemon → the plugin:

```json
{"kind":"call","id":1,"action":"status","payload":null}
{"kind":"event","event":"unlocked"}
{"kind":"host_result","id":7,"ok":{"...":"..."}}
{"kind":"host_result","id":7,"error":"err.pluginNoPermission {\"permission\":\"plugin.perm.secrets\"}"}
```

The plugin → the daemon:

```json
{"kind":"result","id":1,"ok":{"...":"..."}}
{"kind":"result","id":1,"error":"err.pluginUnknownOp {\"op\":\"x\"}"}
{"kind":"host","id":7,"method":"entries","args":{}}
```

The events are `unlocked`, `locked`, `entries_changed` and `tick`; they go to
every plugin that is switched on, external ones included.

Anything a person will read travels as a key, on its own or with arguments:
`err.code` or `err.code {"name":"value"}`. The window has the person's language
and renders it; the daemon and the plugins do not.

A plugin's own keys live in its own dictionary — `<package>/i18n/<lang>.json`,
`crates/plugins/<id>/i18n/` in the source — and the window merges them in. The
core's dictionary holds the core's words alone: it cannot know what a plugin
will want to say. A plugin may add words but not replace the core's: a key that
is already in the core wins.

The order of answers promises nothing. While a plugin waits on the core the
daemon may send a second `call`, and it has to go to work rather than queue
behind the first; that is what the numbers are for.

## The host methods

The `host` methods are exactly the methods of the `Host` trait, and the daemon
checks the permission on every call:

| The method | The permission |
|---|---|
| `unlocked` | — |
| `settings`, `set_settings` | — |
| `entries` | `entries` |
| `item_detail`, `note_fields`, `tagged_items` | `items` |
| `create_note`, `trash_item`, `set_fields` | `items_write` |
| `secret` | `secrets` |
| `notice` | `notices` |
| `sign_ssh` | `ssh_sign` |

`network` is declared but never enforced by the core: a plugin's process goes to
the network on its own. The permission exists for the person's sake, and the
consent dialogue shows it on a par with the rest — a plugin with access to
secrets and to the network carries them wherever it likes.

`state_dir` is not needed over the wire: a plugin's directory is the package's
directory, which it knows already.

A method the core does not know is refused rather than allowed.

## What a plugin never gets

- **A password**, and any other secret field, unless the field is its own: an
  external plugin may read only `SecretField::Custom(name)` where `name` begins
  with `kw-`. Everything else is refused with `err.pluginForeignField`.
- **A secret from an item marked "ask for the password again"**: refused with
  `err.pluginReprompt`, whatever the permissions say.
- **A private ssh key**, even with `entries`: the agent signs inside the daemon.
  That is what `sign_ssh` is for.

A refusal is an answer with `error` rather than a broken pipe: a plugin has to
survive a "no".

## The process rules

All of them are compulsory:

- An answer to a `call` is waited for no longer than 30 seconds; a plugin waits
  on a `host` call as long as it likes — that is its own business. Silence past
  the timeout is an error on the call, and the process stays alive.
- A line longer than 4 MiB takes the process down: that is no longer a
  conversation.
- A plugin that falls over three times in a minute switches itself off and says
  so with a notice. The list then comes back with `enabled: false` on the next
  `plugins()` — the switch on the card is drawn from the daemon's answer rather
  than from the interface's own state.
- Switching a plugin off or removing it is not a crash: it does not count
  against the three.

## Consent and the state

An installed plugin lies there **switched off** and has no process: consent to
the permissions is `PluginEnable { on: true }`. Until a person agrees, nothing is
running, and `Request::Plugin` to it answers with an error.

A switched-off plugin is still listed in `Plugins` with `enabled: false` —
otherwise there would be no way to switch it back on — but the rail draws the
sections of the switched-on ones alone, it receives no events, and calls to it
answer with an error.

`PluginInstall` answers with the installed plugin's manifest (`enabled: false`,
`origin: "external"`, and the `permissions` it asks for) — that is what the
consent dialogue shows. `PluginEnable` and `PluginRemove` answer with the whole
list afresh, so there is no need to re-read `plugins()` after them.
