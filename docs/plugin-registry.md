# The plugin catalogue: how it is built and how to publish to it

keyward's plugins live in an R2 bucket: one `index.json` and the packages
beside it. The application reads the catalogue, shows what there is to install
and installs it at the press of a button. Installing from a directory on disk
remains — that is the developer's path.

## What lies in the bucket

```
index.json
ssh/0.1.0/ssh-0.1.0-aarch64-apple-darwin.tar.gz
hashicorp/0.1.0/hashicorp-0.1.0-aarch64-apple-darwin.tar.gz
```

A package is the same directory with a `plugin.json`, packed into a `.tar.gz`.
Inside the archive there is exactly one top-level directory, named after the
plugin's identifier:

```
hashicorp/
  plugin.json
  keyward-plugin-hashicorp        the program the daemon talks to
  i18n/ru.json  i18n/en.json      the plugin's own words
  LICENSE
```

The words travel with the plugin because nothing else has them: the core's
dictionary knows nothing about a kv engine, and the daemon and the window read
`<package>/i18n/<lang>.json` off the disk when they have a sentence of the
plugin's to draw. The screens themselves live in the plugin's source
(`crates/plugins/<id>/ui`) and are built into the window; a package carrying its
own screens is the next step, not this one.

`index.json`:

```json
{
  "version": 1,
  "publishers": [
    { "id": "keyward-dev", "key": "base64, 32 bytes" }
  ],
  "revoked": [
    { "id": "ssh", "version": "1.0.0", "reason": "the publisher's key has leaked" }
  ],
  "plugins": [
    {
      "id": "ssh",
      "title": "Hello",
      "description": "shows that plugins work",
      "icon": "note",
      "homepage": "https://git.example.com/keyward-plugins/ssh",
      "versions": [
        {
          "version": "1.0.0",
          "platform": "any",
          "url": "ssh/0.1.0/ssh-0.1.0-aarch64-apple-darwin.tar.gz",
          "sha256": "…64 hexadecimal characters…",
          "permissions": ["entries", "notices"],
          "size": 4096,
          "publisher": "keyward-dev",
          "signature": "base64, 64 bytes"
        }
      ]
    }
  ]
}
```

- `platform` is `any` (a script) or a triple of the shape
  `aarch64-apple-darwin`. The daemon shows only what suits this machine.
- `url` is relative (beside `index.json`) or a full `https://` one. A relative
  one is handier: the catalogue travels together with its directory, including
  into `dist/registry` for checking through `file://`.
- The order of the versions in the file means nothing: the daemon sorts them
  itself and takes the newest that suits. It does not offer a withdrawn one —
  but it does show it with the reason when there is no other that suits.
- `publishers` are the keys of this catalogue's publishers. Trust in them is
  given separately, after checking the five words of the fingerprint
  (`PluginTrust`).
- Whatever it cannot make sense of the daemon passes over with a line in the
  log: one crooked entry does not hide the rest.

## Publishing

```sh
# once: a publisher key of your own
scripts/plugin-publish.sh --new-key ~/.keyward/publisher.key --publisher my-handle
# the script prints the public key and the five words of the fingerprint

export KEYWARD_PUBLISHER_KEY=~/.keyward/publisher.key
export KEYWARD_PUBLISHER=my-handle

# see what comes out, uploading nothing
scripts/plugin-publish.sh crates/plugins/ssh --dry-run

# for real
export CLOUDFLARE_API_TOKEN=…   # an R2 token with the right to write
export CLOUDFLARE_ACCOUNT_ID=…
scripts/plugin-publish.sh crates/plugins/ssh --bucket keyward-plugins
```

What the script does:

1. reads `plugin.json` (`id`, `version`, `title`, `description`, `icon`,
   `homepage`, `permissions`, and the optional `platform`);
2. packs the directory into `<id>-<version>.tar.gz` without `.git`,
   `__pycache__`, `.DS_Store` and `*.pyc`;
3. counts the `sha256` and the size, and signs the package with Ed25519;
4. puts the package into `<bucket>/<id>/<version>/`;
5. fetches `index.json`, writes in the version and the publisher's key, and
   uploads it back.

The upload goes through `npx wrangler r2 object put`: wrangler is not needed on
the system. With no token or no publisher key the script says what is missing
and leaves with a non-zero code. It does not publish what is unsigned: the
daemon would not install such a package from the catalogue anyway.

`--dry-run` puts everything into `dist/registry/`. From there the catalogue can
be fed to the daemon as a source:

```
file:///path/to/the/repository/dist/registry/index.json
```

The test package for the suites lies in `crates/cli/tests/fixtures/probe/` — it
is there for the tests rather than for people, and it is not published to the
catalogue.

## What the daemon checks at an installation

In order, and all of it before anything reaches `~/.keyward/plugins`:

1. **The withdrawal.** A version from `revoked` is not installed at all.
2. **The publisher.** A package from the catalogue has to be signed by a
   trusted publisher's key. An unknown publisher means a refusal with an offer
   to add the key; an update has to be signed by the **same** publisher as the
   installed version.
3. **The digest.** The `sha256` from the catalogue is checked before
   unpacking.
4. **The catalogue's promise.** The version and the list of permissions in the
   package have to match the card: the consent was given to what was seen.
5. **The archive.** No more than 64 MiB compressed, 256 MiB unpacked, 10,000
   entries; no absolute paths, no `..`, no links, no devices, no setuid/setgid
   and no second top-level directory.
6. **The manifest.** `id` is lower-case latin, digits and hyphens; `version` is
   three numbers through dots; `title` up to 64 characters, `description` up to
   200; `icon` is latin, digits and hyphens; `exec` is a relative path inside
   the package. Extra fields are not an error, but they are not read either.
7. **The permissions in place.** The package's directory 0700, the program
   0755, everything else 0644 — the mode is set by the daemon and not taken
   from the archive.

After that the plugin lies there **switched off**: consent to the permissions
is `PluginEnable { on: true }`. An update that asks for more than before is
switched off too and asks for consent afresh; an equal or smaller one updates
without a word and stays switched on.

**Before every start of the process** the daemon counts the `sha256` of the
`plugin.json` file and of the program from `exec` again and checks them against
what was remembered at the installation. A mismatch and the plugin is not
started, is switched off and says so with a notice: a substitution on disk is
no longer caught by the signature from the installation.

An address typed in by hand and found in no catalogue is installed — but its
manifest arrives with `unverified: true`, and the consent dialogue has to say
so plainly. Installing from a directory on disk is the same.

## The files beside the packages

| File | What is in it |
|---|---|
| `~/.keyward/plugins/sources.json` | the catalogues' addresses, `https://` and `file://` only |
| `~/.keyward/plugins/catalog.json` | the catalogues' cache, alive for an hour; "refresh" always goes to the network |
| `~/.keyward/plugins/publishers.json` | the trusted publishers' keys |
| `~/.keyward/plugins/registry.json` | what is switched off and what was remembered at the installation |
| `~/.keyward/plugins/<id>/` | the package itself |
| `~/.keyward/plugins/<id>.json` | the plugin's settings |

The names `registry`, `sources`, `catalog` and `publishers` will not fall to a
plugin's identifier: the settings file lies beside them and would rub out a
service one.

When a catalogue is out of reach the daemon gives out its cache and marks the
entries `stale: true`. The installed plugins do not suffer from it, and neither
does the list: an empty screen in place of the catalogue is not an error worth
showing.

## The development key

One publisher is built into the code — `keyward-dev`, and its private half lies
in the repository. That is deliberate: without it the example catalogue could
neither be built nor installed. It proves exactly nothing.

Before the first real publication to R2 it is necessary to:

1. create the project's key (`--new-key`) and keep its private half outside the
   repository;
2. replace `BUILTIN` in `crates/cli/src/plugins/publishers.rs` with its public
   half, or publish everything again with the real key.

## The publisher's key

The catalogue is signed by the `keyward` project's key; its private half lies
with the owner alone (`~/.keyward/publisher.key`, permissions 0600) and does
not reach the repository. The public half's fingerprint in five words is
`chimp agreeable mace definite amulet` — those are what is checked, not the
base64.
