# The desktop window

`gui/app` is the desktop app's window on the shared core (`ui/core`, the
package `@keyward/core`): `main.tsx` mounts `<App backend={new DaemonBackend()} />`
and `backend.ts` answers the core's `Backend` through the daemon's Tauri
commands. The page is `gui/app.html`; `npm run build` in `gui/` builds it into
`gui/dist`. In the dev server it is at `http://localhost:5173/app.html` (inside
the Tauri window the commands answer; in a plain browser they do not).

The main window is described in `tauri.conf.json` with `"create": false` and
built in `setup` (`open_main_window` in `src-tauri/src/lib.rs`) on `app.html`.
A page opens its seal session (`window_seal_open`) on its first secret, and a
reopen after a reload replaces the old session.

## Road to parity (release 0.2.0)

0.2.0 ships the new window only: the old one (`index.html`, `gui/src`) is
removed once every blocker below is in the new one. Tick a line when it is in
`release/v0.2.0`. The old window's place is noted for each.

### Phase 0 — the new window stands on its own
- [x] Move what `gui/app` imports from `gui/src` (`seal`, `actionLog`,
      `types`, `declared/channel` with `declared/types`, `plugins/link`,
      `plugins/call`, `plugins/types`) into `gui/app` or `ui/core`.

### Phase 1 — blockers
- [x] **Settings screen** in `ui/core` over `get_settings` / `set_settings`
      (old: `src/screens/Settings.tsx`): Settings on the path (⌘,, the
      account menu), pages Security, Unlocking and Application whose rows are
      live controls saved at once; secret and dangerous changes go through
      verbs with a preview.
- [x] **Account security:** change the master password, email and KDF;
      2FA (authenticator QR, email, recovery code, turn off)
      (old: Settings.tsx:579-993).
- [x] **Export** of the vault, CSV and JSON (old: Settings.tsx:1146).
- [x] **Touch ID:** turn on and off, on launch, for secrets, grace time; **PIN:**
      set and clear (old: Settings.tsx:1320-1476).
- [x] **Browser extensions:** list, pair, unpair, and the pairing prompt that
      polls `extensions` (old: `src/screens/Extensions.tsx`, `src/PairPrompt.tsx`).
- [x] **Autofill:** the `autofill` event, ⌘⇧L, `autofill_fill`, the
      Accessibility request (old: App.tsx:187, Spotlight.tsx:189-244); `> fill`
      chooses what the field in front asks for (the code into a code field);
      `?fill=<site>` presses ⌘⇧L on the stand.
- [x] **Plugin management:** catalogue, install from file, enable, remove,
      trust, sources (old: `src/plugins/Plugins.tsx`): Settings › Plugins,
      each plugin and each offer a step; enable (the consent), disable,
      uninstall, install, trust, install file, install address, add and
      remove source, refresh catalogue are verbs with previews.
- [x] **Plugin screens in `ui/core`, declarative only** (no plugin TS/CSS in
      the window): a place that declares `screen` offers it on its page, and
      the core draws the plugin's page in the page's stead (`ui/screen/*`):
      sections, rows, cards, tables with facets, tabs, forms (secrets read
      once from uncontrolled fields), the checked editor, the danger zone,
      the terminal over the plugin's sealed link; a reply's `go`, drawer,
      dialogue, toast and refresh, a verb's too. Kube opens its catalogue and
      its clusters this way.
- [x] **Plugins moved to Rust pages:** ssh, hashicorp and vaultwarden go from
      `crates/plugins/*/ui` to pages declared in Rust, like kube; their
      settings sections too (`Places.settings`, opened from Settings ›
      Plugins). Left out on purpose or for later: hashicorp shows no secret
      value in the window (copied through the core instead), issues a token
      to the clipboard rather than on screen, edits policies in the checked
      editor without the HCL studio's lint and templates, and has no custom
      metadata editor; vaultwarden's "who may create organisations" is text
      rather than a picker; the ssh terminal has no search in its output.
      `crates/plugins/*/ui` goes with the old window.

### Phase 2 — important
- [x] Account profile (name, fingerprint), deauthorise, purge, delete the
      account. Still to come: editing the name and avatar colour, devices.
- [x] Lock timeout and lock-or-log-out; clipboard clear time, hide on copy,
      website icons, Dock/tray, start at login, screen capture.
- [x] Theme and language saved to `settings.json`, not just locally (the
      strip's toggles too). The accent colour is still to come.
- [ ] Offline edits: the queue, retry, roll back, discard (old: `src/screens/Edits.tsx`).
- [ ] Generator with history (copy, reveal, forget).
- [ ] Passkeys: remove, the Passkeys filter.
- [ ] Organisations: create, rename, delete.
- [ ] Gate: prefill the last server and email (`vault_config`), the daemon
      probe (`daemon_probe`).

### Phase 3 — minor
- [ ] About (version, source, log path); recent items; regenerate a password;
      restore a TOTP secret; password history values; the plugin "available" probe.

### Phase 4 — removal
- [x] Drop `index.html`, `preview.html`, `gui/src`, the plugins' TS screens
      (`crates/plugins/*/ui`), the `main` input and the `@keyward` → `src`
      and `@plugin/*` aliases in `vite.config.ts` and `tsconfig.json`.
- [x] Drop `Interface`, `set_interface`, `KEYWARD_UI`, `interface_page` and
      friends (an old `settings.json` that still has `interface` reads); the
      strip's "new interface" row and its words.
- [ ] Drop the Tauri commands only the old window used.
- [x] The daemon's `err.*` words in the window's dictionary: most are only in
      `i18n/`, which the old window read.
- [ ] README's screenshots: `scripts/readme-shots.mjs` still drives the old
      `preview.html`; make it drive the stand (`ui/stand`) and shoot anew.
