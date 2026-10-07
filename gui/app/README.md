# The new desktop window

`gui/app` is the desktop app's window on the shared core (`ui/core`, the
package `@keyward/core`): `main.tsx` mounts `<App backend={new DaemonBackend()} />`
and `backend.ts` answers the core's `Backend` through the daemon's Tauri
commands. The page is `gui/app.html`, a second Vite entry beside the old
window's `gui/index.html`; `npm run build` in `gui/` builds both into
`gui/dist` (`index.html` and `app.html`).

The Tauri window opens the old window by default; the new one is a beta the
owner turns on. In the dev server it is also at `http://localhost:5173/app.html`
(inside the Tauri window, the commands answer; in a plain browser they do not).

## Trying it in the real app

The choice is the setting `interface` (`"old"` | `"new"`, default `"old"`) in
`~/.keyward/settings.json`, saved through the daemon like every other setting.

- **Old window → new:** Settings → App → "Новый интерфейс (бета)" /
  "New interface (beta)". The choice is saved and the window reloads into
  `app.html` at once — no restart.
- **New window → old:** the account menu (the avatar in the strip) →
  "Новый интерфейс (бета)" with its check mark; a click saves `"old"` and the
  window reloads into `index.html`.
- **For one launch:** `KEYWARD_UI=new` or `KEYWARD_UI=old` wins over the
  setting at launch, e.g.
  `open --env KEYWARD_UI=new -a keyward` or
  `KEYWARD_UI=new /Applications/keyward.app/Contents/MacOS/keyward-gui`.
  Any other value stops the launch with an error rather than being guessed at.
  The toggles above still save the setting and reload the window.

How it is wired: the main window is described in `tauri.conf.json` with
`"create": false` and built in `setup` (`open_main_window` in
`src-tauri/src/lib.rs`) with the chosen page as its URL, so the first frame is
already the right window. The switch is the `set_interface` command: it saves
the setting through the daemon and navigates the same webview to the other
page. Both pages are on the same origin and the same window label (`main`), so
the CSP, the capabilities and the sealed channel are the same: a page opens
its seal session (`window_seal_open`) on its first secret, and a reopen after a
reload replaces the old session.

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
- [ ] **Autofill:** the `autofill` event, ⌘⇧L, `autofill_fill`, the
      Accessibility request (old: App.tsx:187, Spotlight.tsx:189-244).
- [ ] **Plugin management:** catalogue, install from file, enable, remove,
      trust, sources (old: `src/plugins/Plugins.tsx`).
- [ ] **Plugin screens in `ui/core`, declarative only** (no plugin TS/CSS in
      the window): the core renderer learns pages, drawers, dialogs and the
      terminal (`pluginAct` go/drawer/dialog now throw,
      `app/contributions.ts:84-87`).
- [ ] **Plugins moved to Rust pages:** ssh, hashicorp and vaultwarden go from
      `crates/plugins/*/ui` to pages declared in Rust, like kube; their
      settings sections too.

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
- [ ] Drop `index.html`, `preview.html`, `gui/src`, the `main` input and the
      `@keyward` → `src` aliases in `vite.config.ts` and `tsconfig.json`.
- [ ] Drop `Interface`, `set_interface`, `KEYWARD_UI`, `interface_page` and
      friends (keep reading an old `settings.json` that still has
      `interface`); the strip's "new interface" row and its words.
- [ ] Drop the Tauri commands only the old window used; fix README.md:187,
      `scripts/readme-shots.mjs`, this file's sections above.

## Pointing the window at it

When the new window reaches parity with the old one:

1. In `gui/src-tauri/tauri.conf.json` give the main window the page:
   `"app": { "windows": [{ "label": "main", "url": "app.html", ... }] }`.
   The dev server (`build.devUrl`) and `frontendDist` stay as they are; the
   window's `url` is resolved against both.
2. Check the window's CSP still holds (`app.security.csp`): the new window
   loads nothing but its own scripts, styles and fonts.
3. Once nothing opens `index.html` any more, drop it, `gui/src` and the
   `main` input in `gui/vite.config.ts`.
