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

## Not at parity yet

Known gaps of the new window, worked on now:

- **Plugins** — their places, sections and screens (ssh terminal, hashicorp,
  vaultwarden) are being brought in (`app/contributions.ts`); until then use
  the old window for them.
- **The gate** — login, second factor (with "remember this device"), unlock
  by password, Touch ID and PIN are being brought to the old window's
  behaviour.
- **Settings** — the new window has no settings screen; switch back to the old
  window to change them.

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
