# Chrome Web Store — keyward

Everything the store asks for, kept next to the extension and updated with
every change to it. The package itself is `extension/chromium/`; this file is
outside it on purpose and never ships.

Build the upload: `scripts/extension-package.sh` → `dist/extension/keyward-<version>.zip`.

## Single purpose

> Let websites sign in with, and save, passkeys kept in the user's keyward
> vault, through the keyward app on the same Mac.

Nothing else: no password autofill, no page changes, no toolbar features.

## Permissions and why

| Permission | Why it is needed |
|---|---|
| `nativeMessaging` | The passkeys and their private keys live in the keyward app. The extension reaches it only through the native messaging host `me.loper`, which the app installs. Without it the extension can do nothing. |
| `storage` | `chrome.storage.session` only: while a passkey request is open, its parameters and the names shown in the chooser are kept in memory for the chooser window. The access level is `TRUSTED_CONTEXTS`, so content scripts cannot read it. Nothing is stored on disk. |
| Content scripts on `https://*/*`, `http://localhost/*`, `http://*.localhost/*` | A passkey request can come from any site a person signs in to, and WebAuthn exists only on secure pages — hence exactly `https` plus `localhost`, which browsers treat as secure. The scripts do not read or change page content. |
| `inject.js` in the `MAIN` world at `document_start` | WebAuthn is `navigator.credentials` in the page's own world; offering a keyward passkey means answering that call. It runs before the page so that the page cannot tamper with what it relies on. It only intercepts `navigator.credentials.get/create` with `publicKey`; everything else — and every case where keyward has nothing or the person chooses "Another way" — goes to the browser's own implementation. Top frame only. |
| `bridge.js` (isolated world) | Relays a request from the page to the service worker and the answer back. The page's origin is taken from the browser (`sender.origin`), never from the page. |

No host permissions, no `tabs`, no `scripting`, no `webRequest`, no remote code,
no `eval`. The extension pages' CSP is `default-src 'none'; script-src 'self'`.

## Privacy practices (dashboard answers)

- **Data collected:** none is collected by the developer. The extension handles
  *authentication information* (passkey requests and responses) and *personally
  identifiable information* (account names a site sends when creating a
  passkey) **locally**, passing them only to the keyward app on the same device
  over an encrypted native messaging channel.
- **Certifications:** not sold to third parties; not used or transferred for
  purposes unrelated to the single purpose; not used or transferred to
  determine creditworthiness or for lending.
- **Remote code:** no.
- **Privacy policy URL:** https://github.com/loperd/keyward/blob/master/docs/extension-privacy.md

## Listing

**Name:** keyward

**Category:** Productivity → Tools (or "Workflow & Planning" if Tools is not offered)

**Summary (≤132, from `_locales/*/messages.json` → `extDescription`):**
- en: Passkeys from your keyward vault: sign in and save new ones with Touch ID
- ru: Passkey из волта keyward: вход и сохранение новых с Touch ID

**Description (en):**

> Use the passkeys in your keyward vault on any website, and save new ones
> there — with Touch ID every time.
>
> keyward is a macOS client for Bitwarden and Vaultwarden vaults. This
> extension connects the browser to the keyward app: when a site asks for a
> passkey, keyward shows the matching accounts from your vault; you choose one
> and confirm with Touch ID. When a site offers to create a passkey, you choose
> where to keep it — a new login or an existing one for that site.
>
> • Requires the keyward app for macOS, which installs the browser bridge.
> • The private key never leaves the keyward app; the browser gets only a
>   signature.
> • The connection between the extension and the app is encrypted.
> • Nothing is sent to the developer or anyone else: no analytics, no
>   telemetry.
> • "Another way" hands any request back to the browser.
> • Passkeys are stored in Bitwarden's format and work in the official
>   Bitwarden apps too.

**Description (ru):**

> Пользуйся passkey из волта keyward на любом сайте и сохраняй туда новые —
> каждый раз с Touch ID.
>
> keyward — клиент для волтов Bitwarden и Vaultwarden на macOS. Расширение
> связывает браузер с приложением keyward: когда сайт просит passkey, keyward
> показывает подходящие аккаунты из волта; выбираешь один и подтверждаешь
> Touch ID. Когда сайт предлагает создать passkey, выбираешь, где его хранить —
> в новом логине или в уже существующем для этого сайта.
>
> • Нужно приложение keyward для macOS: оно устанавливает мост для браузера.
> • Приватный ключ не покидает приложение keyward; браузер получает только
>   подпись.
> • Соединение между расширением и приложением зашифровано.
> • Разработчику и кому-либо ещё не передаётся ничего: ни аналитики, ни
>   телеметрии.
> • «Другим способом» отдаёт любой запрос браузеру.
> • Passkey хранятся в формате Bitwarden и работают и в официальных
>   приложениях Bitwarden.

**Store assets** are intentionally not versioned. Create the required listing
screenshots and promo tile from a local test profile immediately before
submission; do not use account data or production screenshots.

## Test instructions for the reviewer

> The extension is a companion to the keyward app for macOS and does nothing on
> its own: without the app, every passkey request goes to the browser's own
> implementation, exactly as if the extension were not installed.
>
> To see it work: install keyward from https://github.com/loperd/keyward
> (`make install` on macOS 14 or later; it installs the native messaging host
> for Chrome), sign in to a Bitwarden or Vaultwarden account in the app, then
> open https://webauthn.io, enter a user name and press Register. The keyward
> window asks where to save the passkey; Touch ID confirms. Then press
> Authenticate: keyward offers the passkey and signs in after Touch ID.

## Publishing

1. `scripts/extension-package.sh` — the zip has no `key` in its manifest: the
   store gives the item its own identifier.
2. Upload it as a new item in the developer dashboard, fill in the listing,
   privacy practices and test instructions from this file.
3. **Before submitting:** take the item's identifier from the dashboard and add
   `chrome-extension://<store id>/` to
   - `ALLOWED` in `crates/passkey-host/src/main.rs`;
   - `EXTENSION_ORIGINS` in `scripts/install.sh`.
   Release the app with it, or the store build finds no bridge to talk to.
   The store id is `codlckblccbcnadacdnoieimkmdieajg`; both lists carry it.
4. Submit for review.

Published on 2026-10-09: https://chromewebstore.google.com/detail/keyward/codlckblccbcnadacdnoieimkmdieajg
(0.1.0, with app 0.2.0 carrying its id).

## Changes log

- 0.1.0 — first version: sign in and register passkeys; sealed bridge to the
  app.
