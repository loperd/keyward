# Keyward on the web

A browser client for **one** Vaultwarden (or Bitwarden) server: the shared
window of `ui/core` over `WebBackend` (`src/backend`), which signs in, keeps
the keys in the tab as non-extractable `CryptoKey`s and decrypts there. The
server never sees a key, and the page talks to nobody but that server.

```
npm -w @keyward/web run dev      # http://localhost:5191
npm -w @keyward/web run build    # web/dist
npm -w @keyward/web run test     # the backend's tests (vitest)
npm -w @keyward/web run check    # tsc
```

## Which server

The server is fixed when the app is built or served, never typed by a person:

- `VITE_KEYWARD_SERVER=https://vault.example.com` at build time, or
- nothing: the page's own origin. This is the intended deployment.

A value that is not `https://…` (plain `http` only for `localhost`) stops the
app with "The app's server is not configured correctly".

### Development against a real server

```
VITE_KEYWARD_SERVER=https://vault.example.com npm -w @keyward/web run dev
```

The dev server then proxies `/api/*` and `/identity/*` to that server and the
page talks to its own origin (`http://localhost:5191`), so the server needs no
CORS — exactly as when deployed. The proxy is for a self-hosted layout
(`<server>/api`, `<server>/identity`, as Vaultwarden serves them); Bitwarden's
own clouds keep the API and identity on other hosts and are not proxied.
Without the variable the sign-in shows and every request finds nothing behind
it, which is enough to work on the page.

## Whom you trust

The page is code the server hands out. Whoever serves `web/dist` — the
operator of that host, or anyone who can change the files there — can serve a
version that sends the master password elsewhere, and no browser can tell.
**The operator serving the code is trusted with every account that signs in
through it**, exactly as with Bitwarden's own web vault. The keys staying in
the tab protects against the *API server* reading the vault, not against the
*page's server* changing the page. Where that trust is not there, use the
desktop app, whose code does not arrive with each visit.

## Deploying

Prefer a **dedicated origin** for the app (e.g. `https://keyward.example.com`)
that serves `web/dist` and reverse-proxies `/api` and `/identity` to the
Vaultwarden: requests stay same-origin (no CORS, no third party, the tokens
travel only to that server), and no other application shares the origin. On
a shared origin — under a path of Vaultwarden's own host, which also works
(`base: "./"`, any path) — every other page served there (Vaultwarden's web
vault, its admin panel, anything else on the host) is same-origin with this
one: a hole in any of them can script this tab and read the device id, and
its storage and service workers are shared.

A minimal nginx server for the dedicated origin:

```nginx
server {
    listen 443 ssl;
    server_name keyward.example.com;
    # ssl_certificate …; ssl_certificate_key …;

    location /api/      { proxy_pass https://vault.example.com; proxy_set_header Host vault.example.com; }
    location /identity/ { proxy_pass https://vault.example.com; proxy_set_header Host vault.example.com; }

    location / {
        root /srv/keyward/web/dist;
        try_files $uri $uri/ /index.html;
        # nginx drops every inherited add_header in a block that has its
        # own: keep all of them here.
        add_header Content-Security-Policy "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; style-src 'self'; font-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'" always;
        add_header Cross-Origin-Opener-Policy "same-origin" always;
        add_header Cross-Origin-Resource-Policy "same-origin" always;
        add_header Cache-Control "no-store" always;
        add_header Referrer-Policy "no-referrer" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header Strict-Transport-Security "max-age=63072000" always;
        add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), hid=(), bluetooth=(), clipboard-read=(self), clipboard-write=(self)" always;
    }
}
```

Served under a path of Vaultwarden's host instead, the same headers go in a
`location /keyward/ { alias /srv/keyward/web/dist/; try_files $uri $uri/
/keyward/index.html; … }` beside Vaultwarden's own.

What the headers are for:

- **CSP** — see below.
- `Cross-Origin-Opener-Policy: same-origin`: a page that opened this one (or
  that it opens) gets no handle on its window.
- `Cross-Origin-Resource-Policy: same-origin`: no other site can load the
  app's files into its own page.
- `Cache-Control: no-store`: no copy of the page or its answers is kept on
  disk or in a shared cache, and a fixed release reaches the next visit.
- `Referrer-Policy: no-referrer`: no address of the app leaves with a link.
- `Permissions-Policy`: the page asks for nothing but the clipboard.

What the policy relies on, and keeps true:

- **No inline scripts.** The page loads one module script from its own
  origin, and Argon2id runs in a worker that is a file of the bundle
  (`worker-src 'self'`); nothing is injected or evaluated.
  `'wasm-unsafe-eval'` is for the KDF (Argon2id from `hash-wasm`, compiled
  from the bundle itself) and allows WebAssembly only, not `eval`.
- **No inline styles in markup.** The styles are files of the bundle; the few
  positions the window sets at run time go through the CSSOM, which the policy
  does not restrict.
- **No `data:` URIs and no third-party origins.** Fonts are bundled
  (`assetsInlineLimit: 0` keeps them files), icons are inline SVG markup, and
  `connect-src 'self'` holds because the server is the page's own origin. If
  the app is built with `VITE_KEYWARD_SERVER` pointing elsewhere, that origin
  must be added to `connect-src` — and that server must answer CORS; the
  same-origin deployment avoids both.
- `frame-ancestors 'none'`: the page cannot be framed (no clickjacking of the
  master-password field).

## What the tab keeps

Everything of a session lives in the tab's memory and nowhere else: the
tokens, the still-encrypted keys, the KDF parameters and, if a person ticks
"Remember this device", the server's remember token. A lock keeps them, so
the master password alone unlocks again; a reload, a closed tab or a crash
forgets them all, and the next visit is a whole sign-in with its second
factor. The remember token therefore spares the second factor only for a
sign-in again in the same page. `localStorage` holds one thing: the device
id, a random UUID (not a secret and not a token; without it every sign-in is
a "new device" to the server). Nothing decrypted is ever written anywhere.
The tab locks itself after 15 minutes without input, a sign-in waiting for
its second factor is dropped after 5 minutes, and a copied secret is cleared
from the clipboard after 30 seconds — or, where the browser does not let an
unfocused page write the clipboard, the moment the page has the focus again,
with the window saying meanwhile that the clipboard still holds a secret.
