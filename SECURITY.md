# Security

keyward holds passwords, private keys and passkeys. A weakness in it is worth
reporting privately first.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting: **Security → Report a
vulnerability** on https://github.com/loperd/keyward. Do not open a public
issue for it.

Include what you found, how to reproduce it, and what it lets an attacker do.
You will get an answer within a week; a fix is released as soon as it is ready,
and you are credited unless you ask not to be.

## Scope

- the daemon, the CLI, the app and the plugins in this repository;
- the browser extension (`extension/chromium`) and its native messaging host;
- the local stores under `~/.keyward` and every channel between the parts.

The Bitwarden or Vaultwarden server itself is out of scope — report those to
their projects.

## What keyward promises

- No secret is in the clear on disk, on a socket, on a pipe or in a log.
- The control socket, the plugins' pipes, the browser bridge and the window's
  webview each carry only sealed messages; plaintext is refused.
- Every use of a passkey and every private-key signature marked for it asks for
  Touch ID.

A way to break any of these is a vulnerability.

keyward is experimental and has not had an independent audit.
