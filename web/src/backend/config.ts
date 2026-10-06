// The deployment: one server, fixed when the app is built or served, never
// typed by a person. The app is meant to be served from that server's own
// origin (behind the same Vaultwarden), so requests are same-origin and need
// no CORS.
import type { Capabilities } from "@keyward/core/backend";
import { fail } from "./errors";

export type ServerConfig = {
  /// The server's base, e.g. `https://vault.example.com`, without a slash.
  server: string;
  /// Where `/api/*` lives.
  api: string;
  /// Where `/connect/token` and `/accounts/prelogin` live.
  identity: string;
};

/// The identity server as crates/bw/src/identity.rs finds it: Bitwarden's own
/// for its clouds, `<server>/identity` for a self-hosted one.
export function identityUrl(base: string): string {
  switch (base) {
    case "https://api.bitwarden.com":
    case "https://vault.bitwarden.com":
      return "https://identity.bitwarden.com";
    case "https://api.bitwarden.eu":
    case "https://vault.bitwarden.eu":
      return "https://identity.bitwarden.eu";
    default:
      return `${base}/identity`;
  }
}

export function apiUrl(base: string): string {
  switch (base) {
    case "https://vault.bitwarden.com":
      return "https://api.bitwarden.com";
    case "https://vault.bitwarden.eu":
      return "https://api.bitwarden.eu";
    default:
      return `${base}/api`;
  }
}

/// The server from `VITE_KEYWARD_SERVER`, else the page's own origin. A value
/// that is not an http(s) origin is a broken deployment and stops the app.
export function serverConfig(explicit?: string): ServerConfig {
  // `import.meta.env` is Vite's; outside a Vite build (a bare test run) it
  // may be absent.
  const env = (import.meta as Partial<ImportMeta>).env;
  const configured = explicit ?? env?.VITE_KEYWARD_SERVER ?? globalThis.location?.origin;
  if (!configured) return fail("err.serverNotConfigured");
  let url: URL;
  try {
    url = new URL(configured);
  } catch {
    return fail("err.serverNotConfigured");
  }
  if (url.protocol !== "https:" && !(url.protocol === "http:" && isLocal(url.hostname))) {
    // Plain http carries the password hash and the tokens in the clear;
    // only a developer's own machine is allowed it.
    return fail("err.serverNotConfigured");
  }
  const server = (url.origin + url.pathname).replace(/\/+$/, "");
  return { server, api: apiUrl(server), identity: identityUrl(server) };
}

const isLocal = (host: string) => host === "localhost" || host === "127.0.0.1" || host === "[::1]";

/// What the web app can do: one fixed server, one account, no Touch ID, no
/// plugins (they live in the daemon), and it clears the clipboard itself.
export const WEB_CAPS: Capabilities = {
  chooseServer: false,
  accounts: false,
  biometric: false,
  plugins: false,
  clipboardClears: true,
};

/// How the client introduces itself, exactly as crates/bw/src/client.rs does.
/// The version is no formality: below 2024.12 Vaultwarden hides ssh keys from
/// the sync, and bitwarden.com refuses a login from a version it calls too
/// old. It follows the desktop client's and must not be lowered.
export const CLIENT_NAME = "desktop";
export const CLIENT_VERSION = "2026.6.0";
/// The `Device-Type` header (`DeviceType.MacOsDesktop`), as the desktop sends.
export const DEVICE_TYPE_HEADER = "7";
/// The `deviceType` of the token request (crates/bw/src/login.rs DEVICE_KIND).
export const DEVICE_KIND = "8";
/// The name the device goes by in the account's device list.
export const DEVICE_NAME = "keyward";
/// The device check's pseudo-provider id (crates/core/src/two_factor.rs
/// NEW_DEVICE): not one of Bitwarden's, which stop at 8.
export const NEW_DEVICE = 100;

/// Locks on idle after this long unless the deployment says otherwise.
export const DEFAULT_IDLE_MS = 15 * 60 * 1000;
