// The server's endpoints, spoken as crates/bw speaks them: the same headers,
// the same token form, the same reading of every answer by its status first
// (a refusal, a second factor and a rate limit each have their own word).
// Answers are never logged or put in an error: they carry tokens.
import {
  CLIENT_NAME,
  CLIENT_VERSION,
  DEVICE_KIND,
  DEVICE_NAME,
  DEVICE_TYPE_HEADER,
  type ServerConfig,
} from "./config";
import { toB64Url, utf8 } from "./bytes";
import { fail, WebError } from "./errors";
import { checkKdf, type Kdf, KdfKind } from "./kdf";

/// The HTTP methods the client speaks.
export enum HttpMethod {
  Post = "POST",
}

export type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

export type Tokens = { accessToken: string; refreshToken: string | null };

/// What the server's token endpoint answered a sign-in with.
export enum LoginAnswerKind {
  Done = "done",
  TwoFactor = "twoFactor",
  NewDevice = "newDevice",
}
export type LoginAnswer =
  | {
      kind: LoginAnswerKind.Done;
      accessToken: string;
      refreshToken: string;
      /// The protected user key, sealed with the stretched master key.
      key: string;
      privateKey: string | null;
      /// The 2FA "remember me" token, when one was asked for.
      rememberToken: string | null;
    }
  | { kind: LoginAnswerKind.TwoFactor; providers: number[] }
  | { kind: LoginAnswerKind.NewDevice };

type Json = Record<string, unknown>;

/// A field by either spelling, `null` reading as absent.
function field(v: Json, camel: string): unknown {
  const pascal = camel[0]!.toUpperCase() + camel.slice(1);
  const x = v[camel] ?? v[pascal];
  return x === null ? undefined : x;
}

const parseJson = (body: string): Json | null => {
  try {
    const v = JSON.parse(body) as unknown;
    return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Json) : null;
  } catch {
    return null;
  }
};

const ok = (status: number) => status >= 200 && status < 300;

function intOf(v: unknown): number | null {
  if (typeof v === "number" && Number.isInteger(v) && v >= 0) return v;
  if (typeof v === "string" && /^\d+$/.test(v)) return Number(v);
  return null;
}

/// The prelogin answer: the account's KDF and its own parameters. Argon2's
/// memory and lanes have no default — a default derives another key and
/// refuses a right password. Parameters outside `KDF_BOUNDS` are refused
/// here, before the password is touched.
export function readPrelogin(status: number, body: string): Kdf {
  return checkKdf(preloginKdf(status, body));
}

function preloginKdf(status: number, body: string): Kdf {
  refusal(status, body, false);
  const v = parseJson(body) ?? fail("err.loginFailed", { reason: "prelogin" });
  const iterations = intOf(field(v, "kdfIterations")) ?? fail("err.loginFailed", { reason: "kdfIterations" });
  switch (intOf(field(v, "kdf"))) {
    case 0:
      return { kind: KdfKind.Pbkdf2, iterations };
    case 1:
      return {
        kind: KdfKind.Argon2id,
        iterations,
        memoryMiB: intOf(field(v, "kdfMemory")) ?? fail("err.loginFailed", { reason: "kdfMemory" }),
        parallelism: intOf(field(v, "kdfParallelism")) ?? fail("err.loginFailed", { reason: "kdfParallelism" }),
      };
    default:
      return fail("err.kdfUnknown", { reason: "kdf" });
  }
}

/// The token endpoint's answer to a password login. `withCode`: a second
/// factor's (or the device check's) code was sent, so a refusal is the code's.
export function readLogin(status: number, body: string, withCode: boolean): LoginAnswer {
  if (!ok(status)) {
    const v = parseJson(body);
    if (v) {
      const check = deviceCheck(v);
      if (check === DeviceCheck.Required && !withCode) return { kind: LoginAnswerKind.NewDevice };
      if (check !== null) fail("err.badNewDeviceCode");
      const providers = field(v, "twoFactorProviders");
      if (Array.isArray(providers)) {
        if (withCode) fail("err.badTwoFactor");
        return {
          kind: LoginAnswerKind.TwoFactor,
          providers: providers.map((p) => intOf(p) ?? fail("err.twoFactorProviderUnknown", { id: String(p) })),
        };
      }
    }
    refusal(status, body, withCode);
    return fail("err.loginFailed", { reason: `status ${status}` });
  }
  const v = parseJson(body) ?? fail("err.loginFailed", { reason: "login answer" });
  const text = (name: string) => {
    const x = field(v, name);
    return typeof x === "string" && x !== "" ? x : null;
  };
  const accessToken = text("access_token");
  const refreshToken = text("refresh_token");
  const key = text("key");
  if (!accessToken || !refreshToken || !key) return fail("err.loginFailed", { reason: "token or key missing" });
  return { kind: LoginAnswerKind.Done, accessToken, refreshToken, key, privateKey: text("privateKey"), rememberToken: text("twoFactorToken") };
}

/// Bitwarden's device check, by the words its server sends — its own source
/// calls them the flow's contract with the clients.
enum DeviceCheck {
  Required = "required",
  WrongCode = "wrongCode",
}
function deviceCheck(v: Json): DeviceCheck | null {
  const model = field(v, "errorModel");
  const words = [v.error_description, model && typeof model === "object" ? field(model as Json, "message") : undefined]
    .filter((w): w is string => typeof w === "string")
    .map((w) => w.toLowerCase());
  if (words.includes("new device verification required")) return DeviceCheck.Required;
  if (words.includes("invalid new device otp")) return DeviceCheck.WrongCode;
  return null;
}

/// A refusal in our words; returns when the status is a success.
function refusal(status: number, body: string, withCode: boolean): void {
  if (ok(status)) return;
  if (status === 429) fail("err.loginRateLimited");
  const v = parseJson(body) ?? {};
  const description = typeof v.error_description === "string" ? v.error_description : "";
  const model = field(v, "errorModel");
  const m = (model && typeof model === "object" ? field(model as Json, "message") : undefined) ?? field(v, "message");
  const message = typeof m === "string" ? m.trim() : "";
  if (description === "invalid_username_or_password" || message.startsWith("Username or password is incorrect")) {
    fail("err.badPassword");
  }
  if (withCode && status === 400) fail("err.badTwoFactor");
  // The server's own words: an error answer carries no secret.
  if (message !== "") fail("err.loginRefused", { message: message.slice(0, 200) });
  fail("err.loginFailed", { reason: `status ${status}` });
}

/// The refresh answer. `invalid_grant` is how both servers say the refresh
/// token is no good any more; only a new login helps. A rotated refresh token
/// comes back and must replace the old one (Vaultwarden signs each for thirty
/// days and hands out a new one with every refresh).
export function readRefresh(status: number, body: string): Tokens {
  const v = parseJson(body);
  if (!ok(status)) {
    if (v && v.error === "invalid_grant") fail("err.sessionEnded");
    fail("err.serverAnswered", { status });
  }
  if (!v) return fail("err.serverAnswered", { status });
  const access = v.access_token;
  if (typeof access !== "string" || access === "") return fail("err.serverAnswered", { status });
  const refresh = v.refresh_token;
  return { accessToken: access, refreshToken: typeof refresh === "string" && refresh !== "" ? refresh : null };
}

/// Whether an access token is spent, or will be within `marginS`, by its own
/// `exp`. One that cannot be read counts as spent: a refresh costs a request,
/// a stale token a failed sync.
export function spent(accessToken: string, nowS: number, marginS: number): boolean {
  const payload = accessToken.split(".")[1];
  if (!payload) return true;
  try {
    const std = payload.replace(/-/g, "+").replace(/_/g, "/");
    const claims = JSON.parse(atob(std + "=".repeat((4 - (std.length % 4)) % 4))) as { exp?: unknown };
    return typeof claims.exp !== "number" || claims.exp <= nowS + marginS;
  } catch {
    return true;
  }
}

/// The identifier goes straight into the path; one with `/`, `..`, `?` or
/// `#` in it would walk the request — with our bearer token — off to another
/// endpoint. The server issues UUIDs, so the check cuts nothing real away.
export const isPathId = (id: string) => id.length > 0 && id.length <= 64 && /^[A-Za-z0-9_-]+$/.test(id);

export type Device = { id: string };

export class Api {
  constructor(
    private readonly cfg: ServerConfig,
    private readonly fetchFn: FetchLike,
  ) {}

  private async send(url: string, init: RequestInit): Promise<{ status: number; body: string }> {
    const headers = new Headers(init.headers);
    headers.set("Bitwarden-Client-Name", CLIENT_NAME);
    headers.set("Bitwarden-Client-Version", CLIENT_VERSION);
    headers.set("Device-Type", DEVICE_TYPE_HEADER);
    let res: Response;
    try {
      res = await this.fetchFn(url, {
        ...init,
        headers,
        // The answers are the vault and its tokens: not into the HTTP cache,
        // no cookies, no referrer.
        cache: "no-store",
        credentials: "omit",
        referrerPolicy: "no-referrer",
      });
    } catch {
      return fail("err.serverUnreachable");
    }
    return { status: res.status, body: await res.text() };
  }

  async prelogin(email: string): Promise<Kdf> {
    const r = await this.send(`${this.cfg.identity}/accounts/prelogin`, {
      method: HttpMethod.Post,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email }),
    });
    return readPrelogin(r.status, r.body);
  }

  /// The password grant. `twoFactor`: the provider's id and its code (or the
  /// remember token with provider 5); `newDeviceOtp`: the device check's code.
  async login(input: {
    email: string;
    passwordHash: string;
    device: Device;
    twoFactor?: { provider: number; token: string; remember: boolean };
    newDeviceOtp?: string;
  }): Promise<LoginAnswer> {
    const form = new URLSearchParams({
      grant_type: "password",
      scope: "api offline_access",
      client_id: "cli",
      username: input.email,
      password: input.passwordHash,
      deviceType: DEVICE_KIND,
      deviceIdentifier: input.device.id,
      deviceName: DEVICE_NAME,
      devicePushToken: "",
    });
    if (input.twoFactor) {
      form.set("twoFactorProvider", String(input.twoFactor.provider));
      form.set("twoFactorToken", input.twoFactor.token);
      if (input.twoFactor.remember) form.set("twoFactorRemember", "1");
    }
    if (input.newDeviceOtp !== undefined) form.set("newDeviceOtp", input.newDeviceOtp);
    const r = await this.send(`${this.cfg.identity}/connect/token`, {
      method: HttpMethod.Post,
      headers: { "Content-Type": "application/x-www-form-urlencoded", "auth-email": toB64Url(utf8(input.email)) },
      body: form.toString(),
    });
    // A remember token is not a code a person typed: a server that asks again
    // has merely forgotten the device.
    const withCode = (input.twoFactor !== undefined && input.twoFactor.provider !== 5) || input.newDeviceOtp !== undefined;
    return readLogin(r.status, r.body, withCode);
  }

  async refresh(refreshToken: string): Promise<Tokens> {
    const form = new URLSearchParams({ grant_type: "refresh_token", client_id: "cli", refresh_token: refreshToken });
    const r = await this.send(`${this.cfg.identity}/connect/token`, {
      method: HttpMethod.Post,
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form.toString(),
    });
    return readRefresh(r.status, r.body);
  }

  /// Asks for the login code by email. Vaultwarden sends one only to someone
  /// who proves the password again, so the hash goes along.
  async sendTwoFactorEmail(email: string, passwordHash: string, device: Device): Promise<void> {
    const r = await this.send(`${this.cfg.api}/two-factor/send-email-login`, {
      method: HttpMethod.Post,
      headers: { "Content-Type": "application/json", "auth-email": toB64Url(utf8(email)) },
      body: JSON.stringify({ email, masterPasswordHash: passwordHash, deviceIdentifier: device.id }),
    });
    refusal(r.status, r.body, false);
  }

  /// Asks bitwarden.com to mail the device check's code again.
  async resendNewDeviceCode(email: string, passwordHash: string): Promise<void> {
    const r = await this.send(`${this.cfg.api}/accounts/resend-new-device-otp`, {
      method: HttpMethod.Post,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, masterPasswordHash: passwordHash }),
    });
    refusal(r.status, r.body, false);
  }

  /// An authorised request. 401 is said as `err.sessionExpired` so the caller
  /// can refresh once and try again.
  async authed(method: string, path: string, token: string, json?: unknown): Promise<string> {
    const headers: Record<string, string> = { Authorization: `Bearer ${token}` };
    if (json !== undefined) headers["Content-Type"] = "application/json";
    const r = await this.send(`${this.cfg.api}/${path}`, {
      method,
      headers,
      ...(json !== undefined ? { body: JSON.stringify(json) } : {}),
    });
    if (r.status === 401) fail("err.sessionExpired");
    if (r.status === 403 || r.status === 404) throw new WebError("err.forbidden", { status: r.status });
    if (!ok(r.status)) fail("err.serverAnswered", { status: r.status });
    return r.body;
  }
}
