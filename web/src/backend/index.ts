// The web app's backend: the `Backend` of ui/core, answered from the tab
// against the one server this app is deployed for.
//
// Where the secrets are, at every moment:
//   - The master password exists only inside `login`/`unlock`: it is turned
//     into the master key, the master key into the password hash and the
//     stretched pair, and the master key's bytes are wiped.
//   - Between a login's two steps the password hash (it authenticates, it
//     decrypts nothing) and the stretched pair (non-extractable) wait in
//     `pending`; a lock or a finished login drops them.
//   - Unlocked, the keys are non-extractable CryptoKeys in a `KeyRing`; the
//     vault stays the server's encrypted snapshot, in memory only.
//   - The catalogue holds what a list shows, decrypted; secrets are opened
//     only inside `copy`, `reveal` and `totp`, used and let go.
//   - Unlocked, a SHA-256 digest of the login's password hash (it checks a
//     re-prompt, it logs no one in) is held in memory by the writes
//     (writes.ts), whose drafts' secrets are sealed and their bytes wiped.
//   - A login waiting for its second step is dropped after five minutes.
//   - The tokens and the still-encrypted keys are held in memory too (see
//     session.ts): a reload is a whole login. Nothing is written to storage
//     but the random device id.
//   - An item marked `reprompt` opens no secret unless `verifyReprompt` saw
//     the master password for it within the last minute.
// `lock()` drops keys, snapshot, catalogue, a login in progress and the
// re-prompts seen, and clears what a copy left on the clipboard.
import { type Backend, type Capabilities, type Change, type Copied, type LoginStep, type Revealed, type Session, TwoFactorProvider, SessionState, ChangeKind, LoginStepKind } from "@keyward/core/backend";
import { type Catalog, type ItemDetail, type Member, type OrgRole, type Permission, type SecretRef, type Totp, SecretField } from "@keyward/core/model/types";
import type { Contribution } from "@keyward/core/path/directory";
import type { GeneratorOptions, Invite, ItemDraft, Writes } from "@keyward/core/writes";
import { Api, isPathId, spent, type FetchLike, type LoginAnswer, type Tokens, LoginAnswerKind } from "./api";
import { abilitiesOf, buildCatalog, buildDetail, findCipher, membersOf, secretText } from "./catalog";
import { ClipboardGuard, realTimers, type ClipboardLike, type ClipboardState, type FocusEnv, type Timers } from "./clipboard";
import { DEFAULT_IDLE_MS, NEW_DEVICE, serverConfig, WEB_CAPS, type ServerConfig } from "./config";
import { stretch, type SymKey } from "./crypto";
import { zero } from "./bytes";
import { unwrapSymKey } from "./encstring";
import { fail, isWebError } from "./errors";
import { deriveMasterKey, fromPassword, normalEmail, type Kdf } from "./kdf";
import { KeyRing } from "./keys";
import { browserIdleEnv, IdleLock, MemoryStorage, SessionStore, type IdleEnv, type Persisted, type StorageLike } from "./session";
import { inTrash, parseSync, type SyncData } from "./sync";
import { parseTotp, totpAt } from "./totp";
import { WebWrites } from "./writes";

export { WebError, isWebError, type ErrorCode } from "./errors";

export type WebBackendOptions = {
  /// The server; by default `VITE_KEYWARD_SERVER`, else the page's origin.
  server?: string;
  fetch?: FetchLike;
  /// Where the device id is kept (localStorage by default) — the only thing
  /// this backend writes to any storage.
  deviceStorage?: StorageLike;
  clipboard?: () => ClipboardLike | undefined;
  timers?: Timers;
  /// The page's focus, as the clipboard's clear needs it; `null`: always
  /// focused (tests, a page without a document).
  focus?: FocusEnv | null;
  /// The idle lock's world; `null` turns it off (tests, a page without a
  /// document).
  idle?: IdleEnv | null;
  idleTimeoutMs?: number;
  now?: () => number;
};

/// Bitwarden's provider ids → the window's names. 5 is the "remember me"
/// token, not something a person picks; 4 (U2F) is WebAuthn's forerunner.
const PROVIDER_NAMES: Record<number, TwoFactorProvider | null> = {
  0: TwoFactorProvider.Authenticator,
  1: TwoFactorProvider.Email,
  2: TwoFactorProvider.Duo,
  3: TwoFactorProvider.Yubikey,
  4: TwoFactorProvider.WebAuthn,
  5: null,
  6: TwoFactorProvider.Duo,
  7: TwoFactorProvider.WebAuthn,
  8: TwoFactorProvider.Recovery,
};

/// The names a code can be typed for, back to their ids. Duo and WebAuthn
/// need a browser flow of their own that this backend does not run.
const PROVIDER_IDS: Partial<Record<TwoFactorProvider, number>> = { [TwoFactorProvider.Authenticator]: 0, [TwoFactorProvider.Email]: 1, [TwoFactorProvider.Yubikey]: 3, [TwoFactorProvider.Recovery]: 8 };

type Pending = {
  email: string;
  kdf: Kdf;
  passwordHash: string;
  stretched: SymKey;
  /// The device check (`NEW_DEVICE`) or a second factor.
  providers: number[];
  /// When the login's first step was answered: after `PENDING_LOGIN_MS` the
  /// waiting hash and stretched key are dropped.
  at: number;
};

/// How long a login waits for its second step.
export const PENDING_LOGIN_MS = 5 * 60 * 1000;
/// How long a master password checked by `verifyReprompt` opens its item.
export const REPROMPT_FRESH_MS = 60 * 1000;

function safeStorage(pick: () => Storage | undefined): StorageLike {
  try {
    const s = pick();
    if (s) {
      // Some private modes hand out a storage that throws on write.
      const probe = "keyward.web.probe";
      s.setItem(probe, "1");
      s.removeItem(probe);
      return s;
    }
  } catch {
    // Refused: the device id lives in memory for the page's life instead.
  }
  return new MemoryStorage();
}

export class WebBackend implements Backend, Writes {
  readonly caps: Capabilities;

  private readonly cfg: ServerConfig;
  private readonly api: Api;
  private readonly store: SessionStore;
  private readonly clipboard: ClipboardGuard;
  private readonly idle: IdleLock | null;
  private readonly now: () => number;
  private readonly listeners = new Set<(c: Change) => void>();

  private persisted: Persisted | null | undefined = undefined;
  private pending: Pending | null = null;
  private ring: KeyRing | null = null;
  private snapshot: SyncData | null = null;
  private members: Member[] = [];
  private cached: Catalog | null = null;
  private refreshing: Promise<string> | null = null;
  private readonly timers: Timers;
  private pendingTimer: unknown = null;
  /// The protected user key the ring was opened from: what a re-prompt's
  /// password must open again.
  private openedKey: string | null = null;
  /// Item id → when its re-prompt was last passed.
  private readonly reprompted = new Map<string, number>();
  /// The write side (writes.ts), over this session's keys and snapshot.
  private readonly writes: WebWrites;

  constructor(opts: WebBackendOptions = {}) {
    this.cfg = serverConfig(opts.server);
    const f = opts.fetch ?? ((input: string, init: RequestInit) => globalThis.fetch(input, init));
    this.api = new Api(this.cfg, f);
    this.store = new SessionStore(opts.deviceStorage ?? safeStorage(() => globalThis.localStorage));
    this.timers = opts.timers ?? realTimers;
    this.clipboard = new ClipboardGuard(opts.clipboard, opts.timers, undefined, opts.focus);
    // Honest: true only where there is a clipboard this page can write (and
    // so clear); a clear that is overdue shows in `clipboardState()`.
    this.caps = { ...WEB_CAPS, clipboardClears: this.clipboard.canClear() };
    this.now = opts.now ?? (() => Date.now());
    this.writes = new WebWrites({
      open: () => this.open_(),
      catalog: () => this.catalog(),
      authed: (method, path, json) => this.authed(method, path, json),
      sync: () => this.sync(),
      account: () => {
        const p = this.saved() ?? fail("err.loggedOut");
        return { email: p.email, kdf: p.kdf };
      },
      emit: (c) => this.emit(c),
      now: () => this.now(),
    });
    const env = opts.idle === undefined ? browserIdleEnv() : opts.idle;
    this.idle = env ? new IdleLock(env, opts.idleTimeoutMs ?? DEFAULT_IDLE_MS, () => void this.lock()) : null;
  }

  // --- the session ---------------------------------------------------------

  async session(): Promise<Session> {
    const p = this.saved();
    const server = this.cfg.server;
    if (p && this.ring) return { state: SessionState.Unlocked, email: p.email, server, name: p.name };
    if (p) return { state: SessionState.Locked, email: p.email, server };
    return { state: SessionState.LoggedOut, email: this.livePending()?.email ?? null, server };
  }

  subscribe(cb: (c: Change) => void): () => void {
    this.listeners.add(cb);
    return () => this.listeners.delete(cb);
  }

  /// The server is the deployment's; a `server` in the input is ignored.
  async login(input: { server?: string; email: string; password: string }): Promise<LoginStep> {
    this.drop();
    const email = normalEmail(input.email);
    if (email === "") fail("err.loginFailed", { reason: "email" });
    const kdf = await this.api.prelogin(email);
    const { hash, stretched } = await fromPassword(input.password, email, kdf);
    const remembered = this.store.remembered(email);
    const answer = await this.api.login({
      email,
      passwordHash: hash,
      device: { id: this.store.deviceId() },
      ...(remembered ? { twoFactor: { provider: 5, token: remembered, remember: false } } : {}),
    });
    // Asked for a second factor despite the remember token: it has expired.
    if (remembered && answer.kind !== LoginAnswerKind.Done) this.store.remember(email, null);
    return this.step(answer, { email, kdf, passwordHash: hash, stretched, providers: [], at: this.now() }, false);
  }

  /// The second step. After `{ step: "newDevice" }` the code is the device
  /// check's, whatever `provider` says (it travels as `newDeviceOtp`, the way
  /// the daemon sends its pseudo-provider 100).
  async twoFactor(input: { provider: TwoFactorProvider; code: string; remember: boolean }): Promise<LoginStep> {
    const p = this.livePending() ?? fail("err.noPendingLogin");
    const code = input.code.replace(/\s+/g, "");
    if (code === "") fail("err.badTwoFactor");
    const device = { id: this.store.deviceId() };
    let answer: LoginAnswer;
    if (p.providers.includes(NEW_DEVICE)) {
      answer = await this.api.login({ email: p.email, passwordHash: p.passwordHash, device, newDeviceOtp: code });
    } else {
      const id = PROVIDER_IDS[input.provider] ?? fail("err.twoFactorUnsupported", { provider: input.provider });
      if (!p.providers.includes(id)) fail("err.twoFactorUnsupported", { provider: input.provider });
      answer = await this.api.login({
        email: p.email,
        passwordHash: p.passwordHash,
        device,
        twoFactor: { provider: id, token: code, remember: input.remember },
      });
    }
    return this.step(answer, p, input.remember);
  }

  /// Asks the server to send the code by email — the second factor's, or the
  /// device check's again. The gate reaches it through `sendTwoFactorCode`
  /// where the provider is `email` or the step is `newDevice`.
  async sendCode(): Promise<void> {
    const p = this.livePending() ?? fail("err.noPendingLogin");
    if (p.providers.includes(NEW_DEVICE)) await this.api.resendNewDeviceCode(p.email, p.passwordHash);
    else await this.api.sendTwoFactorEmail(p.email, p.passwordHash, { id: this.store.deviceId() });
  }

  /// The `Backend`'s way to the same: the provider is the second factor's
  /// (only `email` sends anything) or, after `newDevice`, ignored.
  async sendTwoFactorCode(provider: TwoFactorProvider): Promise<void> {
    const p = this.livePending() ?? fail("err.noPendingLogin");
    if (!p.providers.includes(NEW_DEVICE) && provider !== TwoFactorProvider.Email) fail("err.twoFactorUnsupported", { provider });
    await this.sendCode();
  }

  private async step(answer: LoginAnswer, p: Pending, remember: boolean): Promise<LoginStep> {
    switch (answer.kind) {
      case LoginAnswerKind.NewDevice:
        this.setPending({ ...p, providers: [NEW_DEVICE] });
        this.emit({ kind: ChangeKind.Session });
        return { step: LoginStepKind.NewDevice };
      case LoginAnswerKind.TwoFactor: {
        const names: TwoFactorProvider[] = [];
        for (const id of answer.providers) {
          if (!(id in PROVIDER_NAMES)) fail("err.twoFactorProviderUnknown", { id });
          const name = PROVIDER_NAMES[id];
          if (name && !names.includes(name)) names.push(name);
        }
        this.setPending({ ...p, providers: answer.providers });
        this.emit({ kind: ChangeKind.Session });
        return { step: LoginStepKind.TwoFactor, providers: names };
      }
      case LoginAnswerKind.Done: {
        if (remember && answer.rememberToken) this.store.remember(p.email, answer.rememberToken);
        const persisted: Persisted = {
          v: 1,
          email: p.email,
          name: null,
          kdf: p.kdf,
          protectedKey: answer.key,
          protectedPrivateKey: answer.privateKey,
          accessToken: answer.accessToken,
          refreshToken: answer.refreshToken,
        };
        this.persist(persisted);
        this.clearPending();
        await this.open(persisted.protectedKey, p.stretched);
        await this.writes.remember(p.passwordHash);
        return { step: LoginStepKind.Done };
      }
    }
  }

  async unlock(password: string): Promise<void> {
    const p = this.saved() ?? fail("err.loggedOut");
    this.drop();
    const { hash, stretched } = await fromPassword(password, p.email, p.kdf);
    await this.open(p.protectedKey, stretched);
    await this.writes.remember(hash);
  }

  /// Opens the user key, syncs, and starts the idle lock. A sync that fails
  /// leaves the session locked: an unlocked window with no vault is worse
  /// than a refusal it can say.
  private async open(protectedKey: string, stretched: SymKey): Promise<void> {
    const ring = await KeyRing.open(protectedKey, stretched);
    this.ring = ring;
    this.openedKey = protectedKey;
    try {
      await this.sync();
    } catch (e) {
      if (this.ring === ring) this.drop();
      throw e;
    }
    this.idle?.start();
    this.emit({ kind: ChangeKind.Session });
  }

  async lock(): Promise<void> {
    this.drop();
    await this.clipboard.flush();
    this.emit({ kind: ChangeKind.Session });
  }

  async logout(): Promise<void> {
    const p = this.saved();
    this.drop();
    await this.clipboard.flush();
    this.store.clear();
    if (p) this.store.remember(p.email, null);
    this.persisted = null;
    this.emit({ kind: ChangeKind.Session });
  }

  /// Everything decrypted and every key, let go of at once.
  private drop(): void {
    this.idle?.stop();
    this.ring?.drop();
    this.ring = null;
    this.writes.forget();
    this.snapshot = null;
    this.cached = null;
    this.members = [];
    this.clearPending();
    this.openedKey = null;
    this.reprompted.clear();
  }

  /// The login waiting for its second step, unless it has waited too long:
  /// then it is dropped here (a background tab's timer may fire late).
  private livePending(): Pending | null {
    const p = this.pending;
    if (p && !(this.now() - p.at <= PENDING_LOGIN_MS)) {
      this.clearPending();
      return null;
    }
    return p;
  }

  private setPending(p: Pending): void {
    this.clearPending();
    this.pending = p;
    const left = Math.max(0, PENDING_LOGIN_MS - (this.now() - p.at));
    this.pendingTimer = this.timers.setTimeout(() => {
      if (this.pending !== p) return;
      this.clearPending();
      this.emit({ kind: ChangeKind.Session });
    }, left + 1);
  }

  private clearPending(): void {
    if (this.pendingTimer !== null) this.timers.clearTimeout(this.pendingTimer);
    this.pendingTimer = null;
    this.pending = null;
  }

  // --- the vault -----------------------------------------------------------

  async sync(): Promise<void> {
    const ring = this.ring ?? fail("err.locked");
    const body = await this.authed("GET", "sync?excludeDomains=true");
    const data = parseSync(body);
    const p = this.saved() ?? fail("err.loggedOut");
    if (normalEmail(data.profile.email) !== p.email) fail("err.syncUnreadable", { reason: "profile.email" });
    await ring.load(data.profile.privateKey ?? p.protectedPrivateKey, data.profile.organizations);

    const members: Member[] = [];
    for (const o of data.profile.organizations) {
      if (!abilitiesOf(o).manageMembers || !ring.hasOrg(o.id)) continue;
      if (!isPathId(o.id)) fail("err.badIdentifier");
      try {
        members.push(...membersOf(o.id, await this.authed("GET", `organizations/${o.id}/users`), p.email));
      } catch (e) {
        // The server has the last word on rights: a refusal here means no
        // members to show, not a broken vault.
        if (!isWebError(e, "err.forbidden")) throw e;
      }
    }

    // A lock that came while the answer was on its way wins.
    if (this.ring !== ring) fail("err.locked");
    this.snapshot = data;
    this.members = members;
    this.cached = null;
    // The server's current keys (still encrypted) for the next unlock, and
    // the display name.
    this.persist({
      ...p,
      name: data.profile.name,
      protectedKey: data.profile.key ?? p.protectedKey,
      protectedPrivateKey: data.profile.privateKey ?? p.protectedPrivateKey,
    });
    this.emit({ kind: ChangeKind.Catalog });
  }

  async catalog(): Promise<Catalog> {
    const { snapshot, ring } = this.open_();
    if (!this.cached) {
      const built = await buildCatalog(snapshot, ring, this.members);
      if (this.ring !== ring) fail("err.locked");
      this.cached = built;
    }
    return this.cached;
  }

  async contributions(): Promise<Contribution[]> {
    // Plugins live in the daemon; the web app has none.
    return [];
  }

  async item(id: string): Promise<ItemDetail> {
    const { snapshot, ring } = this.open_();
    const item = (await this.catalog()).items.find((i) => i.id === id) ?? fail("err.itemNotFound");
    return buildDetail(snapshot, ring, id, item);
  }

  /// A TOTP field is copied as its current code, never as its seed.
  async copy(ref: SecretRef): Promise<Copied> {
    const value = ref.field === SecretField.Totp ? (await this.totp(ref.itemId)).code : await this.secret(ref);
    await this.clipboard.copy(value);
    return { clearsIn: this.clipboard.canClear() ? this.clipboard.clearsInSeconds() : null };
  }

  async reveal(ref: SecretRef): Promise<Revealed> {
    const value = ref.field === SecretField.Totp ? (await this.totp(ref.itemId)).code : await this.secret(ref);
    // The only reference to the text is this object's: `drop` lets it go.
    const shown: Revealed = {
      value,
      drop: () => {
        shown.value = "";
      },
    };
    return shown;
  }

  async totp(itemId: string): Promise<Totp> {
    const seed = await this.secret({ itemId, field: SecretField.Totp });
    return totpAt(parseTotp(seed), this.now());
  }

  /// Every secret the window gets goes through here (copy, reveal, totp).
  private async secret(ref: SecretRef): Promise<string> {
    const { snapshot, ring } = this.open_();
    // Only what the list knows can be asked for: a service item (`kw-hidden`)
    // is not the window's to open.
    const item = (await this.catalog()).items.find((i) => i.id === ref.itemId) ?? fail("err.itemNotFound");
    if (item.reprompt) {
      const at = this.reprompted.get(ref.itemId);
      const age = at === undefined ? Infinity : this.now() - at;
      if (!(age >= 0 && age <= REPROMPT_FRESH_MS)) fail("err.repromptRequired");
    }
    return secretText(snapshot, ring, ref);
  }

  /// The re-prompt (ui/core `Backend.verifyReprompt`): the master password
  /// is derived again and must open the very protected user key this
  /// session's ring was opened from — its mac is checked under the stretched
  /// key, so only the right password passes, and a key the server swapped in
  /// since does not count. Passed, the item's secrets open for
  /// `REPROMPT_FRESH_MS`; a wrong password is `err.badPassword` and opens
  /// nothing. The derived keys are dropped at once.
  async verifyReprompt(itemId: string, password: string): Promise<void> {
    const { ring } = this.open_();
    if (!(await this.catalog()).items.some((i) => i.id === itemId)) fail("err.itemNotFound");
    const p = this.saved() ?? fail("err.loggedOut");
    const opened = this.openedKey ?? fail("err.locked");
    const mk = await deriveMasterKey(password, p.email, p.kdf);
    let stretched: SymKey;
    try {
      stretched = await stretch(mk);
    } finally {
      zero(mk);
    }
    try {
      await unwrapSymKey(opened, stretched);
    } catch (e) {
      if (isWebError(e, "err.macMismatch")) fail("err.badPassword");
      throw e;
    }
    // A lock while the KDF ran wins.
    if (this.ring !== ring) fail("err.locked");
    this.reprompted.set(itemId, this.now());
  }

  /// What the clipboard holds of a copy (ui/core `Backend.clipboardState`):
  /// `"stuck"` while a due clear could not be done.
  clipboardState(): ClipboardState {
    return this.clipboard.state();
  }

  watchClipboard(cb: (s: ClipboardState) => void): () => void {
    return this.clipboard.watch(cb);
  }

  async trash(ids: string[]): Promise<void> {
    const list = this.chosen(ids, false);
    for (const id of list) await this.authed("PUT", `ciphers/${id}/delete`);
    if (list.length) await this.sync();
  }

  async restore(ids: string[]): Promise<void> {
    const list = this.chosen(ids, true);
    for (const id of list) await this.authed("PUT", `ciphers/${id}/restore`);
    if (list.length) await this.sync();
  }

  /// For good, and only what is already in the trash. One request for all
  /// (a hundred separate ones are a hundred chances to break off halfway);
  /// a server without the batch endpoint gets them one at a time. An empty
  /// selection sends nothing: `DELETE /api/ciphers` with no ids empties the
  /// whole vault on some servers.
  async purge(ids: string[]): Promise<void> {
    const list = this.chosen(ids, true);
    if (!list.length) return;
    try {
      await this.authed("DELETE", "ciphers", { ids: list });
    } catch (e) {
      if (isWebError(e, "err.sessionExpired") || isWebError(e, "err.sessionEnded") || isWebError(e, "err.serverUnreachable")) throw e;
      for (const id of list) await this.authed("DELETE", `ciphers/${id}`);
    }
    await this.sync();
  }

  /// The identifiers, checked: path-safe, known, each once, and in the trash
  /// (or out of it) as the action needs.
  private chosen(ids: string[], trashed: boolean): string[] {
    const { snapshot } = this.open_();
    const out: string[] = [];
    for (const id of ids) {
      if (!isPathId(id)) fail("err.badIdentifier");
      if (out.includes(id)) continue;
      const c = findCipher(snapshot, id);
      if (inTrash(c) !== trashed) fail(trashed ? "err.notInTrash" : "err.alreadyInTrash");
      out.push(id);
    }
    return out;
  }

  // --- writes (writes.ts) ---------------------------------------------------

  verifyPassword(password: string): Promise<boolean> {
    return this.writes.verifyPassword(password);
  }
  create(draft: ItemDraft): Promise<string> {
    return this.writes.create(draft);
  }
  update(id: string, draft: ItemDraft): Promise<void> {
    return this.writes.update(id, draft);
  }
  generate(opts: GeneratorOptions): Promise<{ value: string; drop: () => void }> {
    return this.writes.generate(opts);
  }
  createFolder(name: string): Promise<string> {
    return this.writes.createFolder(name);
  }
  renameFolder(id: string, name: string): Promise<void> {
    return this.writes.renameFolder(id, name);
  }
  deleteFolder(id: string): Promise<void> {
    return this.writes.deleteFolder(id);
  }
  createCollection(orgId: string, name: string): Promise<string> {
    return this.writes.createCollection(orgId, name);
  }
  renameCollection(orgId: string, id: string, name: string): Promise<void> {
    return this.writes.renameCollection(orgId, id, name);
  }
  deleteCollection(orgId: string, id: string): Promise<void> {
    return this.writes.deleteCollection(orgId, id);
  }
  invite(orgId: string, invite: Invite): Promise<void> {
    return this.writes.invite(orgId, invite);
  }
  setMember(orgId: string, memberId: string, change: { role: OrgRole; accessAll: boolean; access: Record<string, Permission> }): Promise<void> {
    return this.writes.setMember(orgId, memberId, change);
  }
  memberFingerprint(orgId: string, memberId: string): Promise<string[]> {
    return this.writes.memberFingerprint(orgId, memberId);
  }
  confirmMember(orgId: string, memberId: string, fingerprint: string[]): Promise<void> {
    return this.writes.confirmMember(orgId, memberId, fingerprint);
  }
  removeMember(orgId: string, memberId: string): Promise<void> {
    return this.writes.removeMember(orgId, memberId);
  }

  // --- tokens --------------------------------------------------------------

  /// An authorised request with a fresh token; a 401 is answered by one
  /// refresh and one retry.
  private async authed(method: string, path: string, json?: unknown): Promise<string> {
    try {
      return await this.api.authed(method, path, await this.token(false), json);
    } catch (e) {
      if (!isWebError(e, "err.sessionExpired")) throw e;
      return this.api.authed(method, path, await this.token(true), json);
    }
  }

  private async token(force: boolean): Promise<string> {
    const p = this.saved() ?? fail("err.loggedOut");
    if (!force && !spent(p.accessToken, Math.floor(this.now() / 1000), 60)) return p.accessToken;
    // One refresh at a time: two at once would race the rotated refresh
    // token, and the loser's would be dead.
    this.refreshing ??= this.refresh(p).finally(() => {
      this.refreshing = null;
    });
    return this.refreshing;
  }

  private async refresh(p: Persisted): Promise<string> {
    let t: Tokens;
    try {
      t = await this.api.refresh(p.refreshToken);
    } catch (e) {
      if (isWebError(e, "err.sessionEnded")) {
        // The server ended the session: its tokens are worth nothing, and
        // keeping them would only fail every request after. Signed out.
        this.drop();
        this.store.clear();
        this.persisted = null;
        this.emit({ kind: ChangeKind.Session });
      }
      throw e;
    }
    const now = this.saved() ?? fail("err.loggedOut");
    this.persist({ ...now, accessToken: t.accessToken, refreshToken: t.refreshToken ?? now.refreshToken });
    return t.accessToken;
  }

  // --- small things --------------------------------------------------------

  private saved(): Persisted | null {
    if (this.persisted === undefined) this.persisted = this.store.load();
    return this.persisted;
  }

  private persist(p: Persisted): void {
    this.persisted = p;
    this.store.save(p);
  }

  private open_(): { snapshot: SyncData; ring: KeyRing } {
    const ring = this.ring ?? fail("err.locked");
    const snapshot = this.snapshot ?? fail("err.locked");
    return { snapshot, ring };
  }

  private emit(c: Change): void {
    for (const l of this.listeners) l(c);
  }
}
