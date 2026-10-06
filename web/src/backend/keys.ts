// The keys of an unlocked session: the user key, the private key, the
// organisations' keys and the items' own keys — all non-extractable
// CryptoKeys, held only by this ring and dropped together on lock.
import { zero, type Bytes } from "./bytes";
import { decryptRsa, importPrivateKey, type PrivateKey, type SymKey } from "./crypto";
import { decryptBytes, oaepSha256, parseEncString, unwrapOrgKey, unwrapSymKey } from "./encstring";
import { fail, isWebError } from "./errors";

/// What the ring needs to know of an item to pick its key.
export type Keyed = { id: string; organizationId: string | null; key: string | null };

export class KeyRing {
  private user: SymKey | null;
  private privateKey: PrivateKey | null = null;
  private readonly orgs = new Map<string, SymKey>();
  /// Items' own keys, opened on first use. They are CryptoKeys too, so the
  /// cache holds nothing readable; it goes with the ring.
  private readonly items = new Map<string, SymKey>();

  private constructor(user: SymKey) {
    this.user = user;
  }

  /// The user key from its protected form. A wrong master password shows
  /// itself here, as a mac that does not match: said as a wrong password.
  static async open(protectedKey: string, stretched: SymKey): Promise<KeyRing> {
    try {
      return new KeyRing(await unwrapSymKey(protectedKey, stretched));
    } catch (e) {
      if (isWebError(e, "err.macMismatch")) fail("err.badPassword");
      throw e;
    }
  }

  /// The private key and, through it, the organisations' keys. Called after
  /// every sync: the server's list of organisations is the truth.
  async load(protectedPrivateKey: string | null, orgKeys: { id: string; key: string | null }[]): Promise<void> {
    const user = this.need();
    this.orgs.clear();
    this.items.clear();
    if (protectedPrivateKey === null) {
      if (orgKeys.some((o) => o.key !== null)) fail("err.keyMalformed", { reason: "noPrivateKey" });
      this.privateKey = null;
      return;
    }
    const der = await decryptBytes(protectedPrivateKey, user);
    try {
      this.privateKey = await importPrivateKey(der);
    } finally {
      zero(der);
    }
    for (const o of orgKeys) {
      // An organisation one has accepted but that has not confirmed one yet
      // has no key; its items do not come in a sync either.
      if (o.key === null) continue;
      this.orgs.set(o.id, await unwrapOrgKey(o.key, this.privateKey));
    }
  }

  hasOrg(id: string): boolean {
    return this.orgs.has(id);
  }

  /// The user key or an organisation's.
  base(orgId: string | null): SymKey {
    if (orgId === null) return this.need();
    return this.orgs.get(orgId) ?? fail("err.noOrgKey");
  }

  /// The key an item's fields are sealed with: its own if it has one (opened
  /// with the base key), else the base key.
  async forItem(c: Keyed): Promise<SymKey> {
    const base = this.base(c.organizationId);
    if (c.key === null) return base;
    const cached = this.items.get(c.id);
    if (cached) return cached;
    const own = await unwrapSymKey(c.key, base);
    this.items.set(c.id, own);
    return own;
  }

  /// An organisation key's own bytes, opened again from its sealed form for
  /// the one moment a confirm seals it for a member. Only for an organisation
  /// this ring holds the key of; the caller wipes the bytes right after.
  async orgKeyBytes(orgId: string, sealed: string): Promise<Bytes> {
    this.need();
    if (!this.orgs.has(orgId)) fail("err.noOrgKey");
    const privateKey = this.privateKey ?? fail("err.noOrgKey");
    const e = parseEncString(sealed);
    if (e.type === 2) return fail("err.encTypeUnsupported", { type: "2" });
    const raw = await decryptRsa(privateKey, oaepSha256(e), e.ct);
    if (raw.length !== 64) {
      zero(raw);
      fail("err.keyMalformed", { reason: "length", length: raw.length });
    }
    return raw;
  }

  /// The user key itself, for values that belong to the account (folders).
  userKey(): SymKey {
    return this.need();
  }

  /// Drops every key. CryptoKeys cannot be wiped, only let go of; without a
  /// reference they are unreachable and no script can use them again.
  drop(): void {
    this.user = null;
    this.privateKey = null;
    this.orgs.clear();
    this.items.clear();
  }

  private need(): SymKey {
    return this.user ?? fail("err.locked");
  }
}
