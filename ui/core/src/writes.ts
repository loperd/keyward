// What the core asks of an app to change a vault. Kept apart from the read
// side so each app can grow its writes without touching the session's.
//
// A new secret a person types (a password, a note, a card number) has to
// exist in the page for the moment it is typed; it crosses to the backend
// once, inside a draft, and the draft is dropped after the call. A secret
// already stored is never sent back: a draft names it with `keep`.
import type { ItemKind, OrgRole, Permission } from "./model/types";

/// A secret in a draft: a value typed now, or the stored one kept.
export type SecretInput = { set: string } | { keep: true } | { clear: true };

export type DraftField =
  | { key: string; value: string }
  | { key: string; secret: SecretInput }
  | { custom: string; value: string; hidden: false }
  | { custom: string; secret: SecretInput; hidden: true };

/// An item as a person edits it. Built-in field keys by kind:
/// login: username, password, totp; card: cardholderName, brand, number,
/// expMonth, expYear, code; identity: title, firstName, lastName, email,
/// phone, address1…; ssh_key: privateKey, publicKey, fingerprint.
export type ItemDraft = {
  kind: ItemKind;
  name: string;
  folderId: string | null;
  orgId: string | null;
  collectionIds: string[];
  favorite: boolean;
  reprompt: boolean;
  uris: string[];
  notes: SecretInput;
  fields: DraftField[];
  /// The item's own `kw-*` fields, written back as they are.
  tags: Record<string, string>;
};

/// What a generator makes: a password of characters, or a phrase of words.
export enum GeneratorKind {
  Password = "password",
  Passphrase = "passphrase",
}
export type GeneratorOptions =
  | { kind: GeneratorKind.Password; length: number; upper: boolean; lower: boolean; digits: boolean; symbols: boolean; avoidAmbiguous: boolean }
  | { kind: GeneratorKind.Passphrase; words: number; separator: string; capitalize: boolean; number: boolean };

export type Invite = { emails: string[]; role: OrgRole; accessAll: boolean; access: Record<string, Permission> };

export interface Writes {
  /// Checks the master password without changing the session: what a
  /// re-prompt item asks for before it is copied or revealed.
  verifyPassword(password: string): Promise<boolean>;

  create(draft: ItemDraft): Promise<string>;
  update(id: string, draft: ItemDraft): Promise<void>;
  /// A fresh password or passphrase, as a value shown for a moment.
  generate(opts: GeneratorOptions): Promise<{ value: string; drop: () => void }>;

  createFolder(name: string): Promise<string>;
  renameFolder(id: string, name: string): Promise<void>;
  deleteFolder(id: string): Promise<void>;

  createCollection(orgId: string, name: string): Promise<string>;
  renameCollection(orgId: string, id: string, name: string): Promise<void>;
  deleteCollection(orgId: string, id: string): Promise<void>;

  invite(orgId: string, invite: Invite): Promise<void>;
  setMember(orgId: string, memberId: string, change: { role: OrgRole; accessAll: boolean; access: Record<string, Permission> }): Promise<void>;
  /// The member's fingerprint phrase: five words of the EFF long list from
  /// the public key the server gives for them now, salted with their user id
  /// (Bitwarden's algorithm). The owner compares it with the member out of
  /// band before confirming.
  memberFingerprint(orgId: string, memberId: string): Promise<string[]>;
  /// Seals the organisation key to the member's public key — only while that
  /// key still makes `fingerprint`, the words the person was shown; refused
  /// with `err.fingerprintChanged` otherwise.
  confirmMember(orgId: string, memberId: string, fingerprint: string[]): Promise<void>;
  removeMember(orgId: string, memberId: string): Promise<void>;
}

/// The joined contract, once every app implements its writes: the window
/// switches its props to it then.
export type FullBackend = import("./backend").Backend & Writes;
