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

/// A field of a login that a merge compares and may take: the built-in
/// ones, a custom field by name, or the record's passkeys all together.
export enum MergeField {
  Username = "username",
  Password = "password",
  Totp = "totp",
  Notes = "notes",
  Custom = "custom",
  Passkeys = "passkeys",
}
export type MergeSlot = { field: Exclude<MergeField, MergeField.Custom> } | { field: MergeField.Custom; name: string };
/// One field of the records being merged, compared where the keys are: the
/// records holding it, and which of them hold the same value (one `group`).
/// No value comes with it. For passkeys each record is a group of its own.
export type MergeRow = { slot: MergeSlot; secret: boolean; holders: { itemId: string; group: number }[] };
export type MergeComparison = { rows: MergeRow[] };
/// A field taken from a merged record into the kept one: into its own place,
/// or, with `asName`, beside the kept record's own as a custom field.
export type MergeTake = { from: string; slot: MergeSlot; asName: string | null };
/// The kept record, the records merged into it, and what is taken from
/// them. Every record's addresses are joined; the others go to the trash
/// once the kept record is saved.
export type MergePlan = { keeper: string; others: string[]; takes: MergeTake[] };

export type Invite = { emails: string[]; role: OrgRole; accessAll: boolean; access: Record<string, Permission> };

export interface Writes {
  /// Checks the master password without changing the session: what a
  /// re-prompt item asks for before it is copied or revealed.
  verifyPassword(password: string): Promise<boolean>;

  create(draft: ItemDraft): Promise<string>;
  update(id: string, draft: ItemDraft): Promise<void>;
  /// A fresh password or passphrase, as a value shown for a moment.
  generate(opts: GeneratorOptions): Promise<{ value: string; drop: () => void }>;

  /// The records compared field by field where the keys are, in the order
  /// asked: which hold a field and which agree, never what it holds.
  compareForMerge(itemIds: string[]): Promise<MergeComparison>;
  /// Merges records into the plan's kept one, the values carried where the
  /// keys are; the others go to the trash only once it is saved.
  merge(plan: MergePlan): Promise<void>;

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
