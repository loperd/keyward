// What the window knows about a vault. Both apps give the core the same
// shapes: the desktop app reads them from the daemon, the web app builds them
// in the tab. No shape here ever carries a secret's value — a secret is
// named by a `SecretRef` and asked for through the backend at the moment it
// is used.
import { enumParser } from "./enum";

export enum ItemKind {
  Login = "login",
  Card = "card",
  Identity = "identity",
  SecureNote = "secure_note",
  SshKey = "ssh_key",
}
export const parseItemKind = enumParser(ItemKind, "an item kind");

/// The spec's order of states, the most serious first. A state is never said
/// by colour alone: each has its own mark (`LEVEL_MARK`).
export enum Level {
  Critical = "critical",
  Action = "action",
  Warning = "warning",
  Healthy = "healthy",
  Unknown = "unknown",
}
export const parseLevel = enumParser(Level, "a level");
/// The levels a line or a legend entry is drawn in colour with.
export type LoudLevel = Level.Critical | Level.Warning;

/// What a list row and the catalogue know of an item: its name and place,
/// never its secrets.
export type Item = {
  id: string;
  name: string;
  kind: ItemKind;
  /// The quiet second line: a login, a host, a card's last four digits.
  subtitle: string | null;
  folderId: string | null;
  orgId: string | null;
  collectionIds: string[];
  uris: string[];
  /// The item's own `kw-*` fields; what each means belongs to a plugin.
  tags: Record<string, string>;
  hasTotp: boolean;
  passkeys: number;
  favorite: boolean;
  deleted: boolean;
  reprompt: boolean;
  /// When the item, and its password, last changed (ISO 8601).
  revised: string | null;
  passwordRevised: string | null;
  /// A card's expiry, `YYYY-MM`.
  expires: string | null;
  /// How many other items share this password, worked out where the keys
  /// are (the daemon, or the web app's crypto) from salted hashes.
  reused: number;
  /// Items with the same number share one password.
  reuseGroup: number | null;
};

export type Folder = { id: string; name: string };

export enum OrgRole {
  Owner = "owner",
  Admin = "admin",
  Manager = "manager",
  User = "user",
  Custom = "custom",
}
export const parseOrgRole = enumParser(OrgRole, "an organisation role");
export enum MemberStatus {
  Invited = "invited",
  Accepted = "accepted",
  Confirmed = "confirmed",
  Revoked = "revoked",
}
export const parseMemberStatus = enumParser(MemberStatus, "a member status");
/// What the one looking may do in an organisation, worked out by the backend
/// from what the server sent. The window shows or hides by these and never
/// compares roles itself.
export type OrgAbilities = {
  editOrg: boolean;
  manageMembers: boolean;
  manageCollections: boolean;
};
export type Org = { id: string; name: string; role: OrgRole; can: OrgAbilities };
export type Collection = { id: string; orgId: string; name: string; readOnly: boolean };

/// A level of access to a collection. `readHidden` and `editHidden` see
/// and change items without seeing their passwords.
export enum Permission {
  Manage = "manage",
  Edit = "edit",
  EditHidden = "editHidden",
  Read = "read",
  ReadHidden = "readHidden",
}
export const parsePermission = enumParser(Permission, "a collection permission");
/// A level that keeps passwords out of sight.
export const hidesPasswords = (p: Permission | null | undefined) => p === Permission.ReadHidden || p === Permission.EditHidden;
/// A level that changes what others use.
export const changesItems = (p: Permission | null | undefined) => p === Permission.Edit || p === Permission.EditHidden || p === Permission.Manage;
export type Member = {
  id: string;
  orgId: string;
  name: string | null;
  email: string;
  role: OrgRole;
  status: MemberStatus;
  twoFactor: boolean | null;
  accessAll: boolean;
  /// Collection id → level. Empty with `accessAll`.
  access: Record<string, Permission>;
  isYou: boolean;
};

/// An organisation's rule, as the server keeps it. Only an organisation's
/// admins see its policies; elsewhere the list is absent, not empty.
export enum PolicyType {
  MasterPassword = "masterPassword",
  TwoFactor = "twoFactor",
  SingleOrg = "singleOrg",
  ResetPassword = "resetPassword",
  PersonalOwnership = "personalOwnership",
  VaultTimeout = "vaultTimeout",
}
export const parsePolicyType = enumParser(PolicyType, "a policy type");
export type Policy = {
  orgId: string;
  type: PolicyType;
  enabled: boolean;
  /// The rule's settings: a master password's least length, a timeout in
  /// minutes.
  data: Record<string, number | boolean>;
};

/// Everything a session shows at once. Members come with the catalogue only
/// where the one looking may see them; so do policies.
export type Catalog = {
  items: Item[];
  folders: Folder[];
  orgs: Org[];
  collections: Collection[];
  members: Member[];
  policies?: Policy[];
  /// The organisations' members are still being read (a backend that reads
  /// them after the catalogue, and announces a change of the catalogue when
  /// they come): an organisation that can manage members and has none yet
  /// shows them as on their way, not as absent.
  membersLoading?: boolean;
};

/// Which secret of an item a reference names: a built-in one, or a field a
/// person made up (`Custom`, with its name).
export enum SecretField {
  Password = "password",
  Username = "username",
  Totp = "totp",
  CardNumber = "cardNumber",
  CardCode = "cardCode",
  Notes = "notes",
  PrivateKey = "privateKey",
  Custom = "custom",
}
export const parseSecretField = enumParser(SecretField, "a secret field");

/// A secret of an item, named, never carried.
export type SecretRef =
  | { itemId: string; field: Exclude<SecretField, SecretField.Custom> }
  | { itemId: string; field: SecretField.Custom; name: string };

/// One field of an opened item. A secret field has no value here: its value
/// is asked for by `ref` only when it is copied or revealed.
export type Field = {
  /// A built-in field's key (translated by the window); `null` for a name a
  /// person made up.
  key: string | null;
  label: string;
  value: string | null;
  secret: SecretRef | null;
  mono: boolean;
};

export type ItemDetail = {
  item: Item;
  fields: Field[];
  notes: SecretRef | null;
  passkeys: { rpId: string; userName: string | null }[];
  passwordHistory: { changed: string | null }[];
};

/// A one-time code and how long it lives.
export type Totp = { code: string; period: number; remaining: number };
