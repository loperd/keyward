export type VaultState =
  | { state: "needs_setup" }
  | { state: "logged_out"; email: string; server: string }
  | { state: "locked"; email: string; server: string }
  | { state: "unlocked"; email: string; server: string; entries: number; tagged: number }
  | { state: "disabled" };

export type Account = { id: string; base_url: string; email: string; identity_url: string | null };
export type AccountView = {
  account: Account;
  state: VaultState;
  biometric: boolean;
  /// Whether a PIN for unlocking is set.
  pin: boolean;
};
export type AccountList = { accounts: AccountView[]; active: string | null };

export type ItemKind = "login" | "card" | "identity" | "secure_note" | "ssh_key";

export type VaultItem = {
  id: string;
  name: string;
  kind: ItemKind;
  subtitle: string | null;
  /** A locally inferred payment network label; no card digits are present. */
  card_brand?: string | null;
  folder_id: string | null;
  folder_name: string | null;
  org_id: string | null;
  uris: string[];
  /// The item's own `kw-*` fields. What any of them means belongs to the plugin
  /// that reads it; the list shows them and searches by them.
  tags: Record<string, string>;
  has_totp: boolean;
  passkeys: number;
  favorite: boolean;
  deleted: boolean;
  org_name: string | null;
  collection_ids: string[];
  reprompt: boolean;
};

/// One's role in an organisation — `keyward_core::items::OrgRole`.
export type OrgRole = "owner" | "admin" | "user" | "manager" | "custom" | "unknown";
export type MemberStatus = "revoked" | "invited" | "accepted" | "confirmed" | "unknown";
/// What one may do in an organisation, worked out by the daemon from what the
/// server sent — `OrgAbilities`. The window shows or hides by these and never
/// compares roles itself.
export type OrgAbilities = {
  edit_org: boolean;
  manage_users: boolean;
  create_collections: boolean;
  edit_collections: boolean;
  delete_collections: boolean;
  assignable_roles: OrgRole[];
};
export type Org = { id: string; name: string; role: OrgRole; can: OrgAbilities; count: number };
export type CollectionView = {
  id: string;
  name: string;
  org_id: string | null;
  read_only: boolean;
  count: number;
};

export type Catalog = {
  items: VaultItem[];
  folders: { id: string; name: string; count: number }[];
  counts: [string, number][];
  unfiled: number;
  orgs: Org[];
  collections: CollectionView[];
  trash: number;
  favorites: number;
};

export type TwoFactorProvider = { id: number; name: string; prompt: string; kind: string };

export type LoginReply =
  | { kind: "done"; state: VaultState }
  | { kind: "two_factor"; providers: TwoFactorProvider[] };

export type Status = {
  version: string;
  source: string;
  pending_edits: number;
  vault: VaultState;
  biometric: boolean;
  /// Whether a PIN is set for unlocking the active account.
  pin: boolean;
};

/// The keys of item kinds in the catalogue's counts arrive from the backend
/// as strings.
export const KIND_KEYS = ["login", "card", "identity", "note", "ssh_key"] as const;
export type KindKey = (typeof KIND_KEYS)[number];

/// An item's kind in the counts and its kind on the item itself are named
/// differently: "note" against "secure_note". The mapping is kept in one
/// place.
/// The dictionary key of a kind's name. The kinds themselves are data
/// (`ssh_key`), the keys are camelCase (`kind.sshKey`).
export function kindLabel(k: string): `kind.${string}` {
  return `kind.${k.replace(/_([a-z0-9])/g, (_, c: string) => c.toUpperCase())}`;
}

export function kindKey(kind: ItemKind): KindKey {
  return kind === "secure_note" ? "note" : (kind as KindKey);
}

/// A secret's field: in the backend this is an enum whose variant with a
/// payload serialises as an object.
export type SecretField =
  | "password"
  | "username"
  | "totp"
  | "totp_secret"
  | "card_number"
  | "card_code"
  | "card_holder"
  | "notes"
  | "private_key"
  | { custom: string }
  | { password_history: number };

export type DetailField = {
  /// The key of a built-in field: translating the caption is the interface's
  /// business. `null` means a person made the name up and there is nothing to
  /// translate.
  key: string | null;
  label: string;
  value: string | null;
  secret: SecretField | null;
  hidden: boolean;
  mono: boolean;
};

export type Passkey = {
  credential_id: string;
  rp_id: string;
  rp_name: string | null;
  user_name: string | null;
  user_display_name: string | null;
  key_algorithm: string | null;
  key_curve: string | null;
  discoverable: boolean;
  counter: number | null;
  created: string | null;
  /** When keyward last signed in with it, on this machine. */
  last_used: string | null;
};

/** A password the login had before: when it was replaced, never its value. */
export type PasswordHistoryEntry = {
  index: number;
  last_used: string | null;
};

export type ItemDetail = {
  id: string;
  name: string;
  kind: ItemKind;
  folder_name: string | null;
  fields: DetailField[];
  uris: string[];
  passkeys: Passkey[];
  password_history?: PasswordHistoryEntry[];
  reprompt: boolean;
  deleted: boolean;
  custom: { name: string; value: string | null; hidden: boolean; kind: number; linked_id: number | null }[];
  favorite: boolean;
};

export type EditState =
  | { state: "pending"; attempts: number; last_error: string | null }
  | { state: "pushed" }
  | { state: "rolled_back" };

export type PendingEdit = {
  id: string;
  account_id: string;
  entry_id: string;
  entry_name: string;
  created_at: string;
  changed: { label: string; had_value: boolean; has_value: boolean }[];
  state: EditState;
  /** Its vault is locked: the name and the fields stay sealed. */
  locked?: boolean;
  /** Its file cannot be read: it can only be discarded. */
  damaged?: boolean;
};

export type ItemEdit = {
  /// `null` takes it out of its folder, `undefined` leaves it alone.
  folder_id?: string | null;
  name?: string | null;
  username?: string | null;
  password?: string | null;
  totp?: string | null;
  notes?: string | null;
  custom?: [string, string][];
};

export type LockTimeout =
  | { kind: "on_restart" }
  | { kind: "minutes"; minutes: number }
  | { kind: "never" };

export type OrgMember = {
  id: string;
  user_id: string | null;
  name: string | null;
  email: string;
  role: OrgRole;
  status: MemberStatus;
  two_factor: boolean;
  access_all: boolean;
  collections: number;
  is_you: boolean;
  /// Set by the daemon: may the one looking change or remove this member.
  can_edit: boolean;
  can_confirm: boolean;
};

/// What to do when the time is up: lock, or log out of the account
/// altogether.
export type LockAction = "lock" | "logout";

/// A mirror of `keyward_core::settings::Settings`, in full, because
/// `set_settings` sends the object back and a missing field would travel as its
/// default.
export type AppSettings = {
  lock_timeout: LockTimeout;
  lock_action: LockAction;
  touch_id_on_launch: boolean;
  touch_id_for_secrets: boolean;
  clipboard_clear_seconds: number;
  biometric_grace_seconds: number;
  show_website_icons: boolean;
  hide_on_copy: boolean;
  keep_in_tray: boolean;
  keep_in_dock: boolean;
  allow_screen_capture: boolean;
  start_on_login: boolean;
  theme: "system" | "dark" | "light";
  accent_color: string | null;
  language: "auto" | "ru" | "en";
};

// -- The Bitwarden account (a mirror of crates/core/src/account.rs) --------

export type KdfInfo =
  | { kind: "pbkdf2"; iterations: number }
  | { kind: "argon2id"; iterations: number; memory_mib: number; parallelism: number };

export type AccountProfile = {
  user_id: string;
  email: string;
  name: string | null;
  /// `#rrggbb`, or nothing — and then the colour is derived from the name.
  avatar_color: string | null;
  master_password_hint: string | null;
  email_verified: boolean;
  premium: boolean;
  creation_date: string | null;
  kdf: KdfInfo;
  /// The five words of the fingerprint.
  fingerprint: string[];
  two_factor_enabled: boolean;
};

export type TwoFactorOther = { provider: number; name: string };
export type TwoFactorStatus = { authenticator: boolean; email: boolean; others: TwoFactorOther[] };
export type AuthenticatorSetup = { key: string; otpauth: string; enabled: boolean };
export type EmailTwoFactorSetup = { email: string; enabled: boolean };

export type Device = {
  id: string;
  name: string;
  /// `desktop`, `browser`, `mobile`, `cli`…
  kind: string;
  identifier: string;
  created: string | null;
  last_active: string | null;
  /// This device is keyward itself.
  current: boolean;
};

export type ExportFormat = "json" | "csv";
