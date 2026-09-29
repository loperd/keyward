/// The HashiCorp Vault plugin's types. The core knows nothing of them:
/// everything listed here arrives and leaves in one `plugin_call` envelope.

/// A connection to a Vault: the address and what lies under it in the item.
export type HashicorpLink = {
  entry_id: string;
  entry_name: string;
  addr: string;
  has_role_id: boolean;
  has_root: boolean;
  unseal_keys: number;
  /// The names of the fields that hold the unseal shares.
  unseal_fields?: string[];
};

export type SealStatus = {
  type: string;
  initialized: boolean;
  sealed: boolean;
  t: number;
  n: number;
  progress: number;
  version: string | null;
};

export type Health = { initialized: boolean; sealed: boolean; standby: boolean; version: string | null };

export type Recipient = "agent" | "person" | "me";

export type Issued = {
  accessor: string;
  recipient: Recipient;
  policies: string[];
  ttl_seconds: number;
  num_uses: number;
  note: string;
  created_at: number;
  wrapped: boolean;
  state: { state: "active" } | { state: "revoked" } | { state: "expired" };
};

export type IssueResult = { issued: Issued; wrapping_token: string | null; token: string | null };

export type Policy = { name: string; rules: string };

export type TokenInfo = {
  accessor: string;
  policies: string[];
  ttl_seconds: number;
  num_uses: number;
  display_name: string;
};

export type RootToken = {
  entry_id: string;
  addr: string;
  issued_at: number;
  info: TokenInfo | null;
};

export type Mount = {
  path: string;
  kind: string;
  description: string;
  kv2: boolean;
  accessor: string;
  default_lease_ttl: number;
  max_lease_ttl: number;
  auth: boolean;
};
export type MountForm = {
  path: string;
  kind: string;
  description: string;
  kv_version: number | null;
  default_lease_ttl: string;
  max_lease_ttl: string;
  auth: boolean;
};
export type MountTune = {
  description: string | null;
  default_lease_ttl: string | null;
  max_lease_ttl: string | null;
  kv_version: number | null;
};
export type KvConfig = { max_versions: number; cas_required: boolean; delete_version_after: string };
/// A kv engine's secret as the window sees it: the keys and how long each
/// value is — never the values. One is fetched on "show", or copied by the
/// plugin. The version and the date belong to kv v2 alone.
export type Secret = {
  mount: string;
  path: string;
  fields: { key: string; length: number }[];
  version: number | null;
  updated: string | null;
};

/// Every value, for the editor alone: a person is changing them.
export type SecretFull = {
  mount: string;
  path: string;
  data: Record<string, string>;
  version: number | null;
  updated: string | null;
};
export type SecretVersion = { version: number; created: string | null; deleted: string | null; destroyed: boolean };
export type SecretMeta = {
  mount: string;
  path: string;
  current_version: number;
  oldest_version: number;
  max_versions: number;
  cas_required: boolean;
  delete_version_after: string;
  custom_metadata: Record<string, string>;
  created: string | null;
  updated: string | null;
  versions: SecretVersion[];
};
export type SecretMetaPatch = {
  max_versions: number | null;
  cas_required: boolean | null;
  delete_version_after: string | null;
  custom_metadata: Record<string, string> | null;
};

/// The plugin's settings: the chosen connection and the notices about issues'
/// deadlines. They left the core's `Settings`, so they are sent as a whole
/// object.
export type HashicorpSettings = { active: string | null; expiry_notices: boolean };
