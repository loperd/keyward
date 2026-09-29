/// The ssh agent plugin's types. The core knows nothing of them.

/// Which kind of key to make — `keyward_core::edits::SshAlgorithm`.
export type SshAlgorithm = "ed25519" | "rsa4096";

/// What the plugin says of a pasted key — `keyward_sshkey::Summary`. The
/// private half never comes back.
export type KeySummary = { public_key: string; fingerprint: string; algorithm: string };

/// A vault item with an ssh key and the hosts it is bound to.
export type SshKeyEntry = { id: string; name: string; hosts: string };

/// A row of the table of routes: which key signs for which host.
export type Mapping = {
  entry_id: string;
  entry_name: string;
  pattern: string;
  user: string | null;
  host: string;
  port: number | null;
  cert_role: string | null;
  confirm: boolean;
  hostkey: string | null;
};

/// The plugin's settings: they left the core's `Settings`.
export type SshSettings = {
  agent_enabled: boolean;
  ask: "never" | "always";
  shared_socket: boolean;
};

/// The agent's state: the same numbers that used to lie in the daemon's
/// `Status`.
export type SshStatus = {
  mappings: number;
  live_sockets: number;
  warnings: string[];
  unmapped: string[];
  /// The shared socket's path, when it is up.
  socket: string | null;
};
