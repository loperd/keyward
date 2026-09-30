/// The ssh agent plugin's types. The core knows nothing of them.

/// Which kind of key to make — `keyward_core::edits::SshAlgorithm`.
export type SshAlgorithm = "ed25519" | "rsa4096";

/// What the plugin says of a pasted key — `keyward_sshkey::Summary`. The
/// private half never comes back.
export type KeySummary = { public_key: string; fingerprint: string; algorithm: string };

/// A vault item with an ssh key and the hosts it is bound to.
export type SshKeyEntry = {
  id: string;
  name: string;
  hosts: string;
  /// `kw-user`: the login its hosts are entered with; empty when unset.
  user: string;
  /// `kw-port` as written; empty when unset.
  port: string;
};

/// What system answers on a host, read from its ssh banner before any login
/// — `terminal::probe::Banner`.
export type HostBanner = { banner: string; os: string | null; login: string };

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
  /// How often the keys' health is checked, in minutes; zero is never.
  health_minutes: number;
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

/// An unknown host's key, as the terminal asks about it —
/// `terminal::connect::HostPrompt`.
export type HostPrompt = { host: string; port: number; fingerprint: string; algorithm: string; others: boolean };

/// Where a terminal session is — `terminal::session::State`.
export type TermState =
  | { kind: "connecting" }
  | { kind: "verify"; prompt: HostPrompt }
  | { kind: "authenticating" }
  | { kind: "open" }
  | { kind: "closed"; error: string | null; exit: number | null };

/// A terminal session as the page knows it — `terminal::session::Info`.
export type TermInfo = {
  id: string;
  entry_id: string;
  entry_name: string;
  host: string;
  /// Where it connects: the real address behind an alias.
  address: string;
  port: number;
  user: string;
  opened_at: number;
};

export type TermSession = TermInfo & { state: TermState };

/// A destination the terminal offers — `terminal::Target`.
export type TermTarget = {
  entry_id: string;
  entry_name: string;
  host: string;
  port: number | null;
  user: string | null;
  pattern: string;
  recent: boolean;
};

/// What a health check found — `terminal::health::Status`, from harmless to
/// alarming.
export type HealthStatus =
  | "unbound"
  | "wildcard"
  | "pending"
  | "ok"
  | "reachable"
  | "host_unknown"
  | "error"
  | "unreachable"
  | "rejected"
  | "host_changed";

export type HealthCheck = {
  host: string;
  port: number;
  user: string | null;
  status: HealthStatus;
  latency_ms: number | null;
  detail: string | null;
  fingerprint: string | null;
  checked_at: number | null;
  /// Being checked right now; the status shown is the last one.
  checking: boolean;
  /// Something besides the status, as a key: the login taken from
  /// `~/.ssh/config`, say.
  note: string | null;
};

/// A host `~/.ssh/config` names — `terminal::sshconfig::Named`.
export type ConfigHost = { alias: string; hostname: string | null; user: string | null; port: number | null; proxy_jump: string | null };

export type KeyHealth = { entry_id: string; entry_name: string; status: HealthStatus; checks: HealthCheck[] };

export type HealthReport = { keys: KeyHealth[]; running: boolean; checked_at: number | null };
