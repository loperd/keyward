// The vault desk's reading of the catalogue: the common projection every row
// shows (vault-desk-i-a-dense-ledger-spatial-spec.md §5) and the typed
// relations Relationship Exploration walks (vault-desk-final-ux-spec.md §4).
// Everything here is read from what the daemon gave; nothing is guessed.
import type { Key } from "../i18n";
import type { ItemKind, VaultItem } from "../types";

/// The spec's order: Critical issue > Action needed > Warning > Healthy >
/// Unknown. Only the highest is shown in the row.
export type Level = "critical" | "action" | "warning" | "healthy" | "unknown";
export const LEVEL_RANK: Record<Level, number> = { critical: 0, action: 1, warning: 2, healthy: 3, unknown: 4 };
/// A state is never said by colour alone: each level has its own mark.
export const LEVEL_MARK: Record<Level, string> = { critical: "!", action: "▲", warning: "~", healthy: "✓", unknown: "○" };

export type Signal = { level: Level; key: Key; args?: Record<string, string | number> };

const DAY = 86_400_000;

/// Months to a card's expiry (`YYYY-MM`): negative once it has passed.
function monthsLeft(expires: string, now: Date): number {
  const [y, m] = expires.split("-").map(Number);
  return (y - now.getFullYear()) * 12 + (m - (now.getMonth() + 1));
}

/// Every signal an item has, the highest first.
export function signals(item: VaultItem, now = new Date()): Signal[] {
  const out: Signal[] = [];
  if ((item.reused ?? 0) > 0) out.push({ level: "critical", key: "desk.sig.reused", args: { n: item.reused ?? 0 } });
  if (item.expires) {
    const left = monthsLeft(item.expires, now);
    if (left < 0) out.push({ level: "critical", key: "desk.sig.expired" });
    else if (left <= 3) out.push({ level: "action", key: "desk.sig.expiresSoon", args: { n: left } });
  }
  if (item.kind === "login" && item.password_revised) {
    const days = Math.floor((now.getTime() - Date.parse(item.password_revised)) / DAY);
    if (days > 365) out.push({ level: "warning", key: "desk.sig.oldPassword", args: { n: Math.floor(days / 30) } });
  }
  if (item.has_totp) out.push({ level: "healthy", key: "desk.sig.totp" });
  if (item.passkeys > 0) out.push({ level: "healthy", key: "desk.sig.passkey" });
  if (item.reprompt) out.push({ level: "healthy", key: "desk.sig.reprompt" });
  if (out.length === 0) out.push({ level: "unknown", key: item.kind === "login" ? "desk.sig.passwordOnly" : "desk.sig.none" });
  return out.sort((a, b) => LEVEL_RANK[a.level] - LEVEL_RANK[b.level]);
}

export const topSignal = (item: VaultItem, now?: Date): Signal => signals(item, now)[0];

export const KIND_ICON: Record<ItemKind, string> = { login: "login", card: "card", identity: "identity", secure_note: "note", ssh_key: "ssh_key" };
export const KIND_KEY: Record<ItemKind, Key> = {
  login: "desk.kind.login",
  card: "desk.kind.card",
  identity: "desk.kind.identity",
  secure_note: "desk.kind.note",
  ssh_key: "desk.kind.sshKey",
};

/// Where an item lives: its organisation and folder, as a short path.
export function context(item: VaultItem): string | null {
  const parts = [item.org_name, item.folder_name].filter((p): p is string => Boolean(p));
  return parts.length ? parts.join(" / ") : null;
}

/// Whose it is: one's own, or an organisation's.
export const shared = (item: VaultItem) => item.org_id !== null;

/// The host of a URI, `example.com` out of `https://login.example.com/x`.
export function domain(uri: string): string | null {
  try {
    const host = new URL(uri.includes("://") ? uri : `https://${uri}`).hostname.toLowerCase();
    const parts = host.split(".");
    return parts.length > 2 ? parts.slice(-2).join(".") : host;
  } catch {
    return null;
  }
}

/// A relation between the root and another node. A node is an object of the
/// vault or a context it hangs off: a folder, an organisation, a service's
/// domain, a host a key opens.
export type Edge = "belongsTo" | "sharesSecret" | "sameService" | "opens" | "sameFolder" | "sameOrg";
export type Node =
  | { kind: "object"; id: string; item: VaultItem }
  | { kind: "folder" | "org" | "domain" | "host"; id: string; label: string };
export type Relation = { edge: Edge; direction: "incoming" | "outgoing"; node: Node };

/// The root's typed relations, both ways, from what the catalogue knows:
/// its folder and organisation, the items sharing its password, the items of
/// the same service, the hosts an ssh key is bound to (`kw-host`), and the
/// items in the same folder or organisation.
export function relations(root: VaultItem, all: VaultItem[]): Relation[] {
  const live = all.filter((i) => !i.deleted && i.id !== root.id);
  const out: Relation[] = [];
  if (root.folder_id && root.folder_name) out.push({ edge: "belongsTo", direction: "outgoing", node: { kind: "folder", id: root.folder_id, label: root.folder_name } });
  if (root.org_id) out.push({ edge: "belongsTo", direction: "outgoing", node: { kind: "org", id: root.org_id, label: root.org_name ?? root.org_id } });
  const domains = new Set(root.uris.map(domain).filter((d): d is string => Boolean(d)));
  for (const d of domains) out.push({ edge: "sameService", direction: "outgoing", node: { kind: "domain", id: d, label: d } });
  const hosts = (root.tags["kw-host"] ?? "").split(/[\s,]+/).filter(Boolean);
  for (const h of hosts) out.push({ edge: "opens", direction: "outgoing", node: { kind: "host", id: h, label: h } });
  for (const other of live) {
    if (root.reuse_group != null && other.reuse_group === root.reuse_group) out.push({ edge: "sharesSecret", direction: "incoming", node: { kind: "object", id: other.id, item: other } });
    else if (other.uris.some((u) => domains.has(domain(u) ?? ""))) out.push({ edge: "sameService", direction: "incoming", node: { kind: "object", id: other.id, item: other } });
    else if (root.folder_id && other.folder_id === root.folder_id) out.push({ edge: "sameFolder", direction: "incoming", node: { kind: "object", id: other.id, item: other } });
    else if (root.org_id && other.org_id === root.org_id) out.push({ edge: "sameOrg", direction: "incoming", node: { kind: "object", id: other.id, item: other } });
  }
  return out;
}

/// How many relations a row reports: existence and scale, not topology.
export const relationCount = (item: VaultItem, all: VaultItem[]) => relations(item, all).length;

export const EDGE_KEY: Record<Edge, Key> = {
  belongsTo: "desk.edge.belongsTo",
  sharesSecret: "desk.edge.sharesSecret",
  sameService: "desk.edge.sameService",
  opens: "desk.edge.opens",
  sameFolder: "desk.edge.sameFolder",
  sameOrg: "desk.edge.sameOrg",
};

/// "5 minutes ago", for the ledger's time column.
export function ago(iso: string | null | undefined, locale: string, now = Date.now()): string {
  if (!iso) return "—";
  const diff = Math.round((Date.parse(iso) - now) / 1000);
  if (Number.isNaN(diff)) return "—";
  const fmt = new Intl.RelativeTimeFormat(locale, { numeric: "auto", style: "narrow" });
  const abs = Math.abs(diff);
  if (abs < 3600) return fmt.format(Math.round(diff / 60), "minute");
  if (abs < 86400) return fmt.format(Math.round(diff / 3600), "hour");
  if (abs < 86400 * 60) return fmt.format(Math.round(diff / 86400), "day");
  if (abs < 86400 * 730) return fmt.format(Math.round(diff / (86400 * 30)), "month");
  return fmt.format(Math.round(diff / (86400 * 365)), "year");
}
