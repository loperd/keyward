// An item's security signals, read from what the backend gave; nothing is
// guessed. Only the most serious is shown in a row.
import { type Item, Level, ItemKind } from "./types";

export const LEVEL_RANK: Record<Level, number> = { [Level.Critical]: 0, [Level.Action]: 1, [Level.Warning]: 2, [Level.Healthy]: 3, [Level.Unknown]: 4 };
/// A state is never said by colour alone.
export const LEVEL_MARK: Record<Level, string> = { [Level.Critical]: "!", [Level.Action]: "▲", [Level.Warning]: "~", [Level.Healthy]: "✓", [Level.Unknown]: "○" };

export type SignalKey =
  | "sig.reused"
  | "sig.duplicate"
  | "sig.expired"
  | "sig.expiresSoon"
  | "sig.oldPassword"
  | "sig.totp"
  | "sig.passkey"
  | "sig.reprompt"
  | "sig.passwordOnly"
  | "sig.none";
export type Signal = { level: Level; key: SignalKey; args?: Record<string, number> };

const DAY = 86_400_000;

/// Months to a card's expiry (`YYYY-MM`): negative once it has passed.
export function monthsLeft(expires: string, now: Date): number {
  const m = /^(\d{4})-(\d{2})$/.exec(expires);
  if (!m) throw new Error(`card expiry is not YYYY-MM: ${expires}`);
  return (Number(m[1]) - now.getFullYear()) * 12 + (Number(m[2]) - (now.getMonth() + 1));
}

/// Every signal an item has, the most serious first.
export function signals(item: Item, now = new Date()): Signal[] {
  const out: Signal[] = [];
  if (item.reused > 0) out.push({ level: Level.Critical, key: "sig.reused", args: { n: item.reused } });
  if (item.expires) {
    const left = monthsLeft(item.expires, now);
    if (left < 0) out.push({ level: Level.Critical, key: "sig.expired" });
    else if (left <= 3) out.push({ level: Level.Action, key: "sig.expiresSoon", args: { n: left } });
  }
  if (item.kind === ItemKind.Login && item.passwordRevised) {
    const days = Math.floor((now.getTime() - Date.parse(item.passwordRevised)) / DAY);
    if (days > 365) out.push({ level: Level.Warning, key: "sig.oldPassword", args: { n: Math.floor(days / 30) } });
  }
  if (item.hasTotp) out.push({ level: Level.Healthy, key: "sig.totp" });
  if (item.passkeys > 0) out.push({ level: Level.Healthy, key: "sig.passkey" });
  // Healthy because it is enforced: the window fetches no value of such an
  // item without a fresh master-password check (ui/reprompt.ts), and a
  // backend without that check enforces it itself.
  if (item.reprompt) out.push({ level: Level.Healthy, key: "sig.reprompt" });
  if (out.length === 0) out.push({ level: Level.Unknown, key: item.kind === ItemKind.Login ? "sig.passwordOnly" : "sig.none" });
  return out.sort((a, b) => LEVEL_RANK[a.level] - LEVEL_RANK[b.level]);
}

export const topSignal = (item: Item, now?: Date): Signal => signals(item, now)[0]!;

/// The most serious of several levels; `unknown` when there are none.
export function worst(levels: Iterable<Level>): Level {
  let w: Level = Level.Unknown;
  let any = false;
  for (const l of levels) {
    if (!any || LEVEL_RANK[l] < LEVEL_RANK[w]) w = l;
    any = true;
  }
  return w;
}
