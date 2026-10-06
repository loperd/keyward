// How long ago, in words a person reads: days, months, years — the coarse
// steps a history line needs. A date that does not parse is an error.
import type { Text } from "../i18n";

const DAY = 86_400_000;

export function ago(iso: string, now: Date): Text {
  const at = Date.parse(iso);
  if (Number.isNaN(at)) throw new Error(`not a date: ${iso}`);
  const days = Math.max(0, Math.floor((now.getTime() - at) / DAY));
  if (days < 1) return { key: "ago.today" };
  if (days < 30) return { key: "ago.days", args: { n: days } };
  const months = Math.floor(days / 30);
  if (months < 12) return { key: "ago.months", args: { n: months } };
  return { key: "ago.years", args: { n: Math.floor(months / 12) } };
}
