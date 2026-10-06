// The layout tokens a component needs as numbers (a column's width for the
// fold, the map's spacing), read once from the style sheet so the CSS stays
// the one source of sizes. A token that is missing is an error.
const cache = new Map<string, number>();
let probe: HTMLDivElement | null = null;

export function tokenPx(name: string): number {
  const hit = cache.get(name);
  if (hit !== undefined) return hit;
  if (!probe) {
    probe = document.createElement("div");
    probe.style.cssText = "position:absolute;visibility:hidden;height:0;pointer-events:none";
    document.body.appendChild(probe);
  }
  probe.style.width = `var(${name})`;
  const v = probe.getBoundingClientRect().width;
  if (!(v > 0)) throw new Error(`layout token ${name} is missing`);
  cache.set(name, v);
  return v;
}
