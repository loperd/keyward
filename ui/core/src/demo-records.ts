// The stand's records of real plugins: each one's places, screens and
// replies, written by the plugin's own Rust test on made-up data
// (`KEYWARD_STAND_OUT=gui/stand cargo test`), served as the plugin would
// serve them. The screens are the plugin's — built by its Rust, drawn by the
// window's kit — and nothing here knows which plugin it serves. An action
// the record did not play is refused, by name.
import type { Words } from "./i18n";
import { contributionOf, type DeclaredPlaces } from "./plugin/declared";
import type { Contribution } from "./path/directory";

/// A record as the plugin's test writes it.
export type PluginRecord = {
  manifest: { id: string };
  places?: unknown;
  views: Record<string, unknown>;
  acts: { op: string; payload: unknown; reply: unknown }[];
};

/// One spelling for a value, whatever order its keys came in.
function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (v && typeof v === "object") {
    const o = v as Record<string, unknown>;
    return `{${Object.keys(o)
      .filter((k) => o[k] !== undefined)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonical(o[k])}`)
      .join(",")}}`;
  }
  return JSON.stringify(v ?? null);
}

export class RecordedPlugins {
  private readonly byId = new Map<string, PluginRecord>();

  constructor(
    records: PluginRecord[],
    private readonly words: (plugin: string) => Words | undefined,
    private readonly icons: ReadonlySet<string>,
  ) {
    for (const r of records) {
      if (this.byId.has(r.manifest.id)) throw new Error(`two records of the plugin "${r.manifest.id}"`);
      this.byId.set(r.manifest.id, r);
    }
  }

  has(plugin: string): boolean {
    return this.byId.has(plugin);
  }

  /// The places of every record that declares them.
  contributions(taken: ReadonlySet<string>): Contribution[] {
    const out: Contribution[] = [];
    for (const [id, r] of this.byId) {
      if (!r.places) continue;
      const words = this.words(id);
      out.push(contributionOf(id, r.places as DeclaredPlaces, { ...(words ? { words } : {}), icons: this.icons, taken }));
    }
    return out;
  }

  view(plugin: string, route: string): unknown {
    const page = this.record(plugin).views[route];
    if (page === undefined) throw new Error(`the stand's record of "${plugin}" has no screen "${route}"`);
    return page;
  }

  act(plugin: string, op: string, payload: unknown): unknown {
    const want = canonical(payload ?? null);
    const hit = this.record(plugin).acts.find((a) => a.op === op && canonical(a.payload ?? null) === want);
    if (!hit) throw new Error(`the stand does not play "${op}" of "${plugin}"`);
    return hit.reply;
  }

  private record(plugin: string): PluginRecord {
    const r = this.byId.get(plugin);
    if (!r) throw new Error(`the stand has no record of the plugin "${plugin}"`);
    return r;
  }
}
