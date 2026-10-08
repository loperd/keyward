// The stand's records of real plugins: each one's places, screens and
// replies, written by the plugin's own Rust test on made-up data
// (`KEYWARD_STAND_OUT=gui/stand cargo test`), served as the plugin would
// serve them. The screens are the plugin's — built by its Rust, drawn by the
// window's kit — and nothing here knows which plugin it serves. An action
// the record did not play is refused, by name.
import type { Words } from "./i18n";
import { contributionOf, type DeclaredPlaces } from "./plugin/declared";
import type { Contribution } from "./path/directory";
import { ScreenNodeType, StreamState } from "./plugin/screen";

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

/// A terminal's operations as a record's screens declare them.
type TermOps = { open: string; read: string; write: string; resize: string; close: string; trust?: string };

/// The terminals a value declares, anywhere in it.
function terminals(v: unknown, out: TermOps[] = []): TermOps[] {
  if (Array.isArray(v)) for (const x of v) terminals(x, out);
  else if (v && typeof v === "object") {
    const o = v as Record<string, unknown>;
    if (o.type === ScreenNodeType.Terminal) out.push({ open: (o.open as { op: string }).op, read: String(o.read), write: String(o.write), resize: String(o.resize), close: String(o.close), ...(typeof o.trust === "string" ? { trust: o.trust } : {}) });
    for (const x of Object.values(o)) terminals(x, out);
  }
  return out;
}

/// An echo shell: what is typed comes back, a line ends with a prompt.
type Echo = { out: string; wake: (() => void)[]; closed: boolean };
const enc = new TextEncoder();
const b64 = (s: string) => btoa(String.fromCharCode(...enc.encode(s)));
const unb64 = (s: string) => new TextDecoder().decode(Uint8Array.from(atob(s), (c) => c.charCodeAt(0)));

export class RecordedPlugins {
  private readonly byId = new Map<string, PluginRecord>();
  private readonly shells = new Map<string, Echo>();

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

  async act(plugin: string, op: string, payload: unknown): Promise<unknown> {
    // A terminal the record declares is played with an echo shell.
    const t = terminals(this.record(plugin)).find((x) => [x.open, x.read, x.write, x.resize, x.close, x.trust].includes(op));
    if (t) return this.echo(t, op, (payload ?? {}) as Record<string, unknown>);
    const want = canonical(payload ?? null);
    const hit = this.record(plugin).acts.find((a) => a.op === op && canonical(a.payload ?? null) === want);
    if (!hit) throw new Error(`the stand does not play "${op}" of "${plugin}"`);
    return hit.reply;
  }

  private async echo(t: TermOps, op: string, p: Record<string, unknown>): Promise<unknown> {
    const say = (e: Echo, s: string) => {
      e.out += s;
      for (const w of e.wake.splice(0)) w();
    };
    if (op === t.open) {
      const stream = typeof p.session === "string" ? p.session : `stand-${this.shells.size + 1}`;
      let e = this.shells.get(stream);
      if (!e) {
        e = { out: "", wake: [], closed: false };
        this.shells.set(stream, e);
        say(e, "\x1b[2mstand · echo shell\x1b[0m\r\n$ ");
      }
      return { data: { stream } };
    }
    const e = this.shells.get(String(p.stream));
    if (!e) throw new Error("the stand has no such shell");
    if (op === t.read) {
      // The cursor is the stand's own, as a plugin's is: where it read to.
      const at = typeof p.cursor === "number" ? p.cursor : 0;
      if (e.out.length <= at && !e.closed) await new Promise<void>((r) => e.wake.push(r));
      return { data: { data: b64(e.out.slice(at)), cursor: e.out.length, state: e.closed ? StreamState.Closed : StreamState.Open } };
    }
    if (op === t.write) say(e, unb64(String(p.data)).replace(/\r/g, "\r\n$ "));
    if (op === t.close) {
      e.closed = true;
      say(e, "");
      this.shells.delete(String(p.stream));
    }
    return { data: null };
  }

  private record(plugin: string): PluginRecord {
    const r = this.byId.get(plugin);
    if (!r) throw new Error(`the stand has no record of the plugin "${plugin}"`);
    return r;
  }
}
