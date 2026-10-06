/// <reference types="vite/client" />
// The stand's declared plugins: each one's record, written by the plugin's own
// tests (`KEYWARD_STAND_OUT=gui/stand cargo test`), is served over the real
// sealed link. The screens are the plugin's — built by its Rust on made-up
// data — and the window draws them as it draws any plugin's; nothing here
// knows which plugin it serves.
import { standLink } from "./standLink";

type Act = { op: string; payload: unknown; reply: unknown };
type Record_ = { manifest: Record<string, unknown> & { id: string }; views: Record<string, unknown>; acts: Act[] };

const RECORDS = Object.values(import.meta.glob<Record_>("../stand/*.json", { eager: true, import: "default" }));

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

type Ops = { open: string; read: string; write: string; resize: string; close: string };

/// The terminals a record's screens declare: the stand plays each with an
/// echo shell under the names the screen gives its operations.
function terminals(v: unknown, out: Ops[] = []): Ops[] {
  if (Array.isArray(v)) v.forEach((x) => terminals(x, out));
  else if (v && typeof v === "object") {
    const o = v as Record<string, unknown>;
    if (o.type === "terminal") out.push({ open: (o.open as { op: string }).op, read: String(o.read), write: String(o.write), resize: String(o.resize), close: String(o.close) });
    Object.values(o).forEach((x) => terminals(x, out));
  }
  return out;
}

const enc = new TextEncoder();
const b64 = (text: string) => btoa(String.fromCharCode(...enc.encode(text)));
type Echo = { out: string; line: string; closed: boolean; wake: (() => void)[] };
const echoes = new Map<string, Echo>();

async function terminal(ops: Ops[], op: string, p: Record<string, unknown>): Promise<unknown> {
  const t = ops.find((o) => [o.open, o.read, o.write, o.resize, o.close].includes(op));
  if (!t) return undefined;
  const id = String(p.stream ?? "");
  const e = echoes.get(id);
  const say = (x: Echo, text: string) => {
    x.out += text;
    x.wake.splice(0).forEach((w) => w());
  };
  if (op === t.open) {
    const stream = `e${echoes.size + 1}`;
    const fresh: Echo = { out: "", line: "", closed: false, wake: [] };
    echoes.set(stream, fresh);
    say(fresh, "\x1b[2mstand · echo shell\x1b[0m\r\n$ ");
    return { data: { stream } };
  }
  if (!e) return { error: "dv.standUnplayed" };
  if (op === t.write) {
    const text = new TextDecoder().decode(Uint8Array.from(atob(String(p.data)), (c) => c.charCodeAt(0)));
    for (const ch of text) {
      if (ch === "\r") {
        say(e, `\r\n${e.line}\r\n$ `);
        e.line = "";
      } else if (ch === "\x7f") {
        if (e.line) say(e, "\b \b");
        e.line = e.line.slice(0, -1);
      } else {
        e.line += ch;
        say(e, ch);
      }
    }
    return { data: null };
  }
  if (op === t.read) {
    const cursor = Number(p.cursor ?? 0);
    if (cursor >= e.out.length && !e.closed) await new Promise<void>((done) => { e.wake.push(done); setTimeout(done, Math.min(Number(p.wait_ms ?? 0), 15000)); });
    return { data: { data: b64(e.out.slice(cursor)), cursor: e.out.length, dropped: false, state: e.closed ? "closed" : "open" } };
  }
  if (op === t.close) {
    e.closed = true;
    say(e, "");
  }
  return { data: null };
}

async function answer(r: Record_, req: Record<string, unknown>): Promise<unknown> {
  if (req.kind === "act") {
    const played = await terminal(terminals(r), String(req.op), (req.payload ?? {}) as Record<string, unknown>);
    if (played !== undefined) return played;
  }
  switch (req.kind) {
    case "view": {
      const page = r.views[String(req.route)];
      return page ?? { error: "dv.standUnplayed" };
    }
    case "act": {
      const key = canonical(req.payload ?? null);
      const found = r.acts.find((a) => a.op === req.op && canonical(a.payload ?? null) === key);
      return found ? found.reply : { toast: { key: "dv.standUnplayed" } };
    }
    default:
      return { error: "dv.standUnplayed" };
  }
}

export const STAND_DECLARED_MANIFESTS = RECORDS.map((r) => r.manifest);

export const STAND_DECLARED_OPS: Record<string, Record<string, (p: Record<string, unknown>) => unknown>> = Object.fromEntries(
  RECORDS.map((r) => {
    const link = standLink("err.linkGone", () => null, (_, __, req) => answer(r, req));
    return [r.manifest.id, { ui_link: link.link, ui: link.call }];
  }),
);
