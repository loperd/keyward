/// Vault policies: parsing, linting, formatting and completions.
///
/// This is not the whole of HCL but the subset ACL policies are written in:
/// `path "..." { ... }` blocks with attributes, strings, lists and comments.
/// Everything else counts as an error: Vault would not take it anyway.
import { StreamLanguage, type StringStream } from "@codemirror/language";
import type { Completion, CompletionContext, CompletionResult } from "@codemirror/autocomplete";
import { snippetCompletion } from "@codemirror/autocomplete";
import type { Diagnostic } from "@codemirror/lint";
import type { Mount } from "../types";

/* -- The lexer ----------------------------------------------------------- */

export type TokKind = "ident" | "string" | "punct" | "comment" | "number" | "bad";
export type Tok = { kind: TokKind; text: string; from: number; to: number };

export function tokenize(src: string): Tok[] {
  const out: Tok[] = [];
  let i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i];
    if (c === " " || c === "\t" || c === "\r" || c === "\n") {
      i += 1;
      continue;
    }
    const from = i;
    if (c === "#" || (c === "/" && src[i + 1] === "/")) {
      while (i < n && src[i] !== "\n") i += 1;
      out.push({ kind: "comment", text: src.slice(from, i), from, to: i });
      continue;
    }
    if (c === "/" && src[i + 1] === "*") {
      const end = src.indexOf("*/", i + 2);
      i = end === -1 ? n : end + 2;
      out.push({ kind: "comment", text: src.slice(from, i), from, to: i });
      continue;
    }
    if (c === '"') {
      i += 1;
      while (i < n && src[i] !== '"' && src[i] !== "\n") {
        if (src[i] === "\\") i += 1;
        i += 1;
      }
      const closed = src[i] === '"';
      if (closed) i += 1;
      out.push({ kind: closed ? "string" : "bad", text: src.slice(from, i), from, to: i });
      continue;
    }
    if ("{}[]=,".includes(c)) {
      i += 1;
      out.push({ kind: "punct", text: c, from, to: i });
      continue;
    }
    if (/[0-9]/.test(c)) {
      while (i < n && /[0-9a-zA-Z_.]/.test(src[i])) i += 1;
      out.push({ kind: "number", text: src.slice(from, i), from, to: i });
      continue;
    }
    if (/[A-Za-z_]/.test(c)) {
      while (i < n && /[A-Za-z0-9_\-]/.test(src[i])) i += 1;
      out.push({ kind: "ident", text: src.slice(from, i), from, to: i });
      continue;
    }
    i += 1;
    out.push({ kind: "bad", text: c, from, to: i });
  }
  return out;
}

/* -- The parser ---------------------------------------------------------- */

export const CAPABILITIES = ["create", "read", "update", "patch", "delete", "list", "sudo", "deny"] as const;

export const BLOCK_ATTRS = [
  "capabilities",
  "allowed_parameters",
  "denied_parameters",
  "required_parameters",
  "min_wrapping_ttl",
  "max_wrapping_ttl",
  "control_group",
] as const;

export type Attr = { name: string; from: number; to: number; value: Value };
export type Value =
  | { kind: "string"; text: string; from: number; to: number }
  | { kind: "list"; items: { text: string; from: number; to: number }[]; from: number; to: number }
  | { kind: "map"; raw: string; from: number; to: number }
  | { kind: "number"; text: string; from: number; to: number };

export type Block = {
  path: string;
  pathFrom: number;
  pathTo: number;
  from: number;
  to: number;
  attrs: Attr[];
  /// The comments immediately before a block: formatting keeps them.
  leading: string[];
};

export type Problem = { from: number; to: number; message: string; severity: "error" | "warning" | "info" };

export type Parsed = { blocks: Block[]; problems: Problem[] };

function unquote(s: string): string {
  return s.length >= 2 && s.startsWith('"') && s.endsWith('"') ? s.slice(1, -1).replace(/\\"/g, '"') : s;
}

export function parsePolicy(src: string, msg: (key: LintKey, vars?: Record<string, string | number>) => string): Parsed {
  const toks = tokenize(src);
  const blocks: Block[] = [];
  const problems: Problem[] = [];
  let i = 0;
  let pending: string[] = [];

  const at = (k: number) => toks[k];
  const err = (t: Tok | undefined, key: LintKey, vars?: Record<string, string | number>) => {
    const from = t ? t.from : Math.max(0, src.length - 1);
    const to = t ? t.to : src.length;
    problems.push({ from, to, message: msg(key, vars), severity: "error" });
  };

  while (i < toks.length) {
    const t = at(i);
    if (t.kind === "comment") {
      pending.push(t.text);
      i += 1;
      continue;
    }
    if (t.kind === "bad") {
      err(t, t.text.startsWith('"') ? "unterminatedString" : "unexpected", { t: t.text });
      i += 1;
      continue;
    }
    if (t.kind !== "ident" || t.text !== "path") {
      err(t, "expectedPath", { t: t.text });
      // Skip to the next `path`, so as not to pour out an error per token.
      i += 1;
      while (i < toks.length && !(at(i).kind === "ident" && at(i).text === "path")) i += 1;
      continue;
    }
    const pathTok = at(i + 1);
    if (!pathTok || pathTok.kind !== "string") {
      err(pathTok ?? t, "pathNeedsString");
      i += 1;
      continue;
    }
    const open = at(i + 2);
    if (!open || open.text !== "{") {
      err(open ?? pathTok, "expectedBrace");
      i += 2;
      continue;
    }
    const block: Block = {
      path: unquote(pathTok.text),
      pathFrom: pathTok.from,
      pathTo: pathTok.to,
      from: t.from,
      to: open.to,
      attrs: [],
      leading: pending,
    };
    pending = [];
    i += 3;
    let closed = false;
    while (i < toks.length) {
      const a = at(i);
      if (a.kind === "comment") {
        i += 1;
        continue;
      }
      if (a.text === "}" && a.kind === "punct") {
        block.to = a.to;
        closed = true;
        i += 1;
        break;
      }
      if (a.kind !== "ident") {
        err(a, "expectedAttr", { t: a.text });
        i += 1;
        continue;
      }
      const eq = at(i + 1);
      if (!eq || eq.text !== "=") {
        err(eq ?? a, "expectedEquals", { t: a.text });
        i += 1;
        continue;
      }
      const v = at(i + 2);
      if (!v) {
        err(eq, "expectedValue", { t: a.text });
        i += 2;
        break;
      }
      if (v.kind === "string") {
        block.attrs.push({ name: a.text, from: a.from, to: v.to, value: { kind: "string", text: unquote(v.text), from: v.from, to: v.to } });
        i += 3;
      } else if (v.kind === "number") {
        block.attrs.push({ name: a.text, from: a.from, to: v.to, value: { kind: "number", text: v.text, from: v.from, to: v.to } });
        i += 3;
      } else if (v.text === "[") {
        const items: { text: string; from: number; to: number }[] = [];
        let j = i + 3;
        let ok = false;
        while (j < toks.length) {
          const x = at(j);
          if (x.text === "]") {
            ok = true;
            break;
          }
          if (x.kind === "string") items.push({ text: unquote(x.text), from: x.from, to: x.to });
          else if (x.text === ",") {
            /* a separator */
          } else if (x.kind === "comment") {
            /* allowed */
          } else {
            err(x, "listNeedsStrings", { t: x.text });
          }
          j += 1;
        }
        if (!ok) err(v, "unclosedList");
        const to = ok ? at(j).to : v.to;
        block.attrs.push({ name: a.text, from: a.from, to, value: { kind: "list", items, from: v.from, to } });
        i = ok ? j + 1 : j;
      } else if (v.text === "{") {
        // A map of parameters is taken as it is, up to the matching brace.
        let depth = 0;
        let j = i + 2;
        for (; j < toks.length; j += 1) {
          if (at(j).text === "{") depth += 1;
          if (at(j).text === "}") {
            depth -= 1;
            if (depth === 0) break;
          }
        }
        if (j >= toks.length) {
          err(v, "unclosedMap");
          i = toks.length;
        } else {
          block.attrs.push({ name: a.text, from: a.from, to: at(j).to, value: { kind: "map", raw: src.slice(v.from, at(j).to), from: v.from, to: at(j).to } });
          i = j + 1;
        }
      } else {
        err(v, "badValue", { t: v.text });
        i += 3;
      }
    }
    if (!closed) err(undefined, "unclosedBlock", { p: block.path });
    blocks.push(block);
  }
  return { blocks, problems };
}

/* -- Checking the meaning ------------------------------------------------ */

export type LintKey =
  | "unexpected"
  | "unterminatedString"
  | "expectedPath"
  | "pathNeedsString"
  | "expectedBrace"
  | "expectedAttr"
  | "expectedEquals"
  | "expectedValue"
  | "listNeedsStrings"
  | "unclosedList"
  | "unclosedMap"
  | "badValue"
  | "unclosedBlock"
  | "noCapabilities"
  | "unknownCapability"
  | "unknownAttr"
  | "emptyCapabilities"
  | "duplicatePath"
  | "sudo"
  | "denyMixed"
  | "kv2Prefix"
  | "unknownMount"
  | "emptyPolicy";

export function lintPolicy(
  src: string,
  mounts: Mount[],
  msg: (key: LintKey, vars?: Record<string, string | number>) => string,
): { parsed: Parsed; diagnostics: Diagnostic[] } {
  const parsed = parsePolicy(src, msg);
  const out: Diagnostic[] = parsed.problems.map((p) => ({ from: p.from, to: p.to, severity: p.severity, message: p.message }));
  const seen = new Map<string, Block>();
  const caps = new Set<string>(CAPABILITIES);
  const attrs = new Set<string>(BLOCK_ATTRS);

  if (parsed.blocks.length === 0 && parsed.problems.length === 0 && src.trim() !== "") {
    out.push({ from: 0, to: src.length, severity: "error", message: msg("emptyPolicy") });
  }

  for (const b of parsed.blocks) {
    const dup = seen.get(b.path);
    if (dup) out.push({ from: b.pathFrom, to: b.pathTo, severity: "warning", message: msg("duplicatePath", { p: b.path }) });
    seen.set(b.path, b);

    const capAttr = b.attrs.find((a) => a.name === "capabilities");
    if (!capAttr) {
      out.push({ from: b.from, to: b.pathTo, severity: "error", message: msg("noCapabilities", { p: b.path }) });
    } else if (capAttr.value.kind !== "list") {
      out.push({ from: capAttr.from, to: capAttr.to, severity: "error", message: msg("badValue", { t: "capabilities" }) });
    } else {
      if (capAttr.value.items.length === 0) {
        out.push({ from: capAttr.value.from, to: capAttr.value.to, severity: "error", message: msg("emptyCapabilities") });
      }
      let hasDeny = false;
      for (const it of capAttr.value.items) {
        if (!caps.has(it.text)) {
          out.push({ from: it.from, to: it.to, severity: "error", message: msg("unknownCapability", { c: it.text }) });
        }
        if (it.text === "sudo") {
          out.push({ from: it.from, to: it.to, severity: "warning", message: msg("sudo", { p: b.path }) });
        }
        if (it.text === "deny") hasDeny = true;
      }
      if (hasDeny && capAttr.value.items.length > 1) {
        out.push({ from: capAttr.value.from, to: capAttr.value.to, severity: "warning", message: msg("denyMixed") });
      }
    }

    for (const a of b.attrs) {
      if (!attrs.has(a.name)) {
        out.push({ from: a.from, to: a.from + a.name.length, severity: "warning", message: msg("unknownAttr", { a: a.name }) });
      }
    }

    // The path against the engines: kv v2 without data/ or metadata/ is the
    // commonest mistake.
    const first = b.path.split("/")[0];
    const mount = mounts.find((m) => b.path === m.path || b.path.startsWith(m.path + "/"));
    if (mount?.kv2) {
      const rest = b.path.slice(mount.path.length + 1);
      const okPrefix = ["data", "metadata", "delete", "undelete", "destroy", "config", "subkeys"].some(
        (p) => rest === p || rest.startsWith(p + "/") || rest === "*" || rest === "+",
      );
      if (!okPrefix) out.push({ from: b.pathFrom, to: b.pathTo, severity: "warning", message: msg("kv2Prefix", { m: mount.path }) });
    } else if (mounts.length > 0 && !mount && !["sys", "auth", "identity", "cubbyhole"].includes(first) && !first.includes("*") && !first.includes("+")) {
      out.push({ from: b.pathFrom, to: b.pathTo, severity: "info", message: msg("unknownMount", { m: first }) });
    }
  }
  return { parsed, diagnostics: out };
}

/* -- Formatting ---------------------------------------------------------- */

const quote = (s: string) => `"${s.replace(/"/g, '\\"')}"`;

/// The canonical shape: blocks with a blank line between them, attributes
/// indented by two spaces, lists on one line. The comments before a block stay
/// where they are. It works on parsed text alone: there is nothing to format
/// with errors in it.
export function formatPolicy(parsed: Parsed, src: string): string | null {
  if (parsed.problems.some((p) => p.severity === "error")) return null;
  const chunks: string[] = [];
  for (const b of parsed.blocks) {
    const lines: string[] = [];
    for (const c of b.leading) lines.push(c.trim());
    lines.push(`path ${quote(b.path)} {`);
    // capabilities first: they are what the eye looks for first.
    const ordered = [...b.attrs].sort((x, y) => Number(y.name === "capabilities") - Number(x.name === "capabilities"));
    for (const a of ordered) {
      const v = a.value;
      if (v.kind === "string") lines.push(`  ${a.name} = ${quote(v.text)}`);
      else if (v.kind === "number") lines.push(`  ${a.name} = ${v.text}`);
      else if (v.kind === "list") {
        const items = a.name === "capabilities" ? sortCaps(v.items.map((x) => x.text)) : v.items.map((x) => x.text);
        lines.push(`  ${a.name} = [${items.map(quote).join(", ")}]`);
      } else {
        const inner = v.raw
          .split("\n")
          .map((l) => l.trim())
          .filter(Boolean);
        if (inner.length <= 1) lines.push(`  ${a.name} = ${inner.join(" ")}`);
        else lines.push(`  ${a.name} = ${inner[0]}`, ...inner.slice(1, -1).map((l) => `    ${l}`), `  ${inner[inner.length - 1]}`);
      }
    }
    lines.push("}");
    chunks.push(lines.join("\n"));
  }
  // The trailing comments after the last block are not lost.
  const tail = trailingComments(src, parsed);
  if (tail.length > 0) chunks.push(tail.join("\n"));
  return chunks.join("\n\n") + "\n";
}

function sortCaps(items: string[]): string[] {
  const order = [...CAPABILITIES] as string[];
  return [...new Set(items)].sort((a, b) => {
    const ia = order.indexOf(a);
    const ib = order.indexOf(b);
    return (ia === -1 ? 99 : ia) - (ib === -1 ? 99 : ib);
  });
}

function trailingComments(src: string, parsed: Parsed): string[] {
  const last = parsed.blocks[parsed.blocks.length - 1];
  const rest = src.slice(last ? last.to : 0);
  return tokenize(rest)
    .filter((t) => t.kind === "comment")
    .map((t) => t.text.trim());
}

/* -- Highlighting --------------------------------------------------------- */

type HclState = { inList: boolean; afterPath: boolean };

export const hclLanguage = StreamLanguage.define<HclState>({
  name: "vault-policy",
  startState: () => ({ inList: false, afterPath: false }),
  token(stream: StringStream, state: HclState) {
    if (stream.eatSpace()) return null;
    if (stream.match(/^(#|\/\/).*/)) return "comment";
    if (stream.match(/^\/\*/)) {
      while (!stream.eol()) {
        if (stream.match(/^\*\//)) break;
        stream.next();
      }
      return "comment";
    }
    if (stream.match(/^"(?:[^"\\\n]|\\.)*"/)) {
      if (state.inList) return "atom";
      if (state.afterPath) {
        state.afterPath = false;
        return "string";
      }
      return "string";
    }
    if (stream.match(/^"[^"\n]*/)) return "invalid";
    if (stream.match(/^\[/)) {
      state.inList = true;
      return "bracket";
    }
    if (stream.match(/^\]/)) {
      state.inList = false;
      return "bracket";
    }
    if (stream.match(/^[{}]/)) return "brace";
    if (stream.match(/^[=,]/)) return "punctuation";
    if (stream.match(/^[0-9][0-9a-zA-Z_.]*/)) return "number";
    if (stream.match(/^[A-Za-z_][A-Za-z0-9_\-]*/)) {
      const w = stream.current();
      if (w === "path") {
        state.afterPath = true;
        return "keyword";
      }
      if ((BLOCK_ATTRS as readonly string[]).includes(w)) return "propertyName";
      return "variableName";
    }
    stream.next();
    return "invalid";
  },
  languageData: { commentTokens: { line: "#" } },
});

/* -- Completion ----------------------------------------------------------- */

const SYSTEM_PATHS = [
  "sys/policies/acl/",
  "sys/policies/acl",
  "sys/mounts",
  "sys/mounts/",
  "sys/internal/ui/mounts",
  "sys/internal/ui/mounts/",
  "sys/leases/lookup",
  "sys/leases/renew",
  "sys/leases/revoke",
  "sys/capabilities-self",
  "sys/health",
  "sys/wrapping/unwrap",
  "sys/wrapping/lookup",
  "auth/token/lookup-self",
  "auth/token/renew-self",
  "auth/token/revoke-self",
  "auth/token/create",
  "auth/token/lookup",
  "auth/token/lookup-accessor",
  "auth/token/revoke-accessor",
  "auth/approle/login",
  "auth/approle/role/",
  "auth/kubernetes/login",
  "auth/kubernetes/role/",
  "identity/entity/",
  "identity/group/",
  "cubbyhole/",
];

export function pathSuggestions(mounts: Mount[]): string[] {
  const out = new Set<string>();
  for (const m of mounts) {
    if (m.kind === "kv" || m.kind === "generic") {
      if (m.kv2) {
        out.add(`${m.path}/data/`);
        out.add(`${m.path}/metadata/`);
        out.add(`${m.path}/delete/`);
        out.add(`${m.path}/destroy/`);
      } else out.add(`${m.path}/`);
    } else if (m.kind === "pki") {
      out.add(`${m.path}/issue/`);
      out.add(`${m.path}/sign/`);
      out.add(`${m.path}/cert/`);
    } else if (m.kind === "transit") {
      out.add(`${m.path}/encrypt/`);
      out.add(`${m.path}/decrypt/`);
      out.add(`${m.path}/keys/`);
    } else if (m.kind === "kubernetes") {
      out.add(`${m.path}/creds/`);
    } else if (m.kind !== "cubbyhole" && !m.path.startsWith("auth/")) {
      out.add(`${m.path}/`);
    }
    if (m.path.startsWith("auth/")) {
      out.add(`${m.path}/login`);
      out.add(`${m.path}/role/`);
    }
  }
  for (const p of SYSTEM_PATHS) out.add(p);
  return [...out];
}

export function makeCompletion(getMounts: () => Mount[]) {
  return (ctx: CompletionContext): CompletionResult | null => {
    const line = ctx.state.doc.lineAt(ctx.pos);
    const before = line.text.slice(0, ctx.pos - line.from);
    const wholeBefore = ctx.state.doc.sliceString(0, ctx.pos);

    // Inside a string after `path` come paths.
    const pathStr = /path\s+"([^"]*)$/.exec(before);
    if (pathStr) {
      const from = ctx.pos - pathStr[1].length;
      const options: Completion[] = pathSuggestions(getMounts()).map((p) => ({
        label: p,
        type: p.startsWith("sys/") || p.startsWith("auth/") ? "namespace" : "variable",
        apply: p.endsWith("/") ? p : p,
        boost: p.startsWith("sys/") ? -1 : 0,
      }));
      return { from, options, validFor: /^[A-Za-z0-9_\-./*+]*$/ };
    }

    // Inside a capabilities list come the capabilities themselves.
    const inCaps = /capabilities\s*=\s*\[[^\]]*$/.test(before);
    if (inCaps) {
      const strStart = /"([A-Za-z]*)$/.exec(before);
      const from = strStart ? ctx.pos - strStart[1].length : ctx.pos;
      const already = new Set([...before.matchAll(/"([a-z]+)"/g)].map((m) => m[1]));
      const options: Completion[] = CAPABILITIES.filter((c) => !already.has(c)).map((c) => ({
        label: c,
        type: c === "sudo" || c === "deny" ? "keyword" : "constant",
        apply: strStart ? c : `"${c}"`,
        detail: c === "sudo" ? "root-only paths" : undefined,
      }));
      return { from, options, validFor: /^[a-z]*$/ };
    }

    // Inside a block come attributes; outside it, a new block.
    const opens = (wholeBefore.match(/{/g) ?? []).length;
    const closes = (wholeBefore.match(/}/g) ?? []).length;
    const word = ctx.matchBefore(/[A-Za-z_]*/);
    if (!word || (word.from === word.to && !ctx.explicit)) return null;
    if (opens > closes) {
      const options: Completion[] = [
        snippetCompletion('capabilities = ["${read}"]', { label: "capabilities", type: "property", boost: 2 }),
        snippetCompletion('allowed_parameters = {\n  "${key}" = [${}]\n}', { label: "allowed_parameters", type: "property" }),
        snippetCompletion('denied_parameters = {\n  "${key}" = [${}]\n}', { label: "denied_parameters", type: "property" }),
        snippetCompletion('required_parameters = ["${key}"]', { label: "required_parameters", type: "property" }),
        snippetCompletion('min_wrapping_ttl = "${1m}"', { label: "min_wrapping_ttl", type: "property" }),
        snippetCompletion('max_wrapping_ttl = "${90s}"', { label: "max_wrapping_ttl", type: "property" }),
      ];
      return { from: word.from, options, validFor: /^[a-z_]*$/ };
    }
    return {
      from: word.from,
      options: [snippetCompletion('path "${secret/data/}" {\n  capabilities = ["${read}"]\n}', { label: "path", type: "keyword", detail: "block" })],
      validFor: /^[a-z]*$/,
    };
  };
}

/* -- Ready-made blocks to insert ------------------------------------------ */

export type Template = { id: string; label: string; hint: string; body: string };

const block = (path: string, caps: string[]) => `path "${path}" {\n  capabilities = [${caps.map(quote).join(", ")}]\n}\n`;

export function templates(mounts: Mount[], label: (key: string, vars?: Record<string, string | number>) => string): Template[] {
  const out: Template[] = [];
  for (const m of mounts) {
    if (m.kind === "kv" || m.kind === "generic") {
      const data = m.kv2 ? `${m.path}/data/*` : `${m.path}/*`;
      const meta = m.kv2 ? `${m.path}/metadata/*` : null;
      const withMeta = (body: string) => (meta ? body + "\n" + block(meta, ["read", "list"]) : body);
      out.push(
        { id: `kv:${m.path}:read`, label: label("tpl.kvRead", { m: m.path }), hint: data, body: withMeta(block(data, ["read", "list"])) },
        { id: `kv:${m.path}:write`, label: label("tpl.kvWrite", { m: m.path }), hint: data, body: withMeta(block(data, ["create", "read", "update", "list"])) },
        { id: `kv:${m.path}:full`, label: label("tpl.kvFull", { m: m.path }), hint: data, body: withMeta(block(data, ["create", "read", "update", "delete", "list"])) },
      );
    } else if (m.kind === "pki") {
      out.push({ id: `pki:${m.path}`, label: label("tpl.pki", { m: m.path }), hint: `${m.path}/issue/*`, body: block(`${m.path}/issue/*`, ["create", "update"]) + "\n" + block(`${m.path}/sign/*`, ["create", "update"]) });
    } else if (m.kind === "transit") {
      out.push({ id: `transit:${m.path}`, label: label("tpl.transit", { m: m.path }), hint: `${m.path}/encrypt/*`, body: block(`${m.path}/encrypt/*`, ["update"]) + "\n" + block(`${m.path}/decrypt/*`, ["update"]) });
    }
  }
  out.push(
    {
      id: "tpl:token-self",
      label: label("tpl.tokenSelf"),
      hint: "auth/token/*-self",
      body: block("auth/token/lookup-self", ["read"]) + "\n" + block("auth/token/renew-self", ["update"]) + "\n" + block("auth/token/revoke-self", ["update"]),
    },
    { id: "tpl:policies", label: label("tpl.policies"), hint: "sys/policies/acl", body: block("sys/policies/acl/*", ["create", "read", "update", "list"]) + "\n" + block("sys/policies/acl", ["list"]) },
    { id: "tpl:mounts", label: label("tpl.mounts"), hint: "sys/mounts", body: block("sys/mounts", ["read"]) + "\n" + block("sys/internal/ui/mounts/*", ["read"]) },
    { id: "tpl:leases", label: label("tpl.leases"), hint: "sys/leases", body: block("sys/leases/renew", ["update"]) + "\n" + block("sys/leases/revoke", ["update"]) },
    { id: "tpl:login", label: label("tpl.login"), hint: "auth/*/login", body: block("auth/approle/login", ["create", "update"]) + "\n" + block("auth/kubernetes/login", ["create", "update"]) },
    { id: "tpl:deny", label: label("tpl.deny"), hint: "deny", body: block("secret/data/prod/*", ["deny"]) },
  );
  return out;
}
