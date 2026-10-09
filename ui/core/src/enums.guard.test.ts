// Every state is an enum: no state, kind, step, status or level is compared
// with, switched on, or set to a bare string anywhere in the window's code
// (`s.state !== "unlocked"` is refused; `s.state !== SessionState.Unlocked`
// is the way). A typo in a string compiles; a typo in a member does not.
//
// The code is read with TypeScript's own parser, so only real expressions are
// looked at — a JSX attribute (`type="button"`), a CSS class, a dictionary key
// or a word in a comment is never one. Words from outside (the daemon's JSON,
// the server's, a plugin's declaration, the typed line, the browser's
// storage) are turned into members in a parse function marked with a
// `// boundary:` comment; what such a declaration holds is not looked at.
// Tests are not looked at either: they speak the wire's words on purpose.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "../../..");
const SCOPES = ["ui/core/src", "gui/app", "web/src", "ui/stand/src"];

/// The properties (and plain names) that hold a state.
const STATE_NAMES = new Set([
  "state",
  "step",
  "kind",
  "status",
  "level",
  "busy",
  "method",
  "group",
  "type",
  "role",
  "phase",
  "mode",
  "op",
  "tile",
  "cut",
  "k",
  "field",
  "provider",
  "hue",
  "shape",
  "zone",
  "move",
  "permission",
]);

const BOUNDARY = /\bboundary:/;

function sources(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) {
      if (name !== "node_modules") out.push(...sources(p));
    } else if (/\.tsx?$/.test(name) && !/\.(test|bench)\.tsx?$/.test(name) && !name.endsWith(".d.ts")) out.push(p);
  }
  return out;
}

/// A string that could be a state's word: one word, no markup, no spaces.
const isString = (n: ts.Node): n is ts.StringLiteral | ts.NoSubstitutionTemplateLiteral => (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) && /^[A-Za-z0-9_.-]+$/.test(n.text);

/// Whether an object literal is the arguments of a dictionary word
/// (`fail("err.x", { kind })`, `t("level.of", { level })`): its values are
/// words said to a person, not states.
function wordArgs(o: ts.Node): boolean {
  const call = o.parent;
  if (!call || !ts.isCallExpression(call) || call.arguments[0] === o) return false;
  const first = call.arguments[0];
  return !!first && ts.isStringLiteral(first) && /^[a-z][A-Za-z0-9]*(\.[A-Za-z0-9]+)+$/.test(first.text);
}

/// The state name an expression reads, if it reads one: `x.state`,
/// `x?.kind`, or a plain `kind`.
function stateName(e: ts.Expression): string | null {
  while (ts.isParenthesizedExpression(e) || ts.isNonNullExpression(e)) e = e.expression;
  if (ts.isPropertyAccessExpression(e)) return STATE_NAMES.has(e.name.text) ? e.name.text : null;
  // A plain name of one letter is a loop's or a key's (`k === "k"`), never a
  // state's; `.k` (a token's key) is.
  if (ts.isIdentifier(e)) return e.text.length > 1 && STATE_NAMES.has(e.text) ? e.text : null;
  return null;
}

/// Whether a node lies inside a declaration marked `// boundary:`.
function inBoundary(n: ts.Node, text: string): boolean {
  for (let p: ts.Node | undefined = n; p && !ts.isSourceFile(p); p = p.parent) {
    const comments = ts.getLeadingCommentRanges(text, p.pos) ?? [];
    if (comments.some((c) => BOUNDARY.test(text.slice(c.pos, c.end)))) return true;
  }
  return false;
}

const EQUALITY = new Set([ts.SyntaxKind.EqualsEqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsEqualsToken, ts.SyntaxKind.EqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsToken]);

/// Every bare state string in a file, as `path:line  what`.
export function bareStates(file: string, text: string): string[] {
  const sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, file.endsWith("x") ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
  const found: string[] = [];
  const report = (n: ts.Node, what: string) => {
    if (inBoundary(n, text)) return;
    const line = sf.getLineAndCharacterOfPosition(n.getStart(sf)).line + 1;
    found.push(`${file}:${line}  ${what}`);
  };
  const visit = (n: ts.Node) => {
    // x.state === "locked", "locked" !== x.state, x.state = "locked"
    if (ts.isBinaryExpression(n)) {
      const op = n.operatorToken.kind;
      if (EQUALITY.has(op)) {
        const [lit, other] = isString(n.right) ? [n.right, n.left] : isString(n.left) ? [n.left, n.right] : [null, null];
        const name = other && stateName(other);
        if (lit && name) report(n, `${name} compared with "${lit.text}"`);
      } else if (op === ts.SyntaxKind.EqualsToken && isString(n.right)) {
        const name = stateName(n.left);
        if (name) report(n, `${name} set to "${n.right.text}"`);
      }
    }
    // ["folder", "collection"].includes(n.kind)
    if (ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) && n.expression.name.text === "includes" && n.arguments[0]) {
      const list = n.expression.expression;
      const name = stateName(n.arguments[0]);
      if (name && ts.isArrayLiteralExpression(list) && list.elements.some(isString)) report(n, `${name} looked up in a list of strings`);
    }
    // switch (x.kind) { case "login": … }
    if (ts.isCaseClause(n) && isString(n.expression)) {
      const name = stateName(n.parent.parent.expression);
      if (name) report(n, `case "${n.expression.text}" on ${name}`);
    }
    // { state: "locked" }
    if (ts.isPropertyAssignment(n) && (ts.isIdentifier(n.name) || ts.isStringLiteral(n.name)) && STATE_NAMES.has(n.name.text) && !wordArgs(n.parent)) {
      let v: ts.Expression = n.initializer;
      while (ts.isParenthesizedExpression(v) || ts.isAsExpression(v) || ts.isSatisfiesExpression(v)) v = v.expression;
      if (isString(v)) report(n, `${n.name.text}: "${v.text}"`);
      // { level: cond ? "critical" : "warning" }
      if (ts.isConditionalExpression(v) && (isString(v.whenTrue) || isString(v.whenFalse))) report(n, `${n.name.text}: a conditional of strings`);
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return found;
}

describe("every state is an enum", () => {
  it("the guard itself sees what it is meant to see", () => {
    const sample = [
      'if (s.state !== "unlocked") go();',
      'switch (v.kind) { case "login": break; }',
      'const x = { level: "critical" };',
      'n.step = "done";',
      'const y = { level: ok ? "healthy" : "warning" };',
      "// boundary: the daemon's words",
      'function parse(r: string) { return r === "x" ? 1 : r.kind === "y" ? 2 : 3; }',
      'const z = <button type="button" className="on" />;',
      'if (typeof v === "string" && s.state === SessionState.Locked) go();',
      'const w = t("level.critical");',
      'fail("err.itemKindUnknown", { kind: "draft" });',
      'const icons = { state: "<circle r=\\"5\\"/>" };',
      'if (k === "k") open();',
      'if (t.k === "state") open();',
      'if (["folder", "org"].includes(n.kind)) open();',
    ].join("\n");
    expect(bareStates("sample.tsx", sample).map((f) => f.split("  ")[1])).toEqual([
      'state compared with "unlocked"',
      'case "login" on kind',
      'level: "critical"',
      'step set to "done"',
      "level: a conditional of strings",
      'k compared with "state"',
      "kind looked up in a list of strings",
    ]);
  });

  it("finds no bare state string in the window's code", () => {
    const found: string[] = [];
    for (const scope of SCOPES) for (const file of sources(join(ROOT, scope))) found.push(...bareStates(relative(ROOT, file), readFileSync(file, "utf8")));
    expect(found).toEqual([]);
  });
});
