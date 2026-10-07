// A plugin's declared screens (keyward-ui's `view`, in Rust), as the core
// reads them: a page of nodes — sections, lists and cards, tables with
// facets, tabs, forms, the checked editor, the terminal, the danger zone —
// and the reply an action leaves (go to a route, a drawer, a dialogue, a
// toast). The answer rides the wire as JSON; it is read once, here, into the
// core's words and members, and whatever does not hold together is refused
// by the plugin's name rather than drawn half. A plugin ships no code for
// any of it: the core draws these with its own kit (ui/screen/*).
import { type Args, type Text, type Words, isKey } from "../i18n";

import { isEnumValue } from "../model/enum";
import { type DeclaredText, wordReader } from "./words";

/// The colour a state is said in.
export enum Tone {
  Plain = "plain",
  Ok = "ok",
  Warn = "warn",
  Bad = "bad",
  Accent = "accent",
}

export enum ScreenNodeType {
  Section = "section",
  List = "list",
  Cards = "cards",
  Table = "table",
  Tabs = "tabs",
  Select = "select",
  Form = "form",
  Pre = "pre",
  Editor = "editor",
  Terminal = "terminal",
  Danger = "danger",
  Chips = "chips",
  Actions = "actions",
  Alert = "alert",
  Empty = "empty",
  Busy = "busy",
}

export enum CellType {
  Text = "text",
  Chip = "chip",
  Ago = "ago",
  Empty = "empty",
}

export enum FieldKind {
  Text = "text",
  /// Never echoed into the form, read once when it is sent.
  Secret = "secret",
  Area = "area",
  Number = "number",
  Select = "select",
  /// On or off: sent as "true" or "false".
  Toggle = "toggle",
}

/// The two lanes of a plugin's sealed link: a long poll (a terminal's
/// output) rides its own, so that it holds no keystroke back.
export enum PluginLane {
  Input = "input",
  Output = "output",
}

/// Where a terminal's stream stands.
export enum StreamState {
  Connecting = "connecting",
  Open = "open",
  Closed = "closed",
}

/// What pressing something does: one of the plugin's operations. `confirm`:
/// the person types this word first; `twice`: a first press arms it.
export type ScreenAction = { op: string; payload: unknown; confirm?: string; twice?: true };
export type ScreenButton = { label?: Text; icon?: string; title: Text; tone: Tone; primary: boolean; disabled: boolean; busy: boolean; action: ScreenAction };
export type ScreenChip = { label: Text; tone: Tone; icon?: string; title?: Text; dot: boolean };
export type ScreenRow = {
  key: string;
  icon: string;
  tone: Tone;
  busy: boolean;
  title: Text;
  mono: boolean;
  subtitle?: Text;
  chips: ScreenChip[];
  note?: Text;
  code?: string;
  /// Seconds since the epoch.
  at?: number;
  actions: ScreenButton[];
  open?: ScreenAction;
};
export type ScreenColumn = { id: string; title: Text; sortable: boolean; mono: boolean };
export type ScreenFacet = { id: string; title: Text; icon: string };
export type ScreenCell = { type: CellType.Text; text: Text } | { type: CellType.Chip; chip: ScreenChip } | { type: CellType.Ago; at: number } | { type: CellType.Empty };
export type ScreenTableRow = {
  key: string;
  cells: Record<string, ScreenCell>;
  facets: Record<string, string>;
  sort: Record<string, string | number>;
  open?: ScreenAction;
  actions: ScreenButton[];
};
export type ScreenFieldSpec =
  | { kind: FieldKind.Text }
  | { kind: FieldKind.Secret }
  | { kind: FieldKind.Area }
  | { kind: FieldKind.Number; min: number; max: number }
  | { kind: FieldKind.Select; options: [string, Text][] }
  | { kind: FieldKind.Toggle };
export type ScreenField = { id: string; label: Text; spec: ScreenFieldSpec; hint?: Text; value?: string };
export type ScreenTab = { id: string; title: Text; icon?: string; load?: ScreenAction; refreshMs?: number; body: ScreenNode[] };
export type TerminalOps = { open: ScreenAction; read: string; write: string; resize: string; close: string };

export type ScreenNode =
  | { type: ScreenNodeType.Section; title: Text; icon: string; tone: Tone; count?: number; folded: boolean; hint?: Text; body: ScreenNode[] }
  | { type: ScreenNodeType.List; rows: ScreenRow[] }
  | { type: ScreenNodeType.Cards; cards: ScreenRow[] }
  | { type: ScreenNodeType.Table; id: string; columns: ScreenColumn[]; facets: ScreenFacet[]; rows: ScreenTableRow[]; empty?: Text }
  | { type: ScreenNodeType.Tabs; id: string; iconsOnly: boolean; on?: string; tabs: ScreenTab[] }
  | { type: ScreenNodeType.Select; id: string; icon: string; title: Text; value: string; options: [string, Text][]; action: ScreenAction }
  | { type: ScreenNodeType.Form; fields: ScreenField[]; submit: ScreenButton }
  | { type: ScreenNodeType.Pre; text: string }
  | { type: ScreenNodeType.Editor; text: string; check: ScreenAction; apply: ScreenAction }
  | ({ type: ScreenNodeType.Terminal } & TerminalOps)
  | { type: ScreenNodeType.Danger; title: Text; hint: Text; button: ScreenButton }
  | { type: ScreenNodeType.Chips; chips: ScreenChip[] }
  | { type: ScreenNodeType.Actions; buttons: ScreenButton[] }
  | { type: ScreenNodeType.Alert; text: Text; tone: Tone }
  | { type: ScreenNodeType.Empty; icon: string; title: Text; body?: Text }
  | { type: ScreenNodeType.Busy; text: Text };

/// A whole screen, a drawer's or a dialogue's contents. The section's
/// switcher (the other clusters, the catalogue) is the path's column in this
/// window; only its "add" is kept, among the actions.
export type ScreenPage = {
  title?: Text;
  icon?: string;
  subtitle?: Text;
  crumb?: { label: Text; action: ScreenAction };
  chips: ScreenChip[];
  actions: ScreenButton[];
  body: ScreenNode[];
  /// Ask again in this many milliseconds.
  refreshMs?: number;
};

/// What an action leaves behind.
export type ScreenReply = {
  go?: string;
  drawer?: ScreenPage;
  closeDrawer: boolean;
  dialog?: ScreenPage;
  closeDialog: boolean;
  toast?: Text;
  refresh: boolean;
  /// For the node that asked: a tab's body, an editor's check, a stream's
  /// chunk — read by the asker (`bodyOf`, `diffOf`, `streamOf`, `chunkOf`).
  data: unknown;
};

/// A terminal's output since `cursor`.
export type Chunk = { data: string; cursor: number; state: StreamState; error: string | null };

export type ScreenOptions = {
  /// The plugin's dictionary; every key it says must be in it.
  words?: Words | undefined;
  /// The icons the window has; a name outside them is refused.
  icons?: ReadonlySet<string>;
};

type Raw = Record<string, unknown>;

/// The reader of one plugin's answers. Every function throws, naming the
/// plugin and what was read, on anything that does not hold together.
export function screenReader(plugin: string, opts: ScreenOptions = {}) {
  const fail = (what: string): never => {
    throw new Error(`the plugin "${plugin}" answered ${what}`);
  };
  const { text, opt } = wordReader(plugin, opts.words, (what) => fail(`with ${what}`));

  const obj = (v: unknown, where: string): Raw => (v && typeof v === "object" && !Array.isArray(v) ? (v as Raw) : fail(`something other than an object for ${where}`));
  const list = (v: unknown, where: string): unknown[] => (v === undefined ? [] : Array.isArray(v) ? v : fail(`something other than a list for ${where}`));
  const str = (v: unknown, where: string): string => (typeof v === "string" ? v : fail(`something other than text for ${where}`));
  const optStr = (v: unknown, where: string): string | undefined => (v === undefined || v === null ? undefined : str(v, where));
  const num = (v: unknown, where: string): number => (typeof v === "number" && Number.isFinite(v) ? v : fail(`something other than a number for ${where}`));
  const optNum = (v: unknown, where: string): number | undefined => (v === undefined || v === null ? undefined : num(v, where));
  const flag = (v: unknown, where: string): boolean => (v === undefined ? false : typeof v === "boolean" ? v : fail(`something other than yes or no for ${where}`));
  const icon = (v: unknown, where: string): string => {
    const i = str(v, `the icon of ${where}`);
    if (opts.icons && !opts.icons.has(i)) fail(`with the icon "${i}" for ${where}, which the window does not have`);
    return i;
  };
  const optIcon = (v: unknown, where: string): string | undefined => (v === undefined || v === null ? undefined : icon(v, where));
  const words = (v: unknown, where: string): Text => text(v as DeclaredText, where);
  const optWords = (v: unknown, where: string): Text | undefined => opt(v as DeclaredText | undefined, where);
  // boundary: a tone's word becomes a member here.
  const tone = (v: unknown, where: string): Tone => (v === undefined ? Tone.Plain : isEnumValue(Tone, v) ? v : fail(`the tone "${String(v)}" for ${where}`));
  const options = (v: unknown, where: string): [string, Text][] =>
    list(v, where).map((o, i) => {
      if (!Array.isArray(o) || o.length !== 2) return fail(`an option that is not a value and its words in ${where}`);
      return [str(o[0], `${where} (${i})`), words(o[1], `${where} (${i})`)];
    });

  const action = (v: unknown, where: string): ScreenAction => {
    const a = obj(v, where);
    const op = str(a.op, `the operation of ${where}`);
    if (!op) fail(`an empty operation for ${where}`);
    const confirm = optStr(a.confirm, `the word to type for ${where}`);
    if (confirm === "") fail(`an empty word to type for ${where}`);
    return { op, payload: a.payload ?? null, ...(confirm !== undefined ? { confirm } : {}), ...(flag(a.twice, where) ? { twice: true as const } : {}) };
  };
  const optAction = (v: unknown, where: string): ScreenAction | undefined => (v === undefined || v === null ? undefined : action(v, where));

  // A word to type is asked in the danger zone, and only there.
  const button = (v: unknown, where: string, typed = false): ScreenButton => {
    const b = obj(v, where);
    const label = optWords(b.label, where);
    const ic = optIcon(b.icon, where);
    if (!label && !ic) fail(`a button with neither words nor an icon in ${where}`);
    return {
      ...(label ? { label } : {}),
      ...(ic ? { icon: ic } : {}),
      title: words(b.title, where),
      tone: tone(b.tone, where),
      primary: flag(b.primary, where),
      disabled: flag(b.disabled, where),
      busy: flag(b.busy, where),
      action: typed ? action(b.action, where) : untyped(action(b.action, where), where),
    };
  };
  const untyped = (a: ScreenAction, where: string): ScreenAction => (a.confirm === undefined ? a : fail(`a button that asks for "${a.confirm}" to be typed outside a danger zone in ${where}`));
  const chip = (v: unknown, where: string): ScreenChip => {
    const c = obj(v, where);
    const ic = optIcon(c.icon, where);
    const title = optWords(c.title, where);
    return { label: words(c.label, where), tone: tone(c.tone, where), ...(ic ? { icon: ic } : {}), ...(title ? { title } : {}), dot: flag(c.dot, where) };
  };
  const row = (v: unknown, where: string): ScreenRow => {
    const r = obj(v, where);
    const w = `${where}'s row "${String(r.key)}"`;
    const subtitle = optWords(r.subtitle, w);
    const note = optWords(r.note, w);
    const code = optStr(r.code, w);
    const at = optNum(r.at, w);
    const open = optAction(r.open, w);
    return {
      key: str(r.key, `the key of a row in ${where}`),
      icon: icon(r.icon, w),
      tone: tone(r.tone, w),
      busy: flag(r.busy, w),
      title: words(r.title, w),
      mono: flag(r.mono, w),
      ...(subtitle ? { subtitle } : {}),
      chips: list(r.chips, w).map((c) => chip(c, w)),
      ...(note ? { note } : {}),
      ...(code !== undefined ? { code } : {}),
      ...(at !== undefined ? { at } : {}),
      actions: list(r.actions, w).map((b) => button(b, w)),
      ...(open ? { open } : {}),
    };
  };
  const cell = (v: unknown, where: string): ScreenCell => {
    const c = obj(v, where);
    switch (c.type) {
      case CellType.Text:
        return { type: CellType.Text, text: words(c.text, where) };
      case CellType.Chip:
        return { type: CellType.Chip, chip: chip(c.chip, where) };
      case CellType.Ago:
        return { type: CellType.Ago, at: num(c.at, where) };
      case CellType.Empty:
        return { type: CellType.Empty };
      default:
        return fail(`a cell of an unknown kind "${String(c.type)}" in ${where}`);
    }
  };
  const tableRow = (v: unknown, columns: Set<string>, facets: Set<string>, where: string): ScreenTableRow => {
    const r = obj(v, where);
    const key = str(r.key, `the key of a row in ${where}`);
    const w = `${where}'s row "${key}"`;
    const cells: Record<string, ScreenCell> = {};
    for (const [k, c] of Object.entries(obj(r.cells ?? {}, w))) {
      if (!columns.has(k)) fail(`a cell "${k}" in ${w}, which is no column of it`);
      cells[k] = cell(c, `${w} (${k})`);
    }
    const fs: Record<string, string> = {};
    for (const [k, f] of Object.entries(obj(r.facets ?? {}, w))) {
      if (!facets.has(k)) fail(`a facet "${k}" in ${w}, which is no facet of it`);
      fs[k] = str(f, `${w} (${k})`);
    }
    const sort: Record<string, string | number> = {};
    for (const [k, s] of Object.entries(obj(r.sort ?? {}, w))) {
      if (!columns.has(k)) fail(`a sort key "${k}" in ${w}, which is no column of it`);
      sort[k] = typeof s === "number" ? num(s, w) : str(s, w);
    }
    const open = optAction(r.open, w);
    return { key, cells, facets: fs, sort, ...(open ? { open } : {}), actions: list(r.actions, w).map((b) => button(b, w)) };
  };
  const field = (v: unknown, where: string): ScreenField => {
    const f = obj(v, where);
    const id = str(f.id, `the id of a field in ${where}`);
    const w = `${where}'s field "${id}"`;
    const k = obj(f.kind, w);
    let spec: ScreenFieldSpec;
    switch (k.kind) {
      case FieldKind.Text:
        spec = { kind: FieldKind.Text };
        break;
      case FieldKind.Secret:
        spec = { kind: FieldKind.Secret };
        break;
      case FieldKind.Area:
        spec = { kind: FieldKind.Area };
        break;
      case FieldKind.Number:
        spec = { kind: FieldKind.Number, min: num(k.min, w), max: num(k.max, w) };
        break;
      case FieldKind.Toggle:
        spec = { kind: FieldKind.Toggle };
        break;
      case FieldKind.Select: {
        const os = options(k.options, w);
        if (!os.length) fail(`a choice with nothing to choose in ${w}`);
        spec = { kind: FieldKind.Select, options: os };
        break;
      }
      default:
        return fail(`a field of an unknown kind "${String(k.kind)}" in ${where}`);
    }
    const hint = optWords(f.hint, w);
    const value = optStr(f.value, w);
    if (value !== undefined && spec.kind === FieldKind.Secret) fail(`a secret field with a value in ${w}: a secret is never echoed into a form`);
    if (value !== undefined && spec.kind === FieldKind.Toggle && value !== "true" && value !== "false") fail(`a switch set to "${value}" in ${w}`);
    return { id, label: words(f.label, w), spec, ...(hint ? { hint } : {}), ...(value !== undefined ? { value } : {}) };
  };
  const tab = (v: unknown, where: string): ScreenTab => {
    const t = obj(v, where);
    const id = str(t.id, `the id of a tab in ${where}`);
    const w = `${where}'s tab "${id}"`;
    const ic = optIcon(t.icon, w);
    const load = optAction(t.load, w);
    const refreshMs = optNum(t.refresh_ms, w);
    if (refreshMs !== undefined && !load) fail(`${w} asked again with nothing to ask`);
    return { id, title: words(t.title, w), ...(ic ? { icon: ic } : {}), ...(load ? { load } : {}), ...(refreshMs !== undefined ? { refreshMs } : {}), body: nodes(t.body, w) };
  };

  const node = (v: unknown, where: string): ScreenNode => {
    const n = obj(v, where);
    switch (n.type) {
      case ScreenNodeType.Section: {
        const count = optNum(n.count, where);
        const hint = optWords(n.hint, where);
        return {
          type: ScreenNodeType.Section,
          title: words(n.title, where),
          icon: icon(n.icon, where),
          tone: tone(n.tone, where),
          ...(count !== undefined ? { count } : {}),
          folded: flag(n.folded, where),
          ...(hint ? { hint } : {}),
          body: nodes(n.body, where),
        };
      }
      case ScreenNodeType.List:
        return { type: ScreenNodeType.List, rows: list(n.rows, where).map((r) => row(r, where)) };
      case ScreenNodeType.Cards:
        return { type: ScreenNodeType.Cards, cards: list(n.cards, where).map((r) => row(r, where)) };
      case ScreenNodeType.Table: {
        const id = str(n.id, `the id of a table in ${where}`);
        const w = `${where}'s table "${id}"`;
        const columns = list(n.columns, w).map((c): ScreenColumn => {
          const o = obj(c, w);
          return { id: str(o.id, w), title: words(o.title, w), sortable: flag(o.sortable, w), mono: flag(o.mono, w) };
        });
        if (!columns.length) fail(`${w} with no columns`);
        const facets = list(n.facets, w).map((f): ScreenFacet => {
          const o = obj(f, w);
          return { id: str(o.id, w), title: words(o.title, w), icon: icon(o.icon, w) };
        });
        const ids = new Set(columns.map((c) => c.id));
        const fids = new Set(facets.map((f) => f.id));
        const empty = optWords(n.empty, w);
        return { type: ScreenNodeType.Table, id, columns, facets, rows: list(n.rows, w).map((r) => tableRow(r, ids, fids, w)), ...(empty ? { empty } : {}) };
      }
      case ScreenNodeType.Tabs: {
        const id = str(n.id, `the id of tabs in ${where}`);
        const tabs = list(n.tabs, where).map((t) => tab(t, where));
        if (!tabs.length) fail(`tabs "${id}" with no tab in ${where}`);
        const on = optStr(n.on, where);
        if (on !== undefined && !tabs.some((t) => t.id === on)) fail(`tabs "${id}" that open on "${on}", which is none of them, in ${where}`);
        return { type: ScreenNodeType.Tabs, id, iconsOnly: flag(n.icons_only, where), ...(on !== undefined ? { on } : {}), tabs };
      }
      case ScreenNodeType.Select:
        return {
          type: ScreenNodeType.Select,
          id: str(n.id, where),
          icon: icon(n.icon, where),
          title: words(n.title, where),
          value: str(n.value, where),
          options: options(n.options, where),
          action: action(n.action, where),
        };
      case ScreenNodeType.Form: {
        const fields = list(n.fields, where).map((f) => field(f, where));
        if (new Set(fields.map((f) => f.id)).size !== fields.length) fail(`a form with a field twice in ${where}`);
        return { type: ScreenNodeType.Form, fields, submit: button(n.submit, `the form of ${where}`) };
      }
      case ScreenNodeType.Pre:
        return { type: ScreenNodeType.Pre, text: str(n.text, where) };
      case ScreenNodeType.Editor:
        return { type: ScreenNodeType.Editor, text: str(n.text, where), check: action(n.check, where), apply: action(n.apply, where) };
      case ScreenNodeType.Terminal:
        return {
          type: ScreenNodeType.Terminal,
          open: action(n.open, where),
          read: str(n.read, where),
          write: str(n.write, where),
          resize: str(n.resize, where),
          close: str(n.close, where),
        };
      case ScreenNodeType.Danger: {
        const b = button(n.button, `the danger zone of ${where}`, true);
        return { type: ScreenNodeType.Danger, title: words(n.title, where), hint: words(n.hint, where), button: b };
      }
      case ScreenNodeType.Chips:
        return { type: ScreenNodeType.Chips, chips: list(n.chips, where).map((c) => chip(c, where)) };
      case ScreenNodeType.Actions:
        return { type: ScreenNodeType.Actions, buttons: list(n.buttons, where).map((b) => button(b, where)) };
      case ScreenNodeType.Alert:
        return { type: ScreenNodeType.Alert, text: words(n.text, where), tone: tone(n.tone, where) };
      case ScreenNodeType.Empty: {
        const body = optWords(n.body, where);
        return { type: ScreenNodeType.Empty, icon: icon(n.icon, where), title: words(n.title, where), ...(body ? { body } : {}) };
      }
      case ScreenNodeType.Busy:
        return { type: ScreenNodeType.Busy, text: words(n.text, where) };
      default:
        return fail(`a node of an unknown kind "${String(n.type)}" in ${where}`);
    }
  };
  const nodes = (v: unknown, where: string): ScreenNode[] => list(v, where).map((n) => node(n, where));

  const page = (v: unknown, where: string): ScreenPage => {
    const p = obj(v, where);
    const title = optWords(p.title, where);
    const ic = optIcon(p.icon, where);
    const subtitle = optWords(p.subtitle, where);
    const c = p.crumb === undefined || p.crumb === null ? undefined : obj(p.crumb, `the crumb of ${where}`);
    const crumb = c ? { label: words(c.label, `the crumb of ${where}`), action: action(c.action, `the crumb of ${where}`) } : undefined;
    const sw = p.switcher === undefined || p.switcher === null ? undefined : obj(p.switcher, `the switcher of ${where}`);
    const add = sw && sw.add !== undefined && sw.add !== null ? button(sw.add, `the switcher of ${where}`) : undefined;
    const refreshMs = optNum(p.refresh_ms, where);
    const actions = list(p.actions, where).map((b) => button(b, where));
    const body = nodes(p.body, where);
    if (!title && !sw) fail(`${where} with no title`);
    return {
      ...(title ? { title } : {}),
      ...(ic ? { icon: ic } : {}),
      ...(subtitle ? { subtitle } : {}),
      ...(crumb ? { crumb } : {}),
      chips: list(p.chips, where).map((x) => chip(x, where)),
      actions: add ? [...actions, add] : actions,
      body,
      ...(refreshMs !== undefined ? { refreshMs } : {}),
    };
  };

  return {
    /// boundary: a screen as the plugin gives it for `route`.
    page: (v: unknown, route: string): ScreenPage => page(v, `the screen "${route}"`),
    /// boundary: what the operation `op` left behind.
    reply: (v: unknown, op: string): ScreenReply => {
      const where = `"${op}"`;
      const r = obj(v, `the reply to ${where}`);
      const go = optStr(r.go, `the route of the reply to ${where}`);
      const drawer = r.drawer === undefined || r.drawer === null ? undefined : page(r.drawer, `the drawer of ${where}`);
      const dialog = r.dialog === undefined || r.dialog === null ? undefined : page(r.dialog, `the dialogue of ${where}`);
      const toast = optWords(r.toast, `the toast of ${where}`);
      return {
        ...(go !== undefined ? { go } : {}),
        ...(drawer ? { drawer } : {}),
        closeDrawer: flag(r.close_drawer, where),
        ...(dialog ? { dialog } : {}),
        closeDialog: flag(r.close_dialog, where),
        ...(toast ? { toast } : {}),
        refresh: flag(r.refresh, where),
        data: r.data ?? null,
      };
    },
    /// boundary: a tab's body, from a reply's data.
    body: (data: unknown, op: string): ScreenNode[] => nodes(obj(data, `the data of "${op}"`).body, `the body "${op}" gave`),
    /// boundary: what the checked editor's `check` says would change.
    diff: (data: unknown, op: string): { before: string | null; after: string } => {
      const d = obj(data, `the data of "${op}"`);
      return { before: d.before === null ? null : str(d.before, `what "${op}" says stands`), after: str(d.after, `what "${op}" says would stand`) };
    },
    /// boundary: the stream a terminal's `open` gave.
    stream: (data: unknown, op: string): string => {
      const s = str(obj(data, `the data of "${op}"`).stream, `the stream "${op}" opened`);
      if (!s) fail(`an empty stream to "${op}"`);
      return s;
    },
    /// boundary: a terminal's output since its cursor.
    chunk: (data: unknown, op: string): Chunk => {
      const d = obj(data, `the data of "${op}"`);
      const state = isEnumValue(StreamState, d.state) ? d.state : fail(`the stream state "${String(d.state)}" to "${op}"`);
      return { data: d.data === undefined || d.data === null ? "" : str(d.data, `the output of "${op}"`), cursor: num(d.cursor, `the cursor of "${op}"`), state, error: optStr(d.error, `the error of "${op}"`) ?? null };
    },
  };
}

export type ScreenReader = ReturnType<typeof screenReader>;

/// A plugin's refusal in words: its code (`err.x {"args"}`) read in its own
/// dictionary, else in the core's, else as it came.
export function refusalText(plugin: string, words: Words | undefined, e: unknown): Text {
  const msg = (e instanceof Error ? e.message : String(e)).trim();
  const m = /^(err\.[A-Za-z0-9]+)(?: (\{.*\}))?$/s.exec(msg);
  if (!m) return { raw: msg };
  const code = m[1]!;
  let args: Args | undefined;
  if (m[2]) {
    // A refusal whose arguments do not read is said as it came.
    let raw: unknown;
    try {
      raw = JSON.parse(m[2]);
    } catch {
      return { raw: msg };
    }
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return { raw: msg };
    args = {};
    for (const [k, v] of Object.entries(raw)) args[k] = typeof v === "number" ? v : String(v);
  }
  if (words && code in words.ru) return args ? { ext: `${plugin}.${code}`, args } : { ext: `${plugin}.${code}` };
  if (isKey(code)) return args ? { key: code, args } : { key: code };
  return { raw: msg };
}
