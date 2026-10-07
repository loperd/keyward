// The declared screens' vocabulary as the window reads it. The Rust half is
// `crates/ui/src/view.rs`; a plugin builds these, the window draws them.

export type Text = { key: string; args?: Record<string, unknown> } | { raw: string };
export type Tone = "plain" | "ok" | "warn" | "bad" | "accent";

export type Action = { op: string; payload?: unknown; confirm?: string; twice?: boolean };

export type Button = {
  label?: Text;
  icon?: string;
  title: Text;
  tone?: Tone;
  primary?: boolean;
  disabled?: boolean;
  busy?: boolean;
  action: Action;
};

export type Chip = { label: Text; tone?: Tone; icon?: string; title?: Text; dot?: boolean };

export type ListRow = {
  key: string;
  icon: string;
  tone?: Tone;
  busy?: boolean;
  title: Text;
  mono?: boolean;
  subtitle?: Text;
  chips?: Chip[];
  note?: Text;
  code?: string;
  at?: number;
  actions?: Button[];
  open?: Action;
};

export type Column = { id: string; title: Text; sortable?: boolean; mono?: boolean };
export type Facet = { id: string; title: Text; icon: string };
export type Cell = { type: "text"; text: Text } | { type: "chip"; chip: Chip } | { type: "ago"; at: number } | { type: "empty" };
export type TableRow = {
  key: string;
  cells: Record<string, Cell>;
  facets?: Record<string, string>;
  sort?: Record<string, string | number>;
  open?: Action;
  actions?: Button[];
};

export type FieldKind =
  | { kind: "text" }
  | { kind: "secret" }
  | { kind: "area" }
  | { kind: "number"; min: number; max: number }
  | { kind: "select"; options: [string, Text][] };
export type Field = { id: string; label: Text; kind: FieldKind; hint?: Text; value?: string };

export type Tab = { id: string; title: Text; icon?: string; load?: Action; refresh_ms?: number; body?: Node[] };

export type Node =
  | { type: "section"; title: Text; icon: string; tone?: Tone; count?: number; folded?: boolean; hint?: Text; body: Node[] }
  | { type: "list"; rows: ListRow[] }
  | { type: "cards"; cards: ListRow[] }
  | { type: "table"; id: string; columns: Column[]; facets?: Facet[]; rows: TableRow[]; empty?: Text }
  | { type: "tabs"; id: string; icons_only?: boolean; on?: string; tabs: Tab[] }
  | { type: "select"; id: string; icon: string; title: Text; value: string; options: [string, Text][]; action: Action }
  | { type: "form"; fields: Field[]; submit: Button }
  | { type: "pre"; text: string }
  | { type: "editor"; text: string; check: Action; apply: Action }
  | { type: "terminal"; open: Action; read: string; write: string; resize: string; close: string }
  | { type: "danger"; title: Text; hint: Text; button: Button }
  | { type: "chips"; chips: Chip[] }
  | { type: "actions"; buttons: Button[] }
  | { type: "alert"; text: Text; tone?: Tone }
  | { type: "empty"; icon: string; title: Text; body?: Text }
  | { type: "busy"; text: Text };

export type Page = {
  title?: Text | null;
  icon?: string;
  subtitle?: Text;
  crumb?: { label: Text; action: Action };
  switcher?: Switcher;
  chips?: Chip[];
  actions?: Button[];
  body: Node[];
  refresh_ms?: number;
};

export type SwitchItem = { key: string; label: Text; hint?: Text; icon?: string; dot?: Tone; route: string };
export type Switcher = { current: string; items: SwitchItem[]; add?: Button; all?: SwitchItem };

export type Reply = {
  go?: string;
  drawer?: Page;
  close_drawer?: boolean;
  dialog?: Page;
  close_dialog?: boolean;
  toast?: Text;
  refresh?: boolean;
  data?: unknown;
};
