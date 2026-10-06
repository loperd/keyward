import { createContext, Fragment, useContext, useEffect, useMemo, useState, type MouseEvent, type ReactNode } from "react";
import { Alert, Empty, Icon, Picker, ScreenHead, Segmented } from "../ui";
import { t, tError } from "../i18n";
import { diffLines, withoutNoise } from "./diff";
import { applyFilters, sortRows, valuesOf, type Filters, type Sort } from "./filters";
import { Terminal } from "./Terminal";
import { SwitcherView } from "./Switcher";
import { ago, tx } from "./text";
import type { Action, Button, Cell, Chip, Column, Facet, Field, ListRow, Node, Page, Reply, Tab, TableRow, Text, Tone } from "./types";

/// What a node needs from the screen it is on: whose plugin, and how an
/// action is carried out.
export type Run = (action: Action, form?: Record<string, string>) => Promise<Reply | null>;
/// `epoch` moves on every `refresh` a reply asks for: what a screen loaded
/// lazily — a tab's body — is asked again then too.
/// `go` opens a route of the section's: the switcher's entries.
export const Ctx = createContext<{ plugin: string; run: Run; epoch: number; go: (route: string) => void }>({ plugin: "", run: async () => null, epoch: 0, go: () => undefined });

const tone = (t?: Tone) => (t && t !== "plain" ? t : "");

// -- Small pieces -----------------------------------------------------------------

export function ChipView({ chip }: { chip: Chip }) {
  return (
    <span className={`chip ${chip.dot ? "dot" : ""} ${tone(chip.tone)} dv-chip`} title={chip.title ? tx(chip.title) : undefined}>
      {chip.icon && <Icon name={chip.icon} size={12} />}
      {tx(chip.label)}
    </span>
  );
}

export function ButtonView({ b, onPress }: { b: Button; onPress?: () => void }) {
  const { run } = useContext(Ctx);
  const [busy, setBusy] = useState(false);
  // An action asked lightly: the first press arms it for a few seconds.
  const [armed, setArmed] = useState(false);
  useEffect(() => {
    if (!armed) return;
    const id = window.setTimeout(() => setArmed(false), ARMED_MS);
    return () => window.clearTimeout(id);
  }, [armed]);
  // An icon stays an icon when armed — red, with a tick — so a row's width
  // does not move; a labelled button says it in words.
  const label = b.label ? (armed ? t("dv.pressAgain") : tx(b.label)) : null;
  const cls = ["btn", b.primary ? "primary" : "", b.tone === "bad" || armed ? "danger" : "", label ? "" : "icon-only", armed ? "armed" : "", "dv-btn"].join(" ");
  const press = (e: MouseEvent) => {
    // A button in a row is not a press on the row.
    e.stopPropagation();
    if (onPress) return onPress();
    if (b.action.twice && !armed) {
      setArmed(true);
      return;
    }
    setArmed(false);
    setBusy(true);
    void run(b.action).finally(() => setBusy(false));
  };
  const title = armed ? t("dv.pressAgain") : tx(b.title);
  return (
    <button type="button" className={cls} disabled={b.disabled || busy || b.busy} aria-busy={busy || b.busy} title={title} aria-label={title} onClick={press}>
      {b.icon && <Icon name={armed ? "check" : b.icon} size={14} />}
      {label}
    </button>
  );
}

/// How long a button asked lightly stays armed.
const ARMED_MS = 3000;

// -- Lists ------------------------------------------------------------------------

function ListRowView({ row }: { row: ListRow }) {
  const tn = tone(row.tone);
  // A row with nothing to report gives its title the width.
  const { run } = useContext(Ctx);
  const bare = !row.chips?.length && !row.note && !row.code;
  const open = row.open;
  return (
    <div
      className={`dv-row ${tn ? `tone-${tn}` : ""} ${bare ? "bare" : ""} ${open ? "opens" : ""}`}
      role={open ? "button" : undefined}
      tabIndex={open ? 0 : undefined}
      onClick={open ? () => void run(open) : undefined}
      onKeyDown={open ? (e) => e.key === "Enter" && void run(open) : undefined}
    >
      <span className={`dv-row-icon ${tn}`}>
        <Icon name={row.icon} />
        {(tn || row.busy) && <span className={`dot ${tn} ${row.busy ? "checking" : ""}`} />}
      </span>
      <span className={`dv-row-main ${row.mono ? "mono" : ""}`}>
        <b title={tx(row.title)}>{tx(row.title)}</b>
        {row.subtitle && <small>{tx(row.subtitle)}</small>}
      </span>
      {!bare && <span className="dv-row-status">
        {row.chips?.map((c, i) => <ChipView key={i} chip={c} />)}
        {row.note && <span className={`dv-row-note ${tn}`}>{tx(row.note)}</span>}
        {row.code && <code className="dv-code">{row.code}</code>}
      </span>}
      <span className="dv-row-actions">
        {row.at ? <span className="dv-when">{ago(row.at)}</span> : null}
        {row.actions?.map((b, i) => <ButtonView key={i} b={b} />)}
      </span>
    </div>
  );
}

// -- Tables -----------------------------------------------------------------------

const VIEWS = new Map<string, { query: string; selects: Filters; sort: Sort }>();

function cellText(c?: Cell): string {
  if (!c) return "";
  if (c.type === "text") return tx(c.text);
  if (c.type === "chip") return tx(c.chip.label);
  if (c.type === "ago") return String(-c.at);
  return "";
}

function CellView({ c, mono }: { c?: Cell; mono?: boolean }) {
  if (!c || c.type === "empty") return null;
  if (c.type === "chip") return <ChipView chip={c.chip} />;
  if (c.type === "ago") return <span className="dv-when">{ago(c.at)}</span>;
  return <span className={mono ? "dv-mono" : ""}>{tx(c.text)}</span>;
}

function TableView({ id, columns, facets = [], rows, empty }: { id: string; columns: Column[]; facets?: Facet[]; rows: TableRow[]; empty?: Text }) {
  const { plugin, run } = useContext(Ctx);
  const key = `${plugin}|${id}`;
  const [v, setV] = useState(() => VIEWS.get(key) ?? { query: "", selects: {}, sort: { key: columns[0]?.id ?? "", desc: false } });
  const set = (next: typeof v) => {
    VIEWS.set(key, next);
    setV(next);
  };
  const shown = useMemo(
    () =>
      sortRows(
        applyFilters(rows, facets, v.query, v.selects, (r) => [...Object.values(r.cells).map(cellText), ...Object.values(r.facets ?? {})].join(" ")),
        v.sort,
        (r, k) => cellText(r.cells[k]),
      ),
    [rows, facets, v],
  );
  const active = v.query.trim() !== "" || Object.values(v.selects).some(Boolean);
  // The table's layout is fixed: the actions' column is given the width of
  // the most buttons a row has (28px each, 4px between, 8px either side).
  const most = Math.max(0, ...rows.map((r) => r.actions?.length ?? 0));
  const withActions = most > 0;
  const actsWidth = most * 28 + (most - 1) * 4 + 16;
  const sortBy = (k: string) => set({ ...v, sort: { key: k, desc: v.sort.key === k ? !v.sort.desc : false } });

  return (
    <div className="dv-list">
      {/* The filters are the facets alone — each a picker with its own
          search over its values; a free search field stood apart from every
          other control and was taken out. The count and the reset close the
          row. */}
      {facets.length > 0 && (
        <div className="dv-filters">
          <div className="dv-facets">
            {facets.map((f) => {
              const value = v.selects[f.id] ?? "";
              return (
                <div key={f.id} className={`dv-facet ${value ? "on" : ""}`} title={tx(f.title)}>
                  <Icon name={f.icon} size={14} />
                  <Picker
                    value={value || null}
                    placeholder={tx(f.title)}
                    options={[{ id: "", label: t("dv.any") }, ...valuesOf(rows, f.id).map((x) => ({ id: x.value, label: x.value, hint: String(x.count) }))]}
                    onChange={(id) => set({ ...v, selects: { ...v.selects, [f.id]: id || undefined } })}
                  />
                </div>
              );
            })}
          </div>
          <span className="dv-shown">{active ? t("dv.shown", { n: shown.length, total: rows.length }) : rows.length}</span>
          {active && (
            <button type="button" className="btn icon-only" title={t("dv.reset")} aria-label={t("dv.reset")} onClick={() => set({ ...v, query: "", selects: {} })}>
              <Icon name="close" size={14} />
            </button>
          )}
        </div>
      )}
      {shown.length === 0 ? (
        <Empty icon={rows.length === 0 ? "cluster" : "search"} title={rows.length === 0 && empty ? tx(empty) : t("dv.nothing")} />
      ) : (
        <div className="dv-table-wrap">
          <table className="dv-table">
            <thead>
              <tr>
                {columns.map((c) => (
                  <th key={c.id} aria-sort={v.sort.key === c.id ? (v.sort.desc ? "descending" : "ascending") : undefined}>
                    {c.sortable ? (
                      <button type="button" className={`dv-sort ${v.sort.key === c.id ? "on" : ""}`} onClick={() => sortBy(c.id)}>
                        {tx(c.title)}
                        <Icon name="chevron" size={10} />
                      </button>
                    ) : (
                      tx(c.title)
                    )}
                  </th>
                ))}
                {withActions && <th className="dv-row-acts" style={{ width: actsWidth }} aria-hidden="true" />}
              </tr>
            </thead>
            <tbody>
              {shown.map((r) => (
                <tr key={r.key} className={r.open ? "open" : ""} tabIndex={r.open ? 0 : undefined} onClick={() => r.open && void run(r.open)} onKeyDown={(e) => e.key === "Enter" && r.open && void run(r.open)}>
                  {columns.map((c, i) => (
                    <td key={c.id} className={i === 0 ? "dv-first" : ""} title={i === 0 ? cellText(r.cells[c.id]) : undefined}>
                      <CellView c={r.cells[c.id]} mono={c.mono} />
                    </td>
                  ))}
                  {withActions && (
                    <td className="dv-row-acts">
                      <span>{r.actions?.map((b, i) => <ButtonView key={i} b={b} />)}</span>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// -- Tabs, selects, forms -----------------------------------------------------------

function TabsView({ id, iconsOnly, initial, tabs }: { id: string; iconsOnly?: boolean; initial?: string; tabs: Tab[] }) {
  const { plugin, run, epoch } = useContext(Ctx);
  const [on, setOn] = useState(() => (initial && tabs.some((x) => x.id === initial) ? initial : VIEWS_TABS.get(`${plugin}|${id}`)) ?? tabs[0]?.id ?? "");
  const [loaded, setLoaded] = useState<Node[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const tab = tabs.find((x) => x.id === on) ?? tabs[0];
  // A tab of its own starts empty; the same tab asked again keeps what it
  // shows until the new answer is in — no flash, the table's filters, sort
  // and scroll stay where they were.
  useEffect(() => {
    VIEWS_TABS.set(`${plugin}|${id}`, on);
    setLoaded(null);
    setError(null);
  }, [plugin, id, on]);
  useEffect(() => {
    const load = tab?.load;
    if (!load) return;
    let alive = true;
    let timer: number | undefined;
    // One answer at a time: the next ask is set after this one is in, so a
    // slow cluster is never asked twice at once. A hidden window is not asked.
    const ask = () => {
      if (document.hidden) {
        schedule();
        return;
      }
      run(load)
        .then((r) => {
          if (!alive) return;
          setLoaded(((r?.data as { body?: Node[] })?.body ?? []) as Node[]);
          setError(null);
        })
        .catch((e) => alive && setError(String(e)))
        .finally(schedule);
    };
    const schedule = () => {
      if (alive && tab?.refresh_ms) timer = window.setTimeout(ask, tab.refresh_ms);
    };
    ask();
    return () => {
      alive = false;
      window.clearTimeout(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [on, tab?.load?.op, JSON.stringify(tab?.load?.payload), tab?.refresh_ms, epoch]);
  if (!tab) return null;
  const body = tab.load ? loaded : tab.body ?? [];
  return (
    <div className="dv-tabs">
      <div className={iconsOnly ? "dv-icon-tabs" : "dv-tab-strip"}>
        <Segmented value={on} onChange={setOn} options={tabs.map((x) => ({ id: x.id, label: iconsOnly ? "" : tx(x.title), icon: x.icon, title: tx(x.title) }))} />
      </div>
      {error && <Alert message={error} />}
      {body === null ? !error && <Busy /> : <Nodes nodes={body} />}
    </div>
  );
}

const VIEWS_TABS = new Map<string, string>();

function SelectView({ node }: { node: Extract<Node, { type: "select" }> }) {
  const { run } = useContext(Ctx);
  return (
    <div className={`dv-facet dv-select ${node.value ? "on" : ""}`} title={tx(node.title)}>
      <Icon name={node.icon} size={13} />
      <Picker
        value={node.value || null}
        placeholder={tx(node.title)}
        options={node.options.map(([v, label]) => ({ id: v, label: tx(label) }))}
        onChange={(value) => void run({ ...node.action, payload: { ...((node.action.payload as object) ?? {}), value } })}
      />
    </div>
  );
}

function FieldView({ f, value, set }: { f: Field; value: string; set: (v: string) => void }) {
  const k = f.kind;
  return (
    <div className="dv-field">
      <span>
        {tx(f.label)}
        {k.kind === "secret" && <Icon name="lock" size={11} />}
      </span>
      {k.kind === "area" ? (
        <textarea className="dv-code-area" aria-label={tx(f.label)} spellCheck={false} value={value} onChange={(e) => set(e.target.value)} />
      ) : k.kind === "select" ? (
        <Picker value={value || null} placeholder={tx(f.label)} options={k.options.map(([v, label]) => ({ id: v, label: tx(label) }))} onChange={set} />
      ) : (
        <input
          className="dv-input"
          aria-label={tx(f.label)}
          type={k.kind === "secret" ? "password" : k.kind === "number" ? "number" : "text"}
          min={k.kind === "number" ? k.min : undefined}
          max={k.kind === "number" ? k.max : undefined}
          value={value}
          autoComplete="off"
          spellCheck={false}
          onChange={(e) => set(e.target.value)}
        />
      )}
      {f.hint && <small className="dv-hint">{tx(f.hint)}</small>}
    </div>
  );
}

function FormView({ fields, submit }: { fields: Field[]; submit: Button }) {
  const { run } = useContext(Ctx);
  const [values, setValues] = useState<Record<string, string>>(() => Object.fromEntries(fields.map((f) => [f.id, f.value ?? (f.kind.kind === "select" ? f.kind.options[0]?.[0] ?? "" : "")])));
  const [busy, setBusy] = useState(false);
  return (
    <form
      className="dv-form"
      onSubmit={(e) => {
        e.preventDefault();
        setBusy(true);
        void run(submit.action, values).finally(() => setBusy(false));
      }}
    >
      {fields.map((f) => (
        <FieldView key={f.id} f={f} value={values[f.id] ?? ""} set={(v) => setValues((x) => ({ ...x, [f.id]: v }))} />
      ))}
      <div className="dv-form-foot">
        <button type="submit" className="btn primary" disabled={busy || submit.disabled}>
          {submit.icon && <Icon name={submit.icon} size={14} />}
          {tx(submit.label ?? submit.title)}
        </button>
      </div>
    </form>
  );
}

// -- The checked editor ------------------------------------------------------------

function EditorView({ text, check, apply }: { text: string; check: Action; apply: Action }) {
  const { run } = useContext(Ctx);
  const [value, setValue] = useState(text);
  const [checked, setChecked] = useState<{ for: string; before: string | null; after: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const fresh = checked !== null && checked.for === value;
  const lines = useMemo(() => (checked ? diffLines(withoutNoise(checked.before ?? ""), withoutNoise(checked.after)) : []), [checked]);
  const changed = lines.some((l) => l.kind !== "same");
  const with_ = (a: Action) => ({ ...a, payload: { ...((a.payload as object) ?? {}), text: value } });
  return (
    <div className="dv-editor">
      <textarea className="dv-code-area tall" spellCheck={false} value={value} onChange={(e) => setValue(e.target.value)} aria-label="YAML" />
      {fresh && (
        <section className="dv-diff">
          <h4>
            <Icon name="code" size={13} />
            {checked.before === null ? t("dv.new") : changed ? t("dv.changes") : t("dv.noChanges")}
          </h4>
          <pre>
            {lines.map((l, i) => (
              <span key={i} className={`dv-diff-${l.kind}`}>
                {l.kind === "add" ? "+ " : l.kind === "del" ? "- " : "  "}
                {l.text}
                {"\n"}
              </span>
            ))}
          </pre>
        </section>
      )}
      <div className="dv-form-foot">
        {fresh ? (
          <button
            type="button"
            className="btn primary"
            disabled={busy || !changed}
            onClick={() => {
              setBusy(true);
              void run(with_(apply)).finally(() => setBusy(false));
            }}
          >
            <Icon name="check" size={14} />
            {t("dv.apply")}
          </button>
        ) : (
          <button
            type="button"
            className="btn primary"
            disabled={busy || !value.trim()}
            onClick={() => {
              setBusy(true);
              run(with_(check))
                .then((r) => {
                  const d = r?.data as { before: string | null; after: string } | undefined;
                  if (d) setChecked({ for: value, before: d.before, after: d.after });
                })
                .finally(() => setBusy(false));
            }}
          >
            <Icon name="check" size={14} />
            {t("dv.check")}
          </button>
        )}
      </div>
    </div>
  );
}

// -- The danger zone ----------------------------------------------------------------

function DangerView({ title, hint, button }: { title: Text; hint: Text; button: Button }) {
  const { run } = useContext(Ctx);
  const [typed, setTyped] = useState("");
  const word = button.action.confirm;
  return (
    <section className="danger-zone">
      <h4>{t("settings.danger")}</h4>
      <div className="danger-row dv-danger">
        <span className="text">
          <b>{tx(title)}</b>
          <span className="hint">{tx(hint)}</span>
        </span>
        <span className="dv-danger-act">
          {word && <input className="dv-input" value={typed} onChange={(e) => setTyped(e.target.value)} placeholder={word} aria-label={tx(hint)} spellCheck={false} />}
          <button type="button" className="btn danger" disabled={button.disabled || (word !== undefined && typed !== word)} onClick={() => void run(button.action)}>
            {button.icon && <Icon name={button.icon} size={14} />}
            {tx(button.label ?? button.title)}
          </button>
        </span>
      </div>
    </section>
  );
}

// -- Everything --------------------------------------------------------------------

function Busy({ text }: { text?: string }) {
  return (
    <div className="dv-busy">
      <span className="dv-spinner" />
      {text && <span>{text}</span>}
    </div>
  );
}

export function NodeView({ node }: { node: Node }) {
  const { plugin } = useContext(Ctx);
  switch (node.type) {
    case "section": {
      const head = (
        <>
          <Icon name={node.icon} size={13} />
          {tx(node.title)}
          {node.count !== undefined && <span className="dv-count">{node.count}</span>}
        </>
      );
      return node.folded ? (
        <details className={`dv-section ${tone(node.tone)}`}>
          <summary className="dv-section-head" title={node.hint ? tx(node.hint) : undefined}>
            <Icon name="chevron" size={12} />
            {head}
          </summary>
          <Nodes nodes={node.body} />
        </details>
      ) : (
        <section className={`dv-section ${tone(node.tone)}`}>
          <h4 className="dv-section-head" title={node.hint ? tx(node.hint) : undefined}>
            {head}
          </h4>
          <Nodes nodes={node.body} />
        </section>
      );
    }
    case "list":
      return (
        <div className="dv-rows">
          {node.rows.map((r) => (
            <ListRowView key={r.key} row={r} />
          ))}
        </div>
      );
    case "cards":
      return (
        <div className="dv-cards">
          {node.cards.map((r) => (
            <ListRowView key={r.key} row={r} />
          ))}
        </div>
      );
    case "table":
      return <TableView key={node.id} id={node.id} columns={node.columns} facets={node.facets} rows={node.rows} empty={node.empty} />;
    case "tabs":
      return <TabsView key={`${node.id}|${node.on ?? ""}`} id={node.id} iconsOnly={node.icons_only} initial={node.on} tabs={node.tabs} />;
    case "select":
      return <SelectView node={node} />;
    case "form":
      return <FormView fields={node.fields} submit={node.submit} />;
    case "pre":
      return <pre className="dv-pre">{node.text || t("dv.empty")}</pre>;
    case "editor":
      return <EditorView text={node.text} check={node.check} apply={node.apply} />;
    case "terminal":
      return <Terminal plugin={plugin} open={node.open} read={node.read} write={node.write} resize={node.resize} close={node.close} />;
    case "danger":
      return <DangerView title={node.title} hint={node.hint} button={node.button} />;
    case "chips":
      return (
        <div className="dv-chips">
          {node.chips.map((c, i) => (
            <ChipView key={i} chip={c} />
          ))}
        </div>
      );
    case "actions":
      return (
        <div className="dv-actions">
          {node.buttons.map((b, i) => (
            <ButtonView key={i} b={b} />
          ))}
        </div>
      );
    case "alert":
      return <Alert message={tx(node.text)} tone={node.tone === "warn" ? "warn" : "error"} />;
    case "empty":
      return <Empty icon={node.icon} title={tx(node.title)} body={node.body ? tx(node.body) : undefined} />;
    case "busy":
      return <Busy text={tx(node.text)} />;
  }
}

export function Nodes({ nodes }: { nodes: Node[] }) {
  return (
    <>
      {nodes.map((n, i) => (
        <Fragment key={i}>
          <NodeView node={n} />
        </Fragment>
      ))}
    </>
  );
}

/// A page's head: the crumb back, the title with its icon and chips, the
/// actions on the right.
export function PageHead({ page, trailing }: { page: Page; trailing?: ReactNode }) {
  const { run } = useContext(Ctx);
  if (!page.title && !page.crumb && !page.switcher && !page.actions?.length) return null;
  // The core's one head: a declared screen, a drawer and a dialogue read as
  // every other screen of the app.
  return (
    <ScreenHead
      icon={page.switcher ? undefined : page.icon}
      title={page.switcher || !page.title ? undefined : tx(page.title)}
      lead={
        <>
          {page.crumb && (
            <button type="button" className="btn icon-only dv-crumb" title={tx(page.crumb.label)} aria-label={tx(page.crumb.label)} onClick={() => void run(page.crumb!.action)}>
              <Icon name="chevron" size={14} />
            </button>
          )}
          {page.switcher && <SwitcherView s={page.switcher} />}
        </>
      }
      subtitle={page.subtitle ? tx(page.subtitle) : undefined}
    >
      {page.chips?.map((c, i) => <ChipView key={i} chip={c} />)}
      {page.actions?.map((b, i) => <ButtonView key={i} b={b} />)}
      {trailing}
    </ScreenHead>
  );
}

export { tError };
