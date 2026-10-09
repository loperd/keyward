// A plugin's declared screen drawn with the core's own kit: sections, rows
// and cards, tables with facets, tabs, forms, the checked editor, the
// terminal, the danger zone. It decides nothing: what a screen holds is the
// plugin's (plugin/screen.ts reads it); how it looks is the window's, the
// same grid, marks and buttons as every other page.
import { Fragment, useEffect, useMemo, useRef, useState, type MouseEvent, type ReactNode } from "react";
import { t, text, type Text } from "../../i18n";
import { Level } from "../../model/types";
import {
  type ScreenFieldSpec,
  type ScreenAction,
  type ScreenButton,
  type ScreenCell,
  type ScreenChip,
  type ScreenColumn,
  type ScreenFacet,
  type ScreenField,
  type ScreenNode,
  type ScreenRow,
  type ScreenTab,
  type ScreenTableRow,
  CellType,
  FieldKind,
  ItemPick,
  ScreenNodeType,
  Tone,
} from "../../plugin/screen";
import { ItemKind } from "../../model/types";
import { Icon } from "../Icons";
import { BtnIcon, Mark, Spinner, useCore, useLang } from "../marks";

import { Phase } from "../feedback";
import { SecretInput, type SecretInputHandle } from "../secret-input";
import { useScreen } from "./context";
import { type Filters, type Sort, DiffKind, agoSeconds, applyFilters, diffLines, sortRows, valuesOf, withoutNoise } from "./table";
import { Terminal } from "./Terminal";

const say = (x: Text) => text(x);

/// A tone as one of the window's levels, for a state's mark.
const LEVEL_OF: Record<Tone, Level> = { [Tone.Plain]: Level.Unknown, [Tone.Ok]: Level.Healthy, [Tone.Warn]: Level.Warning, [Tone.Bad]: Level.Critical, [Tone.Accent]: Level.Action };
const TONE_CLASS: Record<Tone, string> = { [Tone.Plain]: "", [Tone.Ok]: " t-ok", [Tone.Warn]: " t-warn", [Tone.Bad]: " t-bad", [Tone.Accent]: " t-accent" };

/// How long a button asked lightly stays armed.
const ARMED_MS = 3000;

// -- Small pieces -------------------------------------------------------------

export function ChipView({ chip }: { chip: ScreenChip }) {
  // A state is a mark, glyph and words; a kind is a quiet tag.
  if (chip.dot) return <span title={chip.title ? say(chip.title) : undefined}><Mark level={LEVEL_OF[chip.tone]} words={chip.label} /></span>;
  return (
    <span className={`tag${TONE_CLASS[chip.tone]}`} title={chip.title ? say(chip.title) : undefined}>
      {chip.icon && <Icon name={chip.icon} />}
      {say(chip.label)}
    </span>
  );
}

/// A declared button. Icon-only without words, its title in the tooltip; the
/// one main action is solid; one asked lightly arms on the first press.
export function ButtonView({ b, onPress, tipLeft }: { b: ScreenButton; onPress?: () => void; tipLeft?: boolean }) {
  const { run } = useScreen();
  const [busy, setBusy] = useState(false);
  const [armed, setArmed] = useState(false);
  useEffect(() => {
    if (!armed) return;
    const id = window.setTimeout(() => setArmed(false), ARMED_MS);
    return () => window.clearTimeout(id);
  }, [armed]);
  const press = (e: MouseEvent) => {
    // A button in a row is no press on the row.
    e.stopPropagation();
    if (onPress) return onPress();
    if (b.action.twice && !armed) return setArmed(true);
    setArmed(false);
    setBusy(true);
    void run(b.action).finally(() => setBusy(false));
  };
  const tip = armed ? t("scr.pressAgain") : say(b.title);
  const danger = b.tone === Tone.Bad || armed;
  const phase = busy || b.busy ? Phase.Busy : Phase.Idle;
  if (!b.label)
    return (
      <button
        type="button"
        className={`btn ico${danger ? " bad" : ""}${tipLeft ? " tip-l" : ""}`}
        data-tip={tip}
        aria-label={tip}
        aria-busy={phase === Phase.Busy || undefined}
        disabled={b.disabled || phase === Phase.Busy}
        onClick={press}
      >
        <BtnIcon icon={armed ? "check" : b.icon!} phase={phase} />
      </button>
    );
  return (
    <button
      type="button"
      className={`btn ${b.primary ? "solid" : "quiet"}${danger ? " danger bad" : ""}`}
      title={tip}
      aria-busy={phase === Phase.Busy || undefined}
      disabled={b.disabled || phase === Phase.Busy}
      onClick={press}
    >
      {b.icon ? <BtnIcon icon={armed ? "check" : b.icon} phase={phase} /> : phase === Phase.Busy ? <Spinner /> : null}
      {armed ? t("scr.pressAgain") : say(b.label)}
    </button>
  );
}

function Ago({ at }: { at: number }) {
  const lang = useLang();
  return <span className="when">{agoSeconds(at, lang)}</span>;
}

// -- Rows and cards -------------------------------------------------------------

function RowView({ row, card }: { row: ScreenRow; card?: boolean }) {
  const { run } = useScreen();
  const open = row.open;
  const press = open ? () => void run(open) : undefined;
  return (
    <div
      className={`${card ? "scard" : "srow"}${open ? " opens" : ""}`}
      role={open ? "button" : undefined}
      tabIndex={open ? 0 : undefined}
      onClick={press}
      onKeyDown={press ? (e) => e.key === "Enter" && e.target === e.currentTarget && press() : undefined}
    >
      <span className={`tile plain srow-ic${TONE_CLASS[row.tone]}`}>
        <Icon name={row.icon} />
        {(row.tone !== Tone.Plain || row.busy) && <i className={`dot${row.busy ? " pulse" : ""}`} />}
      </span>
      <span className="srow-t">
        <b className={row.mono ? "mono" : undefined} title={say(row.title)}>
          {say(row.title)}
        </b>
        {row.subtitle && <span>{say(row.subtitle)}</span>}
      </span>
      {(row.chips.length > 0 || row.note || row.code) && (
        <span className="srow-s">
          {row.chips.map((c, i) => (
            <ChipView key={i} chip={c} />
          ))}
          {row.note && <span className={`srow-note${TONE_CLASS[row.tone]}`}>{say(row.note)}</span>}
          {row.code && <code className="mono srow-code">{row.code}</code>}
        </span>
      )}
      <span className="srow-a">
        {row.at !== undefined && <Ago at={row.at} />}
        {row.actions.map((b, i) => (
          <ButtonView key={i} b={b} tipLeft={i === row.actions.length - 1} />
        ))}
      </span>
    </div>
  );
}

// -- Tables ---------------------------------------------------------------------

/// A table's filters and sort, kept by the table's name while the session
/// lasts: a table asked again, or come back to, keeps them.
const VIEWS = new Map<string, { selects: Filters; sort: Sort }>();

function cellText(c: ScreenCell | undefined): string {
  if (!c) return "";
  switch (c.type) {
    case CellType.Text:
      return say(c.text);
    case CellType.Chip:
      return say(c.chip.label);
    case CellType.Ago:
      return String(-c.at);
    case CellType.Empty:
      return "";
  }
}

function CellView({ c, mono }: { c: ScreenCell | undefined; mono: boolean }) {
  if (!c) return null;
  switch (c.type) {
    case CellType.Text:
      return <span className={mono ? "mono" : undefined}>{say(c.text)}</span>;
    case CellType.Chip:
      return <ChipView chip={c.chip} />;
    case CellType.Ago:
      return <Ago at={c.at} />;
    case CellType.Empty:
      return null;
  }
}

function TableView({ id, columns, facets, rows, empty }: { id: string; columns: ScreenColumn[]; facets: ScreenFacet[]; rows: ScreenTableRow[]; empty?: Text | undefined }) {
  const { plugin, run } = useScreen();
  const key = `${plugin}|${id}`;
  const [v, setV] = useState(() => VIEWS.get(key) ?? { selects: {}, sort: { key: columns[0]!.id, desc: false } });
  const set = (next: typeof v) => {
    VIEWS.set(key, next);
    setV(next);
  };
  const lang = useLang();
  const shown = useMemo(
    () => sortRows(applyFilters(rows, "", v.selects, () => ""), v.sort, (r, k) => cellText(r.cells[k])),
    // The words of a cell are the language's.
    [rows, v, lang], // eslint-disable-line react-hooks/exhaustive-deps
  );
  const active = Object.values(v.selects).some((x) => x !== undefined);
  const acts = rows.some((r) => r.actions.length > 0);
  const sortBy = (k: string) => set({ ...v, sort: { key: k, desc: v.sort.key === k ? !v.sort.desc : false } });
  return (
    <div className="stable">
      {facets.length > 0 && (
        <div className="sfilters">
          {facets.map((f) => {
            const value = v.selects[f.id];
            return (
              <label key={f.id} className={`ssel${value !== undefined ? " on" : ""}`} data-tip={say(f.title)}>
                <Icon name={f.icon} />
                <select
                  aria-label={say(f.title)}
                  value={value ?? ""}
                  onChange={(e) => set({ ...v, selects: { ...v.selects, [f.id]: e.target.value === "" ? undefined : e.target.value } })}
                >
                  <option value="">{t("scr.any", { what: say(f.title) })}</option>
                  {valuesOf(rows, f.id).map((x) => (
                    <option key={x.value} value={x.value}>
                      {x.value} · {x.count}
                    </option>
                  ))}
                </select>
              </label>
            );
          })}
          <span className="sshown">{active ? t("scr.shown", { n: shown.length, total: rows.length }) : rows.length}</span>
          {active && (
            <button type="button" className="btn ico tip-l" data-tip={t("scr.reset")} aria-label={t("scr.reset")} onClick={() => set({ ...v, selects: {} })}>
              <Icon name="close" />
            </button>
          )}
        </div>
      )}
      {shown.length === 0 ? (
        <div className="sempty">
          <Icon name={rows.length === 0 ? "info" : "filter"} />
          <span>{rows.length === 0 && empty ? say(empty) : t("scr.nothing")}</span>
        </div>
      ) : (
        <div className="stable-wrap">
          <table>
            <thead>
              <tr>
                {columns.map((c) => (
                  <th key={c.id} aria-sort={v.sort.key === c.id ? (v.sort.desc ? "descending" : "ascending") : undefined}>
                    {c.sortable ? (
                      <button type="button" className={`ssort${v.sort.key === c.id ? " on" : ""}${v.sort.desc ? " desc" : ""}`} onClick={() => sortBy(c.id)}>
                        {say(c.title)}
                        <Icon name="chev" />
                      </button>
                    ) : (
                      say(c.title)
                    )}
                  </th>
                ))}
                {acts && <th className="sacts" aria-hidden="true" />}
              </tr>
            </thead>
            <tbody>
              {shown.map((r) => {
                const open = r.open;
                return (
                  <tr
                    key={r.key}
                    className={open ? "opens" : undefined}
                    tabIndex={open ? 0 : undefined}
                    onClick={open ? () => void run(open) : undefined}
                    onKeyDown={open ? (e) => e.key === "Enter" && e.target === e.currentTarget && void run(open) : undefined}
                  >
                    {columns.map((c, i) => (
                      <td key={c.id} className={i === 0 ? "sfirst" : undefined} title={i === 0 ? cellText(r.cells[c.id]) : undefined}>
                        <CellView c={r.cells[c.id]} mono={c.mono} />
                      </td>
                    ))}
                    {acts && (
                      <td className="sacts">
                        <span>
                          {r.actions.map((b, i) => (
                            <ButtonView key={i} b={b} tipLeft={i === r.actions.length - 1} />
                          ))}
                        </span>
                      </td>
                    )}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// -- Tabs and selects -------------------------------------------------------------

/// The tab a person had on last, by the tabs' name, while the session lasts.
const TABS = new Map<string, string>();

function TabsView({ id, iconsOnly, initial, tabs }: { id: string; iconsOnly: boolean; initial: string | undefined; tabs: ScreenTab[] }) {
  const { plugin, run, epoch, reader, refusal } = useScreen();

  const key = `${plugin}|${id}`;
  const [on, setOn] = useState(() => initial ?? (tabs.some((x) => x.id === TABS.get(key)) ? TABS.get(key)! : tabs[0]!.id));
  const [loaded, setLoaded] = useState<{ tab: string; body: ScreenNode[] } | null>(null);
  const tab = tabs.find((x) => x.id === on) ?? tabs[0]!;
  useEffect(() => {
    TABS.set(key, on);
  }, [key, on]);
  const load = tab.load;
  const loadSig = load ? JSON.stringify(load) : "";
  useEffect(() => {
    if (!load) return;
    let alive = true;
    let timer: number | undefined;
    // One answer at a time: the next ask is set once this one is in, so a
    // slow plugin is never asked twice at once. A hidden window is not asked.
    const ask = () => {
      if (document.hidden) return schedule();
      void run(load)
        .then((r) => {
          if (alive && r) setLoaded({ tab: tab.id, body: reader.body(r.data, load.op) });
        })
        .catch((e: unknown) => {
          if (!alive) return;
          // A body that does not read is the plugin's mistake: said, and the
          // tab shows what it had.
          console.error(e);
          setLoaded({ tab: tab.id, body: [{ type: ScreenNodeType.Alert, text: refusal(e), tone: Tone.Bad }] });
        })
        .finally(schedule);
    };
    const schedule = () => {
      if (alive && tab.refreshMs) timer = window.setTimeout(ask, tab.refreshMs);
    };
    ask();
    return () => {
      alive = false;
      window.clearTimeout(timer);
    };
  }, [tab.id, loadSig, tab.refreshMs, epoch]); // eslint-disable-line react-hooks/exhaustive-deps
  // A tab of its own starts empty; the same tab asked again keeps what it
  // shows until the new answer is in.
  const body = load ? (loaded?.tab === tab.id ? loaded.body : null) : tab.body;
  return (
    <div className="stabs">
      <div className={`fseg stabbar${iconsOnly ? " icons" : ""}`} role="tablist">
        {tabs.map((x) => (
          <button
            key={x.id}
            type="button"
            role="tab"
            aria-selected={x.id === tab.id}
            className={x.id === tab.id ? "on" : undefined}
            data-tip={iconsOnly ? say(x.title) : undefined}
            aria-label={say(x.title)}
            onClick={() => setOn(x.id)}
          >
            {x.icon && <Icon name={x.icon} />}
            {!iconsOnly && <span>{say(x.title)}</span>}
          </button>
        ))}
      </div>
      {body === null ? <BusyView /> : <Nodes nodes={body} />}
    </div>
  );
}

function SelectView({ node }: { node: Extract<ScreenNode, { type: ScreenNodeType.Select }> }) {
  const { run } = useScreen();
  return (
    <label className={`ssel${node.value ? " on" : ""}`} data-tip={say(node.title)}>
      <Icon name={node.icon} />
      <select aria-label={say(node.title)} value={node.value} onChange={(e) => void run({ ...node.action, payload: { ...((node.action.payload as object | null) ?? {}), value: e.target.value } })}>
        {node.options.map(([v, label]) => (
          <option key={v} value={v}>
            {say(label)}
          </option>
        ))}
      </select>
    </label>
  );
}

// -- Forms --------------------------------------------------------------------------

/// A field's control. Every one is uncontrolled: what is typed lives in the
/// control alone and is read once, when the form is sent; a secret is read
/// through its `take()`, which empties it.
function FieldControl({ f, refs, secrets }: { f: ScreenField; refs: Map<string, HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>; secrets: Map<string, SecretInputHandle> }) {
  const label = say(f.label);
  const keep = (id: string) => (el: HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement | null) => {
    if (el) refs.set(id, el);
    else refs.delete(id);
  };
  const spec: ScreenFieldSpec = f.spec;
  switch (spec.kind) {
    case FieldKind.Secret:
      return (
        <span className="fin">
          <SecretInput
            aria-label={label}
            ref={(h) => {
              if (h) secrets.set(f.id, h);
              else secrets.delete(f.id);
            }}
          />
          <Icon name="lock" className="fin-ic" />
        </span>
      );
    case FieldKind.Area:
      return <textarea ref={keep(f.id)} className="sarea" aria-label={label} defaultValue={f.value ?? ""} spellCheck={false} rows={8} />;
    case FieldKind.Select:
      return (
        <span className="fin ssel-in">
          <select ref={keep(f.id)} aria-label={label} defaultValue={f.value ?? spec.options[0]![0]}>
            {spec.options.map(([v, l]) => (
              <option key={v} value={v}>
                {say(l)}
              </option>
            ))}
          </select>
          <Icon name="chev" className="fin-ic down" />
        </span>
      );
    case FieldKind.Toggle:
      return <ToggleControl label={label} initial={f.value === "true"} keep={keep(f.id)} />;
    case FieldKind.Item:
      return <ItemControl label={label} pick={spec.pick} initial={f.value} keep={keep(f.id)} />;
    case FieldKind.Number:
      return (
        <span className="fin">
          <input ref={keep(f.id)} aria-label={label} type="number" min={spec.min} max={spec.max} defaultValue={f.value ?? ""} autoComplete="off" />
        </span>
      );
    case FieldKind.Text:
      return (
        <span className="fin">
          <input ref={keep(f.id)} aria-label={label} type="text" defaultValue={f.value ?? ""} autoComplete="off" spellCheck={false} />
        </span>
      );
  }
}

/// The kind of item each pick offers.
const PICKED: Record<ItemPick, ItemKind> = { [ItemPick.Note]: ItemKind.SecureNote };

/// One of the vault's items, from the window's own catalogue: the plugin is
/// sent the id of the one picked, and never sees the list.
function ItemControl({ label, pick, initial, keep }: { label: string; pick: ItemPick; initial: string | undefined; keep: (el: HTMLSelectElement | null) => void }) {
  const { dir } = useCore();
  const items = dir.catalog.items.filter((i) => i.kind === PICKED[pick] && !i.deleted).sort((a, b) => a.name.localeCompare(b.name));
  return (
    <span className="fin ssel-in">
      <select ref={keep} aria-label={label} defaultValue={initial ?? ""}>
        <option value="" disabled>
          {t("scr.pickItem")}
        </option>
        {items.map((i) => (
          <option key={i.id} value={i.id}>
            {i.name}
          </option>
        ))}
      </select>
      <Icon name="chev" className="fin-ic down" />
    </span>
  );
}

/// A switch of a form: the window's own, its state read at sending from the
/// hidden box it keeps.
function ToggleControl({ label, initial, keep }: { label: string; initial: boolean; keep: (el: HTMLInputElement | null) => void }) {
  const [on, setOn] = useState(initial);
  return (
    <span className="stoggle">
      <input ref={keep} type="checkbox" hidden checked={on} readOnly />
      <button type="button" role="switch" aria-checked={on} aria-label={label} title={t(on ? "set.on" : "set.off")} className={`switch${on ? " on" : ""}`} onClick={() => setOn((x) => !x)} />
    </span>
  );
}

function FormView({ fields, submit }: { fields: ScreenField[]; submit: ScreenButton }) {
  const { run } = useScreen();
  const refs = useRef(new Map<string, HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>()).current;
  const secrets = useRef(new Map<string, SecretInputHandle>()).current;
  const [busy, setBusy] = useState(false);
  const send = () => {
    // Read now, and only now; the secrets are emptied as they are read.
    const form: Record<string, string> = {};
    for (const f of fields) {
      if (f.spec.kind === FieldKind.Secret) {
        const h = secrets.get(f.id);
        if (!h) throw new Error(`the secret field "${f.id}" was sent before it was drawn`);
        form[f.id] = h.take();
      } else {
        const el = refs.get(f.id);
        if (!el) throw new Error(`the field "${f.id}" was sent before it was drawn`);
        form[f.id] = f.spec.kind === FieldKind.Toggle ? String((el as HTMLInputElement).checked) : el.value;
      }
    }
    setBusy(true);
    void run(submit.action, form).finally(() => setBusy(false));
  };
  return (
    <form
      className="sform"
      onSubmit={(e) => {
        e.preventDefault();
        send();
      }}
    >
      {fields.map((f) => (
        <div key={f.id} className={`frow${f.spec.kind === FieldKind.Area ? " frow-area" : ""}`}>
          <span className="fl">
            <span>{say(f.label)}</span>
          </span>
          <span className="sctl">
            <FieldControl f={f} refs={refs} secrets={secrets} />
            {f.hint && <span className="shint">{say(f.hint)}</span>}
          </span>
        </div>
      ))}
      <div className="sfoot">
        <button type="submit" className={`btn ${submit.primary ? "solid" : "quiet"}`} disabled={busy || submit.disabled} aria-busy={busy || undefined}>
          {submit.icon ? <BtnIcon icon={submit.icon} phase={busy ? Phase.Busy : Phase.Idle} /> : busy ? <Spinner /> : null}
          {say(submit.label ?? submit.title)}
        </button>
      </div>
    </form>
  );
}

// -- The checked editor -----------------------------------------------------------

/// Text a person changes and applies — checked first: the plugin says what
/// would change, and only then is "apply" offered. The text lives in the
/// field; a change after a check takes the check back.
function EditorView({ text: initial, check, apply }: { text: string; check: ScreenAction; apply: ScreenAction }) {
  const { run, reader } = useScreen();
  const area = useRef<HTMLTextAreaElement>(null);
  const [checked, setChecked] = useState<{ before: string | null; after: string } | null>(null);
  const [blank, setBlank] = useState(initial.trim() === "");
  const [busy, setBusy] = useState(false);
  const lines = useMemo(() => (checked ? diffLines(withoutNoise(checked.before ?? ""), withoutNoise(checked.after)) : []), [checked]);
  const changed = lines.some((l) => l.kind !== DiffKind.Same);
  const withText = (a: ScreenAction): ScreenAction => ({ ...a, payload: { ...((a.payload as object | null) ?? {}), text: area.current!.value } });
  const go = (a: ScreenAction, then: (r: NonNullable<Awaited<ReturnType<typeof run>>>) => void) => {
    setBusy(true);
    void run(withText(a))
      .then((r) => r && then(r))
      .finally(() => setBusy(false));
  };
  return (
    <div className="seditor">
      <textarea
        ref={area}
        className="sarea tall"
        spellCheck={false}
        defaultValue={initial}
        aria-label={t("scr.text")}
        onInput={(e) => {
          setChecked(null);
          setBlank(e.currentTarget.value.trim() === "");
        }}
      />
      {checked && (
        <section className="sdiff">
          <div className="sec-h">
            <h2 className="h2">{checked.before === null ? t("scr.new") : changed ? t("scr.changes") : t("scr.noChanges")}</h2>
          </div>
          <pre>
            {lines.map((l, i) => (
              <span key={i} className={l.kind === DiffKind.Add ? "add" : l.kind === DiffKind.Del ? "del" : undefined}>
                {l.kind === DiffKind.Add ? "+ " : l.kind === DiffKind.Del ? "- " : "  "}
                {l.text}
                {"\n"}
              </span>
            ))}
          </pre>
        </section>
      )}
      <div className="sfoot">
        {checked ? (
          <button type="button" className="btn solid" disabled={busy || !changed} aria-busy={busy || undefined} onClick={() => go(apply, () => setChecked(null))}>
            <BtnIcon icon="check" phase={busy ? Phase.Busy : Phase.Idle} />
            {t("scr.apply")}
          </button>
        ) : (
          <button type="button" className="btn solid" disabled={busy || blank} aria-busy={busy || undefined} onClick={() => go(check, (r) => setChecked(reader.diff(r.data, check.op)))}>
            <BtnIcon icon="eye" phase={busy ? Phase.Busy : Phase.Idle} />
            {t("scr.check")}
          </button>
        )}
      </div>
    </div>
  );
}

// -- The danger zone -----------------------------------------------------------------

/// What cannot be taken back: at the end of the screen, in its colour, with
/// what it does; a word asked for is typed before the button wakes.
function DangerView({ title, hint, button, more }: { title: Text; hint: Text; button: ScreenButton; more: boolean }) {
  const { run } = useScreen();
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const word = button.action.confirm;
  return (
    <section className={`sec sdanger${more ? " more" : ""}`}>
      {/* One heading over the zone: the next of its rows says nothing again. */}
      {!more && (
        <div className="sec-h">
          <h2 className="h2">{t("scr.danger")}</h2>
        </div>
      )}
      <div className="sdanger-row">
        <span className="sdanger-t">
          <b>{say(title)}</b>
          <span>{say(hint)}</span>
        </span>
        <span className="sdanger-a">
          {word !== undefined && (
            <span className="fin">
              <input value={typed} onChange={(e) => setTyped(e.target.value)} placeholder={word} aria-label={t("scr.typeToConfirm", { word })} spellCheck={false} autoComplete="off" className="mono" />
            </span>
          )}
          <button
            type="button"
            className="btn solid danger"
            disabled={button.disabled || busy || (word !== undefined && typed !== word)}
            aria-busy={busy || undefined}
            onClick={() => {
              setBusy(true);
              void run(button.action).finally(() => setBusy(false));
            }}
          >
            <BtnIcon icon={button.icon ?? "trash"} phase={busy ? Phase.Busy : Phase.Idle} />
            {say(button.label ?? button.title)}
          </button>
        </span>
      </div>
    </section>
  );
}

// -- Everything --------------------------------------------------------------------

function BusyView({ words }: { words?: Text }) {
  return (
    <div className="sbusy" role="status">
      <Spinner />
      {words && <span>{say(words)}</span>}
    </div>
  );
}

function SectionView({ node }: { node: Extract<ScreenNode, { type: ScreenNodeType.Section }> }) {
  const head = (
    <>
      <Icon name={node.icon} className={`ssec-ic${TONE_CLASS[node.tone]}`} />
      <h2 className="h2">{say(node.title)}</h2>
      {node.count !== undefined && <span className="n">{node.count}</span>}
      {node.hint && <span className="ssec-hint">{say(node.hint)}</span>}
    </>
  );
  if (node.folded)
    return (
      <details className="sec ssec">
        <summary className="sec-h">
          <Icon name="chev" className="fold" />
          {head}
        </summary>
        <Nodes nodes={node.body} />
      </details>
    );
  return (
    <section className="sec ssec">
      <div className="sec-h">{head}</div>
      <Nodes nodes={node.body} />
    </section>
  );
}

export function NodeView({ node, after }: { node: ScreenNode; after?: ScreenNode | undefined }): ReactNode {
  switch (node.type) {
    case ScreenNodeType.Section:
      return <SectionView node={node} />;
    case ScreenNodeType.List:
      return (
        <div className="srows">
          {node.rows.map((r) => (
            <RowView key={r.key} row={r} />
          ))}
        </div>
      );
    case ScreenNodeType.Cards:
      return (
        <div className="scards">
          {node.cards.map((r) => (
            <RowView key={r.key} row={r} card />
          ))}
        </div>
      );
    case ScreenNodeType.Table:
      return <TableView key={node.id} id={node.id} columns={node.columns} facets={node.facets} rows={node.rows} empty={node.empty} />;
    case ScreenNodeType.Tabs:
      return <TabsView key={`${node.id}|${node.on ?? ""}`} id={node.id} iconsOnly={node.iconsOnly} initial={node.on} tabs={node.tabs} />;
    case ScreenNodeType.Select:
      return <SelectView node={node} />;
    case ScreenNodeType.Form:
      return <FormView fields={node.fields} submit={node.submit} />;
    case ScreenNodeType.Pre:
      return <pre className="spre">{node.text || t("scr.empty")}</pre>;
    case ScreenNodeType.Editor:
      return <EditorView key={node.text} text={node.text} check={node.check} apply={node.apply} />;
    case ScreenNodeType.Terminal:
      return <Terminal ops={node} />;
    case ScreenNodeType.Danger:
      return <DangerView title={node.title} hint={node.hint} button={node.button} more={after?.type === ScreenNodeType.Danger} />;
    case ScreenNodeType.Chips:
      return (
        <div className="schips">
          {node.chips.map((c, i) => (
            <ChipView key={i} chip={c} />
          ))}
        </div>
      );
    case ScreenNodeType.Actions:
      return (
        <div className="sactions">
          {node.buttons.map((b, i) => (
            <ButtonView key={i} b={b} />
          ))}
        </div>
      );
    case ScreenNodeType.Alert:
      return (
        <div className={`salert${TONE_CLASS[node.tone]}`} role={node.tone === Tone.Bad ? "alert" : "status"}>
          <Mark level={node.tone === Tone.Plain ? Level.Unknown : LEVEL_OF[node.tone]} words={node.text} />
        </div>
      );
    case ScreenNodeType.Empty:
      return (
        <div className="sempty big">
          <Icon name={node.icon} />
          <b>{say(node.title)}</b>
          {node.body && <span>{say(node.body)}</span>}
        </div>
      );
    case ScreenNodeType.Busy:
      return <BusyView words={node.text} />;
  }
}

export function Nodes({ nodes }: { nodes: ScreenNode[] }) {
  return (
    <>
      {nodes.map((n, i) => (
        <Fragment key={i}>
          <NodeView node={n} after={nodes[i - 1]} />
        </Fragment>
      ))}
    </>
  );
}

