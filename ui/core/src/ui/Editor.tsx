// An item's document as a form: the same hero and sections, each value an
// input in its place. `EditDocument` is an opened item turned into its form
// (the line does not move); `NewDocument` is a new item's, in the place the
// line stands in. A stored secret shows dots and "Replace": it is never
// fetched to fill an input. A generated password is shown for a moment, like
// a revealed one, and its value is let go when the form is done.
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent,
  type ReactNode,
} from "react";
import { t, text, type Key, type Text } from "../i18n";
import { type Lead, LeadTile, Hue } from "../doc/spec";
import {
  KIND_FIELDS,
  KINDS,
  formForNew,
  formFromDetail,
  kindOfVerb,
  placeOptions,
  placeValue,
  placementOf,
  problems,
  switchKind,
  typedSlots,
  type FieldSpec,
  type Form,
  type SecretSlot,
} from "../edit/draft";
import { FieldRefill } from "../edit/refill";
import { type ItemDetail, ItemKind } from "../model/types";
import { type GeneratorOptions, GeneratorKind } from "../writes";
import { Place } from "./Document";
import { Icon } from "./Icons";
import { BtnIcon, IconButton, Kbd, Mark, Tile, hueOf, nodeLead, useCore } from "./marks";
import { REVEAL_MS, dotsFor } from "./secret";
import { useWrites, type GenPrefs, type WritesApi } from "./writes-context";
import "./edit.css";
import { SecretInput, type SecretInputHandle } from "./secret-input";
import { Phase } from "./feedback";
import { SshKeyBlock } from "./SshKeyEdit";

const say = (x: Text) => text(x);
const KIND_ICON: Record<ItemKind, string> = {
  [ItemKind.Login]: "login",
  [ItemKind.Card]: "card",
  [ItemKind.SecureNote]: "note",
  [ItemKind.Identity]: "identity",
  [ItemKind.SshKey]: "key",
};
const SECTION: Record<ItemKind, Key> = {
  [ItemKind.Login]: "doc.signIn",
  [ItemKind.Card]: "kind.card",
  [ItemKind.SecureNote]: "doc.contents",
  [ItemKind.Identity]: "kind.identity",
  [ItemKind.SshKey]: "doc.key",
};
/// The dots a stored secret shows, by the key the page uses for it.
const DOTS_KEY: Record<string, string> = {
  number: "cardNumber",
  code: "cardCode",
  password: "password",
};

/// Where a form's secret fields hand it their handles.
type Slots = { register: (id: string, h: SecretInputHandle | null) => void };
const SlotsContext = createContext<Slots | null>(null);
function useSlots(): Slots {
  const s = useContext(SlotsContext);
  if (!s) throw new Error("a secret field was drawn outside a form");
  return s;
}

function useApi(): WritesApi {
  const w = useWrites();
  if (!w) throw new Error("a form was drawn where the app gives no writes");
  return w;
}

// ---------- the documents ----------

/// An opened item, edited in its own document.
export function EditDocument({
  nodeId,
  detail,
}: {
  nodeId: string;
  detail: ItemDetail;
}) {
  const { dir } = useCore();
  const w = useApi();
  const key = `edit:${detail.item.id}`;
  const form = w.form(key);
  useLayoutEffect(() => {
    if (!w.form(key)) w.setForm(key, formFromDetail(detail));
  }, [w, key, detail]);
  if (!form) return null;
  const n = dir.node(nodeId);
  return (
    <FormSheet
      formKey={key}
      form={form}
      lead={nodeLead(dir, nodeId, true)}
      what={
        <>
          <Place ids={n.home.slice(0, -1)} what={{ key: "edit.editing" }} />
          {n.why && (
            <div className="state">
              <Mark level={n.level} words={n.why} />
            </div>
          )}
        </>
      }
      owner={{ orgId: detail.item.orgId }}
      itemId={detail.item.id}
      fresh={false}
    />
  );
}

/// A new item, made in the place the line stands in.
export function NewDocument({
  at,
  verb,
  arg,
}: {
  at: string | null;
  verb: string;
  arg: string;
}) {
  const { dir, store } = useCore();
  const w = useApi();
  const kind = kindOfVerb(verb);
  if (!kind) throw new Error(`"${verb}" makes no item`);
  const key = `new:${at ?? "root"}`;
  const form = w.form(key);
  useLayoutEffect(() => {
    const f = w.form(key);
    if (!f) w.setForm(key, formForNew(kind, placementOf(dir, at), arg.trim()));
    // The line names the kind: a kind typed into it is the form's.
    else if (f.kind !== kind) w.setForm(key, switchKind(f, kind));
  }, [w, key, kind, dir, at, arg]);
  if (!form) return null;
  const choose = (k: ItemKind) => {
    w.setForm(key, switchKind(form, k));
    const s = store.get().state;
    store.commitState(
      { ...s, verb: KINDS.find((x) => x.kind === k)!.verb, arg: "" },
      { replace: true },
    );
  };
  const opt = placeOptions(dir).find((o) => o.value === placeValue(form.place));
  const lead: Lead =
    (form.kind === ItemKind.Login || form.kind === ItemKind.Identity) && form.name.trim()
      ? { tile: LeadTile.Letter, of: form.name, hue: hueOf(form.name) }
      : {
          tile: LeadTile.Icon,
          icon: KIND_ICON[form.kind],
          hue:
            form.kind === ItemKind.SshKey
              ? Hue.Cyan
              : form.kind === ItemKind.SecureNote
                ? Hue.Mint
                : Hue.Sky,
        };
  return (
    <FormSheet
      formKey={key}
      form={form}
      lead={lead}
      what={
        <div className="place">
          <span>{t(`edit.new.${form.kind}` as Key)}</span>
          <span className="sl">·</span>
          <span>{opt ? say(opt.label) : t("personal")}</span>
        </div>
      }
      kinds={choose}
      fresh
    />
  );
}

// ---------- the sheet ----------

function FormSheet({
  formKey,
  form,
  lead,
  what,
  owner,
  kinds,
  fresh,
  itemId,
}: {
  formKey: string;
  form: Form;
  lead: Lead;
  what: ReactNode;
  owner?: { orgId: string | null };
  kinds?: (k: ItemKind) => void;
  fresh: boolean;
  /// The item being changed; absent for a new one.
  itemId?: string;
}) {
  const { dir } = useCore();
  const w = useApi();
  const root = useRef<HTMLDivElement>(null);
  const title = useRef<HTMLInputElement>(null);
  const [gen, setGen] = useState<string | null>(null);
  const busy = w.saving === formKey;
  const wrong = problems(form);
  const set = useCallback(
    (f: Partial<Form>) => w.setForm(formKey, { ...form, ...f }),
    [w, formKey, form],
  );
  // The secret fields, by slot: their values are read only here, at the
  // moment of saving, and the fields are emptied as they are read.
  const handles = useRef(new Map<string, SecretInputHandle>());
  const slots = useMemo<Slots>(
    () => ({
      register: (id, h) => {
        if (h) handles.current.set(id, h);
        else handles.current.delete(id);
      },
    }),
    [],
  );
  // What a refused save took, kept while this form lives and put back into
  // the fields each time they are drawn (edit/refill.ts).
  const refill = useRef(new FieldRefill());
  const save = useCallback(() => {
    if (problems(form).length || w.saving) return;
    refill.current.drop();
    const typed = new Map<string, string>();
    for (const id of typedSlots(form)) {
      const h = handles.current.get(id);
      if (!h) throw new Error(`the secret field "${id}" is not drawn`);
      typed.set(id, h.take());
    }
    void w.save(formKey, typed);
  }, [w, formKey, form]);
  // What a refused save took from the fields goes back into them: when the
  // form is drawn again (a refused edit), and when a refusal comes back to a
  // form that stayed drawn (a refused new item).
  const turn = w.refillTurn(formKey);
  useLayoutEffect(() => {
    refill.current.apply(w.refill(formKey), (id) => handles.current.get(id));
    // `turn` is what moves it; `w` is a new object on every change.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [formKey, turn]);
  const cancel = useCallback(() => w.cancel(formKey), [w, formKey]);

  useEffect(() => {
    title.current?.focus();
  }, []);
  // ⌘S and Esc reach the form wherever the focus is not in the line.
  useEffect(() => {
    const onKey = (e: globalThis.KeyboardEvent) => {
      if (e.target !== document.body) return;
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "s") {
        e.preventDefault();
        save();
      } else if (e.key === "Escape") {
        if (gen) setGen(null);
        else cancel();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [save, cancel, gen]);
  // Inside the form the keys are the form's: the columns do not walk, the
  // line does not open. ⌘K and the history keys still reach the window.
  const onKeyDown = (e: KeyboardEvent) => {
    const meta = e.metaKey || e.ctrlKey;
    if (meta && e.key.toLowerCase() === "s") {
      e.preventDefault();
      e.stopPropagation();
      save();
      return;
    }
    if (e.key === "Escape") {
      e.preventDefault();
      e.stopPropagation();
      if (gen) setGen(null);
      else cancel();
      return;
    }
    if (!meta) e.stopPropagation();
  };

  const places = placeOptions(dir, owner);
  const fields = KIND_FIELDS[form.kind];
  return (
    <SlotsContext.Provider value={slots}>
      <div className="form" ref={root} onKeyDown={onKeyDown}>
        <fieldset disabled={busy}>
          <header className="hero">
            <Tile lead={lead} xl />
            <div className="hero-t">
              <input
                ref={title}
                className="in in-title"
                value={form.name}
                placeholder={t("edit.namePlaceholder")}
                aria-label={t("edit.name")}
                spellCheck={false}
                autoComplete="off"
                onChange={(e) => set({ name: e.target.value })}
              />
              {what}
              {kinds && (
                <div
                  className="kinds"
                  role="radiogroup"
                  aria-label={t("edit.kind")}
                >
                  {KINDS.map((k) => (
                    <IconButton
                      key={k.kind}
                      icon={k.icon}
                      tip={t(k.label)}
                      className={form.kind === k.kind ? "on" : undefined}
                      onClick={() => kinds(k.kind)}
                    />
                  ))}
                </div>
              )}
              <div className="acts">
                <button
                  type="button"
                  className="btn solid"
                  disabled={busy || wrong.length > 0}
                  aria-busy={busy || undefined}
                  onClick={save}
                >
                  <BtnIcon icon="check" phase={busy ? Phase.Busy : Phase.Idle} />
                  {t(
                    busy ? "edit.saving" : fresh ? "edit.create" : "edit.save",
                  )}
                  <Kbd>⌘S</Kbd>
                </button>
                <button
                  type="button"
                  className="btn quiet"
                  onClick={cancel}
                >
                  {t("ui.cancel")}
                  <Kbd>Esc</Kbd>
                </button>
                {wrong[0] && <span className="why">{t(wrong[0])}</span>}
              </div>
            </div>
          </header>

          <section className="sec">
            <div className="sec-h">
              <h2 className="h2">{t(SECTION[form.kind])}</h2>
            </div>
            {fields.map((f) => (
              <FieldRow
                key={f.key}
                spec={f}
                form={form}
                set={set}
                gen={gen}
                setGen={setGen}
              />
            ))}
            {form.ssh && (
              <SshKeyBlock
                ssh={form.ssh}
                fresh={fresh}
                {...(itemId ? { itemId } : {})}
                onKey={(d) => set({ ssh: { publicKey: d.publicKey, fingerprint: d.fingerprint, draft: d.id } })}
              />
            )}
            {form.kind === ItemKind.SecureNote && (
              <SecretRow
                slotId="notes"
                label={t("field.notes")}
                slot={form.notes}
                onSlot={(notes) => set({ notes })}
                multiline
                dots={dotsFor("notes")}
              />
            )}
            {form.custom.map((c, i) =>
              c.hidden ? (
                <SecretRow
                  key={`c${i}`}
                  slotId={`custom:${i}`}
                  label={c.name}
                  slot={c.secret}
                  onSlot={(secret) =>
                    set({
                      custom: form.custom.map((x, j) =>
                        j === i ? { ...x, secret } : x,
                      ),
                    })
                  }
                />
              ) : (
                <Row key={`c${i}`} label={c.name}>
                  <input
                    className={`in${c.mono ? " mono" : ""}`}
                    value={c.value}
                    spellCheck={false}
                    autoComplete="off"
                    aria-label={c.name}
                    onChange={(e) =>
                      set({
                        custom: form.custom.map((x, j) =>
                          j === i ? { ...x, value: e.target.value } : x,
                        ),
                      })
                    }
                  />
                </Row>
              ),
            )}
            {form.kind === ItemKind.Login &&
              form.uris.map((u, i) => (
                <Row key={`u${i}`} label={t("field.site")}>
                  <input
                    className="in mono"
                    value={u}
                    placeholder="https://"
                    spellCheck={false}
                    autoComplete="off"
                    aria-label={t("field.site")}
                    onChange={(e) =>
                      set({
                        uris: form.uris.map((x, j) =>
                          j === i ? e.target.value : x,
                        ),
                      })
                    }
                  />
                  {form.uris.length > 1 && (
                    <span className="fa">
                      <IconButton
                        icon="close"
                        tip={t("edit.removeSite")}
                        className="tip-l"
                        onClick={() =>
                          set({ uris: form.uris.filter((_, j) => j !== i) })
                        }
                      />
                    </span>
                  )}
                </Row>
              ))}
            {form.kind === ItemKind.Login && (
              <Row label="">
                <span>
                  <button
                    type="button"
                    className="btn add"
                    onClick={() => set({ uris: [...form.uris, ""] })}
                  >
                    <Icon name="plus" />
                    {t("edit.addSite")}
                  </button>
                </span>
              </Row>
            )}
          </section>

          {form.kind !== ItemKind.SecureNote && (
            <section className="sec">
              <div className="sec-h">
                <h2 className="h2">{t("edit.notes")}</h2>
              </div>
              {form.notes.stored || form.notes.input ? (
                <SecretRow
                  slotId="notes"
                  label={t("field.notes")}
                  slot={form.notes}
                  onSlot={(notes) => set({ notes })}
                  multiline
                  dots={dotsFor("notes")}
                />
              ) : (
                <Row label="">
                  <span>
                    <button
                      type="button"
                      className="btn add"
                      onClick={() =>
                        set({ notes: { stored: false, input: { set: "" } } })
                      }
                    >
                      <Icon name="plus" />
                      {t("edit.addNote")}
                    </button>
                  </span>
                </Row>
              )}
            </section>
          )}

          <section className="sec">
            <div className="sec-h">
              <h2 className="h2">{t("edit.where")}</h2>
            </div>
            <Row label={t("edit.place")}>
              <span className="sel">
                <select
                  className="in"
                  value={placeValue(form.place)}
                  aria-label={t("edit.place")}
                  onChange={(e) => {
                    const o = places.find((x) => x.value === e.target.value);
                    if (!o) throw new Error(`no place "${e.target.value}"`);
                    set({ place: o.place });
                  }}
                >
                  {!places.some((o) => o.value === placeValue(form.place)) && (
                    <option value={placeValue(form.place)}>
                      {t("edit.placeHere")}
                    </option>
                  )}
                  {places.map((o) => (
                    <option key={o.value} value={o.value}>
                      {say(o.label)}
                    </option>
                  ))}
                </select>
                <Icon name="chev" className="sel-ic" />
              </span>
            </Row>
            <Row label={t("edit.favorite")}>
              <Switch
                on={form.favorite}
                label={t("edit.favorite")}
                onChange={(favorite) => set({ favorite })}
              />
            </Row>
            <Row label={t("edit.reprompt")}>
              <span className="inline">
                <Switch
                  on={form.reprompt}
                  label={t("edit.reprompt")}
                  onChange={(reprompt) => set({ reprompt })}
                />
                <span className="faint">{t("edit.repromptHint")}</span>
              </span>
            </Row>
          </section>
        </fieldset>
      </div>
    </SlotsContext.Provider>
  );
}

// ---------- rows ----------

function Row({
  label,
  children,
  top,
}: {
  label: string;
  children: ReactNode;
  top?: boolean;
}) {
  return (
    <div className={`f fe${top ? " top" : ""}`}>
      <span className="k">{label}</span>
      {children}
    </div>
  );
}

function FieldRow({
  spec,
  form,
  set,
  gen,
  setGen,
}: {
  spec: FieldSpec;
  form: Form;
  set: (f: Partial<Form>) => void;
  gen: string | null;
  setGen: (k: string | null) => void;
}) {
  const label = t(spec.label);
  const value = (k: string) => form.values[k] ?? "";
  const put = (k: string, v: string) =>
    set({ values: { ...form.values, [k]: v } });
  if (spec.parts) {
    const [a, b] = spec.parts;
    return (
      <Row label={label}>
        <span className="parts">
          <input
            className="in mono short"
            value={value(a)}
            placeholder={t("edit.mm")}
            inputMode="numeric"
            maxLength={2}
            aria-label={t("edit.expMonth")}
            onChange={(e) => put(a, e.target.value.replace(/\D/g, ""))}
          />
          <span className="sl">/</span>
          <input
            className="in mono year"
            value={value(b)}
            placeholder={t("edit.yyyy")}
            inputMode="numeric"
            maxLength={4}
            aria-label={t("edit.expYear")}
            onChange={(e) => put(b, e.target.value.replace(/\D/g, ""))}
          />
        </span>
      </Row>
    );
  }
  if (spec.secret)
    return (
      <SecretRow
        slotId={spec.key}
        label={label}
        slot={form.secrets[spec.key] ?? { stored: false, input: null }}
        onSlot={(s) => set({ secrets: { ...form.secrets, [spec.key]: s } })}
        multiline={!!spec.multiline}
        dots={dotsFor(DOTS_KEY[spec.key] ?? null)}
        {...(spec.placeholder ? { placeholder: t(spec.placeholder) } : {})}
        {...(spec.generate
          ? {
              generator: {
                open: gen === spec.key,
                toggle: () => setGen(gen === spec.key ? null : spec.key),
                close: () => setGen(null),
              },
            }
          : {})}
      />
    );
  if (spec.readOnly)
    return (
      <Row label={label}>
        <span className={`v${spec.mono ? " mono" : ""}`}>
          {value(spec.key) || (
            <span className="faint">{t("edit.derived")}</span>
          )}
        </span>
      </Row>
    );
  return (
    <Row label={label}>
      <input
        className={`in${spec.mono ? " mono" : ""}`}
        value={value(spec.key)}
        spellCheck={false}
        autoComplete="off"
        aria-label={label}
        onChange={(e) => put(spec.key, e.target.value)}
      />
    </Row>
  );
}

/// A secret's row. Stored and untouched: dots and "Replace". Replaced or
/// new: an input whose value is masked unless it is shown. Cleared: a word
/// that it goes, and the way back.
function SecretRow({
  slotId,
  label,
  slot,
  onSlot,
  multiline,
  dots = dotsFor(null),
  placeholder,
  generator,
}: {
  slotId: string;
  label: string;
  slot: SecretSlot;
  onSlot: (s: SecretSlot) => void;
  multiline?: boolean;
  dots?: string;
  placeholder?: string;
  generator?: { open: boolean; toggle: () => void; close: () => void };
}) {
  const w = useApi();
  const { report } = useCore();
  const [shown, setShown] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const hide = useCallback(() => {
    if (timer.current) clearTimeout(timer.current);
    timer.current = null;
    setShown(false);
  }, []);
  const show = useCallback(() => {
    if (timer.current) clearTimeout(timer.current);
    setShown(true);
    timer.current = setTimeout(hide, REVEAL_MS);
  }, [hide]);
  // A value shown goes back to dots when the window is left, as a revealed
  // one does.
  useEffect(() => {
    const onBlur = () => hide();
    window.addEventListener("blur", onBlur);
    return () => {
      window.removeEventListener("blur", onBlur);
      if (timer.current) clearTimeout(timer.current);
    };
  }, [hide]);

  const slots = useSlots();
  const handle = useRef<SecretInputHandle | null>(null);
  const [filled, setFilled] = useState(false);
  const i = slot.input;
  const marked = !!i && "set" in i;
  const cleared = !!i && "clear" in i;
  const typing = marked || (!slot.stored && !cleared);
  const bind = useCallback(
    (h: SecretInputHandle | null) => {
      handle.current = h;
      slots.register(slotId, h);
    },
    [slots, slotId],
  );
  // The form learns only that a field is being typed into, never what.
  const onFilled = (f: boolean) => {
    setFilled(f);
    if (f && !marked) onSlot({ stored: slot.stored, input: { set: "" } });
  };

  // A generated value goes straight into the field and is let go at once:
  // it lives in the field's own value until the save takes it.
  const generate = async (opts: GeneratorOptions) => {
    const g = await w.writes.generate(opts);
    try {
      if (!handle.current)
        throw new Error("a generated value has no field to go to");
      handle.current.set(g.value);
    } finally {
      g.drop();
    }
    if (!marked) onSlot({ stored: slot.stored, input: { set: "" } });
    show();
  };
  // The dice turns while a value is made; the value fades into the field
  // (each new one again: the turn's parity names the animation anew).
  const [making, setMaking] = useState(false);
  const [madeTurn, setMadeTurn] = useState(0);
  const run = (opts: GeneratorOptions) => {
    if (making) return;
    setMaking(true);
    generate(opts)
      .then(() => setMadeTurn((n) => n + 1))
      .catch(report)
      .finally(() => setMaking(false));
  };
  const optsOf = (p: GenPrefs): GeneratorOptions =>
    p.kind === GeneratorKind.Password ? p.password : p.passphrase;

  let control: ReactNode;
  if (cleared)
    control = <span className="v faint">{t("edit.willClear")}</span>;
  else if (!typing)
    control = (
      <span className="v">
        <span className="dots">{dots}</span>
      </span>
    );
  else
    control = (
      <SecretInput
        ref={bind}
        className={`in mono${shown ? "" : " masked"}`}
        shown={shown}
        multiline={!!multiline}
        rows={4}
        onFilled={onFilled}
        autoFocus={marked}
        aria-label={label}
        placeholder={placeholder ?? (slot.stored ? t("edit.newValue") : "")}
      />
    );
  return (
    <div
      className={`f fe${multiline && typing && !cleared ? " top" : ""}`}
      {...(madeTurn ? { "data-made": madeTurn % 2 ? "odd" : "even" } : {})}
    >
      <span className="k">{label}</span>
      {control}
      <span className="fa">
        {typing && !cleared && (
          <IconButton
            icon="eye"
            tip={shown ? t("ui.hide") : t("ui.reveal")}
            onClick={shown ? hide : show}
            disabled={!filled}
          />
        )}
        {generator && (
          <>
            <IconButton
              icon="dice"
              phase={making ? Phase.Busy : Phase.Idle}
              tip={t("edit.generate")}
              onClick={() => run(optsOf(w.gen))}
            />
            <span className="gen-at">
              <IconButton
                icon="tune"
                tip={t("edit.genOptions")}
                className={`tip-l${generator.open ? " on" : ""}`}
                onClick={generator.toggle}
              />
              {generator.open && (
                <GenPop
                  prefs={w.gen}
                  setPrefs={w.setGen}
                  onGenerate={(p) => run(optsOf(p))}
                  busy={making}
                  onClose={generator.close}
                />
              )}
            </span>
          </>
        )}
        {slot.stored && !typing && (
          <>
            <button
              type="button"
              className="btn replace"
              onClick={() => onSlot({ stored: true, input: { set: "" } })}
            >
              {t("edit.replace")}
            </button>
            <IconButton
              icon="close"
              tip={t("edit.clear")}
              className="tip-l"
              onClick={() => onSlot({ stored: true, input: { clear: true } })}
            />
          </>
        )}
        {slot.stored && (typing || cleared) && (
          <IconButton
            icon="undo"
            tip={t("edit.keepStored")}
            className="tip-l"
            onClick={() => {
              hide();
              onSlot({ stored: true, input: null });
            }}
          />
        )}
      </span>
    </div>
  );
}

function Switch({
  on,
  label,
  onChange,
}: {
  on: boolean;
  label: string;
  onChange: (v: boolean) => void;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={on}
      aria-label={label}
      className={`switch${on ? " on" : ""}`}
      onClick={() => onChange(!on)}
    />
  );
}

// ---------- the generator's options ----------

function GenPop({
  prefs,
  setPrefs,
  onGenerate,
  busy,
  onClose,
}: {
  prefs: GenPrefs;
  setPrefs: (p: GenPrefs) => void;
  onGenerate: (p: GenPrefs) => void;
  busy: boolean;
  onClose: () => void;
}) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const onDown = (e: PointerEvent) => {
      const at = ref.current?.parentElement;
      if (at && !at.contains(e.target as Node)) onClose();
    };
    document.addEventListener("pointerdown", onDown);
    return () => document.removeEventListener("pointerdown", onDown);
  }, [onClose]);
  const change = (p: GenPrefs) => {
    setPrefs(p);
    onGenerate(p);
  };
  const pw = prefs.password;
  const pp = prefs.passphrase;
  const sets = (["upper", "lower", "digits", "symbols"] as const).filter(
    (k) => pw[k],
  );
  const SETS: [
    keyof typeof pw & ("upper" | "lower" | "digits" | "symbols"),
    string,
    Key,
  ][] = [
    ["upper", "A–Z", "edit.gen.upper"],
    ["lower", "a–z", "edit.gen.lower"],
    ["digits", "0–9", "edit.gen.digits"],
    ["symbols", "!@#", "edit.gen.symbols"],
  ];
  return (
    <div
      className="gen"
      ref={ref}
      role="dialog"
      aria-label={t("edit.genOptions")}
    >
      <div className="seg2" role="radiogroup">
        {[GeneratorKind.Password, GeneratorKind.Passphrase].map((k) => (
          <button
            key={k}
            type="button"
            role="radio"
            aria-checked={prefs.kind === k}
            className={prefs.kind === k ? "on" : undefined}
            onClick={() => change({ ...prefs, kind: k })}
          >
            {t(k === GeneratorKind.Password ? "edit.gen.password" : "edit.gen.passphrase")}
          </button>
        ))}
      </div>
      {prefs.kind === GeneratorKind.Password ? (
        <>
          <div className="gen-row">
            <span className="k">{t("edit.gen.length")}</span>
            <input
              type="range"
              className="range"
              min={8}
              max={64}
              value={pw.length}
              aria-label={t("edit.gen.length")}
              onChange={(e) =>
                change({
                  ...prefs,
                  password: { ...pw, length: Number(e.target.value) },
                })
              }
            />
            <span className="gen-n">{pw.length}</span>
          </div>
          <div className="gen-row">
            <span className="k">{t("edit.gen.sets")}</span>
            <span className="chips">
              {SETS.map(([k, label, tip]) => (
                <button
                  key={k}
                  type="button"
                  className={`chip${pw[k] ? " on" : ""}`}
                  aria-pressed={pw[k]}
                  aria-label={t(tip)}
                  title={t(tip)}
                  // The last set left stays: a password is made of something.
                  disabled={pw[k] && sets.length === 1}
                  onClick={() =>
                    change({ ...prefs, password: { ...pw, [k]: !pw[k] } })
                  }
                >
                  {label}
                </button>
              ))}
            </span>
          </div>
          <div className="gen-row">
            <span className="k">{t("edit.gen.similar")}</span>
            <span className="gen-pair">
              <Switch
                on={pw.avoidAmbiguous}
                label={t("edit.gen.avoid")}
                onChange={(v) =>
                  change({ ...prefs, password: { ...pw, avoidAmbiguous: v } })
                }
              />
              <span className="faint">{t("edit.gen.avoidHint")}</span>
            </span>
          </div>
        </>
      ) : (
        <>
          <div className="gen-row">
            <span className="k">{t("edit.gen.words")}</span>
            <input
              type="range"
              className="range"
              min={3}
              max={10}
              value={pp.words}
              aria-label={t("edit.gen.words")}
              onChange={(e) =>
                change({
                  ...prefs,
                  passphrase: { ...pp, words: Number(e.target.value) },
                })
              }
            />
            <span className="gen-n">{pp.words}</span>
          </div>
          <div className="gen-row">
            <span className="k">{t("edit.gen.separator")}</span>
            <input
              className="in mono short"
              value={pp.separator}
              maxLength={1}
              aria-label={t("edit.gen.separator")}
              onChange={(e) =>
                change({
                  ...prefs,
                  passphrase: { ...pp, separator: e.target.value },
                })
              }
            />
            <span />
          </div>
          <div className="gen-row">
            <span className="k">{t("edit.gen.form")}</span>
            <span className="chips">
              <button
                type="button"
                className={`chip sans${pp.capitalize ? " on" : ""}`}
                aria-pressed={pp.capitalize}
                onClick={() =>
                  change({
                    ...prefs,
                    passphrase: { ...pp, capitalize: !pp.capitalize },
                  })
                }
              >
                {t("edit.gen.capitalize")}
              </button>
              <button
                type="button"
                className={`chip sans${pp.number ? " on" : ""}`}
                aria-pressed={pp.number}
                onClick={() =>
                  change({
                    ...prefs,
                    passphrase: { ...pp, number: !pp.number },
                  })
                }
              >
                {t("edit.gen.number")}
              </button>
            </span>
          </div>
        </>
      )}
      <div className="gen-foot">
        <button
          type="button"
          className="btn quiet"
          onClick={() => onGenerate(prefs)}
          disabled={busy}
          aria-busy={busy || undefined}
        >
          <BtnIcon icon="dice" phase={busy ? Phase.Busy : Phase.Idle} />
          {t("edit.gen.again")}
        </button>
      </div>
    </div>
  );
}
