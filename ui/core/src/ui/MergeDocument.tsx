// `> merge`: the copies of one record made one. A person picks the record
// to keep — its name and its own fields stand — and for every value another
// record holds that the kept one does not: add it, put it in place of the
// kept one's, keep both under a new name, or let it go with its copy. The
// comparison is asked for where the keys are; no value is ever shown here
// but a login, which the catalogue already shows.
import { useEffect, useMemo, useRef, useState } from "react";
import { isKey, t, text, type Text } from "../i18n";
import { MergeChoice, RowState, choose, draftMerge, mergeGroup, mergeProblem, planOf, rename, slotLabel, type MergeDraft, type MergeLine, type MergeOffer } from "../edit/merge";
import { placeOf } from "../model/reasons";
import { Level } from "../model/types";
import { MergeField, type MergeComparison } from "../writes";
import { Phase } from "./feedback";
import { Icon } from "./Icons";
import { DocSkeleton } from "./Loading";
import { BtnIcon, Kbd, Mark, Tile, nodeLead, useCore } from "./marks";
import { ToastKind } from "./toasts";
import { useWrites } from "./writes-context";
import "./sheet.css";
import "./merge.css";

const say = (x: Text) => text(x);

enum LoadPhase {
  Loading = "loading",
  Shown = "shown",
  Failed = "failed",
}
type Loaded = { phase: LoadPhase.Loading } | { phase: LoadPhase.Shown; cmp: MergeComparison; draft: MergeDraft } | { phase: LoadPhase.Failed; error: unknown };

/// A refusal in the person's words.
function refusal(e: unknown): string {
  const m = (e instanceof Error ? e.message : String(e)).trim();
  return m.startsWith("err.") && isKey(m) ? t(m) : m;
}

export function MergeDocument({ itemId }: { itemId: string }) {
  const core = useCore();
  const { dir, store, toast } = core;
  const writes = useWrites()!;
  const item = dir.catalog.items.find((i) => i.id === itemId);
  if (!item) throw new Error(`no item "${itemId}" to merge`);
  const group = useMemo(() => mergeGroup(item, dir.catalog), [item, dir.catalog]);
  const ids = group.map((i) => i.id).join(" ");
  const nameOf = (id: string) => group.find((i) => i.id === id)?.name ?? id;
  const label = (s: Parameters<typeof slotLabel>[0]) => say(slotLabel(s));

  const [loaded, setLoaded] = useState<Loaded>({ phase: LoadPhase.Loading });
  const [running, setRunning] = useState(false);
  const [failed, setFailed] = useState<string | null>(null);
  useEffect(() => {
    if (group.length < 2) return;
    let live = true;
    setLoaded({ phase: LoadPhase.Loading });
    writes.writes.compareForMerge(group.map((i) => i.id)).then(
      (cmp) => live && setLoaded({ phase: LoadPhase.Shown, cmp, draft: draftMerge(cmp, itemId, group, label) }),
      (error: unknown) => live && setLoaded({ phase: LoadPhase.Failed, error }),
    );
    return () => {
      live = false;
    };
    // The comparison is asked for again only when the records change.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [writes, ids]);

  // ↵ merges, as it runs any verb, unless a name is being typed.
  const runRef = useRef<() => void>(() => {});
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const a = document.activeElement;
      if (e.key !== "Enter" || e.metaKey || e.ctrlKey || a instanceof HTMLInputElement || a instanceof HTMLTextAreaElement) return;
      runRef.current();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);

  const close = () => store.verb(null);
  const head = (
    <>
      <div className="kw-vlead">
        <Icon name="merge" />
        <span>{t("merge.lead")}</span>
      </div>
      <h1 className="kw-h1">{t("merge.title", { n: group.length })}</h1>
      <p className="kw-lede">{t("merge.lede")}</p>
    </>
  );
  if (group.length < 2)
    return (
      <>
        {head}
        <Mark level={Level.Healthy} words={t("merge.noCopies")} />
      </>
    );
  if (loaded.phase === LoadPhase.Loading)
    return (
      <>
        {head}
        <DocSkeleton rows={4} />
      </>
    );
  if (loaded.phase === LoadPhase.Failed)
    return (
      <>
        {head}
        <span className="kw-why kw-refused" role="alert">
          <Mark level={Level.Critical} words={t("ui.failed", { reason: refusal(loaded.error) })} />
        </span>
      </>
    );

  const { cmp, draft } = loaded;
  const set = (d: MergeDraft) => setLoaded({ phase: LoadPhase.Shown, cmp, draft: d });
  const problem = mergeProblem(draft, cmp);
  const run = () => {
    if (problem || running) return;
    setRunning(true);
    setFailed(null);
    const keeper = draft.keeper;
    writes.writes.merge(planOf(draft)).then(
      () => {
        toast(ToastKind.Ok, t("merge.done", { name: nameOf(keeper), n: draft.others.length }));
        const at = `item:${keeper}`;
        store.commitState({ segs: (dir.has(at) ? dir.node(at).home : []).map((id) => ({ id })), map: null, verb: null, arg: "" });
      },
      (e: unknown) => {
        setRunning(false);
        setFailed(refusal(e));
      },
    );
  };
  runRef.current = run;
  const lines = draft.lines;
  const same = lines.filter((l) => l.state === RowState.Same);
  const open = lines.filter((l) => l.state !== RowState.Same);

  return (
    <div className="kw-merge">
      {head}
      <section className="kw-sec">
        <div className="kw-sec-h">
          <h2 className="kw-h2">{t("merge.keep")}</h2>
        </div>
        <div className="kw-merge-keep" role="radiogroup" aria-label={t("merge.keep")}>
          {group.map((i) => {
            const on = i.id === draft.keeper;
            return (
              <button
                key={i.id}
                type="button"
                role="radio"
                aria-checked={on}
                className={`kw-merge-rec${on ? " kw-on" : ""}`}
                onClick={() => !on && set(draftMerge(cmp, i.id, group, label))}
              >
                <Tile lead={nodeLead(dir, `item:${i.id}`)} />
                <span className="kw-merge-rec-tx">
                  <b>{i.name}</b>
                  <span>{say(placeOf(i, dir.catalog))}</span>
                </span>
                <span className="kw-merge-rec-mk" data-tip={t(on ? "merge.kept" : "merge.toTrash")} aria-label={t(on ? "merge.kept" : "merge.toTrash")}>
                  <Icon name={on ? "check" : "trash"} />
                </span>
              </button>
            );
          })}
        </div>
      </section>

      {open.length > 0 && (
        <section className="kw-sec kw-form">
          <div className="kw-sec-h">
            <h2 className="kw-h2">{t("merge.differs")}</h2>
            <span className="kw-n">{open.length}</span>
          </div>
          {open.map((l) => (
            <Line key={l.key} line={l} keeper={draft.keeper} nameOf={nameOf} label={label(l.slot)} group={group} onChoose={(o, c) => set(choose(draft, l.key, o.group, c))} onRename={(o, n) => set(rename(draft, l.key, o.group, n))} />
          ))}
        </section>
      )}

      {same.length > 0 && (
        <section className="kw-sec">
          <div className="kw-sec-h">
            <h2 className="kw-h2">{t("merge.same")}</h2>
            <span className="kw-n">{same.length}</span>
          </div>
          <div className="kw-merge-same">
            {same.map((l) => (
              <span key={l.key} className="kw-merge-chip">
                <Icon name="check" />
                {label(l.slot)}
              </span>
            ))}
          </div>
        </section>
      )}

      <div className="kw-vbar">
        <button type="button" className="kw-btn kw-solid" disabled={running || !!problem} aria-busy={running || undefined} onClick={run} data-confirm="">
          <BtnIcon icon="merge" phase={running ? Phase.Busy : Phase.Idle} />
          {t("merge.go", { n: draft.others.length })}
        </button>
        <button type="button" className="kw-btn kw-quiet" onClick={close}>
          {t("ui.cancel")}
          <Kbd>Esc</Kbd>
        </button>
        {failed ? (
          <span className="kw-why kw-refused" role="alert">
            <Mark level={Level.Critical} words={t("ui.failed", { reason: failed })} />
          </span>
        ) : problem ? (
          <span className="kw-why kw-held">
            <Icon name="info" />
            {say(problem)}
          </span>
        ) : (
          <span className="kw-why">
            <Icon name="undo" />
            {t("merge.note")}
          </span>
        )}
      </div>
    </div>
  );
}

/// The choices an offer has, as icons with their words in tooltips.
function choicesOf(line: MergeLine): { choice: MergeChoice; icon: string; tip: string }[] {
  if (line.slot.field === MergeField.Passkeys)
    return [
      { choice: MergeChoice.Fill, icon: "plus", tip: t("merge.addPasskeys") },
      { choice: MergeChoice.Drop, icon: "trash", tip: t("merge.dropPasskeys") },
    ];
  const out = [
    { choice: MergeChoice.Drop, icon: line.keeperHolds ? "check" : "close", tip: t(line.keeperHolds ? "merge.keepMine" : "merge.skip") },
    { choice: MergeChoice.Fill, icon: line.keeperHolds ? "refresh" : "plus", tip: t(line.keeperHolds ? "merge.replace" : "merge.add") },
  ];
  // Beside the kept one's own, or beside another taken in its place.
  if (line.keeperHolds || line.offers.length > 1) out.push({ choice: MergeChoice.Beside, icon: "stack", tip: t("merge.both") });
  return out;
}

function Line({
  line,
  keeper,
  nameOf,
  label,
  group,
  onChoose,
  onRename,
}: {
  line: MergeLine;
  keeper: string;
  nameOf: (id: string) => string;
  label: string;
  group: { id: string; subtitle: string | null }[];
  onChoose: (o: MergeOffer, c: MergeChoice) => void;
  onRename: (o: MergeOffer, name: string) => void;
}) {
  // A login is no secret: the catalogue shows it already.
  const login = (id: string) => (line.slot.field === MergeField.Username ? (group.find((i) => i.id === id)?.subtitle ?? null) : null);
  const mine = login(keeper);
  return (
    <div className="kw-merge-line">
      <div className="kw-merge-field">
        <b>{label}</b>
        {line.secret && <Icon name="lock" />}
        <span className="kw-faint">
          {line.keeperHolds ? (mine ? <span className="kw-mono">{mine}</span> : t("merge.inKept")) : t("merge.notInKept")}
        </span>
      </div>
      {line.offers.map((o) => {
        const value = login(o.from);
        const from = o.holders.length > 1 ? t("merge.fromMany", { name: nameOf(o.from), n: o.holders.length - 1 }) : nameOf(o.from);
        return (
          <div key={o.group} className="kw-merge-offer">
            <div className="kw-frow">
              <span className="kw-fl">
                <Icon name="chev" />
                <span>
                  {from}
                  {value && <span className="kw-mono kw-faint"> · {value}</span>}
                </span>
              </span>
              <div className="kw-fseg kw-merge-seg" role="radiogroup" aria-label={t("merge.choiceFor", { field: label, name: nameOf(o.from) })}>
                {choicesOf(line).map((c) => (
                  <button key={c.choice} type="button" role="radio" aria-checked={o.choice === c.choice} aria-label={c.tip} data-tip={c.tip} className={o.choice === c.choice ? "kw-on" : undefined} onClick={() => o.choice !== c.choice && onChoose(o, c.choice)}>
                    <Icon name={c.icon} />
                  </button>
                ))}
              </div>
            </div>
            {o.choice === MergeChoice.Beside && (
              <div className="kw-frow">
                <span className="kw-fl">
                  <span>{t("merge.besideName")}</span>
                </span>
                <label className="kw-fin">
                  <input value={o.name} spellCheck={false} autoComplete="off" aria-label={t("merge.besideName")} onChange={(e) => onRename(o, e.target.value)} />
                </label>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
