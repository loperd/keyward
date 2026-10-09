// The top sheet: the answer takes the shape of the question — a verb is a
// preview, a map is a map, a flat filter is a calm list, one object is its
// document. An item's document waits for the opened item from the backend.
import type { Ref } from "react";
import type { SecretFormHandle } from "./SecretForm";
import { useEffect, useLayoutEffect, useRef, useState } from "react";
import type { ItemDetail } from "../model/types";
import { buildDoc } from "../doc/build";
import { type Answer, type Column, AnswerKind, ColumnType } from "../path/query";
import type { Effect } from "../verbs/spec";
import { CalmList } from "./CalmList";
import { DocSkeleton } from "./Loading";
import { DocumentView } from "./Document";
import { MapSheet } from "./MapSheet";
import { VerbPreview, type RunState } from "./VerbPreview";
import { useCore } from "./marks";
import { EditDocument, NewDocument } from "./Editor";
import { MergeDocument } from "./MergeDocument";
import { useWrites } from "./writes-context";
import { detailOf, kindOfVerb } from "../edit/draft";
import { ScreenSheet, useScreenView } from "./screen/Sheet";

/// The opened item, asked for when its page is shown and again when the
/// backend says it changed. While it is asked for again the page keeps what
/// it had of the same item (it holds no secret value), so a sync does not
/// blank the fields; another item is never shown for this one.
function useDetail(itemId: string | null, version: number): ItemDetail | null {
  const { backend, report } = useCore();
  const [d, setD] = useState<ItemDetail | null>(null);
  useEffect(() => {
    if (!itemId) {
      setD(null);
      return;
    }
    let live = true;
    backend.item(itemId).then((x) => live && setD(x), report);
    return () => {
      live = false;
    };
  }, [backend, itemId, version, report]);
  return d && itemId && d.item.id === itemId ? d : null;
}

export function Inspector({
  answer,
  run,
  onRun,
  lsel,
  mapHover,
  onMapHover,
  version,
  secretForm,
}: {
  answer: Answer;
  run: RunState;
  onRun: (e: Effect) => void;
  /// Where a preview's secret fields are read at ↵.
  secretForm: Ref<SecretFormHandle>;
  lsel: number;
  mapHover: string | null;
  onMapHover: (id: string | null) => void;
  version: number;
}) {
  const core = useCore();
  const { dir, store, places, server, query } = core;
  const writes = useWrites();
  const st = store.get().state;
  const docId = answer.kind === AnswerKind.Document ? (answer.id ?? "root") : null;
  const itemId = docId && dir.has(docId) ? (dir.node(docId).item?.id ?? null) : null;
  const detail = useDetail(itemId, version);
  // A place's declared screen, where one is open, stands in its page's stead.
  const view = useScreenView(core.screens, docId);
  const screen = answer.kind === AnswerKind.Document && docId && view && view.route !== null ? { node: docId, view: { ...view, route: view.route } } : null;
  const ref = useRef<HTMLElement>(null);
  // A verb that makes an item opens the new item's document, not a preview;
  // its kind can change without the sheet being drawn anew.
  const obj = store.object();
  const making =
    writes && answer.kind === AnswerKind.Verb && kindOfVerb(st.verb) !== undefined && query.verbs.find((v) => v.id === st.verb)?.applies(obj ? dir.node(obj) : null) === true;
  const editing = !!writes && !!itemId && writes.editing === itemId;
  // `> merge` is a document of its own too: its choices do not fit a line.
  const merging =
    !!writes && !making && answer.kind === AnswerKind.Verb && st.verb === "merge" && !!obj && query.verbs.find((v) => v.id === "merge")?.applies(dir.node(obj)) === true;
  const key = making
    ? `new:${obj}`
    : merging
      ? `merge:${obj}`
    : answer.kind === AnswerKind.Map
      ? `map:${st.map!.kind}:${st.map!.anchor}`
      : answer.kind === AnswerKind.Verb
        ? `verb:${st.verb}:${obj}`
        : answer.kind === AnswerKind.List
          ? `list:${columnKey(answer.column)}`
          : screen
            ? `screen:${docId}:${screen.view.route}`
            : // A form and its document cross-fade: an edit started, saved, or
              // taken back after a refusal is seen to turn.
              `${editing ? "edit" : "doc"}:${docId}`;
  // A new answer cross-fades with the old one: the sheet that was drawn stays
  // a moment over the new one, fading, where it stood, and the new one fades
  // in from the top.
  const doc = useRef<HTMLDivElement>(null);
  const last = useRef<HTMLDivElement | null>(null);
  const scrolled = useRef(0);
  useLayoutEffect(() => {
    const sheet = ref.current;
    const old = last.current;
    last.current = doc.current;
    if (!sheet) return;
    if (old && old !== doc.current && !old.isConnected) fadeAway(sheet, old, scrolled.current);
    sheet.scrollTop = 0;
    scrolled.current = 0;
  }, [key]);

  let body: React.ReactNode;
  let cls = "doc enter";
  if (making) body = <NewDocument at={obj} verb={st.verb!} arg={st.arg} />;
  else if (merging) body = <MergeDocument itemId={dir.node(obj!).item!.id} />;
  else if (answer.kind === AnswerKind.Map) body = <MapSheet map={st.map!} hover={mapHover} onHover={onMapHover} />;
  else if (editing) body = detail ? <EditDocument nodeId={docId!} detail={detail} /> : <DocSkeleton rows={4} />;
  else if (answer.kind === AnswerKind.Verb) {
    cls += " act";
    body = <VerbPreview run={run} onRun={onRun} secretForm={secretForm} />;
  } else if (screen) {
    cls += " wide";
    body = <ScreenSheet node={screen.node} view={screen.view} />;
  } else if (answer.kind === AnswerKind.List) {

    cls += " flat";
    body = <CalmList column={answer.column as Extract<Column, { type: ColumnType.Results }>} lsel={lsel} />;
  } else {
    // A saved edit the backend has not answered yet reads as saved.
    const p = writes?.pending && itemId === writes.pending.itemId ? writes.pending : null;
    const shown = p && detail ? detailOf(p.draft, { ...detail.item, name: p.draft.name }, detail) : detail;
    const doc = buildDoc({ dir, detail: shown, server, places }, docId!);
    if (p) doc.hero = { ...doc.hero, title: { raw: p.draft.name } };
    if (doc.wide) cls += " wide";
    body = <DocumentView doc={doc} />;
  }
  return (
    <section
      className={`insp${answer.kind === AnswerKind.Map ? " mapmode" : ""}`}
      ref={ref}
      onScroll={(e) => {
        scrolled.current = e.currentTarget.scrollTop;
      }}
    >
      <div className={cls} key={key} ref={doc}>
        {body}
      </div>
    </section>
  );
}

/// What may hold a value shown for a moment: a fading sheet never carries
/// it on, it goes with the sheet the moment the sheet is let go.
const HELD = ".shown, .code, .fprint-words, input, textarea";

/// The sheet that was let go, put back over the new one to fade out where it
/// stood. It is the old sheet's own markup, emptied of every shown value and
/// out of reach of the pointer, the keyboard and a screen reader; it leaves
/// once its fade has played. A sheet still fading makes room for this one.
function fadeAway(sheet: HTMLElement, old: HTMLDivElement, top: number) {
  for (const g of sheet.querySelectorAll(":scope > .ghost")) g.remove();
  for (const n of old.querySelectorAll(HELD)) n.remove();
  old.classList.remove("enter");
  old.classList.add("ghost");
  old.setAttribute("aria-hidden", "true");
  old.inert = true;
  old.style.top = `${-top}px`;
  old.addEventListener("animationend", (e) => {
    if (e.target === old) old.remove();
  });
  sheet.appendChild(old);
}

const columnKey = (c: Column) => (c.type === ColumnType.Results ? `${c.scope}:${JSON.stringify(c.filter)}` : c.parent);
