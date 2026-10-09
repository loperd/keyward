// The one line: the path and the query. Clicks write it, typing builds it.
// Every committed piece reads as a crumb — an icon and a human name — and
// syntax lives only in the input and its suggestions. A long path folds in
// the middle into «…».
import { forwardRef, useCallback, useEffect, useImperativeHandle, useLayoutEffect, useRef, useState } from "react";
import { t, text } from "../i18n";
import { crumbs, columns, type Crumb, CrumbCut, ColumnType } from "../path/query";
import { currentPlace } from "../path/places";
import { firstChoice, lineWith, suggest, take, type Option } from "../path/suggest";
import { usePath } from "../path/store";
import { Icon } from "./Icons";
import { Glyph, Kbd, useCore } from "./marks";
import { tokenPx } from "./tokens";

export type LineHandle = { focus: (typed?: string) => void; blur: () => void };

/// What the line's pop-up shows: the suggestions, the saved places, or the
/// crumbs folded away.
enum PopMode {
  Q = "q",
  Places = "places",
  Hidden = "hidden",
}
type Pop = { mode: PopMode.Q } | { mode: PopMode.Places } | { mode: PopMode.Hidden; left: number };

function CrumbIcon({ c }: { c: Crumb }) {
  if (c.level) return <Glyph level={c.level} />;
  return <Icon name={c.icon} />;
}

export const PathLine = forwardRef<LineHandle, { onConfirm: () => boolean }>(function PathLine({ onConfirm }, handle) {
  const core = useCore();
  const { query, store, places, savePlace } = core;
  const snap = usePath(store);
  const st = snap.state;
  const input = useRef<HTMLInputElement>(null);
  const box = useRef<HTMLDivElement>(null);
  const crumbsEl = useRef<HTMLElement>(null);
  const [value, setValue] = useState("");
  const [typing, setTyping] = useState(false);
  const [pop, setPop] = useState<Pop | null>(null);
  const [sel, setSel] = useState<{ i: number; moved: boolean; for: string }>({ i: 0, moved: false, for: "" });

  const cs = crumbs(query, st);
  const csKey = cs.map((c) => c.key).join("|");
  // Long paths fold in the middle: the first crumb and the last ones stay.
  const [fold, setFold] = useState<{ key: string; k: number }>({ key: "", k: 0 });
  const k = fold.key === csKey ? fold.k : 0;
  useLayoutEffect(() => {
    const el = crumbsEl.current;
    if (!el) return;
    if (el.scrollWidth > el.clientWidth + 1 && k < cs.length - 2) setFold({ key: csKey, k: k + 1 });
    else if (fold.key !== csKey) setFold({ key: csKey, k });
  });
  useEffect(() => {
    // A new width folds the path again from nothing.
    const ro = new ResizeObserver(() => setFold({ key: "", k: 0 }));
    if (box.current) ro.observe(box.current);
    return () => ro.disconnect();
  }, []);
  const prevCrumbs = useRef<string[]>([]);
  const seen = prevCrumbs.current;
  useEffect(() => {
    prevCrumbs.current = cs.map((c) => c.key);
  });

  const opts: Option[] = pop?.mode === PopMode.Q ? suggest(query, st, value, places) : [];
  const forKey = `${snap.line}\n${value}`;
  const cur = sel.for === forKey ? sel : { i: firstChoice(opts), moved: false, for: forKey };

  const openQ = useCallback(() => setPop({ mode: PopMode.Q }), []);
  // Focus put back after a choice is not a person asking for the list.
  const quiet = useRef(false);
  useImperativeHandle(handle, () => ({
    focus: (typed?: string) => {
      input.current?.focus();
      if (typed !== undefined) setValue(typed);
      setPop({ mode: PopMode.Q });
    },
    blur: () => input.current?.blur(),
  }));

  // A press outside the line closes its menus.
  useEffect(() => {
    const down = (e: MouseEvent) => {
      if (!box.current?.contains(e.target as Node)) setPop(null);
    };
    document.addEventListener("mousedown", down);
    return () => document.removeEventListener("mousedown", down);
  }, []);

  const commit = (line: string, reopen: boolean) => {
    store.commit(line);
    setValue("");
    if (reopen) setPop({ mode: PopMode.Q });
    else setPop(null);
  };
  const apply = (o: Option | undefined) => {
    if (!o) return;
    const r = take(query, st, value, o);
    if ("input" in r) {
      setValue(r.input);
      setPop({ mode: PopMode.Q });
      return;
    }
    commit(r.line, r.reopen);
    quiet.current = !r.reopen;
    input.current?.focus();
    quiet.current = false;
  };
  const cutTo = (c: Crumb) => {
    if (c.cut === CrumbCut.Map || c.cut === CrumbCut.Verb) {
      input.current?.focus();
      return;
    }
    store.cut(c.cut);
    setPop(null);
  };

  const onKey = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Backspace" && !value) {
      e.preventDefault();
      const piece = store.unwind();
      if (piece) setValue(piece);
      setPop({ mode: PopMode.Q });
      return;
    }
    // The list closed after a choice: ↓ brings it back.
    if (!pop && e.key === "ArrowDown") {
      e.preventDefault();
      openQ();
      return;
    }
    if (pop?.mode === PopMode.Q && (e.key === "ArrowDown" || e.key === "ArrowUp")) {
      e.preventDefault();
      const n = opts.length;
      if (!n) return;
      let i = cur.i;
      for (let s = 0; s < n; s++) {
        i = (i + (e.key === "ArrowDown" ? 1 : -1) + n) % n;
        if (!opts[i]!.na) break;
      }
      setSel({ i, moved: true, for: forKey });
      return;
    }
    if (pop?.mode === PopMode.Q && e.key === "Tab") {
      e.preventDefault();
      apply(opts[cur.i]);
      return;
    }
    if (e.key === "Enter") {
      // The line blurs on commit; the page must not take this Enter as its own.
      e.preventDefault();
      e.stopPropagation();
      const tv = value.trim();
      if (!tv && st.verb !== null && onConfirm()) return;
      // Enter runs what was typed; a suggestion is taken with Tab, or with
      // Enter once chosen with the arrows.
      if (pop?.mode === PopMode.Q && cur.moved && opts[cur.i]) return apply(opts[cur.i]);
      if (pop?.mode === PopMode.Q && tv.startsWith(">") && !query.verbs.some((v) => tv.slice(1).trim().startsWith(v.id)) && opts[cur.i]) return apply(opts[cur.i]);
      if (!tv) {
        input.current?.blur();
        setPop(null);
        return;
      }
      commit(lineWith(query, st, tv), false);
      input.current?.blur();
      return;
    }
    if (e.key === "Escape") {
      e.preventDefault();
      e.stopPropagation();
      if (pop) setPop(null);
      else if (value) setValue("");
      else input.current?.blur();
    }
  };
  const onChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const v = e.target.value;
    // A finished token followed by a space becomes a crumb at once.
    if (/\S\s$/.test(v) && !v.includes(">")) {
      commit(lineWith(query, st, v.trim()), true);
      return;
    }
    setValue(v);
    setPop({ mode: PopMode.Q });
  };

  const hidden = k ? cs.slice(1, 1 + k) : [];
  const shown = cs.map((c, n) => ({ c, n })).filter(({ n }) => !(n >= 1 && n < 1 + k));
  const place = currentPlace(query, st, places);
  const cols = columns(query, st.segs, st.map);
  const last = cols[cols.length - 1];
  const count = last?.type === ColumnType.Results && last.sel && !st.map && st.verb === null ? query.results(last.scope, last.filter).length : null;
  const placeholder = !st.segs.length && !st.map && st.verb === null ? t("line.empty") : !typing ? "" : st.verb !== null ? t("line.verb") : t("line.more");

  const openHidden = (el: HTMLElement) => {
    if (pop?.mode === PopMode.Hidden) return setPop(null);
    // Under the «…» itself: the options' hover edge on the chip's left edge.
    const left = Math.round(el.getBoundingClientRect().left - box.current!.getBoundingClientRect().left - tokenPx("--u"));
    setPop({ mode: PopMode.Hidden, left });
  };

  let group: string | null = null;
  return (
    <div className="qbox" ref={box}>
      <div
        className={`qline${typing ? " typing" : ""}`}
        // The line is where typing starts, not a handle for the window.
        data-tauri-drag-region="false"
        onMouseDown={(e) => {
          const t0 = e.target as HTMLElement;
          if (t0.closest(".crumb") || t0.closest("[data-places]")) return;
          if (t0 !== input.current) {
            e.preventDefault();
            input.current?.focus();
          }
        }}
      >
        <nav className="crumbs" ref={crumbsEl}>
          {shown.map(({ c, n }, i) => (
            <span key={c.key} style={{ display: "contents" }}>
              {i > 0 && <span className="sep">›</span>}
              <button
                type="button"
                className={`crumb${n === cs.length - 1 ? " last" : ""}${seen.length && !seen.includes(c.key) ? " enter" : ""}`}
                title={c.title ?? c.name}
                onClick={() => (n === cs.length - 1 ? input.current?.focus() : cutTo(c))}
              >
                <CrumbIcon c={c} />
                <span>{c.name}</span>
              </button>
              {k > 0 && i === 0 && (
                <>
                  <span className="sep">›</span>
                  <button type="button" className={`crumb more${pop?.mode === PopMode.Hidden ? " open" : ""}`} title={hidden.map((x) => x.name).join(" › ")} onClick={(e) => openHidden(e.currentTarget)}>
                    <Icon name="more" />
                  </button>
                </>
              )}
            </span>
          ))}
        </nav>
        <input
          ref={input}
          value={value}
          placeholder={placeholder}
          autoComplete="off"
          spellCheck={false}
          onFocus={() => {
            setTyping(true);
            if (!quiet.current) openQ();
          }}
          onBlur={() => setTyping(false)}
          onChange={onChange}
          onKeyDown={onKey}
        />
        {count !== null && <span className="qmeta">{t("count.matches", { n: count })}</span>}
        <button
          type="button"
          data-places=""
          className={`btn ico${place ? " on" : ""}`}
          data-tip={t("places")}
          aria-label={t("places")}
          onClick={(e) => {
            e.stopPropagation();
            setPop(pop?.mode === PopMode.Places ? null : { mode: PopMode.Places });
          }}
        >
          <Icon name={place ? "markOn" : "mark"} />
        </button>
        <Kbd>⌘K</Kbd>
      </div>
      {pop?.mode === PopMode.Q && opts.length > 0 && (
        <div className="pop" onMouseDown={(e) => e.preventDefault()}>
          <div>
            {opts.map((o, n) => {
              const g = text(o.group);
              const head = g !== group ? <h6>{g}</h6> : null;
              group = g;
              return (
                <span key={n} style={{ display: "contents" }}>
                  {head}
                  <button type="button" className={`opt${n === cur.i ? " on" : ""}${o.na ? " na" : ""}`} onClick={() => apply(o)}>
                    {o.level ? <Glyph level={o.level} /> : o.icon ? <Icon name={o.icon} /> : <span className="blank" />}
                    <span className="lb">{text(o.label)}</span>
                    <span className="syn">{o.syn}</span>
                    <span className="d">{n === cur.i && <Kbd>Tab</Kbd>}</span>
                  </button>
                </span>
              );
            })}
          </div>
          <div className="crib">
            <h6>{t("ui.crib")}</h6>
            <div className="gram">
              <code>acme › members</code>
              <span>{t("ui.cr.path")}</span>
              <code>member:dana</code>
              <span>{t("ui.cr.member")}</span>
              <code>state:critical</code>
              <span>{t("ui.cr.state")}</span>
              <code>aws</code>
              <span>{t("ui.cr.word")}</span>
              <code>host:*.prod.*</code>
              <span>{t("ui.cr.hosts")}</span>
              <code>map:acme-access</code>
              <span>{t("ui.cr.map")}</span>
              <code>&gt; rotate</code>
              <span>{t("ui.cr.verb")}</span>
            </div>
            <p>{t("ui.cribNote")}</p>
          </div>
        </div>
      )}
      {pop?.mode === PopMode.Places && (
        <div className="pop one" onMouseDown={(e) => e.preventDefault()}>
          <div>
            <h6>{t("ui.placesHead")}</h6>
            {places.map((p) => (
              <button key={p.id} type="button" className={`opt${place?.id === p.id ? " on" : ""}`} onClick={() => commit(p.line, false)}>
                {p.level ? <Glyph level={p.level} /> : <Icon name={p.icon!} />}
                <span className="lb">{text(p.name)}</span>
                <span className="d" />
              </button>
            ))}
            <h6>{t("current")}</h6>
            <button
              type="button"
              className="opt"
              disabled={!st.segs.length || !!place}
              onClick={() => {
                setPop(null);
                savePlace();
              }}
            >
              <Icon name="plus" />
              <span className="lb">{t("savePlace")}</span>
              <span className="d" />
            </button>
          </div>
        </div>
      )}
      {pop?.mode === PopMode.Hidden && (
        <div className="pop one at-left" style={{ left: pop.left }} onMouseDown={(e) => e.preventDefault()}>
          <div>
            <h6>{t("hidden")}</h6>
            {hidden.map((c) => (
              <button key={c.key} type="button" className="opt" title={c.name} onClick={() => cutTo(c)}>
                <CrumbIcon c={c} />
                <span className="lb">{c.name}</span>
                <span className="d" />
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
});
