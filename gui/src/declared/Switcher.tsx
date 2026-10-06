import { useContext, useEffect, useMemo, useRef, useState } from "react";
import { Icon, useEscape } from "../ui";
import { t } from "../i18n";
import { Ctx } from "./Render";
import { tx } from "./text";
import type { SwitchItem, Switcher as SwitcherT, Tone } from "./types";

/// Past this many the list gets a search field.
const SEARCH_FROM = 6;

const dot = (tone?: Tone) => (tone && tone !== "plain" ? <span className={`dot ${tone}`} /> : null);

/// A screen's head when the section works with several connections: the one
/// on screen as a pill, the others, adding one and the catalog a press away.
/// It stands where the section's column used to be — the screen keeps its
/// width.
export function SwitcherView({ s }: { s: SwitcherT }) {
  const { go, run } = useContext(Ctx);
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const box = useRef<HTMLDivElement>(null);
  useEscape(open ? () => setOpen(false) : null);
  useEffect(() => {
    if (!open) return;
    const away = (e: MouseEvent) => box.current && !box.current.contains(e.target as Node) && setOpen(false);
    window.addEventListener("mousedown", away);
    return () => window.removeEventListener("mousedown", away);
  }, [open]);
  useEffect(() => {
    if (!open) setQuery("");
  }, [open]);

  const current = s.items.find((x) => x.key === s.current);
  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    return q ? s.items.filter((x) => `${tx(x.label)} ${tx(x.hint)}`.toLowerCase().includes(q)) : s.items;
  }, [s.items, query]);
  const pick = (x: SwitchItem) => {
    setOpen(false);
    go(x.route);
  };

  return (
    <div className="dv-switch" ref={box}>
      <button type="button" className={`dv-switch-pill ${open ? "on" : ""}`} aria-haspopup="listbox" aria-expanded={open} onClick={() => setOpen((v) => !v)}>
        {current?.icon && <Icon name={current.icon} size={14} />}
        <b>{current ? tx(current.label) : "—"}</b>
        {current?.hint && <small>{tx(current.hint)}</small>}
        {dot(current?.dot)}
        <Icon name="chevron" size={11} />
      </button>
      {open && (
        <div className="dv-switch-menu" role="listbox">
          {s.items.length > SEARCH_FROM && (
            <label className="search dv-switch-search">
              <Icon name="search" size={13} />
              <input autoFocus value={query} onChange={(e) => setQuery(e.target.value)} placeholder={t("dv.search")} aria-label={t("dv.search")} spellCheck={false} />
            </label>
          )}
          <div className="dv-switch-list">
            {shown.map((x) => (
              <button type="button" role="option" aria-selected={x.key === s.current} key={x.key} className={`dv-switch-item ${x.key === s.current ? "on" : ""}`} onClick={() => pick(x)}>
                {x.icon && <Icon name={x.icon} size={13} />}
                <span className="label">{tx(x.label)}</span>
                {x.hint && <small>{tx(x.hint)}</small>}
                {dot(x.dot)}
              </button>
            ))}
            {shown.length === 0 && <span className="dv-switch-none">{t("dv.nothing")}</span>}
          </div>
          {(s.add || s.all) && (
            <div className="dv-switch-foot">
              {s.add && (
                <button
                  type="button"
                  className="btn"
                  onClick={() => {
                    setOpen(false);
                    void run(s.add!.action);
                  }}
                >
                  {s.add.icon && <Icon name={s.add.icon} size={14} />}
                  {s.add.label ? tx(s.add.label) : tx(s.add.title)}
                </button>
              )}
              {s.all && (
                <button type="button" className="btn" onClick={() => pick(s.all!)}>
                  {s.all.icon && <Icon name={s.all.icon} size={14} />}
                  {tx(s.all.label)}
                </button>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
