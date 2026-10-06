import { useEffect, useRef, useState } from "react";
import { Icon, inkOn, useEscape } from "./ui";
import { t } from "./i18n";
import type { AccountList } from "./types";

/// A place the window can be: a section of the core's or a plugin's.
export type Section = { id: string; icon: string; label: string; badge?: number };

/// The window's one strip — the only chrome the app has, in every section.
/// On the left the section menu (which section, which account, everything
/// else one press away) and Back/Forward across sections and modes; on the
/// right the search, sync and lock. There is no rail: sections live in the
/// menu.
export function Chrome({
  sections,
  current,
  onSection,
  accounts,
  avatar,
  unlocked,
  canBack,
  canForward,
  onBack,
  onForward,
  onSearch,
  onSync,
  onLock,
  busy,
  onSwitchAccount,
  onAddAccount,
  onLogout,
}: {
  sections: Section[];
  current: string;
  onSection: (id: string) => void;
  accounts: AccountList | null;
  avatar: { color: string | null; initials: string } | null;
  unlocked: boolean;
  canBack: boolean;
  canForward: boolean;
  onBack: () => void;
  onForward: () => void;
  onSearch: (() => void) | null;
  onSync: (() => void) | null;
  onLock: () => void;
  busy: boolean;
  onSwitchAccount: (id: string) => void;
  onAddAccount: () => void;
  onLogout: (id: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  useEscape(open ? () => setOpen(false) : null);
  useEffect(() => {
    if (!open) return;
    const away = (e: MouseEvent) => box.current && !box.current.contains(e.target as Node) && setOpen(false);
    window.addEventListener("mousedown", away);
    return () => window.removeEventListener("mousedown", away);
  }, [open]);
  // Alt+← / Alt+→ (the spec's), and ⌘[ / ⌘] as in every Mac application
  // with a history. In a text field Alt+arrows move by word, so they stay its.
  useEffect(() => {
    const keys = (e: KeyboardEvent) => {
      const editing = e.target instanceof HTMLElement && (e.target.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName));
      const alt = e.altKey && !e.metaKey && !e.ctrlKey && !editing;
      const cmd = e.metaKey || e.ctrlKey;
      const back = (alt && e.key === "ArrowLeft") || (cmd && e.key === "[");
      const forward = (alt && e.key === "ArrowRight") || (cmd && e.key === "]");
      if (back && canBack) {
        e.preventDefault();
        onBack();
      } else if (forward && canForward) {
        e.preventDefault();
        onForward();
      }
    };
    window.addEventListener("keydown", keys);
    return () => window.removeEventListener("keydown", keys);
  }, [canBack, canForward, onBack, onForward]);

  const here = sections.find((s) => s.id === current);
  const active = accounts?.accounts.find((a) => a.account.id === accounts.active) ?? null;
  const go = (f: () => void) => () => {
    setOpen(false);
    f();
  };

  return (
    <header className="chrome" data-tauri-drag-region>
      <div className="chrome-lead" ref={box}>
        <button type="button" className={`chrome-section ${open ? "on" : ""}`} aria-haspopup="menu" aria-expanded={open} onClick={() => setOpen((v) => !v)}>
          <span className="chrome-avatar" style={avatar?.color ? { background: avatar.color, color: inkOn(avatar.color) } : undefined}>
            {avatar?.initials ?? (active?.account.email ?? "?").slice(0, 1).toUpperCase()}
            {!unlocked && (
              <span className="chrome-locked" role="img" aria-label={t("state.locked")}>
                <Icon name="lock" size={8} />
              </span>
            )}
          </span>
          {here && <Icon name={here.icon} size={16} />}
          <b>{here?.label ?? ""}</b>
          <Icon name="chevron" size={12} />
        </button>
        {open && (
          <div className="chrome-menu" role="menu">
            <div className="chrome-menu-account">
              <b>{active?.account.email ?? "—"}</b>
              <span>{active?.account.base_url.replace(/^https?:\/\//, "") ?? ""}</span>
            </div>
            <div className="chrome-menu-group" role="group" aria-label={t("nav.sections")}>
              {sections.map((s) => (
                <button type="button" role="menuitem" key={s.id} className={s.id === current ? "on" : ""} onClick={go(() => onSection(s.id))}>
                  <Icon name={s.icon} size={16} />
                  <span>{s.label}</span>
                  {s.badge ? <span className="chrome-badge">{s.badge}</span> : null}
                </button>
              ))}
            </div>
            <div className="chrome-menu-group" role="group" aria-label={t("accounts.title")}>
              {(accounts?.accounts ?? [])
                .filter((a) => a.account.id !== accounts?.active)
                .map((a) => (
                  <button type="button" role="menuitem" key={a.account.id} onClick={go(() => onSwitchAccount(a.account.id))}>
                    <Icon name="shield" size={16} />
                    <span>{a.account.email}</span>
                  </button>
                ))}
              <button type="button" role="menuitem" onClick={go(onAddAccount)}>
                <Icon name="plus" size={16} />
                <span>{t("accounts.add")}</span>
              </button>
              {accounts?.active && (
                <button type="button" role="menuitem" className="danger" onClick={go(() => onLogout(accounts.active!))}>
                  <Icon name="lock" size={16} />
                  <span>{t("accounts.logout")}</span>
                </button>
              )}
            </div>
          </div>
        )}
        <span className="chrome-nav">
          <button type="button" className="btn icon-only" disabled={!canBack} onClick={onBack} title={`${t("nav.back")} (⌥←)`} aria-label={t("nav.back")}>
            <Icon name="chevron" size={14} />
          </button>
          <button type="button" className="btn icon-only" disabled={!canForward} onClick={onForward} title={`${t("nav.forward")} (⌥→)`} aria-label={t("nav.forward")}>
            <Icon name="chevron" size={14} />
          </button>
        </span>
      </div>
      <span className="grow" data-tauri-drag-region />
      <div className="chrome-tools">
        {onSearch && (
          <button type="button" className="chrome-search" onClick={onSearch}>
            <Icon name="search" size={14} />
            <span>{t("action.search")}</span>
            <kbd>{navigator.platform.startsWith("Mac") ? "⌘K" : "Ctrl+K"}</kbd>
          </button>
        )}
        {onSync && (
          <button type="button" className="btn icon-only" title={t("action.sync")} aria-label={t("action.sync")} aria-busy={busy} disabled={busy} onClick={onSync}>
            <Icon name="sync" size={14} />
          </button>
        )}
        <button type="button" className="btn icon-only" title={t("action.lock")} aria-label={t("action.lock")} onClick={onLock}>
          <Icon name="lock" size={14} />
        </button>
      </div>
    </header>
  );
}
