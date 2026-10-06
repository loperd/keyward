// The strip: the window's own buttons' blank, back and forward, the one line,
// the sync state, the theme, and the account menu with sections, language
// and lock.
import { forwardRef, useEffect, useState } from "react";
import { type Account, InterfaceChoice } from "../backend";
import { currentLang, setLang, t, text, Lang } from "../i18n";
import { usePath } from "../path/store";
import { initials } from "../map/model";
import { Icon } from "./Icons";
import { IconButton, Kbd, useCore } from "./marks";
import { PathLine, type LineHandle } from "./PathLine";
import { useBusy, Busy } from "./activity";
import { Turning } from "./Loading";

export const isDark = () => {
  const set = document.documentElement.dataset.theme;
  if (set === "dark" || set === "light") return set === "dark";
  return !matchMedia("(prefers-color-scheme: light)").matches;
};

/// The sections a person jumps to with ⌘1…: the vault, then each plugin's.
export function sectionLines(core: ReturnType<typeof useCore>): { line: string; name: string; icon: string }[] {
  return [
    { line: "", name: t("root"), icon: "vault" },
    ...core.dir.contributions.map((c) => {
      const n = core.dir.node(c.root.id);
      return { line: n.slug, name: text(n.name), icon: n.icon };
    }),
  ];
}

function AccountMenu({ name, onClose }: { name: string; onClose: () => void }) {
  const core = useCore();
  const lang = currentLang();
  // The other accounts, where the app holds several: read each time the menu
  // opens, so a sign-in elsewhere shows.
  const b = core.backend;
  const several = b.caps.accounts && !!b.accounts;
  const [accounts, setAccounts] = useState<Account[] | null>(null);
  useEffect(() => {
    if (!several || !b.accounts) return;
    let live = true;
    b.accounts().then((a) => live && setAccounts(a), core.report);
    return () => {
      live = false;
    };
  }, [b, several, core.report]);
  const act = (fn: () => Promise<void>) => {
    onClose();
    fn().catch(core.report);
  };
  const langRow = (code: Lang, label: string) => (
    <div className="kw-mrow" onClick={() => setLang(code)}>
      <span className="kw-ic">
        <Icon name="lang" />
      </span>
      <span className="kw-lb">{label}</span>
      {lang === code && (
        <span className="kw-ck">
          <Icon name="check" />
        </span>
      )}
    </div>
  );
  return (
    <div className="kw-veil" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="kw-menu">
        <div className="kw-me">
          <span className="kw-ava">{initials(name)}</span>
          <div>
            <b>{name}</b>
            <span>{core.server}</span>
          </div>
        </div>
        <div className="kw-mh">{t("sections")}</div>
        {sectionLines(core).map((s, i) => (
          <div
            key={s.line}
            className="kw-mrow"
            onClick={() => {
              onClose();
              core.store.commit(s.line);
            }}
          >
            <span className="kw-ic">
              <Icon name={s.icon} />
            </span>
            <span className="kw-lb">{s.name}</span>
            <Kbd>{`⌘${i + 1}`}</Kbd>
          </div>
        ))}
        <div className="kw-mh">{t("lang")}</div>
        {langRow(Lang.Ru, t("ui.lang.ru"))}
        {langRow(Lang.En, t("ui.lang.en"))}
        {core.backend.setInterface && (
          // The new window is a beta: on here, and turned off back into the old one.
          <div className="kw-mrow" onClick={() => core.backend.setInterface?.(InterfaceChoice.Old).catch(core.report)}>
            <span className="kw-ic">
              <Icon name="refresh" />
            </span>
            <span className="kw-lb">{t("ui.newInterface")}</span>
            <span className="kw-ck">
              <Icon name="check" />
            </span>
          </div>
        )}
        <div className="kw-mh">{t("account")}</div>
        {several && accounts === null && (
          <div className="kw-mrow kw-sk-mrow kw-sk-late" role="status" aria-label={t("load.accounts")}>
            <span className="kw-ic">
              <Turning />
            </span>
            <span className="kw-sk" aria-hidden="true" />
          </div>
        )}
        {accounts
          ?.filter((a) => !a.active)
          .map((a) => (
            <div key={a.id} className="kw-mrow" onClick={() => b.switchAccount && act(() => b.switchAccount!(a.id))}>
              <span className="kw-ic">
                <Icon name="user2" />
              </span>
              <span className="kw-lb">{a.email}</span>
            </div>
          ))}
        {several && b.addAccount && (
          <div className="kw-mrow" onClick={() => act(() => b.addAccount!())}>
            <span className="kw-ic">
              <Icon name="plus" />
            </span>
            <span className="kw-lb">{t("gate.account.add")}</span>
          </div>
        )}
        {several && (
          <div className="kw-mrow" onClick={() => act(() => b.logout())}>
            <span className="kw-ic">
              <Icon name="logout" />
            </span>
            <span className="kw-lb">{t("gate.account.signOut")}</span>
          </div>
        )}
        <div
          className="kw-mrow"
          onClick={() => {
            onClose();
            core.store.verb("lock");
          }}
        >
          <span className="kw-ic">
            <Icon name="lock" />
          </span>
          <span className="kw-lb">{t("lock")}</span>
          <Kbd>⌘L</Kbd>
        </div>
      </div>
    </div>
  );
}

export const Strip = forwardRef<LineHandle, { name: string; syncedAt: number; menu: boolean; setMenu: (on: boolean) => void; onConfirm: () => boolean }>(function Strip(
  { name, syncedAt, menu, setMenu, onConfirm },
  line,
) {
  const core = useCore();
  const snap = usePath(core.store);
  const [dark, setDark] = useState(isDark);
  // A sync under way, whoever started it: the glyph turns until it ends.
  const syncing = useBusy(core.activity, Busy.Sync);
  return (
    <header className="kw-strip" data-tauri-drag-region="deep">
      <div className="kw-nav">
        <IconButton icon="back" tip={`${t("back")} ⌘[`} onClick={() => core.store.back()} disabled={!snap.canBack} />
        <IconButton icon="fwd" tip={`${t("forward")} ⌘]`} onClick={() => core.store.forward()} disabled={!snap.canForward} />
      </div>
      <PathLine ref={line} onConfirm={onConfirm} />
      {/* Sync: a button, not a status. The window does not know when the
          daemon last synced, so it claims no time; the glyph turns while a
          sync, whoever started it, is under way. */}
      <IconButton
        icon="refresh"
        className={`kw-sync${syncing ? " kw-syncing" : ""}`}
        tip={syncing ? t("ui.syncing") : t("ui.syncWith", { server: core.server })}
        disabled={syncing}
        onClick={() => {
          core.backend.sync().catch(core.report);
        }}
      />
      <IconButton
        icon={dark ? "sun" : "moon"}
        tip={t("theme")}
        onClick={() => {
          document.documentElement.dataset.theme = dark ? "light" : "dark";
          setDark(!dark);
        }}
      />
      <IconButton icon="lock" tip={`${t("lock")} ⌘L`} onClick={() => core.backend.lock().catch(core.report)} />
      <button type="button" className="kw-btn kw-ico kw-tip-l" data-tip={t("ui.account", { name })} aria-label={t("ui.account", { name })} onClick={() => setMenu(true)}>
        <span className="kw-ava">{initials(name)}</span>
      </button>
      {menu && <AccountMenu name={name} onClose={() => setMenu(false)} />}
    </header>
  );
});
