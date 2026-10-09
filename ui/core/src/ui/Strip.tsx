// The strip: the window's own buttons' blank, back and forward, the one line,
// the sync state, the theme, and the account menu with sections, language
// and lock.
import { forwardRef, useEffect, useState } from "react";
import type { Account } from "../backend";
import { currentLang, setLang, t, text, Lang } from "../i18n";
import { usePath } from "../path/store";
import { initials } from "../map/model";
import { Icon } from "./Icons";
import { IconButton, Kbd, useCore } from "./marks";
import { PathLine, type LineHandle } from "./PathLine";
import { useBusy, Busy } from "./activity";
import { Turning } from "./Loading";
import { WindowButtons } from "./WindowButtons";
import { useSettingsMaybe } from "./settings-context";
import { SETTINGS_ID } from "../settings/pages";
import { LanguageChoice, ThemeChoice } from "../settings/types";

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
  const kept = useSettingsMaybe();
  const lang = currentLang();
  // Where the app keeps settings, the language is one of them: chosen here,
  // it is saved, not only shown.
  const chooseLang = (code: Lang) => {
    if (kept?.settings) kept.patch({ language: code === Lang.Ru ? LanguageChoice.Ru : LanguageChoice.En }).catch(core.report);
    else setLang(code);
  };
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
    <div className="mrow" onClick={() => chooseLang(code)}>
      <span className="ic">
        <Icon name="lang" />
      </span>
      <span className="lb">{label}</span>
      {lang === code && (
        <span className="ck">
          <Icon name="check" />
        </span>
      )}
    </div>
  );
  return (
    <div className="veil" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="menu">
        <div className="me">
          <span className="ava">{initials(name)}</span>
          <div>
            <b>{name}</b>
            <span>{core.server}</span>
          </div>
        </div>
        <div className="mh">{t("sections")}</div>
        {sectionLines(core).map((s, i) => (
          <div
            key={s.line}
            className="mrow"
            onClick={() => {
              onClose();
              core.store.commit(s.line);
            }}
          >
            <span className="ic">
              <Icon name={s.icon} />
            </span>
            <span className="lb">{s.name}</span>
            <Kbd>{`⌘${i + 1}`}</Kbd>
          </div>
        ))}
        {core.dir.has(SETTINGS_ID) && (
          <div
            className="mrow"
            onClick={() => {
              onClose();
              core.store.go(SETTINGS_ID);
            }}
          >
            <span className="ic">
              <Icon name="settings" />
            </span>
            <span className="lb">{t("set.title")}</span>
            <Kbd>⌘,</Kbd>
          </div>
        )}
        <div className="mh">{t("lang")}</div>
        {langRow(Lang.Ru, t("ui.lang.ru"))}
        {langRow(Lang.En, t("ui.lang.en"))}
        <div className="mh">{t("account")}</div>
        {several && accounts === null && (
          <div className="mrow sk-mrow sk-late" role="status" aria-label={t("load.accounts")}>
            <span className="ic">
              <Turning />
            </span>
            <span className="sk" aria-hidden="true" />
          </div>
        )}
        {accounts
          ?.filter((a) => !a.active)
          .map((a) => (
            <div key={a.id} className="mrow" onClick={() => b.switchAccount && act(() => b.switchAccount!(a.id))}>
              <span className="ic">
                <Icon name="user2" />
              </span>
              <span className="lb">{a.email}</span>
            </div>
          ))}
        {several && b.addAccount && (
          <div className="mrow" onClick={() => act(() => b.addAccount!())}>
            <span className="ic">
              <Icon name="plus" />
            </span>
            <span className="lb">{t("gate.account.add")}</span>
          </div>
        )}
        {several && (
          <div className="mrow" onClick={() => act(() => b.logout())}>
            <span className="ic">
              <Icon name="logout" />
            </span>
            <span className="lb">{t("gate.account.signOut")}</span>
          </div>
        )}
        <div
          className="mrow"
          onClick={() => {
            onClose();
            core.store.verb("lock");
          }}
        >
          <span className="ic">
            <Icon name="lock" />
          </span>
          <span className="lb">{t("lock")}</span>
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
  const kept = useSettingsMaybe();
  const snap = usePath(core.store);
  const [dark, setDark] = useState(isDark);
  // A sync under way, whoever started it: the glyph turns until it ends.
  const syncing = useBusy(core.activity, Busy.Sync);
  return (
    <header className="strip" data-tauri-drag-region="deep">
      <WindowButtons />
      <div className="nav">
        <IconButton icon="back" tip={`${t("back")} ⌘[`} onClick={() => core.store.back()} disabled={!snap.canBack} />
        <IconButton icon="fwd" tip={`${t("forward")} ⌘]`} onClick={() => core.store.forward()} disabled={!snap.canForward} />
      </div>
      <PathLine ref={line} onConfirm={onConfirm} />
      {/* Sync: a button, not a status. The window does not know when the
          daemon last synced, so it claims no time; the glyph turns while a
          sync, whoever started it, is under way. */}
      <IconButton
        icon="refresh"
        className={`sync${syncing ? " syncing" : ""}`}
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
          // Where the app keeps settings, the theme is one of them.
          if (kept?.settings) kept.patch({ theme: dark ? ThemeChoice.Light : ThemeChoice.Dark }).catch(core.report);
          else document.documentElement.dataset.theme = dark ? "light" : "dark";
          setDark(!dark);
        }}
      />
      <IconButton icon="lock" tip={`${t("lock")} ⌘L`} onClick={() => core.backend.lock().catch(core.report)} />
      <button type="button" className="btn ico tip-l" data-tip={t("ui.account", { name })} aria-label={t("ui.account", { name })} onClick={() => setMenu(true)}>
        <span className="ava">{initials(name)}</span>
      </button>
      {menu && <AccountMenu name={name} onClose={() => setMenu(false)} />}
    </header>
  );
});
