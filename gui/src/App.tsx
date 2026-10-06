import { useCallback, useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import type { FillContext } from "./Spotlight";
import { Alert, Empty, Icon, Toasts, inkOn, useEscape, useToasts } from "./ui";
import { folderColor } from "./folders";
import { Gate } from "./Gate";
import { applyAccent, watchScheme } from "./accent";
import { installOverlayScrollbars } from "./overlayScroll";
import { Spotlight } from "./Spotlight";
import { NewItem } from "./screens/NewItem";
import { NewOrg } from "./screens/NewOrg";
import { OrgManager } from "./screens/Orgs";
import { FolderEditor } from "./screens/Folders";
import { VaultScreen, type Filter } from "./screens/Vault";
import { GeneratorScreen } from "./screens/Generator";
import { PROFILE_EVENT, SettingsScreen } from "./screens/Settings";
import { call, pluginSectionTitle, pluginSettingsTitle, pluginTitle, refreshPlugins, usePlugins, type Manifest } from "./plugins/call";
import { pluginEntry, sectionView, splitSection } from "./plugins";
import type { AccountProfile } from "./types";
import { EditsScreen } from "./screens/Edits";
import { DetailPane } from "./screens/Detail";
import { LANG_EVENT, setLanguage, t, tError } from "./i18n";
import type { Key } from "./i18n";
import type { AppSettings } from "./types";
import { KIND_KEYS, kindLabel, type AccountList, type Catalog, type Status } from "./types";

const POLL_MS = 4000;

/// The settings' sections: the list on the left, the contents on the right.
///
/// Each is a page of its own rather than a piece of one long one: safety, the
/// application, the plugins and the help used to lie in one scroll, and
/// reaching the bottom meant leafing past everything else.
const SETTINGS_TABS = ["account", "security", "preferences", "app", "plugins", "about"] as const;
type SettingsTab = string;
const SETTINGS_ICON: Record<string, string> = {
  account: "identity",
  security: "shield",
  preferences: "eye",
  app: "settings",
  plugins: "puzzle",
  about: "note",
};
/// The core's sections. Everything else in the rail is a plugin: what there is
/// arrives as manifests from the daemon rather than being wired in here as a
/// list.
const CORE_TABS = ["vault", "edits", "generator", "settings"] as const;
type CoreTab = (typeof CORE_TABS)[number];
/// A section is either one of the core's own or a plugin's name.
type Tab = CoreTab | string;

function isCore(tab: Tab): tab is CoreTab {
  return (CORE_TABS as readonly string[]).includes(tab);
}

export default function App() {
  const plugins = usePlugins();
  // The plugins that have something to govern: each has a settings page of its
  // own.
  const settingsPlugins = plugins.filter((m) => m.enabled && pluginEntry(m.id).SettingsSection);
  // The section can be given by the hash: that way the stand opens straight on
  // the screen wanted, while in the application there is no hash and the
  // behaviour is as it was.
  const [tab, setTab] = useState<Tab>(() => window.location.hash.replace("#", "") || "vault");
  // Cmd+K is a habit shared by everybody, and it must not depend on where the
  // focus is just now.
  useEffect(() => {
    installOverlayScrollbars();
  }, []);

  // A plugin was switched off or removed while standing in its section — we
  // leave for the items rather than staying on a screen nobody is left to
  // answer for.
  useEffect(() => {
    if (isCore(tab) || plugins.length === 0) return;
    const live = plugins.find((m) => m.id === splitSection(tab).plugin);
    if (live && !live.enabled) setTab("vault");
  }, [plugins, tab]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      // Cmd+K and Cmd+F are both living habits: the first from editors, the
      // second from browsers. On Linux and Windows the same through Ctrl.
      if ((e.metaKey || e.ctrlKey) && ["k", "f"].includes(e.key.toLowerCase())) {
        e.preventDefault();
        setSpot(true);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  // A change of hash does not reload the page: without this the stand stays on
  // the section it started with.
  useEffect(() => {
    const onHash = () => {
      const wanted = window.location.hash.replace("#", "");
      if (wanted) setTab(wanted);
    };
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  const [status, setStatus] = useState<Status | null>(null);
  const [filtersOpen, setFiltersOpen] = useState<boolean>(() => {
    try {
      return localStorage.getItem("filtersOpen") === "1";
    } catch {
      return false;
    }
  });
  useEffect(() => {
    try {
      localStorage.setItem("filtersOpen", filtersOpen ? "1" : "0");
    } catch {
      /* it works without storage too */
    }
  }, [filtersOpen]);
  const [settingsTab, setSettingsTab] = useState<SettingsTab>("account");
  // The avatar's colour and initials come from the profile on the server. The
  // cache is in localStorage, so that the first frame after a launch is not
  // grey.
  const [avatar, setAvatar] = useState<{ color: string | null; initials: string } | null>(() => {
    try {
      const raw = localStorage.getItem("kw.avatar");
      return raw ? (JSON.parse(raw) as { color: string | null; initials: string }) : null;
    } catch {
      return null;
    }
  });
  // `?spot=1` opens the search at once — the stand needs that so it can be
  // photographed and measured; in the application there is no such address.
  // `?new=1` opens the form at once — the stand needs that to photograph it.
  const [newOrg, setNewOrg] = useState(false);
  // A folder's dialogue: `null` is a new folder, a folder is that one.
  const [folderEditing, setFolderEditing] = useState<Catalog["folders"][number] | null | undefined>(undefined);
  // The organisation whose dialogue is open.
  const [orgManaging, setOrgManaging] = useState<string | null>(null);
  const [adding, setAdding] = useState(() => new URLSearchParams(window.location.search).has("new"));
  const [spot, setSpot] = useState(() => new URLSearchParams(window.location.search).has("spot"));
  // A cramped window: the section's column is hidden and slides out as a
  // drawer from a button in the header. Any choice in it closes the drawer.
  const [drawer, setDrawer] = useState(false);
  // The autofill's context: what was in the foreground at Cmd+Shift+L.
  const [fill, setFill] = useState<FillContext | null>(null);
  useEffect(() => {
    let off: (() => void) | null = null;
    void listen<FillContext>("autofill", (e) => {
      setFill(e.payload);
      setSpot(true);
    }).then((un) => {
      off = un;
    });
    return () => {
      off?.();
    };
  }, []);
  const [catalog, setCatalog] = useState<Catalog | null>(null);
  // What the probing plugins answered to "does your section apply here".
  const [available, setAvailable] = useState<Record<string, boolean>>({});
  const [accounts, setAccounts] = useState<AccountList | null>(null);
  // Asked again when the account or the vault's state changes, and every
  // few minutes: the plugin keeps its own answer for a while, so this is
  // cheap.
  const probing = plugins.filter((m) => m.probe && m.enabled).map((m) => m.id).join(",");
  useEffect(() => {
    if (!probing) return;
    const ask = () =>
      probing.split(",").forEach((id) => {
        void call<{ available: boolean }>(id, "available")
          .then((r) => setAvailable((cur) => (cur[id] === r.available ? cur : { ...cur, [id]: r.available })))
          .catch(() => setAvailable((cur) => (cur[id] === false ? cur : { ...cur, [id]: false })));
      });
    ask();
    const timer = window.setInterval(ask, 5 * 60 * 1000);
    return () => window.clearInterval(timer);
  }, [probing, accounts?.active, status?.vault?.state]);

  // The account's profile — for the sake of the avatar. It is re-read when the
  // vault has opened or the settings have reported a change of name or
  // colour.
  useEffect(() => {
    const unlocked = status?.vault?.state === "unlocked";
    if (!unlocked) return;
    const load = () => {
      void invoke<AccountProfile>("account_profile")
        .then((p) => {
          const source = p.name?.trim() || p.email;
          const words = source.split(/[\s@._-]+/).filter(Boolean);
          const initials = (words.length >= 2 ? words[0][0] + words[1][0] : source.slice(0, 2)).toUpperCase();
          const next = { color: p.avatar_color ?? null, initials };
          setAvatar(next);
          try {
            localStorage.setItem("kw.avatar", JSON.stringify(next));
          } catch {
            // A private window — we will survive without the cache.
          }
        })
        .catch(() => {});
    };
    load();
    window.addEventListener(PROFILE_EVENT, load);
    return () => window.removeEventListener(PROFILE_EVENT, load);
  }, [status?.vault?.state, accounts?.active]);

  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<Filter>({ view: { kind: "all" } });
  const [menuOpen, setMenuOpen] = useState(false);
  const [forceSetup, setForceSetup] = useState(false);
  const [busy, setBusy] = useState(false);
  // `?item=<id>` opens the card at once — for the stand.
  const [selected, setSelected] = useState<string | null>(
    () => new URLSearchParams(window.location.search).get("item"),
  );
  const { toasts, push } = useToasts();
  const [settings, setSettings] = useState<AppSettings | null>(null);

  // The theme is applied at once, without a restart: an attribute on the root
  // overrules the system's preference.
  useEffect(() => {
    invoke<AppSettings>("get_settings").then(setSettings).catch(() => {});
  }, [tab]);

  useEffect(() => {
    const root = document.documentElement;
    if (!settings || settings.theme === "system") root.removeAttribute("data-theme");
    else root.dataset.theme = settings.theme;
    // The language is a setting too: the dictionary is swapped in place, and
    // the tree redraws on the event below.
    if (settings) setLanguage(settings.language);
  }, [settings]);

  // The accent is an application preference, not an account avatar colour.
  // `null` means the built-in violet ladder from theme.css.
  const accent = settings?.accent_color ?? null;
  useEffect(() => {
    const paint = () => applyAccent(accent);
    paint();
    return watchScheme(paint);
  }, [accent, settings?.theme]);

  // A change of language does not reload the page: the dictionary is swapped,
  // and this counter makes the whole tree read `t()` again.
  const [, setLangTick] = useState(0);
  useEffect(() => {
    const bump = () => setLangTick((n) => n + 1);
    window.addEventListener(LANG_EVENT, bump);
    return () => window.removeEventListener(LANG_EVENT, bump);
  }, []);

  // "Hide on copy": you copy, the window goes away, as in Bitwarden. Here
  // rather than in every screen: a copy ends in one and the same toast, and
  // this is the only place they have in common.
  const copied = useCallback(
    (text: string) => {
      push(text);
      if (settings?.hide_on_copy) {
        try {
          void getCurrentWindow().hide();
        } catch {
          /* the stand, with no window */
        }
      }
    },
    [push, settings?.hide_on_copy],
  );

  // While a password is being changed or a second factor set up in the
  // settings, the polling of the state is held back: otherwise the shell would
  // see "logged out" and replace the screen with the gate halfway through.
  const held = useRef(false);

  // The signature of the vault's state: while it has not changed there is no
  // point re-reading the contents — polling every four seconds must not jog the
  // decryption.
  const signature = useRef("");

  const refresh = useCallback(async (force = false) => {
    try {
      const s = await invoke<Status>("daemon_status");
      setStatus(s);
      setError(null);
      setAccounts(await invoke<AccountList>("vault_accounts"));

      const sig = [
        s.vault.state,
        s.vault.state === "unlocked" ? s.vault.entries : 0,
        s.pending_edits,
      ].join(":");
      if (!force && sig === signature.current) {
        setLoading(false);
        return;
      }
      signature.current = sig;

      if (s.vault.state === "unlocked" || s.vault.state === "disabled") {
        setCatalog(await invoke<Catalog>("vault_items"));
      } else {
        setCatalog(null);
      }
    } catch (e) {
      setStatus(null);
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh(true);
    const id = setInterval(() => {
      if (!held.current) void refresh();
    }, POLL_MS);
    return () => clearInterval(id);
  }, [refresh]);

  /*
    The set of plugins changes past the window too: they are installed from the
    command line, and one that falls over three times in a minute switches
    itself off. Asked for once, the rail would show a set half an hour old — the
    sections of a newly installed plugin did not appear until the window was
    restarted. It is re-read on the same timer; when the set has not changed
    there is no redraw.
  */
  useEffect(() => {
    const id = setInterval(() => {
      if (!held.current) void refreshPlugins();
    }, POLL_MS);
    return () => clearInterval(id);
  }, []);

  // Escape closes whatever was opened last — through the one stack: the card,
  // the drawer and the account's menu each take their turn.
  useEscape(selected ? () => setSelected(null) : null);
  useEscape(drawer ? () => setDrawer(false) : null);
  useEscape(menuOpen ? () => setMenuOpen(false) : null);

  const act = async (cmd: string, args?: Record<string, unknown>) => {
    setBusy(true);
    try {
      await invoke(cmd, args);
      await refresh(true);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const vault = status?.vault;
  const open = vault?.state === "unlocked" || vault?.state === "disabled";

  // The daemon does not answer — the one state that overrides everything:
  // without it neither the vault nor ssh works.
  if (!status && !loading) {
    return (
      <div className="gate">
        <div className="gate-card">
          <Empty icon="warn" title={t("daemon.down.title")} body={t("daemon.down.body")} />
          {error && <Alert message={error} onRetry={() => void refresh(true)} />}
        </div>
      </div>
    );
  }

  // The connection screen is shown over an open vault as well: otherwise "add
  // an account" did nothing while the vault was unlocked.
  if (status && (!open || forceSetup)) {
    return (
      <Gate
        status={status}
        onChanged={() => void refresh(true)}
        forceSetup={forceSetup}
        onSetupDone={() => setForceSetup(false)}
      />
    );
  }

  const counts = new Map(catalog?.counts ?? []);
  const total = catalog?.items.length ?? 0;
  const active = accounts?.accounts.find((a) => a.account.id === accounts.active);
  // The heading of the main column: in the list of items it says what exactly
  // has been filtered — or it makes no sense that two items out of four hundred
  // are in view.
  // The slice is named by each axis separately: they add up rather than replace
  // each other, which is why they stand side by side in the breadcrumbs too.
  const viewName =
    filter.view.kind === "all"
      ? t("items.all")
      : filter.view.kind === "favorites"
        ? t("items.favorites")
        : filter.view.kind === "trash"
          ? t("items.trash")
          : filter.view.kind === "passkeys"
            ? t("items.passkeys")
            : t(kindLabel(filter.view.value) as Key);
  const orgName =
    filter.org === undefined
      ? null
      : (catalog?.orgs.find((o) => o.id === filter.org)?.name ?? t("items.orgs"));
  const folderName =
    filter.folder === undefined
      ? null
      : filter.folder === null
        ? t("items.unfiled")
        : (catalog?.folders.find((f) => f.id === filter.folder)?.name ?? t("items.folders"));
  // The manifest of the current section: our own have none, and a foreign
  // plugin has the one the daemon sent. A section the daemon does not know at
  // all may not exist either: then a stand-in manifest is assembled, so that the
  // screen can say so.
  const tabPlugin = splitSection(tab);
  const manifest: Manifest | null = isCore(tab)
    ? null
    : (plugins.find((m) => m.id === tabPlugin.plugin) ?? {
        id: tabPlugin.plugin,
        title: tabPlugin.plugin,
        icon: "warn",
        section: true,
        needs_unlocked: false,
        version: "",
        description: "",
        origin: "external",
        enabled: true,
        permissions: [],
      });
  // What draws the tab: a plugin's main section or one of its further ones.
  const entry = manifest ? sectionView(tab) : null;
  const hasContext = tab === "vault" || tab === "settings" || Boolean(entry?.Context);
  // A switched-off one is not in the rail: it receives no events and answers
  // calls with an error — its section would open into emptiness. It comes back
  // through the same switch in the settings, at once and without a restart.
  // A plugin that probes decides itself whether its section applies here —
  // the Vaultwarden panel exists only on such a server — and it shows on a
  // yes.
  const livePlugins = plugins.filter((m) => m.enabled && (!m.probe || available[m.id] === true));
  // Each plugin's doors in the rail: its main section, then its further
  // ones.
  const sections = livePlugins.flatMap((m) => [
    ...(m.section ? [{ tab: m.id, icon: m.icon, label: pluginTitle(m) }] : []),
    ...(pluginEntry(m.id).sections ?? []).map((sec) => ({ tab: `${m.id}/${sec.id}`, icon: sec.icon, label: pluginSectionTitle(m, sec.id) })),
  ]);
  // A section's caption in the breadcrumbs and the header: for our own from
  // the dictionary, for a plugin the translation by its name, and failing that
  // the name from the manifest.
  const tabLabel = manifest
    ? tabPlugin.section
      ? pluginSectionTitle(manifest, tabPlugin.section)
      : pluginTitle(manifest)
    : tab === "vault"
      ? t("nav.items")
      : t(`nav.${tab}` as Key);

  const passkeyCount = catalog ? catalog.items.filter((i) => i.passkeys > 0 && !i.deleted).length : 0;

  // The breadcrumbs: where we are and where one press can take us back to.
  const crumbs: { label: string; onClick?: () => void }[] =
    tab === "vault"
      ? [
          ...(orgName !== null || folderName !== null || filter.view.kind !== "all"
            ? [{ label: t("nav.items"), onClick: () => setFilter({ view: { kind: "all" } }) }]
            : [{ label: t("nav.items") }]),
          ...(orgName !== null
            ? [{ label: orgName, onClick: () => setFilter({ ...filter, folder: undefined }) }]
            : []),
          ...(folderName !== null ? [{ label: folderName }] : []),
          ...(filter.view.kind !== "all" && folderName === null ? [{ label: viewName }] : []),
        ]
      : [{ label: tabLabel }];

  // The global creation action belongs exclusively to the item list. An open
  // card is a reading/editing surface, not a second place to start a new one.
  const addFab = tab === "vault" && !selected ? (
    <button type="button" className="fab" onClick={() => setAdding(true)} title={t("item.new")} aria-label={t("item.new")}>
      <Icon name="plus" size={18} />
    </button>
  ) : null;

  return (
    // A click past the account's menu closes it: a drop-down that cannot be
    // closed by missing it feels like a trap.
    <div className={`shell ${hasContext ? "" : "solo"}`} onMouseDown={() => menuOpen && setMenuOpen(false)}>
      {/* The strip for dragging the window. By an attribute rather than by
          CSS: -webkit-app-region is Electron's property, WKWebView does not
          understand it, and the window did not move. Tauri looks at
          data-tauri-drag-region. */}
      <div className="titlebar-drag" data-tauri-drag-region />
      {/* The narrow rail: the sections alone. Everything else is in the second
          column, and that depends on which section is chosen. The kinds,
          folders, organisations and collections used to lie in one heap under
          the sections' buttons, and the list had to be scrolled to reach the
          bottom. */}
      <aside className="rail">
        <div className="rail-head" data-tauri-drag-region />

        <nav className="sections">
          <RailItem
            icon="all"
            label={t("nav.items")}
            on={tab === "vault"}
            onClick={() => setTab("vault")}
          />
          {(status?.pending_edits ?? 0) > 0 && (
            <RailItem
              icon="warn"
              label={t("nav.edits")}
              on={tab === "edits"}
              onClick={() => setTab("edits")}
              badge={status?.pending_edits}
            />
          )}
          <RailItem
            icon="key"
            label={t("nav.generator")}
            on={tab === "generator"}
            onClick={() => setTab("generator")}
          />
          {/* The plugins' sections in the order the daemon listed them: after
              the items and before the settings. */}
          {sections.map((sec) => (
            <RailItem
              key={sec.tab}
              icon={sec.icon}
              label={sec.label}
              on={tab === sec.tab}
              onClick={() => setTab(sec.tab)}
            />
          ))}
          <RailItem
            icon="settings"
            label={t("nav.settings")}
            on={tab === "settings"}
            onClick={() => setTab("settings")}
          />
        </nav>

        <button type="button"
          className={`rail-account ${open ? "open" : ""}`}
          onMouseDown={(e) => e.stopPropagation()}
          onClick={() => setMenuOpen((v) => !v)}
          title={active?.account.email ?? ""}
          aria-label={active?.account.email ?? ""}
        >
          <span
            className="avatar"
            style={avatar?.color ? { background: avatar.color, color: inkOn(avatar.color) } : undefined}
          >
            {avatar?.initials ?? (active?.account.email ?? "?").slice(0, 1).toUpperCase()}
          </span>
          {/* The mark appears only when the vault is locked.
              A green "all is well" dot read as "online" and meant nothing: a
              state that is always on the screen stops being a message. The lock
              is in view when the lock is the news. */}
          {!open && (
            <span className="state shut" role="img" aria-label={t("state.locked")}>
              <Icon name="lock" size={9} />
            </span>
          )}
        </button>

        {menuOpen && accounts && (
          <div className="menu rail-menu" onMouseDown={(e) => e.stopPropagation()}>
            <div className="menu-head">
              <b>{active?.account.email ?? "—"}</b>
              <span>{active?.account.base_url.replace(/^https?:\/\//, "") ?? ""}</span>
            </div>
            {accounts.accounts
              .filter((a) => a.account.id !== accounts.active)
              .map((a) => (
                <button type="button"
                  key={a.account.id}
                  onClick={() => {
                    setMenuOpen(false);
                    void act("vault_switch_account", { id: a.account.id });
                  }}
                >
                  <Icon name="shield" size={13} />
                  {a.account.email}
                </button>
              ))}
            <div className="sep" />
            <button type="button"
              onClick={() => {
                setMenuOpen(false);
                setForceSetup(true);
              }}
            >
              <Icon name="plus" size={13} />
              {t("accounts.add")}
            </button>
            {accounts.active && (
              <button type="button"
                className="danger"
                onClick={() => {
                  setMenuOpen(false);
                  void act("vault_logout", { id: accounts.active });
                }}
              >
                <Icon name="lock" size={13} />
                {t("accounts.logout")}
              </button>
            )}
          </div>
        )}
      </aside>

      {hasContext && (
      <>
      {drawer && <div className="drawer-backdrop" onClick={() => setDrawer(false)} />}
      <aside
        className={`context ${drawer ? "drawer" : ""}`}
        onClick={(e) => {
          if (drawer && (e.target as HTMLElement).closest("button")) setDrawer(false);
        }}
      >
        <div className="context-head" data-tauri-drag-region>
          {tab === "vault" ? (
            <button type="button" className="spot-open" onClick={() => setSpot(true)}>
              <Icon name="search" size={13} />
              <span>{t("action.search")}</span>
              <kbd>{navigator.platform.startsWith("Mac") ? "⌘K" : "Ctrl+K"}</kbd>
            </button>
          ) : (
            <h2>{tabLabel}</h2>
          )}
        </div>

        <div className="context-body">
        {tab === "vault" && catalog && (
          <>
            <div className="group">
              <h4>{t("items.types")}</h4>
              <NavItem
                icon="all"
                label={t("items.all")}
                on={filter.view.kind === "all"}
                onClick={() => setFilter({ ...filter, view: { kind: "all" } })}
                count={total - catalog.trash}
              />
              {catalog.favorites > 0 && (
                <NavItem
                  icon="shield"
                  label={t("items.favorites")}
                  on={filter.view.kind === "favorites"}
                  onClick={() => setFilter({ ...filter, view: { kind: "favorites" } })}
                  count={catalog.favorites}
                />
              )}
              {passkeyCount > 0 && (
                <NavItem
                  icon="key"
                  label={t("items.passkeys")}
                  on={filter.view.kind === "passkeys"}
                  onClick={() => setFilter({ ...filter, view: { kind: "passkeys" } })}
                  count={passkeyCount}
                />
              )}
              {KIND_KEYS.map((k) => (
                <NavItem
                  key={k}
                  icon={k === "note" ? "note" : k}
                  label={t(kindLabel(k) as Key)}
                  on={filter.view.kind === "type" && filter.view.value === k}
                  onClick={() => setFilter({ ...filter, view: { kind: "type", value: k } })}
                  count={counts.get(k) ?? 0}
                />
              ))}
            </div>

            {/* Folders and organisations live here, with the items, rather than
                in sections of their own: a click slices the list, the "+" in
                the heading makes one, and the gear on a row looks after it —
                as a Bitwarden client does it. */}
            <div className="group">
              <h4 className="group-head">
                <span>{t("items.folders")}</span>
                <button type="button" className="group-add" title={t("folder.new")} aria-label={t("folder.new")} onClick={() => setFolderEditing(null)}>
                  <Icon name="plus" size={12} />
                </button>
              </h4>
              {catalog.folders.map((f) => (
                <NavItem
                  key={f.id}
                  dot={folderColor(f.name)}
                  label={f.name}
                  on={filter.folder === f.id}
                  onClick={() => setFilter({ ...filter, folder: filter.folder === f.id ? undefined : f.id })}
                  count={f.count}
                  action={{ title: t("folder.manage"), onClick: () => setFolderEditing(f) }}
                />
              ))}
              {catalog.unfiled > 0 && (
                <NavItem
                  dot="transparent"
                  label={t("items.unfiled")}
                  on={filter.folder === null}
                  onClick={() => setFilter({ ...filter, folder: filter.folder === null ? undefined : null })}
                  count={catalog.unfiled}
                />
              )}
            </div>

            <div className="group">
              <h4 className="group-head">
                <span>{t("items.orgs")}</span>
                <button type="button" className="group-add" title={t("org.new")} aria-label={t("org.new")} onClick={() => setNewOrg(true)}>
                  <Icon name="plus" size={12} />
                </button>
              </h4>
              {catalog.orgs.map((o) => (
                <NavItem
                  key={o.id}
                  icon="shield"
                  label={o.name}
                  hint={t(`org.role.${o.role}` as Key)}
                  on={filter.org === o.id}
                  // Switching organisations clears the folder: each has folders
                  // of its own, and keeping somebody else's shows emptiness.
                  onClick={() =>
                    setFilter(filter.org === o.id ? { ...filter, org: undefined, folder: undefined } : { ...filter, org: o.id, folder: undefined })
                  }
                  count={catalog.items.filter((i) => i.org_id === o.id && !i.deleted).length}
                  action={{ title: t("org.manage"), onClick: () => setOrgManaging(o.id) }}
                />
              ))}
            </div>

            {/* Always, even when empty: a section that disappears when there
                is nothing in it cannot be opened to make sure there is nothing
                in it. */}
            <div className="group">
              <NavItem
                icon="warn"
                label={t("items.trash")}
                on={filter.view.kind === "trash"}
                onClick={() => setFilter({ ...filter, view: { kind: "trash" } })}
                count={catalog.trash}
              />
            </div>
          </>
        )}

        {/* A plugin's section column is its own: the core does not know what
            is in it. */}
        {manifest && entry?.Context && (
          <entry.Context
            manifest={manifest}
            catalog={catalog}
            loading={loading}
            onChanged={() => void refresh(true)}
            onCopied={copied}
          />
        )}

        {tab === "settings" && (
          <div className="group">
            {SETTINGS_TABS.map((x) => (
              <NavItem
                key={x}
                icon={SETTINGS_ICON[x]}
                label={t(`settings.tab.${x}` as Key)}
                on={settingsTab === x}
                onClick={() => setSettingsTab(x)}
              />
            ))}
            {/* A plugin with settings of its own gets a page of its own, right
                after ours: they came from outside but live as equals. */}
            {settingsPlugins.length > 0 && <h4>{t("settings.tab.plugins")}</h4>}
            {settingsPlugins.map((m) => (
              <NavItem
                key={m.id}
                icon={m.icon}
                label={pluginSettingsTitle(m)}
                on={settingsTab === m.id}
                onClick={() => setSettingsTab(m.id)}
              />
            ))}
          </div>
        )}
        </div>
      </aside>
      </>
      )}

      <main className="main">
        <header className="head" data-tauri-drag-region>
          <nav className="crumbs" aria-label={t("nav.itemsTitle")}>
            {crumbs.map((c, i) => (
              <span key={c.label} className="crumb-part">
                {i > 0 && <Icon name="chevron" size={11} />}
                {c.onClick ? (
                  <button type="button" onClick={c.onClick}>{c.label}</button>
                ) : (
                  <b>{c.label}</b>
                )}
              </span>
            ))}
          </nav>
          <div className="tools">
            {/* The housekeeping actions come as one group on the glass rather
                than as two separate buttons: the main button stays the only
                one. */}
            <div className="tool-group" role="group">
              {/* The column's sections come as a drawer when the column is
                  hidden. Whether the button shows is CSS's business, by
                  width. */}
              {hasContext && (
                <button type="button" className="btn icon-only tool-menu" title={t("nav.sections")} aria-label={t("nav.sections")} onClick={() => setDrawer((v) => !v)}>
                  <Icon name="all" size={14} />
                </button>
              )}
              {/* The search is always to hand, on any screen and at any
                  width. */}
              {tab === "vault" && (
                <button type="button" className="btn icon-only tool-search" title={t("action.search")} onClick={() => setSpot(true)}>
                  <Icon name="search" size={14} />
                </button>
              )}
              <button type="button" className="btn icon-only" title={t("action.sync")} disabled={busy} onClick={() => void act("vault_sync")}>
                <Icon name="sync" size={14} />
              </button>
              <button type="button" className="btn icon-only" title={t("action.lock")} disabled={busy} onClick={() => void act("vault_lock")}>
                <Icon name="lock" size={14} />
              </button>
            </div>
          </div>
        </header>

        {tab === "vault" && catalog && (catalog.folders.length > 0 || catalog.orgs.length > 0) && (
          // Folders and organisations are a slice of the list rather than the
          // application's sections. As chips rather than drop-downs: there are
          // few of them, they are all in view at once, and choosing is one
          // press rather than two.
          <div className={`filters ${filtersOpen ? "open" : ""}`}>
            {/* One line: a caption, what is switched on just now and an
                arrow. The rows of chips unfold on a click, like an
                accordion. */}
            <button type="button" className="filters-bar" aria-expanded={filtersOpen} onClick={() => setFiltersOpen((v) => !v)}>
              <span className="filter-label">{t("items.filters")}</span>
              <span className="filters-summary">
                {filter.view.kind !== "all" && <span className="fchip on">{viewName}</span>}
                {folderName && <span className="fchip on">{folderName}</span>}
                {orgName && <span className="fchip on">{orgName}</span>}
                {filter.view.kind === "all" && !folderName && !orgName && <span className="hint">{t("items.filtersNone")}</span>}
              </span>
              <Icon name="chevron" size={13} />
            </button>
            <div className="filters-wrap" aria-hidden={!filtersOpen}>
            <div className="filters-body">
              {/* When the window is narrow and the sections' column is
                  hidden, the "all, favourites, kinds, trash" slices live here
                  — otherwise the trash could not be reached at all in a window
                  of the default size. */}
              <div className="filter-line view-line">
                <span className="filter-label">{t("items.view")}</span>
                <div className="chiprow">
                  <button type="button" className={`fchip ${filter.view.kind === "all" ? "on" : ""}`} onClick={() => setFilter({ ...filter, view: { kind: "all" } })}>
                    {t("items.all")}
                    <em>{total - catalog.trash}</em>
                  </button>
                  {catalog.favorites > 0 && (
                    <button type="button" className={`fchip ${filter.view.kind === "favorites" ? "on" : ""}`} onClick={() => setFilter({ ...filter, view: { kind: "favorites" } })}>
                      ★ {t("items.favorites")}
                      <em>{catalog.favorites}</em>
                    </button>
                  )}
                  {passkeyCount > 0 && (
                    <button type="button" className={`fchip ${filter.view.kind === "passkeys" ? "on" : ""}`} onClick={() => setFilter({ ...filter, view: { kind: "passkeys" } })}>
                      <Icon name="key" size={11} />
                      {t("items.passkeys")}
                      <em>{passkeyCount}</em>
                    </button>
                  )}
                  {KIND_KEYS.filter((k) => (counts.get(k) ?? 0) > 0).map((k) => (
                    <button
                      type="button"
                      key={k}
                      className={`fchip ${filter.view.kind === "type" && filter.view.value === k ? "on" : ""}`}
                      onClick={() => setFilter({ ...filter, view: { kind: "type", value: k } })}
                    >
                      {t(kindLabel(k) as Key)}
                      <em>{counts.get(k) ?? 0}</em>
                    </button>
                  ))}
                  <button type="button" className={`fchip trash ${filter.view.kind === "trash" ? "on" : ""}`} onClick={() => setFilter({ ...filter, view: { kind: "trash" } })}>
                    <Icon name="trash" size={11} />
                    {t("items.trash")}
                    <em>{catalog.trash}</em>
                  </button>
                </div>
              </div>

              <div className="filter-line">
                <span className="filter-label">{t("items.folders")}</span>
                <div className="chiprow">
                  <button type="button"
                    className={`fchip ${filter.folder === undefined ? "on" : ""}`}
                    onClick={() => setFilter({ ...filter, folder: undefined })}
                  >
                    {t("items.all")}
                  </button>
                  {catalog.folders.map((f) => {
                    const on = filter.folder === f.id;
                    return (
                    <button type="button"
                      key={f.id}
                      className={`fchip ${on ? "on" : ""}`}
                      // A second press on a chip that is on takes the slice
                      // off: otherwise the only way out of a folder is through
                      // "All items", which is one more aim of the mouse.
                      // The folder goes back to "any", the organisation is left
                      // alone.
                      onClick={() => setFilter({ ...filter, folder: on ? undefined : f.id })}
                    >
                      <span className="dot" aria-hidden="true" style={{ background: folderColor(f.name) }} />
                      {f.name}
                      <em>{f.count}</em>
                    </button>
                    );
                  })}
                  {catalog.unfiled > 0 && (
                    <button type="button"
                      className={`fchip ${filter.folder === null ? "on" : ""}`}
                      onClick={() => setFilter({ ...filter, folder: filter.folder === null ? undefined : null })}
                    >
                      <span className="dot hollow" aria-hidden="true" />
                      {t("items.unfiled")}
                      <em>{catalog.unfiled}</em>
                    </button>
                  )}
                </div>
              </div>

              {catalog.orgs.length > 0 && (
                // On a line of its own: an organisation is not a folder but
                // whose vault it is, and in one row with the folders they read
                // as a single list.
                <div className="filter-line">
                  <span className="filter-label">{t("items.orgs")}</span>
                  <div className="chiprow">
                    {catalog.orgs.map((o) => {
                      const on = filter.org === o.id;
                      return (
                        <button type="button"
                          key={o.id}
                          className={`fchip ${on ? "on" : ""}`}
                          // Switching organisations clears the folder: each
                          // has folders of its own, and keeping somebody else's
                          // means showing emptiness.
                          onClick={() =>
                            setFilter(
                              on
                                ? { ...filter, org: undefined, folder: undefined }
                                : { ...filter, org: o.id, folder: undefined },
                            )
                          }
                          title={o.role}
                        >
                          <Icon name="identity" size={12} />
                          {o.name}
                        </button>
                      );
                    })}
                    {/* Creating lives in the organisations' own section:
                        here the row only slices the list. */}
                  </div>
                </div>
              )}
            </div>
            </div>
          </div>
        )}

        <div className={`content ${tab === "vault" || entry?.flush ? "flush" : ""}`}>
          {error && <Alert message={error} onRetry={() => void refresh(true)} />}
          {tab === "vault" && (
            <div className={selected ? "with-pane" : ""}>
              <VaultScreen
                catalog={catalog}
                filter={filter}
                query=""
                loading={loading}
                selected={selected}
                // A second press on the same item closes the card.
                onSelect={(id) =>
                  setSelected((cur) => {
                    if (cur === id) return null;
                    // What is opened goes into the recent ones — that is what
                    // the search shows before the first letter is typed.
                    void invoke("remember_opened", { entryId: id }).catch(() => {});
                    return id;
                  })
                }
                serverUrl={settings?.show_website_icons === false ? "" : (active?.account.base_url ?? "")}
                onCopied={copied}
                onChanged={() => void refresh(true)}
              />
              {selected && (
                <DetailPane
                  entryId={selected}
                  serverUrl={settings?.show_website_icons === false ? "" : (active?.account.base_url ?? "")}
                  onCopied={copied}
                  onClose={() => setSelected(null)}
                  onChanged={() => void refresh(true)}
                />
              )}
            </div>
          )}
          {tab === "generator" && <GeneratorScreen onCopied={copied} />}
          {manifest &&
            entry &&
            (manifest.needs_unlocked && !open ? (
              // A plugin needs an open vault: with no keys it has nothing to
              // show.
              <Empty icon="lock" title={t("unlock.title")} body={t("plugin.locked", { title: tabLabel })} />
            ) : (
              <entry.Screen
                manifest={manifest}
                catalog={catalog}
                loading={loading}
                onChanged={() => void refresh(true)}
                onCopied={copied}
              />
            ))}
          {tab === "edits" && <EditsScreen onChanged={() => void refresh(true)} />}
          {tab === "settings" && status && (
            <SettingsScreen
              tab={settingsTab}
              status={status}
              accounts={accounts}
              onChanged={() => void refresh(true)}
              onAddAccount={() => setForceSetup(true)}
              onSettingsChanged={setSettings}
              onCopied={copied}
              hold={(on) => {
                held.current = on;
              }}
            />
          )}
        </div>
      </main>
      {folderEditing !== undefined && (
        <FolderEditor
          folder={folderEditing}
          onClose={() => setFolderEditing(undefined)}
          onChanged={() => {
            // A deleted folder cannot stay the slice.
            if (folderEditing && filter.folder === folderEditing.id) setFilter({ ...filter, folder: undefined });
            void refresh(true);
          }}
        />
      )}
      {orgManaging && catalog && (
        <OrgManager catalog={catalog} orgId={orgManaging} onClose={() => setOrgManaging(null)} onChanged={() => void refresh(true)} />
      )}
      {newOrg && (
        <NewOrg onClose={() => setNewOrg(false)} onCreated={() => void refresh(true)} />
      )}

      {adding && (
        <NewItem catalog={catalog} onClose={() => setAdding(false)} onCreated={() => void refresh(true)} />
      )}

      {addFab}

      {spot && (
        <Spotlight
          catalog={catalog}
          serverUrl={settings?.show_website_icons === false ? "" : (active?.account.base_url ?? "")}
          fill={fill}
          onFill={(id, mode) => {
            void invoke("autofill_fill", { entryId: id, mode, submit: false })
              .then(() => {
                const name = catalog?.items.find((i) => i.id === id)?.name ?? "";
                push(t("autofill.done", { name }));
                void invoke("remember_opened", { entryId: id }).catch(() => {});
              })
              .catch((e) => push(tError(String(e))));
          }}
          onPick={(id) => {
            setTab("vault");
            setSelected(id);
            void invoke("remember_opened", { entryId: id }).catch(() => {});
          }}
          onClose={() => {
            setSpot(false);
            setFill(null);
          }}
        />
      )}

      <Toasts toasts={toasts} />
    </div>
  );
}

/// A section's button in the narrow rail: the icon alone, the caption as a
/// tooltip. The tooltip is ours (`data-tip` + CSS) rather than the native
/// `title`: the system's appears a second later somewhere near the cursor,
/// ours at once to the right of the button, where a section's name is
/// expected.
function RailItem({
  icon,
  label,
  on,
  onClick,
  badge,
}: {
  icon: string;
  label: string;
  on: boolean;
  onClick: () => void;
  badge?: number;
}) {
  return (
    <button type="button" className={`rail-item ${on ? "on" : ""}`} onClick={onClick} data-tip={label} aria-label={label}>
      <Icon name={icon} size={17} />
      {badge !== undefined && badge > 0 && <span className="badge">{badge}</span>}
    </button>
  );
}

function NavItem({
  icon,
  dot,
  label,
  hint,
  on,
  onClick,
  count,
  action,
}: {
  icon?: string;
  /// A coloured mark in place of an icon — that is how folders are made.
  dot?: string;
  label: string;
  hint?: string;
  on: boolean;
  onClick: () => void;
  count?: number;
  /// A gear at the row's end, in place of the count on hover: looking after
  /// the thing rather than slicing by it.
  action?: { title: string; onClick: () => void };
}) {
  const row = (
    <button type="button"
      className={`nav ${on ? "on" : ""} ${dot ? "with-dot" : ""}`}
      onClick={onClick}
      title={hint ? `${label} · ${hint}` : label}
    >
      {dot ? (
        <span
          className="dot"
          aria-hidden="true"
          style={{ background: dot, borderColor: dot === "transparent" ? "var(--faint)" : dot }}
        />
      ) : (
        <Icon name={icon ?? "all"} />
      )}
      <span className="label">{label}</span>
      {count !== undefined && <span className="count">{count}</span>}
    </button>
  );
  if (!action) return row;
  return (
    <div className="nav-row">
      {row}
      <button
        type="button"
        className="nav-act"
        title={action.title}
        aria-label={action.title}
        onClick={(e) => {
          e.stopPropagation();
          action.onClick();
        }}
      >
        <Icon name="settings" size={13} />
      </button>
    </div>
  );
}
