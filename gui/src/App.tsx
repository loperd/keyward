import { useCallback, useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import type { FillContext } from "./Spotlight";
import { ActivityBar, Alert, Count, Empty, Icon, Toasts, useEscape, useToasts, withTransition } from "./ui";
import { folderColor } from "./folders";
import { Gate, type GateBack } from "./Gate";
import { applyAccent, watchScheme } from "./accent";
import { installOverlayScrollbars } from "./overlayScroll";
import { Spotlight } from "./Spotlight";
import { NewItem } from "./screens/NewItem";
import { NewOrg } from "./screens/NewOrg";
import { OrgManager } from "./screens/Orgs";
import { FolderEditor } from "./screens/Folders";
import { type Filter } from "./screens/Vault";
import { GeneratorScreen } from "./screens/Generator";
import { PROFILE_EVENT, SETTINGS_ICON, SettingsScreen } from "./screens/Settings";
import { call, pluginSettingsTitle, pluginTitle, refreshPlugins, usePlugins, type Manifest } from "./plugins/call";
import { pluginEntry } from "./plugins";
import type { AccountProfile } from "./types";
import { EditsScreen } from "./screens/Edits";
import { VaultDesk, type DeskLocation } from "./VaultDesk";
import type { LocalChange } from "./screens/Detail";
import { Chrome } from "./Chrome";
import { LANG_EVENT, setLanguage, t, tError } from "./i18n";
import type { Key } from "./i18n";
import { PairPrompt } from "./PairPrompt";
import { useContextFolded } from "./declared/layout";
import type { AppSettings } from "./types";
import { KIND_KEYS, kindLabel, type AccountList, type Catalog, type Status } from "./types";

const POLL_MS = 4000;

/// A place in the window: a section, and where in the vault.
type Place = { tab: string; desk: DeskLocation };
const samePlace = (a: Place, b: Place) =>
  a.tab === b.tab && a.desk.mode === b.desk.mode && a.desk.objectId === b.desk.objectId && a.desk.relationRoot === b.desk.relationRoot;

/// The longest the window waits on a daemon that is coming up before it says
/// the socket will not come up.
const STARTUP_MS = 45_000;

type DaemonProbe = { state: "answers" } | { state: "starting" } | { state: "down"; reason: string };

/// Asks why the daemon did not answer. A start that goes on past `STARTUP_MS`
/// is no longer a start.
async function probeDaemon(since: { current: number | null }): Promise<DaemonProbe> {
  let p: DaemonProbe;
  try {
    p = await invoke<DaemonProbe>("daemon_probe");
  } catch (e) {
    return { state: "down", reason: String(e) };
  }
  if (p.state !== "starting") {
    since.current = null;
    return p;
  }
  since.current ??= Date.now();
  return Date.now() - since.current > STARTUP_MS ? { state: "down", reason: `err.daemonNeverUp {"seconds":"${Math.round(STARTUP_MS / 1000)}"}` } : p;
}

/// The settings' sections: the list on the left, the contents on the right.
///
/// Each is a page of its own rather than a piece of one long one: safety, the
/// application, the plugins and the help used to lie in one scroll, and
/// reaching the bottom meant leafing past everything else.
const SETTINGS_TABS = ["account", "security", "preferences", "app", "plugins", "about"] as const;
type SettingsTab = string;
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
  const settingsPlugins = plugins.filter((m) => m.enabled && pluginEntry(m).SettingsSection);
  // The section can be given by the hash: that way the stand opens straight on
  // the screen wanted, while in the application there is no hash and the
  // behaviour is as it was.
  const [tab, setTab] = useState<Tab>(() => window.location.hash.replace("#", "") || "vault");
  // Where in the vault one is: the ledger, an object, its relations.
  const [desk, setDesk] = useState<DeskLocation>({ mode: "inventory" });
  // One history for the whole window, across sections and the vault's modes
  // alike: it watches where the window is, so every way of getting somewhere
  // — the menu, ⌘K, a toast — is in it without remembering to push.
  const history = useRef<{ back: Place[]; forward: Place[]; travelling: boolean; last: Place | null }>({ back: [], forward: [], travelling: false, last: null });
  const [, redrawHistory] = useState(0);
  useEffect(() => {
    const h = history.current;
    const here: Place = { tab, desk };
    if (h.last && !h.travelling && !samePlace(h.last, here)) {
      h.back.push(h.last);
      h.forward = [];
    }
    h.travelling = false;
    h.last = here;
    redrawHistory((n) => n + 1);
  }, [tab, desk]);
  const travel = (from: "back" | "forward") => {
    const h = history.current;
    const to = h[from].pop();
    if (!to || !h.last) return;
    (from === "back" ? h.forward : h.back).push(h.last);
    h.travelling = true;
    setTab(to.tab);
    setDesk(to.desk);
  };
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
    const live = plugins.find((m) => m.id === tab);
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
  // Why the daemon does not answer: coming up, or not coming up at all.
  const [probe, setProbe] = useState<DaemonProbe | null>(null);
  const waitingSince = useRef<number | null>(null);
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

  // A change to the list made at once, before the server's answer: the item
  // leaves the ledger and enters the trash (or the reverse) the moment it is
  // pressed. The returned `undo` puts the list back if the server refuses;
  // `settle` lets polling resume.
  const changeLocally = useCallback((change: LocalChange) => {
    pendingLocal.current += 1;
    setPendingN((n) => n + 1);
    let before: Catalog | null = null;
    withTransition(() =>
      setCatalog((c) => {
        before = c;
        if (!c) return c;
        const was = c.items.find((i) => i.id === change.id);
        if (!was) return c;
        if (change.kind === "purged") return { ...c, items: c.items.filter((i) => i.id !== change.id), trash: was.deleted ? c.trash - 1 : c.trash };
        const deleted = change.kind === "trashed";
        if (was.deleted === deleted) return c;
        return { ...c, items: c.items.map((i) => (i.id === change.id ? { ...i, deleted } : i)), trash: c.trash + (deleted ? 1 : -1) };
      }),
    );
    let settled = false;
    const settle = () => {
      if (!settled) {
        pendingLocal.current -= 1;
        setPendingN((n) => n - 1);
      }
      settled = true;
    };
    return { undo: () => withTransition(() => setCatalog(before)), settle };
  }, []);

  /// The desk's writes: shown at once, confirmed by the server after.
  const deskWrite = async (kind: LocalChange["kind"], ids: string[]) => {
    const locals = ids.map((id) => changeLocally({ kind, id }));
    push(t(kind === "trashed" ? "item.trashed" : kind === "restored" ? "item.restored" : "item.purged"), kind === "restored" ? "restore" : "trash");
    try {
      if (kind === "purged") await invoke("purge_items", { entryIds: ids });
      else for (const id of ids) await invoke(kind === "trashed" ? "trash_item" : "restore_item", { entryId: id });
    } catch (e) {
      [...locals].reverse().forEach((l) => l.undo());
      push(tError(String(e)), "error");
    } finally {
      locals.forEach((l) => l.settle());
      void refresh(true);
    }
  };

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
  /// Changes shown before the server has confirmed them.
  const pendingLocal = useRef(0);
  // The same count as state, for the activity bar to show.
  const [pendingN, setPendingN] = useState(0);

  // The signature of the vault's state: while it has not changed there is no
  // point re-reading the contents — polling every four seconds must not jog the
  // decryption.
  const signature = useRef("");

  const refresh = useCallback(async (force = false) => {
    try {
      const s = await invoke<Status>("daemon_status");
      setStatus(s);
      setError(null);
      setProbe(null);
      waitingSince.current = null;
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
      setProbe(await probeDaemon(waitingSince));
    } finally {
      setLoading(false);
    }
  }, []);

  // While the daemon comes up it is asked every second, not every four: the
  // loader gives way to the window as soon as the socket answers.
  useEffect(() => {
    if (probe?.state !== "starting") return;
    const id = window.setTimeout(() => void refresh(true), 1000);
    return () => window.clearTimeout(id);
  }, [probe, refresh]);

  useEffect(() => {
    void refresh(true);
    const id = setInterval(() => {
      // Not while a change made here waits for the server: the daemon would
      // answer with the list from before it, and the item would come back.
      if (!held.current && pendingLocal.current === 0) void refresh();
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
  // A drawer asks for the section's column to step aside while it is open.
  // A hook: above every early return, or the gate screens draw fewer hooks.
  const contextFolded = useContextFolded();
  // The way out of a gate: out of a setup opened over a working vault, or
  // back to another account — the one that opens, before one that does not.
  const otherAccount = (accounts?.accounts ?? [])
    .filter((a) => a.account.id !== accounts?.active)
    .sort((a, b) => Number(b.state.state === "unlocked" || b.state.state === "locked") - Number(a.state.state === "unlocked" || a.state.state === "locked"))[0];
  // A setup opened by hand closes back to where it was opened from; a login
  // or unlock of an account goes back to another one.
  const gateBack: GateBack | null = forceSetup
    ? { label: t("action.cancel"), go: () => setForceSetup(false) }
    : otherAccount
      ? {
          label: t("gate.backTo", { name: otherAccount.account.email }),
          go: () => {
            void invoke("vault_switch_account", { id: otherAccount.account.id }).then(() => refresh(true));
          },
        }
      : null;

  // The daemon does not answer — the one state that overrides everything:
  // without it neither the vault nor ssh works.
  if (!status && (loading || probe?.state === "starting")) {
    return (
      <div className="gate">
        <div className="gate-card gate-wait" role="status" aria-live="polite">
          <span className="spinner" />
          <span>{t("daemon.starting")}</span>
        </div>
      </div>
    );
  }
  if (!status) {
    // The reason is the probe's when it found one; when the socket answers
    // and refuses, it is the daemon's own error.
    const reason = probe?.state === "down" ? probe.reason : error;
    return (
      <div className="gate">
        <div className="gate-card">
          <Empty icon="warn" title={t("daemon.down.title")} body={t("daemon.down.body")} />
          {reason && <Alert message={reason} onRetry={() => void refresh(true)} />}
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
        onEditSetup={() => setForceSetup(true)}
        back={gateBack}
      />
    );
  }

  const counts = new Map(catalog?.counts ?? []);
  const total = catalog?.items.length ?? 0;
  const active = accounts?.accounts.find((a) => a.account.id === accounts.active);
  // The manifest of the current section: our own have none, and a foreign
  // plugin has the one the daemon sent. A section the daemon does not know at
  // all may not exist either: then a stand-in manifest is assembled, so that the
  // screen can say so.
  const manifest: Manifest | null = isCore(tab)
    ? null
    : (plugins.find((m) => m.id === tab) ?? {
        id: tab,
        title: tab,
        icon: "warn",
        section: true,
        needs_unlocked: false,
        version: "",
        description: "",
        origin: "external",
        enabled: true,
        permissions: [],
      });
  const entry = manifest ? pluginEntry(manifest) : null;
  // The vault has no column: its ledger is the whole plane. A section keeps
  // one only where it has something to list beside its screen.
  const hasContext = !contextFolded && (tab === "settings" || Boolean(entry?.Context));
  // A switched-off one is not in the rail: it receives no events and answers
  // calls with an error — its section would open into emptiness. It comes back
  // through the same switch in the settings, at once and without a restart.
  // A plugin that probes decides itself whether its section applies here —
  // the Vaultwarden panel exists only on such a server — and it shows on a
  // yes.
  const sections = plugins.filter((m) => m.section && m.enabled && (!m.probe || available[m.id] === true));
  // A section's caption in the breadcrumbs and the header: for our own from
  // the dictionary, for a plugin the translation by its name, and failing that
  // the name from the manifest.
  const tabLabel = manifest
    ? pluginTitle(manifest)
    : tab === "vault"
      ? t("nav.items")
      : t(`nav.${tab}` as Key);

  const passkeyCount = catalog ? catalog.items.filter((i) => i.passkeys > 0 && !i.deleted).length : 0;

  return (
    // A click past the account's menu closes it: a drop-down that cannot be
    // closed by missing it feels like a trap.
    <div className={`shell ${hasContext ? "" : "solo"}`} onMouseDown={() => menuOpen && setMenuOpen(false)}>
      {/* The strip for dragging the window. By an attribute rather than by
          CSS: -webkit-app-region is Electron's property, WKWebView does not
          understand it, and the window did not move. Tauri looks at
          data-tauri-drag-region. */}
      <Chrome
        sections={[
          { id: "vault", icon: "all", label: t("nav.items") },
          ...((status?.pending_edits ?? 0) > 0 ? [{ id: "edits", icon: "warn", label: t("nav.edits"), badge: status?.pending_edits }] : []),
          { id: "generator", icon: "key", label: t("nav.generator") },
          ...sections.map((m) => ({ id: m.id, icon: m.icon, label: pluginTitle(m) })),
          { id: "settings", icon: "settings", label: t("nav.settings") },
        ]}
        current={tab}
        onSection={(id) => setTab(id)}
        accounts={accounts}
        avatar={avatar}
        unlocked={open}
        canBack={history.current.back.length > 0}
        canForward={history.current.forward.length > 0}
        onBack={() => travel("back")}
        onForward={() => travel("forward")}
        onSearch={tab === "vault" ? () => setSpot(true) : null}
        onSync={tab === "vault" ? () => void act("vault_sync") : null}
        onLock={() => void act("vault_lock")}
        busy={busy}
        onSwitchAccount={(id) => void act("vault_switch_account", { id })}
        onAddAccount={() => setForceSetup(true)}
        onLogout={(id) => void act("vault_logout", { id })}
      />
      <PairPrompt unlocked={open} />
      {hasContext && (
      <>
      {drawer && <div className="drawer-backdrop" onClick={() => setDrawer(false)} />}
      <aside
        className={`context ${drawer ? "drawer" : ""}`}
        onClick={(e) => {
          if (drawer && (e.target as HTMLElement).closest("button")) setDrawer(false);
        }}
      >

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

        <div className={`content ${tab === "vault" || entry?.flush ? "flush" : ""}`}>
          {error && <Alert message={error} onRetry={() => void refresh(true)} />}
          {tab === "vault" && (
            <VaultDesk
              catalog={catalog}
              loading={loading}
              location={desk}
              onNavigate={(to, opts) => {
                // A tab switched to is no step of the history.
                if (opts?.passive) history.current.travelling = true;
                setDesk(to);
              }}
              onCreate={() => setAdding(true)}
              onChanged={() => void refresh(true)}
              onNotice={push}
              onTrash={(ids) => void deskWrite("trashed", ids)}
              onRestore={(id) => void deskWrite("restored", [id])}
              onPurge={(id) => void deskWrite("purged", [id])}
            />
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
      <ActivityBar on={busy || pendingN > 0} />
    </div>
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
      {count !== undefined && <Count n={count} />}
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
