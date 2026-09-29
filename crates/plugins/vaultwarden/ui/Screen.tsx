import "./style.css";
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Alert, DangerZone, EmailChips, Empty, Icon, Modal, Monogram, NumberInput, Picker, Section, Segmented, Skeleton, Tabs, Toggle, useEscape } from "@keyward/ui";
import { PasswordInput } from "@keyward/PasswordInput";
import { t } from "@keyward/i18n";
import { call } from "@keyward/plugins/call";
import type { PluginScreenProps } from "@keyward/plugins/types";
import type { OrgAbilities, OrgMember, OrgRole } from "@keyward/types";
import type { ActionView, AdminOrg, AdminUser, Choice, Setting, SettingsGroup, UsersOut } from "./types";

type View = "users" | "orgs" | "settings" | "tools";

type Status = { panel: string | null; unlocked: boolean };

/// Vaultwarden's admin panel — part of the server the account is on. The
/// section shows only when the plugin found the panel there; it is unlocked by
/// pasting the admin token, which the plugin keeps in the keychain. What can
/// be done and to whom arrives with the answers — the window only draws it.
export function VaultwardenScreen({ catalog }: PluginScreenProps) {
  const [status, setStatus] = useState<Status | null>(null);
  const [view, setView] = useState<View>("users");
  // The person whose own screen is open, over the tabs.
  const [person, setPerson] = useState<string | null>(null);
  const [stateFilter, setStateFilter] = useState<StateFilter>("all");
  // Likewise the organisation whose page is open.
  const [orgOpen, setOrgOpen] = useState<string | null>(null);
  // How tall the pinned tabs are, for what pins under them — the settings'
  // bar — measured rather than guessed.
  const tabsRef = useRef<HTMLDivElement | null>(null);
  const rootRef = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    const tabs = tabsRef.current;
    const root = rootRef.current;
    if (!tabs || !root) return;
    const put = () => root.style.setProperty("--vw-under-tabs", `${tabs.getBoundingClientRect().height}px`);
    put();
    const ro = new ResizeObserver(put);
    ro.observe(tabs);
    return () => ro.disconnect();
  });
  const [users, setUsers] = useState<UsersOut | null>(null);
  const [orgs, setOrgs] = useState<AdminOrg[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(() => {
    void call<Status>("vaultwarden", "status")
      .then(setStatus)
      .catch((e) => setError(String(e)));
  }, []);
  useEffect(reload, [reload]);

  const load = useCallback(() => {
    setError(null);
    void call<UsersOut>("vaultwarden", "users")
      .then(setUsers)
      .catch((e) => setError(String(e)));
    void call<AdminOrg[]>("vaultwarden", "orgs")
      .then(setOrgs)
      .catch(() => {});
  }, []);
  useEffect(() => {
    if (status?.unlocked) load();
  }, [status?.unlocked, load]);

  // The person is looked up in the fresh list: an action changes them, and
  // the screen shows them as the server has them now.
  const open = person ? (users?.users.find((u) => u.id === person) ?? null) : null;
  const openOrg = orgOpen ? (orgs?.find((o) => o.id === orgOpen) ?? null) : null;

  if (!status) return error ? <Alert message={error} onRetry={reload} /> : <Skeleton rows={5} />;
  if (!status.unlocked) return <Unlock panel={status.panel} onUnlocked={reload} />;

  return (
    <div className="settings vw" ref={rootRef}>
      <div className="vw-head">
        <span className="glyph"><Icon name="shield" size={16} /></span>
        <span className="vw-title">
          <b>{t("plugin.vaultwarden.title")}</b>
          <span className="hint">{status.panel}</span>
        </span>
        <span className="grow" />
        <button type="button" className="btn" onClick={load} title={t("action.sync")}>
          <Icon name="sync" size={13} />
          {t("vwadmin.refresh")}
        </button>
      </div>
      {error && <Alert message={error} onRetry={load} />}
      {open && users ? (
        <UserPage user={open} roles={users.assignable_roles} onBack={() => setPerson(null)} onChanged={load} />
      ) : openOrg && users ? (
        <OrgPage
          org={openOrg}
          roles={users.assignable_roles}
          mine={catalog?.orgs.find((o) => o.id === openOrg.id)?.can ?? null}
          serverEmails={users.users.map((u) => u.email)}
          onBack={() => setOrgOpen(null)}
          onChanged={load}
        />
      ) : (
        <>
      <div className="vw-tabs" ref={tabsRef}>
      <Tabs
        value={view}
        onChange={setView}
        options={[
          { id: "users", label: t("vwadmin.users"), count: users?.users.length },
          { id: "orgs", label: t("vwadmin.orgs"), count: orgs?.length },
          { id: "settings", label: t("vwadmin.settings") },
          { id: "tools", label: t("vwadmin.tools") },
        ]}
      />
      </div>
      {view === "users" && (users ? <Users data={users} state={stateFilter} onState={setStateFilter} onOpen={setPerson} onChanged={load} /> : !error && <Skeleton rows={6} />)}
      {view === "orgs" && (orgs ? <Orgs orgs={orgs} onOpen={setOrgOpen} /> : <Skeleton rows={4} />)}
      {view === "settings" && <Settings />}
      {view === "tools" && <Tools onLocked={reload} />}
        </>
      )}
    </div>
  );
}

/// Unlocking: the admin token and nothing else — the panel is the account's
/// server's own. The token is tried before it is kept.
function Unlock({ panel, onUnlocked }: { panel: string | null; onUnlocked: () => void }) {
  const [token, setToken] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const unlock = async () => {
    setBusy(true);
    setError(null);
    try {
      await call("vaultwarden", "unlock", { token });
      setToken("");
      onUnlocked();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="settings vw vw-unlock">
      <Empty icon="lock" title={t("vwadmin.unlockTitle")} body={t("vwadmin.unlockBody")} />
      <form
        className="vw-connect"
        onSubmit={(e) => {
          e.preventDefault();
          void unlock();
        }}
      >
        {panel && <span className="hint mono">{panel}</span>}
        <div className="field">
          <label>{t("vwadmin.token")}</label>
          <PasswordInput value={token} onChange={setToken} autoFocus ariaLabel={t("vwadmin.token")} />
          <span className="hint">{t("vwadmin.tokenHint")}</span>
        </div>
        {error && <Alert message={error} />}
        <div className="block-actions">
          <button type="submit" className="btn primary" disabled={busy || !token.trim()}>
            <Icon name="lock" size={13} />
            {busy ? t("vwadmin.unlocking") : t("vwadmin.unlock")}
          </button>
        </div>
      </form>
    </div>
  );
}

// -- Users -------------------------------------------------------------------

/// What the list is narrowed to: a state, or those without a second factor.
type StateFilter = "all" | AdminUser["state"] | "no_two_factor";

/// Whether the person has a second factor — shown either way, so its absence
/// is as visible as its presence.
function TwoFactorChip({ on }: { on: boolean }) {
  return (
    <span className={`chip vw-2fa ${on ? "on" : "off"}`}>
      <Icon name="key" size={11} />
      {t(on ? "vwadmin.twoFactorOn" : "vwadmin.twoFactorOff")}
    </span>
  );
}

/// The users: a list to find someone in, each row the way to that person's
/// own screen.
function Users({
  data,
  state,
  onState,
  onOpen,
  onChanged,
}: {
  data: UsersOut;
  state: StateFilter;
  onState: (s: StateFilter) => void;
  onOpen: (id: string) => void;
  onChanged: () => void;
}) {
  const [query, setQuery] = useState("");
  const setState = onState;
  const [inviting, setInviting] = useState(false);
  const counts = useMemo(() => {
    const c: Record<StateFilter, number> = { all: data.users.length, enabled: 0, invited: 0, disabled: 0, no_two_factor: 0 };
    for (const u of data.users) {
      c[u.state] += 1;
      if (!u.two_factor) c.no_two_factor += 1;
    }
    return c;
  }, [data.users]);
  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    return data.users.filter(
      (u) =>
        (state === "all" || u.state === state || (state === "no_two_factor" && !u.two_factor)) && (!q || u.email.toLowerCase().includes(q) || (u.name ?? "").toLowerCase().includes(q)),
    );
  }, [data.users, query, state]);
  const filters: StateFilter[] = ["all", "enabled", "invited", "disabled", "no_two_factor"];
  return (
    <>
      <div className="vw-toolbar">
        <div className="search vw-search">
          <Icon name="search" size={13} />
          <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder={t("vwadmin.findUser")} spellCheck={false} />
        </div>
        <button type="button" className="btn primary" onClick={() => setInviting(true)}>
          <Icon name="plus" size={13} />
          {t("vwadmin.invite")}
        </button>
      </div>
      <div className="chiprow vw-filters">
        {filters
          .filter((f) => f === "all" || counts[f] > 0)
          .map((f) => (
            <button key={f} type="button" className={`fchip ${state === f ? "on" : ""}`} onClick={() => setState(f)}>
              {f === "all" ? t("vwadmin.everyone") : f === "no_two_factor" ? t("vwadmin.twoFactorOff") : t(`vwadmin.state.${f}` as never)}
              <em>{counts[f]}</em>
            </button>
          ))}
      </div>
      {shown.length === 0 ? (
        <Empty icon="search" title={t("vwadmin.noUsers")} />
      ) : (
        <div className="list vw-list">
          {shown.map((u) => {
            const label = u.name ?? u.email;
            return (
              <div key={u.id} className="vw-row-line">
              <button type="button" className="row plain vw-row" onClick={() => onOpen(u.id)}>
                <Monogram name={label} size={32} />
                <span className="text">
                  <b>{label}</b>
                  <span>
                    {[u.name ? u.email : null, u.last_active ? t("vwadmin.lastActive", { when: u.last_active }) : t("vwadmin.neverActive")]
                      .filter(Boolean)
                      .join(" · ")}
                  </span>
                </span>
                <span className="side">
                  {u.state !== "enabled" && <span className={`chip vw-state-${u.state}`}>{t(`vwadmin.state.${u.state}` as never)}</span>}
                  <TwoFactorChip on={u.two_factor} />
                  {u.memberships.length > 0 && (
                    <span className="chip" title={u.memberships.map((m) => m.org_name).join(", ")}>
                      <Icon name="shield" size={11} />
                      {u.memberships.length}
                    </span>
                  )}
                  <Icon name="chevron" size={13} />
                </span>
              </button>
              <RowMenu user={u} onChanged={onChanged} />
              </div>
            );
          })}
        </div>
      )}
      {inviting && <Invite onClose={() => setInviting(false)} onDone={onChanged} />}
    </>
  );
}

/// One person on the server: who they are, where they are a member and in
/// what role, and what can be done to them — the careful actions apart, in
/// the danger zone. Which action is which the plugin says.
function UserPage({
  user,
  roles,
  onBack,
  onChanged,
}: {
  user: AdminUser;
  roles: OrgRole[];
  onBack: () => void;
  onChanged: () => void;
}) {
  const [asking, setAsking] = useState<ActionView | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const run = async (fn: () => Promise<unknown>, after?: () => void) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
      setAsking(null);
      after?.();
      onChanged();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };
  const doAction = (a: ActionView) =>
    // A deleted user has no screen left to stand on.
    run(() => call("vaultwarden", "user_action", { user_id: user.id, action: a.action }), a.action === "delete" ? onBack : undefined);
  const act = (a: ActionView) => (a.confirm ? setAsking(a) : void doAction(a));
  const label = user.name ?? user.email;
  // Escape leads back to the list, like the link above.
  useEscape(onBack);
  const plain = user.actions.filter((a) => !a.danger);
  const danger = user.actions.filter((a) => a.danger);
  return (
    <>
      <button type="button" className="vw-back" onClick={onBack}>
        <Icon name="chevron" size={12} />
        {t("vwadmin.users")}
      </button>
      <div className="vw-person">
        <Monogram name={label} size={48} />
        <span className="vw-title">
          <b>{label}</b>
          {user.name && <span className="hint">{user.email}</span>}
        </span>
        <span className="side">
          <span className={`chip vw-state-${user.state}`}>{t(`vwadmin.state.${user.state}` as never)}</span>
          <TwoFactorChip on={user.two_factor} />
        </span>
      </div>
      {error && <Alert message={error} />}

      <div className="vw-page">
      <div className="vw-page-main">
      {plain.length > 0 && (
        <Section title={t("vwadmin.access")} tone="mint">
          <div className="vw-actions">
            {plain.map((a) => (
              <button key={a.action} type="button" className="btn" disabled={busy} onClick={() => act(a)}>
                {t(`vwadmin.action.${a.action}` as never)}
              </button>
            ))}
          </div>
        </Section>
      )}

      <Section title={t("vwadmin.orgs")} tone="amber">
        {user.memberships.length === 0 ? (
          <p className="hint">{t("vwadmin.noMemberships")}</p>
        ) : (
          <div className="vw-memberships">
            {user.memberships.map((m) => (
              <div className="vw-membership" key={m.org_id}>
                <Icon name="shield" size={13} />
                <span className="grow">{m.org_name}</span>
                {m.status !== "confirmed" && <span className="chip">{t(`org.status.${m.status}` as never)}</span>}
                <Picker
                  value={m.role}
                  placeholder={t("member.role")}
                  options={roles.map((r) => ({ id: r, label: t(`org.role.${r}` as never) }))}
                  onChange={(role) => void run(() => call("vaultwarden", "set_org_role", { user_id: user.id, org_id: m.org_id, role }))}
                />
              </div>
            ))}
          </div>
        )}
      </Section>

      </div>
      <div className="vw-page-side">
      <Section title={t("vwadmin.facts")} tone="orange">
        <div className="kv">
          <span className="k">{t("vwadmin.factCreated")}</span>
          <span className="v">{user.created_at ?? "—"}</span>
        </div>
        <div className="kv">
          <span className="k">{t("vwadmin.factActive")}</span>
          <span className="v">{user.last_active ?? t("vwadmin.neverActive")}</span>
        </div>
        <div className="kv">
          <span className="k">{t("vwadmin.factEmail")}</span>
          <span className={`v ${user.email_verified ? "" : "vw-warn"}`}>{user.email_verified ? t("vwadmin.verified") : t("vwadmin.unverified")}</span>
        </div>
      </Section>
      </div>
      </div>

      <DangerZone
        title={t("settings.danger")}
        items={danger.map((a) => ({
          label: t(`vwadmin.action.${a.action}` as never),
          hint: t(`vwadmin.confirm.${a.action}` as never, { who: label }),
          action: t(`vwadmin.action.${a.action}` as never),
          disabled: busy,
          onClick: () => act(a),
        }))}
      />

      {asking && (
        <ConfirmAction action={asking} who={label} busy={busy} error={error} onConfirm={() => void doAction(asking)} onClose={() => setAsking(null)} />
      )}
    </>
  );
}

/// Asks before an action that says it wants asking; the same words on the
/// user's page and in the list's menu.
function ConfirmAction({
  action,
  who,
  busy,
  error,
  onConfirm,
  onClose,
}: {
  action: ActionView;
  who: string;
  busy: boolean;
  error: string | null;
  onConfirm: () => void;
  onClose: () => void;
}) {
  return (
    <Modal
      title={t(`vwadmin.action.${action.action}` as never)}
      onClose={onClose}
      footer={
        <button type="button" className={`btn ${action.danger ? "danger" : "primary"}`} disabled={busy} onClick={onConfirm}>
          {busy ? t("action.saving") : t(`vwadmin.action.${action.action}` as never)}
        </button>
      }
    >
      <p className="hint">{t(`vwadmin.confirm.${action.action}` as never, { who })}</p>
      {error && <Alert message={error} />}
    </Modal>
  );
}

/// The everyday actions on a person — log out, disable, enable, resend the
/// invitation — without opening their page. The careful ones stay there, in
/// the danger zone.
function RowMenu({ user, onChanged }: { user: AdminUser; onChanged: () => void }) {
  const [open, setOpen] = useState(false);
  const [asking, setAsking] = useState<ActionView | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const ref = useRef<HTMLDivElement | null>(null);
  const popRef = useRef<HTMLDivElement | null>(null);
  // Where the menu stands: fixed to the window, so no scrolling box clips it,
  // and kept inside what is visible — above the button when below is short.
  const [place, setPlace] = useState<{ top: number; right: number } | null>(null);
  const actions = user.actions.filter((a) => !a.danger);
  useEscape(open ? () => setOpen(false) : null);
  useEffect(() => {
    if (!open) return;
    const away = (e: MouseEvent) => {
      if (!ref.current?.contains(e.target as Node)) setOpen(false);
    };
    // A scrolled list leaves a fixed menu behind: it closes instead.
    const scrolled = (e: Event) => {
      if (!popRef.current?.contains(e.target as Node)) setOpen(false);
    };
    const resized = () => setOpen(false);
    document.addEventListener("mousedown", away);
    document.addEventListener("scroll", scrolled, true);
    window.addEventListener("resize", resized);
    return () => {
      document.removeEventListener("mousedown", away);
      document.removeEventListener("scroll", scrolled, true);
      window.removeEventListener("resize", resized);
    };
  }, [open]);
  useLayoutEffect(() => {
    if (!open) {
      setPlace(null);
      return;
    }
    const button = ref.current?.querySelector("button")?.getBoundingClientRect();
    const pop = popRef.current?.getBoundingClientRect();
    if (!button || !pop) return;
    const gap = 4;
    const edge = 8;
    const below = button.bottom + gap;
    const top = below + pop.height <= window.innerHeight - edge ? below : Math.max(edge, button.top - gap - pop.height);
    const right = Math.max(edge, window.innerWidth - button.right);
    setPlace({ top, right });
  }, [open]);
  const doAction = async (a: ActionView) => {
    setBusy(true);
    setError(null);
    try {
      await call("vaultwarden", "user_action", { user_id: user.id, action: a.action });
      setAsking(null);
      onChanged();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };
  if (actions.length === 0) return null;
  return (
    <div className="vw-row-menu" ref={ref}>
      <button
        type="button"
        className="btn icon-only"
        title={t("vwadmin.actions")}
        aria-label={t("vwadmin.actions")}
        aria-expanded={open}
        disabled={busy}
        onClick={() => setOpen((v) => !v)}
      >
        <Icon name="more" size={14} />
      </button>
      {open && (
        <div
          className="menu vw-pop"
          ref={popRef}
          style={place ? { top: place.top, right: place.right } : { visibility: "hidden" }}
        >
          {actions.map((a) => (
            <button
              key={a.action}
              type="button"
              onClick={() => {
                setOpen(false);
                if (a.confirm) setAsking(a);
                else void doAction(a);
              }}
            >
              {t(`vwadmin.action.${a.action}` as never)}
            </button>
          ))}
        </div>
      )}
      {error && !asking && <span className="vw-row-error" title={error}><Icon name="warn" size={13} /></span>}
      {asking && (
        <ConfirmAction
          action={asking}
          who={user.name ?? user.email}
          busy={busy}
          error={error}
          onConfirm={() => void doAction(asking)}
          onClose={() => setAsking(null)}
        />
      )}
    </div>
  );
}

function Invite({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const send = async () => {
    setBusy(true);
    setError(null);
    try {
      await call("vaultwarden", "invite", { email });
      onDone();
      onClose();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      title={t("vwadmin.invite")}
      onClose={onClose}
      onSubmit={() => void send()}
      footer={
        <button type="button" className="btn primary" disabled={busy || !email.includes("@")} onClick={() => void send()}>
          {busy ? t("action.saving") : t("vwadmin.invite")}
        </button>
      }
    >
      <div className="field">
        <label>{t("member.email")}</label>
        <input value={email} onChange={(e) => setEmail(e.target.value)} autoFocus spellCheck={false} />
        <span className="hint">{t("vwadmin.inviteHint")}</span>
      </div>
      {error && <Alert message={error} />}
    </Modal>
  );
}

// -- Organisations -------------------------------------------------------------

/// The organisations: each row the way to its own page.
function Orgs({ orgs, onOpen }: { orgs: AdminOrg[]; onOpen: (id: string) => void }) {
  if (orgs.length === 0) return <Empty icon="shield" title={t("vwadmin.noOrgs")} />;
  return (
    <div className="list vw-list">
      {orgs.map((o) => (
        <button key={o.id} type="button" className="row plain vw-row" onClick={() => onOpen(o.id)}>
          <span className="glyph"><Icon name="shield" size={15} /></span>
          <span className="text">
            <b>{o.name}</b>
            <span>{t("vwadmin.orgFacts", { members: o.members.length, owners: o.owners })}</span>
          </span>
          <span className="side">
            <Icon name="chevron" size={13} />
          </span>
        </button>
      ))}
    </div>
  );
}

/// One organisation. Roles are changed through the panel, which stands above
/// every organisation. Adding and removing people is not something the panel
/// can do — joining hands a person the organisation's key, which only its
/// members hold — so that goes through the organisation itself, as this
/// account, and only where this account manages it.
function OrgPage({
  org,
  roles,
  mine,
  serverEmails,
  onBack,
  onChanged,
}: {
  org: AdminOrg;
  roles: OrgRole[];
  /// The server's users, to pick from when adding.
  serverEmails: string[];
  /// What this account may do in the organisation, from the daemon; null when
  /// it is not a member.
  mine: OrgAbilities | null;
  onBack: () => void;
  onChanged: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [inviting, setInviting] = useState(false);
  const [emails, setEmails] = useState<string[]>([]);
  const [role, setRole] = useState<OrgRole | null>(mine?.assignable_roles[0] ?? null);
  const [removing, setRemoving] = useState<{ email: string; label: string } | null>(null);
  const [killing, setKilling] = useState(false);
  const [typed, setTyped] = useState("");
  // The organisation's own view of its members: the ids its API speaks and
  // what this account may do to each.
  const [own, setOwn] = useState<OrgMember[] | null>(null);
  const manage = Boolean(mine?.manage_users);
  const loadOwn = useCallback(() => {
    if (!manage) return;
    void invoke<OrgMember[]>("org_members", { orgId: org.id })
      .then(setOwn)
      .catch(() => setOwn([]));
  }, [manage, org.id]);
  useEffect(loadOwn, [loadOwn]);

  const run = async (fn: () => Promise<unknown>, after?: () => void) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
      after?.();
      onChanged();
      loadOwn();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };
  useEscape(onBack);
  // Everyone is asked in turn; the ones the server refuses are named, the
  // rest stay invited.
  const inviteAll = async () => {
    setBusy(true);
    setError(null);
    const failed: string[] = [];
    for (const email of emails) {
      try {
        await invoke("invite_member", { orgId: org.id, email, role });
      } catch (e) {
        failed.push(`${email}: ${String(e)}`);
      }
    }
    setBusy(false);
    onChanged();
    loadOwn();
    if (failed.length) {
      setEmails(emails.filter((e) => failed.some((f) => f.startsWith(`${e}:`))));
      setError(failed.join("\n"));
    } else {
      setEmails([]);
      setInviting(false);
    }
  };
  const ownOf = (e: string) => own?.find((m) => m.email.toLowerCase() === e.toLowerCase()) ?? null;

  return (
    <>
      <button type="button" className="vw-back" onClick={onBack}>
        <Icon name="chevron" size={12} />
        {t("vwadmin.orgs")}
      </button>
      <div className="vw-person">
        <span className="glyph vw-org-glyph"><Icon name="shield" size={22} /></span>
        <span className="vw-title">
          <b>{org.name}</b>
          <span className="hint">{t("vwadmin.orgFacts", { members: org.members.length, owners: org.owners })}</span>
        </span>
      </div>
      {error && <Alert message={error} />}

      <Section title={t("vwadmin.members")} tone="mint">
        <div className="vw-members-head">
          <span className="hint">{manage ? t("vwadmin.membersYours") : t("vwadmin.membersNotYours")}</span>
          {manage && (
            <button type="button" className="btn" onClick={() => setInviting(true)}>
              <Icon name="plus" size={13} />
              {t("vwadmin.addToOrg")}
            </button>
          )}
        </div>
        <div className="vw-memberships">
          {org.members.map((m) => {
            const label = m.name ?? m.email;
            const theirs = ownOf(m.email);
            return (
              <div className="vw-membership" key={m.user_id}>
                <Monogram name={label} size={24} />
                <span className="grow">
                  {label}
                  {m.name && <span className="hint"> · {m.email}</span>}
                </span>
                {m.status !== "confirmed" && <span className="chip">{t(`org.status.${m.status}` as never)}</span>}
                <Picker
                  value={m.role}
                  placeholder={t("member.role")}
                  options={roles.map((r) => ({ id: r, label: t(`org.role.${r}` as never) }))}
                  onChange={(r) => void run(() => call("vaultwarden", "set_org_role", { user_id: m.user_id, org_id: org.id, role: r }))}
                />
                {theirs?.can_edit && (
                  <button
                    type="button"
                    className="btn icon-only danger"
                    title={t("vwadmin.removeFromOrg")}
                    aria-label={t("vwadmin.removeFromOrg")}
                    disabled={busy}
                    onClick={() => setRemoving({ email: m.email, label })}
                  >
                    <Icon name="trash" size={13} />
                  </button>
                )}
              </div>
            );
          })}
        </div>
      </Section>

      <DangerZone
        title={t("settings.danger")}
        items={[{ label: t("vwadmin.deleteOrg"), hint: t("vwadmin.deleteOrgHint"), action: t("vwadmin.deleteOrg"), onClick: () => setKilling(true) }]}
      />

      {inviting && (
        <Modal
          title={t("vwadmin.addToOrg")}
          onClose={() => setInviting(false)}
          footer={
            <button type="button" className="btn primary" disabled={busy || emails.length === 0 || !role} onClick={() => void inviteAll()}>
              {busy ? t("action.saving") : emails.length > 1 ? t("vwadmin.inviteN", { n: emails.length }) : t("member.invite")}
            </button>
          }
        >
          <div className="field">
            <label>{t("vwadmin.whoToAdd")}</label>
            <EmailChips
              value={emails}
              onChange={setEmails}
              options={serverEmails.filter((e) => !org.members.some((m) => m.email.toLowerCase() === e.toLowerCase()))}
              placeholder={t("vwadmin.whoToAddPlaceholder")}
              autoFocus
            />
            <span className="hint">{t("vwadmin.whoToAddHint")}</span>
          </div>
          <div className="field">
            <label>{t("member.role")}</label>
            <Picker
              value={role}
              placeholder={t("member.role")}
              options={(mine?.assignable_roles ?? []).map((r) => ({ id: r, label: t(`org.role.${r}` as never) }))}
              onChange={(r) => setRole(r as OrgRole)}
            />
          </div>
          <span className="hint">{t("vwadmin.addToOrgHint")}</span>
          {error && <Alert message={error} />}
        </Modal>
      )}

      {removing && (
        <Modal
          title={t("vwadmin.removeFromOrg")}
          onClose={() => setRemoving(null)}
          footer={
            <button
              type="button"
              className="btn danger"
              disabled={busy}
              onClick={() => {
                const theirs = ownOf(removing.email);
                if (theirs) void run(() => invoke("remove_member", { orgId: org.id, memberId: theirs.id }), () => setRemoving(null));
              }}
            >
              {busy ? t("action.saving") : t("vwadmin.removeFromOrg")}
            </button>
          }
        >
          <p className="hint">{t("member.removeWarn", { name: removing.label })}</p>
          {error && <Alert message={error} />}
        </Modal>
      )}

      {killing && (
        <Modal
          title={t("vwadmin.deleteOrg")}
          onClose={() => {
            setKilling(false);
            setTyped("");
          }}
          footer={
            <button
              type="button"
              className="btn danger"
              disabled={busy || typed.trim() !== org.name}
              onClick={() => void run(() => call("vaultwarden", "delete_org", { org_id: org.id }), onBack)}
            >
              {busy ? t("action.saving") : t("vwadmin.deleteOrg")}
            </button>
          }
        >
          <Alert tone="warn" message={t("vwadmin.deleteOrgWarn", { name: org.name })} />
          <div className="field">
            <label>{t("vwadmin.typeName", { name: org.name })}</label>
            <input value={typed} onChange={(e) => setTyped(e.target.value)} autoFocus spellCheck={false} />
          </div>
          {error && <Alert message={error} />}
        </Modal>
      )}
    </>
  );
}

// -- The server ----------------------------------------------------------------

/// The server's settings, in the groups the server keeps them in — each a tab
/// of its own — with what cannot be edited here in a tab at the end. Changes
/// gather across the tabs and go out together; the plugin lays them over what
/// the server has at that moment.
function Settings() {
  const [groups, setGroups] = useState<SettingsGroup[] | null>(null);
  const [tab, setTab] = useState<string | null>(null);
  const [changes, setChanges] = useState<Record<string, unknown>>({});
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    setError(null);
    void call<SettingsGroup[]>("vaultwarden", "settings")
      .then((g) => {
        setGroups(g);
        setTab((cur) => cur ?? g[0]?.id ?? null);
      })
      .catch((e) => setError(String(e)));
  }, []);
  useEffect(load, [load]);

  const dirty = Object.keys(changes).length;
  const save = async () => {
    setBusy(true);
    setError(null);
    setNote(null);
    try {
      await call("vaultwarden", "save_settings", { changes });
      setNote(t("vwadmin.settingsSaved"));
      setChanges({});
      load();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };
  const shown = groups?.find((g) => g.id === tab) ?? null;

  return (
    <>
      <div className="vw-settings-bar">
        <div className="chiprow">
          {(groups ?? []).map((g) => {
            const touched = g.settings.some((x) => x.name in changes);
            return (
              <button key={g.id} type="button" className={`fchip ${tab === g.id ? "on" : ""}`} onClick={() => setTab(g.id)}>
                {g.id === "readonly" ? t("vwadmin.readonly") : g.title}
                {touched && <span className="vw-dirty" aria-hidden="true" />}
              </button>
            );
          })}
        </div>
        <button type="button" className="btn primary small" disabled={busy || dirty === 0} onClick={() => void save()}>
          {busy ? t("action.saving") : dirty > 0 ? t("vwadmin.saveN", { n: dirty }) : t("action.save")}
        </button>
      </div>
      {note && (
        <p className="vw-note">
          <Icon name="check" size={13} />
          {note}
        </p>
      )}
      {error && <Alert message={error} onRetry={load} />}
      {!groups && !error && <Skeleton rows={8} />}

      {shown && (
        <Section title={shown.id === "readonly" ? t("vwadmin.readonly") : shown.title} tone="mint">
          {shown.id === "readonly" && <p className="hint">{t("vwadmin.readonlyHint")}</p>}
          <div className="vw-fields">
            {shown.settings.map((x) => (
              <SettingField
                key={x.name}
                setting={x}
                value={x.name in changes ? changes[x.name] : x.value}
                changed={x.name in changes}
                onChange={(v) =>
                  setChanges((cur) => {
                    const next = { ...cur };
                    // Back to what the server has means no change at all.
                    if (JSON.stringify(v ?? null) === JSON.stringify(x.value ?? null) || (v === "" && x.value === null)) delete next[x.name];
                    else next[x.name] = v;
                    return next;
                  })
                }
              />
            ))}
          </div>
          {shown.id === "smtp" && <SmtpTest />}
        </Section>
      )}
    </>
  );
}

/// What is done to the server rather than set on it: a database backup, a
/// test letter, and — apart — resetting the settings and locking the panel.
function Tools({ onLocked }: { onLocked: () => void }) {
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [resetting, setResetting] = useState(false);
  const run = async (fn: () => Promise<unknown>, done: (v: unknown) => string, after?: () => void) => {
    setBusy(true);
    setError(null);
    setNote(null);
    try {
      setNote(done(await fn()));
      after?.();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <Section title={t("vwadmin.backup")} tone="amber">
        <div className="vw-tool">
          <span className="grow">
            <span className="hint">{t("vwadmin.backupHint")}</span>
          </span>
          <button type="button" className="btn" disabled={busy} onClick={() => void run(() => call<string>("vaultwarden", "backup_db"), (v) => String(v))}>
            {t("vwadmin.backupAction")}
          </button>
        </div>
      </Section>
      <Section title={t("vwadmin.smtp")} tone="mint">
        <SmtpTest bare />
      </Section>
      {note && (
        <p className="vw-note">
          <Icon name="check" size={13} />
          {note}
        </p>
      )}
      {error && <Alert message={error} />}
      <DangerZone
        title={t("settings.danger")}
        items={[
          { label: t("vwadmin.reset"), hint: t("vwadmin.resetHint"), action: t("vwadmin.resetAction"), onClick: () => setResetting(true) },
          { label: t("vwadmin.forget"), hint: t("vwadmin.forgetHint"), action: t("vwadmin.forgetAction"), onClick: () => void call("vaultwarden", "forget").then(onLocked) },
        ]}
      />
      {resetting && (
        <Modal
          title={t("vwadmin.reset")}
          onClose={() => setResetting(false)}
          footer={
            <button
              type="button"
              className="btn danger"
              disabled={busy}
              onClick={() => void run(() => call("vaultwarden", "reset_settings"), () => t("vwadmin.resetDone"), () => setResetting(false))}
            >
              {t("vwadmin.resetAction")}
            </button>
          }
        >
          <p className="hint">{t("vwadmin.resetWarn")}</p>
        </Modal>
      )}
    </>
  );
}

/// One setting: its caption, its field by kind — a secret behind an eye — and
/// what it defaults to.
function SettingField({ setting, value, changed, onChange }: { setting: Setting; value: unknown; changed: boolean; onChange: (v: unknown) => void }) {
  const ro = !setting.editable;
  const str = value === null || value === undefined ? "" : String(value);
  return (
    <div className={`vw-field ${changed ? "changed" : ""}`}>
      <div className="vw-field-text">
      <div className="vw-field-head">
        <label>{setting.label}</label>
        <span className="hint mono">{setting.name}</span>
        {setting.overridden && <span className="chip vw-over" title={t("vwadmin.overriddenHint")}>{t("vwadmin.overridden")}</span>}
        {ro && (
          <span className="chip vw-env" title={t("vwadmin.envHint")}>
            <Icon name="lock" size={11} />
            {t("vwadmin.envChip")}
          </span>
        )}
      </div>
      {setting.description && <span className="hint">{setting.description}</span>}
      </div>
      <div className="vw-field-control">
      {ro ? (
        <EnvValue setting={setting} />
      ) : setting.choice?.kind === "users" ? (
        <UsersChoice choice={setting.choice} value={str} onChange={onChange} />
      ) : setting.kind === "checkbox" ? (
        <div className="vw-toggle">
          <Toggle on={Boolean(value)} onChange={onChange} />
        </div>
      ) : setting.kind === "password" ? (
        <PasswordInput value={str} onChange={(v) => onChange(v)} ariaLabel={setting.label} placeholder={setting.default ?? ""} />
      ) : setting.kind === "number" ? (
        <div className="vw-number">
          <NumberInput
            value={typeof value === "number" ? value : value === null || value === undefined || value === "" ? null : Number(value)}
            onChange={onChange}
            placeholder={setting.default ?? ""}
            ariaLabel={setting.label}
          />
        </div>
      ) : (
        <input value={str} placeholder={setting.default ?? ""} spellCheck={false} onChange={(e) => onChange(e.target.value)} />
      )}
      </div>
    </div>
  );
}

/// A value the environment sets: shown, never typed into — a secret behind
/// an eye, a flag as a word, the rest as it is.
function EnvValue({ setting }: { setting: Setting }) {
  const [shown, setShown] = useState(false);
  const v = setting.value;
  if (setting.kind === "checkbox") return <span className="vw-env-value">{v ? t("vwadmin.on") : t("vwadmin.off")}</span>;
  const text = v === null || v === undefined || v === "" ? null : String(v);
  if (!text) return <span className="vw-env-value vw-none">{setting.default ? t("vwadmin.byDefault", { value: setting.default }) : "—"}</span>;
  if (setting.kind !== "password") return <span className="vw-env-value mono">{text}</span>;
  return (
    <span className="vw-env-value mono">
      {shown ? text : "••••••••••••"}
      <button type="button" className="btn icon-only" title={t("action.show")} aria-label={t("action.show")} onClick={() => setShown((x) => !x)}>
        <Icon name="eye" size={13} />
      </button>
    </span>
  );
}

/// Some of the server's users, for a setting that names them: everyone,
/// nobody, or only the ones ticked. The words for everyone and nobody and the
/// separator come from the plugin; an address in the value that is no user of
/// the server is kept and shown too.
function UsersChoice({ choice, value, onChange }: { choice: Choice; value: string; onChange: (v: unknown) => void }) {
  const raw = value.trim().toLowerCase();
  const mode: "all" | "none" | "some" = raw === "" || raw === choice.all ? "all" : raw === choice.none ? "none" : "some";
  const picked = mode === "some" ? raw.split(choice.separator).map((e) => e.trim()).filter(Boolean) : [];
  const options = [...new Set([...choice.options.map((o) => o.toLowerCase()), ...picked])];
  const set = (list: string[]) => onChange(list.length ? list.join(choice.separator) : choice.none);
  return (
    <div className="vw-choice">
      <Segmented
        value={mode}
        onChange={(m) => onChange(m === "all" ? "" : m === "none" ? choice.none : options.slice(0, 1).join(choice.separator))}
        options={[
          { id: "all", label: t("vwadmin.choiceAll") },
          { id: "none", label: t("vwadmin.choiceNone") },
          { id: "some", label: t("vwadmin.choiceSome") },
        ]}
      />
      {mode === "some" && (
        <div className="chiprow">
          {options.map((o) => {
            const on = picked.includes(o);
            return (
              <button key={o} type="button" className={`fchip ${on ? "on" : ""}`} onClick={() => set(on ? picked.filter((p) => p !== o) : [...picked, o])}>
                {on && <Icon name="check" size={11} />}
                {o}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

function SmtpTest({ bare = false }: { bare?: boolean }) {
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const send = async () => {
    setBusy(true);
    setNote(null);
    setError(null);
    try {
      await call("vaultwarden", "test_smtp", { email });
      setNote(t("vwadmin.smtpSent", { email }));
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <form
      className={`vw-tool ${bare ? "" : "vw-smtp"}`}
      onSubmit={(e) => {
        e.preventDefault();
        void send();
      }}
    >
      <span className="grow">
        {!bare && <b>{t("vwadmin.smtp")}</b>}
        <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder={t("member.email")} spellCheck={false} />
        {note && <span className="vw-note"><Icon name="check" size={13} />{note}</span>}
        {error && <Alert message={error} />}
      </span>
      <button type="submit" className="btn" disabled={busy || !email.includes("@")}>
        {t("vwadmin.smtpAction")}
      </button>
    </form>
  );
}
