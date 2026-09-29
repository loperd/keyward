/// Managing an organisation: what it is called, its collections and who is in
/// it, in one dialogue opened from the organisation's row in the items'
/// column. Its items are the list itself, sliced by that row.
import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Alert, DangerZone, Empty, Icon, Modal, Picker, Section, Skeleton, Tabs } from "../ui";
import { t } from "../i18n";
import type { Catalog, OrgAbilities, OrgMember, OrgRole } from "../types";
import { PasswordInput } from "../PasswordInput";

type Org = Catalog["orgs"][number];
type OrgView = "overview" | "collections" | "members";

export function OrgManager({
  catalog,
  orgId,
  onClose,
  onChanged,
}: {
  catalog: Catalog;
  orgId: string;
  onClose: () => void;
  onChanged: () => void;
}) {
  const [view, setView] = useState<OrgView>("overview");
  const org = catalog.orgs.find((o) => o.id === orgId);
  // Deleted or left from elsewhere: nothing is left to manage.
  useEffect(() => {
    if (!org) onClose();
  }, [org, onClose]);
  if (!org) return null;
  const collections = catalog.collections.filter((c) => c.org_id === org.id);
  return (
    <Modal title={org.name} onClose={onClose} wide>
      <div className="org-manage">
        <div className="org-manage-head">
          <span className={`chip role-${org.role}`}>{t(`org.role.${org.role}` as never)}</span>
          <span className="hint">
            {t("org.collectionItems", { n: catalog.items.filter((i) => i.org_id === org.id && !i.deleted).length })}
          </span>
        </div>
        <Tabs
          value={view}
          onChange={setView}
          options={[
            { id: "overview", label: t("org.overview") },
            { id: "collections", label: t("org.collections"), count: collections.length },
            { id: "members", label: t("org.members") },
          ]}
        />
        {view === "overview" && <OrgOverview key={org.id} org={org} onChanged={onChanged} />}
        {view === "collections" && <Collections org={org} list={collections} onChanged={onChanged} />}
        {view === "members" && <Members orgId={org.id} can={org.can} onChanged={onChanged} />}
      </div>
    </Modal>
  );
}

/// What an organisation is called and where its bills go, with deletion
/// apart, in the danger zone. It used to be a dialogue whose footer held
/// "Save", "Delete" and "Cancel" side by side.
function OrgOverview({ org, onChanged }: { org: Org; onChanged: () => void }) {
  const [name, setName] = useState(org.name);
  const [email, setEmail] = useState("");
  const [killing, setKilling] = useState(false);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  const run = async (fn: () => Promise<unknown>, after?: () => void) => {
    setBusy(true);
    setError(null);
    setSaved(false);
    try {
      await fn();
      after?.();
      onChanged();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };
  const dirty = name.trim() !== org.name || email.trim() !== "";

  if (!org.can.edit_org) {
    return (
      <Section title={t("org.overview")} tone="mint">
        <p className="hint">{t("org.readOnlyHint", { role: t(`org.role.${org.role}` as never) })}</p>
      </Section>
    );
  }
  return (
    <>
      <Section title={t("org.profile")} tone="mint">
        <div className="field">
          <label>{t("org.name")}</label>
          <input value={name} onChange={(e) => setName(e.target.value)} spellCheck={false} />
        </div>
        <div className="field">
          <label>{t("org.billing")}</label>
          <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder={t("org.billingKeep")} spellCheck={false} />
          <span className="hint">{t("org.billingHint")}</span>
        </div>
        <div className="block-actions">
          {saved && <span className="hint">{t("action.saved")}</span>}
          <button
            type="button"
            className="btn primary"
            disabled={busy || !name.trim() || !dirty}
            onClick={() => void run(() => invoke("update_org", { orgId: org.id, name, billingEmail: email }), () => setSaved(true))}
          >
            {busy ? t("action.saving") : t("action.save")}
          </button>
        </div>
        {error && !killing && <Alert message={error} />}
      </Section>

      <DangerZone
        title={t("settings.danger")}
        items={[{ label: t("org.delete"), hint: t("org.deleteZoneHint"), action: t("org.delete"), onClick: () => setKilling(true) }]}
      />

      {killing && (
        <Modal
          title={t("org.delete")}
          onClose={() => setKilling(false)}
          onSubmit={() => void run(() => invoke("delete_org", { orgId: org.id, masterPassword: password }))}
          footer={
            <button
              type="button"
              className="btn danger"
              disabled={busy || !password}
              onClick={() => void run(() => invoke("delete_org", { orgId: org.id, masterPassword: password }))}
            >
              {busy ? t("action.saving") : t("org.deleteForGood")}
            </button>
          }
        >
          <Alert tone="warn" message={t("org.deleteWarn", { name: org.name })} />
          <div className="field">
            <label>{t("login.password")}</label>
            <PasswordInput value={password} onChange={setPassword} autoFocus ariaLabel={t("login.password")} />
            <span className="hint">{t("org.deleteWhyPassword")}</span>
          </div>
          {error && <Alert message={error} />}
        </Modal>
      )}
    </>
  );
}

/// An organisation's collections.
///
/// The name is encrypted with the organisation's key rather than the user's: a
/// collection has to be readable by all of its members, and only they have that
/// key.
function Collections({
  org,
  list,
  onChanged,
}: {
  org: { id: string; can: OrgAbilities };
  list: { id: string; name: string; count: number; read_only: boolean }[];
  onChanged: () => void;
}) {
  const [adding, setAdding] = useState(false);
  const [renaming, setRenaming] = useState<{ id: string; name: string } | null>(null);
  const [killing, setKilling] = useState<{ id: string; name: string } | null>(null);
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const run = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
      setAdding(false);
      setRenaming(null);
      setKilling(null);
      setName("");
      onChanged();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      {org.can.create_collections && (
        <div className="section-head">
          <span className="title">
            <b>{t("org.collections")}</b>
            <span className="hint">{t("collection.count", { n: list.length })}</span>
          </span>
          <button type="button"
            className="btn"
            onClick={() => {
              setName("");
              setAdding(true);
            }}
          >
            <Icon name="plus" size={13} />
            {t("collection.new")}
          </button>
        </div>
      )}

      {error && <Alert message={error} />}

      {list.length === 0 ? (
        <Empty icon="folder" title={t("org.noCollections")} />
      ) : (
        <div className="list">
          {list.map((c) => (
            <div className="row plain" key={c.id}>
              <span className="glyph"><Icon name="folder" size={15} /></span>
              <span className="text">
                <b>{c.name}</b>
                <span>{t("org.collectionItems", { n: c.count })}</span>
              </span>
              <span className="side">
                {c.read_only && <span className="chip">{t("org.readOnly")}</span>}
                {org.can.edit_collections && (
                    <button type="button"
                      className="btn icon-only"
                      title={t("edit.open")}
                      aria-label={t("edit.open")}
                      onClick={() => {
                        setName(c.name);
                        setRenaming({ id: c.id, name: c.name });
                      }}
                    >
                      <Icon name="edit" size={13} />
                    </button>
                )}
                {org.can.delete_collections && (
                    <button type="button"
                      className="btn icon-only danger"
                      title={t("collection.delete")}
                      aria-label={t("collection.delete")}
                      onClick={() => setKilling({ id: c.id, name: c.name })}
                    >
                      <Icon name="trash" size={13} />
                    </button>
                )}
              </span>
            </div>
          ))}
        </div>
      )}

      {(adding || renaming) && (
        <Modal
          title={adding ? t("collection.new") : t("collection.rename")}
          onClose={() => {
            setAdding(false);
            setRenaming(null);
          }}
          onSubmit={() =>
            void run(() =>
              adding
                ? invoke("create_collection", { orgId: org.id, name })
                : invoke("rename_collection", { orgId: org.id, collectionId: renaming?.id, name }),
            )
          }
          footer={
            <>
              <button type="button"
                className="btn primary"
                disabled={busy || !name.trim()}
                onClick={() =>
                  void run(() =>
                    adding
                      ? invoke("create_collection", { orgId: org.id, name })
                      : invoke("rename_collection", { orgId: org.id, collectionId: renaming?.id, name }),
                  )
                }
              >
                {busy ? t("action.saving") : t("action.save")}
              </button>
            </>
          }
        >
          <div className="field">
            <label>{t("org.name")}</label>
            <input value={name} onChange={(e) => setName(e.target.value)} autoFocus spellCheck={false} />
          </div>
          {error && <Alert message={error} />}
        </Modal>
      )}

      {killing && (
        <Modal
          title={t("collection.delete")}
          onClose={() => setKilling(null)}
          footer={
            <>
              <button type="button"
                className="btn danger"
                disabled={busy}
                onClick={() =>
                  void run(() =>
                    invoke("delete_collection", { orgId: org.id, collectionId: killing.id }),
                  )
                }
              >
                {busy ? t("action.saving") : t("collection.delete")}
              </button>
            </>
          }
        >
          <p className="hint">{t("collection.deleteWarn", { name: killing.name })}</p>
        </Modal>
      )}
    </>
  );
}

/// The members: the one thing the snapshot does not hold — so the server is
/// asked, and a refusal is shown honestly when the rights are not enough. Who
/// may do what to whom comes with the answer, worked out by the daemon.
function Members({
  orgId,
  can,
  onChanged,
}: {
  orgId: string;
  can: OrgAbilities;
  onChanged: () => void;
}) {
  const grantable = can.assignable_roles;
  const roleOptions = grantable.map((r) => ({ id: r, label: t(`org.role.${r}` as never) }));
  const [members, setMembers] = useState<OrgMember[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [inviting, setInviting] = useState(false);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<OrgRole | null>(grantable[0] ?? null);
  const [killing, setKilling] = useState<OrgMember | null>(null);

  const load = useCallback(() => {
    setMembers(null);
    invoke<OrgMember[]>("org_members", { orgId })
      .then(setMembers)
      .catch((e) => setError(String(e)));
  }, [orgId]);

  useEffect(load, [load]);

  const run = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
      setInviting(false);
      setKilling(null);
      setEmail("");
      onChanged();
      load();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  if (error && members === null) return <Alert message={error} onRetry={load} />;
  if (!members) return <Skeleton rows={3} />;

  return (
    <>
      {can.manage_users && (
        <div className="section-head">
          <span className="title">
            <b>{t("org.members")}</b>
            <span className="hint">{t("member.count", { n: members.length })}</span>
          </span>
          <button type="button" className="btn" onClick={() => setInviting(true)}>
            <Icon name="plus" size={13} />
            {t("member.invite")}
          </button>
        </div>
      )}

      {error && <Alert message={error} />}

      {members.length === 0 ? (
        <Empty icon="identity" title={t("org.noMembers")} />
      ) : (
        <div className="list">
          {members.map((m) => (
            <div className="row plain" key={m.id}>
              <span className="face">{(m.name ?? m.email).trim().charAt(0).toUpperCase()}</span>
              <span className="text">
                <b>
                  {m.name ?? m.email}
                  {m.is_you && <span className="you">{t("org.you")}</span>}
                </b>
                <span>
                  {m.name ? m.email : m.access_all ? t("org.accessAll") : t("org.accessSome", { n: m.collections })}
                </span>
              </span>
              <span className="side">
                {m.two_factor && <span className="chip" title={t("org.twoFactor")}>2FA</span>}
                {m.status !== "confirmed" && (
                  <span className={`chip status-${m.status}`}>{t(`org.status.${m.status}` as never)}</span>
                )}
                {m.can_confirm && (
                  <button type="button"
                    className="btn"
                    disabled={busy}
                    title={t("member.confirmHint")}
                    onClick={() =>
                      void run(() =>
                        invoke("confirm_member", { orgId, memberId: m.id, userId: m.user_id ?? "" }),
                      )
                    }
                  >
                    {t("member.confirm")}
                  </button>
                )}
                {m.can_edit ? (
                  <>
                    {/* The role changes in place: a form of its own for one
                        value is a step too many. */}
                    <Picker
                      value={m.role}
                      placeholder={t("member.role")}
                      options={roleOptions}
                      onChange={(id) =>
                        void run(() => invoke("set_member_role", { orgId, memberId: m.id, role: id as OrgRole }))
                      }
                    />
                    <button type="button"
                      className="btn icon-only danger"
                      disabled={busy}
                      title={t("member.remove")}
                      aria-label={t("member.remove")}
                      onClick={() => setKilling(m)}
                    >
                      <Icon name="trash" size={13} />
                    </button>
                  </>
                ) : (
                  <span className={`chip role-${m.role}`}>{t(`org.role.${m.role}` as never)}</span>
                )}
              </span>
            </div>
          ))}
        </div>
      )}

      {inviting && (
        <Modal
          title={t("member.inviteTitle")}
          onClose={() => setInviting(false)}
          onSubmit={() => void run(() => invoke("invite_member", { orgId, email, role }))}
          footer={
            <>
              <button type="button"
                className="btn primary"
                disabled={busy || !email.includes("@") || !role}
                onClick={() => void run(() => invoke("invite_member", { orgId, email, role }))}
              >
                {busy ? t("action.saving") : t("member.invite")}
              </button>
            </>
          }
        >
          <div className="pair">
            <div className="field">
              <label>{t("member.email")}</label>
              <input value={email} onChange={(e) => setEmail(e.target.value)} autoFocus spellCheck={false} />
            </div>
            <div className="field">
              <label>{t("member.role")}</label>
              <Picker
                value={role}
                placeholder={t("member.role")}
                options={roleOptions}
                onChange={(id) => setRole(id as OrgRole)}
              />
            </div>
          </div>
          <span className="hint">{t("member.inviteHint")}</span>
          {error && <Alert message={error} />}
        </Modal>
      )}

      {killing && (
        <Modal
          title={t("member.remove")}
          onClose={() => setKilling(null)}
          footer={
            <>
              <button type="button"
                className="btn danger"
                disabled={busy}
                onClick={() => void run(() => invoke("remove_member", { orgId, memberId: killing.id }))}
              >
                {busy ? t("action.saving") : t("member.remove")}
              </button>
            </>
          }
        >
          <p className="hint">{t("member.removeWarn", { name: killing.name ?? killing.email })}</p>
        </Modal>
      )}
    </>
  );
}
