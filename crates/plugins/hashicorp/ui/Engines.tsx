/// Secrets engines and auth methods: what is mounted, mounting a new one with
/// hints about the kinds, tuning it, unmounting it. For kv, the version and the
/// version-retention settings for the whole engine.
import { useCallback, useEffect, useState } from "react";
import { Alert, DangerZone, Disclosure, Empty, Icon, Modal, Picker, Segmented, Skeleton, Toggle } from "@keyward/ui";
import { t } from "@keyward/i18n";
import type { Key } from "@keyward/i18n";
import { call } from "@keyward/plugins/call";
import type { KvConfig, Mount, MountForm, MountTune } from "./types";

/// The kinds of engine worth offering. Each has a hint about what it is good
/// for and a default path.
const SECRET_KINDS = ["kv", "transit", "pki", "ssh", "totp", "database", "aws", "rabbitmq", "consul", "nomad"] as const;
const AUTH_KINDS = ["approle", "kubernetes", "userpass", "jwt", "oidc", "github", "ldap", "aws", "cert"] as const;

const KIND_TONE: Record<string, string> = {
  kv: "tone-kv",
  transit: "tone-transit",
  pki: "tone-pki",
  ssh: "tone-pki",
  totp: "tone-transit",
  database: "tone-db",
  aws: "tone-db",
  approle: "tone-auth",
  kubernetes: "tone-auth",
  userpass: "tone-auth",
  jwt: "tone-auth",
  oidc: "tone-auth",
  github: "tone-auth",
  ldap: "tone-auth",
  cert: "tone-auth",
  token: "tone-auth",
};

const KNOWN_KINDS = new Set<string>([...SECRET_KINDS, ...AUTH_KINDS, "token", "generic", "cubbyhole", "identity"]);
function kindHint(kind: string): string {
  return KNOWN_KINDS.has(kind) ? t(`engine.kind.${kind}` as Key) : "";
}

function ttl(seconds: number): string {
  if (seconds === 0) return t("engine.ttlSystem");
  if (seconds % 3600 === 0) return `${seconds / 3600}h`;
  if (seconds % 60 === 0) return `${seconds / 60}m`;
  return `${seconds}s`;
}

export function Engines({ onOpenSecrets }: { onOpenSecrets: (mount: string) => void }) {
  const [mounts, setMounts] = useState<Mount[] | null>(null);
  const [auth, setAuth] = useState<Mount[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [opened, setOpened] = useState<Mount | null>(null);
  const [enabling, setEnabling] = useState<"secret" | "auth" | null>(null);
  const [view, setView] = useState<"secrets" | "auth">("secrets");

  const load = useCallback(() => {
    call<Mount[]>("hashicorp", "mounts")
      .then((m) => {
        setMounts(m.filter((x) => !x.auth));
        setError(null);
      })
      .catch((e) => setError(String(e)));
    call<Mount[]>("hashicorp", "auth_mounts")
      .then(setAuth)
      .catch((e) => setError(String(e)));
  }, []);

  useEffect(load, [load]);

  if (error && mounts === null) return <Alert message={error} onRetry={load} />;
  if (!mounts) return <Skeleton rows={4} />;

  const row = (m: Mount) => (
    <button key={m.path} type="button" className="row conn" onClick={() => setOpened(m)}>
      <span className={`glyph engine ${KIND_TONE[m.kind] ?? "tone-other"}`}>
        <Icon name={m.auth ? "login" : m.kind === "kv" ? "folder" : m.kind === "pki" || m.kind === "ssh" ? "shield" : "key"} size={15} />
      </span>
      <span className="text">
        <b>{m.path}</b>
        <span>
          {m.kind}
          {m.kv2 ? " · v2" : m.kind === "kv" ? " · v1" : ""}
          {m.description ? ` · ${m.description}` : ""}
        </span>
      </span>
      <span className="side">
        {!m.auth && m.max_lease_ttl > 0 && <span className="chip">{ttl(m.max_lease_ttl)}</span>}
        <span className={`chip ${KIND_TONE[m.kind] ?? ""}`}>{m.kind}{m.kv2 ? " v2" : ""}</span>
        <Icon name="chevron" size={13} />
      </span>
    </button>
  );

  const list = view === "secrets" ? mounts : auth;

  return (
    <>
      {/* Two tables and two switches, not one long page. */}
      <div className="section-head">
        <Segmented<"secrets" | "auth">
          value={view}
          onChange={setView}
          options={[
            { id: "secrets", label: t("engine.secrets"), count: mounts.length },
            { id: "auth", label: t("engine.auth"), count: auth?.length },
          ]}
        />
        <button type="button" className="btn primary" onClick={() => setEnabling(view === "secrets" ? "secret" : "auth")}>
          <Icon name="plus" size={13} />
          {view === "secrets" ? t("engine.enable") : t("engine.enableAuth")}
        </button>
      </div>

      {list === null ? (
        <Skeleton rows={3} />
      ) : list.length === 0 ? (
        <Empty icon={view === "secrets" ? "folder" : "login"} title={t("engine.none")} body={view === "secrets" ? t("engine.noneHint") : t("engine.noneAuthHint")} />
      ) : (
        <div className="list">{list.map(row)}</div>
      )}

      {error && <Alert message={error} onRetry={load} />}

      {opened && (
        <EngineCard
          mount={opened}
          onClose={() => setOpened(null)}
          onChanged={(list) => {
            if (opened.auth) setAuth(list);
            else setMounts(list.filter((x) => !x.auth));
            const fresh = list.find((m) => m.path === opened.path);
            setOpened(fresh ?? null);
          }}
          onOpenSecrets={onOpenSecrets}
        />
      )}

      {enabling && (
        <EnableMount
          auth={enabling === "auth"}
          existing={[...mounts, ...(auth ?? [])].map((m) => m.path)}
          onClose={() => setEnabling(null)}
          onEnabled={(list) => {
            if (enabling === "auth") setAuth(list);
            else setMounts(list.filter((x) => !x.auth));
            setEnabling(null);
          }}
        />
      )}
    </>
  );
}

/// An engine's card: the facts, the tuning, the kv config, unmounting.
function EngineCard({
  mount,
  onClose,
  onChanged,
  onOpenSecrets,
}: {
  mount: Mount;
  onClose: () => void;
  onChanged: (list: Mount[]) => void;
  onOpenSecrets: (mount: string) => void;
}) {
  const [description, setDescription] = useState(mount.description);
  const [defTtl, setDefTtl] = useState(mount.default_lease_ttl ? ttl(mount.default_lease_ttl) : "");
  const [maxTtl, setMaxTtl] = useState(mount.max_lease_ttl ? ttl(mount.max_lease_ttl) : "");
  const [cfg, setCfg] = useState<KvConfig | null>(null);
  const [cfgDraft, setCfgDraft] = useState<{ max: string; cas: boolean; after: string }>({ max: "", cas: false, after: "" });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<"disable" | "upgrade" | null>(null);

  const builtin = mount.path === "cubbyhole" || mount.path === "identity" || mount.path === "sys" || mount.path === "auth/token";
  const isKv = mount.kind === "kv" || mount.kind === "generic";

  useEffect(() => {
    if (!(isKv && mount.kv2)) return;
    call<KvConfig>("hashicorp", "kv_config", { mount: mount.path })
      .then((c) => {
        setCfg(c);
        setCfgDraft({ max: c.max_versions === 0 ? "" : String(c.max_versions), cas: c.cas_required, after: c.delete_version_after === "0s" ? "" : c.delete_version_after });
      })
      .catch((e) => setError(String(e)));
  }, [isKv, mount.kv2, mount.path]);

  const run = async (f: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    try {
      await f();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const durationOk = (v: string) => v.trim() === "" || /^\d+(s|m|h)$/.test(v.trim());
  const tuneDirty = description !== mount.description || defTtl !== (mount.default_lease_ttl ? ttl(mount.default_lease_ttl) : "") || maxTtl !== (mount.max_lease_ttl ? ttl(mount.max_lease_ttl) : "");
  const tuneOk = durationOk(defTtl) && durationOk(maxTtl);

  const cfgDirty = cfg !== null && (cfgDraft.max !== (cfg.max_versions === 0 ? "" : String(cfg.max_versions)) || cfgDraft.cas !== cfg.cas_required || cfgDraft.after !== (cfg.delete_version_after === "0s" ? "" : cfg.delete_version_after));
  const dirty = tuneDirty || cfgDirty;
  const valid = tuneOk && durationOk(cfgDraft.after);

  // One "Save" button for the whole card: it writes only what changed.
  const saveAll = () =>
    void run(async () => {
      if (tuneDirty) {
        const tune: MountTune = {
          description: description !== mount.description ? description : null,
          default_lease_ttl: mount.auth ? null : defTtl.trim() === "" && mount.default_lease_ttl === 0 ? null : defTtl.trim(),
          max_lease_ttl: mount.auth ? null : maxTtl.trim() === "" && mount.max_lease_ttl === 0 ? null : maxTtl.trim(),
          kv_version: null,
        };
        onChanged(await call<Mount[]>("hashicorp", "mount_tune", { path: mount.path, auth: mount.auth, tune }));
      }
      if (cfgDirty) {
        const config: KvConfig = {
          max_versions: Number(cfgDraft.max) || 0,
          cas_required: cfgDraft.cas,
          delete_version_after: cfgDraft.after.trim() === "" ? "0s" : cfgDraft.after.trim(),
        };
        setCfg(await call<KvConfig>("hashicorp", "kv_config_write", { mount: mount.path, config }));
      }
    });

  const act = () =>
    void run(async () => {
      if (confirm === "disable") {
        onChanged(await call<Mount[]>("hashicorp", "mount_disable", { path: mount.path, auth: mount.auth }));
        onClose();
      } else if (confirm === "upgrade") {
        const tune: MountTune = { description: null, default_lease_ttl: null, max_lease_ttl: null, kv_version: 2 };
        onChanged(await call<Mount[]>("hashicorp", "mount_tune", { path: mount.path, auth: false, tune }));
      }
      setConfirm(null);
    });

  return (
    <Modal
      title={mount.path}
      onClose={onClose}
      wide
      footer={
        <>
          {dirty && <span className="foot-why hint">{valid ? t("engine.unsaved") : t("engine.ttlHint")}</span>}
          {isKv && (
            <button type="button" className="btn" onClick={() => onOpenSecrets(mount.path)}>
              <Icon name="folder" size={13} />
              {t("engine.openSecrets")}
            </button>
          )}
          {!builtin && (
            <button type="button" className="btn primary" disabled={busy || !dirty || !valid} onClick={saveAll}>
              {busy ? t("action.saving") : t("action.save")}
            </button>
          )}
        </>
      }
    >
      <dl className="issue-facts">
        <dt>{t("engine.type")}</dt>
        <dd className="wrap">
          <span className={`chip ${KIND_TONE[mount.kind] ?? ""}`}>{mount.kind}</span>
          {isKv && <span className={mount.kv2 ? "chip on" : "chip"}>{mount.kv2 ? "kv v2" : "kv v1"}</span>}
          <span className="hint"> {kindHint(mount.kind)}</span>
        </dd>
        {mount.accessor && (
          <>
            <dt>{t("engine.accessor")}</dt>
            <dd className="mono">{mount.accessor}</dd>
          </>
        )}
        {!mount.auth && (
          <>
            <dt>{t("engine.defaultTtl")}</dt>
            <dd>{ttl(mount.default_lease_ttl)}</dd>
            <dt>{t("engine.maxTtl")}</dt>
            <dd>{ttl(mount.max_lease_ttl)}</dd>
          </>
        )}
      </dl>

      {!builtin && (
        <Disclosure title={t("engine.tune")} open>
          <div className="field">
            <label>{t("engine.description")}</label>
            <input type="text" value={description} onChange={(e) => setDescription(e.target.value)} placeholder={t("engine.descriptionPlaceholder")} />
          </div>
          {!mount.auth && (
            <div className="pair">
              <div className="field">
                <label>{t("engine.defaultTtl")}</label>
                <input type="text" className="mono" value={defTtl} onChange={(e) => setDefTtl(e.target.value)} placeholder={t("engine.ttlSystem")} spellCheck={false} />
                <span className={durationOk(defTtl) ? "hint" : "hint warn"}>{t("engine.ttlHint")}</span>
              </div>
              <div className="field">
                <label>{t("engine.maxTtl")}</label>
                <input type="text" className="mono" value={maxTtl} onChange={(e) => setMaxTtl(e.target.value)} placeholder={t("engine.ttlSystem")} spellCheck={false} />
                <span className={durationOk(maxTtl) ? "hint" : "hint warn"}>{t("engine.maxTtlHint")}</span>
              </div>
            </div>
          )}
        </Disclosure>
      )}

      {isKv && mount.kv2 && (
        <Disclosure title={t("engine.kvConfig")} open>
          {cfg === null ? (
            <Skeleton rows={2} />
          ) : (
            <>
              <div className="pair">
                <div className="field">
                  <label>{t("secret.maxVersions")}</label>
                  <input type="text" inputMode="numeric" className="mono" value={cfgDraft.max} onChange={(e) => setCfgDraft((d) => ({ ...d, max: e.target.value.replace(/\D/g, "") }))} placeholder="10" />
                  <span className="hint">{t("engine.maxVersionsHint")}</span>
                </div>
                <div className="field">
                  <label>{t("secret.deleteAfter")}</label>
                  <input type="text" className="mono" value={cfgDraft.after} onChange={(e) => setCfgDraft((d) => ({ ...d, after: e.target.value }))} placeholder="0s" spellCheck={false} />
                  <span className={durationOk(cfgDraft.after) ? "hint" : "hint warn"}>{t("secret.deleteAfterHint")}</span>
                </div>
              </div>
              <div className="between wrap-row">
                <span className="text">
                  <b>{t("secret.casRequired")}</b>
                  <span className="hint">{t("engine.casHint")}</span>
                </span>
                <Toggle on={cfgDraft.cas} onChange={(v) => setCfgDraft((d) => ({ ...d, cas: v }))} />
              </div>
            </>
          )}
        </Disclosure>
      )}

      {!builtin && (
        <DangerZone
          title={t("danger.title")}
          items={[
            ...(isKv && !mount.kv2
              ? [{ label: t("engine.upgrade"), hint: t("engine.upgradeHint"), action: t("engine.upgrade"), onClick: () => setConfirm("upgrade" as const), disabled: busy, tone: "warn" as const }]
              : []),
            { label: t("engine.disable"), hint: mount.auth ? t("engine.disableAuthConfirm") : t("engine.disableConfirm"), action: t("engine.disable"), onClick: () => setConfirm("disable"), disabled: busy },
          ]}
        />
      )}

      {error && <Alert message={error} />}

      {confirm && (
        <Modal
          title={confirm === "disable" ? t("engine.disableTitle", { p: mount.path }) : t("engine.upgradeTitle")}
          onClose={() => setConfirm(null)}
          footer={
            <>
              <button type="button" className={confirm === "disable" ? "btn danger" : "btn primary"} disabled={busy} onClick={act}>
                {busy ? t("action.saving") : confirm === "disable" ? t("engine.disable") : t("engine.upgrade")}
              </button>
              <button type="button" className="btn" onClick={() => setConfirm(null)}>
                {t("action.cancel")}
              </button>
            </>
          }
        >
          <p className="hint">{confirm === "disable" ? (mount.auth ? t("engine.disableAuthConfirm") : t("engine.disableConfirm")) : t("engine.upgradeConfirm")}</p>
        </Modal>
      )}
    </Modal>
  );
}

/// Mounting an engine or an auth method, with a hint for each kind.
function EnableMount({ auth, existing, onClose, onEnabled }: { auth: boolean; existing: string[]; onClose: () => void; onEnabled: (list: Mount[]) => void }) {
  const kinds = auth ? AUTH_KINDS : SECRET_KINDS;
  const [kind, setKind] = useState<string>(kinds[0]);
  const [path, setPath] = useState<string>(kinds[0]);
  const [pathTouched, setPathTouched] = useState(false);
  const [description, setDescription] = useState("");
  const [kvVersion, setKvVersion] = useState<"1" | "2">("2");
  const [defTtl, setDefTtl] = useState("");
  const [maxTtl, setMaxTtl] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const pickKind = (k: string) => {
    setKind(k);
    if (!pathTouched) setPath(k);
  };

  const cleanPath = path.trim().replace(/^\/+/, "").replace(/\/+$/, "");
  const fullPath = auth ? `auth/${cleanPath}` : cleanPath;
  const durationOk = (v: string) => v.trim() === "" || /^\d+(s|m|h)$/.test(v.trim());
  const why =
    cleanPath === ""
      ? t("engine.needPath")
      : !/^[A-Za-z0-9][A-Za-z0-9_./-]*$/.test(cleanPath) || cleanPath.split("/").includes("..")
        ? t("engine.badPath")
        : existing.includes(fullPath) || existing.includes(cleanPath)
          ? t("engine.taken", { p: fullPath })
          : !durationOk(defTtl) || !durationOk(maxTtl)
            ? t("engine.ttlHint")
            : null;

  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      const form: MountForm = {
        path: cleanPath,
        kind,
        description: description.trim(),
        kv_version: !auth && kind === "kv" ? Number(kvVersion) : null,
        default_lease_ttl: auth ? "" : defTtl.trim(),
        max_lease_ttl: auth ? "" : maxTtl.trim(),
        auth,
      };
      onEnabled(await call<Mount[]>("hashicorp", "mount_enable", { form }));
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      title={auth ? t("engine.enableAuth") : t("engine.enable")}
      onClose={onClose}
      onSubmit={() => why === null && !busy && void save()}
      wide
      footer={
        <>
          {why && <span className="foot-why hint">{why}</span>}
          <button type="button" className="btn" onClick={onClose}>
            {t("action.cancel")}
          </button>
          <button type="button" className="btn primary" disabled={busy || why !== null} onClick={() => void save()}>
            {busy ? t("action.saving") : t("engine.enableDo")}
          </button>
        </>
      }
    >
      <div className="field">
        <label>{t("engine.type")}</label>
        <Picker
          value={kind}
          placeholder={t("engine.type")}
          options={kinds.map((k) => ({ id: k, label: k, hint: kindHint(k) }))}
          onChange={pickKind}
        />
        <span className="hint engine-hint">{kindHint(kind)}</span>
      </div>

      <div className="field">
        <label>{t("engine.path")}</label>
        <div className="with-prefix">
          {auth && <span className="prefix mono">auth/</span>}
          <input
            type="text"
            className="mono"
            value={path}
            onChange={(e) => {
              setPath(e.target.value);
              setPathTouched(true);
            }}
            spellCheck={false}
          />
        </div>
        <span className="hint">{auth ? t("engine.pathHintAuth") : t("engine.pathHint")}</span>
      </div>

      <div className="field">
        <label>{t("engine.description")}</label>
        <input type="text" value={description} onChange={(e) => setDescription(e.target.value)} placeholder={t("engine.descriptionPlaceholder")} />
      </div>

      {!auth && kind === "kv" && (
        <div className="field">
          <label>{t("engine.kvVersion")}</label>
          <Segmented<"1" | "2">
            value={kvVersion}
            onChange={setKvVersion}
            options={[
              { id: "2", label: "kv v2" },
              { id: "1", label: "kv v1" },
            ]}
          />
          <span className="hint">{kvVersion === "2" ? t("engine.kvV2Hint") : t("engine.kvV1Hint")}</span>
        </div>
      )}

      {!auth && (
        <Disclosure title={t("engine.leases")}>
          <div className="pair">
            <div className="field">
              <label>{t("engine.defaultTtl")}</label>
              <input type="text" className="mono" value={defTtl} onChange={(e) => setDefTtl(e.target.value)} placeholder={t("engine.ttlSystem")} spellCheck={false} />
              <span className="hint">{t("engine.ttlHint")}</span>
            </div>
            <div className="field">
              <label>{t("engine.maxTtl")}</label>
              <input type="text" className="mono" value={maxTtl} onChange={(e) => setMaxTtl(e.target.value)} placeholder={t("engine.ttlSystem")} spellCheck={false} />
              <span className="hint">{t("engine.maxTtlHint")}</span>
            </div>
          </div>
        </Disclosure>
      )}

      {error && <Alert message={error} />}
    </Modal>
  );
}
