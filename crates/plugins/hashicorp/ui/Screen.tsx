import "./style.css";
import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Alert, CopyButton, DangerZone, Disclosure, Empty, Icon, Modal, Picker, Segmented, Skeleton, Tabs, Toggle, copyText, useEscape } from "@keyward/ui";
import { useEphemeral } from "@keyward/ephemeral";
import { t } from "@keyward/i18n";
import type { Key } from "@keyward/i18n";
import { PolicyStudio } from "./policy/PolicyStudio";
import { Engines } from "./Engines";
import { CodeEditor, envLanguage } from "./policy/CodeEditor";
import { json, jsonParseLinter } from "@codemirror/lang-json";
import { linter, lintGutter } from "@codemirror/lint";
import { PasswordInput } from "@keyward/PasswordInput";
import { call, callWithFields } from "@keyward/plugins/call";
import type { PluginScreenProps } from "@keyward/plugins/types";
import { bumpConnections, setConnecting, setOpened, useConnecting, useOpened } from "./state";
import type { VaultItem } from "@keyward/types";
import type {
  HashicorpLink,
  Health,
  IssueResult,
  Issued,
  Mount,
  Policy,
  Recipient,
  RootToken,
  SealStatus,
  Secret,
  SecretFull,
  SecretMeta,
  SecretMetaPatch,
} from "./types";

const RECIPIENTS: Recipient[] = ["agent", "person", "me"];
/// The defaults repeat the server's (`Recipient::defaults` in the core).
///
/// Nobody has a single-use token here: the first thing any Vault client does is
/// `lookup-self`, the one use burns on that check, and after it everything
/// answers 403. The protection is a short life, not a counter. The agent does
/// not need an envelope either: it puts the token into an environment variable
/// rather than unpacking it.
const DEFAULTS: Record<Recipient, { ttl: number; uses: number; wrap: boolean }> = {
  agent: { ttl: 15, uses: 0, wrap: false },
  person: { ttl: 60, uses: 0, wrap: true },
  me: { ttl: 30, uses: 0, wrap: false },
};

/// The unseal shares lie in fields a person named, and the daemon gives the
/// plugin only its own `kw-` fields. So the screen names the fields and the
/// daemon reads them — under the same Touch ID rules as revealing any field by
/// hand — and puts them into the call as `shares`. The keys go from the daemon
/// to the plugin; the window never holds them.
/// HashiCorp Vault: the server's state, handing out temporary access and taking
/// it back.
export function HashicorpScreen({ catalog, onChanged, onCopied }: PluginScreenProps) {
  const [editing, setEditing] = useState(false);
  // The choice of connection comes from the section's column — through the
  // plugin's store.
  const opened = useOpened();
  const connecting = useConnecting();
  const [link, setLink] = useState<HashicorpLink | null>(null);
  // The address and the unseal keys lie in a secure note: neither a login nor a
  // card has room for either.
  const notes = (catalog?.items ?? []).filter((i) => i.kind === "secure_note");

  // The plugin remembers the active connection itself: the core no longer knows
  // about it.
  const reload = useCallback(() => {
    void call<HashicorpLink | null>("hashicorp", "status")
      .then(setLink)
      .catch(() => setLink(null));
  }, []);
  // Asked again whenever the catalogue changes, not only on mounting: opened
  // while the daemon was still starting or the vault still locked, the screen
  // got "no connection" once and kept it — "Vault is not connected" for good,
  // with the connection sitting right there after the unlock.
  const catalogKey = catalog ? `${catalog.items.length}:${catalog.items.filter((i) => i.kind === "secure_note").length}` : "none";
  useEffect(reload, [reload, catalogKey]);

  const changed = useCallback(() => {
    reload();
    bumpConnections();
    onChanged();
  }, [reload, onChanged]);

  // There is only one connection (or the chosen one is known) — it opens at
  // once: an empty "choose a vault" screen with a single vault is one click too
  // many.
  useEffect(() => {
    if (!opened && link) setOpened(link.entry_id);
  }, [opened, link]);

  // The broker works with whichever connection is chosen in the daemon — so
  // opening a vault and choosing it are one and the same action.
  useEffect(() => {
    if (!opened || opened === link?.entry_id) return;
    void call("hashicorp", "select", { entry_id: opened })
      .then(() => changed())
      .catch(() => {});
  }, [opened, link?.entry_id, changed]);

  // Editing an existing connection is a form, not the ritual all over again.
  // The wizard is needed once: it leads from an empty address to a root token,
  // and running it again means handing out a second root for no reason.
  if (link && editing) {
    return (
      <HashicorpEdit
        link={link}
        notes={notes}
        onDone={() => setEditing(false)}
        onChanged={changed}
      />
    );
  }

  if (!link && !connecting) {
    return (
      <Empty
        icon="vault"
        title={t("hashicorp.absent")}
        body={t("hashicorp.absentBody")}
        action={
          <button type="button" className="btn primary" onClick={() => setConnecting(true)}>
            <Icon name="plus" size={13} />
            {t("hashicorp.connectNew")}
          </button>
        }
      />
    );
  }

  if (connecting || !link) {
    // A new vault is being connected rather than an existing one edited: the
    // address and the note have to be empty, or the very first step slips
    // somebody else's server in.
    return <HashicorpConnect existing={null} notes={notes} onDone={() => setConnecting(false)} onChanged={changed} />;
  }

  // The list of connections lives in the section's column: showing it here as
  // well would mean showing one and the same thing twice.
  if (!opened || opened !== link.entry_id) {
    return (
      <section className="vault-picker-empty">
        <div className="vault-picker-orb" aria-hidden="true"><Icon name="vault" size={24} /></div>
        <span className="vault-picker-kicker">{t("hashicorp.connections")}</span>
        <h1>{t("hashicorp.pickVault")}</h1>
        <p>{t("hashicorp.pickVaultHint")}</p>
        <div className="vault-picker-current">
          <span className="vault-picker-mark"><Icon name="vault" size={17} /></span>
          <span>
            <small>{t("vault.active")}</small>
            <b>{link.entry_name || link.addr}</b>
            <em className="mono">{link.addr}</em>
          </span>
          <button type="button" className="btn primary" onClick={() => setOpened(link.entry_id)}>
            {t("action.continue")}
          </button>
        </div>
        <div className="vault-picker-actions">
          <button type="button" className="btn quiet" onClick={() => setConnecting(true)}>
            <Icon name="plus" size={13} />
            {t("hashicorp.connectMore")}
          </button>
        </div>
      </section>
    );
  }

  return (
    <div className="stack">
      <div className="crumb">
        <span className="crumb-text">
          <b>{link.entry_name || link.addr}</b>
          <span>{link.addr}</span>
        </span>
        {/* The action on a vault stands by its name. In the state bar it
            travelled to the window's right edge — eight hundred pixels from
            the marks it had nothing to do with. */}
        <button type="button" className="btn" onClick={() => setEditing(true)}>
          {t("edit.open")}
        </button>
      </div>
      <Broker link={link} onCopied={onCopied} />
    </div>
  );
}

type VaultTab = "issue" | "issued" | "secrets" | "engines" | "policies" | "root";

/// Whether a policy grants full rights. The same reading as in the broker:
/// `root` and any policy beginning with `sudo`.
/// keyward's policy for creating policies — the name matches `POLICY_ADMIN` in
/// the core.
const POLICY_ADMIN = "keyward-policy-admin";

function isWide(policy: string): boolean {
  const p = policy.trim().toLowerCase();
  return p === "root" || p.startsWith("sudo") || p === POLICY_ADMIN;
}

/// One vault's view: the state on top, then the tabs.
///
/// It all used to lie on one canvas: handing out, what was handed out and the
/// empty state one under another. Each of them is a piece of work of its own,
/// and mixing them means making somebody scroll past what they do not need
/// just now.
function Broker({
  link,
  onCopied,
}: {
  link: HashicorpLink;
  onCopied: (text: string) => void;
}) {
  const [tab, setTab] = useState<VaultTab>(
    // The stand opens the tab wanted by a link: ?vaultTab=policies.
    () => (new URLSearchParams(window.location.search).get("vaultTab") as VaultTab) || "issue",
  );
  const [health, setHealth] = useState<Health | null>(null);
  const [seal, setSeal] = useState<SealStatus | null>(null);
  const [issued, setIssued] = useState<Issued[]>([]);
  const [secretsMount, setSecretsMount] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    call<Health>("hashicorp", "health").then(setHealth).catch((e) => setError(String(e)));
    call<SealStatus>("hashicorp", "seal_status").then(setSeal).catch(() => {});
    call<Issued[]>("hashicorp", "issues").then(setIssued).catch(() => {});
  }, []);

  useEffect(load, [load]);

  // The list of grants lives in time: "3 min left" and "expired" have to change
  // by themselves rather than after the tab is reopened.
  const [now, setNow] = useState(() => Math.floor(Date.now() / 1000));
  useEffect(() => {
    const tick = setInterval(() => {
      setNow(Math.floor(Date.now() / 1000));
      call<Issued[]>("hashicorp", "issues").then(setIssued).catch(() => {});
    }, 30_000);
    return () => clearInterval(tick);
  }, []);
  const live = issued.filter((i) => i.state.state === "active").length;

  // The list of grants grows without end and the cards are heavy: they are
  // shown in portions, and the next is loaded when one screen is left to the
  // end of the list.
  const PAGE = 20;
  const [shownCount, setShownCount] = useState(PAGE);
  const sentinel = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    if (tab !== "issued") return;
    const el = sentinel.current;
    if (!el) return;
    const io = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting)) setShownCount((c) => Math.min(issued.length, c + PAGE));
      },
      { rootMargin: "400px 0px" },
    );
    io.observe(el);
    return () => io.disconnect();
  }, [tab, issued.length, shownCount]);
  // The living ones on top: they are what the tab is opened for.
  const ordered = useMemo(
    () => [...issued].sort((a, b) => Number(b.state.state === "active") - Number(a.state.state === "active") || b.created_at - a.created_at),
    [issued],
  );

  const unseal = async () => {
    setBusy(true);
    setError(null);
    try {
      setSeal(
        link
          ? await callWithFields<SealStatus>("hashicorp", "unseal", {}, { entryId: link.entry_id, fields: link.unseal_fields ?? [], into: "shares" })
          : await call<SealStatus>("hashicorp", "unseal", { shares: [] }),
      );
      load();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      {/* The vault's state in one bar: the seal, the version, the threshold in
          parts, the keys. */}
      <div className={`vault-status${health?.sealed ? " sealed" : ""}`}>
        {health && (
          <span className="stat">
            <span className={`dot ${health.sealed ? "bad" : "ok"}`} />
            <b>{health.sealed ? t("vault.sealed") : t("vault.unsealed")}</b>
            {health.version && <span className="mono dim">{health.version}</span>}
          </span>
        )}
        {seal && seal.t > 0 && (
          <span className="stat" title={t("vault.threshold", { t: seal.t, n: seal.n })}>
            <span className="shares" aria-hidden="true">
              {Array.from({ length: Math.min(seal.n, 10) }, (_, i) => (
                <i key={i} className={i < seal.t ? "need" : ""} />
              ))}
            </span>
            <span>{t("vault.threshold", { t: seal.t, n: seal.n })}</span>
          </span>
        )}
        {link.unseal_keys > 0 && (
          <span className="stat">
            <Icon name="key" size={12} />
            <span>{t("vault.unsealStored", { n: link.unseal_keys })}</span>
          </span>
        )}
        {health && !health.sealed && live > 0 && (
          <span className="stat grow-right">
            <span className="dot ok pulse" />
            <span>{t("vault.liveTokens", { n: live })}</span>
          </span>
        )}
      </div>

      {error && <Alert message={error} onRetry={load} />}

      {seal?.sealed && (
        <div className="banner warn">
          <Icon name="warn" size={15} />
          <span className="grow">
            <b>{t("vault.sealedTitle")}</b>
            <span className="hint">{t("vault.sealedBody", { p: seal.progress, t: seal.t })}</span>
          </span>
          <button type="button" className="btn primary" disabled={busy || link.unseal_keys === 0} onClick={() => void unseal()}>
            {busy ? t("vault.unsealing") : t("vault.unsealAction")}
          </button>
        </div>
      )}

      <Tabs
        value={tab}
        onChange={setTab}
        options={[
          { id: "issue", label: t("vault.tab.issue"), icon: "key" },
          { id: "issued", label: t("vault.tab.issued"), count: live, icon: "clock" },
          { id: "secrets", label: t("vault.tab.secrets"), icon: "folder" },
          { id: "engines", label: t("vault.tab.engines"), icon: "settings" },
          { id: "policies", label: t("vault.tab.policies"), icon: "shield" },
          { id: "root", label: t("vault.tab.root"), icon: "lock" },
        ]}
      />

      <div className={`tab-panel tab-${tab}`} key={tab}>
      {tab === "issue" && (
        <IssueForm sealed={seal?.sealed === true} onIssued={load} onCopied={onCopied} />
      )}

      {tab === "issued" &&
        (issued.length === 0 ? (
          <Empty icon="vault" title={t("vault.noIssues")} body={t("vault.noIssuesHint")} />
        ) : (
          <div className="list">
            {ordered.slice(0, shownCount).map((i) => (
              <IssuedCard
                key={i.accessor}
                issued={i}
                now={now}
                busy={busy}
                onRevoke={() =>
                  void (async () => {
                    setBusy(true);
                    try {
                      setIssued(await call<Issued[]>("hashicorp", "revoke", { accessor: i.accessor }));
                    } catch (e) {
                      setError(String(e));
                    } finally {
                      setBusy(false);
                    }
                  })()
                }
              />
            ))}
            {shownCount < ordered.length && (
              <div className="load-more" ref={sentinel}>
                <span className="hint">{t("vault.moreIssues", { shown: shownCount, total: ordered.length })}</span>
                <button type="button" className="btn" onClick={() => setShownCount((c) => Math.min(ordered.length, c + PAGE))}>
                  {t("vault.loadMore")}
                </button>
              </div>
            )}
          </div>
        ))}

      {tab === "secrets" && <Secrets onCopied={onCopied} initialMount={secretsMount} />}

      {tab === "engines" && (
        <Engines
          onOpenSecrets={(m) => {
            setSecretsMount(m);
            setTab("secrets");
          }}
        />
      )}

      {tab === "policies" && <Policies />}

      {tab === "root" && <Roots addr={link.addr} />}
      </div>
    </>
  );
}

/// How long a token is to live. The ready-made spans cover almost every case,
/// and typing minutes by hand is rarely needed — which is why they are hidden
/// behind "otherwise".
const TTL_PRESETS = [5, 15, 60, 480];
/// The scale counts how many times the recipient will use the token
/// themselves. One more goes to Vault: any client spends its first use on a
/// self-check (`lookup-self`), and a single-use token dies having done nothing
/// useful. Fewer than five are not offered for the same reason.
const USES_PRESETS = [0, 5, 10, 25];
const SELF_CHECK_USES = 1;

/// The date and time, short: "9 Sep, 09:22". The year is not needed — tokens
/// live for hours.
function when(secs: number): string {
  return new Date(secs * 1000).toLocaleString(undefined, {
    day: "numeric",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function ttlLabel(seconds: number): string {
  const m = Math.round(seconds / 60);
  return m < 60 ? t("ttl.minutes", { n: m }) : t("ttl.hours", { n: Math.round(m / 60) });
}

/// One grant: the status, to whom and what for, the policies, and the bare
/// facts — when it was issued, when it ends or ended, how many uses, how it was
/// handed over.
function IssuedCard({
  issued: i,
  now,
  busy,
  onRevoke,
}: {
  issued: Issued;
  now: number;
  busy: boolean;
  onRevoke: () => void;
}) {
  const ends = i.created_at + i.ttl_seconds;
  const leftSecs = ends - now;
  // The daemon marks an expiry by Vault's answer, but time passes between
  // polls, and "in force, 0 min left" would look like a lie.
  const state = i.state.state === "active" && leftSecs <= 0 ? "expired" : i.state.state;
  const active = state === "active";
  const status = active ? t("vault.active") : state === "revoked" ? t("vault.revoked") : t("vault.expired");
  const chip = active ? (leftSecs < 300 ? "chip warn" : "chip ok") : state === "revoked" ? "chip bad" : "chip";
  const left = leftSecs < 60 ? t("vault.leftSoon") : t("vault.left", { m: Math.round(leftSecs / 60) });

  return (
    <div className={`issue-card ${active ? (leftSecs < 300 ? "soon" : "live") : "off"}`}>
      <div className="issue-head">
        <span className={`glyph tile ${i.recipient}`}>
          <Icon name={i.recipient === "agent" ? "route" : i.recipient === "person" ? "identity" : "login"} size={14} />
        </span>
        <span className={`${chip} dot`}>{status}</span>
        <b>{t(`vault.recipient.${i.recipient}` as Key)}</b>
        {i.note && <span className="issue-note">{i.note}</span>}
        <span className="side">
          {active && (
            <button type="button" className="btn danger" disabled={busy} onClick={onRevoke}>
              {t("vault.revoke")}
            </button>
          )}
        </span>
      </div>

      {active && (
        <div className="issue-bar" aria-hidden="true">
          <i style={{ width: `${Math.max(2, Math.min(100, (leftSecs / Math.max(1, i.ttl_seconds)) * 100))}%` }} />
        </div>
      )}

      <div className="issue-policies">
        {i.policies.map((p) => (
          <span key={p} className={isWide(p) ? "chip warn" : "chip"}>
            {p}
          </span>
        ))}
      </div>

      <dl className="issue-facts">
        <dt>{t("vault.issuedAt")}</dt>
        <dd>{when(i.created_at)}</dd>

        <dt>{t("vault.ttlLabel")}</dt>
        <dd>
          {ttlLabel(i.ttl_seconds)}
          {" · "}
          {active
            ? t("vault.expiresAt", { when: when(ends), left })
            : state === "revoked"
              ? t("vault.revokedBefore", { when: when(ends) })
              : t("vault.expiredAt", { when: when(ends) })}
        </dd>

        <dt>{t("vault.uses")}</dt>
        <dd>{i.num_uses === 0 ? t("vault.usesUnlimited") : t("vault.usesN", { n: i.num_uses })}</dd>

        <dt>{t("vault.handover")}</dt>
        <dd>{i.wrapped ? t("vault.byWrap") : t("vault.byToken")}</dd>

        <dt>{t("vault.accessor")}</dt>
        <dd className="mono">{i.accessor}</dd>
      </dl>
    </div>
  );
}

/// Handing out access.
function IssueForm({
  sealed,
  onIssued,
  onCopied,
}: {
  sealed: boolean;
  onIssued: () => void;
  onCopied: (text: string) => void;
}) {
  const [recipient, setRecipient] = useState<Recipient>("agent");
  const [policies, setPolicies] = useState<string[]>([]);
  const [ttl, setTtl] = useState(DEFAULTS.agent.ttl);
  const [uses, setUses] = useState(DEFAULTS.agent.uses);
  const [wrap, setWrap] = useState(DEFAULTS.agent.wrap);
  const [wideOk, setWideOk] = useState(false);
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<IssueResult | null>(null);

  // The policies with full rights: choosing them changes both the warning and
  // the limit on the span — an hour instead of a day.
  const wide = policies.filter(isWide);

  const pick = (r: Recipient) => {
    setRecipient(r);
    setTtl(DEFAULTS[r].ttl);
    setUses(DEFAULTS[r].uses);
    setWrap(DEFAULTS[r].wrap);
  };

  const issue = async () => {
    setBusy(true);
    setError(null);
    try {
      setResult(
        await call<IssueResult>("hashicorp", "issue", {
          request: {
            recipient,
            policies,
            ttl_seconds: Math.max(1, Math.round(ttl * 60)),
            num_uses: uses === 0 ? 0 : uses + SELF_CHECK_USES,
            wrap,
            note,
            wide_ok: wideOk,
          },
        }),
      );
      onIssued();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="form wide">
      <div className="cols">
        <section className="block tone-sky">
          <h4 className="block-title">{t("vault.block.who")}</h4>
          <div className="field">
            <label>{t("vault.recipient")}</label>
            <Segmented
              value={recipient}
              onChange={pick}
              options={RECIPIENTS.map((r) => ({ id: r, label: t(`vault.recipient.${r}` as Key) }))}
            />
          </div>

          <div className="field">
            <label>{t("vault.policies")}</label>
            <PolicyPicker value={policies} onChange={setPolicies} />
          </div>

          <div className="field">
            <label>{t("vault.note")}</label>
            <input
              value={note}
              onChange={(e) => setNote(e.target.value)}
              aria-label={t("vault.note")}
              placeholder={t("vault.notePlaceholder")}
            />
          </div>

        </section>

        <section className="block tone-mint">
          <h4 className="block-title">{t("vault.block.terms")}</h4>
          <div className="field">
            <label>{t("vault.ttl")}</label>
            <Choice
              title={t("vault.ttl")}
              otherIcon="clock"
              value={ttl}
              presets={TTL_PRESETS}
              label={(m) => (m < 60 ? t("ttl.minutes", { n: m }) : t("ttl.hours", { n: Math.round(m / 60) }))}
              onChange={setTtl}
            />
          </div>

          <div className="field">
            <label>{t("vault.uses")}</label>
            <Choice
              title={t("vault.uses")}
              min={USES_PRESETS[1]}
              value={uses}
              presets={USES_PRESETS}
              label={(n) => (n === 0 ? t("uses.unlimited") : String(n))}
              onChange={setUses}
            />
            {uses > 0 && <span className="hint">{t("vault.usesHint", { n: uses + SELF_CHECK_USES })}</span>}
          </div>

          {/* How to hand it over gets a block of its own: switches among
              lists of values read as one more list. */}
          <div className="form-block">
            <h4 className="form-section">{t("vault.handover")}</h4>
            <div className="between wrap-row">
              <span className="text">
                <b>{t("vault.wrap")}</b>
                <span className="hint">{t("vault.wrapHint")}</span>
              </span>
              <Toggle on={wrap} onChange={setWrap} />
            </div>

            {/* Full rights need a consent of their own rather than a silent
                permission: root and sudo-* stand in the list of policies next
                to the harmless ones, and hitting them by mistake is far too
                easy. */}
            {wide.length > 0 && (
              <div className="between wrap-row">
                <span className="text">
                  <b>{t("vault.wide")}</b>
                  <span className="hint">{t("vault.wideHint", { p: wide.join(", ") })}</span>
                </span>
                <Toggle on={wideOk} onChange={setWideOk} />
              </div>
            )}
          </div>

        </section>
      </div>

      {error && <Alert message={error} />}

      <div className="between line submit-row">
        <span className="issue-summary">
          <span className="chips">
            <span className="chip on">{t(`vault.recipient.${recipient}` as Key)}</span>
            <span className="chip">{ttl < 60 ? t("ttl.minutes", { n: ttl }) : t("ttl.hours", { n: Math.round(ttl / 60) })}</span>
            <span className="chip">{uses === 0 ? "∞" : `${uses + SELF_CHECK_USES}×`}</span>
            <span className="chip">{wrap ? t("vault.wrappingToken") : t("vault.token")}</span>
            {policies.map((p) => (
              <span key={p} className={isWide(p) ? "chip warn" : "chip ok"}>
                {p}
              </span>
            ))}
          </span>
          <span className={policies.length === 0 || (wide.length > 0 && !wideOk) ? "hint warn" : "hint"}>
            {policies.length === 0
              ? t("vault.needPolicy")
              : wide.length > 0 && !wideOk
                ? t("vault.wideNeeded")
                : t("vault.summary", { n: policies.length })}
          </span>
        </span>
        <button type="button"
          className="btn primary"
          disabled={busy || policies.length === 0 || sealed || (wide.length > 0 && !wideOk)}
          onClick={() => void issue()}
        >
          {busy ? t("action.saving") : t("vault.issue")}
        </button>
      </div>

      {result && (
        <Modal
          title={t("vault.issued")}
          onClose={() => setResult(null)}
          footer={
            <>
              <span className="foot-why hint">{t("vault.issuedOnce")}</span>
              <button
                type="button"
                className="btn primary"
                onClick={() => void copyText(result.wrapping_token ?? result.token ?? "").then(() => onCopied(t("action.copied")))}
              >
                <Icon name="copy" size={13} />
                {t("action.copy")}
              </button>
            </>
          }
        >
          <div className="field">
            <label>{result.wrapping_token ? t("vault.wrappingToken") : t("vault.token")}</label>
            <IssuedToken value={result.wrapping_token ?? result.token ?? ""} />
            {result.wrapping_token && <span className="hint">{t("vault.unwrapHow")}</span>}
          </div>
        </Modal>
      )}
    </div>
  );
}

/// A number from ready-made choices, with typing by hand as a fallback.
///
/// The native `input[type=number]` draws arrows of its own that obey neither
/// the size nor the colour of everything else — which is why it is not here.
function Choice({
  title,
  value,
  presets,
  label,
  min = 0,
  otherIcon,
  onChange,
}: {
  /// The heading of the dialogue for typing by hand — the name of the field
  /// being edited.
  title: string;
  value: number;
  presets: number[];
  label: (n: number) => string;
  /// The lower bound for values that are not zero; zero stays "no limit".
  min?: number;
  /// The icon on the cell for typing by hand, in place of the word
  /// "otherwise".
  otherIcon?: string;
  onChange: (n: number) => void;
}) {
  // Typing by hand happens in a dialogue rather than in the same row: a field
  // that popped up in the scale's place broke the form's grid and had no clear
  // "done".
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState("");
  const custom = !presets.includes(value);

  const open = () => {
    setDraft(custom ? String(value) : "");
    setEditing(true);
  };
  const apply = () => {
    const n = Number(draft.replace(/\D/g, "")) || 0;
    onChange(n === 0 ? 0 : Math.max(min, n));
    setEditing(false);
  };

  return (
    <>
      <div className="choice">
        <div className="cells">
          {presets.map((p) => (
            <button key={p} type="button" className={p === value ? "on" : ""} onClick={() => onChange(p)}>
              {label(p)}
            </button>
          ))}
          <button
            type="button"
            className={custom ? "other on" : "other"}
            onClick={open}
            aria-label={t("choice.other")}
            title={t("choice.other")}
          >
            {custom ? label(value) : otherIcon ? <Icon name={otherIcon} size={13} /> : t("choice.other")}
          </button>
        </div>
      </div>

      {editing && (
        <Modal
          title={title}
          onClose={() => setEditing(false)}
          onSubmit={apply}
          footer={
            <>
              <button type="button" className="btn" onClick={() => setEditing(false)}>
                {t("action.cancel")}
              </button>
              <button type="button" className="btn primary" onClick={apply}>
                {t("action.save")}
              </button>
            </>
          }
        >
          <div className="field">
            <input
              type="text"
              inputMode="numeric"
              value={draft}
              placeholder={min > 0 ? String(min) : undefined}
              onChange={(e) => setDraft(e.target.value.replace(/\D/g, ""))}
              autoFocus
            />
            {min > 0 && <span className="hint">{t("choice.min", { n: min })}</span>}
          </div>
        </Modal>
      )}
    </>
  );
}

/// Choosing policies from those the server has.
///
/// There used to be a text field here: a name typed wrongly Vault accepts
/// without a word, and the token turns out to have no rights — and sorting that
/// out then falls to whoever it was handed to.
function PolicyPicker({ value, onChange }: { value: string[]; onChange: (v: string[]) => void }) {
  const [names, setNames] = useState<string[] | null>(null);
  const [rules, setRules] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [ensuring, setEnsuring] = useState(false);

  // A token for bootstrapping: the agent has to describe its own paths in
  // Vault, and root must not be given out for that. The policy is created by
  // the daemon from a canonical body and reaches the choice at once; the form
  // will ask for consent to the wide rights.
  const ensureAdmin = async () => {
    setEnsuring(true);
    try {
      setNames(await call<string[]>("hashicorp", "ensure_policy_admin"));
      setError(null);
      if (!value.includes(POLICY_ADMIN)) onChange([...value, POLICY_ADMIN]);
    } catch (e) {
      setError(String(e));
    } finally {
      setEnsuring(false);
    }
  };

  const load = useCallback(() => {
    call<string[]>("hashicorp", "policies")
      .then((n) => {
        setNames(n);
        setError(null);
      })
      .catch((e) => setError(String(e)));
  }, []);

  useEffect(load, [load]);

  // The chosen policy's body — so that next to the name it is visible what it
  // allows at all. A name like "kv-read" says nothing about the path or the
  // rights, and a mistake here means handing out the wrong access.
  useEffect(() => {
    for (const name of value) {
      if (name in rules) continue;
      void call<Policy>("hashicorp", "policy", { name })
        .then((p) => setRules((cur) => ({ ...cur, [name]: p.rules })))
        .catch(() => setRules((cur) => ({ ...cur, [name]: "" })));
    }
  }, [value, rules]);

  const free = (names ?? []).filter((n) => !value.includes(n) && n !== "root");

  return (
    <>
      <div className="row-actions">
        <Picker
          value={null}
          placeholder={names === null ? t("policy.loading") : t("policy.add")}
          options={free.map((n) => ({ id: n, label: n }))}
          onChange={(id) => onChange([...value, id])}
          // What is chosen sits inside the control, and what each policy allows
          // is its tooltip: the list of paths used to stand beside the name and
          // grew the form every time a policy was added.
          picked={value.map((n) => ({ id: n, label: n, hint: accesses(rules[n]) }))}
          onUnpick={(id) => onChange(value.filter((x) => x !== id))}
        />
        <button type="button" className="btn" onClick={() => setCreating(true)}>
          <Icon name="plus" size={13} />
          {t("policy.new")}
        </button>
        {!value.includes(POLICY_ADMIN) && (
          <button
            type="button"
            className="btn"
            disabled={ensuring}
            title={t("policy.adminHint")}
            onClick={() => void ensureAdmin()}
          >
            {ensuring ? t("policy.reading") : t("policy.admin")}
          </button>
        )}
      </div>

      {/* What each chosen policy allows, folded away. The chip carries the
          same thing as a tooltip for a quick look; this is for reading, when
          the question is which of the three gives the write. */}
      {value.length > 0 && (
        <Disclosure title={t("policy.scopes")}>
          <ul className="policy-scopes">
            {value.map((n) => (
              <li key={n}>
                <b>{n}</b>
                <span>{summarize(rules[n])}</span>
              </li>
            ))}
          </ul>
        </Disclosure>
      )}

      {/* The explanation is needed once but took up room always: two
          paragraphs of grey text were taller and wider than the fields they
          belong to. */}
      <Disclosure title={t("policy.howItWorks")}>
        <span className="hint">{t("policy.what")}</span>
        <span className="hint">{t("vault.defaultPolicy")}</span>
      </Disclosure>

      {error && <Alert message={error} onRetry={load} />}

      {creating && (
        <PolicyStudio
          policy={null}
          onClose={() => setCreating(false)}
          onSaved={(p) => {
            load();
            onChange([...value, p.name]);
            setCreating(false);
          }}
        />
      )}
    </>
  );
}

/// What a policy allows, path by path.
///
/// Not a reading of the whole HCL: the paths and the rights are enough, and the
/// full body can always be opened in the "Policies" section.
function paths(rules: string): string[] {
  const out: string[] = [];
  const blocks = rules.matchAll(/path\s+"([^"]+)"\s*\{([^}]*)\}/g);
  for (const [, path, body] of blocks) {
    const caps = [...body.matchAll(/"([a-z-]+)"/g)].map((m) => m[1]);
    const wide = caps.some((c) => ["create", "update", "delete", "sudo"].includes(c));
    out.push(`${path} — ${wide ? t("policy.rw") : t("policy.ro")}`);
  }
  return out;
}

/// The same in one line, for a row that has room for one line.
function summarize(rules: string | undefined): string {
  if (rules === undefined) return t("policy.reading");
  if (!rules.trim()) return t("policy.builtinWhat");
  const out = paths(rules);
  return out.length > 0 ? out.join(" · ") : t("policy.unknownWhat");
}

/// The same for a tooltip: one path to a line, so that a policy with ten of
/// them is read rather than skimmed. A tooltip has room; a form does not.
function accesses(rules: string | undefined): string {
  if (rules === undefined) return t("policy.reading");
  if (!rules.trim()) return t("policy.builtinWhat");
  const out = paths(rules);
  return out.length > 0 ? out.join("\n") : t("policy.unknownWhat");
}

/// The "Policies" section: look at what there is, and create a new one.
function Policies() {
  const [names, setNames] = useState<string[] | null>(null);
  const [opened, setOpened] = useState<Policy | null>(null);
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<Policy | null>(null);
  const [confirm, setConfirm] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [rules, setRules] = useState<Record<string, string>>({});

  const load = useCallback(() => {
    call<string[]>("hashicorp", "policies").then(setNames).catch((e) => setError(String(e)));
  }, []);

  useEffect(load, [load]);

  const builtin = (n: string) => n === "root" || n === "default";

  // A row's subtitle is what the policy allows. The bodies are pulled one by
  // one in the background; the list does not wait for them but fills itself
  // in.
  useEffect(() => {
    if (!names) return;
    for (const n of names.slice(0, 40)) {
      if (n in rules || builtin(n)) continue;
      void call<Policy>("hashicorp", "policy", { name: n })
        .then((p) => setRules((cur) => ({ ...cur, [n]: p.rules })))
        .catch(() => setRules((cur) => ({ ...cur, [n]: "" })));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [names]);

  const remove = async (name: string) => {
    setBusy(true);
    try {
      setNames(await call<string[]>("hashicorp", "delete_policy", { name }));
      setOpened(null);
      setConfirm(null);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const edit = (name: string) =>
    void call<Policy>("hashicorp", "policy", { name })
      .then((p) => {
        setOpened(null);
        setEditing(p);
      })
      .catch((e) => setError(String(e)));

  if (error) return <Alert message={error} onRetry={load} />;
  if (!names) return <Skeleton rows={4} />;

  return (
    <>
      <div className="section-head">
        <span className="title">
          <b>{t("vault.tab.policies")}</b>
          <span className="hint">{t("policy.count", { n: names.length })}</span>
        </span>
        <button type="button" className="btn primary" onClick={() => setCreating(true)}>
          <Icon name="plus" size={13} />
          {t("policy.new")}
        </button>
      </div>

      {/* Editing and deleting live in the row itself, on hover: there is no
          need to open a card for one button. Vault's built-in policies are not
          touched, and they have no buttons. */}
      <div className="list">
        {names.map((n) => (
          <div key={n} className="row conn policy-row">
            <button
              type="button"
              className="row-main"
              onClick={() => void call<Policy>("hashicorp", "policy", { name: n }).then(setOpened).catch((e) => setError(String(e)))}
            >
              <span className={isWide(n) ? "glyph shield wide" : "glyph shield"}><Icon name="shield" size={15} /></span>
              <span className="text">
                <b>{n}</b>
                {builtin(n) ? (
                  <span>{t("policy.builtin")}</span>
                ) : isWide(n) ? (
                  <span>{t("policy.wideRow")}</span>
                ) : n in rules ? (
                  <span>{summarize(rules[n])}</span>
                ) : (
                  <span>{t("policy.reading")}</span>
                )}
              </span>
            </button>
            <span className="side">
              {!builtin(n) && (
                <>
                  <button
                    type="button"
                    className="btn icon-only reveal"
                    aria-label={t("policy.edit")}
                    title={t("policy.edit")}
                    onClick={() => edit(n)}
                  >
                    <Icon name="edit" size={13} />
                  </button>
                  <button
                    type="button"
                    className="btn icon-only reveal"
                    aria-label={t("policy.delete")}
                    title={t("policy.delete")}
                    onClick={() => setConfirm(n)}
                  >
                    <Icon name="trash" size={13} />
                  </button>
                </>
              )}
              <Icon name="chevron" size={13} />
            </span>
          </div>
        ))}
      </div>

      {opened && (
        <Modal
          title={opened.name}
          onClose={() => setOpened(null)}
          wide
          footer={
            builtin(opened.name) ? undefined : (
              <button
                type="button"
                className="btn primary"
                onClick={() => {
                  setEditing(opened);
                  setOpened(null);
                }}
              >
                <Icon name="edit" size={13} />
                {t("policy.edit")}
              </button>
            )
          }
        >
          <pre className="secret">{opened.rules.trim() || t("policy.empty")}</pre>
          {!builtin(opened.name) && (
            <DangerZone
              title={t("danger.title")}
              items={[{ label: t("policy.delete"), hint: t("policy.deleteConfirm"), action: t("policy.delete"), onClick: () => setConfirm(opened.name) }]}
            />
          )}
        </Modal>
      )}

      {confirm && (
        <Modal
          title={t("policy.deleteTitle", { name: confirm })}
          onClose={() => setConfirm(null)}
          footer={
            <>
              <button type="button" className="btn danger" disabled={busy} onClick={() => void remove(confirm)}>
                {busy ? t("action.saving") : t("policy.delete")}
              </button>
              <button type="button" className="btn" onClick={() => setConfirm(null)}>
                {t("action.cancel")}
              </button>
            </>
          }
        >
          <p className="hint">{t("policy.deleteConfirm")}</p>
        </Modal>
      )}

      {editing && (
        <PolicyStudio
          policy={editing}
          onClose={() => setEditing(null)}
          onSaved={(p) => {
            load();
            setEditing(null);
            setOpened(p);
          }}
        />
      )}

      {creating && (
        <PolicyStudio
          policy={null}
          onClose={() => setCreating(false)}
          onSaved={(p) => {
            load();
            setCreating(false);
            setOpened(p);
          }}
        />
      )}
    </>
  );
}

/// The root tokens: what has been handed out and what of it is still alive.
///
/// Root is access to everything at once, so here there is not only a list but
/// the one action worth taking with it: revoke.
function Roots({ addr }: { addr: string }) {
  const [tokens, setTokens] = useState<RootToken[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<RootToken | null>(null);

  const load = useCallback(() => {
    call<RootToken[]>("hashicorp", "root_tokens").then(setTokens).catch((e) => setError(String(e)));
  }, []);

  useEffect(load, [load]);

  const revoke = async (token: RootToken) => {
    setBusy(token.addr);
    setError(null);
    try {
      await call("hashicorp", "revoke_root", { addr: token.addr });
      setConfirm(null);
      load();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(null);
    }
  };

  if (error) return <Alert message={error} onRetry={load} />;
  if (!tokens) return <Skeleton rows={3} />;
  if (tokens.length === 0)
    return <Empty icon="lock" title={t("root.none")} body={t("root.noneHint", { addr })} />;

  return (
    <>
      <Alert tone="warn" message={t("root.warn")} />

      <div className="list">
        {tokens.map((r) => {
          const alive = r.info !== null;
          return (
            <div className="row" key={r.entry_id}>
              <span className="glyph">
                <Icon name={alive ? "shield" : "lock"} size={15} />
              </span>
              <span className="text">
                <b>{r.addr}</b>
                <span>
                  {r.issued_at > 0 ? t("root.issued", { when: when(r.issued_at) }) : t("root.issuedUnknown")}
                  {r.info ? ` · ${t("root.accessor", { a: r.info.accessor.slice(0, 12) })}` : ` · ${t("root.dead")}`}
                </span>
              </span>
              <span className="side">
                <span className={`chip ${alive ? "warn" : ""}`}>{alive ? t("root.alive") : t("root.dead")}</span>
                {alive && (
                  <button type="button" className="btn danger" disabled={busy === r.addr} onClick={() => setConfirm(r)}>
                    {t("root.revoke")}
                  </button>
                )}
              </span>
            </div>
          );
        })}
      </div>

      {confirm && (
        <Modal
          title={t("root.revokeTitle")}
          onClose={() => setConfirm(null)}
          footer={
            <>
              <button type="button" className="btn danger" disabled={busy !== null} onClick={() => void revoke(confirm)}>
                {busy ? t("action.saving") : t("root.revoke")}
              </button>
              <button type="button" className="btn" onClick={() => setConfirm(null)}>
                {t("action.cancel")}
              </button>
            </>
          }
        >
          <p className="hint">{t("root.revokeBody", { addr: confirm.addr })}</p>
        </Modal>
      )}
    </>
  );
}

/// The kv engines' secrets: the engine, the folders and the keys along a path,
/// reading and writing.
function Secrets({ onCopied, initialMount = null }: { onCopied: (text: string) => void; initialMount?: string | null }) {
  const [mounts, setMounts] = useState<Mount[] | null>(null);
  const [mount, setMount] = useState<string | null>(initialMount);
  const [pickingMount, setPickingMount] = useState(false);
  const [path, setPath] = useState("");
  const [keys, setKeys] = useState<string[] | null>(null);
  const [opened, setOpened] = useState<Secret | null>(null);
  const [editing, setEditing] = useState<{ mount: string; path: string; data: Record<string, string>; version: number | null } | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    call<Mount[]>("hashicorp", "mounts")
      .then((all) => {
        const kv = all.filter((m) => m.kind === "kv" || m.kind === "generic");
        setMounts(kv);
        setMount((cur) => cur ?? kv[0]?.path ?? null);
      })
      .catch((e) => setError(String(e)));
  }, []);

  const list = useCallback(() => {
    if (!mount) return;
    setKeys(null);
    call<string[]>("hashicorp", "secret_list", { mount, path })
      .then((k) => {
        setKeys(k);
        setError(null);
      })
      .catch((e) => setError(String(e)));
  }, [mount, path]);

  useEffect(list, [list]);

  const open = (name: string) =>
    void call<Secret>("hashicorp", "secret_read", { mount, path: path + name })
      .then(setOpened)
      .catch((e) => setError(String(e)));

  const crumbs = path.split("/").filter(Boolean);
  const current = mounts?.find((m) => m.path === mount) ?? null;

  if (error && keys === null && mounts === null) return <Alert message={error} onRetry={list} />;
  if (!mounts) return <Skeleton rows={4} />;
  if (mounts.length === 0 || !mount) {
    return <Empty icon="folder" title={t("secret.noMounts")} body={t("secret.noMountsHint")} />;
  }

  return (
    <>
      <div className="section-head">
        <span className="title">
          <b>{t("vault.tab.secrets")}</b>
          {keys && <span className="hint">{t("secret.count", { n: keys.length })}</span>}
        </span>
        <button
          type="button"
          className="btn primary"
          onClick={() => setEditing({ mount, path: "", data: {}, version: null })}
        >
          <Icon name="plus" size={13} />
          {t("secret.new")}
        </button>
      </div>

      {/* Where we are: the engine and the path. The engine is always a choice,
          even when there is one: that way it is visible what this place is and
          which version of kv it is. */}
      <div className="path-crumbs">
        {/* The engine is chosen in a dialogue: a list with the version and the
            description reads better than a drop-down, and choosing is a rare
            action. */}
        <button type="button" className="crumb mount" onClick={() => setPickingMount(true)} title={t("policy.pickMount")}>
          <Icon name="folder" size={12} />
          {mount}
          <span className="down"><Icon name="chevron" size={11} /></span>
        </button>
        <button type="button" className="crumb root" onClick={() => setPath("")} title={t("secret.toRoot")} aria-label={t("secret.toRoot")}>
          <Icon name="folder" size={12} />
        </button>
        {crumbs.map((seg, i) => (
          <span key={i} className="crumb-wrap">
            <button type="button" className="crumb" onClick={() => setPath(crumbs.slice(0, i + 1).join("/") + "/")}>
              {seg}
            </button>
            <span className="sep">/</span>
          </span>
        ))}
        {current && <span className={current.kv2 ? "chip on" : "chip"}>{current.kv2 ? "kv v2" : "kv v1"}</span>}
      </div>

      {pickingMount && (
        <MountModal
          mounts={mounts}
          value={mount}
          onClose={() => setPickingMount(false)}
          onPick={(id) => {
            setMount(id);
            setPath("");
          }}
        />
      )}

      {error && <Alert message={error} onRetry={list} />}

      {keys === null ? (
        <Skeleton rows={4} />
      ) : keys.length === 0 ? (
        <Empty
          icon="folder"
          title={t("secret.empty")}
          body={t("secret.emptyHint")}
        />
      ) : (
        <div className="list">
          {keys.map((k) => {
            const folder = k.endsWith("/");
            return (
              <button
                key={k}
                type="button"
                className="row conn"
                onClick={() => (folder ? setPath(path + k) : open(k))}
              >
                <span className={folder ? "glyph folder" : "glyph key"}>
                  <Icon name={folder ? "folder" : "key"} size={15} />
                </span>
                <span className="text">
                  <b>{folder ? k.slice(0, -1) : k}</b>
                  {folder && <span>{t("secret.folder")}</span>}
                </span>
                <span className="side">
                  <Icon name="chevron" size={13} />
                </span>
              </button>
            );
          })}
        </div>
      )}

      {opened && current && (
        <SecretView
          secret={opened}
          kv2={current.kv2}
          onClose={() => setOpened(null)}
          onCopied={onCopied}
          onChanged={(s) => setOpened(s)}
          onDeleted={(keysAfter) => {
            setOpened(null);
            setKeys(keysAfter);
          }}
          onEdit={() => {
            // The values are loaded only now, for the editor: a person is
            // changing them.
            void call<SecretFull>("hashicorp", "secret_read_full", { mount: opened.mount, path: opened.path, version: opened.version })
              .then((full) => {
                setEditing({ mount: full.mount, path: full.path, data: full.data, version: full.version });
                setOpened(null);
              })
              .catch((e) => setError(String(e)));
          }}
        />
      )}

      {editing && (
        <SecretEditor
          mounts={mounts}
          initial={editing}
          prefix={editing.path === "" ? path : ""}
          onClose={() => setEditing(null)}
          onSaved={(s) => {
            setEditing(null);
            if (s.mount !== mount) {
              setMount(s.mount);
              setPath(s.path.includes("/") ? s.path.slice(0, s.path.lastIndexOf("/") + 1) : "");
            } else {
              list();
            }
            setOpened(s);
          }}
        />
      )}
    </>
  );
}

function fmtIso(iso: string | null): string {
  if (!iso) return "";
  const ts = Date.parse(iso);
  return Number.isNaN(ts) ? iso : when(Math.floor(ts / 1000));
}

/// A secret's card: the values, the versions and all of the handling — as in
/// Vault's own interface. The values are hidden until they are asked for:
/// secrets on the screen are what can be seen over a shoulder.
/// Choosing a kv engine in a dialogue with a list: the path, the kv version,
/// the description.
function MountModal({
  mounts,
  value,
  onPick,
  onClose,
}: {
  mounts: Mount[];
  value: string | null;
  onPick: (id: string) => void;
  onClose: () => void;
}) {
  return (
    <Modal title={t("policy.pickMount")} onClose={onClose}>
      <div className="list pick-list">
        {mounts.map((m) => (
          <button
            type="button"
            key={m.path}
            className={`row pick ${m.path === value ? "on" : ""}`}
            onClick={() => {
              onPick(m.path);
              onClose();
            }}
          >
            <span className="glyph"><Icon name="folder" size={14} /></span>
            <span className="text">
              <b>{m.path}</b>
              <span>{m.kv2 ? "kv v2" : "kv v1"}{m.description ? ` · ${m.description}` : ""}</span>
            </span>
            {m.path === value && <Icon name="check" size={13} />}
          </button>
        ))}
      </div>
    </Modal>
  );
}

function SecretView({
  secret,
  kv2,
  onClose,
  onCopied,
  onEdit,
  onChanged,
  onDeleted,
}: {
  secret: Secret;
  kv2: boolean;
  onClose: () => void;
  onCopied: (text: string) => void;
  onEdit: () => void;
  onChanged: (s: Secret) => void;
  onDeleted: (keys: string[]) => void;
}) {
  const [meta, setMeta] = useState<SecretMeta | null>(null);
  const [viewing, setViewing] = useState<Secret>(secret);
  // A shown value hides itself soon, and at once when the window is left.
  const { values: shown, keep: showValue, forget: hideValue, forgetAll: hideAll } = useEphemeral(viewing);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<{ kind: "delete" | "purge" | "destroy" | "rollback"; version?: number } | null>(null);
  const [metaEdit, setMetaEdit] = useState(false);

  const loadMeta = useCallback(() => {
    if (!kv2) return;
    call<SecretMeta>("hashicorp", "secret_meta", { mount: secret.mount, path: secret.path })
      .then(setMeta)
      .catch((e) => setError(String(e)));
  }, [kv2, secret.mount, secret.path]);

  useEffect(loadMeta, [loadMeta]);
  useEffect(() => setViewing(secret), [secret]);

  const entries = viewing.fields;
  const allShown = entries.length > 0 && entries.every((f) => shown[f.key] !== undefined);
  // One value at a time, fetched on "show"; it hides itself soon.
  const reveal = async (key: string) =>
    showValue(key, await call<string>("hashicorp", "secret_value", { mount: viewing.mount, path: viewing.path, version: viewing.version, key }));
  // Copied by the plugin through the core: the value does not come here.
  const copyValue = (key: string) =>
    void call<number>("hashicorp", "secret_copy", { mount: viewing.mount, path: viewing.path, version: viewing.version, key })
      .then(() => onCopied(t("action.copied")))
      .catch((e) => setError(String(e)));
  const isCurrent = viewing.version === null || meta === null || viewing.version === meta.current_version;
  const fullPath = `${secret.mount}/${secret.path}`;


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

  const showVersion = (v: number) =>
    void run(async () => {
      // Another version is another `viewing`: what was shown hides by itself.
      setViewing(await call<Secret>("hashicorp", "secret_read", { mount: secret.mount, path: secret.path, version: v }));
    });

  const act = (c: NonNullable<typeof confirm>) =>
    void run(async () => {
      if (c.kind === "delete") {
        onDeleted(await call<string[]>("hashicorp", "secret_delete", { mount: secret.mount, path: secret.path, permanent: !kv2 }));
      } else if (c.kind === "purge") {
        onDeleted(await call<string[]>("hashicorp", "secret_delete", { mount: secret.mount, path: secret.path, permanent: true }));
      } else if (c.kind === "destroy" && c.version !== undefined) {
        setMeta(await call<SecretMeta>("hashicorp", "secret_destroy", { mount: secret.mount, path: secret.path, version: c.version }));
        if (viewing.version === c.version) setViewing(secret);
      } else if (c.kind === "rollback") {
        // A rollback is a new version with the old one's data; the history
        // stays whole.
        const s = await call<Secret>("hashicorp", "secret_rollback", {
          mount: secret.mount,
          path: secret.path,
          version: viewing.version,
          cas: meta?.current_version ?? null,
        });
        onChanged(s);
        loadMeta();
      }
      setConfirm(null);
    });

  const undelete = (v: number) =>
    void run(async () => {
      setMeta(await call<SecretMeta>("hashicorp", "secret_undelete", { mount: secret.mount, path: secret.path, version: v }));
    });

  const confirmText = {
    delete: [t("secret.delete"), kv2 ? t("secret.deleteConfirmV2") : t("secret.deleteConfirmV1")],
    purge: [t("secret.purge"), t("secret.purgeConfirm")],
    destroy: [t("secret.destroyVersion", { v: confirm?.version ?? 0 }), t("secret.destroyConfirm")],
    rollback: [t("secret.rollback", { v: viewing.version ?? 0 }), t("secret.rollbackConfirm", { v: viewing.version ?? 0, cur: meta?.current_version ?? 0 })],
  } as const;

  return (
    <Modal
      title={fullPath}
      onClose={onClose}
      wide
      footer={
        isCurrent ? (
          <button type="button" className="btn primary" onClick={onEdit}>
            <Icon name="edit" size={13} />
            {t("secret.edit")}
          </button>
        ) : (
          <>
            <span className="foot-why hint">{t("secret.viewingOld", { v: viewing.version ?? 0 })}</span>
            <button type="button" className="btn" onClick={() => setViewing(secret)}>
              {t("secret.backToCurrent")}
            </button>
            <button type="button" className="btn primary" disabled={busy} onClick={() => setConfirm({ kind: "rollback" })}>
              <Icon name="undo" size={13} />
              {t("secret.rollback", { v: viewing.version ?? 0 })}
            </button>
          </>
        )
      }
    >
      <div className="sv-meta">
        <span className="sv-path">
          {viewing.version !== null && (
            <span className={isCurrent ? "chip ok dot" : "chip warn dot"}>
              v{viewing.version}
              {isCurrent ? ` · ${t("secret.current")}` : ""}
            </span>
          )}
          {viewing.updated && <span className="hint">{t("secret.updated", { when: fmtIso(viewing.updated) })}</span>}
          <span className="hint">{t("secret.fieldsCount", { n: entries.length })}</span>
        </span>
        <span className="sv-tools">
          <CopyButton value={fullPath} onCopied={onCopied} title={t("secret.copyPath")} />
          {entries.length > 0 && (
            <button
              type="button"
              className="btn"
              onClick={() => (allShown ? hideAll() : void Promise.all(entries.map((f) => reveal(f.key))).catch((e) => setError(String(e))))}
            >
              <Icon name="eye" size={13} />
              {allShown ? t("secret.hideAll") : t("secret.revealAll")}
            </button>
          )}
        </span>
      </div>

      {entries.length === 0 ? (
        <p className="hint">{t("secret.noFields")}</p>
      ) : (
        <div className="sv">
          {entries.map(({ key: k, length }) => {
            const open = shown[k] !== undefined;
            return (
              <div className={open ? "sv-field open" : "sv-field"} key={k}>
                <div className="sv-head">
                  <span className="sv-key mono">{k}</span>
                  <span className="sv-actions">
                    <button
                      type="button"
                      className="btn icon-only"
                      aria-label={open ? t("secret.hide") : t("secret.reveal")}
                      title={open ? t("secret.hide") : t("secret.reveal")}
                      onClick={() => (open ? hideValue(k) : void reveal(k).catch((e) => setError(String(e))))}
                    >
                      <Icon name="eye" size={13} />
                    </button>
                    <button
                      type="button"
                      className="btn icon-only"
                      aria-label={t("action.copy")}
                      title={t("action.copy")}
                      disabled={length === 0}
                      onClick={() => copyValue(k)}
                    >
                      <Icon name="copy" size={13} />
                    </button>
                  </span>
                </div>
                <div className="sv-val mono">
                  {length === 0 ? <span className="sv-empty">{t("secret.emptyValue")}</span> : open ? shown[k] : "•".repeat(Math.min(Math.max(length, 8), 40))}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {kv2 && meta && (
        <>
          <Disclosure title={t("secret.versions", { n: meta.versions.length })} open>
            <div className="versions">
              {meta.versions.map((v) => {
                const state = v.destroyed ? "destroyed" : v.deleted ? "deleted" : v.version === meta.current_version ? "current" : "old";
                const active = viewing.version === v.version;
                return (
                  <div key={v.version} className={`version ${state}${active ? " active" : ""}`}>
                    <button
                      type="button"
                      className="version-main"
                      disabled={state === "destroyed" || state === "deleted" || busy}
                      onClick={() => showVersion(v.version)}
                    >
                      <span className={`chip ${state === "current" ? "ok" : state === "destroyed" ? "bad" : state === "deleted" ? "warn" : ""}`}>v{v.version}</span>
                      <span className="version-when">{fmtIso(v.created)}</span>
                      <span className="version-state">{t(`secret.state.${state}` as Key)}</span>
                    </button>
                    <span className="version-actions">
                      {state === "deleted" && (
                        <button type="button" className="btn" disabled={busy} onClick={() => undelete(v.version)}>
                          <Icon name="undo" size={12} />
                          {t("secret.undelete")}
                        </button>
                      )}
                      {state !== "destroyed" && (
                        <button
                          type="button"
                          className="btn icon-only ghost"
                          disabled={busy}
                          title={t("secret.destroyVersion", { v: v.version })}
                          aria-label={t("secret.destroyVersion", { v: v.version })}
                          onClick={() => setConfirm({ kind: "destroy", version: v.version })}
                        >
                          <Icon name="trash" size={12} />
                        </button>
                      )}
                    </span>
                  </div>
                );
              })}
            </div>
          </Disclosure>

          <Disclosure title={t("secret.metadata")}>
            <dl className="issue-facts">
              <dt>{t("secret.maxVersions")}</dt>
              <dd>{meta.max_versions === 0 ? t("secret.maxVersionsDefault") : meta.max_versions}</dd>
              <dt>{t("secret.casRequired")}</dt>
              <dd>{meta.cas_required ? t("common.yes") : t("common.no")}</dd>
              <dt>{t("secret.deleteAfter")}</dt>
              <dd>{meta.delete_version_after === "0s" ? t("secret.never") : meta.delete_version_after}</dd>
              <dt>{t("secret.created")}</dt>
              <dd>{fmtIso(meta.created)}</dd>
              {Object.entries(meta.custom_metadata).map(([k, v]) => (
                <Fragment key={k}>
                  <dt className="mono">{k}</dt>
                  <dd>{v}</dd>
                </Fragment>
              ))}
            </dl>
            <button type="button" className="btn" onClick={() => setMetaEdit(true)}>
              <Icon name="edit" size={13} />
              {t("secret.editMetadata")}
            </button>
          </Disclosure>
        </>
      )}

      <DangerZone
        title={t("danger.title")}
        items={[
          {
            label: t("secret.delete"),
            hint: kv2 ? t("secret.deleteZoneV2") : t("secret.deleteZoneV1"),
            action: t("secret.delete"),
            onClick: () => setConfirm({ kind: "delete" }),
            disabled: busy,
            tone: kv2 ? "warn" : "danger",
          },
          ...(kv2
            ? [{ label: t("secret.purge"), hint: t("secret.purgeZone"), action: t("secret.purge"), onClick: () => setConfirm({ kind: "purge" as const }), disabled: busy }]
            : []),
        ]}
      />

      {error && <Alert message={error} />}

      {confirm && (
        <Modal
          title={confirmText[confirm.kind][0]}
          onClose={() => setConfirm(null)}
          footer={
            <>
              <button type="button" className={confirm.kind === "rollback" ? "btn primary" : "btn danger"} disabled={busy} onClick={() => act(confirm)}>
                {busy ? t("action.saving") : confirmText[confirm.kind][0]}
              </button>
              <button type="button" className="btn" onClick={() => setConfirm(null)}>
                {t("action.cancel")}
              </button>
            </>
          }
        >
          <p className="hint">{confirmText[confirm.kind][1]}</p>
        </Modal>
      )}

      {metaEdit && meta && (
        <SecretMetaEditor
          meta={meta}
          onClose={() => setMetaEdit(false)}
          onSaved={(m) => {
            setMeta(m);
            setMetaEdit(false);
          }}
        />
      )}
    </Modal>
  );
}

/// kv v2's metadata: the limit on versions, a compulsory CAS, how long versions
/// live and the custom fields. They are written separately from the data —
/// that is how Vault is built.
function SecretMetaEditor({ meta, onClose, onSaved }: { meta: SecretMeta; onClose: () => void; onSaved: (m: SecretMeta) => void }) {
  const [maxVersions, setMaxVersions] = useState(String(meta.max_versions));
  const [cas, setCas] = useState(meta.cas_required);
  const [deleteAfter, setDeleteAfter] = useState(meta.delete_version_after === "0s" ? "" : meta.delete_version_after);
  const [rows, setRows] = useState<{ k: string; v: string }[]>(() => {
    const r = Object.entries(meta.custom_metadata).map(([k, v]) => ({ k, v }));
    return r.length > 0 ? r : [{ k: "", v: "" }];
  });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const custom: Record<string, string> = {};
  for (const { k, v } of rows) if (k.trim() !== "") custom[k.trim()] = v;
  const mv = Number(maxVersions.replace(/\D/g, "")) || 0;
  const durationOk = deleteAfter.trim() === "" || /^\d+(s|m|h)$/.test(deleteAfter.trim());

  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      const patch: SecretMetaPatch = {
        max_versions: mv,
        cas_required: cas,
        delete_version_after: deleteAfter.trim() === "" ? "0s" : deleteAfter.trim(),
        custom_metadata: custom,
      };
      onSaved(await call<SecretMeta>("hashicorp", "secret_meta_write", { mount: meta.mount, path: meta.path, patch }));
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const set = (i: number, patch: Partial<{ k: string; v: string }>) => setRows((cur) => cur.map((r, j) => (j === i ? { ...r, ...patch } : r)));

  return (
    <Modal
      title={t("secret.metadataTitle", { p: `${meta.mount}/${meta.path}` })}
      onClose={onClose}
      wide
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            {t("action.cancel")}
          </button>
          <button type="button" className="btn primary" disabled={busy || !durationOk} onClick={() => void save()}>
            {busy ? t("action.saving") : t("action.save")}
          </button>
        </>
      }
    >
      <div className="pair">
        <div className="field">
          <label>{t("secret.maxVersions")}</label>
          <input type="text" inputMode="numeric" className="mono" value={maxVersions} onChange={(e) => setMaxVersions(e.target.value.replace(/\D/g, ""))} placeholder="0" />
          <span className="hint">{t("secret.maxVersionsHint")}</span>
        </div>
        <div className="field">
          <label>{t("secret.deleteAfter")}</label>
          <input type="text" className="mono" value={deleteAfter} onChange={(e) => setDeleteAfter(e.target.value)} placeholder="0s" spellCheck={false} />
          <span className={durationOk ? "hint" : "hint warn"}>{t("secret.deleteAfterHint")}</span>
        </div>
      </div>

      <div className="between wrap-row">
        <span className="text">
          <b>{t("secret.casRequired")}</b>
          <span className="hint">{t("secret.casRequiredHint")}</span>
        </span>
        <Toggle on={cas} onChange={setCas} />
      </div>

      <div className="sv-meta">
        <label className="sv-label">{t("secret.customMetadata")}</label>
        <button type="button" className="btn" onClick={() => setRows((cur) => [...cur, { k: "", v: "" }])}>
          <Icon name="plus" size={13} />
          {t("secret.addField")}
        </button>
      </div>
      <div className="kvgrid" role="table">
        <span className="kvgrid-head">{t("secret.key")}</span>
        <span className="kvgrid-head">{t("secret.value")}</span>
        <span />
        {rows.map((r, i) => (
          <div className="kvgrid-row" key={i} role="row">
            <input className="mono flat" type="text" value={r.k} placeholder={t("secret.key")} onChange={(e) => set(i, { k: e.target.value })} spellCheck={false} />
            <AutoTextarea className="mono flat" value={r.v} placeholder={t("secret.value")} onChange={(v) => set(i, { v })} />
            <button type="button" className="btn icon-only ghost" aria-label={t("secret.removeField")} title={t("secret.removeField")} disabled={rows.length === 1} onClick={() => setRows((cur) => cur.filter((_, j) => j !== i))}>
              <Icon name="trash" size={13} />
            </button>
          </div>
        ))}
      </div>
      <span className="hint">{t("secret.customMetadataHint")}</span>

      {error && <Alert message={error} />}
    </Modal>
  );
}

/// Reading a `.env`: `KEY=VALUE` line by line, `export` and the quotes are
/// taken off, comments and empty lines are passed over. A value may contain
/// `=`. Inside double quotes `\n`, `\t`, `\"` and `\\` are understood — that
/// way multi-line values survive the journey there and back.
function parseEnv(text: string): { rows: { k: string; v: string }[]; bad: number[] } {
  const rows: { k: string; v: string }[] = [];
  const bad: number[] = [];
  text.split(/\r?\n/).forEach((raw, idx) => {
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) return;
    const m = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*[=:]\s*(.*)$/.exec(line);
    if (!m) {
      bad.push(idx + 1);
      return;
    }
    let v = m[2].trim();
    const quoted = /^("(?:[^"\\]|\\.)*"|'[^']*')\s*(#.*)?$/.exec(v);
    if (quoted) v = quoted[1];
    if (v.startsWith('"') && v.endsWith('"') && v.length >= 2) {
      v = v.slice(1, -1).replace(/\\(["\\nt])/g, (_, c: string) => (c === "n" ? "\n" : c === "t" ? "\t" : c));
    } else if (v.startsWith("'") && v.endsWith("'") && v.length >= 2) {
      v = v.slice(1, -1);
    } else {
      // A trailing comment on an unquoted value: `KEY=value # what for`.
      v = v.replace(/\s+#.*$/, "").trim();
    }
    rows.push({ k: m[1], v });
  });
  return { rows, bad };
}

function toEnv(rows: { k: string; v: string }[]): string {
  return rows
    .filter((r) => r.k.trim() !== "")
    .map(({ k, v }) => {
      const needsQuotes = /[\s#"'\\]/.test(v) || v === "" || v.includes("\n");
      const q = needsQuotes ? `"${v.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n").replace(/\t/g, "\\t")}"` : v;
      return `${k.trim()}=${q}`;
    })
    .join("\n");
}

function toJson(rows: { k: string; v: string }[]): string {
  const obj: Record<string, string> = {};
  for (const { k, v } of rows) if (k.trim() !== "") obj[k.trim()] = v;
  return JSON.stringify(obj, null, 2);
}

/// JSON into rows. Nested values and numbers are kept as strings: our kv keeps
/// strings alone, and losing a structure without a word is not on — the warning
/// next to the editor says so.
function fromJson(text: string): { rows: { k: string; v: string }[]; error: string | null; coerced: string[] } {
  try {
    const obj: unknown = JSON.parse(text);
    if (obj === null || typeof obj !== "object" || Array.isArray(obj)) return { rows: [], error: t("secret.jsonNotObject"), coerced: [] };
    const rows: { k: string; v: string }[] = [];
    const coerced: string[] = [];
    for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
      if (typeof v === "string") rows.push({ k, v });
      else {
        rows.push({ k, v: v === null || v === undefined ? "" : typeof v === "object" ? JSON.stringify(v) : String(v) });
        coerced.push(k);
      }
    }
    return { rows, error: null, coerced };
  } catch (e) {
    return { rows: [], error: String((e as Error).message ?? e), coerced: [] };
  }
}

/// A textarea that grows to fit its contents: no thumb, no scrolling
/// inside.
function AutoTextarea({ value, onChange, placeholder, className }: { value: string; onChange: (v: string) => void; placeholder?: string; className?: string }) {
  const fit = (el: HTMLTextAreaElement | null) => {
    if (!el) return;
    el.style.height = "0px";
    el.style.height = `${el.scrollHeight}px`;
  };
  return (
    <textarea
      ref={fit}
      className={className}
      rows={1}
      value={value}
      placeholder={placeholder}
      spellCheck={false}
      onChange={(e) => {
        fit(e.currentTarget);
        onChange(e.target.value);
      }}
    />
  );
}

type SecretMode = "fields" | "json" | "env";

/// Creating and editing a secret. Three views of one and the same thing: a
/// table of fields, JSON as in Vault's interface, and `.env` as it is pasted
/// from a file.
/// It is written whole: in kv v2 that is a new version, and the old one stays
/// in the history.
/// On an edit the version that was edited is passed along: if it has been
/// changed in the meantime Vault refuses, and somebody else's write is not
/// rubbed out.
function SecretEditor({
  mounts,
  prefix,
  initial,
  onClose,
  onSaved,
}: {
  mounts: Mount[];
  prefix: string;
  initial: { mount: string; path: string; data: Record<string, string>; version: number | null };
  onClose: () => void;
  onSaved: (s: Secret) => void;
}) {
  const isNew = initial.path === "";
  const [mount, setMount] = useState(initial.mount);
  const [path, setPath] = useState(isNew ? prefix : initial.path);
  const [rows, setRows] = useState<{ k: string; v: string }[]>(() => {
    const r = Object.entries(initial.data).map(([k, v]) => ({ k, v }));
    return r.length > 0 ? r : [{ k: "", v: "" }];
  });
  const [mode, setMode] = useState<SecretMode>("fields");
  const [text, setText] = useState("");
  const [maxVersions, setMaxVersions] = useState("");
  const [casRequired, setCasRequired] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const kv2 = mounts.find((m) => m.path === mount)?.kv2 ?? false;
  const cleanPath = path.trim().replace(/^\/+/, "").replace(/\/+$/, "");

  // What counts as the data just now depends on the mode.
  const jsonParsed = mode === "json" ? fromJson(text) : null;
  const envParsed = mode === "env" ? parseEnv(text) : null;
  const current = mode === "fields" ? rows : jsonParsed?.rows ?? envParsed?.rows ?? [];
  const data: Record<string, string> = {};
  for (const { k, v } of current) if (k.trim() !== "") data[k.trim()] = v;
  const dupes = current.map((r) => r.k.trim()).filter((k, i, all) => k !== "" && all.indexOf(k) !== i);
  const badLines: number[] = envParsed?.bad ?? [];

  const why =
    cleanPath === ""
      ? t("secret.needPath")
      : cleanPath.split("/").includes("..")
        ? t("secret.badPath")
        : jsonParsed?.error
          ? t("secret.jsonInvalid", { e: jsonParsed.error })
          : badLines.length > 0
            ? t("secret.badLines", { lines: badLines.join(", ") })
            : Object.keys(data).length === 0
              ? t("secret.needFields")
              : dupes.length > 0
                ? t("secret.dupes", { k: dupes[0] })
                : null;
  const ready = why === null;
  const coerced = jsonParsed?.coerced ?? [];

  // The view can be switched whenever the text can be read. The path, the
  // emptiness and the duplicates are about saving rather than about how to look
  // at the data.
  const textOk = mode === "fields" || (mode === "json" ? !jsonParsed?.error : badLines.length === 0);
  const [switchBlocked, setSwitchBlocked] = useState<string | null>(null);
  const switchMode = (next: SecretMode) => {
    if (next === mode) return;
    if (mode !== "fields") {
      if (!textOk) {
        setSwitchBlocked(mode === "json" ? t("secret.jsonInvalid", { e: jsonParsed?.error ?? "" }) : t("secret.badLines", { lines: badLines.join(", ") }));
        return;
      }
      setRows(current.length > 0 ? current : [{ k: "", v: "" }]);
    }
    setSwitchBlocked(null);
    const base = mode === "fields" ? rows : current;
    if (next === "json") setText(toJson(base));
    if (next === "env") setText(toEnv(base));
    setMode(next);
  };

  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      const s = await call<Secret>("hashicorp", "secret_write", {
        mount,
        path: cleanPath,
        data,
        // Editing an existing one in kv v2 happens only on top of the version
        // that was seen.
        cas: !isNew && kv2 && initial.version !== null ? initial.version : null,
      });
      if (isNew && kv2 && (maxVersions !== "" || casRequired)) {
        const patch: SecretMetaPatch = {
          max_versions: maxVersions === "" ? null : Number(maxVersions),
          cas_required: casRequired ? true : null,
          delete_version_after: null,
          custom_metadata: null,
        };
        await call<SecretMeta>("hashicorp", "secret_meta_write", { mount, path: cleanPath, patch });
      }
      onSaved(s);
    } catch (e) {
      const msg = String(e);
      setError(/check-and-set|cas/i.test(msg) ? t("secret.casConflict") : msg);
    } finally {
      setBusy(false);
    }
  };

  const set = (i: number, patch: Partial<{ k: string; v: string }>) =>
    setRows((cur) => cur.map((r, j) => (j === i ? { ...r, ...patch } : r)));

  const jsonExtensions = useMemo(() => [json(), lintGutter(), linter(jsonParseLinter())], []);
  const envExtensions = useMemo(() => [envLanguage], []);

  return (
    <Modal
      title={isNew ? t("secret.newTitle") : `${mount}/${initial.path}`}
      onClose={onClose}
      wide
      footer={
        <>
          <span className="foot-why hint">{why ?? (coerced.length > 0 ? t("secret.jsonCoerced", { k: coerced.join(", ") }) : t("secret.fieldsCount", { n: Object.keys(data).length }))}</span>
          <button type="button" className="btn" onClick={onClose}>
            {t("action.cancel")}
          </button>
          <button type="button" className="btn primary" disabled={busy || !ready} onClick={() => void save()}>
            {busy ? t("action.saving") : isNew ? t("secret.create") : t("action.save")}
          </button>
        </>
      }
    >
      {isNew && (
        <div className="pair">
          <div className="field">
            <label>{t("secret.engine")}</label>
            <Picker
              value={mount}
              placeholder={t("policy.pickMount")}
              options={mounts.map((m) => ({ id: m.path, label: m.path, hint: m.kv2 ? "kv v2" : "kv v1" }))}
              onChange={setMount}
            />
            <span className="hint">{kv2 ? t("secret.engineV2") : t("secret.engineV1")}</span>
          </div>
          <div className="field">
            <label>{t("secret.path")}</label>
            <div className="with-prefix">
              <span className="prefix mono">{mount}/</span>
              <input type="text" className="mono" value={path} onChange={(e) => setPath(e.target.value)} placeholder={t("secret.pathPlaceholder")} autoFocus spellCheck={false} />
            </div>
            <span className="hint">{t("secret.pathHint")}</span>
          </div>
        </div>
      )}

      <div className="sv-meta">
        <Segmented<SecretMode>
          value={mode}
          onChange={switchMode}
          options={[
            { id: "fields", label: t("secret.mode.fields") },
            { id: "json", label: "JSON" },
            { id: "env", label: ".env" },
          ]}
        />
        {mode === "fields" && (
          <button type="button" className="btn" onClick={() => setRows((cur) => [...cur, { k: "", v: "" }])}>
            <Icon name="plus" size={13} />
            {t("secret.addField")}
          </button>
        )}
      </div>

      {switchBlocked && <Alert tone="warn" message={t("secret.switchBlocked", { why: switchBlocked })} />}

      {mode === "fields" && (
        <div className="kvgrid" role="table">
          <span className="kvgrid-head">{t("secret.key")}</span>
          <span className="kvgrid-head">{t("secret.value")}</span>
          <span />
          {rows.map((r, i) => {
            const dup = r.k.trim() !== "" && dupes.includes(r.k.trim());
            return (
              <div className={dup ? "kvgrid-row dup" : "kvgrid-row"} key={i} role="row">
                <input className="mono flat" type="text" value={r.k} placeholder={t("secret.key")} onChange={(e) => set(i, { k: e.target.value })} spellCheck={false} />
                <AutoTextarea className="mono flat" value={r.v} placeholder={t("secret.value")} onChange={(v) => set(i, { v })} />
                <button
                  type="button"
                  className="btn icon-only ghost"
                  aria-label={t("secret.removeField")}
                  title={t("secret.removeField")}
                  disabled={rows.length === 1}
                  onClick={() => setRows((cur) => cur.filter((_, j) => j !== i))}
                >
                  <Icon name="trash" size={13} />
                </button>
              </div>
            );
          })}
        </div>
      )}

      {mode === "json" && (
        <>
          <CodeEditor key="json" initial={text} onChange={setText} extensions={jsonExtensions} minHeight="180px" maxHeight="40vh" autoFocus />
          <span className="hint">{t("secret.jsonHint")}</span>
        </>
      )}

      {mode === "env" && (
        <>
          <CodeEditor key="env" initial={text} onChange={setText} extensions={envExtensions} minHeight="180px" maxHeight="40vh" autoFocus placeholder={"DATABASE_URL=postgres://…\nJWT_SECRET=…"} />
          <span className="hint">{t("secret.envHint")}</span>
        </>
      )}

      {isNew && kv2 && (
        <Disclosure title={t("secret.advanced")}>
          <div className="pair">
            <div className="field">
              <label>{t("secret.maxVersions")}</label>
              <input type="text" inputMode="numeric" className="mono" value={maxVersions} onChange={(e) => setMaxVersions(e.target.value.replace(/\D/g, ""))} placeholder={t("secret.maxVersionsDefault")} />
              <span className="hint">{t("secret.maxVersionsHint")}</span>
            </div>
            <div className="between wrap-row">
              <span className="text">
                <b>{t("secret.casRequired")}</b>
                <span className="hint">{t("secret.casRequiredHint")}</span>
              </span>
              <Toggle on={casRequired} onChange={setCasRequired} />
            </div>
          </div>
        </Disclosure>
      )}

      <span className="hint">{kv2 ? t("secret.writeHintV2") : t("secret.writeHintV1")}</span>
      {error && <Alert message={error} />}
    </Modal>
  );
}

/// Editing an existing connection.
///
/// All on one screen and with no root generated: the address, the note with the
/// keys, the shares and the AppRole — what is really changed. Root is handed out
/// once by the wizard, and when there is none that is visible on a line of its
/// own.
function HashicorpEdit({
  link,
  notes,
  onDone,
  onChanged,
}: {
  link: HashicorpLink;
  notes: VaultItem[];
  onDone: () => void;
  onChanged: () => void;
}) {
  const [addr, setAddr] = useState(link.addr);
  const [entryId, setEntryId] = useState<string | null>(link.entry_id);
  const [fields, setFields] = useState<string[]>([]);
  const [shares, setShares] = useState<string[]>([]);
  const [roleId, setRoleId] = useState("");
  const [secretId, setSecretId] = useState("");
  const [namespace, setNamespace] = useState("");
  const [busy, setBusy] = useState(false);
  const [dropping, setDropping] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEscape(onDone);

  useEffect(() => {
    if (!entryId) {
      setFields([]);
      return;
    }
    invoke<string[]>("note_fields", { entryId }).then((f) => setFields(f ?? [])).catch(() => setFields([]));
  }, [entryId]);

  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      await call("hashicorp", "connect", {
        form: {
          name: "",
          entry_id: entryId,
          addr,
          unseal_fields: shares.filter(Boolean),
          role_id: roleId,
          secret_id: secretId,
          namespace,
        },
      });
      onChanged();
      onDone();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="wizard">
      <div className="card">
        <div className="field">
          <label>{t("hashicorp.addr")}</label>
          <input
            value={addr}
            onChange={(e) => setAddr(e.target.value)}
            spellCheck={false}
            onKeyDown={(e) => e.key === "Enter" && void save()}
          />
        </div>

        <div className="field">
          <label>{t("hashicorp.entry")}</label>
          <Picker
            value={entryId}
            placeholder={t("hashicorp.pickNote")}
            options={notes.map((n) => ({ id: n.id, label: n.name, hint: n.folder_name ?? undefined }))}
            onChange={setEntryId}
          />
        </div>

        <div className="field">
          <label>{t("vault.unsealKeys")}</label>
          <div className="slots">
            {Array.from({ length: Math.max(link.unseal_keys, 1) }, (_, i) => {
              const taken = shares.filter((_, j) => j !== i);
              return (
                <div className="slot" key={i}>
                  <span className="slot-label">{t("hashicorp.shareSlot", { n: i + 1 })}</span>
                  <Picker
                    value={shares[i] ?? null}
                    placeholder={t("hashicorp.pickField")}
                    options={fields.filter((n) => !taken.includes(n)).map((n) => ({ id: n, label: n }))}
                    onChange={(id) => {
                      const next = [...shares];
                      next[i] = id;
                      setShares(next);
                    }}
                  />
                </div>
              );
            })}
          </div>
          <span className="hint">{t("edit.sharesKept")}</span>
        </div>

        <Disclosure title={t("hashicorp.approleOptional")}>
          <div className="field">
            <div className="pair">
              <input value={roleId} onChange={(e) => setRoleId(e.target.value)} placeholder="role_id" spellCheck={false} />
              <PasswordInput value={secretId} onChange={setSecretId} placeholder="secret_id" />
            </div>
            <span className="hint">{t("hashicorp.approleHint")}</span>
          </div>
          <div className="field">
            <label>{t("hashicorp.namespace")}</label>
            <div className="pair">
              <input value={namespace} onChange={(e) => setNamespace(e.target.value)} placeholder={t("hashicorp.optional")} spellCheck={false} />
            </div>
            <span className="hint">{t("hashicorp.namespaceHint")}</span>
          </div>
        </Disclosure>

        <p className="hint">{link.has_root ? t("edit.rootPresent") : t("edit.rootAbsent")}</p>
        {error && <Alert message={error} />}

        <DangerZone
          title={t("danger.title")}
          items={[{ label: t("hashicorp.forget"), hint: t("hashicorp.forgetWarn"), action: t("hashicorp.forget"), onClick: () => setDropping(true), disabled: busy }]}
        />

        <div className="row-actions">
          <button type="button" className="btn" onClick={onDone}>
            {t("action.cancel")}
          </button>
          <button type="button" className="btn primary" disabled={busy || !addr.trim()} onClick={() => void save()}>
            {busy ? t("action.saving") : t("action.save")}
          </button>
        </div>

        {dropping && (
          <Modal
            title={t("hashicorp.forget")}
            onClose={() => setDropping(false)}
            footer={
              <>
                <button type="button"
                  className="btn danger"
                  disabled={busy}
                  onClick={() =>
                    void (async () => {
                      setBusy(true);
                      setError(null);
                      try {
                        await call("hashicorp", "forget", { entry_id: link.entry_id });
                        onChanged();
                        onDone();
                      } catch (e) {
                        setError(String(e));
                      } finally {
                        setBusy(false);
                      }
                    })()
                  }
                >
                  {busy ? t("action.saving") : t("hashicorp.forget")}
                </button>
                <button type="button" className="btn" onClick={() => setDropping(false)}>
                  {t("action.cancel")}
                </button>
              </>
            }
          >
            <p className="hint">{t("hashicorp.forgetWarn")}</p>
          </Modal>
        )}
      </div>
    </div>
  );
}

/// Connecting a Vault, step by step.
///
/// By steps rather than on one canvas exactly because, while the address is
/// unknown, asking about the shares makes no sense — the server itself will say
/// how many are needed, and only after that do the fields mean anything.
export function HashicorpConnect({
  existing,
  notes,
  onDone,
  onChanged,
}: {
  existing: HashicorpLink | null;
  /// Secure notes alone: logins and cards have no room for an address and
  /// keys.
  notes: VaultItem[];
  onDone?: () => void;
  onChanged: () => void;
}) {
  const STEPS = ["addr", "note", "shares", "root"] as const;
  type Step = (typeof STEPS)[number];

  const [step, setStep] = useState<Step>("addr");
  const [addr, setAddr] = useState(existing?.addr ?? "");
  const [seal, setSeal] = useState<SealStatus | null>(null);
  const [entryId, setEntryId] = useState<string | null>(existing?.entry_id ?? null);
  const [noteFields, setNoteFields] = useState<string[]>([]);
  const [shares, setShares] = useState<string[]>([]);
  const [rootReady, setRootReady] = useState(false);
  const [roleId, setRoleId] = useState("");
  const [secretId, setSecretId] = useState("");
  const [namespace, setNamespace] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!entryId) {
      setNoteFields([]);
      return;
    }
    invoke<string[]>("note_fields", { entryId })
      .then(setNoteFields)
      .catch(() => setNoteFields([]));
  }, [entryId]);

  const run = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const probe = () =>
    run(async () => {
      const s = await call<SealStatus>("hashicorp", "probe", { addr });
      setSeal(s);
      setStep("note");
    });

  const generate = () =>
    run(async () => {
      // The address is given along with the item: the seal is read before the
      // connection is saved, and the item has no address yet.
      const payload = { entry_id: entryId, addr, fields: shares };
      if (entryId) await callWithFields("hashicorp", "generate_root", payload, { entryId, fields: shares, into: "shares" });
      else await call("hashicorp", "generate_root", { ...payload, shares: [] });
      setRootReady(true);
    });

  const save = () =>
    run(async () => {
      await call("hashicorp", "connect", {
        form: {
          name: "",
          entry_id: entryId,
          addr,
          unseal_fields: shares.filter(Boolean),
          role_id: roleId,
          secret_id: secretId,
          namespace,
        },
      });
      onChanged();
      onDone?.();
    });

  const index = STEPS.indexOf(step);
  const needed = seal?.t ?? 0;

  // Escape cancels — as everywhere else in the application.
  useEscape(onDone ?? null);

  return (
    <div className="wizard">
      <ol className="steps">
        {STEPS.map((x, i) => (
          <li key={x} className={i === index ? "on" : i < index ? "past" : ""}>
            <span className="num">{i + 1}</span>
            <span>{t(`connect.step.${x}` as Key)}</span>
          </li>
        ))}
      </ol>

      <div className="card">
        {step === "addr" && (
          <>
            <div className="field">
              <label>{t("hashicorp.addr")}</label>
              <input
                value={addr}
                onChange={(e) => setAddr(e.target.value)}
                placeholder="https://vault.example.com"
                spellCheck={false}
                autoFocus
                onKeyDown={(e) => e.key === "Enter" && addr.trim() && void probe()}
              />
              <span className="hint">{t("connect.addrHint")}</span>
            </div>
            {error && <Alert message={error} />}
            <div className="row-actions">
              <button type="button" className="btn primary" disabled={busy || !addr.trim()} onClick={() => void probe()}>
                {busy ? "…" : t("hashicorp.probe")}
              </button>
              {onDone && (
                <button type="button" className="btn" onClick={onDone}>
                  {t("action.cancel")}
                </button>
              )}
            </div>
          </>
        )}

        {step === "note" && (
          <>
            <p className="hint">
              {seal && seal.t > 0
                ? t("hashicorp.threshold", { t: seal.t, n: seal.n })
                : t("hashicorp.sealAuto")}
              {seal?.version ? ` · ${seal.version}` : ""}
            </p>
            <div className="field">
              <label>{t("hashicorp.entry")}</label>
              <Picker
                value={entryId}
                placeholder={t("hashicorp.pickNote")}
                options={notes.map((n) => ({ id: n.id, label: n.name, hint: n.folder_name ?? undefined }))}
                onChange={setEntryId}
              />
              <span className="hint">{t("connect.noteHint")}</span>
            </div>
            {error && <Alert message={error} />}
            <div className="row-actions">
              <button type="button" className="btn" onClick={() => setStep("addr")}>
                {t("step.back")}
              </button>
              {onDone && (
                <button type="button" className="btn" onClick={onDone}>
                  {t("action.cancel")}
                </button>
              )}
              <button type="button"
                className="btn primary"
                disabled={!entryId}
                onClick={() => setStep(needed > 0 ? "shares" : "root")}
              >
                {t("step.next")}
              </button>
            </div>
          </>
        )}

        {step === "shares" && (
          <>
            <div className="field">
              <label>{t("vault.unsealKeys")}</label>
              {noteFields.length === 0 ? (
                <span className="hint">{t("hashicorp.noFields")}</span>
              ) : (
                <div className="slots">
                  {Array.from({ length: needed }, (_, i) => {
                    const taken = shares.filter((_, j) => j !== i);
                    return (
                      <div className="slot" key={i}>
                        <span className="slot-label">{t("hashicorp.shareSlot", { n: i + 1 })}</span>
                        <Picker
                          value={shares[i] ?? null}
                          placeholder={t("hashicorp.pickField")}
                          options={noteFields
                            .filter((n) => !taken.includes(n))
                            .map((n) => ({ id: n, label: n }))}
                          onChange={(id) => {
                            const next = [...shares];
                            next[i] = id;
                            setShares(next);
                          }}
                        />
                      </div>
                    );
                  })}
                </div>
              )}
              <span className="hint">{t("connect.sharesHint")}</span>
            </div>
            {error && <Alert message={error} />}
            <div className="row-actions">
              <button type="button" className="btn" onClick={() => setStep("note")}>
                {t("step.back")}
              </button>
              {onDone && (
                <button type="button" className="btn" onClick={onDone}>
                  {t("action.cancel")}
                </button>
              )}
              <button type="button"
                className="btn primary"
                disabled={shares.filter(Boolean).length < needed}
                onClick={() => setStep("root")}
              >
                {t("step.next")}
              </button>
            </div>
          </>
        )}

        {step === "root" && (
          <>
            {rootReady ? (
              <>
                <p className="done">
                  <Icon name="check" size={14} />
                  {t("connect.rootDone")}
                </p>
                <Alert tone="warn" message={t("connect.rootWarn")} />
                <p className="hint">{t("connect.finishHint")}</p>
                <Disclosure title={t("hashicorp.approleOptional")}>
                  <div className="field">
                    <div className="pair">
                      <input
                        value={roleId}
                        onChange={(e) => setRoleId(e.target.value)}
                        placeholder="role_id"
                        spellCheck={false}
                      />
                      <PasswordInput value={secretId} onChange={setSecretId} placeholder="secret_id" />
                    </div>
                    <span className="hint">{t("hashicorp.approleHint")}</span>
                  </div>
                  <div className="field">
                    <label>{t("hashicorp.namespace")}</label>
                    <div className="pair">
                      <input
                        value={namespace}
                        onChange={(e) => setNamespace(e.target.value)}
                        placeholder={t("hashicorp.optional")}
                        spellCheck={false}
                      />
                    </div>
                    <span className="hint">{t("hashicorp.namespaceHint")}</span>
                  </div>
                </Disclosure>
                {error && <Alert message={error} />}
                <div className="row-actions">
                  <button type="button" className="btn primary" disabled={busy} onClick={() => void save()}>
                    {busy ? t("action.saving") : t("connect.finish")}
                  </button>
                  {onDone && (
                    <button type="button" className="btn" onClick={onDone}>
                      {t("action.cancel")}
                    </button>
                  )}
                </div>
              </>
            ) : (
              <>
                <p className="hint">{t("connect.rootHint")}</p>
                {error && <Alert message={error} />}
                <div className="row-actions">
                  <button type="button" className="btn" onClick={() => setStep(needed > 0 ? "shares" : "note")}>
                    {t("step.back")}
                  </button>
                  {onDone && (
                    <button type="button" className="btn" onClick={onDone}>
                      {t("action.cancel")}
                    </button>
                  )}
                  <button type="button" className="btn primary" disabled={busy} onClick={() => void generate()}>
                    {busy ? t("connect.generating") : t("connect.generate")}
                  </button>
                </div>
              </>
            )}
          </>
        )}
      </div>
    </div>
  );
}

/// A token just issued: dots until asked for, and hidden again soon — it is
/// copied through the daemon, so there is rarely a need to read it at all.
function IssuedToken({ value }: { value: string }) {
  const { values, keep, forget } = useEphemeral(value);
  const open = values.token !== undefined;
  return (
    <div className="issued-token">
      <pre className="secret">{open ? value : "•".repeat(Math.min(Math.max(value.length, 8), 40))}</pre>
      <button type="button" className="btn small" onClick={() => (open ? forget("token") : keep("token", "shown"))}>
        <Icon name="eye" size={12} />
        {open ? t("secret.hide") : t("secret.reveal")}
      </button>
    </div>
  );
}
