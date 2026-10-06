// O-B Object Workspace — one credential as a document
// (vault-desk-final-ux-spec.md §3). A sticky identity header, the
// immediate-use strip, a body composed for the type; no Inventory residue and
// no inspector beside it.
import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Alert, Icon, Modal, useEscape } from "../ui";
import { currentLang, t, tError } from "../i18n";
import { invokeSecret } from "../seal";
import { Totp } from "../Totp";
import { EditItem } from "../screens/EditItem";
import { fieldLabel, fieldValue } from "../screens/Detail";
import type { DetailField, ItemDetail, SecretField, VaultItem } from "../types";
import { EDGE_KEY, KIND_ICON, KIND_KEY, LEVEL_MARK, ago, context, relations, shared, signals, topSignal, type Relation } from "./model";

const secretId = (f: SecretField) => (typeof f === "string" ? f : "custom" in f ? `custom:${f.custom}` : `history:${f.password_history}`);

export function ObjectPage({
  id,
  item,
  all,
  onRelations,
  onOpen,
  onChanged,
  onNotice,
  onTrash,
  onRestore,
  onPurge,
}: {
  id: string;
  item: VaultItem | null;
  all: VaultItem[];
  onRelations: (id: string) => void;
  onOpen: (id: string) => void;
  onChanged: () => void;
  onNotice: (text: string) => void;
  onTrash: (id: string) => void;
  onRestore: (id: string) => void;
  onPurge: (id: string) => void;
}) {
  const [detail, setDetail] = useState<ItemDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [revealed, setRevealed] = useState<Record<string, string>>({});
  const [editing, setEditing] = useState(false);
  const [more, setMore] = useState(false);
  const [purging, setPurging] = useState(false);
  const [epoch, setEpoch] = useState(0);
  const moreBox = useRef<HTMLDivElement>(null);
  const lang = currentLang();
  useEscape(more ? () => setMore(false) : null);

  useEffect(() => {
    setDetail(null);
    setError(null);
    setRevealed({});
    invoke<ItemDetail>("item_detail", { entryId: id })
      .then(setDetail)
      .catch((e) => setError(String(e)));
  }, [id, epoch, item?.revised]);
  // What was revealed is hidden again when the window loses focus.
  useEffect(() => {
    const hide = () => setRevealed({});
    window.addEventListener("blur", hide);
    return () => window.removeEventListener("blur", hide);
  }, []);
  useEffect(() => {
    if (!more) return;
    const away = (e: MouseEvent) => moreBox.current && !moreBox.current.contains(e.target as Node) && setMore(false);
    window.addEventListener("mousedown", away);
    return () => window.removeEventListener("mousedown", away);
  }, [more]);

  const copy = async (f: DetailField) => {
    if (!f.secret) return;
    try {
      await invoke("copy_secret", { entryId: id, field: f.secret });
      onNotice(t("desk.copied", { what: fieldLabel(f.key, f.label) }));
    } catch (e) {
      setError(String(e));
    }
  };
  const reveal = async (f: DetailField) => {
    if (!f.secret) return;
    const k = secretId(f.secret);
    if (revealed[k] !== undefined) {
      setRevealed(({ [k]: _, ...rest }) => rest);
      return;
    }
    try {
      const value = await invokeSecret("reveal_secret", { entryId: id, field: f.secret });
      setRevealed((r) => ({ ...r, [k]: value }));
    } catch (e) {
      setError(String(e));
    }
  };

  // §3.14: the identity stays while the document loads or fails.
  const kind = detail?.kind ?? item?.kind ?? "login";
  const sig = item ? topSignal(item) : null;
  const rels = item ? relations(item, all) : [];
  const head = (
    <header className="object-head">
      <div className="object-head-row">
        <span className="object-type" title={t(KIND_KEY[kind])}>
          <Icon name={KIND_ICON[kind]} size={20} />
        </span>
        <div className="object-ident">
          <h1>{detail?.name ?? item?.name ?? "—"}</h1>
          <p>
            {[t(KIND_KEY[kind]), item ? context(item) : null, item ? (shared(item) ? t("desk.owner.shared") : t("desk.owner.personal")) : null].filter(Boolean).join(" · ")}
            {sig && (
              <span className={`ledger-security ${sig.level}`}>
                <i aria-hidden="true">{LEVEL_MARK[sig.level]}</i>
                {t(sig.key, sig.args)}
              </span>
            )}
          </p>
        </div>
        <span className="grow" />
        <button type="button" className="btn" onClick={() => onRelations(id)}>
          <Icon name="network" size={14} />
          {t("desk.relationsN", { n: rels.length })}
        </button>
        {detail && !detail.deleted && (
          <button type="button" className="btn" onClick={() => setEditing(true)}>
            <Icon name="edit" size={14} />
            {t("edit.open")}
          </button>
        )}
        {detail?.deleted && (
          <button type="button" className="btn" onClick={() => onRestore(id)}>
            <Icon name="undo" size={14} />
            {t("item.restore")}
          </button>
        )}
        <div className="object-more" ref={moreBox}>
          <button type="button" className="btn icon-only" title={t("desk.more")} aria-label={t("desk.more")} aria-expanded={more} onClick={() => setMore((v) => !v)}>
            <Icon name="more" size={16} />
          </button>
          {more && (
            <div className="chrome-menu object-menu" role="menu">
              <div className="chrome-menu-group">
                {detail?.deleted ? (
                  <button type="button" role="menuitem" className="danger" onClick={() => { setMore(false); setPurging(true); }}>
                    <Icon name="trash" size={16} />
                    <span>{t("item.purge")}</span>
                  </button>
                ) : (
                  <button type="button" role="menuitem" className="danger" onClick={() => { setMore(false); onTrash(id); }}>
                    <Icon name="trash" size={16} />
                    <span>{t("item.trash")}</span>
                  </button>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  );

  if (error && !detail)
    return (
      <main className="desk-mode object">
        {head}
        <div className="object-body">
          <Alert message={error} onRetry={() => setEpoch((n) => n + 1)} />
        </div>
      </main>
    );

  const fields = detail?.fields ?? [];
  const by = (...keys: string[]) => fields.filter((f) => f.key !== null && keys.includes(f.key));
  const rest = (taken: DetailField[]) => fields.filter((f) => !taken.includes(f) && f.key !== "notes");
  const immediate =
    kind === "login" ? by("username", "password", "totp") :
    kind === "ssh_key" ? by("fingerprint", "publicKey") :
    kind === "card" ? by("cardNumber", "expiry", "expMonth", "expYear", "cardholderName") :
    kind === "secure_note" ? [] : by("username", "email");
  const notes = fields.find((f) => f.key === "notes");

  return (
    <main className="desk-mode object">
      {head}
      {detail && (
        <div className="object-body">
          {error && <Alert message={error} onClose={() => setError(null)} />}
          {detail.deleted && <Alert tone="warn" message={t("desk.inTrash")} />}

          {immediate.length > 0 && (
            <section className="object-section use">
              <h2>{t("desk.sec.use")}</h2>
              {immediate.map((f) => (
                <FieldRow key={f.label} f={f} entryId={id} value={f.secret ? revealed[secretId(f.secret)] : undefined} onCopy={() => void copy(f)} onReveal={() => void reveal(f)} />
              ))}
              {kind === "login" && detail.passkeys.length > 0 && (
                <div className="object-field">
                  <span>{t("desk.field.passkey")}</span>
                  <b>{detail.passkeys.map((p) => p.rp_id).join(" · ")}</b>
                </div>
              )}
            </section>
          )}

          {kind === "secure_note" && notes && (
            <section className="object-section content">
              <h2>{t("desk.sec.content")}</h2>
              <FieldRow f={notes} entryId={id} long value={notes.secret ? revealed[secretId(notes.secret)] : undefined} onCopy={() => void copy(notes)} onReveal={() => void reveal(notes)} />
            </section>
          )}

          {(detail.uris.length > 0 || (kind === "ssh_key" && item?.tags["kw-host"])) && (
            <section className="object-section">
              <h2>{kind === "ssh_key" ? t("desk.sec.bindings") : t("desk.sec.access")}</h2>
              {detail.uris.map((u) => (
                <div className="object-field" key={u}>
                  <span>{t("desk.field.site")}</span>
                  <b className="mono">{u}</b>
                </div>
              ))}
              {kind === "ssh_key" &&
                (item?.tags["kw-host"] ?? "").split(/[\s,]+/).filter(Boolean).map((h) => (
                  <div className="object-field" key={h}>
                    <span>{t("desk.field.host")}</span>
                    <b className="mono">{h}</b>
                  </div>
                ))}
            </section>
          )}

          {item && (
            <section className="object-section">
              <h2>{t("desk.sec.security")}</h2>
              {signals(item).map((s) => (
                <div className="object-field" key={s.key}>
                  <span className={`ledger-security ${s.level}`}>
                    <i aria-hidden="true">{LEVEL_MARK[s.level]}</i>
                    {t(`desk.level.${s.level}` as "desk.level.critical")}
                  </span>
                  <b>{t(s.key, s.args)}</b>
                  {s.key === "desk.sig.reused" && (
                    <button type="button" className="btn" onClick={() => onRelations(id)}>
                      <Icon name="network" size={14} />
                      {t("desk.explore")}
                    </button>
                  )}
                </div>
              ))}
              <div className="object-field">
                <span>{t("desk.col.updated")}</span>
                <b>{ago(item.revised, lang)}</b>
              </div>
            </section>
          )}

          {rest(immediate).length > 0 && kind !== "secure_note" && (
            <section className="object-section">
              <h2>{t("desk.sec.details")}</h2>
              {rest(immediate).map((f) => (
                <FieldRow key={f.label} f={f} entryId={id} value={f.secret ? revealed[secretId(f.secret)] : undefined} onCopy={() => void copy(f)} onReveal={() => void reveal(f)} />
              ))}
            </section>
          )}

          {kind !== "secure_note" && notes && (
            <section className="object-section">
              <h2>{t("desk.sec.notes")}</h2>
              <FieldRow f={notes} entryId={id} long value={notes.secret ? revealed[secretId(notes.secret)] : undefined} onCopy={() => void copy(notes)} onReveal={() => void reveal(notes)} />
            </section>
          )}

          <Related relations={rels} onOpen={onOpen} onExplore={() => onRelations(id)} />
        </div>
      )}
      {!detail && !error && <div className="object-body"><div className="object-loading" aria-busy="true" /></div>}

      {editing && detail && (
        <EditItem
          detail={detail}
          onClose={() => setEditing(false)}
          onCopied={onNotice}
          onSaved={(e) => {
            onNotice(e.state.state === "pushed" ? t("edit.pushed") : t("edit.savedLocally"));
            onChanged();
            setEpoch((n) => n + 1);
          }}
        />
      )}
      {purging && (
        <Modal
          title={t("item.purge")}
          onClose={() => setPurging(false)}
          footer={
            <button type="button" className="btn danger" onClick={() => { setPurging(false); onPurge(id); }}>
              {t("item.purge")}
            </button>
          }
        >
          <p className="hint">{t("item.purgeConfirm")}</p>
        </Modal>
      )}
    </main>
  );
}

/// One field of the document: its name, its value (a secret as dots until it
/// is revealed), its copy and reveal. A TOTP shows its live code.
function FieldRow({ f, entryId, value, long, onCopy, onReveal }: { f: DetailField; entryId: string; value?: string; long?: boolean; onCopy: () => void; onReveal: () => void }) {
  const isSecret = Boolean(f.secret) && f.hidden;
  const shown = isSecret ? (value ?? "••••••••••••") : (value ?? fieldValue(f.key, f.value) ?? "—");
  return (
    <div className={`object-field ${long ? "long" : ""}`}>
      <span>{fieldLabel(f.key, f.label)}</span>
      {f.secret === "totp" ? <Totp entryId={entryId} onError={(e) => console.error(tError(e))} /> : <b className={f.mono || isSecret ? "mono" : ""}>{shown}</b>}
      <span className="object-field-acts">
        {isSecret && f.secret !== "totp" && (
          <button type="button" className="btn icon-only" title={value ? t("desk.hide") : t("desk.reveal")} aria-label={value ? t("desk.hide") : t("desk.reveal")} onClick={onReveal}>
            <Icon name={value ? "eye-off" : "eye"} size={14} />
          </button>
        )}
        {f.secret && (
          <button type="button" className="btn icon-only" title={t("desk.copy")} aria-label={t("desk.copy")} onClick={onCopy}>
            <Icon name="copy" size={14} />
          </button>
        )}
      </span>
    </div>
  );
}

/// §3.11: related objects as compact references — open, or explore.
function Related({ relations, onOpen, onExplore }: { relations: Relation[]; onOpen: (id: string) => void; onExplore: () => void }) {
  const objects = relations.filter((r) => r.node.kind === "object").slice(0, 6);
  if (objects.length === 0) return null;
  return (
    <section className="object-section">
      <h2>{t("desk.sec.related")}</h2>
      {objects.map((r) => {
        if (r.node.kind !== "object") return null;
        const it = r.node.item;
        const s = topSignal(it);
        return (
          <div className="object-field related" key={`${r.edge}:${r.node.id}`}>
            <span>{t(EDGE_KEY[r.edge])}</span>
            <b>
              <Icon name={KIND_ICON[it.kind]} size={14} />
              {it.name}
              <span className={`ledger-security ${s.level}`}>
                <i aria-hidden="true">{LEVEL_MARK[s.level]}</i>
              </span>
            </b>
            <span className="object-field-acts">
              <button type="button" className="btn" onClick={() => onOpen(it.id)}>
                {t("desk.open")}
              </button>
            </span>
          </div>
        );
      })}
      {relations.length > objects.length && (
        <button type="button" className="btn object-more-rel" onClick={onExplore}>
          <Icon name="network" size={14} />
          {t("desk.relationsN", { n: relations.length })}
        </button>
      )}
    </section>
  );
}
