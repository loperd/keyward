import { useEffect, useState } from "react";
import { Totp } from "../Totp";
import { invoke } from "@tauri-apps/api/core";
import { usePlugins } from "../plugins/call";
import { pluginEntry } from "../plugins";
import { Alert, CopyButton, DangerZone, Empty, Icon, Modal, Monogram } from "../ui";
import { EditItem } from "./EditItem";
import { RegenerateModal } from "./RegenerateModal";
import { useEphemeral } from "../ephemeral";
import { t } from "../i18n";
import type { ItemDetail, ItemKind, SecretField } from "../types";
import { useImageHue, useSiteIcon } from "../icons";
import { CardBrandMark, detectCardBrand } from "../CardBrand";

const KIND_KEY: Record<ItemKind, Key> = {
  login: "kindOne.login",
  card: "kindOne.card",
  identity: "kindOne.identity",
  secure_note: "kindOne.note",
  ssh_key: "kindOne.sshKey",
};
import { linkLabel } from "./ItemFields";
import type { Key } from "../i18n";
import { invokeSecret } from "../seal";

/*
  A field's caption in the interface's language.

  The daemon gives a key ("username", "password") rather than finished text: it
  has no language of the person's, and an English window used to hold a Russian
  "Login" next to "Addresses". A custom field has nothing to translate — a person
  made its name up.
*/
function fieldLabel(key: string | null, label: string): string {
  if (!key) return label;
  if (key.startsWith("link:") || key === "checkbox") return label;
  return t(`field.${key}` as Key);
}

/// The value of a field whose meaning is not in its text: a checkbox and a
/// linked field.
function fieldValue(key: string | null, value: string | null): string | null {
  if (key === "checkbox") return value === "true" ? t("value.yes") : t("value.no");
  if (key?.startsWith("link:")) return `→ ${linkLabel(Number(key.slice(5)))}`;
  return value;
}

/// An item's card. At a button a secret travels to the clipboard **from the
/// daemon** and does not reach the interface at all. "Show" is a deliberate
/// action of its own, and only then does the value come here.
function fmtIso(iso: string, withTime = false): string {
  const ts = Date.parse(iso);
  const time = withTime ? ({ hour: "2-digit", minute: "2-digit" } as const) : {};
  return Number.isNaN(ts) ? iso : new Date(ts).toLocaleString(undefined, { day: "numeric", month: "short", year: "numeric", ...time });
}

/** A card-shaped summary is quicker to scan than four disconnected fields.
 * It only uses the catalog-safe masked value that is already on screen. */
function PaymentCard({ detail, brand }: { detail: ItemDetail; brand: NonNullable<ReturnType<typeof detectCardBrand>> }) {
  const value = (key: string) => detail.fields.find((field) => field.key === key)?.value ?? "—";
  const number = value("cardNumber");
  const holder = value("cardholder");
  const expiry = value("expiry");

  return (
    <section className="payment-card" aria-label="Payment card summary">
      <span className="payment-card-topline">
        <span className="payment-card-label">Payment card</span>
        <CardBrandMark brand={brand} />
      </span>
      <span className="payment-card-number mono">{number}</span>
      <span className="payment-card-footer">
        <span><small>Cardholder</small>{holder}</span>
        <span><small>Valid through</small>{expiry}</span>
      </span>
    </section>
  );
}

export function DetailPane({
  entryId,
  serverUrl = "",
  onCopied,
  onClose,
  onChanged,
}: {
  entryId: string;
  serverUrl?: string;
  onCopied: (text: string) => void;
  onClose: () => void;
  onChanged: () => void;
}) {
  // `?edit=1` opens the edit form at once, which the harness needs in order to
  // capture it.
  // A new password made and saved in the daemon; afterwards the card offers
  // to copy it, on a press — nothing reaches the clipboard on its own.
  const [regenerating, setRegenerating] = useState(false);
  const [regenerated, setRegenerated] = useState(false);

  const [editing, setEditing] = useState(
    () => new URLSearchParams(window.location.search).has("edit"),
  );
  const [detail, setDetail] = useState<ItemDetail | null>(null);
  // The plugins that are on: each may have a block of its own to draw on this
  // card, and the card does not know what any of them is about.
  const plugins = usePlugins().filter((m) => m.enabled);
  const siteIcon = useSiteIcon(serverUrl, detail?.uris ?? [], detail?.kind === "login");
  const [removingPasskey, setRemovingPasskey] = useState<string | null>(null);
  const [clearingHistory, setClearingHistory] = useState(false);
  const iconHue = useImageHue(siteIcon ?? null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirm, setConfirm] = useState<"trash" | "purge" | null>(null);
  // What was revealed hides itself soon, and at once when the window is left.
  const { values: revealed, keep: keepRevealed, forget: hideRevealed } = useEphemeral(entryId);

  useEffect(() => {
    setDetail(null);
    setError(null);
    invoke<ItemDetail>("item_detail", { entryId })
      .then(setDetail)
      .catch((e) => setError(String(e)));
  }, [entryId]);

  // The card disappears only when the item itself did not load, and even then
  // it can be closed or retried. Errors from actions inside the card are shown
  // above the fields and dismissed with a cross.
  if (!detail) {
    return (
      <div className="pane">
        <div className="pane-head">
          <span className="acts" style={{ marginLeft: "auto" }}>
            <button type="button" className="btn icon-only" onClick={onClose} title={t("detail.close")} aria-label={t("detail.close")}>
              <Icon name="close" size={14} />
            </button>
          </span>
        </div>
        {error && (
          <Alert
            message={error}
            onClose={onClose}
            onRetry={() => {
              setError(null);
              invoke<ItemDetail>("item_detail", { entryId })
                .then(setDetail)
                .catch((e) => setError(String(e)));
            }}
          />
        )}
      </div>
    );
  }

  const key = (f: SecretField) =>
    typeof f === "string" ? f : "custom" in f ? `custom:${f.custom}` : `history:${f.password_history}`;

  const copy = async (field: SecretField, label: string) => {
    try {
      const clears = await invoke<number>("copy_secret", { entryId, field });
      onCopied(clears > 0 ? t("detail.copied", { sec: clears }) : `${label} → ${t("action.copied").toLowerCase()}`);
    } catch (e) {
      setError(String(e));
    }
  };

  const reveal = async (field: SecretField) => {
    const k = key(field);
    if (revealed[k]) {
      hideRevealed(k);
      return;
    }
    try {
      const value = await invokeSecret("reveal_secret", { entryId, field });
      keepRevealed(k, value);
    } catch (e) {
      setError(String(e));
    }
  };

  const act = async (cmd: string) => {
    setBusy(true);
    setError(null);
    try {
      await invoke(cmd, cmd === "purge_items" ? { entryIds: [entryId] } : { entryId });
      setConfirm(null);
      onChanged();
      onClose();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const favicon = siteIcon ?? null;
  const brand = detail.kind === "card"
    ? detectCardBrand(detail.fields.find((f) => f.key === "cardNumber")?.value, detail.fields.find((f) => f.key === "brand")?.value)
    : null;
  const useCardBrand = brand !== null;
  const useFavicon = !useCardBrand && favicon !== null;
  // A site favicon may carry its own recognizable hue. Everything else keeps
  // the stable colour of its type, so a key is always a key and a card always
  // reads as a card instead of changing colour with a person's name.
  const hue = useFavicon ? iconHue : null;
  const accent = hue === null ? undefined : ({ ["--h" as string]: String(hue) } as React.CSSProperties);

  return (
    <div className={`pane kind-${detail.kind}${hue === null ? "" : " hued"}`} style={accent}>
      {/* The hero header: a large tile — the site's favicon or a monogram —
          the name and the tags. When the tile is a monogram, its hue becomes the
          accent of the whole card: the sections' edges, the headings, the
          chips. */}
      <div className="pane-head pane-hero">
        <span className="hero-tile">
          {useCardBrand ? (
            <CardBrandMark brand={brand} />
          ) : useFavicon ? (
            <img src={favicon} alt="" />
          ) : (
            <Monogram name={detail.name} size={44} />
          )}
        </span>
        <div className="pane-title">
          <h2>{detail.name}</h2>
          <span className="hero-meta">
            <span className="chip kind">{t(KIND_KEY[detail.kind])}</span>
            {detail.folder_name && <span className="chip"><Icon name="folder" size={11} />{detail.folder_name}</span>}
            {detail.favorite && <span className="chip warn">★ {t("detail.favourite")}</span>}
            {detail.reprompt && <span className="chip"><Icon name="lock" size={11} />{t("detail.reprompt")}</span>}
            {detail.deleted && <span className="chip bad">{t("detail.inTrash")}</span>}
          </span>
        </div>
        {/* As icons: three captions in a row took half the line away from the
            name, and the actions here are short and familiar to everyone. The
            dangerous one is set off by a rule and reddens only under the
            cursor — a permanent red patch in the corner shouts louder than it
            should. */}
        <span className="acts">
          {detail.deleted ? (
            <>
              <button type="button"
                className="btn icon-only"
                disabled={busy}
                onClick={() => void act("restore_item")}
                title={t("item.restore")}
                aria-label={t("item.restore")}
              >
                <Icon name="undo" size={14} />
              </button>
              <span className="acts-sep" />
              <button type="button"
                className="btn icon-only danger"
                disabled={busy}
                onClick={() => setConfirm("purge")}
                title={t("item.purge")}
                aria-label={t("item.purge")}
              >
                <Icon name="trash" size={14} />
              </button>
            </>
          ) : (
            <>
              <button type="button"
                className="btn icon-only"
                onClick={() => setEditing(true)}
                title={t("edit.open")}
                aria-label={t("edit.open")}
              >
                <Icon name="edit" size={14} />
              </button>
              <span className="acts-sep" />
              <button type="button"
                className="btn icon-only danger"
                disabled={busy}
                onClick={() => setConfirm("trash")}
                title={t("item.trash")}
                aria-label={t("item.trash")}
              >
                <Icon name="trash" size={14} />
              </button>
            </>
          )}
          <span className="acts-sep" />
          <button type="button"
            className="btn icon-only"
            onClick={onClose}
            title={t("detail.close")}
            aria-label={t("detail.close")}
          >
            <Icon name="close" size={14} />
          </button>
        </span>
      </div>

      {confirm && (
        <Modal
          title={confirm === "trash" ? t("item.trash") : t("item.purge")}
          onClose={() => setConfirm(null)}
          footer={
            <>
              <button type="button"
                className="btn danger"
                disabled={busy}
                onClick={() => void act(confirm === "trash" ? "trash_item" : "purge_items")}
              >
                {confirm === "trash" ? t("item.trash") : t("item.purge")}
              </button>
              <button type="button" className="btn" onClick={() => setConfirm(null)}>
                {t("action.cancel")}
              </button>
            </>
          }
        >
          <p className="hint">{confirm === "trash" ? t("item.trashConfirm") : t("item.purgeConfirm")}</p>
        </Modal>
      )}

      {error && <Alert message={error} onClose={() => setError(null)} />}

      {detail.kind === "card" && brand && <PaymentCard detail={detail} brand={brand} />}

      {/* What a plugin has to say about this item. The card knows nothing
          about an ssh route or a vault connection: it gives the plugins the
          item and lets each draw its own block. */}
      {plugins.map((m) => {
        const Card = pluginEntry(m.id).ItemCard;
        return Card ? <Card key={m.id} detail={detail} entryId={entryId} onChanged={onChanged} /> : null;
      })}

      {detail.fields.length > 0 && (
      <section className="pane-card">
      <h4 className="block-title">{t("detail.section.fields")}</h4>
      {detail.fields.map((f, idx) => {
        const k = f.secret ? key(f.secret) : `${f.label}:${idx}`;

        // Hiding a one-time code means nothing: it lives half a minute and
        // exists precisely to be read.
        if (f.secret === "totp") {
          return (
            <div className="rowline" key={k}>
              <span className="val">
                <label>{fieldLabel(f.key, f.label)}</label>
                <Totp entryId={entryId} />
              </span>
              <span className="acts">
                <button type="button" className="btn icon-only" title={t("detail.copy")} onClick={() => void copy("totp", fieldLabel(f.key, f.label))}>
                  <Icon name="copy" size={13} />
                </button>
              </span>
            </div>
          );
        }
        // On a hidden field `value` is a safe preview (a card's mask, for
        // instance). The dots are shown only when there is no preview.
        const shown = fieldValue(f.key, f.hidden ? (revealed[k] ?? f.value) : f.value);
        return (
          <div className="rowline" key={k}>
            <span className="val">
              <label>{fieldLabel(f.key, f.label)}</label>
              <span className={`v ${f.mono ? "mono" : ""}`}>{shown ?? "••••••••••"}</span>
            </span>
            <span className="acts">
              {f.hidden && f.secret && (
                <button type="button"
                  className="btn icon-only"
                  title={revealed[k] ? t("detail.hide") : t("detail.reveal")}
                  onClick={() => void reveal(f.secret as SecretField)}
                >
                  <Icon name={revealed[k] ? "eye-off" : "eye"} size={13} />
                </button>
              )}
              {f.secret && (
                <button type="button" className="btn icon-only" title={t("detail.copy")} onClick={() => void copy(f.secret as SecretField, fieldLabel(f.key, f.label))}>
                  <Icon name="copy" size={13} />
                </button>
              )}
              {f.secret === "password" && !detail.deleted && (
                <button type="button" className="btn icon-only" title={t("regen.title")} aria-label={t("regen.title")} onClick={() => setRegenerating(true)}>
                  <Icon name="sync" size={13} />
                </button>
              )}
            </span>
            {f.secret === "password" && regenerated && (
              <span className="regen-done">
                {t("regen.done")}
                <button type="button" className="btn small" onClick={() => { setRegenerated(false); void copy("password", fieldLabel(f.key, f.label)); }}>
                  {t("regen.copy")}
                </button>
              </span>
            )}
          </div>
        );
      })}
      </section>
      )}

      {detail.passkeys.length > 0 && (
        <section className="pane-card tone-orange">
          <h4 className="block-title">{t("passkey.title", { n: detail.passkeys.length })}</h4>
          <div className="passkeys">
            {detail.passkeys.map((p) => (
              <div className="passkey" key={p.credential_id || p.rp_id + (p.user_name ?? "")}>
                <span className="passkey-icon" aria-hidden="true">
                  <Icon name="key" size={14} />
                </span>
                <span className="passkey-text">
                  <b className="mono">{p.rp_id}</b>
                  <span>
                    {p.user_display_name || p.user_name || t("passkey.noUser")}
                    {p.user_display_name && p.user_name && p.user_display_name !== p.user_name ? ` · ${p.user_name}` : ""}
                  </span>
                  <span className="passkey-meta">
                    {p.created && <span className="chip">{t("passkey.created", { when: fmtIso(p.created) })}</span>}
                    {p.last_used && <span className="chip ok">{t("passkey.lastUsed", { when: fmtIso(p.last_used, true) })}</span>}
                    {p.key_algorithm && <span className="chip">{p.key_algorithm}{p.key_curve ? ` · ${p.key_curve}` : ""}</span>}
                    <span className={p.discoverable ? "chip ok" : "chip"}>{p.discoverable ? t("passkey.discoverable") : t("passkey.nonDiscoverable")}</span>
                    {p.counter !== null && p.counter > 0 && <span className="chip">{t("passkey.uses", { n: p.counter })}</span>}
                  </span>
                </span>
                <span className="acts">
                  <button
                    type="button"
                    className="btn icon-only danger"
                    title={t("passkey.remove")}
                    aria-label={t("passkey.remove")}
                    disabled={busy || detail.deleted}
                    onClick={() => setRemovingPasskey(p.credential_id)}
                  >
                    <Icon name="trash" size={13} />
                  </button>
                </span>
              </div>
            ))}
          </div>
          <span className="hint">{t("passkey.hint")}</span>
        </section>
      )}

      {removingPasskey !== null && (
        <Modal
          title={t("passkey.removeTitle")}
          onClose={() => setRemovingPasskey(null)}
          footer={
            <>
              <button
                type="button"
                className="btn danger"
                disabled={busy}
                onClick={() =>
                  void (async () => {
                    setBusy(true);
                    try {
                      await invoke("update_item", { entryId: detail.id, edit: { remove_passkeys: [removingPasskey], custom: [], remove_custom: [] } });
                      setRemovingPasskey(null);
                      onChanged();
                    } catch (e) {
                      setError(String(e));
                    } finally {
                      setBusy(false);
                    }
                  })()
                }
              >
                {busy ? t("action.saving") : t("passkey.remove")}
              </button>
              <button type="button" className="btn" onClick={() => setRemovingPasskey(null)}>
                {t("action.cancel")}
              </button>
            </>
          }
        >
          <p className="hint">{t("passkey.removeConfirm")}</p>
        </Modal>
      )}

      {(detail.password_history?.length ?? 0) > 0 && (
        <section className="pane-card tone-amber">
          <h4 className="block-title">{t("detail.history", { n: detail.password_history!.length })}</h4>
          {detail.password_history!.map((h) => {
            const field: SecretField = { password_history: h.index };
            const k = key(field);
            return (
              <div className="rowline" key={k}>
                <span className="val">
                  <label>{h.last_used ? t("detail.historyUntil", { when: fmtIso(h.last_used, true) }) : t("field.passwordHistory")}</label>
                  <span className="v mono">{revealed[k] ?? "••••••••••"}</span>
                </span>
                <span className="acts">
                  <button type="button" className="btn icon-only" title={revealed[k] ? t("detail.hide") : t("detail.reveal")} aria-label={revealed[k] ? t("detail.hide") : t("detail.reveal")} onClick={() => void reveal(field)}>
                    <Icon name={revealed[k] ? "eye-off" : "eye"} size={13} />
                  </button>
                  <button type="button" className="btn icon-only" title={t("detail.copy")} aria-label={t("detail.copy")} onClick={() => void copy(field, t("field.passwordHistory"))}>
                    <Icon name="copy" size={13} />
                  </button>
                </span>
              </div>
            );
          })}
          <span className="hint">{t("detail.historyHint")}</span>
        </section>
      )}

      {detail.uris.length > 0 && (
        <section className="pane-card tone-mint">
          <h4 className="block-title">{t("detail.uris")}</h4>
          <div className="uri-list">
            {detail.uris.map((u) => (
              <span className="uri" key={u}>
                <Icon name="all" size={12} />
                <span className="mono">{u}</span>
                <CopyButton value={u} onCopied={onCopied} title={t("detail.copy")} size={12} className="btn icon-only ghost" />
              </span>
            ))}
          </div>
        </section>
      )}

      {detail.fields.length === 0 && detail.uris.length === 0 && (
        <Empty icon="note" title={t("items.empty")} />
      )}

      {!detail.deleted && (detail.password_history?.length ?? 0) > 0 && (
        <DangerZone
          title={t("settings.danger")}
          items={[
            {
              label: t("detail.historyClear"),
              hint: t("detail.historyClearHint"),
              action: t("detail.historyClearAction"),
              onClick: () => setClearingHistory(true),
              disabled: busy,
            },
          ]}
        />
      )}

      {clearingHistory && (
        <Modal
          title={t("detail.historyClearTitle")}
          onClose={() => setClearingHistory(false)}
          footer={
            <>
              <button
                type="button"
                className="btn danger"
                disabled={busy}
                onClick={async () => {
                  setBusy(true);
                  setError(null);
                  try {
                    await invoke("update_item", { entryId: detail.id, edit: { clear_password_history: true, custom: [], remove_custom: [] } });
                    setClearingHistory(false);
                    for (const h of detail.password_history ?? []) hideRevealed(key({ password_history: h.index }));
                    onChanged();
                    setDetail(await invoke<ItemDetail>("item_detail", { entryId }));
                  } catch (e) {
                    setError(String(e));
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                {busy ? t("action.saving") : t("detail.historyClearAction")}
              </button>
              <button type="button" className="btn" onClick={() => setClearingHistory(false)}>
                {t("action.cancel")}
              </button>
            </>
          }
        >
          <p className="hint">{t("detail.historyClearConfirm")}</p>
        </Modal>
      )}

      {regenerating && (
        <RegenerateModal
          entryId={entryId}
          onClose={() => setRegenerating(false)}
          onDone={() => {
            setRegenerating(false);
            setRegenerated(true);
            onChanged();
          }}
        />
      )}

      {editing && (
        <EditItem
          detail={detail}
          onClose={() => setEditing(false)}
          onCopied={onCopied}
          onSaved={(e) => {
            onCopied(e.state.state === "pushed" ? t("edit.pushed") : t("edit.savedLocally"));
            onChanged();
          }}
        />
      )}
    </div>
  );
}
