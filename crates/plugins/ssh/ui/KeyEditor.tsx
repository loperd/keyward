import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Alert, CopyButton, DangerZone, Icon } from "@keyward/ui";
import { PasswordInput } from "@keyward/PasswordInput";
import { t } from "@keyward/i18n";
import type { PluginItemEditorProps } from "@keyward/plugins/types";
import type { KeySummary } from "./types";
import "./style.css";

/// A key made or read for the form, before it is saved: a draft the daemon
/// holds. The window has its number and the public half — never the private
/// key, which goes from the daemon into the item on save.
type Pending = KeySummary & { id: string };

/// An ssh key item's key, in the item form — the way a Bitwarden client does
/// it.
///
/// A new item simply has a key: an Ed25519 pair is made the moment the form
/// opens, and its public parts are shown as fields. Importing one's own is a
/// button by the private key: the daemon reads the clipboard itself, checks
/// the key at once, and a passphrase is asked for only when the key has one.
/// There is no "generate or paste" step to go through first.
///
/// An existing item keeps its key: the public half and the fingerprint are
/// shown to copy, and replacing the key lives in the danger zone — a new key
/// locks the old one out of every server that trusted it.
export function SshKeyEditor({ detail, onChange, onCopied }: PluginItemEditorProps) {
  const [pending, setPending] = useState<Pending | null>(null);
  const [replacing, setReplacing] = useState(!detail);
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  // The key on the clipboard is under a passphrase: asked for, then the
  // clipboard is read again with it.
  const [locked, setLocked] = useState(false);
  const [passphrase, setPassphrase] = useState("");
  const made = useRef(false);

  const take = (p: Pending | null) => {
    setPending(p);
    onChange(p ? { ssh_key: { source: "draft", id: p.id } } : null, p !== null || !replacing);
  };

  const draft = async (source: Record<string, unknown>) =>
    invoke<Pending>("ssh_key_draft", { source });

  const generate = async () => {
    setBusy(true);
    setProblem(null);
    setLocked(false);
    try {
      take(await draft({ source: "generate", algorithm: "ed25519" }));
    } catch (e) {
      setProblem(String(e));
      onChange(null, false);
    } finally {
      setBusy(false);
    }
  };

  const fromClipboard = async (pass: string | null = null) => {
    setBusy(true);
    setProblem(null);
    try {
      take(await draft({ source: "clipboard", passphrase: pass }));
      setLocked(false);
      setPassphrase("");
    } catch (e) {
      const message = String(e);
      if (message.includes("err.sshKeyNeedsPassphrase") || message.includes("err.sshKeyWrongPassphrase")) {
        // Ask for what opens it; the key made before stays until the import
        // succeeds.
        setLocked(true);
      }
      setProblem(message);
    } finally {
      setBusy(false);
    }
  };

  const copyPrivate = async () => {
    if (!pending) return;
    try {
      await invoke<number>("copy_ssh_draft", { id: pending.id });
      onCopied(t("action.copied"));
    } catch (e) {
      setProblem(String(e));
    }
  };

  // A new item gets its key at once.
  useEffect(() => {
    if (detail || made.current) return;
    made.current = true;
    onChange(null, false);
    void generate();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const keep = () => {
    setReplacing(false);
    setPending(null);
    setProblem(null);
    setLocked(false);
    onChange(null, true);
  };

  const current = detail
    ? {
        public_key: detail.fields.find((f) => f.key === "publicKey")?.value ?? "",
        fingerprint: detail.fields.find((f) => f.key === "fingerprint")?.value ?? "",
      }
    : null;
  const shown = pending ?? (replacing ? null : current);

  return (
    <div className="form-block ssh-key-editor">
      <h4 className="form-section">{t("sshkey.section")}</h4>

      {detail && replacing && <Alert tone="warn" message={t("sshkey.replacingWarn")} />}

      {replacing && (
        <div className="field">
          <div className="ssh-field-head">
            <label>{t("sshkey.private")}</label>
            {pending && <span className="chip ssh-alg">{pending.algorithm}</span>}
            <span className="grow" />
            <button type="button" className="btn small" disabled={busy} onClick={() => void fromClipboard()}>
              <Icon name="copy" size={12} />
              {t("sshkey.importClipboard")}
            </button>
          </div>
          {/* The private key is in the daemon, not here: dots, and a copy
              that the daemon makes. */}
          <div className="with-inner">
            <input
              className="mono"
              type="password"
              readOnly
              value={pending ? "••••••••••••••••••••••••" : ""}
              placeholder={busy ? t("sshkey.making") : ""}
              aria-label={t("sshkey.private")}
            />
            <button
              type="button"
              className="btn icon-only inner"
              title={t("sshkey.copyPrivate")}
              aria-label={t("sshkey.copyPrivate")}
              disabled={!pending}
              onClick={() => void copyPrivate()}
            >
              <Icon name="copy" size={13} />
            </button>
          </div>
          <span className="hint">{t("sshkey.importHint")}</span>
        </div>
      )}

      {locked && (
        <form
          className="field"
          onSubmit={(e) => {
            e.preventDefault();
            void fromClipboard(passphrase);
          }}
        >
          <label>{t("sshkey.passphrase")}</label>
          <div className="ssh-pass">
            <PasswordInput value={passphrase} onChange={setPassphrase} autoFocus ariaLabel={t("sshkey.passphrase")} />
            <button type="submit" className="btn" disabled={busy || !passphrase}>
              {t("sshkey.open")}
            </button>
          </div>
          <span className="hint">{t("sshkey.passphraseHint")}</span>
        </form>
      )}

      {problem && <Alert message={problem} />}

      {shown && (
        <>
          <Fact label={t("sshkey.public")} value={shown.public_key} copyTitle={t("sshkey.copyPublic")} onCopied={onCopied} />
          <Fact label={t("sshkey.fingerprint")} value={shown.fingerprint} copyTitle={t("sshkey.copyFingerprint")} onCopied={onCopied} />
        </>
      )}

      {detail && !replacing && <span className="hint">{t("sshkey.privateStored")}</span>}

      {detail && replacing && (
        <div className="ssh-keep">
          <button type="button" className="btn" onClick={keep}>
            {t("sshkey.keep")}
          </button>
        </div>
      )}

      {detail && !replacing && (
        <DangerZone
          title={t("sshkey.danger")}
          items={[
            {
              label: t("sshkey.regenerate"),
              hint: t("sshkey.regenerateHint"),
              action: t("sshkey.regenerateAction"),
              tone: "warn",
              onClick: () => {
                setReplacing(true);
                void generate();
              },
            },
            {
              label: t("sshkey.replace"),
              hint: t("sshkey.replaceHint"),
              action: t("sshkey.importClipboard"),
              tone: "warn",
              onClick: () => {
                setReplacing(true);
                onChange(null, false);
                void fromClipboard();
              },
            },
          ]}
        />
      )}
    </div>
  );
}

/// A read-only part of the key with a copy button: the public key goes into
/// `authorized_keys`, the fingerprint is what a server's log names.
function Fact({ label, value, copyTitle, onCopied }: { label: string; value: string; copyTitle: string; onCopied: (text: string) => void }) {
  return (
    <div className="field">
      <label>{label}</label>
      <div className="with-inner">
        <input className="mono" readOnly value={value} aria-label={label} />
        <CopyButton className="inner" value={value} onCopied={onCopied} title={copyTitle} disabled={!value} />
      </div>
    </div>
  );
}
