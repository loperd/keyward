// An ssh key item's key in the editor: the public half and the fingerprint,
// as they are now — worked out where the keys are, so they change the moment
// a new key is made or read — and the two ways to a new key: made there
// (Ed25519, or RSA 4096), or a person's own, pasted into a sheet of its own.
// The private half never stays in the window: a pasted key is read from its
// field once, handed over and the field emptied; one from the clipboard is
// read by the daemon itself. What comes back is a draft's number, saved with
// the item.
import { useEffect, useRef, useState } from "react";
import { SshAlgorithm, type SshKeyDraft, type SshKeyFrom } from "../backend";
import type { SshKeyForm } from "../edit/draft";
import { t } from "../i18n";
import { Level } from "../model/types";
import { faultWords } from "./fault";
import { Icon } from "./Icons";
import { BtnIcon, Kbd, Mark, useCore } from "./marks";
import { Phase } from "./feedback";
import "./ssh-key-edit.css";

/// A key's kind as its public line names it, in a person's words.
const ALGORITHM_WORDS: Readonly<Record<string, string>> = {
  "ssh-ed25519": "Ed25519",
  "ssh-rsa": "RSA",
  "ecdsa-sha2-nistp256": "ECDSA P-256",
  "ecdsa-sha2-nistp384": "ECDSA P-384",
  "ecdsa-sha2-nistp521": "ECDSA P-521",
  "sk-ssh-ed25519@openssh.com": "Ed25519 (FIDO)",
  "sk-ecdsa-sha2-nistp256@openssh.com": "ECDSA (FIDO)",
};

/// What a public key line says its kind is; the line's own word for a kind
/// the table does not know.
export function algorithmOf(publicKey: string): string | null {
  const kind = publicKey.trim().split(/\s+/)[0] ?? "";
  return ALGORITHM_WORDS[kind] ?? (kind || null);
}

/// What the block is busy with.
enum KeyBusy {
  Ed25519 = "ed25519",
  Rsa = "rsa",
  Stored = "stored",
}

export function SshKeyBlock({ ssh, fresh, itemId, onKey }: { ssh: SshKeyForm; fresh: boolean; itemId?: string; onKey: (d: SshKeyDraft) => void }) {
  const { backend } = useCore();
  const [busy, setBusy] = useState<KeyBusy | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [importing, setImporting] = useState(false);
  const can = !!backend.sshKeyDraft;
  const ask = (what: KeyBusy, from: SshKeyFrom) => {
    setBusy(what);
    setError(null);
    backend.sshKeyDraft!(from)
      .then(onKey, (e: unknown) => setError(faultWords(e)))
      .finally(() => setBusy(null));
  };
  const make = (algorithm: SshAlgorithm) => ask(algorithm === SshAlgorithm.Ed25519 ? KeyBusy.Ed25519 : KeyBusy.Rsa, { generate: algorithm });
  const alg = algorithmOf(ssh.publicKey);
  return (
    <>
      <div className="f fe">
        <span className="k">{t("field.algorithm")}</span>
        <span className="v">{alg ?? "—"}</span>
      </div>
      <div className="f fe">
        <span className="k">{t("field.fingerprint")}</span>
        <span className="v mono">{ssh.fingerprint || "—"}</span>
      </div>
      <div className="f fe top">
        <span className="k">{t("field.publicKey")}</span>
        <span className={`v mono keypub${ssh.draft ? " fresh" : ""}`}>{ssh.publicKey || t("edit.key.none")}</span>
      </div>
      {ssh.draft && (
        <div className="keynote">
          <Mark level={Level.Action} words={t("edit.key.new")} />
        </div>
      )}
      {can ? (
        <div className="keyacts">
          <button type="button" className={`btn${fresh && !ssh.draft ? " solid" : " quiet"}`} disabled={busy !== null} aria-busy={busy === KeyBusy.Ed25519 || undefined} onClick={() => make(SshAlgorithm.Ed25519)}>
            <BtnIcon icon="dice" phase={busy === KeyBusy.Ed25519 ? Phase.Busy : Phase.Idle} />
            {t("edit.key.generate")}
          </button>
          <button type="button" className="btn quiet" disabled={busy !== null} aria-busy={busy === KeyBusy.Rsa || undefined} onClick={() => make(SshAlgorithm.Rsa4096)}>
            <BtnIcon icon="dice" phase={busy === KeyBusy.Rsa ? Phase.Busy : Phase.Idle} />
            {t("edit.key.generateRsa")}
          </button>
          <button type="button" className="btn quiet" disabled={busy !== null} onClick={() => setImporting(true)}>
            <Icon name="key" />
            {t("edit.key.import")}
          </button>
          {itemId && !ssh.draft && (
            <button type="button" className="btn quiet" disabled={busy !== null} aria-busy={busy === KeyBusy.Stored || undefined} onClick={() => ask(KeyBusy.Stored, { stored: itemId })}>
              <BtnIcon icon="refresh" phase={busy === KeyBusy.Stored ? Phase.Busy : Phase.Idle} />
              {t("edit.key.fromStored")}
            </button>
          )}
        </div>
      ) : (
        <div className="keynote">
          <Mark level={Level.Unknown} words={t("edit.key.appOnly")} />
        </div>
      )}
      {error && (
        <div className="keynote" role="alert">
          <Mark level={Level.Critical} words={error} />
        </div>
      )}
      {importing && (
        <KeyImportSheet
          onKey={(d) => {
            onKey(d);
            setImporting(false);
          }}
          onClose={() => setImporting(false)}
        />
      )}
    </>
  );
}

/// A person's own private key, pasted into a field of its own over the
/// window, or taken off the clipboard by the daemon. The field is read once
/// at the press and emptied; a passphrase opens a key under one and goes
/// with it.
function KeyImportSheet({ onKey, onClose }: { onKey: (d: SshKeyDraft) => void; onClose: () => void }) {
  const { backend } = useCore();
  const area = useRef<HTMLTextAreaElement>(null);
  const pass = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Whatever was typed leaves with the sheet.
  useEffect(() => {
    const a = area.current;
    const p = pass.current;
    return () => {
      if (a) a.value = "";
      if (p) p.value = "";
    };
  }, []);
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        e.stopPropagation();
        if (!busy) onClose();
      } else if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "s") {
        // Saving the item must wait until the sheet has handed its key over.
        e.preventDefault();
        e.stopPropagation();
      }
    };
    window.addEventListener("keydown", onKeyDown, true);
    return () => window.removeEventListener("keydown", onKeyDown, true);
  }, [busy, onClose]);
  const read = (from: (passphrase: string | null) => SshKeyFrom) => {
    const passphrase = pass.current?.value || null;
    const ask = from(passphrase);
    // The field lets go of the key the moment it is handed over.
    if (area.current) area.current.value = "";
    if (pass.current) pass.current.value = "";
    setBusy(true);
    setError(null);
    backend.sshKeyDraft!(ask)
      .then(onKey, (e: unknown) => setError(faultWords(e)))
      .finally(() => setBusy(false));
  };
  const paste = () => {
    const text = area.current?.value ?? "";
    if (!text.trim()) {
      setError(t("edit.key.empty"));
      area.current?.focus();
      return;
    }
    read((passphrase) => ({ paste: text, passphrase }));
  };
  return (
    <div className="reprompt-veil" onClick={(e) => e.target === e.currentTarget && !busy && onClose()}>
      <div className="reprompt keysheet" role="dialog" aria-modal="true" aria-label={t("edit.key.importTitle")} aria-busy={busy}>
        <div className="reprompt-h">
          <Icon name="key" />
          <span>{t("edit.key.importTitle")}</span>
        </div>
        <p>{t("edit.key.importLede")}</p>
        <textarea
          ref={area}
          className="keyarea mono"
          placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
          aria-label={t("field.privateKey")}
          spellCheck={false}
          autoComplete="off"
          autoCorrect="off"
          autoCapitalize="off"
          rows={14}
          autoFocus
          onKeyDown={(e) => {
            if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
              e.preventDefault();
              if (!busy) paste();
            }
          }}
        />
        <div className="reprompt-in">
          <input ref={pass} type="password" placeholder={t("edit.key.passphrase")} aria-label={t("edit.key.passphrase")} autoComplete="off" spellCheck={false} />
        </div>
        {error && (
          <div role="alert">
            <Mark level={Level.Critical} words={error} />
          </div>
        )}
        <div className="reprompt-go">
          <button type="button" className="btn quiet" disabled={busy} onClick={() => read((passphrase) => ({ clipboard: true, passphrase }))}>
            <Icon name="copy" />
            {t("edit.key.fromClipboard")}
          </button>
          <span className="keygap" />
          <button type="button" className="btn" disabled={busy} onClick={onClose}>
            {t("ui.cancel")}
          </button>
          <button type="button" className="btn solid" disabled={busy} aria-busy={busy || undefined} onClick={paste}>
            <BtnIcon icon="check" phase={busy ? Phase.Busy : Phase.Idle} />
            {t("edit.key.read")}
            <Kbd>⌘↵</Kbd>
          </button>
        </div>
      </div>
    </div>
  );
}
