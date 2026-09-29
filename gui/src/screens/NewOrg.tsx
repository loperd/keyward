/// Creating an organisation.
///
/// The server asks for a billing email even where there is nothing to pay for:
/// the field came from Bitwarden's cloud and stayed in Vaultwarden. Ours is
/// filled in, and can be edited.
import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Alert, Modal } from "../ui";
import { t } from "../i18n";

export function NewOrg({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const create = async () => {
    setBusy(true);
    setError(null);
    try {
      await invoke("create_org", { name, billingEmail: email });
      onCreated();
      onClose();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      title={t("org.new")}
      onClose={onClose}
      onSubmit={() => void create()}
      footer={
        <button type="button"
          className="btn primary"
          disabled={busy || !name.trim() || !email.includes("@")}
          onClick={() => void create()}
        >
          {busy ? t("org.creating") : t("item.create")}
        </button>
      }
    >
      <div className="field">
        <label>{t("org.name")}</label>
        <input value={name} onChange={(e) => setName(e.target.value)} autoFocus spellCheck={false} />
      </div>
      <div className="field">
        <label>{t("org.billing")}</label>
        <input value={email} onChange={(e) => setEmail(e.target.value)} spellCheck={false} />
        <span className="hint">{t("org.billingHint")}</span>
      </div>
      <p className="hint">{t("org.newHint")}</p>
      {error && <Alert message={error} />}
    </Modal>
  );
}
