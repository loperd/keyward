/// A new password for a login, made and saved in one step.
///
/// The password is assembled and written into the item by the daemon: it never
/// comes to the window, so there is nothing of it here to show, to log or to
/// leave behind in the webview's memory. What the window sees is the rules it
/// is made by and how strong that makes it. The old password goes into the
/// item's history; the new one is copied afterwards, on a press, the usual
/// way.
import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Alert, Modal } from "../ui";
import { t } from "../i18n";
import { DEFAULT_SPEC, GenControls, bits, strength, type Spec } from "./Generator";

export function RegenerateModal({
  entryId,
  onClose,
  onDone,
}: {
  entryId: string;
  onClose: () => void;
  onDone: () => void;
}) {
  const [spec, setSpec] = useState<Spec>(DEFAULT_SPEC);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const n = bits(spec);
  const level = strength(n);

  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      await invoke("regenerate_password", { entryId, spec });
      onDone();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      wide
      title={t("regen.title")}
      onClose={onClose}
      onSubmit={() => void save()}
      footer={
        <button type="button" className="btn primary" disabled={busy} onClick={() => void save()}>
          {busy ? t("action.saving") : t("regen.save")}
        </button>
      }
    >
      <p className="hint">{t("regen.hint")}</p>
      <p className="hint">{t("regen.strength", { bits: n, level: t(`gen.strength.${level}` as never) })}</p>
      <GenControls spec={spec} patch={(change) => setSpec({ ...spec, ...change })} />
      {error && <Alert message={error} />}
    </Modal>
  );
}
