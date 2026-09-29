/// A folder's dialogue: creating one, or renaming and deleting it — opened
/// from the folders in the items' column. A folder is one's own way of
/// sorting items, so it lives where the items are, not in a section of its
/// own.
import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Alert, DangerZone, Modal } from "../ui";
import { t } from "../i18n";
import type { Catalog } from "../types";

type Folder = Catalog["folders"][number];

export function FolderEditor({
  folder,
  onClose,
  onChanged,
}: {
  /// `null` — a new folder.
  folder: Folder | null;
  onClose: () => void;
  onChanged: () => void;
}) {
  const [name, setName] = useState(folder?.name ?? "");
  const [killing, setKilling] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const ok = name.trim() !== "" && name.trim() !== folder?.name;

  const run = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
      onChanged();
      onClose();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };
  const save = () => {
    if (!ok) return;
    void run(() => (folder ? invoke("rename_folder", { folderId: folder.id, name }) : invoke("create_folder", { name })));
  };

  if (killing && folder) {
    return (
      <Modal
        title={t("folder.delete")}
        onClose={() => setKilling(false)}
        footer={
          <button type="button" className="btn danger" disabled={busy} onClick={() => void run(() => invoke("delete_folder", { folderId: folder.id }))}>
            {busy ? t("action.saving") : t("folder.delete")}
          </button>
        }
      >
        <p className="hint">{t("folder.deleteWarn", { name: folder.name, n: folder.count })}</p>
        {error && <Alert message={error} />}
      </Modal>
    );
  }

  return (
    <Modal
      title={folder ? folder.name : t("folder.new")}
      onClose={onClose}
      onSubmit={save}
      footer={
        <button type="button" className="btn primary" disabled={busy || !ok} onClick={save}>
          {busy ? t("action.saving") : folder ? t("action.save") : t("item.create")}
        </button>
      }
    >
      <div className="field">
        <label>{t("folder.name")}</label>
        <input value={name} onChange={(e) => setName(e.target.value)} autoFocus spellCheck={false} />
        <span className="hint">{t("folder.nameHint")}</span>
      </div>
      {error && <Alert message={error} />}
      {folder && (
        <DangerZone
          title={t("settings.danger")}
          items={[{ label: t("folder.delete"), hint: t("folder.deleteHint", { n: folder.count }), action: t("folder.delete"), onClick: () => setKilling(true) }]}
        />
      )}
    </Modal>
  );
}
