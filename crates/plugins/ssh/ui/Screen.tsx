import "./style.css";
import { useCallback, useEffect, useState } from "react";
import { Alert, Empty, Icon, Modal, Skeleton } from "@keyward/ui";
import { t } from "@keyward/i18n";
import { call } from "@keyward/plugins/call";
import type { PluginScreenProps } from "@keyward/plugins/types";
import type { SshKeyEntry } from "./types";

/// Routes: the ssh keys and the hosts they are bound to.
///
/// The table of hosts against keys is gone: it showed the same binding from
/// the other side and had to be read twice. The point of the section is to see
/// at a glance which keys have no hosts, and to give them some.
export function SshScreen({ catalog, loading, onChanged }: PluginScreenProps) {
  const [keys, setKeys] = useState<SshKeyEntry[]>([]);
  const [editing, setEditing] = useState<string | null>(null);
  const editingEntry = keys.find((k) => k.id === editing) ?? null;

  // The keys are asked of the plugin: the core gives the catalogue of items,
  // and which of them is an ssh key and where it leads is known only to the
  // agent. The catalogue is in the dependencies so that the list refreshes
  // after an item is edited.
  const entries = catalog?.items.length ?? 0;
  const reload = useCallback(() => {
    void call<SshKeyEntry[]>("ssh", "keys")
      .then(setKeys)
      .catch(() => setKeys([]));
  }, []);
  useEffect(reload, [reload, entries]);

  if (loading && keys.length === 0) return <Skeleton rows={5} />;

  const unbound = keys.filter((k) => !k.hosts.trim());

  return (
    <>
      {keys.length === 0 ? (
        <Empty icon="route" title={t("routes.empty.title")} body={t("routes.empty.body")} />
      ) : (
        <>
          <h4 className="section-title">{t("routes.pending", { count: unbound.length })}</h4>
          <div className="list">
            {keys.map((k) =>
              (
                <div className="row" key={k.id}>
                  <span className="glyph">
                    <Icon name="ssh_key" />
                  </span>
                  <span className="text">
                    <b>{k.name}</b>
                    <span>{k.hosts || "—"}</span>
                  </span>
                  <span className="side reveal">
                    <button type="button" className="btn" onClick={() => setEditing(k.id)}>
                      <Icon name="plus" size={13} />
                      {k.hosts ? t("edit.open") : t("routes.bind")}
                    </button>
                  </span>
                </div>
              ),
            )}
          </div>
        </>
      )}

      {editingEntry && (
        <HostModal
          entry={editingEntry}
          onDone={() => setEditing(null)}
          onChanged={(next) => {
            setKeys(next);
            onChanged();
          }}
        />
      )}
    </>
  );
}

/// Binding hosts happens in a modal rather than an inline form: an inline one
/// broke the list's row and ran over its neighbours.
function HostModal({
  entry,
  onDone,
  onChanged,
}: {
  entry: SshKeyEntry;
  onDone: () => void;
  onChanged: (keys: SshKeyEntry[]) => void;
}) {
  const [hosts, setHosts] = useState(entry.hosts);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const save = async (value: string) => {
    setBusy(true);
    setError(null);
    try {
      onChanged(await call<SshKeyEntry[]>("ssh", "set_hosts", { entry_id: entry.id, hosts: value }));
      onDone();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      title={entry.name}
      onClose={onDone}
      footer={
        <>
          {entry.hosts && (
            <button type="button" className="btn" disabled={busy} onClick={() => void save("")}>
              {t("routes.unbind")}
            </button>
          )}
          <button type="button" className="btn" onClick={onDone}>
            {t("action.cancel")}
          </button>
          <button type="button" className="btn primary" disabled={busy} onClick={() => void save(hosts)}>
            {busy ? t("action.saving") : t("action.save")}
          </button>
        </>
      }
    >
      <div className="field">
        <label>{t("routes.hosts")}</label>
        <input
          value={hosts}
          onChange={(e) => setHosts(e.target.value)}
          placeholder="*.example.com, git.example.com, admin@10.0.0.5"
          autoFocus
          spellCheck={false}
          onKeyDown={(e) => e.key === "Enter" && void save(hosts)}
        />
      </div>
      <p className="hint">{t("routes.empty.body")}</p>
      {error && <Alert message={error} />}
    </Modal>
  );
}
