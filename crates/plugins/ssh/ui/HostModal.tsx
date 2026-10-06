import { useState } from "react";
import { Alert, Modal } from "@keyward/ui";
import { t } from "@keyward/i18n";
import { call } from "@keyward/plugins/call";
import type { SshKeyEntry } from "./types";

/// Binding hosts happens in a modal rather than an inline form: an inline one
/// broke the list's row and ran over its neighbours.
export function HostModal({
  entry,
  onDone,
  onChanged,
}: {
  entry: SshKeyEntry;
  onDone: () => void;
  onChanged: (keys: SshKeyEntry[]) => void;
}) {
  const [hosts, setHosts] = useState(entry.hosts);
  const [user, setUser] = useState(entry.user);
  const [port, setPort] = useState(entry.port);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const save = async (value: string) => {
    setBusy(true);
    setError(null);
    try {
      onChanged(await call<SshKeyEntry[]>("ssh", "set_hosts", { entry_id: entry.id, hosts: value, user: user.trim(), port: port.trim() }));
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
      <div className="routes-login">
        <div className="field grow">
          <label>{t("routes.login")}</label>
          <input
            value={user}
            onChange={(e) => setUser(e.target.value)}
            placeholder="root"
            spellCheck={false}
            autoCapitalize="off"
            autoCorrect="off"
          />
        </div>
        <div className="field">
          <label>{t("routes.port")}</label>
          <input value={port} onChange={(e) => setPort(e.target.value.replace(/[^0-9]/g, ""))} placeholder="22" inputMode="numeric" />
        </div>
      </div>
      <p className="hint">{t("routes.loginHint")}</p>
      {error && <Alert message={error} />}
    </Modal>
  );
}
