import { useEffect, useState } from "react";
import { Modal, NumberInput, Picker } from "@keyward/ui";
import { t } from "@keyward/i18n";
import { call } from "@keyward/plugins/call";
import { openTab, type Destination } from "./terminalState";
import type { SshKeyEntry } from "./types";

const BY_ROUTE = "";

/// `alex@db.example.com:2222` into its parts. A person types it the way ssh
/// takes it; the fields below fill in from it.
function parse(text: string): { user?: string; host: string; port?: number } {
  let rest = text.trim();
  let user: string | undefined;
  const at = rest.lastIndexOf("@");
  if (at > 0) {
    user = rest.slice(0, at);
    rest = rest.slice(at + 1);
  }
  const m = /^(.*):(\d{1,5})$/.exec(rest);
  if (m && !m[1].includes(":")) return { user, host: m[1], port: Number(m[2]) };
  return { user, host: rest };
}

/// Opening a shell to a host by hand. The key is the one the routes give the
/// host — exactly one, as for ssh — unless a person picks another.
export function ConnectModal({ initial, onClose }: { initial: Destination; onClose: () => void }) {
  const [host, setHost] = useState(initial.host);
  const [user, setUser] = useState(initial.user ?? "");
  const [port, setPort] = useState<number>(initial.port ?? 22);
  const [key, setKey] = useState<string>(initial.entry_id ?? BY_ROUTE);
  const [keys, setKeys] = useState<SshKeyEntry[]>([]);

  useEffect(() => {
    void call<SshKeyEntry[]>("ssh", "keys")
      .then(setKeys)
      .catch(() => setKeys([]));
  }, []);

  const typed = parse(host);
  // The login may be left to the route: `alex@db` in kw-host gives it.
  const ready = typed.host.length > 0 && !/\s/.test(typed.host);

  const submit = () => {
    if (!ready) return;
    openTab({
      entry_id: key || undefined,
      host: typed.host,
      port: typed.port ?? port,
      user: typed.user ?? (user.trim() || undefined),
    });
    onClose();
  };

  const chosen = keys.find((k) => k.id === key);

  return (
    <Modal
      title={t("term.connectTitle")}
      onClose={onClose}
      onSubmit={submit}
      footer={
        <button type="button" className="btn primary" disabled={!ready} onClick={submit}>
          {t("term.connect")}
        </button>
      }
    >
      <div className="term-connect">
        <div className="field">
          <label>{t("term.host")}</label>
          <input
            value={host}
            autoFocus
            spellCheck={false}
            autoCapitalize="off"
            autoCorrect="off"
            placeholder="alex@db.example.com:22"
            onChange={(e) => setHost(e.target.value)}
          />
        </div>
        <div className="term-connect-row">
          <div className="field grow">
            <label>{t("term.login")}</label>
            <input
              value={typed.user ?? user}
              disabled={Boolean(typed.user)}
              spellCheck={false}
              autoCapitalize="off"
              autoCorrect="off"
              placeholder={t("term.loginPlaceholder")}
              onChange={(e) => setUser(e.target.value)}
            />
          </div>
          <div className="field">
            <label>{t("term.port")}</label>
            <NumberInput value={typed.port ?? port} min={1} ariaLabel={t("term.port")} onChange={(v) => setPort(Math.min(65535, Math.max(1, v ?? 22)))} />
          </div>
        </div>
        <div className="field">
          <label>{t("term.key")}</label>
          <Picker
            value={key}
            placeholder={chosen ? chosen.name : t("term.keyByRoute")}
            options={[{ id: BY_ROUTE, label: t("term.keyByRoute") }, ...keys.map((k) => ({ id: k.id, label: k.name }))]}
            onChange={(id) => setKey(id)}
          />
        </div>
        <p className="hint">{t("term.connectHint")}</p>
      </div>
    </Modal>
  );
}
