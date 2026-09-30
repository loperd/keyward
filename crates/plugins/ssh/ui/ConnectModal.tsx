import { useEffect, useRef, useState } from "react";
import { Modal, NumberInput, Picker } from "@keyward/ui";
import { t } from "@keyward/i18n";
import { call } from "@keyward/plugins/call";
import { openTab, type Destination } from "./terminalState";
import type { ConfigHost, HostBanner, SshKeyEntry } from "./types";

const BY_ROUTE = "";

/// `alex@db.example.com:2222` into its parts. A person often pastes it the way
/// ssh takes it; the login and the port go to fields of their own at once.
function split(text: string): { user?: string; host: string; port?: number } {
  let rest = text.trim();
  let user: string | undefined;
  const at = rest.lastIndexOf("@");
  if (at > 0) {
    user = rest.slice(0, at);
    rest = rest.slice(at + 1);
  }
  const m = /^(.*):(\d{1,5})$/.exec(rest);
  if (m && !m[1].includes(":") && Number(m[2]) > 0 && Number(m[2]) < 65536) return { user, host: m[1], port: Number(m[2]) };
  return { user, host: rest };
}

function validHost(host: string): boolean {
  return host.length > 0 && !/\s/.test(host) && !host.startsWith("-");
}

/// Opening a shell to a host by hand. The key is the one the routes give the
/// host — exactly one, as for ssh — unless a person picks another. The login
/// is what the key's item keeps, or what the server's system suggests: its
/// ssh banner names it before any login.
export function ConnectModal({ initial, onClose }: { initial: Destination; onClose: () => void }) {
  const [host, setHost] = useState(initial.host);
  const [user, setUser] = useState(initial.user ?? "");
  const [port, setPort] = useState<number>(initial.port ?? 22);
  const [key, setKey] = useState<string>(initial.entry_id ?? BY_ROUTE);
  const [keys, setKeys] = useState<SshKeyEntry[]>([]);
  const [banner, setBanner] = useState<HostBanner | null>(null);
  const [configHosts, setConfigHosts] = useState<ConfigHost[]>([]);
  // A login a person typed is theirs; a suggested one may be replaced.
  const typedLogin = useRef(Boolean(initial.user));

  useEffect(() => {
    void call<SshKeyEntry[]>("ssh", "keys")
      .then(setKeys)
      .catch(() => setKeys([]));
    void call<ConfigHost[]>("ssh", "term_config_hosts")
      .then((list) => setConfigHosts(list.filter((h) => !h.proxy_jump)))
      .catch(() => setConfigHosts([]));
  }, []);

  const chosen = keys.find((k) => k.id === key);
  const fromConfig = configHosts.find((h) => h.alias === split(host).host);

  // ~/.ssh/config knows the host: its login and port come before a guess.
  useEffect(() => {
    if (!fromConfig) return;
    if (fromConfig.user && !typedLogin.current && !chosen?.user) setUser(fromConfig.user);
    if (fromConfig.port && !initial.port) setPort(fromConfig.port);
  }, [fromConfig, chosen?.user, initial.port]);

  // The key's own login and port come first.
  useEffect(() => {
    if (!chosen) return;
    if (chosen.user && !typedLogin.current) setUser(chosen.user);
    if (chosen.port && !initial.port) setPort(Number(chosen.port) || 22);
  }, [chosen, initial.port]);

  // Then what the server's system suggests.
  useEffect(() => {
    setBanner(null);
    const target = split(host);
    if (!validHost(target.host)) return;
    let alive = true;
    const timer = setTimeout(() => {
      void call<HostBanner>("ssh", "term_probe", { host: target.host, port: target.port ?? port })
        .then((b) => {
          if (!alive) return;
          setBanner(b);
          if (!typedLogin.current && !chosen?.user && !fromConfig?.user) setUser(b.login);
        })
        .catch(() => {});
    }, 600);
    return () => {
      alive = false;
      clearTimeout(timer);
    };
  }, [host, port, chosen?.user, fromConfig?.user]);

  // Taken apart when the text is whole — pasted, or the field left — never
  // halfway through typing, where ":2" of ":2200" would become a port.
  const spread = (text: string): string => {
    const parts = split(text);
    if (parts.user !== undefined) {
      typedLogin.current = true;
      setUser(parts.user);
    }
    if (parts.port !== undefined) setPort(parts.port);
    setHost(parts.host);
    return parts.host;
  };
  const whole = split(host);

  // The login may be left to the route or the item.
  const ready = validHost(whole.host);

  const submit = () => {
    if (!ready) return;
    openTab({
      entry_id: key || undefined,
      host: whole.host,
      port: whole.port ?? port,
      user: whole.user ?? (user.trim() || undefined),
    });
    onClose();
  };

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
            placeholder="db.example.com"
            list="kw-ssh-config-hosts"
            onChange={(e) => setHost(e.target.value)}
            onBlur={(e) => spread(e.target.value)}
            onPaste={(e) => {
              const text = e.clipboardData.getData("text");
              if (!text) return;
              e.preventDefault();
              const el = e.currentTarget;
              const next = el.value.slice(0, el.selectionStart ?? el.value.length) + text + el.value.slice(el.selectionEnd ?? el.value.length);
              spread(next);
            }}
          />
        </div>
        <datalist id="kw-ssh-config-hosts">
          {configHosts.map((h) => (
            <option key={h.alias} value={h.alias}>
              {[h.user && `${h.user}@`, h.hostname ?? h.alias, h.port && `:${h.port}`].filter(Boolean).join("")}
            </option>
          ))}
        </datalist>
        <div className="term-connect-row">
          <div className="field grow">
            <label>{t("term.login")}</label>
            <input
              value={user}
              spellCheck={false}
              autoCapitalize="off"
              autoCorrect="off"
              placeholder="root"
              onChange={(e) => {
                typedLogin.current = true;
                setUser(e.target.value);
              }}
            />
          </div>
          <div className="field">
            <label>{t("term.port")}</label>
            <NumberInput value={port} min={1} ariaLabel={t("term.port")} onChange={(v) => setPort(Math.min(65535, Math.max(1, v ?? 22)))} />
          </div>
        </div>
        {(fromConfig || banner) && (
          <p className="hint term-banner">
            {fromConfig && <span className="chip dot on">~/.ssh/config</span>}
            {fromConfig?.hostname && <code>{fromConfig.hostname}</code>}
            {banner && <span className="chip dot ok">{banner.os ?? "SSH"}</span>}
            {banner && !fromConfig?.user && !typedLogin.current && !chosen?.user && t("term.suggestedLogin", { login: banner.login })}
          </p>
        )}
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
