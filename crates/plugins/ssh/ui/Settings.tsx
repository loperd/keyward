import "./style.css";
import { useCallback, useEffect, useState } from "react";
import { Alert, CopyButton, Field, Picker, Row, Rows, Section, Toggle, copyText } from "@keyward/ui";
import { t } from "@keyward/i18n";
import { call } from "@keyward/plugins/call";
import type { SshSettings as Settings, SshStatus } from "./types";

/// The ssh agent's settings. Its own: the core knows nothing about the agent,
/// the sockets or the confirmation of a signature, and they are no longer in the
/// shared `Settings`.
export function SshSettings() {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [status, setStatus] = useState<SshStatus | null>(null);
  const [snippet, setSnippet] = useState("");
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    void call<Settings>("ssh", "settings").then(setSettings).catch((e) => setError(String(e)));
    void call<SshStatus>("ssh", "status").then(setStatus).catch(() => setStatus(null));
  }, []);

  useEffect(() => {
    load();
    void call<string>("ssh", "snippet").then(setSnippet).catch(() => setSnippet(""));
  }, [load]);

  const patch = async (next: Partial<Settings>) => {
    if (!settings) return;
    const merged = { ...settings, ...next };
    setSettings(merged);
    setError(null);
    try {
      setSettings(await call<Settings>("ssh", "set_settings", merged));
      // The sockets come up and go down in place: the numbers beside them have
      // to show what happened rather than what was there before the switch.
      void call<SshStatus>("ssh", "status").then(setStatus).catch(() => {});
    } catch (e) {
      setError(String(e));
      // What the plugin really holds is returned: a value that was not
      // accepted must not be shown as though it had been.
      void call<Settings>("ssh", "settings").then(setSettings).catch(() => {});
    }
  };

  // The lines for ~/.ssh/config are copied whole, so the button carries a word
  // rather than an icon: there is no field beside it an icon could belong
  // to.
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    await copyText(snippet);
    setCopied(true);
    setTimeout(() => setCopied(false), 1600);
  };

  const socket = status?.socket ?? "~/.keyward/agent.sock";

  return (
    <>
      {settings && (
        <Section title={t("plugin.ssh.agent")} tone="mint">
          <Rows>
            <Row title={t("settings.sshAgent")} hint={t("settings.sshAgentHint")}>
              <Toggle on={settings.agent_enabled} onChange={(v) => void patch({ agent_enabled: v })} />
            </Row>
            <Row title={t("settings.sshAsk")} hint={t("settings.sshAskHint")}>
              <div className="control">
                <Picker
                  value={settings.ask}
                  placeholder={t(settings.ask === "always" ? "settings.sshAsk.always" : "settings.sshAsk.never")}
                  options={[
                    { id: "never", label: t("settings.sshAsk.never") },
                    { id: "always", label: t("settings.sshAsk.always") },
                  ]}
                  onChange={(id) => void patch({ ask: id as Settings["ask"] })}
                />
              </div>
            </Row>
            <Row title={t("settings.sshSocket")} hint={t("settings.sshSocketHint")}>
              <Toggle on={settings.shared_socket} onChange={(v) => void patch({ shared_socket: v })} />
            </Row>
            {settings.shared_socket && (
              <Row title={t("settings.sshSocketPath")} hint={t("settings.sshSocketPathHint")}>
                <span className="snippet-line">
                  <code className="mono">export SSH_AUTH_SOCK={socket}</code>
                  <CopyButton
                    value={`export SSH_AUTH_SOCK=${socket}`}
                    onCopied={() => {}}
                    title={t("action.copy")}
                  />
                </span>
              </Row>
            )}
          </Rows>
        </Section>
      )}

      <Section title={t("settings.sshConfig")} tone="amber">
        <pre>{snippet || "…"}</pre>
        <div className="between">
          <p className="hint">{t("settings.sshConfigHint")}</p>
          <button type="button" className="btn" onClick={copy} disabled={!snippet}>
            {copied ? t("action.copied") : t("action.copy")}
          </button>
        </div>
      </Section>

      {status && (
        <Section title={t("plugin.ssh.state")}>
          <Field label={t("settings.ssh.agent")} value={String(status.live_sockets)} />
          <Field label={t("routes.title")} value={String(status.mappings)} />
          <Field label={t("plugin.ssh.unmapped")} value={String(status.unmapped.length)} />
        </Section>
      )}

      {status && status.warnings.length > 0 && (
        <Section title={t("settings.ssh.warnings", { n: status.warnings.length })} tone="orange">
          {status.warnings.map((w) => (
            <p key={w}>{w}</p>
          ))}
        </Section>
      )}

      {error && <Alert message={error} />}
    </>
  );
}
