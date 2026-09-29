import "./style.css";
import { useEffect, useState } from "react";
import { Alert, Row, Rows, Section, Toggle } from "@keyward/ui";
import { t } from "@keyward/i18n";
import { call } from "@keyward/plugins/call";
import type { HashicorpSettings as Settings } from "./types";

/// The broker's settings: notices about the deadlines of issued access.
///
/// The chosen connection lies here too, but there is nothing to draw it with: a
/// Vault is chosen in the section's column rather than in the settings. The
/// object is sent whole — the plugin keeps it as it is.
export function HashicorpSettings() {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void call<Settings>("hashicorp", "settings").then(setSettings).catch((e) => setError(String(e)));
  }, []);

  const patch = async (next: Partial<Settings>) => {
    if (!settings) return;
    const merged = { ...settings, ...next };
    setSettings(merged);
    setError(null);
    try {
      setSettings(await call<Settings>("hashicorp", "set_settings", merged));
    } catch (e) {
      setError(String(e));
      void call<Settings>("hashicorp", "settings").then(setSettings).catch(() => {});
    }
  };

  if (!settings) return error ? <Alert message={error} /> : null;

  return (
    <>
      <Section title={t("plugin.hashicorp.notices")} tone="mint">
        <Rows>
          <Row title={t("settings.expiryNotices")} hint={t("settings.expiryNoticesHint")}>
            <Toggle on={settings.expiry_notices} onChange={(v) => void patch({ expiry_notices: v })} />
          </Row>
        </Rows>
      </Section>
      {error && <Alert message={error} />}
    </>
  );
}
