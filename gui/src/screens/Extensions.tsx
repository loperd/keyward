import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Alert, Icon, Row, Rows, Section } from "../ui";
import { t } from "../i18n";

type ExtensionRow = { key: string; words: string[]; at: number };
type Extensions = { paired: ExtensionRow[]; pending: ExtensionRow[] };

function Words({ words }: { words: string[] }) {
  return (
    <span className="ext-words">
      {words.map((w, i) => (
        <code key={i}>{w}</code>
      ))}
    </span>
  );
}

/// The browser extensions that may ask for passkeys. A new one asks, is
/// refused with its five words, and shows up here to be paired: the person
/// compares the words with the extension's window and pairs with the finger.
export function BrowserExtensions() {
  const [list, setList] = useState<Extensions | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const load = useCallback(() => {
    invoke<Extensions>("extensions")
      .then((l) => {
        setList(l);
        setError(null);
      })
      .catch((e) => setError(String(e)));
  }, []);
  useEffect(() => {
    load();
    // A browser that asks while the screen is open shows up without a reload.
    const timer = setInterval(load, 5000);
    return () => clearInterval(timer);
  }, [load]);

  const act = (command: string, key: string) => {
    setBusy(true);
    setError(null);
    invoke<Extensions>(command, { key })
      .then(setList)
      .catch((e) => setError(String(e)))
      .finally(() => setBusy(false));
  };

  return (
    <Section title={t("settings.extensions")} tone="orange">
      <Rows>
        {list?.pending.map((r) => (
          <Row key={r.key} title={t("settings.extensions.asking")} hint={<Words words={r.words} />}>
            <button type="button" className="btn primary" disabled={busy} onClick={() => act("extension_pair", r.key)}>
              <Icon name="shield-check" size={14} />
              {t("settings.extensions.pair")}
            </button>
          </Row>
        ))}
        {list?.paired.map((r) => (
          <Row key={r.key} title={t("settings.extensions.paired")} hint={<Words words={r.words} />}>
            <button
              type="button"
              className="btn icon-only"
              disabled={busy}
              title={t("settings.extensions.unpair")}
              aria-label={t("settings.extensions.unpair")}
              onClick={() => act("extension_unpair", r.key)}
            >
              <Icon name="trash" size={14} />
            </button>
          </Row>
        ))}
        {list && list.paired.length === 0 && list.pending.length === 0 && (
          <Row title={t("settings.extensions.none")} hint={t("settings.extensions.noneHint")}>
            <Icon name="globe" />
          </Row>
        )}
      </Rows>
      {error && <Alert message={error} onClose={() => setError(null)} />}
    </Section>
  );
}
