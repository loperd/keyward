import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Alert, Icon, Modal } from "./ui";
import { t } from "./i18n";

type ExtensionRow = { key: string; words: string[]; at: number; expires: number };
type Extensions = { paired: ExtensionRow[]; pending: ExtensionRow[] };

/// A browser extension asking to be paired comes to the person: the window
/// sees it on the daemon's list and asks, with the key's five words to compare
/// with the extension's own window. One action; the finger confirms it, with
/// the same words in the prompt.
export function PairPrompt({ unlocked }: { unlocked: boolean }) {
  const [asking, setAsking] = useState<ExtensionRow | null>(null);
  const [dismissed, setDismissed] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [now, setNow] = useState(() => Date.now() / 1000);
  useEffect(() => {
    if (!asking) return;
    const timer = setInterval(() => setNow(Date.now() / 1000), 1000);
    return () => clearInterval(timer);
  }, [asking]);

  useEffect(() => {
    if (!unlocked) return;
    let alive = true;
    const look = () =>
      invoke<Extensions>("extensions")
        .then((l) => {
          if (!alive) return;
          const next = l.pending.find((r) => !dismissed.includes(r.key)) ?? null;
          setAsking((cur) => (cur && l.pending.some((r) => r.key === cur.key) ? cur : next));
        })
        .catch(() => {});
    void look();
    const timer = setInterval(look, 3000);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, [unlocked, dismissed]);

  if (!asking) return null;
  // The same count the extension's window shows: once it runs out, the words
  // mean nothing and the daemon refuses them.
  const left = Math.max(0, Math.round(asking.expires - now));
  const expired = left === 0;
  const close = () => {
    setDismissed((d) => [...d, asking.key]);
    setAsking(null);
    setError(null);
  };
  const pair = () => {
    setBusy(true);
    setError(null);
    invoke("extension_pair", { key: asking.key })
      .then(() => setAsking(null))
      .catch((e) => setError(String(e)))
      .finally(() => setBusy(false));
  };

  return (
    <Modal
      title={t("pair.title")}
      onClose={close}
      footer={
        <button type="button" className="btn primary" disabled={busy || expired} onClick={pair}>
          <Icon name="shield-check" size={14} />
          {busy ? t("pair.touch") : t("pair.confirm")}
        </button>
      }
    >
      <div className="pair-prompt">
        <Icon name="globe" size={22} />
        <p>{t("pair.body")}</p>
        <p className="ext-words pair-words">
          {asking.words.map((w, i) => (
            <code key={i}>{w}</code>
          ))}
        </p>
        <p className={`pair-timer ${expired ? "expired" : ""}`}>
          <Icon name="clock" size={13} />
          {expired ? t("pair.expired") : t("pair.left", { left: `${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}` })}
        </p>
        {error && <Alert message={error} />}
      </div>
    </Modal>
  );
}
