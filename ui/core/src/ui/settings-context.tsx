// The settings the window holds while the vault is open, and a row of them
// drawn as a live control. The settings are read once the window is up and
// again after every change; a change is sent at once and what the backend
// answers is what stands — a refused one leaves the row as it was and says
// why.
import { createContext, useContext, useState } from "react";
import "./edit.css";
import "./settings.css";
import { t, text } from "../i18n";
import { ROWS, RowKind, type SettingKey } from "../settings/rows";
import type { AppSettings, SettingsPatch } from "../settings/types";

export type SettingsHold = {
  /// `null` while they are on their way.
  settings: AppSettings | null;
  /// Why they could not be read, if they could not.
  failed: string | null;
  /// Sends a change; rejects with the backend's reason.
  patch: (p: SettingsPatch) => Promise<void>;
};

export const SettingsContext = createContext<SettingsHold | null>(null);

/// The settings where the app keeps any; `null` where it keeps none.
export const useSettingsMaybe = (): SettingsHold | null => useContext(SettingsContext);

function useSettingsHold(): SettingsHold {
  const h = useContext(SettingsContext);
  if (!h) throw new Error("a setting was drawn outside the settings' provider");
  return h;
}

/// One setting: its words on the left, a switch on the right, or its choices
/// under the words across the row.
export function SettingRowView({ setting, report }: { setting: SettingKey; report: (e: unknown) => void }) {
  const hold = useSettingsHold();
  const [busy, setBusy] = useState(false);
  const row = ROWS[setting];
  const s = hold.settings;
  const title = t(row.title);
  if (!s)
    return (
      <div className="kw-set kw-set-wait" role="status" aria-label={hold.failed ? t("set.readFailed", { reason: hold.failed }) : t("set.loading")}>
        <span className="kw-set-t">
          <b>{title}</b>
          {hold.failed && <span className="kw-set-h">{t("set.readFailed", { reason: hold.failed })}</span>}
        </span>
      </div>
    );
  const send = (p: SettingsPatch) => {
    setBusy(true);
    hold
      .patch(p)
      .catch((e: unknown) => report(new Error(t("set.saveFailed", { reason: e instanceof Error ? e.message : String(e) }))))
      .finally(() => setBusy(false));
  };
  const hint = row.hint ? t(row.hint(s)) : null;
  if (row.kind === RowKind.Toggle) {
    const on = row.on(s);
    return (
      <div className="kw-set" aria-busy={busy || undefined}>
        <span className="kw-set-t">
          <b>{title}</b>
          {hint && <span className="kw-set-h">{hint}</span>}
        </span>
        <button type="button" role="switch" aria-checked={on} aria-label={title} title={t(on ? "set.on" : "set.off")} className={`kw-switch${on ? " kw-on" : ""}`} disabled={busy} onClick={() => send(row.patch(!on))} />
      </div>
    );
  }
  const choices = row.choices(s);
  return (
    <div className="kw-set kw-set-choice" aria-busy={busy || undefined}>
      <span className="kw-set-t">
        <b>{title}</b>
        {hint && <span className="kw-set-h">{hint}</span>}
      </span>
      <span className="kw-chips kw-set-chips" role="radiogroup" aria-label={title}>
        {choices.map((c, i) => (
          <button key={i} type="button" role="radio" aria-checked={c.on} className={`kw-chip kw-sans${c.on ? " kw-on" : ""}`} disabled={busy} onClick={c.on ? undefined : () => send(c.patch)}>
            {text(c.label)}
          </button>
        ))}
      </span>
    </div>
  );
}
