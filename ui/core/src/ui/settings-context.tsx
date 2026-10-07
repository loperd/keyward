// The settings the window holds while the vault is open, and a row of them
// drawn as a live control. The settings are read once the window is up and
// again after every change; a change is sent at once and what the backend
// answers is what stands — a refused one leaves the row as it was and says
// why.
import { createContext, useContext, useState } from "react";
import "./edit.css";
import "./settings.css";
import { t, text } from "../i18n";
import { type MethodVerb, ROWS, RowKind, type SettingKey, type SettingRow } from "../settings/rows";
import type { AppSettings, SettingsPatch, UnlockState } from "../settings/types";
import { useCore, BtnIcon } from "./marks";
import { Phase } from "./feedback";

export type SettingsHold = {
  /// `null` while they are on their way.
  settings: AppSettings | null;
  /// Why they could not be read, if they could not.
  failed: string | null;
  /// Sends a change; rejects with the backend's reason.
  patch: (p: SettingsPatch) => Promise<void>;
  /// How the account opens here besides the master password: `null` while
  /// on its way, or where the app cannot tell.
  unlock: UnlockState | null;
};

export const SettingsContext = createContext<SettingsHold | null>(null);

/// The settings where the app keeps any; `null` where it keeps none.
export const useSettingsMaybe = (): SettingsHold | null => useContext(SettingsContext);

function useSettingsHold(): SettingsHold {
  const h = useContext(SettingsContext);
  if (!h) throw new Error("a setting was drawn outside the settings' provider");
  return h;
}

/// A row while what it shows is on its way, or could not be read.
function Waiting({ title, failed }: { title: string; failed: string | null }) {
  return (
    <div className="kw-set kw-set-wait" role="status" aria-label={failed ? t("set.readFailed", { reason: failed }) : t("set.loading")}>
      <span className="kw-set-t">
        <b>{title}</b>
        {failed && <span className="kw-set-h">{t("set.readFailed", { reason: failed })}</span>}
      </span>
    </div>
  );
}

function Words({ title, hint }: { title: string; hint: string | null }) {
  return (
    <span className="kw-set-t">
      <b>{title}</b>
      {hint && <span className="kw-set-h">{hint}</span>}
    </span>
  );
}

/// One setting: its words on the left, a switch or a method's buttons on the
/// right, or its choices under the words across the row.
export function SettingRowView({ setting, report }: { setting: SettingKey; report: (e: unknown) => void }) {
  const row = ROWS[setting];
  if (row.kind === RowKind.Method) return <MethodRow row={row} />;
  if (row.kind === RowKind.Action) return <ActionRow row={row} />;
  return <ValueRow row={row} report={report} />;
}

function VerbButtons({ verbs }: { verbs: MethodVerb[] }) {
  const { store } = useCore();
  return (
    <>
      {verbs.map((v) => (
        <button key={v.verb} type="button" className={`kw-btn${v.quiet ? " kw-quiet" : " kw-solid"}`} onClick={() => store.verb(v.verb)}>
          <BtnIcon icon={v.icon} phase={Phase.Idle} />
          {t(v.label)}
        </button>
      ))}
    </>
  );
}

/// Something done from the settings (an export): its words, and the verb
/// that opens its preview.
function ActionRow({ row }: { row: Extract<SettingRow, { kind: RowKind.Action }> }) {
  return (
    <div className="kw-set">
      <Words title={t(row.title)} hint={t(row.hint)} />
      <span className="kw-set-acts">
        <VerbButtons verbs={row.verbs} />
      </span>
    </div>
  );
}

function ValueRow({ row, report }: { row: Extract<SettingRow, { kind: RowKind.Toggle | RowKind.Choice }>; report: (e: unknown) => void }) {
  const hold = useSettingsHold();
  const [busy, setBusy] = useState(false);
  const s = hold.settings;
  const title = t(row.title);
  if (!s) return <Waiting title={title} failed={hold.failed} />;
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
        <Words title={title} hint={hint} />
        <button type="button" role="switch" aria-checked={on} aria-label={title} title={t(on ? "set.on" : "set.off")} className={`kw-switch${on ? " kw-on" : ""}`} disabled={busy} onClick={() => send(row.patch(!on))} />
      </div>
    );
  }
  return (
    <div className="kw-set kw-set-choice" aria-busy={busy || undefined}>
      <Words title={title} hint={hint} />
      <span className="kw-chips kw-set-chips" role="radiogroup" aria-label={title}>
        {row.choices(s).map((c, i) => (
          <button key={i} type="button" role="radio" aria-checked={c.on} className={`kw-chip kw-sans${c.on ? " kw-on" : ""}`} disabled={busy} onClick={c.on ? undefined : () => send(c.patch)}>
            {text(c.label)}
          </button>
        ))}
      </span>
    </div>
  );
}

/// A way to open the vault: on or off, and the verbs that change it — each
/// opens its preview on the line, where what it needs is typed.
function MethodRow({ row }: { row: Extract<SettingRow, { kind: RowKind.Method }> }) {
  const hold = useSettingsHold();
  const u = hold.unlock;
  const title = t(row.title);
  if (!u) return <Waiting title={title} failed={null} />;
  const on = row.on(u);
  return (
    <div className="kw-set">
      <Words title={title} hint={text(row.hint(u))} />
      <span className="kw-set-acts">
        <span className={`kw-set-state${on ? " kw-on" : ""}`}>{t(on ? "set.on" : "set.off")}</span>
        {row.available(u) && <VerbButtons verbs={row.verbs(u)} />}
      </span>
    </div>
  );
}
