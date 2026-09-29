import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Alert, Empty, Icon } from "../ui";
import { t, tMaybe } from "../i18n";
import type { PendingEdit } from "../types";

/// The queue of edits: what did not reach the server, and what to do about
/// it.
export function EditsScreen({ onChanged }: { onChanged: () => void }) {
  const [edits, setEdits] = useState<PendingEdit[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const load = () =>
    invoke<PendingEdit[]>("pending_edits")
      .then(setEdits)
      .catch((e) => setError(String(e)));

  useEffect(() => {
    void load();
  }, []);

  const act = async (cmd: string, id: string) => {
    setBusy(id);
    setError(null);
    try {
      setEdits(await invoke<PendingEdit[]>(cmd, { id }));
      onChanged();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(null);
    }
  };

  if (error && !edits) return <Alert message={error} onRetry={() => void load()} />;
  if (!edits) return null;
  if (edits.length === 0) {
    return <Empty icon="sync" title={t("edits.empty")} body={t("edits.emptyHint")} />;
  }

  return (
    <>
      {error && <Alert message={error} />}
      <div className="list">
        {edits.map((e) => {
          const waiting = e.state.state === "pending";
          return (
            <div className="row" key={e.id}>
              <span className="glyph">
                <Icon name={waiting || e.damaged ? "warn" : "shield"} />
              </span>
              <span className="text">
                <b>{e.damaged ? t("edits.damaged") : e.locked ? t("edits.locked") : e.entry_name}</b>
                {e.damaged || e.locked ? (
                  <span>{e.damaged ? t("edits.damagedHint") : t("edits.lockedHint")}</span>
                ) : (
                <span>
                  {e.changed.map((c) => tMaybe(c.label, c.label)).join(", ")}
                  {" · "}
                  {e.state.state === "pending"
                    ? `${t("edits.waiting")} · ${t("edits.attempts", { n: e.state.attempts })}`
                    : e.state.state === "pushed"
                      ? t("edits.pushed")
                      : t("edits.rolledBack")}
                </span>
                )}
              </span>
              <span className="side">
                {waiting && !e.locked && !e.damaged && (
                  <>
                    <button type="button" className="btn" disabled={busy === e.id} onClick={() => void act("retry_edit", e.id)}>
                      {t("edits.retry")}
                    </button>
                    <button type="button" className="btn" disabled={busy === e.id} onClick={() => void act("rollback_edit", e.id)}>
                      {t("edits.rollback")}
                    </button>
                  </>
                )}
                <button type="button" className="btn" disabled={busy === e.id} onClick={() => void act("discard_edit", e.id)}>
                  {t("edits.discard")}
                </button>
              </span>
            </div>
          );
        })}
      </div>
      {(() => {
        // The last failure's reason matters more than the list: it says
        // whether to wait for the server or to mend the account.
        const failed = edits.find((e) => e.state.state === "pending" && e.state.last_error);
        if (!failed || failed.state.state !== "pending" || !failed.state.last_error) return null;
        return <Alert tone="warn" message={failed.state.last_error} />;
      })()}
    </>
  );
}
