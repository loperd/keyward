import "./style.css";
import { useEffect, useState } from "react";
import { t } from "@keyward/i18n";
import { call } from "@keyward/plugins/call";
import type { PluginScreenProps } from "@keyward/plugins/types";
import { HealthDot } from "./Health";
import { openTab, setConnect, useHealth } from "./terminalState";
import type { HealthStatus, TermTarget } from "./types";

function label(tg: TermTarget): string {
  const port = tg.port && tg.port !== 22 ? `:${tg.port}` : "";
  return `${tg.user ? `${tg.user}@` : ""}${tg.host}${port}`;
}

/// The section's column: the hosts the routes name, each with its key's
/// health, one click from a shell.
export function TerminalContext({ catalog }: PluginScreenProps) {
  const [targets, setTargets] = useState<TermTarget[]>([]);
  const report = useHealth();
  // Re-read when the items change: a new route is a new host.
  const items = catalog?.items.length ?? 0;

  useEffect(() => {
    void call<TermTarget[]>("ssh", "term_targets")
      .then(setTargets)
      .catch(() => setTargets([]));
  }, [items, report?.checked_at]);

  const checkOf = (tg: TermTarget) => {
    const key = report?.keys.find((k) => k.entry_id === tg.entry_id);
    const port = tg.port ?? 22;
    return key?.checks.find((c) => c.host === tg.host && c.port === port);
  };
  const statusOf = (tg: TermTarget): HealthStatus => checkOf(tg)?.status ?? "pending";

  return (
    <div className="group">
      <h4>{t("term.hosts")}</h4>
      {targets.map((tg) => (
        <button
          type="button"
          key={`${tg.entry_id}/${label(tg)}`}
          className="nav term-target"
          title={[label(tg), ...tg.aliases, tg.entry_name].join(" · ")}
          onClick={() =>
            tg.user
              ? openTab({ entry_id: tg.entry_id, host: tg.host, port: tg.port, user: tg.user })
              : setConnect({ entry_id: tg.entry_id, host: tg.host, port: tg.port })
          }
        >
          <span className="term-target-dot">
            <HealthDot status={statusOf(tg)} checking={checkOf(tg)?.checking} />
          </span>
          <span className="label">
            {label(tg)}
            <small>{tg.aliases.length > 0 ? `${tg.entry_name} · ${t("term.aliases", { names: tg.aliases.join(", ") })}` : tg.entry_name}</small>
          </span>
        </button>
      ))}
      {targets.length === 0 && <p className="hint term-nohosts">{t("term.noHosts")}</p>}
    </div>
  );
}
