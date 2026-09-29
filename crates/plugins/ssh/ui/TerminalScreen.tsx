import "./style.css";
import { useEffect } from "react";
import { Icon } from "@keyward/ui";
import { t } from "@keyward/i18n";
import { call } from "@keyward/plugins/call";
import type { PluginScreenProps } from "@keyward/plugins/types";
import { ConnectModal } from "./ConnectModal";
import { HealthOverview } from "./Health";
import { TerminalPane, stateTone, stateWord } from "./TerminalPane";
import { OVERVIEW, adoptSessions, closeTab, setActive, setConnect, useActive, useConnect, useHealth, useTabs } from "./terminalState";
import type { TermSession } from "./types";

/// The terminal: shells on servers, reached with the vault's keys, in tabs.
///
/// The first tab is the overview — whether each key still gets in where it is
/// bound. The shells follow, one tab each; every terminal stays mounted while
/// another is shown, so switching keeps its screen, and leaving the section
/// keeps the shell itself: the plugin holds it, and the tab re-attaches.
export function TerminalScreen(_: PluginScreenProps) {
  const tabs = useTabs();
  const active = useActive();
  const connect = useConnect();
  const report = useHealth();

  // Shells the plugin kept while the section was away get their tabs back.
  useEffect(() => {
    void call<TermSession[]>("ssh", "term_sessions")
      .then(adoptSessions)
      .catch(() => {});
  }, []);

  return (
    <div className="term-screen">
      <div className="term-tabs" role="tablist">
        <button type="button" role="tab" aria-selected={active === OVERVIEW} className={`term-tab ${active === OVERVIEW ? "on" : ""}`} onClick={() => setActive(OVERVIEW)}>
          <Icon name="shield" size={14} />
          <span className="term-tab-label">{t("term.overview")}</span>
        </button>
        {tabs.map((tab) => {
          const label = tab.info ? `${tab.info.user}@${tab.info.host}` : tab.destination?.host || t("term.state.connecting");
          return (
            <div key={tab.key} role="tab" aria-selected={active === tab.key} className={`term-tab ${active === tab.key ? "on" : ""}`}>
              <button type="button" className="term-tab-open" title={`${label} · ${stateWord(tab)}`} onClick={() => setActive(tab.key)}>
                <span className={`dot ${stateTone(tab)}`} />
                <span className="term-tab-label">{label}</span>
              </button>
              <button type="button" className="term-tab-close" title={t("term.closeTab")} aria-label={t("term.closeTab")} onClick={() => void closeTab(tab.key)}>
                <Icon name="close" size={12} />
              </button>
            </div>
          );
        })}
        <button type="button" className="btn icon-only term-new" title={t("term.connectMore")} aria-label={t("term.connectMore")} onClick={() => setConnect({ host: "" })}>
          <Icon name="plus" size={14} />
        </button>
      </div>

      <div className="term-body">
        {active === OVERVIEW && <HealthOverview report={report} />}
        {tabs.map((tab) => (
          <TerminalPane key={tab.key} tab={tab} visible={active === tab.key} />
        ))}
      </div>

      {connect && <ConnectModal initial={connect} onClose={() => setConnect(null)} />}
    </div>
  );
}
