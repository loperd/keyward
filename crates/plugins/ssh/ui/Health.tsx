import { Empty, Icon, Skeleton } from "@keyward/ui";
import { locale, t, tError, type Key } from "@keyward/i18n";
import { openTab, runHealth, setConnect } from "./terminalState";
import type { HealthCheck, HealthReport, HealthStatus, KeyHealth } from "./types";

/// A status's tone: the dot's and the chip's colour.
export function healthTone(status: HealthStatus): "ok" | "warn" | "bad" | "" {
  switch (status) {
    case "ok":
      return "ok";
    case "reachable":
    case "host_unknown":
    case "pending":
      return "warn";
    case "error":
    case "unreachable":
    case "rejected":
    case "host_changed":
      return "bad";
    default:
      return "";
  }
}

/// Dictionary keys are camelCase; the plugin's statuses are snake_case.
export function healthWord(status: HealthStatus): string {
  const camel = status.replace(/_([a-z])/g, (_, c: string) => c.toUpperCase());
  return t(`term.health.${camel}` as Key);
}

/// The dot beside a key or a host. A host being checked pulses.
export function HealthDot({ status, title, checking = false }: { status: HealthStatus; title?: string; checking?: boolean }) {
  const word = checking ? t("term.health.checking") : (title ?? healthWord(status));
  return <span className={`dot ${healthTone(status)} health-dot ${checking ? "checking" : ""}`} title={word} aria-label={word} />;
}

/// The chip with a dot and a word.
export function HealthChip({ status }: { status: HealthStatus }) {
  return <span className={`chip dot ${healthTone(status)}`}>{healthWord(status)}</span>;
}

/// "5 minutes ago", in the person's language.
export function ago(seconds: number | null): string {
  if (!seconds) return "";
  const diff = Math.round(seconds - Date.now() / 1000);
  const fmt = new Intl.RelativeTimeFormat(locale(), { numeric: "auto" });
  const abs = Math.abs(diff);
  if (abs < 60) return fmt.format(diff, "second");
  if (abs < 3600) return fmt.format(Math.round(diff / 60), "minute");
  if (abs < 86400) return fmt.format(Math.round(diff / 3600), "hour");
  return fmt.format(Math.round(diff / 86400), "day");
}

function hostLabel(c: HealthCheck): string {
  const port = c.port !== 22 ? `:${c.port}` : "";
  return `${c.user ? `${c.user}@` : ""}${c.host}${port}`;
}

/// What to say under a host besides its status: how fast it answered, or why
/// it did not.
function checkNote(c: HealthCheck): string {
  if (c.note) return tError(c.note);
  if (c.status === "ok" && c.latency_ms !== null) return t("term.health.latency", { ms: c.latency_ms });
  if (c.status === "reachable") return t("term.health.reachableHint");
  if (c.status === "host_unknown") return t("term.health.hostUnknownHint");
  if (c.detail) return tError(c.detail);
  return "";
}

/// The keys' health: the section's overview when no shell is on view.
export function HealthOverview({ report }: { report: HealthReport | null }) {
  if (!report) {
    return (
      <div className="term-overview">
        <Skeleton rows={4} />
      </div>
    );
  }
  const keys = report.keys;
  if (keys.length === 0) {
    return <Empty icon="terminal" title={t("term.empty.title")} body={t("term.empty.body")} />;
  }
  // Counted by hosts: a key that gets in everywhere but one host is not
  // "one bad key" to a person looking for what to fix.
  const checks = keys.flatMap((k) => k.checks);
  const good = checks.filter((c) => c.status === "ok").length;
  const bad = checks.filter((c) => healthTone(c.status) === "bad").length;

  return (
    <div className="term-overview">
      <div className="term-overview-head">
        <div className="term-summary">
          <h3>{t("term.health.title")}</h3>
          <div className="term-health-metrics">
            <span className="chip dot ok">{t("term.health.good", { n: good, total: checks.length })}</span>
            {bad > 0 && <span className="chip dot bad">{t("term.health.bad", { n: bad })}</span>}
            {report.checked_at && <span className="hint">{t("term.health.checked", { when: ago(report.checked_at) })}</span>}
          </div>
        </div>
        <button
          type="button"
          className="btn primary icon-only term-health-run"
          disabled={report.running}
          title={report.running ? t("term.health.running") : t("term.health.run")}
          aria-label={report.running ? t("term.health.running") : t("term.health.run")}
          aria-busy={report.running}
          onClick={() => void runHealth()}
        >
          <Icon name="sync" size={15} />
        </button>
      </div>
      <p className="hint">{t("term.health.explain")}</p>
      <div className="term-keys">
        {keys.map((k) => (
          <KeyCard key={k.entry_id} k={k} running={report.running} />
        ))}
      </div>
    </div>
  );
}

function KeyCard({ k, running }: { k: KeyHealth; running: boolean }) {
  const tone = healthTone(k.status);
  return (
    <section className={`block term-key ${tone ? `health-${tone}` : ""}`}>
      <header className="term-key-head">
        <Icon name="ssh_key" />
        <b>{k.entry_name}</b>
        <HealthChip status={k.status} />
        <span className="grow" />
        {k.checks.length > 0 && (
          <button
            type="button"
            className="btn icon-only term-key-check"
            disabled={running}
            title={t("term.health.check")}
            aria-label={t("term.health.check")}
            onClick={() => void runHealth(k.entry_id)}
          >
            <Icon name="sync" size={14} />
          </button>
        )}
      </header>
      {k.checks.length === 0 ? (
        <p className="hint">{k.status === "unbound" ? t("term.health.unboundHint") : t("term.health.wildcardHint")}</p>
      ) : (
        <div className="term-checks">
          {k.checks.map((c) => (
            <div className="term-check" key={`${c.user ?? ""}@${c.host}:${c.port}`}>
              <HealthDot status={c.status} checking={c.checking} />
              <span className="term-check-text">
                <code>{hostLabel(c)}</code>
                {c.aliases.length > 0 && <span className="hint term-aliases">{t("term.aliases", { names: c.aliases.join(", ") })}</span>}
                <span className="hint">
                  {c.checking ? t("term.health.checking") : healthWord(c.status)}
                  {!c.checking && checkNote(c) ? ` · ${checkNote(c)}` : ""}
                </span>
                {c.status === "host_changed" && c.fingerprint && <code className="term-fp bad-text">{c.fingerprint}</code>}
              </span>
              <button
                type="button"
                className="btn icon-only term-connect-action"
                disabled={c.status === "host_changed"}
                title={c.status === "host_changed" ? t("term.health.changedHint") : t("term.connect")}
                aria-label={c.status === "host_changed" ? t("term.health.changedHint") : t("term.connect")}
                onClick={() =>
                  c.user
                    ? openTab({ entry_id: k.entry_id, host: c.host, port: c.port, user: c.user })
                    : setConnect({ entry_id: k.entry_id, host: c.host, port: c.port })
                }
              >
                <Icon name="terminal" size={14} />
              </button>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
