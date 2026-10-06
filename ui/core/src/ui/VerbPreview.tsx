// A verb's preview: what will happen, step by step, what changes and what
// stays — and nothing happens until ↵. The preview is the verb's own
// (verbs/core.ts or a plugin's); this only draws it and runs its effect.
import { isKey, t, text, type Text } from "../i18n";
import { previewOf } from "../verbs/core";
import { type DeltaSide, type Effect, type Line, PreviewKind } from "../verbs/spec";
import { Icon } from "./Icons";
import { VerbForm } from "./VerbForm";
import { BtnIcon, Glyph, Kbd, Mark, Tile, nodeLead, useCore } from "./marks";
import { useEffect, useState } from "react";
import { useMemberFingerprint, type ShownFingerprint, FingerprintPhase } from "./writes-context";
import { Phase } from "./feedback";
import { Level } from "../model/types";
import { Turning } from "./Loading";

/// Where a verb's run stands.
export enum RunPhase {
  Idle = "idle",
  Running = "running",
  Done = "done",
  Failed = "failed",
}
export type RunState = { phase: RunPhase.Idle } | { phase: RunPhase.Running } | { phase: RunPhase.Done; changed: boolean } | { phase: RunPhase.Failed; reason: string };

const say = (x: Text) => text(x);

function Side({ s }: { s: DeltaSide }) {
  if ("faint" in s) return <span className="kw-faint">{say(s.faint)}</span>;
  return <Mark level={s.level} words={s.text} />;
}

function Lines({ lines }: { lines: Line[] }) {
  return (
    <>
      {lines.map((l, i) => (
        <div key={i} className="kw-sig">
          <Glyph level={l.level} />
          <span className="kw-tx">
            <b>{say(l.title)}</b>
            {l.sub && <span>{say(l.sub)}</span>}
          </span>
          <span />
        </div>
      ))}
    </>
  );
}

function Section({ title, count, children }: { title: string; count?: number | undefined; children: React.ReactNode }) {
  return (
    <section className="kw-sec">
      <div className="kw-sec-h">
        <h2 className="kw-h2">{title}</h2>
        {count !== undefined && <span className="kw-n">{count}</span>}
      </div>
      {children}
    </section>
  );
}

/// A backend's refusal in the person's words: its `err.*` key when it has
/// one, its message otherwise.
function refusal(e: unknown): string {
  const code = e && typeof e === "object" && "code" in e && typeof e.code === "string" ? e.code : (e instanceof Error ? e.message : String(e)).trim();
  return code.startsWith("err.") && isKey(code) ? t(code) : code;
}

/// The member's fingerprint phrase, as Bitwarden writes it (words joined by
/// hyphens), with what to do with it: read it out with the member before ↵.
function Fingerprint({ shown, compare }: { shown: ShownFingerprint | null; compare: Text }) {
  return (
    <Section title={t("verb.org.confirm.fingerprint")}>
      <div className="kw-fprint" aria-live="polite">
        {shown?.phase === FingerprintPhase.Shown ? (
          <b className="kw-fprint-words" data-fingerprint="">{shown.words.join("-")}</b>
        ) : shown?.phase === FingerprintPhase.Failed ? (
          <Mark level={Level.Critical} words={t("verb.org.confirm.fingerprintFailed", { reason: refusal(shown.error) })} />
        ) : (
          <span className="kw-sk-late kw-sk-fprint" role="status" aria-label={t("verb.org.confirm.fingerprintLoading")}>
            <span className="kw-sk-line kw-sk-l" aria-hidden="true">
              <span className="kw-sk kw-sk-phrase" />
            </span>
            <span className="kw-load-inline">
              <Turning />
              {t("verb.org.confirm.fingerprintLoading")}
            </span>
          </span>
        )}
        <span className="kw-fprint-how">{say(compare)}</span>
      </div>
    </Section>
  );
}

function Lead() {
  return (
    <div className="kw-vlead">
      <Icon name="verb" />
      <span>{t("ui.previewLead")}</span>
    </div>
  );
}

function Target({ id }: { id: string }) {
  const { dir } = useCore();
  const n = dir.node(id);
  const place = n.home.slice(0, -1).map((x) => text(dir.node(x).name)).join(" › ") || t("root");
  return (
    <div className="kw-target">
      <Tile lead={nodeLead(dir, id)} />
      <span>
        <b>{text(n.name)}</b> · {place}
      </span>
    </div>
  );
}

export function VerbPreview({ run, onRun }: { run: RunState; onRun: (e: Effect) => void }) {
  const { dir, query, store } = useCore();
  const st = store.get().state;
  const verb = st.verb!;
  const obj = st.segs.length ? store.object() : null;
  const p = previewOf(dir, query.verbs, verb, obj, st.arg);
  const print = useMemberFingerprint(p.kind === PreviewKind.Ready ? p.fingerprint ?? null : null);
  const close = () => store.verb(null);
  // A refusal nudges the button it came from, once per refusal.
  const [shake, setShake] = useState(false);
  useEffect(() => {
    if (run.phase === RunPhase.Failed) setShake(true);
  }, [run]);
  if (p.kind === PreviewKind.Unknown)
    return (
      <>
        <Lead />
        <h1 className="kw-h1">{t("ui.noVerb", { verb })}</h1>
        <p className="kw-lede">{t("ui.thereAre", { list: p.known.map(say).join(", ") })}</p>
      </>
    );
  if (p.kind === PreviewKind.Pick)
    return (
      <>
        <Lead />
        <h1 className="kw-h1">{t("ui.onWhat", { verb: say(p.name) })}</h1>
        <p className="kw-lede">{p.obj ? t("ui.doesNotFit", { name: text(dir.node(p.obj).name) }) : t("ui.pickFirst")}</p>
        {p.example && (
          <div className="kw-vbar">
            <button
              type="button"
              className="kw-btn kw-quiet"
              onClick={() => store.commitState({ segs: dir.node(p.example!).home.map((x) => ({ id: x })), map: null, verb, arg: "" })}
            >
              <Icon name={dir.node(p.example).icon} />
              {`${say(p.exampleName!)} › ${say(p.name)}`}
            </button>
          </div>
        )}
      </>
    );
  const steps = p.steps.length > 0 && (
    <ol className="kw-steps">
      {p.steps.map((s, i) => (
        <li key={i}>
          <div>
            <b>{say(s.title)}</b>
            <span>{say(s.sub)}</span>
          </div>
        </li>
      ))}
    </ol>
  );
  // A confirm waits for the member's words on screen: ↵ sends them.
  const held = p.fingerprint && print?.phase !== FingerprintPhase.Shown ? t(print?.phase === FingerprintPhase.Failed ? "verb.org.confirm.fingerprintMissing" : "verb.org.confirm.fingerprintLoading") : null;
  return (
    <>
      <Lead />
      {p.target && <Target id={p.target} />}
      <h1 className="kw-h1">{say(p.title)}</h1>
      <p className="kw-lede">{say(p.lede)}</p>
      {p.fingerprint && <Fingerprint shown={print} compare={p.fingerprint.compare} />}
      {p.form && <VerbForm form={p.form} onEnter={() => !p.blocked && !held && run.phase !== RunPhase.Running && onRun(p.effect)} />}
      {!p.form && steps}
      {p.now && (
        <Section title={t("ui.now")}>
          <Lines lines={p.now} />
        </Section>
      )}
      {p.changes && p.changes.rows.length > 0 && (
        <Section title={t("ui.whatChanges")} count={p.changes.count}>
          {p.changes.rows.map((d, i) => (
            <div key={i} className="kw-delta">
              <span className="kw-nm">
                <Tile lead={d.lead} />
                <span className={d.mono ? "kw-mono" : undefined}>{say(d.name)}</span>
              </span>
              <Side s={d.from} />
              <span className="kw-arrow">→</span>
              <Side s={d.to} />
            </div>
          ))}
        </Section>
      )}
      {/* With controls, what they lead to stands next to them; how it
          goes comes after. */}
      {p.form && p.steps.length > 0 && <Section title={t("ui.howItGoes")}>{steps}</Section>}
      {p.stays && p.stays.length > 0 && (
        <Section title={t("ui.whatStays")}>
          <Lines lines={p.stays} />
        </Section>
      )}
      {run.phase === RunPhase.Done ? (
        <div className="kw-vbar kw-resolved" role="status">
          <Mark level={Level.Healthy} words={t("ui.done")} />
          <span className="kw-why">{t(run.changed ? "ui.doneChanged" : "ui.doneNothing")}</span>
          <button type="button" className="kw-btn kw-quiet" onClick={close}>
            {t("ui.close")}
            <Kbd>Esc</Kbd>
          </button>
        </div>
      ) : (
        <div className="kw-vbar">
          <button
            type="button"
            className={`kw-btn kw-solid${p.danger ? " kw-danger" : ""}${shake ? " kw-shake" : ""}`}
            disabled={run.phase === RunPhase.Running || !!p.blocked || !!held}
            aria-busy={run.phase === RunPhase.Running || undefined}
            onClick={() => onRun(p.effect)}
            onAnimationEnd={(e) => {
              if (e.animationName === "kw-shake") setShake(false);
            }}
            data-confirm=""
          >
            <BtnIcon icon={p.danger ? "trash" : "check"} phase={run.phase === RunPhase.Running ? Phase.Busy : Phase.Idle} />
            {say(p.go)}
            <Kbd>↵</Kbd>
          </button>
          <button type="button" className="kw-btn kw-quiet" onClick={close}>
            {t("ui.cancel")}
            <Kbd>Esc</Kbd>
          </button>
          {run.phase === RunPhase.Failed ? (
            <span className="kw-why kw-refused" role="alert">
              <Mark level={Level.Critical} words={t("ui.failed", { reason: run.reason })} />
            </span>
          ) : (
            p.blocked || held ? (
              <span className="kw-why kw-held">
                <Icon name="info" />
                {p.blocked ? say(p.blocked) : held}
              </span>
            ) : p.note && (
              <span className="kw-why">
                <Icon name="finger" />
                {say(p.note)}
              </span>
            )
          )}
        </div>
      )}
    </>
  );
}

/// The effect a line's verb would run, if it is ready to: what ↵ does, and
/// the preview's title, to say it was done once the sheet has moved on.
export function readyEffect(core: ReturnType<typeof useCore>): { effect: Effect; title: Text } | null {
  const st = core.store.get().state;
  if (st.verb === null) return null;
  const p = previewOf(core.dir, core.query.verbs, st.verb, st.segs.length ? core.store.object() : null, st.arg);
  return p.kind === PreviewKind.Ready && !p.blocked ? { effect: p.effect, title: p.title } : null;
}
